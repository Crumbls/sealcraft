<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Providers;

use Closure;
use Crumbls\Sealcraft\Contracts\KekProvider;
use Crumbls\Sealcraft\Contracts\SupportsKeyVersioning;
use Crumbls\Sealcraft\Contracts\SupportsNativeAad;
use Crumbls\Sealcraft\Exceptions\DecryptionFailedException;
use Crumbls\Sealcraft\Exceptions\KekUnavailableException;
use Crumbls\Sealcraft\Values\EncryptionContext;
use Crumbls\Sealcraft\Values\ProviderCapabilities;
use Crumbls\Sealcraft\Values\WrappedDek;
use Illuminate\Http\Client\Factory as HttpFactory;
use Illuminate\Http\Client\RequestException;

/**
 * HashiCorp Vault Transit backed KEK provider.
 *
 * Uses /transit/encrypt/:name and /transit/decrypt/:name with the
 * `context` parameter. Transit derives a per-context key using the
 * supplied context as HKDF info input, so AAD is enforced at the
 * service layer: a context mismatch yields a hard decrypt failure
 * from Vault itself.
 *
 * DEK generation is local (random_bytes); Transit has no
 * GenerateDataKey equivalent that returns both plaintext + wrapped
 * in one call.
 */
final class VaultTransitKekProvider implements KekProvider, SupportsKeyVersioning, SupportsNativeAad
{
    public const NAME = 'vault_transit';

    private const MAX_ATTEMPTS = 3;

    /**
     * @param  Closure(): string  $tokenResolver  Returns a Vault token for the Transit backend.
     */
    public function __construct(
        private readonly HttpFactory $http,
        private readonly string $address,
        private readonly string $keyName,
        private readonly Closure $tokenResolver,
        private readonly string $mount = 'transit',
    ) {}

    public function name(): string
    {
        return self::NAME;
    }

    public function currentKeyId(): string
    {
        return rtrim($this->address, '/') . '/' . trim($this->mount, '/') . '/keys/' . $this->keyName;
    }

    public function capabilities(): ProviderCapabilities
    {
        return new ProviderCapabilities(
            generatesDataKeys: false,
            hasNativeAad: true,
            supportsKeyVersioning: true,
            aadStrategy: ProviderCapabilities::AAD_NATIVE,
        );
    }

    public function wrap(string $plaintextDek, EncryptionContext $ctx): WrappedDek
    {
        $response = $this->retrying(fn () => $this->http
            ->withHeaders(['X-Vault-Token' => ($this->tokenResolver)()])
            ->acceptJson()
            ->asJson()
            ->throw()
            ->post($this->endpoint('encrypt'), [
                'plaintext' => base64_encode($plaintextDek),
                'context' => $ctx->toVaultTransitContext(),
            ]));

        $body = $response->json();

        if (! is_array($body) || ! isset($body['data']['ciphertext'])) {
            throw new KekUnavailableException('Vault Transit encrypt response missing ciphertext.');
        }

        $ciphertext = (string) $body['data']['ciphertext'];
        $version = $this->parseVersionFromCiphertext($ciphertext);

        return new WrappedDek(
            ciphertext: $ciphertext,
            providerName: self::NAME,
            keyId: $this->currentKeyId(),
            keyVersion: $version,
            aadStrategy: ProviderCapabilities::AAD_NATIVE,
        );
    }

    public function unwrap(WrappedDek $wrapped, EncryptionContext $ctx): string
    {
        try {
            $response = $this->retrying(fn () => $this->http
                ->withHeaders(['X-Vault-Token' => ($this->tokenResolver)()])
                ->acceptJson()
                ->asJson()
                ->throw()
                ->post($this->endpoint('decrypt'), [
                    'ciphertext' => $wrapped->ciphertext,
                    'context' => $ctx->toVaultTransitContext(),
                ]));
        } catch (RequestException $e) {
            if ($this->isAuthError($e)) {
                throw new DecryptionFailedException('Vault Transit refused decrypt: context mismatch or tampering.');
            }

            throw new KekUnavailableException('Vault Transit decrypt failed: ' . $e->getMessage(), 0, $e);
        }

        $body = $response->json();

        if (! is_array($body) || ! isset($body['data']['plaintext'])) {
            throw new KekUnavailableException('Vault Transit decrypt response missing plaintext.');
        }

        $plaintext = base64_decode((string) $body['data']['plaintext'], true);

        if ($plaintext === false) {
            throw new KekUnavailableException('Vault Transit decrypt plaintext was not valid base64.');
        }

        return $plaintext;
    }

    /**
     * @return array<int, string>
     */
    public function listKeyVersions(): array
    {
        $response = $this->retrying(fn () => $this->http
            ->withHeaders(['X-Vault-Token' => ($this->tokenResolver)()])
            ->acceptJson()
            ->throw()
            ->get(rtrim($this->address, '/') . '/v1/' . trim($this->mount, '/') . '/keys/' . $this->keyName));

        $body = $response->json();
        $keys = is_array($body) && isset($body['data']['keys']) && is_array($body['data']['keys'])
            ? $body['data']['keys']
            : [];

        $versions = array_map(static fn ($v) => (string) $v, array_keys($keys));
        sort($versions, SORT_NUMERIC);

        return $versions;
    }

    public function wrapWithVersion(string $plaintextDek, EncryptionContext $ctx, string $version): WrappedDek
    {
        // Transit always encrypts under `latest_version`; pinning to an
        // older version requires updating the key's min_encryption_version
        // on the Vault side. Fall through to current wrap.
        return $this->wrap($plaintextDek, $ctx);
    }

    private function endpoint(string $operation): string
    {
        return rtrim($this->address, '/')
            . '/v1/' . trim($this->mount, '/')
            . '/' . $operation
            . '/' . $this->keyName;
    }

    private function parseVersionFromCiphertext(string $ciphertext): ?string
    {
        // Vault Transit ciphertext format: vault:vN:<base64>
        if (preg_match('/^vault:v(\d+):/', $ciphertext, $m) === 1) {
            return $m[1];
        }

        return null;
    }

    /**
     * @template T
     *
     * @param  callable(): T  $operation
     * @return T
     */
    private function retrying(callable $operation): mixed
    {
        $attempt = 0;

        while (true) {
            $attempt++;

            try {
                return $operation();
            } catch (RequestException $e) {
                if ($attempt >= self::MAX_ATTEMPTS || ! $this->isRetryable($e)) {
                    throw $e;
                }

                usleep((int) (random_int(50, 150) * 1000 * (2 ** ($attempt - 1))));
            } catch (\Throwable $e) {
                throw new KekUnavailableException('Vault Transit client error: ' . $e->getMessage(), 0, $e);
            }
        }
    }

    private function isRetryable(RequestException $e): bool
    {
        return in_array($e->response->status(), [429, 500, 502, 503, 504], true);
    }

    private function isAuthError(RequestException $e): bool
    {
        $status = $e->response->status();

        // 400 from Transit often carries "ciphertext or context invalid"
        return $status === 400;
    }
}
