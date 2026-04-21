<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Providers;

use Closure;
use Crumbls\Sealcraft\Contracts\KekProvider;
use Crumbls\Sealcraft\Contracts\SupportsKeyVersioning;
use Crumbls\Sealcraft\Exceptions\DecryptionFailedException;
use Crumbls\Sealcraft\Exceptions\KekUnavailableException;
use Crumbls\Sealcraft\Exceptions\SealcraftException;
use Crumbls\Sealcraft\Values\EncryptionContext;
use Crumbls\Sealcraft\Values\ProviderCapabilities;
use Crumbls\Sealcraft\Values\WrappedDek;
use Illuminate\Http\Client\Factory as HttpFactory;
use Illuminate\Http\Client\RequestException;

/**
 * Azure Key Vault backed KEK provider.
 *
 * Azure's wrapKey / unwrapKey operations do not accept AAD natively,
 * which would leave the wrapped DEK vulnerable to cross-context
 * replay at the KEK layer (even though cipher-layer AAD still binds
 * the field ciphertext to its context).
 *
 * To recover defense-in-depth equivalent to AWS/GCP/Vault, this
 * provider defaults to a "synthetic AAD" strategy: before wrapping,
 * we prepend an HMAC-SHA256 of the canonical context over the DEK
 * using a separate Key Vault-stored HMAC secret. On unwrap we split
 * the HMAC off and verify it in constant time; a context mismatch
 * fails at that step before the DEK is ever returned.
 *
 * Apps that can accept the weaker posture (relying solely on
 * cipher-layer AAD and Key Vault RBAC) may select `cipher_only`
 * via config.
 */
final class AzureKeyVaultKekProvider implements KekProvider, SupportsKeyVersioning
{
    public const NAME = 'azure_kv';

    public const STRATEGY_SYNTHETIC = ProviderCapabilities::AAD_SYNTHETIC;

    public const STRATEGY_CIPHER_ONLY = ProviderCapabilities::AAD_NONE;

    private const ALGORITHM = 'RSA-OAEP-256';

    private const API_VERSION = '7.4';

    private const MAX_ATTEMPTS = 3;

    /**
     * @param  Closure(): string  $tokenResolver  Returns an Azure AD bearer token for Key Vault.
     * @param  Closure(): string  $hmacKeyResolver  Returns raw HMAC key bytes (for synthetic strategy).
     */
    public function __construct(
        private readonly HttpFactory $http,
        private readonly string $vaultUrl,
        private readonly string $keyName,
        private readonly Closure $tokenResolver,
        private readonly string $aadStrategy = self::STRATEGY_SYNTHETIC,
        private readonly ?Closure $hmacKeyResolver = null,
    ) {
        if (! in_array($this->aadStrategy, [self::STRATEGY_SYNTHETIC, self::STRATEGY_CIPHER_ONLY], true)) {
            throw new SealcraftException("Unknown Azure AAD strategy: {$this->aadStrategy}");
        }

        if ($this->aadStrategy === self::STRATEGY_SYNTHETIC && $this->hmacKeyResolver === null) {
            throw new SealcraftException(
                'AzureKeyVaultKekProvider: synthetic AAD strategy requires an hmacKeyResolver.'
            );
        }
    }

    public function name(): string
    {
        return self::NAME;
    }

    public function currentKeyId(): string
    {
        return rtrim($this->vaultUrl, '/') . '/keys/' . $this->keyName;
    }

    public function capabilities(): ProviderCapabilities
    {
        return new ProviderCapabilities(
            generatesDataKeys: false,
            hasNativeAad: $this->aadStrategy === self::STRATEGY_SYNTHETIC,
            supportsKeyVersioning: true,
            aadStrategy: $this->aadStrategy,
        );
    }

    public function wrap(string $plaintextDek, EncryptionContext $ctx): WrappedDek
    {
        $payload = $this->buildWrapPayload($plaintextDek, $ctx);

        $response = $this->retrying(fn () => $this->http
            ->withToken(($this->tokenResolver)())
            ->acceptJson()
            ->asJson()
            ->post($this->keyOperationUrl('wrapkey'), [
                'alg' => self::ALGORITHM,
                'value' => $this->base64UrlEncode($payload),
            ]));

        $body = $response->json();

        if (! is_array($body) || ! isset($body['value'])) {
            throw new KekUnavailableException('Azure Key Vault wrapkey response missing value field.');
        }

        $ciphertext = $this->base64UrlDecode((string) $body['value']);

        if ($ciphertext === false) {
            throw new KekUnavailableException('Azure Key Vault wrapkey returned invalid base64url.');
        }

        return new WrappedDek(
            ciphertext: $ciphertext,
            providerName: self::NAME,
            keyId: $this->currentKeyId(),
            keyVersion: isset($body['kid']) ? $this->extractVersionFromKid((string) $body['kid']) : null,
            aadStrategy: $this->aadStrategy,
        );
    }

    public function unwrap(WrappedDek $wrapped, EncryptionContext $ctx): string
    {
        try {
            $response = $this->retrying(fn () => $this->http
                ->withToken(($this->tokenResolver)())
                ->acceptJson()
                ->asJson()
                ->post($this->keyOperationUrl('unwrapkey'), [
                    'alg' => self::ALGORITHM,
                    'value' => $this->base64UrlEncode($wrapped->ciphertext),
                ]));
        } catch (RequestException $e) {
            throw new KekUnavailableException('Azure Key Vault unwrap failed: ' . $e->getMessage(), 0, $e);
        }

        $body = $response->json();

        if (! is_array($body) || ! isset($body['value'])) {
            throw new KekUnavailableException('Azure Key Vault unwrapkey response missing value field.');
        }

        $unwrapped = $this->base64UrlDecode((string) $body['value']);

        if ($unwrapped === false) {
            throw new KekUnavailableException('Azure Key Vault unwrapkey returned invalid base64url.');
        }

        return $this->stripSyntheticAad($unwrapped, $ctx);
    }

    /**
     * @return array<int, string>
     */
    public function listKeyVersions(): array
    {
        $url = rtrim($this->vaultUrl, '/') . '/keys/' . $this->keyName . '/versions?api-version=' . self::API_VERSION;

        $response = $this->retrying(fn () => $this->http
            ->withToken(($this->tokenResolver)())
            ->acceptJson()
            ->get($url));

        $body = $response->json();
        $items = is_array($body) && isset($body['value']) && is_array($body['value']) ? $body['value'] : [];

        $versions = [];

        foreach ($items as $item) {
            if (! is_array($item) || ! isset($item['kid'])) {
                continue;
            }

            $version = $this->extractVersionFromKid((string) $item['kid']);

            if ($version !== null) {
                $versions[] = $version;
            }
        }

        return $versions;
    }

    public function wrapWithVersion(string $plaintextDek, EncryptionContext $ctx, string $version): WrappedDek
    {
        // Pinning to a specific Azure key version requires a separate
        // URL path. For v1 we wrap under the current primary; version
        // pinning lands with the rotation command in Phase 6.
        return $this->wrap($plaintextDek, $ctx);
    }

    private function buildWrapPayload(string $plaintextDek, EncryptionContext $ctx): string
    {
        if ($this->aadStrategy === self::STRATEGY_CIPHER_ONLY) {
            return $plaintextDek;
        }

        $hmac = $ctx->toSyntheticAadHmac($this->hmacKey());

        return $hmac . $plaintextDek;
    }

    private function stripSyntheticAad(string $unwrapped, EncryptionContext $ctx): string
    {
        if ($this->aadStrategy === self::STRATEGY_CIPHER_ONLY) {
            return $unwrapped;
        }

        if (strlen($unwrapped) < 33) {
            throw new DecryptionFailedException('Azure unwrapped DEK is too short to contain synthetic AAD.');
        }

        $storedHmac = substr($unwrapped, 0, 32);
        $dek = substr($unwrapped, 32);

        $expected = $ctx->toSyntheticAadHmac($this->hmacKey());

        if (! hash_equals($expected, $storedHmac)) {
            throw new DecryptionFailedException('Azure synthetic AAD HMAC mismatch: context does not match.');
        }

        return $dek;
    }

    private function hmacKey(): string
    {
        if ($this->hmacKeyResolver === null) {
            throw new SealcraftException('HMAC key resolver is required for synthetic AAD strategy.');
        }

        return ($this->hmacKeyResolver)();
    }

    private function keyOperationUrl(string $operation): string
    {
        return rtrim($this->vaultUrl, '/')
            . '/keys/' . $this->keyName
            . '/' . $operation
            . '?api-version=' . self::API_VERSION;
    }

    private function extractVersionFromKid(string $kid): ?string
    {
        $parts = explode('/', $kid);

        return $parts[count($parts) - 1] ?: null;
    }

    private function base64UrlEncode(string $bytes): string
    {
        return rtrim(strtr(base64_encode($bytes), '+/', '-_'), '=');
    }

    private function base64UrlDecode(string $encoded): string|false
    {
        $pad = strlen($encoded) % 4;

        if ($pad > 0) {
            $encoded .= str_repeat('=', 4 - $pad);
        }

        return base64_decode(strtr($encoded, '-_', '+/'), true);
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
                throw new KekUnavailableException('Azure Key Vault client error: ' . $e->getMessage(), 0, $e);
            }
        }
    }

    private function isRetryable(RequestException $e): bool
    {
        return in_array($e->response->status(), [429, 500, 502, 503, 504], true);
    }
}
