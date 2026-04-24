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
 * Google Cloud KMS backed KEK provider.
 *
 * Talks to the Cloud KMS REST API via Laravel's HTTP client. Uses
 * cryptoKeys.encrypt / cryptoKeys.decrypt with
 * additionalAuthenticatedData bound to the canonical
 * EncryptionContext, so AAD is enforced at the service layer.
 *
 * DEK generation happens locally (random_bytes) and is wrapped in a
 * single KMS round-trip. GCP KMS doesn't expose a GenerateDataKey
 * equivalent, so we can't claim the GeneratesDataKeys capability.
 *
 * Auth is supplied by the caller: the `token_resolver` closure is
 * invoked per request to produce a bearer token. Apps typically bind
 * this to a GCP ADC helper; for tests, supply a static string.
 */
final class GcpCloudKmsKekProvider implements KekProvider, SupportsKeyVersioning, SupportsNativeAad
{
    public const NAME = 'gcp_kms';

    private const MAX_ATTEMPTS = 3;

    private const BASE_URL = 'https://cloudkms.googleapis.com';

    /**
     * @param  Closure(): string  $tokenResolver  Returns a GCP bearer token
     */
    public function __construct(
        private readonly HttpFactory $http,
        private readonly string $project,
        private readonly string $location,
        private readonly string $keyRing,
        private readonly string $cryptoKey,
        private readonly Closure $tokenResolver,
        private readonly string $baseUrl = self::BASE_URL,
    ) {}

    public function name(): string
    {
        return self::NAME;
    }

    public function currentKeyId(): string
    {
        return $this->resourceName();
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
            ->withToken(($this->tokenResolver)())
            ->acceptJson()
            ->asJson()
            ->throw()
            ->post("{$this->baseUrl}/v1/{$this->resourceName()}:encrypt", [
                'plaintext' => base64_encode($plaintextDek),
                'additionalAuthenticatedData' => base64_encode($ctx->toGcpAdditionalAuthenticatedData()),
            ]));

        $body = $response->json();

        if (! is_array($body) || ! isset($body['ciphertext'], $body['name'])) {
            throw new KekUnavailableException('GCP KMS encrypt response missing required fields.');
        }

        $ciphertext = base64_decode((string) $body['ciphertext'], true);

        if ($ciphertext === false) {
            throw new KekUnavailableException('GCP KMS encrypt response contained invalid base64.');
        }

        $resolvedKeyId = (string) $body['name'];
        $version = $this->extractVersionFromResourceName($resolvedKeyId);

        return new WrappedDek(
            ciphertext: $ciphertext,
            providerName: self::NAME,
            keyId: $this->resourceName(),
            keyVersion: $version,
            aadStrategy: ProviderCapabilities::AAD_NATIVE,
        );
    }

    public function unwrap(WrappedDek $wrapped, EncryptionContext $ctx): string
    {
        try {
            $response = $this->retrying(fn () => $this->http
                ->withToken(($this->tokenResolver)())
                ->acceptJson()
                ->asJson()
                ->throw()
                ->post("{$this->baseUrl}/v1/{$this->resourceName()}:decrypt", [
                    'ciphertext' => base64_encode($wrapped->ciphertext),
                    'additionalAuthenticatedData' => base64_encode($ctx->toGcpAdditionalAuthenticatedData()),
                ]));
        } catch (RequestException $e) {
            if ($this->isAuthError($e)) {
                throw new DecryptionFailedException('GCP KMS refused to decrypt: AAD mismatch or corruption.');
            }

            throw new KekUnavailableException('GCP KMS decrypt failed: ' . $e->getMessage(), 0, $e);
        }

        $body = $response->json();

        if (! is_array($body) || ! isset($body['plaintext'])) {
            throw new KekUnavailableException('GCP KMS decrypt response missing plaintext.');
        }

        $plaintext = base64_decode((string) $body['plaintext'], true);

        if ($plaintext === false) {
            throw new KekUnavailableException('GCP KMS decrypt response contained invalid base64.');
        }

        return $plaintext;
    }

    /**
     * @return array<int, string>
     */
    public function listKeyVersions(): array
    {
        $response = $this->retrying(fn () => $this->http
            ->withToken(($this->tokenResolver)())
            ->acceptJson()
            ->throw()
            ->get("{$this->baseUrl}/v1/{$this->resourceName()}/cryptoKeyVersions"));

        $body = $response->json();
        $versions = is_array($body) && isset($body['cryptoKeyVersions']) && is_array($body['cryptoKeyVersions'])
            ? $body['cryptoKeyVersions']
            : [];

        $out = [];

        foreach ($versions as $version) {
            if (! is_array($version) || ! isset($version['name'])) {
                continue;
            }

            $extracted = $this->extractVersionFromResourceName((string) $version['name']);

            if ($extracted !== null) {
                $out[] = $extracted;
            }
        }

        return $out;
    }

    public function wrapWithVersion(string $plaintextDek, EncryptionContext $ctx, string $version): WrappedDek
    {
        // GCP KMS uses the CryptoKey's active primary version for all
        // encrypt operations; version pinning happens by rotating the
        // primary rather than by specifying a version per-call.
        return $this->wrap($plaintextDek, $ctx);
    }

    private function resourceName(): string
    {
        return "projects/{$this->project}/locations/{$this->location}/keyRings/{$this->keyRing}/cryptoKeys/{$this->cryptoKey}";
    }

    private function extractVersionFromResourceName(string $resourceName): ?string
    {
        if (preg_match('#/cryptoKeyVersions/(\d+)$#', $resourceName, $m) !== 1) {
            return null;
        }

        return $m[1];
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
                throw new KekUnavailableException('GCP KMS client error: ' . $e->getMessage(), 0, $e);
            }
        }
    }

    private function isRetryable(RequestException $e): bool
    {
        $status = $e->response->status();

        return in_array($status, [429, 500, 502, 503, 504], true);
    }

    private function isAuthError(RequestException $e): bool
    {
        return $e->response->status() === 400
            || str_contains(strtolower((string) $e->response->body()), 'decryption failed');
    }
}
