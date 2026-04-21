<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Services;

use Aws\Kms\KmsClient;
use Closure;
use Crumbls\Sealcraft\Contracts\KekProvider;
use Crumbls\Sealcraft\Exceptions\SealcraftException;
use Crumbls\Sealcraft\Providers\AwsKmsKekProvider;
use Crumbls\Sealcraft\Providers\AzureKeyVaultKekProvider;
use Crumbls\Sealcraft\Providers\ConfigKekProvider;
use Crumbls\Sealcraft\Providers\GcpCloudKmsKekProvider;
use Crumbls\Sealcraft\Providers\LocalKekProvider;
use Crumbls\Sealcraft\Providers\NullKekProvider;
use Crumbls\Sealcraft\Providers\VaultTransitKekProvider;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Http\Client\Factory as HttpFactory;

/**
 * Resolves KEK providers by name from configuration. Drivers are
 * registered via extend() and resolved lazily; resolved instances are
 * memoized for the lifetime of the registry (container-scoped).
 */
final class ProviderRegistry
{
    /** @var array<string, Closure(array<string, mixed>, Application): KekProvider> */
    private array $drivers = [];

    /** @var array<string, KekProvider> */
    private array $resolved = [];

    public function __construct(
        private readonly Application $app,
        private readonly Repository $config,
    ) {
        $this->registerBuiltInDrivers();
    }

    /**
     * Register or override a driver factory.
     *
     * @param  Closure(array<string, mixed>, Application): KekProvider  $factory
     */
    public function extend(string $driver, Closure $factory): void
    {
        $this->drivers[$driver] = $factory;
        unset($this->resolved[$driver]);
    }

    public function provider(?string $name = null): KekProvider
    {
        $name ??= (string) $this->config->get('sealcraft.default_provider', 'local');

        if (isset($this->resolved[$name])) {
            return $this->resolved[$name];
        }

        $config = $this->config->get("sealcraft.providers.{$name}");

        if (! is_array($config)) {
            throw new SealcraftException("Sealcraft provider [{$name}] is not configured.");
        }

        $driver = (string) ($config['driver'] ?? $name);

        if (! isset($this->drivers[$driver])) {
            throw new SealcraftException("Sealcraft provider driver [{$driver}] is not registered.");
        }

        return $this->resolved[$name] = ($this->drivers[$driver])($config, $this->app);
    }

    public function default(): KekProvider
    {
        return $this->provider(null);
    }

    public function forget(string $name): void
    {
        unset($this->resolved[$name]);
    }

    private function registerBuiltInDrivers(): void
    {
        $this->drivers['local'] = function (array $config, Application $app): KekProvider {
            $path = isset($config['key_path']) && is_string($config['key_path']) && $config['key_path'] !== ''
                ? $config['key_path']
                : $app->storagePath('sealcraft/kek.key');

            return new LocalKekProvider(
                keyPath: $path,
                app: $app,
                allowProduction: (bool) ($config['allow_production'] ?? false),
            );
        };

        $this->drivers['null'] = fn (): KekProvider => new NullKekProvider;

        $this->drivers['config'] = function (array $config): KekProvider {
            $rawVersions = (array) ($config['versions'] ?? []);
            $decoded = [];

            foreach ($rawVersions as $name => $b64) {
                if (! is_string($name) || $name === '') {
                    throw new SealcraftException('ConfigKekProvider versions must be a keyed array (version => base64 bytes).');
                }

                if (! is_string($b64) || $b64 === '') {
                    continue;
                }

                $bytes = base64_decode($b64, true);

                if ($bytes === false) {
                    throw new SealcraftException("ConfigKekProvider version [{$name}] is not valid base64.");
                }

                if (strlen($bytes) !== ConfigKekProvider::KEY_BYTES) {
                    throw new SealcraftException(
                        "ConfigKekProvider version [{$name}] must decode to exactly " . ConfigKekProvider::KEY_BYTES . ' bytes.'
                    );
                }

                $decoded[$name] = $bytes;
            }

            if ($decoded === []) {
                throw new SealcraftException(
                    'ConfigKekProvider requires at least one base64-encoded 32-byte key in sealcraft.providers.config.versions.'
                );
            }

            $current = (string) ($config['current_version'] ?? array_key_first($decoded));

            return new ConfigKekProvider(
                versionBytes: $decoded,
                currentVersion: $current,
            );
        };

        $this->drivers['aws_kms'] = function (array $config): KekProvider {
            if (! class_exists(KmsClient::class)) {
                throw new SealcraftException(
                    'Install aws/aws-sdk-php to use the aws_kms provider: composer require aws/aws-sdk-php'
                );
            }

            $clientConfig = [
                'version' => $config['version'] ?? 'latest',
                'region' => $config['region'] ?? null,
            ];

            if (isset($config['endpoint'])) {
                $clientConfig['endpoint'] = $config['endpoint'];
            }

            if (isset($config['credentials']) && is_array($config['credentials'])) {
                $clientConfig['credentials'] = $config['credentials'];
            }

            return new AwsKmsKekProvider(
                client: new KmsClient(array_filter($clientConfig, static fn ($v): bool => $v !== null)),
                keyId: (string) ($config['key_id'] ?? ''),
            );
        };

        $this->drivers['gcp_kms'] = function (array $config, Application $app): KekProvider {
            return new GcpCloudKmsKekProvider(
                http: $app->make(HttpFactory::class),
                project: (string) ($config['project'] ?? ''),
                location: (string) ($config['location'] ?? ''),
                keyRing: (string) ($config['key_ring'] ?? ''),
                cryptoKey: (string) ($config['crypto_key'] ?? ''),
                tokenResolver: $config['token_resolver'] ?? fn (): string => (string) ($config['access_token'] ?? ''),
            );
        };

        $this->drivers['azure_key_vault'] = function (array $config, Application $app): KekProvider {
            return new AzureKeyVaultKekProvider(
                http: $app->make(HttpFactory::class),
                vaultUrl: (string) ($config['vault_url'] ?? ''),
                keyName: (string) ($config['key_name'] ?? ''),
                tokenResolver: $config['token_resolver'] ?? fn (): string => (string) ($config['access_token'] ?? ''),
                aadStrategy: (string) ($config['aad_strategy'] ?? AzureKeyVaultKekProvider::STRATEGY_SYNTHETIC),
                hmacKeyResolver: $config['hmac_key_resolver'] ?? null,
            );
        };

        $this->drivers['vault_transit'] = function (array $config, Application $app): KekProvider {
            return new VaultTransitKekProvider(
                http: $app->make(HttpFactory::class),
                address: (string) ($config['address'] ?? ''),
                keyName: (string) ($config['key_name'] ?? ''),
                tokenResolver: $config['token_resolver'] ?? fn (): string => (string) ($config['token'] ?? ''),
                mount: (string) ($config['mount'] ?? 'transit'),
            );
        };
    }
}
