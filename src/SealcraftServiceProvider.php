<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft;

use Crumbls\Sealcraft\Commands\AuditCommand;
use Crumbls\Sealcraft\Commands\BackfillRowKeysCommand;
use Crumbls\Sealcraft\Commands\DoctorCommand;
use Crumbls\Sealcraft\Commands\GenerateDekCommand;
use Crumbls\Sealcraft\Commands\InstallCommand;
use Crumbls\Sealcraft\Commands\MigrateProviderCommand;
use Crumbls\Sealcraft\Commands\ModelsCommand;
use Crumbls\Sealcraft\Commands\ReencryptContextCommand;
use Crumbls\Sealcraft\Commands\RotateDekCommand;
use Crumbls\Sealcraft\Commands\RotateKekCommand;
use Crumbls\Sealcraft\Commands\ShredCommand;
use Crumbls\Sealcraft\Commands\VerifyCommand;
use Crumbls\Sealcraft\Services\CipherRegistry;
use Crumbls\Sealcraft\Services\ConfigValidator;
use Crumbls\Sealcraft\Services\DekCache;
use Crumbls\Sealcraft\Services\KeyManager;
use Crumbls\Sealcraft\Services\ProviderRegistry;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Foundation\Application;
use Illuminate\Database\ConnectionResolverInterface;
use Illuminate\Support\ServiceProvider;

class SealcraftServiceProvider extends ServiceProvider
{
    public function register(): void
    {
        $this->mergeConfigFrom(__DIR__ . '/../config/sealcraft.php', 'sealcraft');

        $this->app->singleton(ProviderRegistry::class, fn (Application $app): ProviderRegistry => new ProviderRegistry(
            app: $app,
            config: $app->make(Repository::class),
        ));

        $this->app->singleton(CipherRegistry::class, fn (Application $app): CipherRegistry => new CipherRegistry(
            config: $app->make(Repository::class),
        ));

        $this->app->singleton(DekCache::class, fn (Application $app): DekCache => new DekCache(
            maxEntries: (int) $app->make(Repository::class)->get('sealcraft.dek_cache.max_entries', 1024),
        ));

        $this->app->singleton(KeyManager::class, fn (Application $app): KeyManager => new KeyManager(
            providers: $app->make(ProviderRegistry::class),
            ciphers: $app->make(CipherRegistry::class),
            cache: $app->make(DekCache::class),
            config: $app->make(Repository::class),
            db: $app->make(ConnectionResolverInterface::class),
        ));
    }

    public function boot(): void
    {
        $this->registerMigrations();
        $this->registerPublishing();
        $this->registerCommands();
        $this->registerTerminatingFlush();
        $this->validateConfigOnBoot();
    }

    protected function validateConfigOnBoot(): void
    {
        if ((bool) $this->app->make(Repository::class)->get('sealcraft.validate_on_boot', true) !== true) {
            return;
        }

        $config = (array) $this->app->make(Repository::class)->get('sealcraft', []);

        ConfigValidator::validate($config);
    }

    protected function registerCommands(): void
    {
        if (! $this->app->runningInConsole()) {
            return;
        }

        $this->commands([
            AuditCommand::class,
            BackfillRowKeysCommand::class,
            DoctorCommand::class,
            GenerateDekCommand::class,
            InstallCommand::class,
            MigrateProviderCommand::class,
            ModelsCommand::class,
            ReencryptContextCommand::class,
            RotateDekCommand::class,
            RotateKekCommand::class,
            ShredCommand::class,
            VerifyCommand::class,
        ]);
    }

    protected function registerMigrations(): void
    {
        $this->loadMigrationsFrom(__DIR__ . '/../database/migrations');
    }

    protected function registerPublishing(): void
    {
        if (! $this->app->runningInConsole()) {
            return;
        }

        $this->publishes([
            __DIR__ . '/../config/sealcraft.php' => config_path('sealcraft.php'),
        ], 'sealcraft-config');

        $this->publishes([
            __DIR__ . '/../database/migrations/create_sealcraft_data_keys_table.php' => database_path(
                'migrations/' . date('Y_m_d_His') . '_create_sealcraft_data_keys_table.php'
            ),
        ], 'sealcraft-migrations');
    }

    protected function registerTerminatingFlush(): void
    {
        $this->app->terminating(function (): void {
            if ($this->app->resolved(DekCache::class)) {
                $this->app->make(DekCache::class)->flush();
            }
        });
    }
}
