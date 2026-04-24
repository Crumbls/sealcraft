<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Commands;

use Illuminate\Console\Command;

/**
 * One-shot onboarding command. Publishes config, publishes the
 * migration, runs migrate, and prints next steps. Idempotent — safe
 * to run again after each step without duplicating published files.
 *
 * In production, `migrate` itself prompts before running unless
 * `--force` is passed. This command forwards `--force` to both the
 * `vendor:publish` calls (so existing published files are overwritten)
 * and to `migrate` (so the production confirmation prompt is skipped).
 */
final class InstallCommand extends Command
{
    protected $signature = 'sealcraft:install
        {--force : Overwrite previously published config/migration files AND skip the production migrate confirmation prompt}
        {--no-migrate : Skip running migrations after publishing (useful when CI runs migrations separately)}';

    protected $description = 'Publish config + migrations and run migrate in one step. Run after `composer require crumbls/sealcraft`.';

    public function handle(): int
    {
        $force = (bool) $this->option('force');

        $this->info('Publishing Sealcraft config...');
        if (file_exists(config_path('sealcraft.php')) && ! $force) {
            $this->line('  config/sealcraft.php already exists; skipping (use --force to overwrite).');
        } else {
            $this->call('vendor:publish', [
                '--tag' => 'sealcraft-config',
                '--force' => $force,
            ]);
        }

        $this->info('Publishing Sealcraft migration...');
        $existing = $this->findExistingSealcraftMigration();
        if ($existing !== null && ! $force) {
            $this->line("  {$existing} already exists; skipping (use --force to republish).");
        } else {
            $this->call('vendor:publish', [
                '--tag' => 'sealcraft-migrations',
                '--force' => $force,
            ]);
        }

        if (! $this->option('no-migrate')) {
            $this->info('Running migrations...');
            // Forward --force so `migrate` does not prompt in production.
            // Without this, a developer who passed --force to sealcraft:install
            // on a production box would still be stopped by migrate's confirm.
            $this->call('migrate', $force ? ['--force' => true] : []);
        }

        $this->line('');
        $this->info('Sealcraft is ready.');
        $this->line('');
        $this->line('Next steps:');
        $this->line('  1. Pick a KEK provider: SEALCRAFT_PROVIDER=aws_kms|gcp_kms|azure_key_vault|vault_transit|local');
        $this->line('  2. Add use HasEncryptedAttributes; to a model');
        $this->line('  3. Cast a column:  protected $casts = [\'ssn\' => \Crumbls\Sealcraft\Casts\Encrypted::class];');
        $this->line('  4. Verify end-to-end:  php artisan sealcraft:verify');
        $this->line('');

        return self::SUCCESS;
    }

    private function findExistingSealcraftMigration(): ?string
    {
        $files = glob(database_path('migrations/*_create_sealcraft_data_keys_table.php'));

        if ($files === false || $files === []) {
            return null;
        }

        return 'database/migrations/' . basename($files[0]);
    }
}
