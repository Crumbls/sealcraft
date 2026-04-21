<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Commands;

use Crumbls\Sealcraft\Commands\Concerns\ResolvesEncryptionContext;
use Crumbls\Sealcraft\Models\DataKey;
use Crumbls\Sealcraft\Services\KeyManager;
use Illuminate\Console\Command;
use Throwable;

final class MigrateProviderCommand extends Command
{
    use ResolvesEncryptionContext;

    protected $signature = 'sealcraft:migrate-provider
        {--from= : Source provider name (required)}
        {--to= : Target provider name (required)}
        {--context-type= : Only migrate DataKeys with this context type}
        {--context-id= : Only migrate this single context id (requires --context-type)}
        {--chunk=500 : Iterate DataKeys in chunks of this size}
        {--dry-run : Report what would migrate without performing the operation}';

    protected $description = 'Rewrap DataKeys from one KEK provider to another. Original rows are retired; new active rows are created under the target provider.';

    public function handle(KeyManager $manager): int
    {
        $from = $this->option('from');
        $to = $this->option('to');

        if (! is_string($from) || ! is_string($to) || $from === '' || $to === '' || $from === $to) {
            $this->error('Both --from and --to are required and must differ.');

            return self::FAILURE;
        }

        if (is_string($this->option('context-id')) && ! is_string($this->option('context-type'))) {
            $this->error('--context-id requires --context-type.');

            return self::FAILURE;
        }

        $query = DataKey::query()->active()->forProvider($from);

        if (is_string($this->option('context-type'))) {
            $query->where('context_type', (string) $this->option('context-type'));
        }

        if (is_string($this->option('context-id'))) {
            $query->where('context_id', (string) $this->option('context-id'));
        }

        $chunk = max(1, (int) $this->option('chunk'));
        $total = (clone $query)->count();

        $this->info("Migrating DataKeys from [{$from}] to [{$to}]. Target count: {$total}.");

        if ($total === 0) {
            return self::SUCCESS;
        }

        if ($this->option('dry-run')) {
            $this->line('(dry-run) no changes made.');

            return self::SUCCESS;
        }

        $moved = 0;
        $failed = 0;

        $query->chunkById($chunk, function ($rows) use ($manager, $from, $to, &$moved, &$failed): void {
            foreach ($rows as $dataKey) {
                /** @var DataKey $dataKey */
                $this->line("  migrating {$dataKey->context_type}:{$dataKey->context_id}...");

                try {
                    $ctx = $this->buildContext($dataKey->context_type, $dataKey->context_id);
                    $manager->migrateProvider($ctx, $from, $to);
                    $moved++;
                } catch (Throwable $e) {
                    $failed++;
                    $this->warn('    failed: ' . $e->getMessage());
                }
            }
        });

        $this->info("Migrated {$moved} DataKey(s), {$failed} failure(s).");

        return $failed === 0 ? self::SUCCESS : self::FAILURE;
    }
}
