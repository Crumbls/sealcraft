<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Commands;

use Crumbls\Sealcraft\Commands\Concerns\ResolvesEncryptionContext;
use Crumbls\Sealcraft\Models\DataKey;
use Crumbls\Sealcraft\Services\KeyManager;
use Illuminate\Console\Command;
use Throwable;

final class RotateKekCommand extends Command
{
    use ResolvesEncryptionContext;

    protected $signature = 'sealcraft:rotate-kek
        {--context-type= : Only rotate DataKeys with this context type}
        {--context-id= : Only rotate this single context id (requires --context-type)}
        {--provider= : Only rotate DataKeys wrapped by this provider}
        {--chunk=500 : Iterate DataKeys in chunks of this size}
        {--dry-run : Report what would be rotated without performing the operation}';

    protected $description = 'Rewrap active DataKeys under the current KEK version. Scope via --context-type, --context-id, or --provider; no scope rotates everything.';

    public function handle(KeyManager $manager): int
    {
        if (is_string($this->option('context-id')) && ! is_string($this->option('context-type'))) {
            $this->error('--context-id requires --context-type.');

            return self::FAILURE;
        }

        $query = DataKey::query()->active();

        $scope = [];

        if (is_string($this->option('context-type'))) {
            $query->where('context_type', (string) $this->option('context-type'));
            $scope[] = 'context_type=' . $this->option('context-type');
        }

        if (is_string($this->option('context-id'))) {
            $query->where('context_id', (string) $this->option('context-id'));
            $scope[] = 'context_id=' . $this->option('context-id');
        }

        if (is_string($this->option('provider'))) {
            $query->forProvider((string) $this->option('provider'));
            $scope[] = 'provider=' . $this->option('provider');
        }

        $chunk = max(1, (int) $this->option('chunk'));
        $total = (clone $query)->count();

        $this->info('Rotation scope: ' . ($scope === [] ? 'ALL active DataKeys' : implode(' ', $scope)));
        $this->info("Target DataKey count: {$total}");

        if ($total === 0) {
            return self::SUCCESS;
        }

        if ($this->option('dry-run')) {
            $this->line('(dry-run) no changes made.');

            return self::SUCCESS;
        }

        $rotated = 0;
        $failed = 0;

        $query->chunkById($chunk, function ($rows) use ($manager, &$rotated, &$failed): void {
            foreach ($rows as $dataKey) {
                /** @var DataKey $dataKey */
                $this->line("  rotating {$dataKey->context_type}:{$dataKey->context_id}...");

                try {
                    $ctx = $this->buildContext($dataKey->context_type, $dataKey->context_id);
                    $manager->rotateKek($ctx);
                    $rotated++;
                } catch (Throwable $e) {
                    $failed++;
                    $this->warn('    failed: ' . $e->getMessage());
                }
            }
        });

        $this->info("Rotated {$rotated} DataKey(s), {$failed} failure(s).");

        return $failed === 0 ? self::SUCCESS : self::FAILURE;
    }
}
