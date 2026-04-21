<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Commands;

use Crumbls\Sealcraft\Models\DataKey;
use Crumbls\Sealcraft\Services\KeyManager;
use Crumbls\Sealcraft\Values\EncryptionContext;
use Illuminate\Console\Command;
use Throwable;

final class AuditCommand extends Command
{
    protected $signature = 'sealcraft:audit
        {--provider= : Filter to a specific KEK provider}
        {--context-type= : Filter to a specific context type}
        {--roundtrip : Round-trip a test DEK through every active DataKey (slow: N KMS calls)}';

    protected $description = 'Report sealcraft DEK health: counts, provider/version distribution, retired/shredded states, optional round-trip validation.';

    public function handle(KeyManager $manager): int
    {
        $query = DataKey::query();

        if (is_string($this->option('provider'))) {
            $query->forProvider((string) $this->option('provider'));
        }

        if (is_string($this->option('context-type'))) {
            $query->where('context_type', (string) $this->option('context-type'));
        }

        $active = (clone $query)->active()->count();
        $retired = (clone $query)->retired()->whereNull('shredded_at')->count();
        $shredded = (clone $query)->shredded()->count();

        $this->line(str_pad('Active DEKs', 32) . ": {$active}");
        $this->line(str_pad('Retired (rotated) DEKs', 32) . ": {$retired}");
        $this->line(str_pad('Shredded DEKs', 32) . ": {$shredded}");

        $this->line('');
        $this->info('Provider distribution:');
        $byProvider = (clone $query)->selectRaw('provider_name, count(*) as n')->groupBy('provider_name')->pluck('n', 'provider_name');

        foreach ($byProvider as $provider => $count) {
            $this->line('  ' . str_pad((string) $provider, 24) . ": {$count}");
        }

        $this->line('');
        $this->info('KEK version distribution (active only):');
        $byVersion = (clone $query)->active()
            ->selectRaw('coalesce(key_version, "-") as v, count(*) as n')
            ->groupBy('v')
            ->pluck('n', 'v');

        foreach ($byVersion as $version => $count) {
            $this->line('  ' . str_pad((string) $version, 24) . ": {$count}");
        }

        if (! $this->option('roundtrip')) {
            return self::SUCCESS;
        }

        $this->line('');
        $this->info('Round-trip validation against every active DataKey...');

        $failures = 0;

        (clone $query)->active()->chunkById(100, function ($rows) use ($manager, &$failures): void {
            foreach ($rows as $dataKey) {
                /** @var DataKey $dataKey */
                $ctx = new EncryptionContext(
                    contextType: $dataKey->context_type,
                    contextId: is_numeric($dataKey->context_id) && ctype_digit($dataKey->context_id)
                        ? (int) $dataKey->context_id
                        : $dataKey->context_id,
                );

                try {
                    $plaintext = $manager->getOrCreateDek($ctx);

                    if (strlen($plaintext) === 0) {
                        $failures++;
                        $this->warn("  [{$dataKey->context_type}:{$dataKey->context_id}] unwrapped to empty bytes");
                    }
                } catch (Throwable $e) {
                    $failures++;
                    $this->warn("  [{$dataKey->context_type}:{$dataKey->context_id}] unwrap failed: " . $e->getMessage());
                }
            }
        });

        if ($failures === 0) {
            $this->info('All active DataKeys unwrapped successfully.');

            return self::SUCCESS;
        }

        $this->error("{$failures} DataKey(s) failed round-trip validation.");

        return self::FAILURE;
    }
}
