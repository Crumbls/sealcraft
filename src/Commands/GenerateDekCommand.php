<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Commands;

use Crumbls\Sealcraft\Commands\Concerns\ResolvesEncryptionContext;
use Crumbls\Sealcraft\Exceptions\SealcraftException;
use Crumbls\Sealcraft\Services\KeyManager;
use Illuminate\Console\Command;

final class GenerateDekCommand extends Command
{
    use ResolvesEncryptionContext;

    protected $signature = 'sealcraft:generate-dek
        {context_type : Context type (e.g. "tenant", "patient", or a model FQN)}
        {context_id : Context identifier}
        {--provider= : Override the default KEK provider}';

    protected $description = 'Provision a new active DEK for a context (fails if one already exists).';

    public function handle(KeyManager $manager): int
    {
        $ctx = $this->buildContext((string) $this->argument('context_type'), (string) $this->argument('context_id'));
        $provider = $this->option('provider');

        $this->info("Creating DEK for context [{$ctx->contextType}:{$ctx->contextId}]" . ($provider ? " using provider [{$provider}]" : '') . '...');

        try {
            $dataKey = $manager->createDek($ctx, is_string($provider) ? $provider : null);
        } catch (SealcraftException $e) {
            $this->error($e->getMessage());

            return self::FAILURE;
        }

        $this->info("DataKey id {$dataKey->id} created under provider [{$dataKey->provider_name}] key_id [{$dataKey->key_id}].");

        return self::SUCCESS;
    }
}
