<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Commands;

use Crumbls\Sealcraft\Commands\Concerns\ResolvesEncryptionContext;
use Crumbls\Sealcraft\Services\KeyManager;
use Illuminate\Console\Command;

final class ShredCommand extends Command
{
    use ResolvesEncryptionContext;

    protected $signature = 'sealcraft:shred
        {context_type : Context type (e.g. "tenant", "patient", or a model FQN)}
        {context_id : Context identifier}
        {--force : Skip the interactive confirmation}';

    protected $description = 'Crypto-shred a context: retire its DEK without re-encryption, making all data under it permanently unrecoverable.';

    public function handle(KeyManager $manager): int
    {
        $ctx = $this->buildContext((string) $this->argument('context_type'), (string) $this->argument('context_id'));

        $this->warn("This will DESTROY every ciphertext ever encrypted under context [{$ctx->contextType}:{$ctx->contextId}].");
        $this->warn('The underlying row data stays on disk but becomes permanently unrecoverable. There is no undo.');

        if (! $this->option('force')) {
            $confirmation = (string) $this->ask("Type the context id [{$ctx->contextId}] to confirm");

            if ($confirmation !== (string) $ctx->contextId) {
                $this->info('Aborted: confirmation did not match.');

                return self::FAILURE;
            }
        }

        $manager->shredContext($ctx);

        $this->info("Context [{$ctx->contextType}:{$ctx->contextId}] has been crypto-shredded.");

        return self::SUCCESS;
    }
}
