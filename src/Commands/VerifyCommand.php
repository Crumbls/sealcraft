<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Commands;

use Crumbls\Sealcraft\Services\CipherRegistry;
use Crumbls\Sealcraft\Services\DekCache;
use Crumbls\Sealcraft\Services\KeyManager;
use Crumbls\Sealcraft\Services\ProviderRegistry;
use Crumbls\Sealcraft\Values\EncryptionContext;
use Illuminate\Console\Command;
use Throwable;

/**
 * End-to-end smoke test of the configured provider + cipher: creates a
 * synthetic DEK, unwraps it, round-trips a known plaintext through the
 * cipher, and shreds the synthetic context so no residue is left. The
 * first command to run after `sealcraft:install` to confirm the
 * deployment actually talks to the KEK provider.
 */
final class VerifyCommand extends Command
{
    protected $signature = 'sealcraft:verify
        {--provider= : Verify a specific provider instead of the default}';

    protected $description = 'Round-trip a synthetic DEK through the configured provider and cipher to confirm end-to-end connectivity.';

    public function handle(
        ProviderRegistry $providers,
        CipherRegistry $ciphers,
        KeyManager $manager,
        DekCache $cache,
    ): int {
        $providerName = $this->option('provider');
        $contextType = 'sealcraft_verify';
        $contextId = 'smoke-' . bin2hex(random_bytes(4));
        $ctx = new EncryptionContext($contextType, $contextId);

        $started = microtime(true);

        try {
            $provider = is_string($providerName) && $providerName !== ''
                ? $providers->provider($providerName)
                : $providers->default();
        } catch (Throwable $e) {
            $this->error('Provider resolution failed: ' . $e->getMessage());

            return self::FAILURE;
        }

        $this->line('Provider:     ' . $provider->name());
        $this->line('Key id:       ' . $provider->currentKeyId());
        $this->line('Context:      ' . $contextType . ':' . $contextId);

        try {
            $cipherName = (string) config('sealcraft.default_cipher', 'aes-256-gcm');
            $cipher = $ciphers->cipher($cipherName);
        } catch (Throwable $e) {
            $this->error('Cipher resolution failed: ' . $e->getMessage());

            return self::FAILURE;
        }

        $this->line('Cipher:       ' . $cipher->name());

        $cache->flush();

        try {
            $dataKey = $manager->createDek($ctx, is_string($providerName) && $providerName !== '' ? $providerName : null);
        } catch (Throwable $e) {
            $this->error('DEK creation failed: ' . $e->getMessage());
            $this->warn('Check provider credentials and KMS reachability.');

            return self::FAILURE;
        }

        $this->line('DEK created:  DataKey#' . $dataKey->id . ' version=' . ($dataKey->key_version ?? '(n/a)'));

        $cache->flush();

        try {
            $manager->getOrCreateDek($ctx);
        } catch (Throwable $e) {
            $this->error('DEK unwrap failed: ' . $e->getMessage());
            $manager->shredContext($ctx);

            return self::FAILURE;
        }

        // Round-trip a known plaintext through the cipher with the same AAD
        $dek = $manager->getOrCreateDek($ctx);
        $plaintext = 'sealcraft-verify-' . bin2hex(random_bytes(4));

        try {
            $envelope = $cipher->encrypt($plaintext, $dek, $ctx->toCanonicalBytes());
            $decrypted = $cipher->decrypt($envelope, $dek, $ctx->toCanonicalBytes());
        } catch (Throwable $e) {
            $this->error('Cipher round-trip failed: ' . $e->getMessage());
            $manager->shredContext($ctx);

            return self::FAILURE;
        }

        if ($decrypted !== $plaintext) {
            $this->error('Cipher round-trip produced mismatched plaintext.');
            $manager->shredContext($ctx);

            return self::FAILURE;
        }

        $manager->shredContext($ctx);

        $elapsedMs = (int) round((microtime(true) - $started) * 1000);

        $this->line('');
        $this->info("Sealcraft verified: {$elapsedMs}ms end-to-end.");

        return self::SUCCESS;
    }
}
