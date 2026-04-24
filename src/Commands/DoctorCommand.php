<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Commands;

use Crumbls\Sealcraft\Exceptions\SealcraftException;
use Crumbls\Sealcraft\Services\CipherRegistry;
use Crumbls\Sealcraft\Services\ConfigValidator;
use Crumbls\Sealcraft\Services\DekCache;
use Crumbls\Sealcraft\Services\KeyManager;
use Crumbls\Sealcraft\Services\ProviderRegistry;
use Crumbls\Sealcraft\Values\EncryptionContext;
use Illuminate\Console\Command;
use Illuminate\Contracts\Config\Repository;
use Throwable;

/**
 * End-to-end diagnostic that combines every health check in one place:
 *
 *   1. Config validation (every sealcraft.* knob).
 *   2. Provider + cipher round-trip (like sealcraft:verify).
 *   3. Model inventory scan (like sealcraft:models).
 *
 * Exits non-zero if any step fails. Intended to be the first command a
 * dev (or deployment CI) runs after a `composer require` + install.
 */
final class DoctorCommand extends Command
{
    protected $signature = 'sealcraft:doctor
        {--skip-roundtrip : Skip the provider round-trip (useful in CI without KMS reach)}
        {--skip-models : Skip the model discovery scan}';

    protected $description = 'Run every Sealcraft health check: config validation, provider round-trip, and model inventory.';

    public function handle(
        Repository $config,
        ProviderRegistry $providers,
        CipherRegistry $ciphers,
        KeyManager $manager,
        DekCache $cache,
    ): int {
        $this->line('<info>Sealcraft doctor</info>');
        $this->line('');

        $allOk = true;

        // --- Step 1: config validation ---
        $this->line('<comment>[1/3]</comment> Config validation');
        try {
            ConfigValidator::validate((array) $config->get('sealcraft', []));
            $this->line('  <info>OK</info> sealcraft.* configuration is valid.');
        } catch (SealcraftException $e) {
            $this->line('  <error>FAIL</error> ' . $e->getMessage());
            $allOk = false;
        }
        $this->line('');

        // --- Step 2: provider + cipher round-trip ---
        $this->line('<comment>[2/3]</comment> Provider round-trip');
        if ($this->option('skip-roundtrip')) {
            $this->line('  <comment>SKIP</comment> (--skip-roundtrip)');
        } else {
            $ok = $this->runRoundtrip($providers, $ciphers, $manager, $cache);
            $allOk = $allOk && $ok;
        }
        $this->line('');

        // --- Step 3: model inventory ---
        $this->line('<comment>[3/3]</comment> Model inventory');
        if ($this->option('skip-models')) {
            $this->line('  <comment>SKIP</comment> (--skip-models)');
        } else {
            $this->call('sealcraft:models');
        }
        $this->line('');

        if ($allOk) {
            $this->line('<info>All Sealcraft checks passed.</info>');

            return self::SUCCESS;
        }

        $this->line('<error>One or more Sealcraft checks failed. See messages above.</error>');

        return self::FAILURE;
    }

    private function runRoundtrip(
        ProviderRegistry $providers,
        CipherRegistry $ciphers,
        KeyManager $manager,
        DekCache $cache,
    ): bool {
        $contextType = 'sealcraft_doctor';
        $contextId = 'smoke-' . bin2hex(random_bytes(4));
        $ctx = new EncryptionContext($contextType, $contextId);

        try {
            $provider = $providers->default();
            $this->line("  provider:  {$provider->name()} (key id: {$provider->currentKeyId()})");

            $cipherName = (string) config('sealcraft.default_cipher', 'aes-256-gcm');
            $cipher = $ciphers->cipher($cipherName);
            $this->line("  cipher:    {$cipher->name()}");

            $cache->flush();
            $manager->createDek($ctx);

            $cache->flush();
            $dek = $manager->getOrCreateDek($ctx);

            $plaintext = 'doctor-' . bin2hex(random_bytes(4));
            $envelope = $cipher->encrypt($plaintext, $dek, $ctx->toCanonicalBytes());
            $decrypted = $cipher->decrypt($envelope, $dek, $ctx->toCanonicalBytes());

            if ($decrypted !== $plaintext) {
                $manager->shredContext($ctx);
                $this->line('  <error>FAIL</error> cipher round-trip produced mismatched plaintext.');

                return false;
            }

            $manager->shredContext($ctx);
            $this->line('  <info>OK</info> round-trip succeeded.');

            return true;
        } catch (Throwable $e) {
            $this->line('  <error>FAIL</error> ' . $e->getMessage());

            try {
                $manager->shredContext($ctx);
            } catch (Throwable) {
                // best-effort cleanup only
            }

            return false;
        }
    }
}
