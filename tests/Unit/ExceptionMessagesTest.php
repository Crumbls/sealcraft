<?php

declare(strict_types=1);

/*
 * Pins the actionable shape of every user-facing exception message so
 * a future refactor can't quietly regress the DX. Each assertion checks
 * that the message contains the phrase a developer would grep for when
 * debugging: the valid set of values, the env var to set, or the
 * command that fixes the problem.
 */

use Crumbls\Sealcraft\Exceptions\DecryptionFailedException;
use Crumbls\Sealcraft\Exceptions\SealcraftException;
use Crumbls\Sealcraft\Services\CipherRegistry;
use Crumbls\Sealcraft\Services\DekCache;
use Crumbls\Sealcraft\Services\ProviderRegistry;
use Crumbls\Sealcraft\Tests\Fixtures\EncryptedDocument;
use Illuminate\Support\Facades\DB;

beforeEach(function (): void {
    config()->set('sealcraft.default_provider', 'null');
    config()->set('sealcraft.default_cipher', 'aes-256-gcm');
    $this->app->make(DekCache::class)->flush();
});

it('ProviderRegistry lists valid provider names when an unknown provider is requested', function (): void {
    $registry = $this->app->make(ProviderRegistry::class);

    try {
        $registry->provider('definitely-not-a-provider');
    } catch (SealcraftException $e) {
        expect($e->getMessage())->toContain('Valid providers:');
        expect($e->getMessage())->toContain('null');
        expect($e->getMessage())->toContain('SEALCRAFT_PROVIDER');

        return;
    }

    throw new RuntimeException('expected SealcraftException');
});

it('ProviderRegistry lists valid drivers when an unknown driver is requested', function (): void {
    config()->set('sealcraft.providers.bogus', ['driver' => 'bogus_driver']);
    $registry = $this->app->make(ProviderRegistry::class);

    try {
        $registry->provider('bogus');
    } catch (SealcraftException $e) {
        expect($e->getMessage())->toContain('Valid drivers:');
        expect($e->getMessage())->toContain('local');
        expect($e->getMessage())->toContain('null');

        return;
    }

    throw new RuntimeException('expected SealcraftException');
});

it('CipherRegistry lists valid ciphers when an unknown cipher is requested', function (): void {
    $registry = $this->app->make(CipherRegistry::class);

    try {
        $registry->cipher('definitely-not-a-cipher');
    } catch (SealcraftException $e) {
        expect($e->getMessage())->toContain('Valid ciphers:');
        expect($e->getMessage())->toContain('aes-256-gcm');
        expect($e->getMessage())->toContain('SEALCRAFT_CIPHER');

        return;
    }

    throw new RuntimeException('expected SealcraftException');
});

it('CipherRegistry lists registered ids when cipherById is called with an unknown id', function (): void {
    $registry = $this->app->make(CipherRegistry::class);

    try {
        $registry->cipherById('xx');
    } catch (SealcraftException $e) {
        expect($e->getMessage())->toContain('Registered cipher ids:');
        expect($e->getMessage())->toContain('ag1');

        return;
    }

    throw new RuntimeException('expected SealcraftException');
});

it('Encrypted cast guides the caller toward the legacy migration path when it hits plaintext', function (): void {
    DB::table('encrypted_documents')->insert([
        'tenant_id' => 999,
        'secret' => 'pure plaintext',
    ]);

    $doc = EncryptedDocument::query()->where('tenant_id', 999)->first();

    try {
        $doc->secret;
    } catch (DecryptionFailedException $e) {
        expect($e->getMessage())->toContain('legacy plaintext');
        expect($e->getMessage())->toContain('getRawOriginal');
        expect($e->getMessage())->toContain('Migrating from APP_KEY');

        return;
    }

    throw new RuntimeException('expected DecryptionFailedException');
});

it('HasEncryptedAttributes per-row empty-key error names the backfill command', function (): void {
    \Illuminate\Support\Facades\DB::table('owned_users')->insert([
        'id' => 5001,
        'email' => 'empty-key@x',
        'sealcraft_key' => null,
    ]);

    $user = \Crumbls\Sealcraft\Tests\Fixtures\OwnedUser::query()->find(5001);

    try {
        $user->sealcraftContext();
    } catch (\Crumbls\Sealcraft\Exceptions\InvalidContextException $e) {
        expect($e->getMessage())->toContain('sealcraft:backfill-row-keys');

        return;
    }

    throw new RuntimeException('expected InvalidContextException');
});
