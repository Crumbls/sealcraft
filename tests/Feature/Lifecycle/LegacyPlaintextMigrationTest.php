<?php

declare(strict_types=1);

/*
 * Real-world adoption state: when a table already contains rows and
 * sealcraft is turned on for the first time.
 *
 * The scalar `Encrypted` cast does NOT pass plaintext through — it
 * throws DecryptionFailedException so you get a loud signal that
 * something is unencrypted when it should be. The `EncryptedJson` cast
 * DOES tolerate unencrypted leaves so JSON columns can mix plaintext
 * shape data with encrypted leaves (README line 111-113).
 *
 * The documented migration path (README "Migrating from APP_KEY /
 * encrypted cast") is: read each legacy column OUT OF BAND, re-assign
 * it through the `Encrypted` cast on the model, save. This test pins
 * both behaviors: the loud-signal refusal, and the assign-to-upgrade
 * round-trip.
 */

use Crumbls\Sealcraft\Exceptions\DecryptionFailedException;
use Crumbls\Sealcraft\Services\CipherRegistry;
use Crumbls\Sealcraft\Services\DekCache;
use Crumbls\Sealcraft\Tests\Fixtures\EncryptedDocument;
use Illuminate\Support\Facades\DB;

beforeEach(function (): void {
    config()->set('sealcraft.default_provider', 'null');
    config()->set('sealcraft.default_cipher', 'aes-256-gcm');
    config()->set('sealcraft.context_type', 'tenant');
    config()->set('sealcraft.context_column', 'tenant_id');

    $this->app->make(DekCache::class)->flush();
});

it('peekId returns null for legacy plaintext values that look nothing like an envelope', function (): void {
    $ciphers = $this->app->make(CipherRegistry::class);

    expect($ciphers->peekId('plain string value'))->toBeNull();
    expect($ciphers->peekId('data:image/png;base64,iVBORw0K...'))->toBeNull();
    expect($ciphers->peekId('https://example.com/path'))->toBeNull();
    expect($ciphers->peekId('mailto:test@example.com'))->toBeNull();
    expect($ciphers->peekId('{"legacy": "json"}'))->toBeNull();
});

it('raises DecryptionFailedException when the Encrypted cast reads a plaintext row (loud-signal by design)', function (): void {
    $tenantId = 800;

    DB::table('encrypted_documents')->insert([
        'tenant_id' => $tenantId,
        'secret' => 'legacy plaintext',
    ]);

    $doc = EncryptedDocument::query()->where('tenant_id', $tenantId)->first();

    expect(fn () => $doc->secret)->toThrow(DecryptionFailedException::class);
});

it('upgrades a plaintext row when the caller reads it out of band and reassigns through the cast', function (): void {
    $tenantId = 810;

    $id = DB::table('encrypted_documents')->insertGetId([
        'tenant_id' => $tenantId,
        'secret' => 'legacy plaintext',
    ]);

    // The documented migration path: read raw, assign through cast, save.
    $rawPlaintext = DB::table('encrypted_documents')->where('id', $id)->value('secret');
    $doc = EncryptedDocument::query()->find($id);
    $doc->secret = $rawPlaintext;
    $doc->save();

    // Raw column is now a cipher envelope
    expect(DB::table('encrypted_documents')->where('id', $id)->value('secret'))->toStartWith('ag1:v1:');

    // And reads back as the original plaintext
    $this->app->make(DekCache::class)->flush();
    expect(EncryptedDocument::query()->find($id)->secret)->toBe('legacy plaintext');
});
