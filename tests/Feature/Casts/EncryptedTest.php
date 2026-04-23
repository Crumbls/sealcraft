<?php

declare(strict_types=1);

use Crumbls\Sealcraft\Events\DecryptionFailed;
use Crumbls\Sealcraft\Exceptions\DecryptionFailedException;
use Crumbls\Sealcraft\Exceptions\InvalidContextException;
use Crumbls\Sealcraft\Models\DataKey;
use Crumbls\Sealcraft\Services\DekCache;
use Crumbls\Sealcraft\Tests\Fixtures\EncryptedDocument;
use Crumbls\Sealcraft\Tests\Fixtures\EncryptedVaultEntry;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;

beforeEach(function (): void {
    config()->set('sealcraft.default_provider', 'null');
    config()->set('sealcraft.default_cipher', 'aes-256-gcm');
    config()->set('sealcraft.context_type', 'tenant');
    config()->set('sealcraft.context_column', 'tenant_id');

    $this->app->make(DekCache::class)->flush();
});

it('round-trips a plaintext attribute through the cast', function (): void {
    $doc = EncryptedDocument::query()->create([
        'tenant_id' => 42,
        'secret' => 'treasure map',
    ]);

    expect(strlen($doc->getRawOriginal('secret')))->toBeGreaterThan(0);
    expect($doc->getRawOriginal('secret'))->not->toBe('treasure map');

    $fresh = EncryptedDocument::query()->find($doc->id);
    expect($fresh->secret)->toBe('treasure map');
});

it('preserves null values without encrypting', function (): void {
    $doc = EncryptedDocument::query()->create([
        'tenant_id' => 42,
        'secret' => 'x',
        'note' => null,
    ]);

    expect($doc->getRawOriginal('note'))->toBeNull();

    $fresh = EncryptedDocument::query()->find($doc->id);
    expect($fresh->note)->toBeNull();
    expect($fresh->secret)->toBe('x');
});

it('raises DecryptionFailedException on cross-tenant ciphertext swap', function (): void {
    $a = EncryptedDocument::query()->create(['tenant_id' => 42, 'secret' => 'a-secret']);
    $b = EncryptedDocument::query()->create(['tenant_id' => 99, 'secret' => 'b-secret']);

    // Swap ciphertext directly at the DB layer — emulates a blob-level
    // theft + replay attack. forceFill would route through the cast and
    // re-encrypt, masking the scenario; DB::table bypasses the ORM.
    $aCiphertext = $a->getRawOriginal('secret');
    DB::table('encrypted_documents')->where('id', $b->id)->update(['secret' => $aCiphertext]);

    // Fetch a fresh model so no stale cast cache hides the failure.
    $tampered = EncryptedDocument::query()->find($b->id);

    Event::fake([DecryptionFailed::class]);

    expect(fn () => $tampered->secret)->toThrow(DecryptionFailedException::class);

    Event::assertDispatched(DecryptionFailed::class);
});

it('raises InvalidContextException when context column is missing', function (): void {
    expect(fn () => new EncryptedDocument(['secret' => 'no-tenant']))
        ->toThrow(InvalidContextException::class);
});

it('materializes at most one DataKey per tenant for per-group models', function (): void {
    EncryptedDocument::query()->create(['tenant_id' => 42, 'secret' => 'one']);
    EncryptedDocument::query()->create(['tenant_id' => 42, 'secret' => 'two']);
    EncryptedDocument::query()->create(['tenant_id' => 42, 'secret' => 'three']);

    expect(DataKey::query()->forContext('tenant', 42)->active()->count())->toBe(1);
});

it('refuses encrypted writes on a pre-existing row with empty sealcraft_key, then accepts them after backfill', function (): void {
    // Simulate the "pre-existing row gets sealcraft column added later"
    // flow: row exists in the DB with sealcraft_key NULL. The trait must
    // refuse to mint a throwaway context (which would orphan a DEK and
    // guarantee future decryption failure) until the operator backfills.
    DB::table('encrypted_vault_entries')->insert([
        'id' => 1000,
        'sealcraft_key' => null,
        'payload' => null,
    ]);

    $entry = EncryptedVaultEntry::query()->find(1000);
    expect($entry->sealcraft_key)->toBeNull();

    expect(fn () => $entry->payload = 'something sensitive')
        ->toThrow(InvalidContextException::class);

    // No DEK should have been minted by the failed write.
    expect(DataKey::query()->count())->toBe(0);

    // Operator runs the backfill command; the row now has a stable
    // sealcraft_key, so writes and round-trips succeed.
    Artisan::call('sealcraft:backfill-row-keys', ['model' => EncryptedVaultEntry::class]);

    $backfilledKey = DB::table('encrypted_vault_entries')->where('id', 1000)->value('sealcraft_key');
    expect($backfilledKey)->toBeString()->not->toBe('');

    $reloaded = EncryptedVaultEntry::query()->find(1000);
    $reloaded->payload = 'something sensitive';
    $reloaded->save();

    $raw = DB::table('encrypted_vault_entries')->where('id', 1000)->first();
    expect($raw->sealcraft_key)->toBe($backfilledKey);
    expect($raw->payload)->toStartWith('ag1:v1:');

    $this->app->make(DekCache::class)->flush();
    $fresh = EncryptedVaultEntry::query()->find(1000);
    expect($fresh->payload)->toBe('something sensitive');
});

it('creates a DataKey per row for per-row models', function (): void {
    $a = EncryptedVaultEntry::query()->create(['payload' => 'alpha']);
    $b = EncryptedVaultEntry::query()->create(['payload' => 'beta']);

    $morph = (new EncryptedVaultEntry)->getMorphClass();

    expect($a->sealcraft_key)->not->toBeNull();
    expect($b->sealcraft_key)->not->toBeNull();
    expect($a->sealcraft_key)->not->toBe($b->sealcraft_key);

    expect(DataKey::query()->forContext($morph, $a->sealcraft_key)->active()->count())->toBe(1);
    expect(DataKey::query()->forContext($morph, $b->sealcraft_key)->active()->count())->toBe(1);

    // Round-trip still works after a fresh fetch
    $aFresh = EncryptedVaultEntry::query()->find($a->id);
    $bFresh = EncryptedVaultEntry::query()->find($b->id);

    expect($aFresh->payload)->toBe('alpha');
    expect($bFresh->payload)->toBe('beta');
});
