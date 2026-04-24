<?php

declare(strict_types=1);

/*
 * Per-group and per-row strategies in the same app. Changes to one
 * strategy's contexts must not disturb the other. Rotation scoped to
 * one strategy's context must only touch that strategy's keys.
 */

use Crumbls\Sealcraft\Models\DataKey;
use Crumbls\Sealcraft\Services\DekCache;
use Crumbls\Sealcraft\Tests\Fixtures\EncryptedDocument;
use Crumbls\Sealcraft\Tests\Fixtures\EncryptedVaultEntry;
use Illuminate\Support\Facades\Artisan;

beforeEach(function (): void {
    config()->set('sealcraft.default_provider', 'null');
    config()->set('sealcraft.default_cipher', 'aes-256-gcm');
    config()->set('sealcraft.context_type', 'tenant');
    config()->set('sealcraft.context_column', 'tenant_id');

    $this->app->make(DekCache::class)->flush();
});

it('lets per-group and per-row models coexist without context leakage', function (): void {
    // Per-group: tenant-scoped document
    $doc = EncryptedDocument::query()->create(['tenant_id' => 500, 'secret' => 'tenant secret']);
    // Per-row: independent vault entry
    $vault = EncryptedVaultEntry::query()->create(['payload' => 'vault secret']);

    $morph = (new EncryptedVaultEntry)->getMorphClass();

    expect(DataKey::query()->forContext('tenant', '500')->active()->count())->toBe(1);
    expect(DataKey::query()->forContext($morph, $vault->sealcraft_key)->active()->count())->toBe(1);
    expect(DataKey::query()->count())->toBe(2);

    $this->app->make(DekCache::class)->flush();
    expect(EncryptedDocument::query()->find($doc->id)->secret)->toBe('tenant secret');
    expect(EncryptedVaultEntry::query()->find($vault->id)->payload)->toBe('vault secret');
});

it('scopes rotate-kek to the per-group context and leaves per-row DEKs untouched', function (): void {
    EncryptedDocument::query()->create(['tenant_id' => 600, 'secret' => 'tenant-a']);
    EncryptedVaultEntry::query()->create(['payload' => 'vault-a']);

    Artisan::call('sealcraft:rotate-kek', [
        '--context-type' => 'tenant',
        '--context-id' => '600',
    ]);

    $morph = (new EncryptedVaultEntry)->getMorphClass();

    expect(DataKey::query()->where('context_type', 'tenant')->whereNotNull('rotated_at')->count())->toBe(1);
    expect(DataKey::query()->where('context_type', $morph)->whereNotNull('rotated_at')->count())->toBe(0);
});

it('does not disturb per-row data when a per-group tenant_id changes', function (): void {
    $doc = EncryptedDocument::query()->create(['tenant_id' => 700, 'secret' => 'will-move']);
    $vault = EncryptedVaultEntry::query()->create(['payload' => 'stays-put']);

    // Move the per-group doc to a new tenant (auto-reencrypts)
    $doc->tenant_id = 701;
    $doc->save();

    $this->app->make(DekCache::class)->flush();

    // Per-group read uses the new tenant's DEK
    expect(EncryptedDocument::query()->find($doc->id)->secret)->toBe('will-move');

    // Per-row vault is totally untouched — same DEK, same ciphertext
    $vaultFresh = EncryptedVaultEntry::query()->find($vault->id);
    expect($vaultFresh->payload)->toBe('stays-put');
    expect($vaultFresh->getRawOriginal('payload'))->toBe($vault->getRawOriginal('payload'));
});
