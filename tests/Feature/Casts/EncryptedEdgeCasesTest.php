<?php

declare(strict_types=1);

/*
 * Real-world Eloquent usage patterns that developers will hit on day 1:
 * mass assignment, replication, fresh reads across instances, and the
 * "silently returns no rows" trap of querying an encrypted column by
 * plaintext.
 */

use Crumbls\Sealcraft\Models\DataKey;
use Crumbls\Sealcraft\Services\DekCache;
use Crumbls\Sealcraft\Tests\Fixtures\EncryptedDocument;
use Crumbls\Sealcraft\Tests\Fixtures\OwnedUser;

beforeEach(function (): void {
    config()->set('sealcraft.default_provider', 'null');
    config()->set('sealcraft.default_cipher', 'aes-256-gcm');
    config()->set('sealcraft.context_type', 'tenant');
    config()->set('sealcraft.context_column', 'tenant_id');
    $this->app->make(DekCache::class)->flush();
});

it('handles mass assignment of encrypted columns', function (): void {
    $doc = EncryptedDocument::query()->create([
        'tenant_id' => 1,
        'secret' => 'alpha',
        'note' => 'beta',
    ]);

    $this->app->make(DekCache::class)->flush();

    $fresh = EncryptedDocument::query()->find($doc->id);
    expect($fresh->secret)->toBe('alpha');
    expect($fresh->note)->toBe('beta');
});

it('handles update() with encrypted columns', function (): void {
    $doc = EncryptedDocument::query()->create(['tenant_id' => 1, 'secret' => 'original']);

    $doc->update(['secret' => 'updated']);

    $this->app->make(DekCache::class)->flush();
    expect(EncryptedDocument::query()->find($doc->id)->secret)->toBe('updated');
});

it('returns zero rows when querying an encrypted column by plaintext (expected: plaintext does not match ciphertext)', function (): void {
    EncryptedDocument::query()->create(['tenant_id' => 1, 'secret' => 'findme']);
    $this->app->make(DekCache::class)->flush();

    $rows = EncryptedDocument::query()->where('secret', 'findme')->get();

    expect($rows)->toHaveCount(0);
});

it('replicates a per-group model with encrypted columns correctly', function (): void {
    $original = EncryptedDocument::query()->create([
        'tenant_id' => 42,
        'secret' => 'replicate-me',
    ]);

    $copy = $original->replicate();
    $copy->save();

    $this->app->make(DekCache::class)->flush();

    $freshOriginal = EncryptedDocument::query()->find($original->id);
    $freshCopy = EncryptedDocument::query()->find($copy->id);

    expect($freshOriginal->secret)->toBe('replicate-me');
    expect($freshCopy->secret)->toBe('replicate-me');
    expect($freshCopy->id)->not->toBe($original->id);

    // Both live under the same per-group tenant DEK
    expect(DataKey::query()->forContext('tenant', '42')->active()->count())->toBe(1);
});

it('replicates a per-row model and mints a fresh sealcraft_key for the copy', function (): void {
    $original = OwnedUser::query()->create(['email' => 'orig@x', 'ssn' => '111-22-3333']);

    $copy = $original->replicate();
    $copy->save();

    expect($copy->sealcraft_key)->not->toBe($original->sealcraft_key);

    $this->app->make(DekCache::class)->flush();
    expect(OwnedUser::query()->find($copy->id)->ssn)->toBe('111-22-3333');

    $morph = (new OwnedUser)->getMorphClass();
    // Per-row means each row has its own DEK, so replicate produces a new DEK
    expect(DataKey::query()->forContext($morph, $original->sealcraft_key)->active()->count())->toBe(1);
    expect(DataKey::query()->forContext($morph, $copy->sealcraft_key)->active()->count())->toBe(1);
});

it('returns fresh values after $model->refresh()', function (): void {
    $doc = EncryptedDocument::query()->create(['tenant_id' => 1, 'secret' => 'v1']);

    EncryptedDocument::query()->where('id', $doc->id)->update(['secret' => $doc->getRawOriginal('secret')]);
    $doc->refresh();

    expect($doc->secret)->toBe('v1');
});
