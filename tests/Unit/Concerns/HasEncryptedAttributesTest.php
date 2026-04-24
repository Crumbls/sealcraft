<?php

declare(strict_types=1);

use Crumbls\Sealcraft\Casts\Encrypted;
use Crumbls\Sealcraft\Casts\EncryptedJson;
use Crumbls\Sealcraft\Concerns\HasEncryptedAttributes;
use Crumbls\Sealcraft\Exceptions\InvalidContextException;
use Crumbls\Sealcraft\Tests\Unit\Concerns\Probes\ConfigOnlyProbe;
use Crumbls\Sealcraft\Tests\Unit\Concerns\Probes\PerGroupProbe;
use Crumbls\Sealcraft\Tests\Unit\Concerns\Probes\PerGroupWithCastsProbe;
use Crumbls\Sealcraft\Tests\Unit\Concerns\Probes\PerRowProbe;
use Crumbls\Sealcraft\Tests\Unit\Concerns\Probes\TypedPerRowProbe;

/*
 * Dedicated probe classes live under tests/Unit/Concerns/Probes so the
 * trait's resolvers can be tested with real declared-property state.
 * `Model::__set` routes all dynamic property writes into the attribute
 * bag, so "$probe->sealcraftStrategy = 'per_row'" from outside has no
 * effect — the only way to exercise the property-resolution branch of
 * the trait is with classes that declare these properties.
 */

// --- resolveSealcraftStrategy --------------------------------------------

it('resolves strategy from the model property when set', function (): void {
    expect((new PerRowProbe)->callResolveStrategy())->toBe('per_row');
});

it('falls back to config for strategy when no property is set', function (): void {
    config()->set('sealcraft.dek_strategy', 'per_row');
    expect((new ConfigOnlyProbe)->callResolveStrategy())->toBe('per_row');
});

it('defaults to per_group when neither property nor env override is set', function (): void {
    expect((new ConfigOnlyProbe)->callResolveStrategy())->toBe('per_group');
});

it('defaults to per_group when config is explicitly null (hardening against env misconfiguration)', function (): void {
    config()->set('sealcraft.dek_strategy', null);
    expect((new ConfigOnlyProbe)->callResolveStrategy())->toBe('per_group');
});

it('defaults to per_group when config is explicitly empty string', function (): void {
    config()->set('sealcraft.dek_strategy', '');
    expect((new ConfigOnlyProbe)->callResolveStrategy())->toBe('per_group');
});

it('defaults context column to tenant_id when config is null', function (): void {
    config()->set('sealcraft.context_column', null);
    expect((new ConfigOnlyProbe)->callResolveContextColumn())->toBe('tenant_id');
});

it('defaults context type to tenant when config is null', function (): void {
    config()->set('sealcraft.context_type', null);
    expect((new ConfigOnlyProbe)->callResolveContextType())->toBe('tenant');
});

// --- resolveSealcraftContextType ----------------------------------------

it('resolves context type from the model property when set', function (): void {
    expect((new TypedPerRowProbe)->callResolveContextType())->toBe('patient');
});

it('falls back to config for context type', function (): void {
    config()->set('sealcraft.context_type', 'customer');
    expect((new ConfigOnlyProbe)->callResolveContextType())->toBe('customer');
});

// --- resolveSealcraftContextColumn --------------------------------------

it('resolves context column from the model property when set', function (): void {
    expect((new PerGroupProbe)->callResolveContextColumn())->toBe('tenant_id');
});

it('falls back to config for context column', function (): void {
    config()->set('sealcraft.context_column', 'owner_id');
    expect((new ConfigOnlyProbe)->callResolveContextColumn())->toBe('owner_id');
});

// --- resolveSealcraftRowContextType -------------------------------------

it('uses context type property for per-row context type too', function (): void {
    expect((new TypedPerRowProbe)->callResolveRowContextType())->toBe('patient');
});

it('falls back to morph class for per-row context type', function (): void {
    $probe = new PerRowProbe;
    expect($probe->callResolveRowContextType())->toBe($probe->getMorphClass());
});

// --- resolveSealcraftRowKeyColumn ---------------------------------------

it('defaults row-key column to sealcraft_key', function (): void {
    expect((new PerRowProbe)->callResolveRowKeyColumn())->toBe('sealcraft_key');
});

// --- sealcraftEncryptedAttributes ---------------------------------------

it('introspects casts to find Encrypted and EncryptedJson columns', function (): void {
    expect((new PerGroupWithCastsProbe)->callEncryptedAttributes())->toEqual(['ssn', 'history']);
});

it('returns an empty array when no encrypted casts are declared', function (): void {
    expect((new ConfigOnlyProbe)->callEncryptedAttributes())->toEqual([]);
});

// --- ensureSealcraftRowKeyMinted ----------------------------------------

it('mints a UUID for per-row models when row-key column is empty', function (): void {
    $probe = new PerRowProbe;

    expect($probe->getAttributes()['sealcraft_key'] ?? null)->toBeNull();
    $probe->callEnsureRowKeyMinted();

    expect($probe->getAttributes()['sealcraft_key'])
        ->toBeString()
        ->and(strlen($probe->getAttributes()['sealcraft_key']))->toBe(36);
});

it('does not overwrite an existing row-key value on mint', function (): void {
    $probe = new PerRowProbe;
    $probe->setRawAttribute('sealcraft_key', 'preserve-me');

    $probe->callEnsureRowKeyMinted();

    expect($probe->getAttributes()['sealcraft_key'])->toBe('preserve-me');
});

it('is a no-op for per-group models', function (): void {
    $probe = new PerGroupProbe;

    $probe->callEnsureRowKeyMinted();

    expect(array_key_exists('sealcraft_key', $probe->getAttributes()))->toBeFalse();
});

// --- sealcraftContext() ------------------------------------------------

it('derives a per-group context from the configured column', function (): void {
    $probe = new PerGroupProbe;
    $probe->setRawAttribute('tenant_id', 42);

    $ctx = $probe->sealcraftContext();
    expect($ctx->contextType)->toBe('tenant');
    expect($ctx->contextId)->toBe(42);
});

it('throws when per-group context column is empty on a loaded model', function (): void {
    $probe = new PerGroupProbe;

    expect(fn () => $probe->sealcraftContext())
        ->toThrow(InvalidContextException::class, 'Per-group Sealcraft strategy requires column');
});

it('derives a per-row context from the row-key column', function (): void {
    $probe = new PerRowProbe;
    $probe->setRawAttribute('sealcraft_key', 'fixed-uuid-1234');

    $ctx = $probe->sealcraftContext();
    expect($ctx->contextType)->toBe($probe->getMorphClass());
    expect($ctx->contextId)->toBe('fixed-uuid-1234');
});

it('auto-mints a context on unsaved per-row models when row-key is empty', function (): void {
    $probe = new PerRowProbe;

    $ctx = $probe->sealcraftContext();
    expect($ctx->contextId)->toBeString();
    expect(strlen((string) $ctx->contextId))->toBe(36);
});

it('throws on per-row model with empty row-key if the row was loaded from DB', function (): void {
    $probe = new PerRowProbe;
    $probe->exists = true;
    $probe->setRawAttribute($probe->getKeyName(), 99);

    expect(fn () => $probe->sealcraftContext())
        ->toThrow(InvalidContextException::class, 'backfill-row-keys');
});
