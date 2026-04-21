<?php

declare(strict_types=1);

use Crumbls\Sealcraft\Models\DataKey;
use Illuminate\Support\Facades\Schema;

it('publishes the sealcraft config', function (): void {
    expect(config('sealcraft.default_provider'))->toBe('local');
    expect(config('sealcraft.default_cipher'))->toBe('aes-256-gcm');
    expect(config('sealcraft.dek_strategy'))->toBe('per_group');
    expect(config('sealcraft.table_name'))->toBe('sealcraft_data_keys');
});

it('runs the sealcraft_data_keys migration', function (): void {
    expect(Schema::hasTable('sealcraft_data_keys'))->toBeTrue();

    $columns = Schema::getColumnListing('sealcraft_data_keys');

    expect($columns)->toContain(
        'id',
        'context_type',
        'context_id',
        'provider_name',
        'key_id',
        'key_version',
        'cipher',
        'wrapped_dek',
        'created_at',
        'rotated_at',
        'retired_at',
    );
});

it('persists a DataKey and applies the active scope', function (): void {
    DataKey::query()->create([
        'context_type' => 'tenant',
        'context_id' => '42',
        'provider_name' => 'local',
        'key_id' => 'test-key',
        'key_version' => 'v1',
        'cipher' => 'aes-256-gcm',
        'wrapped_dek' => 'sc1:placeholder',
    ]);

    DataKey::query()->create([
        'context_type' => 'tenant',
        'context_id' => '99',
        'provider_name' => 'local',
        'key_id' => 'test-key',
        'key_version' => 'v1',
        'cipher' => 'aes-256-gcm',
        'wrapped_dek' => 'sc1:placeholder',
        'retired_at' => now(),
    ]);

    expect(DataKey::query()->active()->count())->toBe(1);
    expect(DataKey::query()->retired()->count())->toBe(1);
    expect(DataKey::query()->forContext('tenant', 42)->active()->count())->toBe(1);
    expect(DataKey::query()->forProvider('local')->count())->toBe(2);
});

it('allows multiple retired DataKeys for the same context (history)', function (): void {
    DataKey::query()->create([
        'context_type' => 'tenant',
        'context_id' => '7',
        'provider_name' => 'local',
        'key_id' => 'test-key',
        'cipher' => 'aes-256-gcm',
        'wrapped_dek' => 'sc1:placeholder',
        'retired_at' => now()->subDays(2),
    ]);

    DataKey::query()->create([
        'context_type' => 'tenant',
        'context_id' => '7',
        'provider_name' => 'local',
        'key_id' => 'test-key',
        'cipher' => 'aes-256-gcm',
        'wrapped_dek' => 'sc1:placeholder',
        'retired_at' => now()->subDay(),
    ]);

    DataKey::query()->create([
        'context_type' => 'tenant',
        'context_id' => '7',
        'provider_name' => 'local',
        'key_id' => 'test-key',
        'cipher' => 'aes-256-gcm',
        'wrapped_dek' => 'sc1:placeholder',
    ]);

    expect(DataKey::query()->forContext('tenant', 7)->count())->toBe(3);
    expect(DataKey::query()->forContext('tenant', 7)->active()->count())->toBe(1);
    expect(DataKey::query()->forContext('tenant', 7)->retired()->count())->toBe(2);
});

it('coerces integer context_id to string via the forContext scope', function (): void {
    DataKey::query()->create([
        'context_type' => 'tenant',
        'context_id' => '42',
        'provider_name' => 'local',
        'key_id' => 'test-key',
        'cipher' => 'aes-256-gcm',
        'wrapped_dek' => 'sc1:placeholder',
    ]);

    expect(DataKey::query()->forContext('tenant', 42)->exists())->toBeTrue();
    expect(DataKey::query()->forContext('tenant', '42')->exists())->toBeTrue();
});
