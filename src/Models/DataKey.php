<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Models;

use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Carbon;

/**
 * @property int $id
 * @property string $context_type
 * @property string $context_id
 * @property string $provider_name
 * @property string $key_id
 * @property string|null $key_version
 * @property string $cipher
 * @property string $wrapped_dek
 * @property Carbon $created_at
 * @property Carbon|null $rotated_at
 * @property Carbon|null $retired_at
 * @property Carbon|null $shredded_at
 */
class DataKey extends Model
{
    public const UPDATED_AT = null;

    protected $guarded = [];

    protected $casts = [
        'created_at' => 'datetime',
        'rotated_at' => 'datetime',
        'retired_at' => 'datetime',
        'shredded_at' => 'datetime',
    ];

    public function getTable(): string
    {
        return (string) config('sealcraft.table_name', 'sealcraft_data_keys');
    }

    public function scopeActive(Builder $query): Builder
    {
        return $query->whereNull('retired_at');
    }

    public function scopeRetired(Builder $query): Builder
    {
        return $query->whereNotNull('retired_at');
    }

    public function scopeShredded(Builder $query): Builder
    {
        return $query->whereNotNull('shredded_at');
    }

    public function scopeForContext(Builder $query, string $type, string|int $id): Builder
    {
        return $query->where('context_type', $type)
            ->where('context_id', (string) $id);
    }

    public function scopeForProvider(Builder $query, string $providerName): Builder
    {
        return $query->where('provider_name', $providerName);
    }

    public function isRetired(): bool
    {
        return $this->retired_at !== null;
    }

    public function isShredded(): bool
    {
        return $this->shredded_at !== null;
    }
}
