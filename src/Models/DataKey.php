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
 * @property string|null $active_context_hash
 * @property string $provider_name
 * @property string $key_id
 * @property string|null $key_version
 * @property string $cipher
 * @property string $wrapped_dek
 * @property Carbon $created_at
 * @property Carbon|null $rotated_at
 * @property Carbon|null $retired_at
 * @property Carbon|null $shredded_at
 *
 * @method static Builder<static> active()
 * @method static Builder<static> retired()
 * @method static Builder<static> shredded()
 * @method static Builder<static> forContext(string $type, string|int $id)
 * @method static Builder<static> forProvider(string $providerName)
 */
class DataKey extends Model
{
    public const UPDATED_AT = null;

    protected $guarded = [];

    /** @var array<string, string> */
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

    /**
     * @return Builder<static>
     */
    public static function queryForContext(string $type, string|int $id): Builder
    {
        $query = self::query();
        $query->where('context_type', $type)
            ->where('context_id', (string) $id);

        return $query;
    }

    /**
     * @return Builder<static>
     */
    public static function queryActive(): Builder
    {
        $query = self::query();
        $query->whereNull('retired_at');

        return $query;
    }

    /**
     * @return Builder<static>
     */
    public static function queryActiveForContext(string $type, string|int $id): Builder
    {
        $query = self::queryForContext($type, $id);
        $query->whereNull('retired_at');

        return $query;
    }

    /**
     * @return Builder<static>
     */
    public static function queryForProvider(string $providerName): Builder
    {
        $query = self::query();
        $query->where('provider_name', $providerName);

        return $query;
    }

    /**
     * @param  Builder<self>  $query
     * @return Builder<self>
     */
    public function scopeActive(Builder $query): Builder
    {
        $query->whereNull('retired_at');

        return $query;
    }

    /**
     * @param  Builder<self>  $query
     * @return Builder<self>
     */
    public function scopeRetired(Builder $query): Builder
    {
        $query->whereNotNull('retired_at');

        return $query;
    }

    /**
     * @param  Builder<self>  $query
     * @return Builder<self>
     */
    public function scopeShredded(Builder $query): Builder
    {
        $query->whereNotNull('shredded_at');

        return $query;
    }

    /**
     * @param  Builder<self>  $query
     * @return Builder<self>
     */
    public function scopeForContext(Builder $query, string $type, string|int $id): Builder
    {
        $query->where('context_type', $type)
            ->where('context_id', (string) $id);

        return $query;
    }

    public static function activeContextHash(string $type, string|int $id): string
    {
        return hash('sha256', $type . "\0" . (string) $id);
    }

    public function markActive(): void
    {
        $this->retired_at = null;
        $this->active_context_hash = self::activeContextHash($this->context_type, $this->context_id);
    }

    public function markRetired(?Carbon $timestamp = null): void
    {
        $this->retired_at = $timestamp ?? Carbon::now();
        $this->active_context_hash = null;
    }

    /**
     * @param  Builder<self>  $query
     * @return Builder<self>
     */
    public function scopeForProvider(Builder $query, string $providerName): Builder
    {
        $query->where('provider_name', $providerName);

        return $query;
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
