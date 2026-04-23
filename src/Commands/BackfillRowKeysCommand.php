<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Commands;

use Crumbls\Sealcraft\Concerns\HasEncryptedAttributes;
use Illuminate\Console\Command;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;

/**
 * Populate the per-row row-key column on rows that were inserted with an
 * empty/NULL value (e.g., rows that predate the per_row encryption
 * strategy). Required before encrypted attributes on those rows can be
 * read or written, since sealcraftContext() refuses to mint a throwaway
 * UUID on an already-persisted row.
 *
 * The command bypasses Eloquent events and casts so it can safely run on
 * tables whose other columns may already hold ciphertext bound to a
 * different (and still-empty) context.
 */
final class BackfillRowKeysCommand extends Command
{
    protected $signature = 'sealcraft:backfill-row-keys
        {model : Fully-qualified model class using HasEncryptedAttributes (per_row strategy)}
        {--chunk=500 : Update rows in chunks of this size}
        {--dry-run : Report the affected row count without writing}';

    protected $description = 'Backfill the per-row sealcraft row-key column with fresh UUIDs on rows where it is empty.';

    public function handle(): int
    {
        $modelClass = (string) $this->argument('model');

        if (! class_exists($modelClass) || ! is_subclass_of($modelClass, Model::class)) {
            $this->error("[{$modelClass}] is not a valid Eloquent model class.");

            return self::FAILURE;
        }

        if (! in_array(HasEncryptedAttributes::class, class_uses_recursive($modelClass), true)) {
            $this->error("[{$modelClass}] does not use HasEncryptedAttributes.");

            return self::FAILURE;
        }

        /** @var Model $probe */
        $probe = new $modelClass;

        $strategy = $this->reflectInvoke($probe, 'resolveSealcraftStrategy');

        if ($strategy !== 'per_row') {
            $this->error("[{$modelClass}] does not use the per_row strategy (got [{$strategy}]); backfill is only meaningful for per_row.");

            return self::FAILURE;
        }

        $column = $this->reflectInvoke($probe, 'resolveSealcraftRowKeyColumn');
        $table = $probe->getTable();
        $keyName = $probe->getKeyName();
        $connection = $probe->getConnection();
        $chunk = max(1, (int) $this->option('chunk'));
        $dryRun = (bool) $this->option('dry-run');

        $emptyClause = static function ($query) use ($column): void {
            $query->whereNull($column)->orWhere($column, '');
        };

        $total = $connection->table($table)->where($emptyClause)->count();

        $this->info("Backfilling [{$column}] on table [{$table}] for model [{$modelClass}].");
        $this->info("Rows with empty row-key: {$total}");

        if ($dryRun) {
            $this->line('(dry-run) no changes made.');

            return self::SUCCESS;
        }

        if ($total === 0) {
            return self::SUCCESS;
        }

        $updated = 0;

        do {
            $rows = $connection->table($table)
                ->select([$keyName])
                ->where($emptyClause)
                ->orderBy($keyName)
                ->limit($chunk)
                ->get();

            if ($rows->isEmpty()) {
                break;
            }

            foreach ($rows as $row) {
                $affected = $connection->table($table)
                    ->where($keyName, $row->{$keyName})
                    ->where(static function ($q) use ($column): void {
                        $q->whereNull($column)->orWhere($column, '');
                    })
                    ->update([$column => (string) Str::uuid()]);

                $updated += $affected;
            }
        } while ($rows->count() === $chunk);

        $this->info("Backfilled {$updated} row(s).");

        return self::SUCCESS;
    }

    private function reflectInvoke(Model $probe, string $method): string
    {
        $ref = new \ReflectionMethod($probe, $method);
        $ref->setAccessible(true);

        return (string) $ref->invoke($probe);
    }
}
