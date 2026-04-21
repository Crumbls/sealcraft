<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Commands;

use Illuminate\Console\Command;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Config;

/**
 * Manually migrate one row's encryption context. Primarily useful for
 * installs that run with auto_reencrypt_on_context_change disabled.
 *
 * The command forces auto-reencrypt on for the duration of its own
 * save() so the trait's existing event + re-encrypt machinery runs
 * with full audit eventing, then restores the original config.
 */
final class ReencryptContextCommand extends Command
{
    protected $signature = 'sealcraft:reencrypt-context
        {model : Fully-qualified model class}
        {id : Primary key of the row to migrate}
        {new_value : New value for the context column}
        {--column= : Override the model\'s context column name}
        {--dry-run : Report what would change without performing the save}';

    protected $description = 'Migrate a model row from one encryption context to another, re-encrypting every encrypted column.';

    public function handle(): int
    {
        $modelClass = (string) $this->argument('model');
        $id = (string) $this->argument('id');
        $newValue = $this->argument('new_value');

        if (! class_exists($modelClass) || ! is_subclass_of($modelClass, Model::class)) {
            $this->error("[{$modelClass}] is not a valid Eloquent model class.");

            return self::FAILURE;
        }

        /** @var Model $instance */
        $instance = $modelClass::query()->find($id);

        if ($instance === null) {
            $this->error("No {$modelClass} row found with primary key [{$id}].");

            return self::FAILURE;
        }

        $column = is_string($this->option('column'))
            ? (string) $this->option('column')
            : (string) Config::get('sealcraft.context_column', 'tenant_id');

        $currentValue = $instance->getAttribute($column);

        $this->info("{$modelClass}#{$id} {$column}: [{$currentValue}] -> [{$newValue}]");

        if ($this->option('dry-run')) {
            $this->line('(dry-run) no changes made.');

            return self::SUCCESS;
        }

        $instance->{$column} = $newValue;

        if (! $instance->isDirty($column)) {
            $this->info('No change: current value already matches.');

            return self::SUCCESS;
        }

        $previousAutoFlag = Config::get('sealcraft.auto_reencrypt_on_context_change');

        try {
            Config::set('sealcraft.auto_reencrypt_on_context_change', true);
            $instance->save();
        } finally {
            Config::set('sealcraft.auto_reencrypt_on_context_change', $previousAutoFlag);
        }

        $this->info("{$modelClass}#{$id} re-encrypted under new context.");

        return self::SUCCESS;
    }
}
