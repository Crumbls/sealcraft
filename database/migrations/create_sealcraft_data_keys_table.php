<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create(config('sealcraft.table_name', 'sealcraft_data_keys'), function (Blueprint $table): void {
            $table->bigIncrements('id');

            $table->string('context_type', 191);
            $table->string('context_id', 191);

            $table->string('provider_name', 64);
            $table->string('key_id', 512);
            $table->string('key_version', 128)->nullable();

            $table->string('cipher', 32);

            $table->mediumText('wrapped_dek');

            $table->timestamp('created_at')->useCurrent();
            $table->timestamp('rotated_at')->nullable();
            $table->timestamp('retired_at')->nullable();
            $table->timestamp('shredded_at')->nullable();

            // Note: active-DEK uniqueness ("one active DEK per context") is
            // enforced at the application layer in KeyManager::createDek.
            // SQL UNIQUE indexes treat NULL as distinct across MySQL, SQLite,
            // and PostgreSQL < 15, so a portable DB-level constraint isn't
            // achievable without partial indexes. The composite index below
            // still makes active lookups fast.
            $table->index(['context_type', 'context_id', 'retired_at'], 'sealcraft_data_keys_context_idx');
            $table->index('provider_name', 'sealcraft_data_keys_provider_idx');
            $table->index(['key_id', 'key_version'], 'sealcraft_data_keys_key_idx');
        });
    }
};
