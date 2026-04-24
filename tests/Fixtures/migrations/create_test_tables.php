<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('encrypted_documents', function (Blueprint $table): void {
            $table->bigIncrements('id');
            $table->unsignedBigInteger('tenant_id')->nullable();
            $table->text('secret')->nullable();
            $table->text('note')->nullable();
        });

        Schema::create('encrypted_vault_entries', function (Blueprint $table): void {
            $table->bigIncrements('id');
            $table->string('sealcraft_key', 191)->nullable();
            $table->text('payload')->nullable();
            $table->index('sealcraft_key');
        });

        Schema::create('owned_users', function (Blueprint $table): void {
            $table->bigIncrements('id');
            $table->string('sealcraft_key', 191)->nullable();
            $table->string('email')->nullable();
            $table->text('ssn')->nullable();
            $table->text('dob')->nullable();
            $table->index('sealcraft_key');
        });

        Schema::create('owned_records', function (Blueprint $table): void {
            $table->bigIncrements('id');
            $table->unsignedBigInteger('owned_user_id');
            $table->text('body')->nullable();
            $table->index('owned_user_id');
        });

        Schema::create('encrypted_json_records', function (Blueprint $table): void {
            $table->bigIncrements('id');
            $table->string('sealcraft_key', 191)->nullable();
            $table->text('name')->nullable();
            $table->longText('history')->nullable();
            $table->index('sealcraft_key');
        });

        Schema::create('delegated_json_records', function (Blueprint $table): void {
            $table->bigIncrements('id');
            $table->unsignedBigInteger('owned_user_id');
            $table->longText('payload')->nullable();
            $table->index('owned_user_id');
        });

        Schema::create('unified_patients', function (Blueprint $table): void {
            $table->bigIncrements('id');
            $table->unsignedBigInteger('patient_id')->nullable();
            $table->unsignedBigInteger('employer_id')->nullable();
            $table->text('ssn')->nullable();
            $table->longText('history')->nullable();
            $table->text('work_notes')->nullable();
            $table->index('patient_id');
            $table->index('employer_id');
        });
    }
};
