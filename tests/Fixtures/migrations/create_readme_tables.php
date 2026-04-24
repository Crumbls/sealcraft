<?php

declare(strict_types=1);

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('readme_patients', function (Blueprint $table): void {
            $table->bigIncrements('id');
            $table->unsignedBigInteger('tenant_id')->nullable();
            $table->text('ssn')->nullable();
            $table->text('dob')->nullable();
            $table->text('diagnosis')->nullable();
            $table->longText('history')->nullable();
            $table->index('tenant_id');
        });

        Schema::create('readme_documents', function (Blueprint $table): void {
            $table->bigIncrements('id');
            $table->unsignedBigInteger('tenant_id')->nullable();
            $table->text('body')->nullable();
            $table->index('tenant_id');
        });

        Schema::create('readme_vault_entries', function (Blueprint $table): void {
            $table->bigIncrements('id');
            $table->string('sealcraft_key', 191)->nullable();
            $table->text('secret')->nullable();
            $table->index('sealcraft_key');
        });
    }
};
