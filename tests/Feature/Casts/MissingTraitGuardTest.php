<?php

declare(strict_types=1);

/*
 * Regression: if a dev adds the Encrypted cast to a model but forgets
 * to `use HasEncryptedAttributes`, the cast must raise a loud,
 * actionable InvalidContextException — not an opaque "method not found"
 * error deep in Laravel internals.
 */

use Crumbls\Sealcraft\Casts\Encrypted;
use Crumbls\Sealcraft\Casts\EncryptedJson;
use Crumbls\Sealcraft\Exceptions\InvalidContextException;
use Crumbls\Sealcraft\Services\DekCache;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Facades\Schema;

beforeEach(function (): void {
    config()->set('sealcraft.default_provider', 'null');
    config()->set('sealcraft.default_cipher', 'aes-256-gcm');
    $this->app->make(DekCache::class)->flush();

    Schema::create('trait_guard_models', function ($t) {
        $t->bigIncrements('id');
        $t->text('secret')->nullable();
        $t->longText('payload')->nullable();
    });
});

afterEach(function (): void {
    Schema::dropIfExists('trait_guard_models');
});

class MissingTraitModel extends Model
{
    protected $table = 'trait_guard_models';

    protected $guarded = [];

    public $timestamps = false;

    protected $casts = [
        'secret' => Encrypted::class,
        'payload' => EncryptedJson::class,
    ];
}

it('Encrypted cast raises InvalidContextException when the model lacks HasEncryptedAttributes', function (): void {
    $model = new MissingTraitModel;

    expect(function () use ($model): void {
        $model->secret = 'value';
    })->toThrow(InvalidContextException::class, 'must use HasEncryptedAttributes');
});

it('Encrypted cast error names the specific model class', function (): void {
    $model = new MissingTraitModel;

    try {
        $model->secret = 'value';
    } catch (InvalidContextException $e) {
        expect($e->getMessage())->toContain(MissingTraitModel::class);
        expect($e->getMessage())->toContain('sealcraftContext');

        return;
    }

    throw new RuntimeException('expected InvalidContextException');
});

it('EncryptedJson cast raises InvalidContextException when the model lacks HasEncryptedAttributes', function (): void {
    $model = new MissingTraitModel;

    expect(function () use ($model): void {
        $model->payload = ['nested' => 'value'];
    })->toThrow(InvalidContextException::class, 'must use HasEncryptedAttributes');
});
