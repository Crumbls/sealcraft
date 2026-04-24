<?php

declare(strict_types=1);

/*
 * Pin the safe defaults for how encrypted columns behave when the
 * model is serialized via toArray() / toJson() / PHP serialize(). The
 * cast is transparent by design — toArray() decrypts — so apps must
 * control exposure via `$hidden` / API resources / explicit projection.
 * These tests exist to surface the expected behavior so it does not
 * quietly change in a refactor.
 */

use Crumbls\Sealcraft\Services\DekCache;
use Crumbls\Sealcraft\Tests\Fixtures\EncryptedDocument;

beforeEach(function (): void {
    config()->set('sealcraft.default_provider', 'null');
    config()->set('sealcraft.default_cipher', 'aes-256-gcm');
    $this->app->make(DekCache::class)->flush();
});

it('toArray() decrypts encrypted attributes (transparent-cast behavior)', function (): void {
    $doc = EncryptedDocument::query()->create([
        'tenant_id' => 1,
        'secret' => 'plaintext value',
    ]);

    $this->app->make(DekCache::class)->flush();
    $array = EncryptedDocument::query()->find($doc->id)->toArray();

    // Transparent cast: toArray returns plaintext. Apps that want to hide
    // the column from API output must add it to $hidden or use a Resource.
    expect($array['secret'])->toBe('plaintext value');
});

it('honors $hidden to suppress encrypted attributes from toArray/toJson', function (): void {
    $doc = new class extends \Illuminate\Database\Eloquent\Model {
        use \Crumbls\Sealcraft\Concerns\HasEncryptedAttributes;

        protected $table = 'encrypted_documents';

        protected $guarded = [];

        public $timestamps = false;

        protected $hidden = ['secret'];

        protected $casts = [
            'secret' => \Crumbls\Sealcraft\Casts\Encrypted::class,
        ];
    };

    $doc->tenant_id = 2;
    $doc->secret = 'hidden-please';
    $doc->save();

    $array = $doc->toArray();
    expect($array)->not->toHaveKey('secret');
});

it('getRawOriginal returns ciphertext, not plaintext (useful for migrations and debugging)', function (): void {
    $doc = EncryptedDocument::query()->create(['tenant_id' => 3, 'secret' => 'plaintext']);

    expect($doc->getRawOriginal('secret'))->toStartWith('ag1:v1:');
    expect($doc->getRawOriginal('secret'))->not->toContain('plaintext');
});

it('var_export and print_r of a fresh-from-DB model do not accidentally contain plaintext', function (): void {
    $doc = EncryptedDocument::query()->create(['tenant_id' => 4, 'secret' => 'secret-payload']);

    $this->app->make(DekCache::class)->flush();
    $fresh = EncryptedDocument::query()->find($doc->id);

    // Until an attribute is accessed, the model holds ciphertext in $attributes.
    expect(print_r($fresh->getAttributes(), true))->not->toContain('secret-payload');
});
