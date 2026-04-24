<?php

declare(strict_types=1);

/*
 * Day-one Laravel patterns: Eloquent factories and queue serialization.
 * Both routinely trip up transparent-cast packages.
 *
 *   - Factories: create() should transparently encrypt via the cast and
 *     persist ciphertext; read-back must decrypt.
 *   - Queue serialization: SerializesModels stores the class + primary
 *     key, re-hydrates on handle(). As long as the row is still in the
 *     DB (and the worker's DekCache is fresh), decryption works.
 */

use Crumbls\Sealcraft\Services\DekCache;
use Crumbls\Sealcraft\Tests\Fixtures\EncryptedDocument;
use Crumbls\Sealcraft\Tests\Fixtures\OwnedUser;
use Illuminate\Database\Eloquent\Factories\Factory;
use Illuminate\Queue\SerializesModels;

// Named job class — anonymous classes cannot be serialized.
class SealcraftFactoryQueueTestJob
{
    use SerializesModels;

    public function __construct(public EncryptedDocument $document) {}
}

beforeEach(function (): void {
    config()->set('sealcraft.default_provider', 'null');
    config()->set('sealcraft.default_cipher', 'aes-256-gcm');
    $this->app->make(DekCache::class)->flush();
});

it('Eloquent factory create() persists ciphertext and reads back plaintext', function (): void {
    $factory = new class extends Factory {
        protected $model = EncryptedDocument::class;

        public function definition(): array
        {
            return [
                'tenant_id' => 1,
                'secret' => 'factory-secret',
                'note' => 'factory-note',
            ];
        }
    };

    $doc = $factory->create();

    expect($doc->getRawOriginal('secret'))->toStartWith('ag1:v1:');

    $this->app->make(DekCache::class)->flush();
    $fresh = EncryptedDocument::query()->find($doc->id);
    expect($fresh->secret)->toBe('factory-secret');
    expect($fresh->note)->toBe('factory-note');
});

it('factory->count(N) creates N independent encrypted rows', function (): void {
    $factory = new class extends Factory {
        protected $model = EncryptedDocument::class;

        public function definition(): array
        {
            return ['tenant_id' => 2, 'secret' => 'count-me'];
        }
    };

    $docs = $factory->count(3)->create();

    expect($docs)->toHaveCount(3);
    foreach ($docs as $doc) {
        expect($doc->getRawOriginal('secret'))->toStartWith('ag1:v1:');
    }

    $this->app->make(DekCache::class)->flush();
    foreach ($docs as $doc) {
        expect(EncryptedDocument::query()->find($doc->id)->secret)->toBe('count-me');
    }
});

it('per-row factory rows each get their own sealcraft_key and DEK', function (): void {
    $factory = new class extends Factory {
        protected $model = OwnedUser::class;

        public function definition(): array
        {
            return [
                'email' => 'factory-' . bin2hex(random_bytes(4)) . '@x',
                'ssn' => '222-22-2222',
            ];
        }
    };

    $users = $factory->count(3)->create();

    $keys = $users->pluck('sealcraft_key')->all();
    expect(array_unique($keys))->toHaveCount(3); // all distinct

    $this->app->make(DekCache::class)->flush();

    foreach ($users as $user) {
        expect(OwnedUser::query()->find($user->id)->ssn)->toBe('222-22-2222');
    }
});

it('SerializesModels re-hydration preserves encrypted attribute access', function (): void {
    $doc = EncryptedDocument::query()->create([
        'tenant_id' => 50,
        'secret' => 'queued-payload',
    ]);

    // Simulate what Laravel's queue does: serialize the model reference,
    // then re-hydrate in the "worker" process by deserializing.
    $job = new SealcraftFactoryQueueTestJob($doc);

    $serialized = serialize($job);

    // Flush to simulate a fresh worker memory state
    $this->app->make(DekCache::class)->flush();

    $rehydrated = unserialize($serialized);
    expect($rehydrated->document)->toBeInstanceOf(EncryptedDocument::class);
    expect($rehydrated->document->secret)->toBe('queued-payload');
});

it('SerializesModels does not leak plaintext into the serialized byte stream', function (): void {
    $doc = EncryptedDocument::query()->create([
        'tenant_id' => 60,
        'secret' => 'never-leak-me',
    ]);

    // Trigger decryption once so the cast sees the plaintext
    expect($doc->secret)->toBe('never-leak-me');

    $job = new SealcraftFactoryQueueTestJob($doc);

    $serialized = serialize($job);

    // SerializesModels stores only {class, id, relations, connection} —
    // not the attribute map — so the plaintext must not appear in the blob.
    expect($serialized)->not->toContain('never-leak-me');
});
