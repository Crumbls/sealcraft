<?php

declare(strict_types=1);

use Crumbls\Sealcraft\Casts\EncryptedJson;
use Crumbls\Sealcraft\Events\DecryptionFailed;
use Crumbls\Sealcraft\Exceptions\ContextShreddedException;
use Crumbls\Sealcraft\Exceptions\DecryptionFailedException;
use Crumbls\Sealcraft\Exceptions\InvalidContextException;
use Crumbls\Sealcraft\Exceptions\SealcraftException;
use Crumbls\Sealcraft\Models\DataKey;
use Crumbls\Sealcraft\Services\CipherRegistry;
use Crumbls\Sealcraft\Services\DekCache;
use Crumbls\Sealcraft\Services\KeyManager;
use Crumbls\Sealcraft\Tests\Fixtures\DelegatedJsonRecord;
use Crumbls\Sealcraft\Tests\Fixtures\EncryptedJsonRecord;
use Crumbls\Sealcraft\Tests\Fixtures\OwnedUser;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;
use Illuminate\Support\Str;

beforeEach(function (): void {
    config()->set('sealcraft.default_provider', 'null');
    config()->set('sealcraft.default_cipher', 'aes-256-gcm');

    $this->app->make(DekCache::class)->flush();
});

it('round-trips a nested structure with every leaf scalar encrypted in place', function (): void {
    $history = [
        'conditions' => ['asthma', 'hypertension'],
        'allergies' => [
            ['substance' => 'penicillin', 'severity' => 'severe'],
            ['substance' => 'peanuts', 'severity' => 'mild'],
        ],
        'notes' => 'no recent flares',
    ];

    $record = EncryptedJsonRecord::query()->create([
        'name' => 'Alice',
        'history' => $history,
    ]);

    $raw = $record->getRawOriginal('history');
    expect($raw)->toBeString();

    $rawDecoded = json_decode($raw, true);
    expect($rawDecoded)->toBeArray();
    expect($rawDecoded['conditions'])->toHaveCount(2);
    expect($rawDecoded['conditions'][0])->not->toBe('asthma');
    expect($rawDecoded['allergies'][0]['substance'])->not->toBe('penicillin');
    expect($rawDecoded['allergies'][0]['severity'])->not->toBe('severe');
    expect($rawDecoded['notes'])->not->toBe('no recent flares');
    $registry = $this->app->make(CipherRegistry::class);
    foreach ($rawDecoded['conditions'] as $leaf) {
        expect($registry->peekId($leaf))->not->toBeNull();
    }

    $this->app->make(DekCache::class)->flush();
    $fresh = EncryptedJsonRecord::query()->find($record->id);
    expect($fresh->history)->toBe($history);
    expect($fresh->name)->toBe('Alice');
});

it('preserves structure — keys, nested arrays, and non-string scalars are untouched', function (): void {
    $input = [
        'patient_id' => 12345,
        'active' => true,
        'weight_kg' => 72.5,
        'tags' => ['critical', 'vip'],
        'meta' => [
            'visits' => 4,
            'last_visit_score' => 0.92,
            'archived' => false,
        ],
        'pii' => 'sensitive string',
    ];

    $record = EncryptedJsonRecord::query()->create([
        'name' => 'struct-test',
        'history' => $input,
    ]);

    $raw = json_decode($record->getRawOriginal('history'), true);

    expect($raw['patient_id'])->toBe(12345);
    expect($raw['active'])->toBeTrue();
    expect($raw['weight_kg'])->toBe(72.5);
    expect($raw['meta']['visits'])->toBe(4);
    expect($raw['meta']['last_visit_score'])->toBe(0.92);
    expect($raw['meta']['archived'])->toBeFalse();

    expect($raw['tags'])->toHaveCount(2);
    expect($raw['tags'][0])->not->toBe('critical');
    expect($this->app->make(CipherRegistry::class)->peekId($raw['tags'][0]))->not->toBeNull();
    expect($raw['pii'])->not->toBe('sensitive string');

    $this->app->make(DekCache::class)->flush();
    expect(EncryptedJsonRecord::query()->find($record->id)->history)->toBe($input);
});

it('preserves null values and empty strings without encrypting them', function (): void {
    $record = EncryptedJsonRecord::query()->create([
        'name' => 'null-test',
        'history' => [
            'allergies' => null,
            'notes' => '',
            'medications' => ['aspirin', null, 'ibuprofen'],
        ],
    ]);

    $raw = json_decode($record->getRawOriginal('history'), true);

    expect($raw['allergies'])->toBeNull();
    expect($raw['notes'])->toBe('');
    expect($raw['medications'][1])->toBeNull();
    expect($raw['medications'][0])->not->toBe('aspirin');
    expect($raw['medications'][2])->not->toBe('ibuprofen');

    $this->app->make(DekCache::class)->flush();
    $fresh = EncryptedJsonRecord::query()->find($record->id);
    expect($fresh->history['allergies'])->toBeNull();
    expect($fresh->history['notes'])->toBe('');
    expect($fresh->history['medications'])->toBe(['aspirin', null, 'ibuprofen']);
});

it('passes null column through unchanged in both directions', function (): void {
    $record = EncryptedJsonRecord::query()->create([
        'name' => 'nullable',
        'history' => null,
    ]);

    expect($record->getRawOriginal('history'))->toBeNull();

    $this->app->make(DekCache::class)->flush();
    expect(EncryptedJsonRecord::query()->find($record->id)->history)->toBeNull();
});

it('stores empty arrays as empty JSON without materializing a DEK', function (): void {
    $record = EncryptedJsonRecord::query()->create([
        'name' => 'empty-history',
        'history' => [],
    ]);

    expect($record->getRawOriginal('history'))->toBe('[]');

    $morph = (new EncryptedJsonRecord)->getMorphClass();
    // Only the scalar 'name' column triggered a DEK — the empty JSON did not.
    expect(DataKey::query()->forContext($morph, $record->sealcraft_key)->active()->count())->toBe(1);

    $this->app->make(DekCache::class)->flush();
    expect(EncryptedJsonRecord::query()->find($record->id)->history)->toBe([]);
});

it('accepts a JSON string as input and round-trips to the decoded array', function (): void {
    $record = EncryptedJsonRecord::query()->create([
        'name' => 'json-string-input',
        'history' => json_encode(['foo' => 'bar', 'baz' => ['qux']]),
    ]);

    $this->app->make(DekCache::class)->flush();
    expect(EncryptedJsonRecord::query()->find($record->id)->history)
        ->toBe(['foo' => 'bar', 'baz' => ['qux']]);
});

it('rejects non-JSON string input with a clear error', function (): void {
    $record = new EncryptedJsonRecord(['name' => 'bad-input']);

    expect(fn () => $record->history = 'not valid json')
        ->toThrow(SealcraftException::class);
});

it('raises DecryptionFailedException when a ciphertext leaf is tampered with', function (): void {
    $a = EncryptedJsonRecord::query()->create([
        'name' => 'victim',
        'history' => ['field' => 'alpha-plain'],
    ]);
    $b = EncryptedJsonRecord::query()->create([
        'name' => 'intruder',
        'history' => ['field' => 'beta-plain'],
    ]);

    // Substitute B's encrypted leaf with A's leaf at the DB layer.
    // Fetching B must now fail authentication on that leaf because
    // the AAD binds the ciphertext to A's context, not B's.
    $aRaw = json_decode($a->getRawOriginal('history'), true);
    $bRaw = json_decode($b->getRawOriginal('history'), true);

    $bRaw['field'] = $aRaw['field'];

    DB::table('encrypted_json_records')
        ->where('id', $b->id)
        ->update(['history' => json_encode($bRaw)]);

    $this->app->make(DekCache::class)->flush();
    Event::fake([DecryptionFailed::class]);

    $tampered = EncryptedJsonRecord::query()->find($b->id);

    expect(fn () => $tampered->history)->toThrow(DecryptionFailedException::class);

    Event::assertDispatched(DecryptionFailed::class);
});

it('passes plaintext leaves without a cipher prefix straight through on read', function (): void {
    // Simulate a row written by a previous system that stored plain JSON;
    // sealcraft should not attempt to decrypt strings that carry no
    // recognizable cipher prefix.
    $record = EncryptedJsonRecord::query()->create([
        'name' => 'mixed',
        'history' => ['encrypted-leaf' => 'will be ciphered'],
    ]);

    $raw = json_decode($record->getRawOriginal('history'), true);
    $raw['plain-leaf'] = 'this is plaintext';

    DB::table('encrypted_json_records')
        ->where('id', $record->id)
        ->update(['history' => json_encode($raw)]);

    $this->app->make(DekCache::class)->flush();
    $fresh = EncryptedJsonRecord::query()->find($record->id);

    expect($fresh->history['encrypted-leaf'])->toBe('will be ciphered');
    expect($fresh->history['plain-leaf'])->toBe('this is plaintext');
});

it('refuses encrypted JSON writes on a pre-existing row with empty sealcraft_key, then accepts them after backfill', function (): void {
    DB::table('encrypted_json_records')->insert([
        'id' => 9001,
        'sealcraft_key' => null,
        'name' => null,
        'history' => null,
    ]);

    $record = EncryptedJsonRecord::query()->find(9001);
    expect($record->sealcraft_key)->toBeNull();

    expect(fn () => $record->history = ['note' => 'first entry'])
        ->toThrow(InvalidContextException::class);

    Artisan::call('sealcraft:backfill-row-keys', ['model' => EncryptedJsonRecord::class]);

    $backfilledKey = DB::table('encrypted_json_records')->where('id', 9001)->value('sealcraft_key');
    expect($backfilledKey)->toBeString()->not->toBe('');

    $reloaded = EncryptedJsonRecord::query()->find(9001);
    $reloaded->history = ['note' => 'first entry'];
    $reloaded->save();

    $raw = DB::table('encrypted_json_records')->where('id', 9001)->first();
    expect($raw->sealcraft_key)->toBe($backfilledKey);
    expect($raw->history)->not->toBeNull();

    $this->app->make(DekCache::class)->flush();
    expect(EncryptedJsonRecord::query()->find(9001)->history)
        ->toBe(['note' => 'first entry']);
});

it('shares a single DEK across a user and a delegated JSON record', function (): void {
    $user = OwnedUser::query()->create(['email' => 'pat@example.com', 'ssn' => '555-44-3333']);

    $record = DelegatedJsonRecord::query()->create([
        'owned_user_id' => $user->id,
        'payload' => [
            'diagnosis' => 'routine checkup',
            'vitals' => ['bp' => '120/80', 'hr' => 72],
        ],
    ]);

    $morph = (new OwnedUser)->getMorphClass();
    expect(DataKey::query()->forContext($morph, $user->sealcraft_key)->active()->count())->toBe(1);

    $this->app->make(DekCache::class)->flush();
    $fresh = DelegatedJsonRecord::query()->find($record->id);
    expect($fresh->payload)->toBe([
        'diagnosis' => 'routine checkup',
        'vitals' => ['bp' => '120/80', 'hr' => 72],
    ]);
});

it('makes a delegated JSON column unreadable after shredding the owner', function (): void {
    $user = OwnedUser::query()->create(['email' => 'shred-me@x', 'ssn' => '999-88-7777']);

    $record = DelegatedJsonRecord::query()->create([
        'owned_user_id' => $user->id,
        'payload' => ['secret' => 'nuclear codes'],
    ]);

    $this->app->make(KeyManager::class)->shredContext($user->sealcraftContext());
    $this->app->make(DekCache::class)->flush();

    expect(fn () => DelegatedJsonRecord::query()->find($record->id)->payload)
        ->toThrow(ContextShreddedException::class);
});

it('does not fire DecryptionFailed when reading a shredded JSON column', function (): void {
    $user = OwnedUser::query()->create(['email' => 'quiet-shred@x', 'ssn' => 'x']);

    DelegatedJsonRecord::query()->create([
        'owned_user_id' => $user->id,
        'payload' => ['note' => 'will be shredded'],
    ]);

    $this->app->make(KeyManager::class)->shredContext($user->sealcraftContext());
    $this->app->make(DekCache::class)->flush();

    Event::fake([DecryptionFailed::class]);

    try {
        DelegatedJsonRecord::query()->first()->payload;
    } catch (ContextShreddedException) {
        // expected
    }

    Event::assertNotDispatched(DecryptionFailed::class);
});

it('rejects non-string storage in the column on read', function (): void {
    // This is a defensive check — shouldn't happen via the cast itself,
    // but guards against schema drift where the column is migrated to a
    // binary/blob type and Laravel surfaces a non-string value.
    $record = new EncryptedJsonRecord;
    $cast = new EncryptedJson;

    expect(fn () => $cast->get($record, 'history', 12345, []))
        ->toThrow(SealcraftException::class);
});

it('rejects invalid JSON in the column on read', function (): void {
    DB::table('encrypted_json_records')->insert([
        'id' => 9100,
        'sealcraft_key' => (string) Str::uuid(),
        'history' => 'this is not json',
    ]);

    $record = EncryptedJsonRecord::query()->find(9100);

    expect(fn () => $record->history)->toThrow(SealcraftException::class);
});
