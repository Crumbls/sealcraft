<?php

declare(strict_types=1);

use Crumbls\Sealcraft\Events\DecryptionFailed;
use Crumbls\Sealcraft\Events\DekShredded;
use Crumbls\Sealcraft\Exceptions\ContextShreddedException;
use Crumbls\Sealcraft\Models\DataKey;
use Crumbls\Sealcraft\Services\DekCache;
use Crumbls\Sealcraft\Services\KeyManager;
use Crumbls\Sealcraft\Tests\Fixtures\OwnedRecord;
use Crumbls\Sealcraft\Tests\Fixtures\OwnedUser;
use Illuminate\Support\Facades\Event;

beforeEach(function (): void {
    config()->set('sealcraft.default_provider', 'null');
    config()->set('sealcraft.default_cipher', 'aes-256-gcm');

    $this->app->make(DekCache::class)->flush();
});

it('delegates a related record context to its owning user', function (): void {
    $user = OwnedUser::query()->create(['email' => 'alice@example.com', 'ssn' => '111-22-3333']);

    $record = OwnedRecord::query()->create([
        'owned_user_id' => $user->id,
        'body' => 'clinical note',
    ]);

    $morph = (new OwnedUser)->getMorphClass();

    // Exactly one DEK backs BOTH the user and the record, keyed by the
    // user's sealcraft_key (not its primary key).
    expect(DataKey::query()->forContext($morph, $user->sealcraft_key)->active()->count())->toBe(1);

    // Round-trips after fresh fetches prove the delegation works.
    $this->app->make(DekCache::class)->flush();

    expect(OwnedUser::query()->find($user->id)->ssn)->toBe('111-22-3333');
    expect(OwnedRecord::query()->find($record->id)->body)->toBe('clinical note');
});

it('shredding a user destroys every related record in one operation', function (): void {
    $user = OwnedUser::query()->create([
        'email' => 'bob@example.com',
        'ssn' => '222-33-4444',
        'dob' => '1980-01-02',
    ]);

    $a = OwnedRecord::query()->create(['owned_user_id' => $user->id, 'body' => 'note-a']);
    $b = OwnedRecord::query()->create(['owned_user_id' => $user->id, 'body' => 'note-b']);

    Event::fake([DekShredded::class]);

    $this->app->make(KeyManager::class)->shredContext($user->sealcraftContext());

    $this->app->make(DekCache::class)->flush();

    // Every encrypted column across every related row is now unreachable.
    expect(fn () => OwnedUser::query()->find($user->id)->ssn)
        ->toThrow(ContextShreddedException::class);
    expect(fn () => OwnedUser::query()->find($user->id)->dob)
        ->toThrow(ContextShreddedException::class);
    expect(fn () => OwnedRecord::query()->find($a->id)->body)
        ->toThrow(ContextShreddedException::class);
    expect(fn () => OwnedRecord::query()->find($b->id)->body)
        ->toThrow(ContextShreddedException::class);

    Event::assertDispatched(DekShredded::class);
});

it('leaves unrelated users untouched when one is shredded', function (): void {
    $alice = OwnedUser::query()->create(['email' => 'alice@x', 'ssn' => 'alice-ssn']);
    $bob = OwnedUser::query()->create(['email' => 'bob@x', 'ssn' => 'bob-ssn']);

    $this->app->make(KeyManager::class)->shredContext($alice->sealcraftContext());

    $this->app->make(DekCache::class)->flush();

    expect(fn () => OwnedUser::query()->find($alice->id)->ssn)
        ->toThrow(ContextShreddedException::class);

    expect(OwnedUser::query()->find($bob->id)->ssn)->toBe('bob-ssn');
});

it('refuses to write new encrypted data under a shredded context', function (): void {
    $user = OwnedUser::query()->create(['email' => 'carol@x', 'ssn' => 'first']);

    $this->app->make(KeyManager::class)->shredContext($user->sealcraftContext());

    $this->app->make(DekCache::class)->flush();

    // Any attempt to encrypt new data under this context must fail.
    expect(fn () => OwnedRecord::query()->create(['owned_user_id' => $user->id, 'body' => 'nope']))
        ->toThrow(ContextShreddedException::class);
});

it('is idempotent when shredding an already-shredded context', function (): void {
    $user = OwnedUser::query()->create(['email' => 'dana@x', 'ssn' => 'dana-ssn']);

    $manager = $this->app->make(KeyManager::class);
    $ctx = $user->sealcraftContext();
    $morph = (new OwnedUser)->getMorphClass();

    $manager->shredContext($ctx);
    $manager->shredContext($ctx);  // must not throw

    expect($manager->isContextShredded($ctx))->toBeTrue();
    expect(DataKey::query()->forContext($morph, $user->sealcraft_key)->shredded()->count())->toBe(1);
});

it('never fires a DecryptionFailed event on a shredded read', function (): void {
    $user = OwnedUser::query()->create(['email' => 'eve@x', 'ssn' => 'eve-ssn']);

    $this->app->make(KeyManager::class)->shredContext($user->sealcraftContext());

    $this->app->make(DekCache::class)->flush();

    Event::fake([DecryptionFailed::class]);

    try {
        OwnedUser::query()->find($user->id)->ssn;
    } catch (ContextShreddedException) {
        // expected
    }

    Event::assertNotDispatched(DecryptionFailed::class);
});
