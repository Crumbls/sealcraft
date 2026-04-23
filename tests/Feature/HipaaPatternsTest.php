<?php

declare(strict_types=1);

use Crumbls\Sealcraft\Events\DecryptionFailed;
use Crumbls\Sealcraft\Events\DekShredded;
use Crumbls\Sealcraft\Exceptions\ContextShreddedException;
use Crumbls\Sealcraft\Exceptions\InvalidContextException;
use Crumbls\Sealcraft\Models\DataKey;
use Crumbls\Sealcraft\Services\DekCache;
use Crumbls\Sealcraft\Services\KeyManager;
use Crumbls\Sealcraft\Tests\Fixtures\OwnedRecord;
use Crumbls\Sealcraft\Tests\Fixtures\OwnedUser;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\DB;
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

it('refuses to read encrypted attributes from a saved row with an empty row-key', function (): void {
    $user = OwnedUser::query()->create(['email' => 'frank@x', 'ssn' => 'frank-ssn']);

    DB::table('owned_users')->where('id', $user->id)->update(['sealcraft_key' => null]);

    $this->app->make(DekCache::class)->flush();

    $dekCountBefore = DataKey::query()->count();

    expect(fn () => OwnedUser::query()->find($user->id)->ssn)
        ->toThrow(InvalidContextException::class);

    expect(DataKey::query()->count())->toBe($dekCountBefore);
});

it('refuses to write encrypted attributes onto a saved row with an empty row-key', function (): void {
    $user = OwnedUser::query()->create(['email' => 'gina@x', 'ssn' => 'gina-ssn']);

    DB::table('owned_users')->where('id', $user->id)->update(['sealcraft_key' => null]);

    $this->app->make(DekCache::class)->flush();

    $reloaded = OwnedUser::query()->find($user->id);

    expect(fn () => $reloaded->ssn = 'updated')
        ->toThrow(InvalidContextException::class);
});

it('surfaces the same throw on a delegated read when the owner has no row-key', function (): void {
    $user = OwnedUser::query()->create(['email' => 'hank@x', 'ssn' => 'hank-ssn']);
    $record = OwnedRecord::query()->create(['owned_user_id' => $user->id, 'body' => 'note']);

    DB::table('owned_users')->where('id', $user->id)->update(['sealcraft_key' => null]);

    $this->app->make(DekCache::class)->flush();

    expect(fn () => OwnedRecord::query()->find($record->id)->body)
        ->toThrow(InvalidContextException::class);
});

it('persists the row-key on create even when no encrypted attribute is touched', function (): void {
    $user = OwnedUser::query()->create(['email' => 'ivy@x']);

    $persisted = DB::table('owned_users')->where('id', $user->id)->value('sealcraft_key');

    expect($persisted)->toBeString()->not->toBe('');

    // Subsequent encrypted writes must not throw and must reuse the same row-key.
    $user->ssn = 'ivy-ssn';
    $user->save();

    expect(OwnedUser::query()->find($user->id)->ssn)->toBe('ivy-ssn');

    expect(DB::table('owned_users')->where('id', $user->id)->value('sealcraft_key'))
        ->toBe($persisted);
});

it('backfills empty row-keys with the sealcraft:backfill-row-keys command', function (): void {
    $idA = DB::table('owned_users')->insertGetId(['email' => 'jay@x', 'sealcraft_key' => null]);
    $idB = DB::table('owned_users')->insertGetId(['email' => 'kim@x', 'sealcraft_key' => '']);

    Artisan::call('sealcraft:backfill-row-keys', ['model' => OwnedUser::class]);

    $keyA = DB::table('owned_users')->where('id', $idA)->value('sealcraft_key');
    $keyB = DB::table('owned_users')->where('id', $idB)->value('sealcraft_key');

    expect($keyA)->toBeString()->not->toBe('');
    expect($keyB)->toBeString()->not->toBe('');
    expect($keyA)->not->toBe($keyB);

    // Idempotent: a second run touches no rows and leaves keys intact.
    Artisan::call('sealcraft:backfill-row-keys', ['model' => OwnedUser::class]);

    expect(DB::table('owned_users')->where('id', $idA)->value('sealcraft_key'))->toBe($keyA);
    expect(DB::table('owned_users')->where('id', $idB)->value('sealcraft_key'))->toBe($keyB);
});

it('leaves row-keys untouched in --dry-run mode', function (): void {
    $id = DB::table('owned_users')->insertGetId(['email' => 'lyn@x', 'sealcraft_key' => null]);

    Artisan::call('sealcraft:backfill-row-keys', [
        'model' => OwnedUser::class,
        '--dry-run' => true,
    ]);

    expect(DB::table('owned_users')->where('id', $id)->value('sealcraft_key'))->toBeNull();
});
