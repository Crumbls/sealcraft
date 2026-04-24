<?php

declare(strict_types=1);

/*
 * HIPAA right-to-be-forgotten cascade: an owner model holds the DEK for
 * itself and all records in other tables that delegate context through
 * it. Shredding the owner makes every delegated row unrecoverable in
 * one operation — no row-by-row DELETE across tables, no backups to
 * chase, no audit logs to scrub.
 *
 * Also asserts that shredded-read paths do NOT fire DecryptionFailed
 * (silent denial, not an error — SIEM signal differentiation).
 */

use Crumbls\Sealcraft\Events\DecryptionFailed;
use Crumbls\Sealcraft\Exceptions\ContextShreddedException;
use Crumbls\Sealcraft\Models\DataKey;
use Crumbls\Sealcraft\Services\DekCache;
use Crumbls\Sealcraft\Services\KeyManager;
use Crumbls\Sealcraft\Tests\Fixtures\DelegatedJsonRecord;
use Crumbls\Sealcraft\Tests\Fixtures\OwnedRecord;
use Crumbls\Sealcraft\Tests\Fixtures\OwnedUser;
use Illuminate\Support\Facades\Event;

beforeEach(function (): void {
    config()->set('sealcraft.default_provider', 'null');
    config()->set('sealcraft.default_cipher', 'aes-256-gcm');

    $this->app->make(DekCache::class)->flush();
});

it('cascades shred across every delegated table using the owner DEK', function (): void {
    $user = OwnedUser::query()->create([
        'email' => 'cascade@x',
        'ssn' => '111-11-1111',
        'dob' => '1970-01-01',
    ]);

    $record = OwnedRecord::query()->create([
        'owned_user_id' => $user->id,
        'body' => 'clinical note',
    ]);

    $jsonRecord = DelegatedJsonRecord::query()->create([
        'owned_user_id' => $user->id,
        'payload' => ['diagnosis' => 'asthma', 'severity' => 'mild'],
    ]);

    // Sanity: every delegated record reads back correctly before shred
    $this->app->make(DekCache::class)->flush();
    $record->setRelation('owner', $user);
    $jsonRecord->setRelation('owner', $user);
    expect($record->body)->toBe('clinical note');
    expect($jsonRecord->payload)->toEqual(['diagnosis' => 'asthma', 'severity' => 'mild']);

    // Only one DEK row exists — the owner's — shared across all 3 tables' encrypted data
    expect(DataKey::query()->count())->toBe(1);

    // Shred the owner's context
    $this->app->make(KeyManager::class)->shredContext($user->sealcraftContext());
    $this->app->make(DekCache::class)->flush();

    // Every delegated read now throws ContextShreddedException
    $freshUser = OwnedUser::query()->find($user->id);
    $freshRecord = OwnedRecord::query()->find($record->id);
    $freshJson = DelegatedJsonRecord::query()->find($jsonRecord->id);
    $freshRecord->setRelation('owner', $freshUser);
    $freshJson->setRelation('owner', $freshUser);

    expect(fn () => $freshUser->ssn)->toThrow(ContextShreddedException::class);
    expect(fn () => $freshRecord->body)->toThrow(ContextShreddedException::class);
    expect(fn () => $freshJson->payload)->toThrow(ContextShreddedException::class);
});

it('never fires DecryptionFailed on a shredded read (silent denial, not an auth error)', function (): void {
    Event::fake([DecryptionFailed::class]);

    $user = OwnedUser::query()->create(['email' => 'silent@x', 'ssn' => '222-22-2222']);
    $record = OwnedRecord::query()->create(['owned_user_id' => $user->id, 'body' => 'note']);

    $this->app->make(KeyManager::class)->shredContext($user->sealcraftContext());
    $this->app->make(DekCache::class)->flush();

    $freshRecord = OwnedRecord::query()->find($record->id);
    $freshRecord->setRelation('owner', OwnedUser::query()->find($user->id));

    try {
        $freshRecord->body;
    } catch (ContextShreddedException) {
        // expected
    }

    Event::assertNotDispatched(DecryptionFailed::class);
});

it('leaves unrelated owners untouched when one owner is shredded', function (): void {
    $alice = OwnedUser::query()->create(['email' => 'alice@x', 'ssn' => '333-33-3333']);
    $bob = OwnedUser::query()->create(['email' => 'bob@x', 'ssn' => '444-44-4444']);

    $this->app->make(KeyManager::class)->shredContext($alice->sealcraftContext());
    $this->app->make(DekCache::class)->flush();

    // Alice is gone
    $freshAlice = OwnedUser::query()->find($alice->id);
    expect(fn () => $freshAlice->ssn)->toThrow(ContextShreddedException::class);

    // Bob is untouched
    $freshBob = OwnedUser::query()->find($bob->id);
    expect($freshBob->ssn)->toBe('444-44-4444');
});
