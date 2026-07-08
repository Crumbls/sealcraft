<?php

declare(strict_types=1);

use Crumbls\Sealcraft\Events\ContextReencrypted;
use Crumbls\Sealcraft\Events\ContextReencrypting;
use Crumbls\Sealcraft\Exceptions\InvalidContextException;
use Crumbls\Sealcraft\Models\DataKey;
use Crumbls\Sealcraft\Services\DekCache;
use Crumbls\Sealcraft\Tests\Fixtures\EncryptedDocument;
use Crumbls\Sealcraft\Tests\Fixtures\Unified\UnifiedPatient;
use Illuminate\Support\Facades\Event;

beforeEach(function (): void {
    config()->set('sealcraft.default_provider', 'null');
    config()->set('sealcraft.default_cipher', 'aes-256-gcm');
    config()->set('sealcraft.context_type', 'tenant');
    config()->set('sealcraft.context_column', 'tenant_id');
    config()->set('sealcraft.auto_reencrypt_on_context_change', true);

    $this->app->make(DekCache::class)->flush();
});

it('auto re-encrypts every encrypted column when context changes', function (): void {
    $doc = EncryptedDocument::query()->create([
        'tenant_id' => 42,
        'secret' => 'original-secret',
        'note' => 'original-note',
    ]);

    $oldCiphertextSecret = $doc->getRawOriginal('secret');
    $oldCiphertextNote = $doc->getRawOriginal('note');

    Event::fake([ContextReencrypting::class, ContextReencrypted::class]);

    $doc->tenant_id = 99;
    $doc->save();

    // New ciphertext under the new context
    expect($doc->getRawOriginal('secret'))->not->toBe($oldCiphertextSecret);
    expect($doc->getRawOriginal('note'))->not->toBe($oldCiphertextNote);

    // Flush cache so read goes back through KeyManager under the new context
    $this->app->make(DekCache::class)->flush();

    $fresh = EncryptedDocument::query()->find($doc->id);
    expect($fresh->secret)->toBe('original-secret');
    expect($fresh->note)->toBe('original-note');

    Event::assertDispatched(ContextReencrypting::class);
    Event::assertDispatched(ContextReencrypted::class);
});

it('preserves newly assigned encrypted values while changing context', function (): void {
    $doc = EncryptedDocument::query()->create([
        'tenant_id' => 42,
        'secret' => 'original-secret',
        'note' => 'original-note',
    ]);

    expect($doc->secret)->toBe('original-secret');

    $doc->tenant_id = 99;
    $doc->secret = 'updated-during-move';
    $doc->save();

    $this->app->make(DekCache::class)->flush();

    $fresh = EncryptedDocument::query()->find($doc->id);
    expect($fresh->tenant_id)->toBe(99);
    expect($fresh->secret)->toBe('updated-during-move');
    expect($fresh->note)->toBe('original-note');
});

it('re-encrypts encrypted json columns when context changes', function (): void {
    $patient = UnifiedPatient::query()->create([
        'patient_id' => 42,
        'employer_id' => 9,
        'ssn' => '111-22-3333',
        'history' => [
            'diagnosis' => 'hypertension',
            'visits' => [
                ['note' => 'annual physical'],
            ],
        ],
    ]);

    $oldRaw = $patient->getRawOriginal('history');

    $patient->patient_id = 99;
    $patient->save();

    expect($patient->getRawOriginal('history'))->not->toBe($oldRaw);

    $this->app->make(DekCache::class)->flush();

    $fresh = UnifiedPatient::query()->find($patient->id);
    expect($fresh->history['diagnosis'])->toBe('hypertension');
    expect($fresh->history['visits'][0]['note'])->toBe('annual physical');
});

it('fires a new DataKey creation on the new tenant during reencrypt', function (): void {
    $doc = EncryptedDocument::query()->create([
        'tenant_id' => 42,
        'secret' => 's',
    ]);

    $doc->tenant_id = 99;
    $doc->save();

    expect(DataKey::query()->forContext('tenant', 42)->active()->count())->toBe(1);
    expect(DataKey::query()->forContext('tenant', 99)->active()->count())->toBe(1);
});

it('raises InvalidContextException when auto-reencrypt is disabled', function (): void {
    $doc = EncryptedDocument::query()->create([
        'tenant_id' => 42,
        'secret' => 's',
    ]);

    config()->set('sealcraft.auto_reencrypt_on_context_change', false);

    $doc->tenant_id = 99;

    expect(fn () => $doc->save())->toThrow(InvalidContextException::class);
});

it('aborts save when a ContextReencrypting listener cancels', function (): void {
    $doc = EncryptedDocument::query()->create([
        'tenant_id' => 42,
        'secret' => 'intact',
    ]);

    Event::listen(ContextReencrypting::class, fn (): bool => false);

    $doc->tenant_id = 99;

    expect(fn () => $doc->save())->toThrow(InvalidContextException::class);

    $fresh = EncryptedDocument::query()->find($doc->id);
    expect($fresh->tenant_id)->toBe(42);
    expect($fresh->secret)->toBe('intact');
});

it('is a no-op when the context column is not dirty', function (): void {
    $doc = EncryptedDocument::query()->create([
        'tenant_id' => 42,
        'secret' => 's',
    ]);

    Event::fake([ContextReencrypted::class]);

    $doc->note = 'added later';
    $doc->save();

    Event::assertNotDispatched(ContextReencrypted::class);
});

it('supports mass assignment with encrypted casts', function (): void {
    $doc = EncryptedDocument::query()->create([
        'tenant_id' => 42,
        'secret' => 'from-mass-assignment',
        'note' => 'also-from-mass-assignment',
    ]);

    $fresh = EncryptedDocument::query()->find($doc->id);
    expect($fresh->secret)->toBe('from-mass-assignment');
    expect($fresh->note)->toBe('also-from-mass-assignment');
});
