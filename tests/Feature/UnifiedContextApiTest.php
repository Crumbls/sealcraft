<?php

declare(strict_types=1);

/*
 * Exercises the unified context API:
 *   - $sealcraft array replaces the individual $sealcraft* properties
 *   - Encrypted / EncryptedJson accept cast parameters for per-column
 *     context overrides
 */

use Crumbls\Sealcraft\Casts\Encrypted;
use Crumbls\Sealcraft\Exceptions\InvalidContextException;
use Crumbls\Sealcraft\Exceptions\SealcraftException;
use Crumbls\Sealcraft\Models\DataKey;
use Crumbls\Sealcraft\Services\DekCache;
use Crumbls\Sealcraft\Tests\Fixtures\Unified\UnifiedPatient;

beforeEach(function (): void {
    config()->set('sealcraft.default_provider', 'null');
    config()->set('sealcraft.default_cipher', 'aes-256-gcm');
    $this->app->make(DekCache::class)->flush();
});

it('$sealcraft array drives strategy, type, and column for the whole model', function (): void {
    $patient = UnifiedPatient::query()->create([
        'patient_id' => 1001,
        'employer_id' => 5000,
        'ssn' => '111-22-3333',
    ]);

    $this->app->make(DekCache::class)->flush();
    $fresh = UnifiedPatient::query()->find($patient->id);
    expect($fresh->ssn)->toBe('111-22-3333');

    // Per-group under the model-level context (type=patient, id=1001)
    expect(DataKey::query()->forContext('patient', '1001')->active()->count())->toBe(1);
});

it('EncryptedJson on the same model uses the same model-level context', function (): void {
    $patient = UnifiedPatient::query()->create([
        'patient_id' => 1002,
        'employer_id' => 5001,
        'ssn' => 'a-ssn',
        'history' => ['note' => 'history-entry'],
    ]);

    $this->app->make(DekCache::class)->flush();
    $fresh = UnifiedPatient::query()->find($patient->id);
    expect($fresh->ssn)->toBe('a-ssn');
    expect($fresh->history)->toEqual(['note' => 'history-entry']);

    // Both columns share one DEK under (type=patient, id=1002)
    expect(DataKey::query()->forContext('patient', '1002')->active()->count())->toBe(1);
});

it('cast parameter override routes a single column to a different context', function (): void {
    $patient = UnifiedPatient::query()->create([
        'patient_id' => 1003,
        'employer_id' => 6000,
        'ssn' => 'under-patient-dek',
        'work_notes' => 'under-employer-dek',
    ]);

    // Two distinct DEKs — one per (type,id) pair — because work_notes has a cast override
    expect(DataKey::query()->forContext('patient', '1003')->active()->count())->toBe(1);
    expect(DataKey::query()->forContext('employer', '6000')->active()->count())->toBe(1);

    $this->app->make(DekCache::class)->flush();
    $fresh = UnifiedPatient::query()->find($patient->id);
    expect($fresh->ssn)->toBe('under-patient-dek');
    expect($fresh->work_notes)->toBe('under-employer-dek');
});

it('cast-override ciphertext cannot be decrypted with the model-level DEK (proves the binding)', function (): void {
    $patient = UnifiedPatient::query()->create([
        'patient_id' => 1004,
        'employer_id' => 6001,
        'ssn' => 'patient-dek',
        'work_notes' => 'employer-dek',
    ]);

    // Swap the ciphertext of a patient-context column with an employer-context column
    $patientCtCol = $patient->getRawOriginal('ssn');
    $employerCtCol = $patient->getRawOriginal('work_notes');

    \Illuminate\Support\Facades\DB::table('unified_patients')
        ->where('id', $patient->id)
        ->update(['ssn' => $employerCtCol]);

    $this->app->make(DekCache::class)->flush();

    // Reading ssn (uses patient DEK) with the employer-bound ciphertext fails
    expect(fn () => UnifiedPatient::query()->find($patient->id)->ssn)
        ->toThrow(\Crumbls\Sealcraft\Exceptions\DecryptionFailedException::class);
});

it('cast parameter override raises InvalidContext when the override column is empty', function (): void {
    $patient = UnifiedPatient::query()->create([
        'patient_id' => 1005,
        'employer_id' => null,     // work_notes cast requires this
        'ssn' => 'ok',
    ]);

    // ssn was written fine (model-level context), but setting work_notes would fail
    expect(function () use ($patient): void {
        $patient->work_notes = 'needs employer_id';
        $patient->save();
    })->toThrow(InvalidContextException::class, 'requires column [employer_id]');
});

it('rejects a cast with only type= or only column= (must be paired)', function (): void {
    expect(fn () => new Encrypted('type=patient'))
        ->toThrow(SealcraftException::class, 'BOTH `type` and `column`');

    expect(fn () => new Encrypted('column=patient_id'))
        ->toThrow(SealcraftException::class, 'BOTH `type` and `column`');
});

it('ignores unrecognized cast parameter keys gracefully', function (): void {
    $cast = new Encrypted('type=patient', 'column=patient_id', 'unknown=value');

    // No exception — unknown keys are parsed but unused
    expect($cast)->toBeInstanceOf(Encrypted::class);
});

it('discovers cast-parameterized columns in sealcraftEncryptedAttributes()', function (): void {
    $patient = new UnifiedPatient;

    $encrypted = \Closure::bind(fn () => $patient->sealcraftEncryptedAttributes(), $patient, UnifiedPatient::class)();

    expect($encrypted)->toContain('ssn');
    expect($encrypted)->toContain('history');
    expect($encrypted)->toContain('work_notes');
});
