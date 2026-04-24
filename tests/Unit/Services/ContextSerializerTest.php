<?php

declare(strict_types=1);

use Crumbls\Sealcraft\Exceptions\InvalidContextException;
use Crumbls\Sealcraft\Services\ContextSerializer;

it('produces pipe-delimited bytes with sorted attribute keys', function (): void {
    $bytes = ContextSerializer::canonicalize('tenant', '42', [
        'region' => 'us-east-1',
        'env' => 'prod',
    ]);

    expect($bytes)->toBe('tenant|42|env=prod|region=us-east-1');
});

it('includes only type and id when no attributes are provided', function (): void {
    expect(ContextSerializer::canonicalize('tenant', '42'))->toBe('tenant|42');
});

it('accepts integer contextId and coerces to decimal string', function (): void {
    expect(ContextSerializer::canonicalize('tenant', 42))->toBe('tenant|42');
});

it('escapes pipes and backslashes inside values', function (): void {
    $bytes = ContextSerializer::canonicalize('tenant', 'a|b\\c');
    expect($bytes)->toBe('tenant|a\\|b\\\\c');
});

it('allows backslash-laden context types so FQN morph classes work', function (): void {
    expect(ContextSerializer::canonicalize('App\\Models\\Patient', '7'))
        ->toBe('App\\Models\\Patient|7');
});

it('strips null attributes entirely', function (): void {
    expect(ContextSerializer::canonicalize('tenant', '1', ['unused' => null, 'kept' => 'yes']))
        ->toBe('tenant|1|kept=yes');
});

it('strips empty-string attributes entirely', function (): void {
    expect(ContextSerializer::canonicalize('tenant', '1', ['empty' => '', 'kept' => 'yes']))
        ->toBe('tenant|1|kept=yes');
});

it('coerces booleans to "true"/"false" strings', function (): void {
    expect(ContextSerializer::canonicalize('tenant', '1', ['admin' => true, 'beta' => false]))
        ->toBe('tenant|1|admin=true|beta=false');
});

it('rejects float values with an actionable error', function (): void {
    expect(fn () => ContextSerializer::canonicalize('tenant', '1', ['weight' => 1.5]))
        ->toThrow(InvalidContextException::class, 'Pre-serialize to string');
});

it('rejects nested arrays', function (): void {
    expect(fn () => ContextSerializer::canonicalize('tenant', '1', ['nested' => ['a' => 'b']]))
        ->toThrow(InvalidContextException::class, 'flat scalars');
});

it('rejects object attributes even if stringable', function (): void {
    $obj = new class {
        public function __toString(): string
        {
            return 'x';
        }
    };

    expect(fn () => ContextSerializer::canonicalize('tenant', '1', ['bad' => $obj]))
        ->toThrow(InvalidContextException::class, 'flat scalars');
});

it('rejects an empty contextType', function (): void {
    expect(fn () => ContextSerializer::canonicalize('', '1'))
        ->toThrow(InvalidContextException::class, 'cannot be empty');
});

it('rejects a contextType containing pipes', function (): void {
    expect(fn () => ContextSerializer::canonicalize('a|b', '1'))
        ->toThrow(InvalidContextException::class, 'Invalid contextType');
});

it('rejects an empty contextId', function (): void {
    expect(fn () => ContextSerializer::canonicalize('tenant', ''))
        ->toThrow(InvalidContextException::class, 'cannot be null or empty');
});

it('rejects attribute keys containing pipes or equals', function (): void {
    expect(fn () => ContextSerializer::canonicalize('tenant', '1', ['a|b' => 'x']))
        ->toThrow(InvalidContextException::class, 'Invalid context attribute key');
    expect(fn () => ContextSerializer::canonicalize('tenant', '1', ['a=b' => 'x']))
        ->toThrow(InvalidContextException::class, 'Invalid context attribute key');
});

it('rejects attribute keys that start with a dot', function (): void {
    expect(fn () => ContextSerializer::canonicalize('tenant', '1', ['.leading' => 'x']))
        ->toThrow(InvalidContextException::class, 'Invalid context attribute key');
});

it('rejects non-string attribute keys', function (): void {
    expect(fn () => ContextSerializer::canonicalize('tenant', '1', [42 => 'value']))
        ->toThrow(InvalidContextException::class, 'keys must be strings');
});

it('throws when the canonical form exceeds 4096 bytes', function (): void {
    $huge = str_repeat('x', 5000);
    expect(fn () => ContextSerializer::canonicalize('tenant', '1', ['big' => $huge]))
        ->toThrow(InvalidContextException::class, 'exceeds 4096 bytes');
});

it('normalizes Unicode values to NFC', function (): void {
    // "é" as U+00E9 (NFC) vs "e" + U+0301 (NFD) must canonicalize identically.
    $nfc = "\xC3\xA9";
    $nfd = "e\xCC\x81";

    $a = ContextSerializer::canonicalize('tenant', '1', ['name' => $nfc]);
    $b = ContextSerializer::canonicalize('tenant', '1', ['name' => $nfd]);

    expect($a)->toBe($b);
});

it('is deterministic — equivalent inputs produce identical bytes', function (): void {
    $a = ContextSerializer::canonicalize('tenant', '1', ['b' => '2', 'a' => '1']);
    $b = ContextSerializer::canonicalize('tenant', '1', ['a' => '1', 'b' => '2']);

    expect($a)->toBe($b);
});
