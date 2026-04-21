<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Services;

use Crumbls\Sealcraft\Exceptions\InvalidContextException;
use Normalizer;

/**
 * Canonical, deterministic serialization for EncryptionContext.
 *
 * Produces pipe-delimited bytes:
 *     <contextType>|<contextId>|<sortedKey>=<value>|<sortedKey>=<value>...
 *
 * Rules (see plan's "Canonical serialization rules (locked)" section):
 *
 *  1. UTF-8 throughout; all string inputs are normalized to Unicode NFC
 *     before any further processing.
 *  2. Attribute keys sorted by UTF-8 byte-lexicographic order.
 *  3. Value coercion: int -> decimal string, bool -> "true"/"false",
 *     string -> NFC verbatim, null -> attribute dropped. Floats and
 *     non-scalar types rejected at construction.
 *  4. Null or empty-string attributes are stripped before canonicalization.
 *  5. Flat only; nested arrays/objects are rejected.
 *  6. Escaping within values: "\" -> "\\", "|" -> "\|". Keys must match
 *     /^[A-Za-z0-9_][A-Za-z0-9_\.\-]*$/ and cannot contain "|" or "=".
 *  7. No whitespace is injected.
 *  8. Max canonical output is 4096 bytes.
 */
final class ContextSerializer
{
    public const MAX_BYTES = 4096;

    /**
     * Attribute keys must be simple identifiers — they're part of the
     * canonical output and the AAD surface. No backslashes, pipes, etc.
     */
    private const ATTR_KEY_REGEX = '/^[A-Za-z0-9_][A-Za-z0-9_.\-]*$/';

    /**
     * Context types permit backslashes so a Laravel model FQN (e.g.
     * App\Models\Patient) can serve as a per-row context type without
     * requiring apps to register a morphMap first. Pipes and equals
     * are still forbidden since they'd break canonical parsing.
     */
    private const CONTEXT_TYPE_REGEX = '/^[A-Za-z0-9_\\\\][A-Za-z0-9_.\-\\\\]*$/';

    /**
     * @param  array<string, scalar|null>  $attributes
     */
    public static function canonicalize(string $contextType, string|int $contextId, array $attributes = []): string
    {
        $type = self::validateContextType($contextType);
        $id = self::coerceScalar($contextId, 'contextId');

        if ($id === null || $id === '') {
            throw new InvalidContextException('contextId cannot be null or empty.');
        }

        $normalized = [];

        foreach ($attributes as $key => $value) {
            if (! is_string($key)) {
                throw new InvalidContextException('Context attribute keys must be strings.');
            }

            if (preg_match(self::ATTR_KEY_REGEX, $key) !== 1) {
                throw new InvalidContextException("Invalid context attribute key: {$key}");
            }

            $coerced = self::coerceScalar($value, "attribute '{$key}'");

            if ($coerced === null || $coerced === '') {
                continue;
            }

            $normalizedKey = self::nfcOrFail($key, "attribute key '{$key}'");

            $normalized[$normalizedKey] = self::escapeValue($coerced);
        }

        ksort($normalized, SORT_STRING);

        $pieces = [$type, self::escapeValue($id)];

        foreach ($normalized as $key => $value) {
            $pieces[] = $key . '=' . $value;
        }

        $canonical = implode('|', $pieces);

        if (strlen($canonical) > self::MAX_BYTES) {
            throw new InvalidContextException(
                'Canonical context exceeds ' . self::MAX_BYTES . ' bytes.'
            );
        }

        return $canonical;
    }

    private static function validateContextType(string $value): string
    {
        if ($value === '') {
            throw new InvalidContextException('contextType cannot be empty.');
        }

        if (preg_match(self::CONTEXT_TYPE_REGEX, $value) !== 1) {
            throw new InvalidContextException("Invalid contextType: {$value}");
        }

        return self::nfcOrFail($value, 'contextType');
    }

    private static function coerceScalar(mixed $value, string $field): ?string
    {
        if ($value === null) {
            return null;
        }

        if (is_int($value)) {
            return (string) $value;
        }

        if (is_bool($value)) {
            return $value ? 'true' : 'false';
        }

        if (is_float($value)) {
            throw new InvalidContextException(
                "Float values are not supported for {$field}. Pre-serialize to string."
            );
        }

        if (is_string($value)) {
            return self::nfcOrFail($value, $field);
        }

        throw new InvalidContextException(
            "Unsupported type for {$field}: " . get_debug_type($value) . '. Context must be flat scalars.'
        );
    }

    private static function nfcOrFail(string $value, string $field): string
    {
        if (! class_exists(Normalizer::class)) {
            throw new InvalidContextException(
                'ext-intl is required for context normalization.'
            );
        }

        $normalized = Normalizer::normalize($value, Normalizer::FORM_C);

        if ($normalized === false) {
            throw new InvalidContextException("Failed to normalize {$field} to Unicode NFC.");
        }

        return $normalized;
    }

    private static function escapeValue(string $value): string
    {
        return str_replace(['\\', '|'], ['\\\\', '\\|'], $value);
    }
}
