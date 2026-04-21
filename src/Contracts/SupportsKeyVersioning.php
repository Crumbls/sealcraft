<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Contracts;

use Crumbls\Sealcraft\Values\EncryptionContext;
use Crumbls\Sealcraft\Values\WrappedDek;

/**
 * Capability: provider exposes KEK versions explicitly, enabling scoped
 * rotation (rewrap only DEKs wrapped under a specific KEK version) and
 * pin-to-version wrapping for rollback scenarios.
 */
interface SupportsKeyVersioning extends KekProvider
{
    /**
     * @return array<int, string> Provider-specific version identifiers,
     *                            ordered oldest first.
     */
    public function listKeyVersions(): array;

    public function wrapWithVersion(string $plaintextDek, EncryptionContext $ctx, string $version): WrappedDek;
}
