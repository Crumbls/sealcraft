<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Contracts;

/**
 * Marker capability: provider honors the EncryptionContext as real AAD
 * at the wrap/unwrap layer. A wrap/unwrap with mismatched context must
 * fail at the provider, not just at the cipher.
 *
 * Providers without this marker either have no AAD support (e.g. Azure
 * Key Vault's wrapKey) and must synthesize it at the wrap layer, or
 * have no AAD support at all and rely solely on cipher-layer AAD.
 */
interface SupportsNativeAad extends KekProvider {}
