<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Values;

final class ProviderCapabilities
{
    public const AAD_NATIVE = 'native';

    public const AAD_SYNTHETIC = 'synthetic';

    public const AAD_NONE = 'none';

    public function __construct(
        public readonly bool $generatesDataKeys,
        public readonly bool $hasNativeAad,
        public readonly bool $supportsKeyVersioning,
        public readonly string $aadStrategy,
    ) {
        if (! in_array($aadStrategy, [self::AAD_NATIVE, self::AAD_SYNTHETIC, self::AAD_NONE], true)) {
            throw new \InvalidArgumentException("Unknown AAD strategy: {$aadStrategy}");
        }
    }
}
