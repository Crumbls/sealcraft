<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Commands\Concerns;

use Crumbls\Sealcraft\Values\EncryptionContext;

trait ResolvesEncryptionContext
{
    protected function buildContext(string $type, string|int $id): EncryptionContext
    {
        return new EncryptionContext(
            contextType: $type,
            contextId: is_numeric($id) && ctype_digit((string) $id) ? (int) $id : (string) $id,
        );
    }
}
