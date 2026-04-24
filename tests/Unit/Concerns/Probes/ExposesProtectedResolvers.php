<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Tests\Unit\Concerns\Probes;

/**
 * Lets unit tests reach the trait's protected resolvers without going
 * through a full model lifecycle.
 */
trait ExposesProtectedResolvers
{
    public function callResolveStrategy(): string
    {
        return $this->resolveSealcraftStrategy();
    }

    public function callResolveContextType(): string
    {
        return $this->resolveSealcraftContextType();
    }

    public function callResolveContextColumn(): string
    {
        return $this->resolveSealcraftContextColumn();
    }

    public function callResolveRowContextType(): string
    {
        return $this->resolveSealcraftRowContextType();
    }

    public function callResolveRowKeyColumn(): string
    {
        return $this->resolveSealcraftRowKeyColumn();
    }

    public function callEncryptedAttributes(): array
    {
        return $this->sealcraftEncryptedAttributes();
    }

    public function callEnsureRowKeyMinted(): void
    {
        $this->ensureSealcraftRowKeyMinted();
    }

    /**
     * Direct raw-attribute write that bypasses casts and mutators — mirrors
     * what a DB hydration would put in $model->attributes.
     */
    public function setRawAttribute(string $key, mixed $value): void
    {
        $this->attributes[$key] = $value;
    }
}
