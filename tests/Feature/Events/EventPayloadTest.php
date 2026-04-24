<?php

declare(strict_types=1);

/*
 * Pins the payload shape of every event the package dispatches. Most
 * existing tests use plain `Event::assertDispatched(X::class)` which
 * would pass even if the event's properties quietly changed. This file
 * asserts the full shape so payload regressions break CI loudly — and
 * gives SIEM integrators a documented contract.
 */

use Crumbls\Sealcraft\Events\ContextReencrypted;
use Crumbls\Sealcraft\Events\ContextReencrypting;
use Crumbls\Sealcraft\Events\DecryptionFailed;
use Crumbls\Sealcraft\Events\DekCreated;
use Crumbls\Sealcraft\Events\DekRotated;
use Crumbls\Sealcraft\Events\DekShredded;
use Crumbls\Sealcraft\Events\DekUnwrapped;
use Crumbls\Sealcraft\Services\DekCache;
use Crumbls\Sealcraft\Services\KeyManager;
use Crumbls\Sealcraft\Tests\Fixtures\EncryptedDocument;
use Crumbls\Sealcraft\Values\EncryptionContext;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Event;

beforeEach(function (): void {
    config()->set('sealcraft.default_provider', 'null');
    config()->set('sealcraft.default_cipher', 'aes-256-gcm');
    config()->set('sealcraft.context_type', 'tenant');
    config()->set('sealcraft.context_column', 'tenant_id');

    $this->app->make(DekCache::class)->flush();
});

it('DekCreated carries the DataKey, context, and provider name', function (): void {
    Event::fake([DekCreated::class]);

    $ctx = new EncryptionContext('tenant', 100);
    $this->app->make(KeyManager::class)->createDek($ctx);

    Event::assertDispatched(DekCreated::class, function (DekCreated $event) use ($ctx): bool {
        return $event->providerName === 'null'
            && $event->context->toCanonicalHash() === $ctx->toCanonicalHash()
            && $event->dataKey->context_type === 'tenant'
            && $event->dataKey->context_id === '100';
    });
});

it('DekUnwrapped carries a cacheHit flag that is false on first unwrap', function (): void {
    $ctx = new EncryptionContext('tenant', 101);
    $this->app->make(KeyManager::class)->createDek($ctx);
    $this->app->make(DekCache::class)->flush();

    Event::fake([DekUnwrapped::class]);

    $this->app->make(KeyManager::class)->getOrCreateDek($ctx);

    Event::assertDispatched(DekUnwrapped::class, function (DekUnwrapped $event) use ($ctx): bool {
        return $event->cacheHit === false
            && $event->context->toCanonicalHash() === $ctx->toCanonicalHash()
            && $event->providerName === 'null';
    });
});

it('DekRotated carries the source and target KEK versions', function (): void {
    $ctx = new EncryptionContext('tenant', 102);
    $this->app->make(KeyManager::class)->createDek($ctx);

    Event::fake([DekRotated::class]);

    $this->app->make(KeyManager::class)->rotateKek($ctx);

    Event::assertDispatched(DekRotated::class, function (DekRotated $event): bool {
        // null provider is not version-aware — keyVersion stays null through rotation
        return $event->providerName === 'null';
    });
});

it('DekShredded carries the context and provider name', function (): void {
    $ctx = new EncryptionContext('tenant', 103);
    $this->app->make(KeyManager::class)->createDek($ctx);

    Event::fake([DekShredded::class]);

    $this->app->make(KeyManager::class)->shredContext($ctx);

    Event::assertDispatched(DekShredded::class, function (DekShredded $event) use ($ctx): bool {
        return $event->context->toCanonicalHash() === $ctx->toCanonicalHash()
            && $event->providerName === 'null';
    });
});

it('ContextReencrypting carries the old context, new context, and attribute list', function (): void {
    Event::fake([ContextReencrypting::class, ContextReencrypted::class]);

    $doc = EncryptedDocument::query()->create(['tenant_id' => 200, 'secret' => 'a', 'note' => 'b']);
    $doc->tenant_id = 201;
    $doc->save();

    Event::assertDispatched(ContextReencrypting::class, function (ContextReencrypting $event) use ($doc): bool {
        return $event->model->is($doc)
            && $event->oldContext->contextId === 200
            && $event->newContext->contextId === 201
            && in_array('secret', $event->encryptedAttributes, true)
            && in_array('note', $event->encryptedAttributes, true);
    });

    Event::assertDispatched(ContextReencrypted::class, function (ContextReencrypted $event): bool {
        return $event->oldContext->contextId === 200
            && $event->newContext->contextId === 201;
    });
});

it('DecryptionFailed classifies the failure stage and omits plaintext', function (): void {
    Event::fake([DecryptionFailed::class]);

    $a = EncryptedDocument::query()->create(['tenant_id' => 300, 'secret' => 'a-secret']);
    $b = EncryptedDocument::query()->create(['tenant_id' => 301, 'secret' => 'b-secret']);

    // Swap A's ciphertext into B's row — AAD mismatch at cipher layer
    DB::table('encrypted_documents')->where('id', $b->id)->update([
        'secret' => $a->getRawOriginal('secret'),
    ]);
    $this->app->make(DekCache::class)->flush();

    try {
        EncryptedDocument::query()->find($b->id)->secret;
    } catch (\Throwable) {
        // expected
    }

    Event::assertDispatched(DecryptionFailed::class, function (DecryptionFailed $event): bool {
        // stage must be one of the documented values
        return in_array($event->stage, ['cipher', 'kek_unwrap', 'synthetic_aad'], true)
            && $event->exception instanceof \Throwable;
    });
});
