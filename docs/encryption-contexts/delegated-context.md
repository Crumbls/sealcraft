---
title: Delegated Context
weight: 30
---

A record delegates its encryption context to a parent so all of a user's data across multiple tables shares one DEK. This is the HIPAA primitive for one-shot crypto-shred.

## Pattern

```php
use Crumbls\Sealcraft\Casts\Encrypted;
use Crumbls\Sealcraft\Concerns\HasEncryptedAttributes;
use Crumbls\Sealcraft\Values\EncryptionContext;

class OwnedUser extends Model
{
    use HasEncryptedAttributes;

    protected string $sealcraftStrategy = 'per_row';

    protected $casts = ['ssn' => Encrypted::class, 'dob' => Encrypted::class];
}

class OwnedRecord extends Model
{
    use HasEncryptedAttributes;

    protected $casts = ['body' => Encrypted::class];

    public function owner()
    {
        return $this->belongsTo(OwnedUser::class);
    }

    public function sealcraftContext(): EncryptionContext
    {
        return $this->owner->sealcraftContext();
    }
}
```

The `OwnedUser` is the root -- its per-row DEK encrypts its own columns. `OwnedRecord` overrides `sealcraftContext()` to return the owner's context. Every related row encrypts under the same DEK.

## Right-to-be-forgotten in one shred

```bash
php artisan sealcraft:shred \
    "App\\Models\\OwnedUser" \
    <sealcraft_key>
```

One shred destroys the DEK that protected the user's columns **and** every dependent table that delegates to them. See [Crypto-shred](/documentation/sealcraft/v1/key-management/crypto-shred) for the full story.

## Loading the parent efficiently

Eager load the owner relationship when you read delegated rows, otherwise every `sealcraftContext()` call triggers a lazy-load:

```php
OwnedRecord::with('owner')->get();
```

The DEK cache absorbs repeated unwraps within a request, but the extra query round-trips are pure waste.
