---
title: Moving columns from APP_KEY to Sealcraft
weight: 40
---

Per-column adoption flow for apps that already use Laravel's `encrypted` cast on a field and now want that specific column protected by Sealcraft instead. This is a column-scoped migration, not a whole-app migration -- the rest of your app keeps using `Crypt` / `encrypted` as usual.

## Short version

1. Back up the database
2. Install Sealcraft, configure a KEK provider, run migrations
3. Write a one-off Artisan command that reads each encrypted column via `Crypt::decrypt` and re-assigns via the `Encrypted` cast
4. Run during a maintenance window
5. Keep `APP_KEY` around for at least one full backup cycle in case of rollback

## The migration command

```php
use App\Models\Patient;
use Illuminate\Support\Facades\Crypt;

class MigratePatientsToSealcraft extends Command
{
    protected $signature = 'migrate:patients-to-sealcraft {--dry-run}';

    public function handle(): int
    {
        Patient::query()->chunkById(500, function ($chunk): void {
            foreach ($chunk as $patient) {
                $plain = Crypt::decrypt($patient->getRawOriginal('ssn'));

                if ($this->option('dry-run')) {
                    $this->line("Would migrate patient {$patient->id}");
                    continue;
                }

                $patient->ssn = $plain;   // re-assignment triggers the Encrypted cast
                $patient->save();
            }
        });

        return self::SUCCESS;
    }
}
```

## Model config during migration

For the migration window, temporarily mark the column with **both** behaviors disabled:

1. Remove the Laravel `'encrypted'` cast (don't let it try to decrypt the new Sealcraft ciphertext)
2. Add the Sealcraft `Encrypted::class` cast
3. Use `getRawOriginal()` in the migration command to read the raw column before the cast kicks in

## After migration

- Rotate `APP_KEY` only after you have a clean backup that no longer contains `APP_KEY`-encrypted data
- Run `sealcraft:audit` to confirm every row has a DataKey
- Run a `sealcraft:rotate-kek` at the end to confirm all DEKs are wrapped under the current KEK version

## Rollback

Keep `APP_KEY` and its backups until you are certain the migration is complete. If rollback is needed:

1. Revert the cast back to `'encrypted'`
2. Restore from the last pre-migration backup
3. `APP_KEY` still works because you kept it

This is why step one is "back up the database."
