<?php

declare(strict_types=1);

namespace Crumbls\Sealcraft\Commands;

use Crumbls\Sealcraft\Concerns\HasEncryptedAttributes;
use Crumbls\Sealcraft\Models\DataKey;
use Illuminate\Console\Command;
use Illuminate\Database\Eloquent\Model;
use ReflectionClass;
use Symfony\Component\Finder\Finder;
use Throwable;

/**
 * Scan the application for Eloquent models using HasEncryptedAttributes
 * and print a summary table. Useful during onboarding ("show me every
 * encrypted model") and for compliance audits ("every model with
 * encrypted columns has a DEK").
 */
final class ModelsCommand extends Command
{
    protected $signature = 'sealcraft:models
        {--path=* : Additional directories to scan (relative to the app root; defaults to app/)}
        {--json : Emit a JSON array instead of a human-readable table}';

    protected $description = 'List every Eloquent model using HasEncryptedAttributes with its strategy, context, and DEK count.';

    public function handle(): int
    {
        $paths = $this->resolveScanPaths();
        $rows = [];

        foreach ($this->discoverModels($paths) as $class) {
            $rows[] = $this->describe($class);
        }

        if ($rows === []) {
            $this->warn('No models using HasEncryptedAttributes were found under: ' . implode(', ', $paths));

            return self::SUCCESS;
        }

        if ($this->option('json')) {
            $this->line((string) json_encode($rows, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));

            return self::SUCCESS;
        }

        $this->table(
            ['Model', 'Strategy', 'Context', 'Encrypted columns', 'Active DEKs'],
            array_map(static fn (array $r): array => [
                $r['model'],
                $r['strategy'],
                $r['context'],
                implode(', ', $r['encrypted_attributes']),
                (string) $r['active_deks'],
            ], $rows),
        );

        return self::SUCCESS;
    }

    /** @return array<int, string> */
    private function resolveScanPaths(): array
    {
        /** @var array<int, string> $explicit */
        $explicit = (array) $this->option('path');

        if ($explicit !== []) {
            return array_values(array_filter(array_map(static fn ($p) => is_string($p) ? $p : null, $explicit)));
        }

        $base = base_path();
        $default = $base . DIRECTORY_SEPARATOR . 'app';

        return is_dir($default) ? [$default] : [$base];
    }

    /**
     * @param  array<int, string>  $paths
     * @return iterable<int, class-string>
     */
    private function discoverModels(array $paths): iterable
    {
        $existingPaths = array_filter($paths, static fn (string $p): bool => is_dir($p));

        if ($existingPaths === []) {
            return;
        }

        $finder = Finder::create()
            ->files()
            ->in($existingPaths)
            ->name('*.php');

        foreach ($finder as $file) {
            $class = $this->classFromFile($file->getRealPath() ?: $file->getPathname());

            if ($class === null || ! class_exists($class)) {
                continue;
            }

            try {
                $reflection = new ReflectionClass($class);
            } catch (Throwable) {
                continue;
            }

            if ($reflection->isAbstract() || ! $reflection->isSubclassOf(Model::class)) {
                continue;
            }

            if (! in_array(HasEncryptedAttributes::class, class_uses_recursive($class), true)) {
                continue;
            }

            yield $class;
        }
    }

    private function classFromFile(string $path): ?string
    {
        $contents = @file_get_contents($path);

        if ($contents === false) {
            return null;
        }

        if (preg_match('/^namespace\s+([^;]+);/m', $contents, $ns) !== 1) {
            return null;
        }

        if (preg_match('/^(?:final\s+|abstract\s+)?class\s+([A-Za-z_][A-Za-z0-9_]*)/m', $contents, $cls) !== 1) {
            return null;
        }

        return trim($ns[1]) . '\\' . trim($cls[1]);
    }

    /**
     * @return array{model: string, strategy: string, context: string, encrypted_attributes: array<int, string>, active_deks: int}
     */
    private function describe(string $class): array
    {
        /** @var Model $instance */
        $instance = new $class;

        $reflection = new ReflectionClass($class);

        $strategy = $this->resolvePropertyOrConfig($reflection, $instance, 'sealcraftStrategy', 'dek_strategy', 'per_group');
        $contextType = $this->resolvePropertyOrConfig($reflection, $instance, 'sealcraftContextType', 'context_type', 'tenant');

        $contextColumn = $strategy === 'per_row'
            ? $this->resolvePropertyDefault($reflection, $instance, 'sealcraftRowKeyColumn', 'sealcraft_key')
            : $this->resolvePropertyOrConfig($reflection, $instance, 'sealcraftContextColumn', 'context_column', 'tenant_id');

        $encryptedAttributes = method_exists($instance, 'sealcraftEncryptedAttributes')
            ? (array) \Closure::bind(fn () => $instance->sealcraftEncryptedAttributes(), $instance, $class)()
            : [];

        $activeDeks = $strategy === 'per_row'
            ? DataKey::query()->where('context_type', $instance->getMorphClass())->active()->count()
            : DataKey::query()->where('context_type', $contextType)->active()->count();

        return [
            'model' => $class,
            'strategy' => $strategy,
            'context' => $strategy === 'per_row'
                ? "{$instance->getMorphClass()} (column: {$contextColumn})"
                : "{$contextType} (column: {$contextColumn})",
            'encrypted_attributes' => $encryptedAttributes,
            'active_deks' => $activeDeks,
        ];
    }

    private function resolvePropertyOrConfig(ReflectionClass $reflection, Model $instance, string $property, string $configKey, string $default): string
    {
        if ($reflection->hasProperty($property)) {
            $prop = $reflection->getProperty($property);
            if ($prop->isInitialized($instance)) {
                $value = $prop->getValue($instance);
                if (is_string($value) && $value !== '') {
                    return $value;
                }
            }
        }

        $configured = config("sealcraft.{$configKey}");

        return is_string($configured) && $configured !== '' ? $configured : $default;
    }

    private function resolvePropertyDefault(ReflectionClass $reflection, Model $instance, string $property, string $default): string
    {
        if ($reflection->hasProperty($property)) {
            $prop = $reflection->getProperty($property);
            if ($prop->isInitialized($instance)) {
                $value = $prop->getValue($instance);
                if (is_string($value) && $value !== '') {
                    return $value;
                }
            }
        }

        return $default;
    }
}
