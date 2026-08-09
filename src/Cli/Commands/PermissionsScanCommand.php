<?php

declare(strict_types=1);

namespace Safi\Extensions\Auth\Cli\Commands;

use ReflectionClass;
use ReflectionMethod;
use Safi\Core\Cli\CommandInterface;
use Safi\Core\Contracts\DatabaseDriverInterface;
use Safi\Core\Util\ClassFinder;
use Safi\Extensions\Auth\Attributes\Permission;
use Safi\Extensions\Auth\Models\Permission as PermissionModel;

final readonly class PermissionsScanCommand implements CommandInterface
{
    public function __construct(
        private DatabaseDriverInterface $db,
    ) {}

    #[\Override]
    public function getName(): string
    {
        return 'auth:permissions-scan';
    }

    #[\Override]
    public function getDescription(): string
    {
        return 'Scans target directory for #[Permission] attributes and registers them in the database.';
    }

    #[\Override]
    public function getCategory(): string
    {
        return 'auth';
    }

    #[\Override]
    public function execute(array $args): int
    {
        $customDir = $args[0] ?? null;
        $scanDirs = [];

        if (is_string($customDir) && is_dir($customDir)) {
            $scanDirs[] = $customDir;
        } else {
            // Default project component scanning
            $projectRoot = getcwd();
            if (is_string($projectRoot)) {
                if (is_dir($projectRoot . '/components')) {
                    $scanDirs[] = $projectRoot . '/components';
                }
                if (is_dir($projectRoot . '/src')) {
                    $scanDirs[] = $projectRoot . '/src';
                }
            }
        }

        $registeredCount = 0;

        foreach ($scanDirs as $dir) {
            $classes = $this->findClassesInDir($dir);
            foreach ($classes as $className) {
                try {
                    $ref = new ReflectionClass($className);
                    foreach ($ref->getAttributes(Permission::class) as $attr) {
                        $permAttr = $attr->newInstance();
                        if ($this->ensurePermissionExists($permAttr)) {
                            $registeredCount++;
                        }
                    }

                    foreach ($ref->getMethods(ReflectionMethod::IS_PUBLIC) as $method) {
                        foreach ($method->getAttributes(Permission::class) as $attr) {
                            $permAttr = $attr->newInstance();
                            if ($this->ensurePermissionExists($permAttr)) {
                                $registeredCount++;
                            }
                        }
                    }
                } catch (\Throwable) {
                    // Ignore unreflectable classes
                }
            }
        }

        echo "Permission attribute scan complete. Registered {$registeredCount} new permission(s).\n";
        return 0;
    }

    private function ensurePermissionExists(Permission $perm): bool
    {
        $existing = $this->db->findOneModel(PermissionModel::class, 'key = ?', [$perm->key]);
        if (!$existing instanceof PermissionModel) {
            $this->db->transaction(function () use ($perm): void {
                $model = $this->db->dispenseModel(PermissionModel::class);
                $model->key = $perm->key;
                $model->label = $perm->label !== '' ? $perm->label : $perm->key;
                $model->category = $perm->category;
                $this->db->storeModel($model);
            });
            return true;
        }

        return false;
    }

    /**
     * @return array<int, class-string>
     */
    private function findClassesInDir(string $directory): array
    {
        if (!is_dir($directory)) {
            return [];
        }

        $classes = [];
        $iterator = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($directory));
        $regex = new \RegexIterator($iterator, '/\.php$/i');

        foreach ($regex as $file) {
            if (!$file instanceof \SplFileInfo) {
                continue;
            }
            $content = file_get_contents($file->getPathname());
            if ($content === false) {
                continue;
            }
            $className = ClassFinder::extractClassName($content);
            if ($className !== null && class_exists($className)) {
                $classes[] = $className;
            }
        }

        return $classes;
    }
}
