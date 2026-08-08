<?php

declare(strict_types=1);

namespace Safi\Extensions\Auth\Models;

use Safi\Core\Contracts\ModelInterface;

abstract class AbstractAuthModel implements ModelInterface
{
    public function __construct(protected mixed $storage = null)
    {
        if ($this->storage === null) {
            $this->storage = new \stdClass();
        }
    }

    #[\Override]
    public function unwrap(): mixed
    {
        return $this->storage;
    }

    #[\Override]
    public function getId(): int
    {
        if (is_object($this->storage)) {
            $id = $this->storage->id ?? 0;
            return is_numeric($id) ? (int) $id : 0;
        }

        if (is_array($this->storage)) {
            $id = $this->storage['id'] ?? 0;
            return is_numeric($id) ? (int) $id : 0;
        }

        return 0;
    }

    protected function getProperty(string $property, mixed $default = null): mixed
    {
        if (is_object($this->storage)) {
            return $this->storage->{$property} ?? $default;
        }

        if (is_array($this->storage)) {
            return $this->storage[$property] ?? $default;
        }

        return $default;
    }

    protected function setProperty(string $property, mixed $value): void
    {
        if (is_object($this->storage)) {
            $this->storage->{$property} = $value;
        } elseif (is_array($this->storage)) {
            $this->storage[$property] = $value;
        }
    }
}
