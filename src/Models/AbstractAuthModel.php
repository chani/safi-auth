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
        return $this->getInt('id');
    }

    protected function getString(string $property, string $default = ''): string
    {
        $val = $this->getProperty($property, $default);
        return is_string($val) ? $val : $default;
    }

    protected function getInt(string $property, int $default = 0): int
    {
        $val = $this->getProperty($property, $default);
        return is_numeric($val) ? (int) $val : $default;
    }

    protected function getBool(string $property, bool $default = false): bool
    {
        return (bool) $this->getProperty($property, $default);
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
