<?php

/**
 * Safi Microframework - safi-auth
 * @author Jean Bruenn
 * @copyright 2026 All Rights Reserved
 * @see https://github.com/chani/safi-auth
 */

declare(strict_types=1);

namespace Safi\Extensions\Auth\Models;

use Safi\Core\Contracts\ModelInterface;

/**
 * @psalm-suppress UndefinedPropertyAssignment
 * @psalm-suppress UndefinedPropertyFetch
 */
abstract class AbstractModel implements ModelInterface
{
    public function __construct(protected readonly mixed $entity = null) {}

    #[\Override]
    public function unwrap(): mixed
    {
        return $this->entity;
    }

    #[\Override]
    public function getId(): int
    {
        $id = $this->getProperty('id', 0);
        return is_numeric($id) ? (int) $id : 0;
    }

    protected function getProperty(string $property, mixed $default = null): mixed
    {
        if (is_object($this->entity)) {
            /** @phpstan-ignore property.notFound */
            return $this->entity->{$property} ?? $default;
        }

        return $default;
    }

    protected function setProperty(string $property, mixed $value): void
    {
        if (is_object($this->entity)) {
            /** @phpstan-ignore property.notFound */
            $this->entity->{$property} = $value;
        }
    }
}
