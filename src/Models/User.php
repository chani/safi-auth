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
final class User implements ModelInterface
{
    public function __construct(private readonly mixed $entity = null) {}

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

    public function getEmail(): string
    {
        $email = $this->getProperty('email', '');
        return is_string($email) ? $email : '';
    }

    public function setEmail(string $email): void
    {
        $this->setProperty('email', strtolower(trim($email)));
    }

    public function getPassword(): string
    {
        $password = $this->getProperty('password', '');
        return is_string($password) ? $password : '';
    }

    public function setPassword(string $hash): void
    {
        $this->setProperty('password', $hash);
    }

    public function getRole(): string
    {
        $role = $this->getProperty('role', 'user');
        return is_string($role) ? $role : 'user';
    }

    public function setRole(string $role): void
    {
        $this->setProperty('role', $role);
    }

    public function getCreatedAt(): string
    {
        $time = $this->getProperty('created_at', '');
        return is_string($time) ? $time : '';
    }

    public function setCreatedAt(string $dateTime): void
    {
        $this->setProperty('created_at', $dateTime);
    }

    private function getProperty(string $property, mixed $default = null): mixed
    {
        if (is_object($this->entity)) {
            /** @phpstan-ignore property.notFound */
            return $this->entity->{$property} ?? $default;
        }

        return $default;
    }

    private function setProperty(string $property, mixed $value): void
    {
        if (is_object($this->entity)) {
            /** @phpstan-ignore property.notFound */
            $this->entity->{$property} = $value;
        }
    }
}
