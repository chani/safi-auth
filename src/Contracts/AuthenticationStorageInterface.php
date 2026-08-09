<?php

declare(strict_types=1);

namespace Safi\Extensions\Auth\Contracts;

interface AuthenticationStorageInterface
{
    /**
     * @param array<string, mixed> $options
     */
    public function start(array $options = []): void;

    public function get(string $key, mixed $default = null): mixed;

    public function set(string $key, mixed $value): void;

    public function has(string $key): bool;

    public function remove(string $key): void;

    public function regenerate(bool $deleteOldSession = true): bool;

    public function destroy(): bool;

    public function getId(): string;
}
