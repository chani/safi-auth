<?php

declare(strict_types=1);

namespace Safi\Extensions\Auth\Storage;

use Safi\Extensions\Auth\Contracts\AuthenticationStorageInterface;
use Safi\Extensions\Session\SessionServiceInterface;

final readonly class SessionAuthStorage implements AuthenticationStorageInterface
{
    public function __construct(
        private SessionServiceInterface $session,
    ) {}

    /**
     * @param array<string, mixed> $options
     */
    #[\Override]
    public function start(array $options = []): void
    {
        $this->session->start($options);
    }

    #[\Override]
    public function get(string $key, mixed $default = null): mixed
    {
        return $this->session->get($key, $default);
    }

    #[\Override]
    public function set(string $key, mixed $value): void
    {
        $this->session->set($key, $value);
    }

    #[\Override]
    public function has(string $key): bool
    {
        return $this->session->has($key);
    }

    #[\Override]
    public function remove(string $key): void
    {
        $this->session->remove($key);
    }

    #[\Override]
    public function regenerate(bool $deleteOldSession = true): bool
    {
        return $this->session->regenerateId($deleteOldSession);
    }

    #[\Override]
    public function destroy(): bool
    {
        return $this->session->destroy();
    }

    #[\Override]
    public function getId(): string
    {
        return $this->session->getId();
    }
}
