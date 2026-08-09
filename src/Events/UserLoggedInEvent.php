<?php

declare(strict_types=1);

namespace Safi\Extensions\Auth\Events;

final readonly class UserLoggedInEvent
{
    public function __construct(
        public int $userId,
        public string $username,
        public string $ipAddress = '',
    ) {}
}
