<?php

declare(strict_types=1);

namespace Safi\Extensions\Auth\Events;

final readonly class UserLoggedOutEvent
{
    public function __construct(
        public int $userId,
        public string $sessionId = '',
    ) {}
}
