<?php

declare(strict_types=1);

namespace Safi\Extensions\Auth\Events;

final readonly class FailedLoginAttemptEvent
{
    public function __construct(
        public string $username,
        public string $ipAddress,
    ) {}
}
