<?php

/**
 * Safi Microframework - safi-auth
 * @author Jean Bruenn
 * @copyright 2026 All Rights Reserved
 * @see https://github.com/chani/safi-auth
 */

declare(strict_types=1);

namespace Safi\Extensions\Auth;

final class BruteForceShield
{
    /** @var array<string, array{attempts: int, reset_time: int}> */
    private array $storage = [];

    public function __construct(
        private readonly int $maxAttempts = 5,
        private readonly int $decaySeconds = 300,
    ) {}

    public function isLocked(string $key): bool
    {
        if (!isset($this->storage[$key])) {
            return false;
        }

        if (time() > $this->storage[$key]['reset_time']) {
            unset($this->storage[$key]);
            return false;
        }

        return $this->storage[$key]['attempts'] >= $this->maxAttempts;
    }

    public function recordFailure(string $key): void
    {
        $now = time();
        if (!isset($this->storage[$key]) || $now > $this->storage[$key]['reset_time']) {
            $this->storage[$key] = [
                'attempts' => 1,
                'reset_time' => $now + $this->decaySeconds,
            ];

            return;
        }

        $this->storage[$key]['attempts']++;
    }

    public function reset(string $key): void
    {
        unset($this->storage[$key]);
    }
}
