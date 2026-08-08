<?php

declare(strict_types=1);

namespace Safi\Extensions\Auth;

use Psr\SimpleCache\CacheInterface;

final class BruteForceShield
{
    /** @var array<string, array{attempts: int, reset_time: int}> */
    private array $storage = [];

    public function __construct(
        private readonly ?CacheInterface $cache = null,
        private readonly int $maxAttempts = 5,
        private readonly int $decaySeconds = 300,
    ) {}

    public function isLocked(string $key): bool
    {
        if ($this->cache instanceof CacheInterface) {
            $data = $this->cache->get($this->getCacheKey($key));
            if (!is_array($data)) {
                return false;
            }

            $attempts = is_numeric($data['attempts'] ?? null) ? (int) $data['attempts'] : 0;
            return $attempts >= $this->maxAttempts;
        }

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

        if ($this->cache instanceof CacheInterface) {
            $cacheKey = $this->getCacheKey($key);
            $data = $this->cache->get($cacheKey);

            if (is_array($data) && isset($data['reset_time']) && is_numeric($data['reset_time'])) {
                $resetTime = (int) $data['reset_time'];
                if ($now > $resetTime) {
                    $attempts = 1;
                    $resetTime = $now + $this->decaySeconds;
                } else {
                    $currentAttempts = (isset($data['attempts']) && is_numeric($data['attempts'])) ? (int) $data['attempts'] : 0;
                    $attempts = $currentAttempts + 1;
                }
            } else {
                $attempts = 1;
                $resetTime = $now + $this->decaySeconds;
            }

            $remainingTtl = max(1, $resetTime - $now);

            $this->cache->set($cacheKey, [
                'attempts' => $attempts,
                'reset_time' => $resetTime,
            ], $remainingTtl);
            return;
        }

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
        if ($this->cache instanceof CacheInterface) {
            $this->cache->delete($this->getCacheKey($key));
            return;
        }

        unset($this->storage[$key]);
    }

    private function getCacheKey(string $key): string
    {
        return 'auth_shield:' . hash('sha256', $key);
    }
}
