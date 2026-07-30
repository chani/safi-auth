<?php

/**
 * Safi Microframework - safi-auth
 * @author Jean Bruenn
 * @copyright 2026 All Rights Reserved
 * @see https://github.com/chani/safi-auth
 */

declare(strict_types=1);

namespace Safi\Extensions\Auth\Tests;

use PHPUnit\Framework\TestCase;
use Safi\Core\Contracts\DatabaseDriverInterface;
use Safi\Extensions\Auth\AuthService;
use Safi\Extensions\Auth\BruteForceShield;
use Safi\Extensions\Session\SessionServiceInterface;

final class AuthServiceTest extends TestCase
{
    public function testHashesAndVerifiesPassword(): void
    {
        $shield = new BruteForceShield();
        $db = $this->createMock(DatabaseDriverInterface::class);
        $session = $this->createMock(SessionServiceInterface::class);
        $auth = new AuthService($shield, $db, $session);

        $hash = $auth->hashPassword('secret');
        $this->assertTrue($auth->verifyPassword('secret', $hash));
        $this->assertFalse($auth->verifyPassword('wrong', $hash));
    }

    public function testLocksLoginAttemptOnFailure(): void
    {
        $shield = new BruteForceShield(maxAttempts: 5);
        $db = $this->createMock(DatabaseDriverInterface::class);
        $session = $this->createMock(SessionServiceInterface::class);
        new AuthService($shield, $db, $session);

        $ip = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
        $key = $ip . ':admin';

        for ($i = 0; $i < 5; $i++) {
            $shield->recordFailure($key);
        }

        $this->assertTrue($shield->isLocked($key));
    }
}
