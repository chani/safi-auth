<?php

declare(strict_types=1);

namespace Safi\Extensions\Auth\Tests;

use PHPUnit\Framework\TestCase;
use Safi\Core\Contracts\DatabaseDriverInterface;
use Safi\Extensions\Auth\AuthService;
use Safi\Extensions\Auth\BruteForceShield;

final class AuthServiceTest extends TestCase
{
    public function testHashesAndVerifiesPassword(): void
    {
        $shield = new BruteForceShield();
        $auth = new AuthService($shield);

        $hash = $auth->hashPassword('secret123');
        $this->assertTrue($auth->verifyPassword('secret123', $hash));
        $this->assertFalse($auth->verifyPassword('wrong', $hash));
    }

    public function testLocksLoginAttemptOnFailure(): void
    {
        $shield = new BruteForceShield(maxAttempts: 2, decaySeconds: 60);
        $db = $this->createMock(DatabaseDriverInterface::class);
        $db->method('findOneModel')->willReturn(null);

        $auth = new AuthService($shield, $db);

        $this->assertFalse($auth->loginWithCredentials('testuser', 'wrongpass'));
        $this->assertFalse($auth->loginWithCredentials('testuser', 'wrongpass'));

        $this->assertTrue($shield->isLocked('testuser'));
        $this->assertFalse($auth->loginWithCredentials('testuser', 'wrongpass'));
    }
}
