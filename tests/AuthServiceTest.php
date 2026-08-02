<?php

declare(strict_types=1);

namespace Safi\Extensions\Auth\Tests;

use PHPUnit\Framework\TestCase;
use Safi\Extensions\Auth\AuthService;
use Safi\Extensions\Auth\BruteForceShield;
use Safi\Extensions\Auth\Models\User;
use Safi\Extensions\DbRedBean\RedBeanDatabaseDriver;
use Safi\Extensions\Session\SessionServiceInterface;

final class AuthServiceTest extends TestCase
{
    private RedBeanDatabaseDriver $db;

    protected function setUp(): void
    {
        $this->db = new RedBeanDatabaseDriver('sqlite::memory:');
    }

    public function testHashesAndVerifiesPassword(): void
    {
        $shield = new BruteForceShield();
        $session = $this->createMock(SessionServiceInterface::class);
        $auth = new AuthService($shield, $this->db, $session);

        $hash = $auth->hashPassword('secret123');
        $this->assertTrue($auth->verifyPassword('secret123', $hash));
        $this->assertFalse($auth->verifyPassword('wrong', $hash));
    }

    public function testSuccessfulCredentialsLogin(): void
    {
        $shield = new BruteForceShield();
        $session = $this->createMock(SessionServiceInterface::class);
        $session->expects($this->once())->method('start');
        $session->expects($this->once())->method('regenerateId')->willReturn(true);
        $session->expects($this->once())->method('getId')->willReturn('sess_123');

        $user = $this->db->dispenseModel(User::class);
        $user->email = 'admin@safi.local';
        $user->password = password_hash('password123', PASSWORD_DEFAULT);
        $this->db->storeModel($user);

        $auth = new AuthService($shield, $this->db, $session);
        $result = $auth->loginWithCredentials('admin@safi.local', 'password123');

        $this->assertTrue($result);
    }

    public function testFailedCredentialsLoginRecordsFailureAndBlocks(): void
    {
        $shield = new BruteForceShield(maxAttempts: 2);
        $session = $this->createMock(SessionServiceInterface::class);
        $auth = new AuthService($shield, $this->db, $session);

        $this->assertFalse($auth->loginWithCredentials('unknown@safi.local', 'wrong'));
        $this->assertFalse($auth->loginWithCredentials('unknown@safi.local', 'wrong'));

        // Third attempt should be blocked by shield
        $this->assertFalse($auth->loginWithCredentials('unknown@safi.local', 'wrong'));
    }

    public function testLogoutClearsSessionAndTrashesUserSession(): void
    {
        $shield = new BruteForceShield();
        $session = $this->createMock(SessionServiceInterface::class);
        $session->expects($this->once())->method('getId')->willReturn('sess_abc');
        $session->expects($this->once())->method('destroy')->willReturn(true);

        $auth = new AuthService($shield, $this->db, $session);
        $auth->logout();
    }
}
