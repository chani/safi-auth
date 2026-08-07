<?php

declare(strict_types=1);

namespace Safi\Extensions\Auth\Tests;

use PHPUnit\Framework\TestCase;
use Safi\Core\Contracts\SecurityServiceInterface;
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
        $session = $this->createStub(SessionServiceInterface::class);
        $security = $this->createStub(SecurityServiceInterface::class);
        $auth = new AuthService($shield, $this->db, $session, $security);

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

        $security = $this->createStub(SecurityServiceInterface::class);
        $security->method('getClientIp')->willReturn('127.0.0.1');
        $security->method('getUserAgent')->willReturn('PHPUnit');

        $user = $this->db->dispenseModel(User::class);
        $user->email = 'admin@safi.local';
        $user->password = password_hash('password123', PASSWORD_DEFAULT);
        $this->db->storeModel($user);

        $auth = new AuthService($shield, $this->db, $session, $security);
        $result = $auth->loginWithCredentials('admin@safi.local', 'password123');

        $this->assertTrue($result);
    }

    public function testFailedCredentialsLoginRecordsFailureAndBlocks(): void
    {
        $shield = new BruteForceShield(maxAttempts: 2);
        $session = $this->createStub(SessionServiceInterface::class);
        $security = $this->createStub(SecurityServiceInterface::class);
        $security->method('getClientIp')->willReturn('127.0.0.1');
        $security->method('getUserAgent')->willReturn('PHPUnit');

        $auth = new AuthService($shield, $this->db, $session, $security);

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
        $security = $this->createStub(SecurityServiceInterface::class);

        $auth = new AuthService($shield, $this->db, $session, $security);
        $auth->logout();
    }
}
