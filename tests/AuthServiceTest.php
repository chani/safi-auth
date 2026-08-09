<?php

declare(strict_types=1);

namespace Safi\Extensions\Auth\Tests;

use PHPUnit\Framework\TestCase;
use Safi\Core\Contracts\SecurityServiceInterface;
use Safi\Core\Event\EventDispatcher;
use Safi\Core\Exception\ValidationException;
use Safi\Extensions\Auth\AuthService;
use Safi\Extensions\Auth\BruteForceShield;
use Safi\Extensions\Auth\Contracts\AuthenticationStorageInterface;
use Safi\Extensions\Auth\Models\User;
use Safi\Extensions\Auth\Services\TotpService;
use Safi\Extensions\DbRedBean\RedBeanDatabaseDriver;

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
        $storage = $this->createStub(AuthenticationStorageInterface::class);
        $security = $this->createStub(SecurityServiceInterface::class);
        $dispatcher = new EventDispatcher();
        $totp = new TotpService();

        $auth = new AuthService($shield, $this->db, $storage, $security, $dispatcher, $totp, ['min_password_length' => 12]);

        $hash = $auth->hashPassword('secret123456');
        $this->assertTrue($auth->verifyPassword('secret123456', $hash));
        $this->assertFalse($auth->verifyPassword('wrongpassword', $hash));
    }

    public function testRejectsShortPasswordWithValidationException(): void
    {
        $shield = new BruteForceShield();
        $storage = $this->createStub(AuthenticationStorageInterface::class);
        $security = $this->createStub(SecurityServiceInterface::class);
        $dispatcher = new EventDispatcher();
        $totp = new TotpService();

        $auth = new AuthService($shield, $this->db, $storage, $security, $dispatcher, $totp, ['min_password_length' => 12]);

        $this->expectException(ValidationException::class);
        $auth->hashPassword('short123');
    }

    public function testSuccessfulCredentialsLogin(): void
    {
        $shield = new BruteForceShield();
        $storage = $this->createMock(AuthenticationStorageInterface::class);
        $storage->expects($this->once())->method('start');
        $storage->expects($this->once())->method('regenerate')->with(true)->willReturn(true);
        $storage->expects($this->once())->method('getId')->willReturn('sess_123');

        $security = $this->createStub(SecurityServiceInterface::class);
        $security->method('getClientIp')->willReturn('127.0.0.1');
        $security->method('getUserAgent')->willReturn('PHPUnit');

        $dispatcher = new EventDispatcher();
        $totp = new TotpService();

        $user = $this->db->dispenseModel(User::class);
        $user->email = 'admin@safi.local';
        $user->password = password_hash('password123456', PASSWORD_DEFAULT);
        $this->db->storeModel($user);

        $auth = new AuthService($shield, $this->db, $storage, $security, $dispatcher, $totp);
        $result = $auth->loginWithCredentials('admin@safi.local', 'password123456');

        $this->assertTrue($result);
    }

    public function testEnforcesInactivityTimeout(): void
    {
        $shield = new BruteForceShield();
        $storage = $this->createMock(AuthenticationStorageInterface::class);

        $storage->method('has')->willReturnCallback(static fn(string $key): bool => $key === 'auth_user_id');
        $storage->method('get')->willReturnCallback(static function (string $key, mixed $default = null) {
            return match ($key) {
                'auth_last_interaction_time' => time() - 1000,
                'auth_user_id' => 1,
                default => $default,
            };
        });
        $storage->expects($this->once())->method('destroy')->willReturn(true);

        $security = $this->createStub(SecurityServiceInterface::class);
        $dispatcher = new EventDispatcher();
        $totp = new TotpService();

        $auth = new AuthService($shield, $this->db, $storage, $security, $dispatcher, $totp, ['max_idle_seconds' => 900]);

        $this->assertFalse($auth->check());
    }

    public function testReauthenticateValidatesCurrentUserPassword(): void
    {
        $shield = new BruteForceShield();
        $storage = $this->createStub(AuthenticationStorageInterface::class);

        $security = $this->createStub(SecurityServiceInterface::class);
        $security->method('getUserAgent')->willReturn('PHPUnit');
        $dispatcher = new EventDispatcher();
        $totp = new TotpService();

        $user = $this->db->dispenseModel(User::class);
        $user->email = 'admin@safi.local';
        $user->password = password_hash('password123456', PASSWORD_DEFAULT);
        $userId = $this->db->storeModel($user);

        $storage->method('has')->willReturnCallback(static fn(string $key): bool => $key === 'auth_user_id');
        $storage->method('get')->willReturnCallback(static function (string $key, mixed $default = null) use ($userId) {
            return match ($key) {
                'auth_last_interaction_time' => time(),
                'auth_fingerprint' => hash('sha256', 'PHPUnit'),
                'auth_user_snapshot' => ['id' => $userId, 'email' => 'admin@safi.local', 'role' => 'admin'],
                'auth_user_id' => $userId,
                default => $default,
            };
        });

        $auth = new AuthService($shield, $this->db, $storage, $security, $dispatcher, $totp);

        $this->assertTrue($auth->reauthenticate('password123456'));
        $this->assertFalse($auth->reauthenticate('wrongpassword'));
    }

    public function testTotpReplayProtectionRejectsReusedCode(): void
    {
        $shield = new BruteForceShield();
        $storageData = [];

        $storage = $this->createMock(AuthenticationStorageInterface::class);
        $storage->method('has')->willReturnCallback(static function (string $key) use (&$storageData): bool {
            return isset($storageData[$key]);
        });
        $storage->method('get')->willReturnCallback(static function (string $key, mixed $default = null) use (&$storageData): mixed {
            return $storageData[$key] ?? $default;
        });
        $storage->method('set')->willReturnCallback(static function (string $key, mixed $value) use (&$storageData): void {
            $storageData[$key] = $value;
        });
        $storage->method('remove')->willReturnCallback(static function (string $key) use (&$storageData): void {
            unset($storageData[$key]);
        });

        $security = $this->createStub(SecurityServiceInterface::class);
        $security->method('getClientIp')->willReturn('127.0.0.1');
        $security->method('getUserAgent')->willReturn('PHPUnit');

        $dispatcher = new EventDispatcher();
        $totp = new TotpService();

        $secret = $totp->generateSecret();
        $user = $this->db->dispenseModel(User::class);
        $user->email = '2fa_user@safi.local';
        $user->password = password_hash('password123456', PASSWORD_DEFAULT);
        $user->totpSecret = $secret;
        $user->is2faEnabled = true;
        $userId = $this->db->storeModel($user);

        $storageData['auth_pending_2fa_user_id'] = $userId;

        $auth = new AuthService($shield, $this->db, $storage, $security, $dispatcher, $totp);

        $validCode = $totp->generateCode($secret, null, 30, 6, 'sha256');

        // First verification must succeed
        $this->assertTrue($auth->verifyTwoFactorCode($validCode));

        // Set pending 2FA state again with same valid code to simulate replay attack
        $storageData['auth_pending_2fa_user_id'] = $userId;

        // Second verification with the same consumed code MUST fail (Replay Protection)
        $this->assertFalse($auth->verifyTwoFactorCode($validCode));
    }
}
