<?php

/**
 * Safi Microframework - safi-auth
 * @author Jean Bruenn
 * @copyright 2026 All Rights Reserved
 * @see https://github.com/chani/safi-auth
 */

declare(strict_types=1);

namespace Safi\Extensions\Auth;

use Safi\Core\Contracts\DatabaseDriverInterface;
use Safi\Extensions\Auth\Models\LockedIp;
use Safi\Extensions\Auth\Models\LoginAttempt;
use Safi\Extensions\Auth\Models\User;
use Safi\Extensions\Auth\Models\UserSession;
use Safi\Extensions\Session\SessionServiceInterface;

final class AuthService
{
    private const string SESSION_USER_KEY = 'auth_user_id';
    private const string SESSION_USERNAME_KEY = 'auth_username';
    private const string SESSION_FINGERPRINT_KEY = 'auth_fingerprint';

    public function __construct(
        private readonly BruteForceShield $shield,
        private readonly DatabaseDriverInterface $db,
        private readonly SessionServiceInterface $session,
    ) {}

    public function hashPassword(string $password): string
    {
        return password_hash($password, PASSWORD_DEFAULT);
    }

    public function verifyPassword(string $password, string $hash): bool
    {
        return password_verify($password, $hash);
    }

    public function loginWithCredentials(string $username, string $password): bool
    {
        $rawRemote = $_SERVER['REMOTE_ADDR'] ?? null;
        $ip = is_string($rawRemote) ? $rawRemote : '127.0.0.1';
        $shieldKey = $ip . ':' . $username;

        if ($this->shield->isLocked($shieldKey)) {
            return false;
        }

        $user = $this->db->findOneModel(User::class, 'email = ?', [$username]);
        if (!$user instanceof User) {
            $this->recordFailureAndAudit($username, $ip, $shieldKey);
            return false;
        }

        if (password_verify($password, $user->password)) {
            $this->shield->reset($shieldKey);
            $this->login($user->getId(), $user->email);
            return true;
        }

        $this->recordFailureAndAudit($username, $ip, $shieldKey);
        return false;
    }

    public function login(int $userId, string $username = 'admin'): void
    {
        $this->session->start();
        $this->session->regenerateId(true);

        $sessId = $this->session->getId();
        $this->session->set(self::SESSION_USER_KEY, $userId);
        $this->session->set(self::SESSION_USERNAME_KEY, $username);

        $rawAgent = $_SERVER['HTTP_USER_AGENT'] ?? null;
        $userAgent = is_string($rawAgent) ? $rawAgent : 'unknown';
        $this->session->set(self::SESSION_FINGERPRINT_KEY, hash('sha256', $userAgent));

        $this->syncUserSessionToDb($sessId, $userId, $username);
    }

    public function logout(): void
    {
        $sessId = $this->session->getId();

        if ($sessId !== '') {
            $userSession = $this->db->findOneModel(UserSession::class, 'session_id = ?', [$sessId]);
            if ($userSession instanceof UserSession) {
                $this->db->trashModel($userSession);
            }
        }

        $this->session->destroy();
    }

    public function check(): bool
    {
        if (!$this->session->has(self::SESSION_USER_KEY)) {
            return false;
        }

        $rawAgent = $_SERVER['HTTP_USER_AGENT'] ?? null;
        $currentAgent = is_string($rawAgent) ? $rawAgent : 'unknown';
        $expectedHash = $this->session->get(self::SESSION_FINGERPRINT_KEY);

        if (!is_string($expectedHash) || !hash_equals($expectedHash, hash('sha256', $currentAgent))) {
            $this->logout();
            return false;
        }

        $rawUserId = $this->session->get(self::SESSION_USER_KEY, 0);
        $userId = is_numeric($rawUserId) ? (int) $rawUserId : 0;

        $rawUsername = $this->session->get(self::SESSION_USERNAME_KEY, 'admin');
        $username = is_string($rawUsername) ? $rawUsername : 'admin';

        $this->syncUserSessionToDb($this->session->getId(), $userId, $username);

        return true;
    }

    public function isAuthenticated(): bool
    {
        return $this->check();
    }

    public function getShield(): BruteForceShield
    {
        return $this->shield;
    }

    public function unlockIp(LockedIp $lockedIp): void
    {
        $ip = $lockedIp->ip;
        if ($ip !== '') {
            $this->shield->reset($ip);

            $attempts = $this->db->findModels(LoginAttempt::class, 'ip = ?', [$ip]);
            foreach ($attempts as $attempt) {
                $this->shield->reset($ip . ':' . $attempt->username);
            }
        }

        if ($lockedIp->getId() > 0) {
            $this->db->trashModel($lockedIp);
        }
    }

    private function syncUserSessionToDb(string $sessId, int $userId, string $username): void
    {
        if ($sessId === '') {
            return;
        }

        try {
            $rawRemote = $_SERVER['REMOTE_ADDR'] ?? null;
            $ip = is_string($rawRemote) ? $rawRemote : '127.0.0.1';

            $userSession = $this->db->findOneModel(UserSession::class, 'session_id = ?', [$sessId]);
            if (!$userSession instanceof UserSession) {
                $userSession = $this->db->dispenseModel(UserSession::class);
                $userSession->sessionId = $sessId;
            }
            $userSession->userId = $userId;
            $userSession->username = $username;
            $userSession->ipAddress = $ip;
            $userSession->lastActive = date('Y-m-d H:i:s');
            $this->db->storeModel($userSession);
        } catch (\Throwable) {
        }
    }

    private function recordFailureAndAudit(string $username, string $ip, string $shieldKey): void
    {
        $this->shield->recordFailure($shieldKey);

        try {
            $attempt = $this->db->dispenseModel(LoginAttempt::class);
            $attempt->ip = $ip;
            $attempt->username = $username;
            $attempt->attemptedAt = date('Y-m-d H:i:s');
            $this->db->storeModel($attempt);

            if ($this->shield->isLocked($shieldKey)) {
                $lockedIp = $this->db->findOneModel(LockedIp::class, 'ip = ?', [$ip]);
                if (!$lockedIp instanceof LockedIp) {
                    $lockedIp = $this->db->dispenseModel(LockedIp::class);
                    $lockedIp->ip = $ip;
                }
                $lockedIp->lockedUntil = date('Y-m-d H:i:s', time() + 300);
                $this->db->storeModel($lockedIp);
            }
        } catch (\Throwable) {
        }
    }
}
