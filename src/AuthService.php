<?php

/**
 * Safi Microframework - safi-auth
 * @author Jean Bruenn
 * @copyright 2026 All Rights Reserved
 * @see https://github.com/chani/safi-auth
 */

declare(strict_types=1);

namespace Safi\Extensions\Auth;

use Psr\Log\NullLogger;
use Safi\Core\Contracts\DatabaseDriverInterface;
use Safi\Extensions\Auth\Models\LockedIp;
use Safi\Extensions\Auth\Models\LoginAttempt;
use Safi\Extensions\Auth\Models\User;
use Safi\Extensions\Auth\Models\UserSession;
use Safi\Extensions\Session\SessionService;

final class AuthService
{
    private const string SESSION_USER_KEY = 'auth_user_id';
    private const string SESSION_USERNAME_KEY = 'auth_username';
    private const string SESSION_FINGERPRINT_KEY = 'auth_fingerprint';

    public function __construct(
        private readonly BruteForceShield $shield,
        private readonly ?DatabaseDriverInterface $db = null,
        private readonly ?SessionService $session = null,
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

        if (!$this->db instanceof DatabaseDriverInterface || $this->shield->isLocked($shieldKey)) {
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
        $session = $this->getSession();
        $session->start();
        $session->regenerateId(true);

        $sessId = $session->getId();
        $session->set(self::SESSION_USER_KEY, $userId);
        $session->set(self::SESSION_USERNAME_KEY, $username);

        $rawAgent = $_SERVER['HTTP_USER_AGENT'] ?? null;
        $userAgent = is_string($rawAgent) ? $rawAgent : 'unknown';
        $session->set(self::SESSION_FINGERPRINT_KEY, hash('sha256', $userAgent));

        if ($this->db instanceof DatabaseDriverInterface) {
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
        }
    }

    public function logout(): void
    {
        $session = $this->getSession();
        $sessId = $session->getId();

        if ($this->db instanceof DatabaseDriverInterface && $sessId !== '') {
            $userSession = $this->db->findOneModel(UserSession::class, 'session_id = ?', [$sessId]);
            if ($userSession instanceof UserSession) {
                $this->db->trashModel($userSession);
            }
        }

        $session->destroy();
    }

    public function check(): bool
    {
        $session = $this->getSession();
        if (!$session->has(self::SESSION_USER_KEY)) {
            return false;
        }

        $rawAgent = $_SERVER['HTTP_USER_AGENT'] ?? null;
        $currentAgent = is_string($rawAgent) ? $rawAgent : 'unknown';
        $expectedHash = $session->get(self::SESSION_FINGERPRINT_KEY);

        if (!is_string($expectedHash) || !hash_equals($expectedHash, hash('sha256', $currentAgent))) {
            $this->logout();
            return false;
        }

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

            if ($this->db instanceof DatabaseDriverInterface) {
                $attempts = $this->db->findModels(LoginAttempt::class, 'ip = ?', [$ip]);
                foreach ($attempts as $attempt) {
                    $this->shield->reset($ip . ':' . $attempt->username);
                }
            }
        }

        if ($this->db instanceof DatabaseDriverInterface && $lockedIp->getId() > 0) {
            $this->db->trashModel($lockedIp);
        }
    }

    public function ensureAdminUserExists(): void
    {
        if (!$this->db instanceof DatabaseDriverInterface) {
            return;
        }

        try {
            $init = new AuthDatabaseInit($this->db);
            $init->initializeSchema();

            $admin = $this->db->findOneModel(User::class, 'email = ?', ['admin']);

            if (!$admin instanceof User) {
                $user = $this->db->dispenseModel(User::class);
                $user->email = 'admin';
                $user->password = $this->hashPassword('admin');
                $user->role = 'admin';
                $user->createdAt = date('Y-m-d H:i:s');

                $this->db->storeModel($user);
            }
        } catch (\Throwable) {
            // Guard
        }
    }

    private function getSession(): SessionService
    {
        return $this->session ?? new SessionService(new NullLogger());
    }

    private function recordFailureAndAudit(string $username, string $ip, string $shieldKey): void
    {
        $this->shield->recordFailure($shieldKey);

        if ($this->db instanceof DatabaseDriverInterface) {
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
                // Guard
            }
        }
    }
}
