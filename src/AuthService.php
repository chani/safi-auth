<?php

declare(strict_types=1);

namespace Safi\Extensions\Auth;

use Safi\Core\Contracts\DatabaseDriverInterface;
use Safi\Core\Contracts\SecurityServiceInterface;
use Safi\Extensions\Auth\Models\LockedIp;
use Safi\Extensions\Auth\Models\LoginAttempt;
use Safi\Extensions\Auth\Models\User;
use Safi\Extensions\Auth\Models\UserSession;
use Safi\Extensions\Session\SessionServiceInterface;

final readonly class AuthService
{
    private const string SESSION_USER_KEY = 'auth_user_id';
    private const string SESSION_USERNAME_KEY = 'auth_username';
    private const string SESSION_FINGERPRINT_KEY = 'auth_fingerprint';

    public function __construct(
        private BruteForceShield $shield,
        private DatabaseDriverInterface $db,
        private SessionServiceInterface $session,
        private SecurityServiceInterface $security,
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
        $ip = $this->resolveClientIp();
        $shieldKey = $ip . ':' . $username;

        $lockedIp = $this->db->findOneModel(LockedIp::class, 'ip = ? AND locked_until > ?', [$ip, date('Y-m-d H:i:s')]);
        if ($lockedIp instanceof LockedIp) {
            return false;
        }

        if ($this->shield->isLocked($shieldKey)) {
            return false;
        }

        $user = $this->db->findOneModel(User::class, 'email = ? OR email = ?', [$username, strtolower(trim($username))]);
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

    private function recordFailureAndAudit(string $username, string $ip, string $shieldKey): void
    {
        $this->shield->recordFailure($shieldKey);

        $this->db->transaction(function () use ($username, $ip): void {
            $attempt = $this->db->dispenseModel(LoginAttempt::class);
            $attempt->ip = $ip;
            $attempt->username = $username;
            $attempt->attemptedAt = date('Y-m-d H:i:s');
            $this->db->storeModel($attempt);
        });
    }

    public function login(int $userId, string $username = 'admin'): void
    {
        $this->session->start();
        $this->session->regenerateId(true);

        $sessId = $this->session->getId();
        $this->session->set(self::SESSION_USER_KEY, $userId);
        $this->session->set(self::SESSION_USERNAME_KEY, $username);

        $userAgent = $this->resolveUserAgent();
        $this->session->set(self::SESSION_FINGERPRINT_KEY, hash('sha256', $userAgent));

        $this->syncUserSessionToDb($sessId, $userId, $username);
    }

    public function logout(): void
    {
        $sessId = $this->session->getId();

        if ($sessId !== '') {
            $this->db->transaction(function () use ($sessId): void {
                $userSession = $this->db->findOneModel(UserSession::class, 'session_id = ?', [$sessId]);
                if ($userSession instanceof UserSession) {
                    $this->db->trashModel($userSession);
                }
            });
        }

        $this->session->destroy();
    }

    public function check(): bool
    {
        if (!$this->session->has(self::SESSION_USER_KEY)) {
            return false;
        }

        $currentAgent = $this->resolveUserAgent();
        $expectedHash = $this->session->get(self::SESSION_FINGERPRINT_KEY);
        if (!is_string($expectedHash) || !hash_equals($expectedHash, hash('sha256', $currentAgent))) {
            $this->logout();
            return false;
        }

        $sessId = $this->session->getId();
        $userSession = null;
        if ($sessId !== '') {
            $userSession = $this->db->findOneModel(UserSession::class, 'session_id = ?', [$sessId]);
            if (!$userSession instanceof UserSession) {
                $this->logout();
                return false;
            }

            $rawUserId = $this->session->get(self::SESSION_USER_KEY, 0);
            $userId = is_numeric($rawUserId) ? (int) $rawUserId : 0;
            if ($userId > 0) {
                $user = $this->db->loadModel(User::class, $userId);
                if ($user->getId() <= 0) {
                    $this->logout();
                    return false;
                }
            }
        }

        $rawUserId = $this->session->get(self::SESSION_USER_KEY, 0);
        $userId = is_numeric($rawUserId) ? (int) $rawUserId : 0;
        $rawUsername = $this->session->get(self::SESSION_USERNAME_KEY, 'admin');
        $username = is_string($rawUsername) ? $rawUsername : 'admin';

        $this->syncUserSessionToDb($sessId, $userId, $username, $userSession);
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
        $this->db->transaction(function () use ($lockedIp): void {
            $ip = $lockedIp->ip;
            if ($ip !== '') {
                $this->shield->reset($ip);

                $attempts = $this->db->findModels(LoginAttempt::class, 'ip = ?', [$ip]);
                foreach ($attempts as $attempt) {
                    if ($attempt instanceof LoginAttempt) {
                        $this->shield->reset($ip . ':' . $attempt->username);
                    }
                }
            }

            if ($lockedIp->getId() > 0) {
                $this->db->trashModel($lockedIp);
            }
        });
    }

    private function resolveClientIp(): string
    {
        return $this->security->getClientIp();
    }

    private function resolveUserAgent(): string
    {
        return $this->security->getUserAgent();
    }

    private function syncUserSessionToDb(string $sessId, int $userId, string $username, ?UserSession $existingSession = null): void
    {
        if ($sessId === '') {
            return;
        }

        $this->db->transaction(function () use ($sessId, $userId, $username, $existingSession): void {
            $ip = $this->resolveClientIp();

            $userSession = $existingSession ?? $this->db->findOneModel(UserSession::class, 'session_id = ?', [$sessId]);
            if (!$userSession instanceof UserSession) {
                $userSession = $this->db->dispenseModel(UserSession::class);
                $userSession->sessionId = $sessId;
            }
            $userSession->userId = $userId;
            $userSession->username = $username;
            $userSession->ipAddress = $ip;
            $userSession->lastActive = date('Y-m-d H:i:s');
            $this->db->storeModel($userSession);
        });
    }

}
