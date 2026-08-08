<?php

declare(strict_types=1);

namespace Safi\Extensions\Auth;

use Safi\Core\Contracts\DatabaseDriverInterface;
use Safi\Core\Contracts\SecurityServiceInterface;
use Safi\Extensions\Auth\Models\LockedIp;
use Safi\Extensions\Auth\Models\LoginAttempt;
use Safi\Extensions\Auth\Models\RememberToken;
use Safi\Extensions\Auth\Models\User;
use Safi\Extensions\Auth\Models\UserSession;
use Safi\Extensions\Session\SessionServiceInterface;

final readonly class AuthService
{
    private const string SESSION_USER_KEY = 'auth_user_id';
    private const string SESSION_USERNAME_KEY = 'auth_username';
    private const string SESSION_FINGERPRINT_KEY = 'auth_fingerprint';
    private const string SESSION_SNAPSHOT_KEY = 'auth_user_snapshot';

    // Dummy hash to neutralize timing side-channels during user enumeration attempts
    private const string DUMMY_HASH = '$2y$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUU123456';

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
            // Constant-time execution to prevent timing-based user enumeration
            /** @psalm-suppress UnusedFunctionCall */
            password_verify($password, self::DUMMY_HASH);
            $this->recordFailureAndAudit($username, $ip, $shieldKey);
            return false;
        }

        if (password_verify($password, $user->password)) {
            if (password_needs_rehash($user->password, PASSWORD_DEFAULT)) {
                $this->db->transaction(function () use ($user, $password): void {
                    $user->password = password_hash($password, PASSWORD_DEFAULT);
                    $this->db->storeModel($user);
                });
            }

            $this->shield->reset($shieldKey);
            $this->login($user->getId(), $user->email);
            return true;
        }

        $this->recordFailureAndAudit($username, $ip, $shieldKey);
        return false;
    }

    public function createRememberToken(int $userId): string
    {
        $selector = bin2hex(random_bytes(16));
        $validator = bin2hex(random_bytes(32));

        $this->db->transaction(function () use ($selector, $validator, $userId): void {
            $token = $this->db->dispenseModel(RememberToken::class);
            $token->selector = $selector;
            $token->validatorHash = hash('sha256', $validator);
            $token->userId = $userId;
            $token->expiresAt = date('Y-m-d H:i:s', time() + (86400 * 30));
            $this->db->storeModel($token);
        });

        return $selector . ':' . $validator;
    }

    public function loginWithRememberToken(string $cookieValue): ?string
    {
        $parts = explode(':', $cookieValue, 2);
        if (count($parts) !== 2) {
            return null;
        }

        [$selector, $validator] = $parts;

        $token = $this->db->findOneModel(
            RememberToken::class,
            'selector = ? AND expires_at > ?',
            [$selector, date('Y-m-d H:i:s')],
        );

        if (!$token instanceof RememberToken) {
            return null;
        }

        if (!hash_equals($token->validatorHash, hash('sha256', $validator))) {
            $this->db->transaction(function () use ($token): void {
                $this->db->trashModel($token);
            });
            return null;
        }

        $user = $this->db->loadModel(User::class, $token->userId);
        if ($user->getId() <= 0) {
            $this->db->transaction(function () use ($token): void {
                $this->db->trashModel($token);
            });
            return null;
        }

        $this->db->transaction(function () use ($token): void {
            $this->db->trashModel($token);
        });

        $this->login($user->getId(), $user->email);

        return $this->createRememberToken($user->getId());
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

        $user = $this->db->loadModel(User::class, $userId);
        $role = $user->getId() > 0 ? $user->role : 'user';

        $this->session->set(self::SESSION_SNAPSHOT_KEY, [
            'id' => $userId,
            'email' => $username,
            'role' => $role,
        ]);

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

        $snapshot = $this->session->get(self::SESSION_SNAPSHOT_KEY);
        $sessId = $this->session->getId();

        if ($sessId !== '' && !is_array($snapshot)) {
            $rawUserId = $this->session->get(self::SESSION_USER_KEY, 0);
            $userId = is_numeric($rawUserId) ? (int) $rawUserId : 0;

            if ($userId > 0) {
                $user = $this->db->loadModel(User::class, $userId);
                if ($user->getId() <= 0) {
                    $this->logout();
                    return false;
                }

                $this->session->set(self::SESSION_SNAPSHOT_KEY, [
                    'id' => $userId,
                    'email' => $user->email,
                    'role' => $user->role,
                ]);
            }
        }

        $rawUserId = $this->session->get(self::SESSION_USER_KEY, 0);
        $userId = is_numeric($rawUserId) ? (int) $rawUserId : 0;
        $rawUsername = $this->session->get(self::SESSION_USERNAME_KEY, 'admin');
        $username = is_string($rawUsername) ? $rawUsername : 'admin';

        $this->syncUserSessionToDb($sessId, $userId, $username);
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

        $userSession = $existingSession ?? $this->db->findOneModel(UserSession::class, 'session_id = ?', [$sessId]);

        if ($userSession instanceof UserSession && $userSession->getId() > 0) {
            $lastActiveStr = $userSession->lastActive;
            if ($lastActiveStr !== '') {
                $lastActiveTs = strtotime($lastActiveStr);
                if ($lastActiveTs !== false && (time() - $lastActiveTs < 300)) {
                    return; // Throttle: Only update DB at most once every 5 minutes
                }
            }
        }

        $this->db->transaction(function () use ($sessId, $userId, $username, $userSession): void {
            if (!$userSession instanceof UserSession) {
                $userSession = $this->db->dispenseModel(UserSession::class);
                $userSession->sessionId = $sessId;
            }
            $userSession->userId = $userId;
            $userSession->username = $username;
            $userSession->ipAddress = $this->resolveClientIp();
            $userSession->lastActive = date('Y-m-d H:i:s');
            $this->db->storeModel($userSession);
        });
    }
}
