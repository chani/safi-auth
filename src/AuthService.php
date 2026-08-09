<?php

declare(strict_types=1);

namespace Safi\Extensions\Auth;

use Safi\Core\Contracts\DatabaseDriverInterface;
use Safi\Core\Contracts\SecurityServiceInterface;
use Safi\Core\Event\EventDispatcher;
use Safi\Core\Exception\ValidationException;
use Safi\Extensions\Auth\Contracts\AuthenticationStorageInterface;
use Safi\Extensions\Auth\Events\FailedLoginAttemptEvent;
use Safi\Extensions\Auth\Events\PermissionDeniedEvent;
use Safi\Extensions\Auth\Events\TwoFactorChallengeRequestedEvent;
use Safi\Extensions\Auth\Events\UserLoggedInEvent;
use Safi\Extensions\Auth\Events\UserLoggedOutEvent;
use Safi\Extensions\Auth\Models\Group;
use Safi\Extensions\Auth\Models\GroupPermission;
use Safi\Extensions\Auth\Models\LockedIp;
use Safi\Extensions\Auth\Models\LoginAttempt;
use Safi\Extensions\Auth\Models\RememberToken;
use Safi\Extensions\Auth\Models\User;
use Safi\Extensions\Auth\Models\UserGroup;
use Safi\Extensions\Auth\Models\UserPermission;
use Safi\Extensions\Auth\Models\UserSession;
use Safi\Extensions\Auth\Services\TotpService;

final readonly class AuthService
{
    private const string SESSION_USER_KEY = 'auth_user_id';
    private const string SESSION_USERNAME_KEY = 'auth_username';
    private const string SESSION_FINGERPRINT_KEY = 'auth_fingerprint';
    private const string SESSION_SNAPSHOT_KEY = 'auth_user_snapshot';
    private const string SESSION_LAST_SYNC_KEY = 'auth_last_db_sync';
    private const string SESSION_LAST_INTERACTION_KEY = 'auth_last_interaction_time';
    private const string PENDING_2FA_USER_KEY = 'auth_pending_2fa_user_id';

    private const string DUMMY_HASH = '$2y$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUU123456';

    private int $maxIdleSeconds;
    private int $minPasswordLength;
    private string|int $hashAlgo;
    /** @var array<string, mixed> */
    private array $hashOptions;
    private string $totpAlgo;

    /**
     * @param array<string, mixed> $config Runtime auth configuration overrides
     */
    public function __construct(
        private BruteForceShield $shield,
        private DatabaseDriverInterface $db,
        private AuthenticationStorageInterface $storage,
        private SecurityServiceInterface $security,
        private EventDispatcher $eventDispatcher,
        private TotpService $totpService,
        array $config = [],
    ) {
        $this->maxIdleSeconds = is_numeric($config['max_idle_seconds'] ?? null) ? (int) $config['max_idle_seconds'] : 900;
        $this->minPasswordLength = is_numeric($config['min_password_length'] ?? null) ? (int) $config['min_password_length'] : 12;

        $rawAlgo = $config['hash_algo'] ?? PASSWORD_DEFAULT;
        $this->hashAlgo = is_string($rawAlgo) || is_int($rawAlgo) ? $rawAlgo : PASSWORD_DEFAULT;

        $rawOptions = $config['hash_options'] ?? null;
        $filteredOptions = is_array($rawOptions) ? array_filter($rawOptions, 'is_string', ARRAY_FILTER_USE_KEY) : [];
        $this->hashOptions = $filteredOptions !== [] ? $filteredOptions : ['cost' => 12];

        $this->totpAlgo = is_string($config['totp_algo'] ?? null) ? $config['totp_algo'] : 'sha256';
    }

    public function hashPassword(string $password): string
    {
        if (mb_strlen($password) < $this->minPasswordLength) {
            throw new ValidationException(
                sprintf('Password does not meet security policy requirements (minimum %d characters required).', $this->minPasswordLength),
            );
        }

        return password_hash($password, $this->hashAlgo, $this->hashOptions);
    }

    public function verifyPassword(string $password, string $hash): bool
    {
        return password_verify($password, $hash);
    }

    public function reauthenticate(string $password): bool
    {
        if (!$this->isAuthenticated()) {
            return false;
        }

        $rawUserId = $this->storage->get(self::SESSION_USER_KEY, 0);
        $userId = is_numeric($rawUserId) ? (int) $rawUserId : 0;
        if ($userId <= 0) {
            return false;
        }

        $user = $this->db->loadModel(User::class, $userId);
        if ($user->getId() <= 0) {
            return false;
        }

        return password_verify($password, $user->password);
    }

    public function loginWithCredentials(string $username, string $password): bool
    {
        $ip = $this->resolveClientIp();
        $cleanUsername = strtolower(trim($username));
        $shieldKey = $ip . ':' . $cleanUsername;

        $lockedIp = $this->db->findOneModel(LockedIp::class, 'ip = ? AND locked_until > ?', [$ip, date('Y-m-d H:i:s')]);
        if ($lockedIp instanceof LockedIp) {
            return false;
        }

        if ($this->shield->isLocked($shieldKey) || $this->shield->isLocked($ip)) {
            return false;
        }

        $user = $this->db->findOneModel(User::class, 'email = ?', [$cleanUsername]);
        if (!$user instanceof User) {
            /** @psalm-suppress UnusedFunctionCall */
            password_verify($password, self::DUMMY_HASH);
            $this->recordFailureAndAudit($cleanUsername, $ip, $shieldKey);
            return false;
        }

        if (password_verify($password, $user->password)) {
            if (password_needs_rehash($user->password, $this->hashAlgo, $this->hashOptions)) {
                $this->db->transaction(function () use ($user, $password): void {
                    $user->password = password_hash($password, $this->hashAlgo, $this->hashOptions);
                    $this->db->storeModel($user);
                });
            }

            $this->shield->reset($shieldKey);

            if ($user->is2faEnabled && $user->totpSecret !== '') {
                $this->storage->set(self::PENDING_2FA_USER_KEY, $user->getId());
                $this->eventDispatcher->dispatch(new TwoFactorChallengeRequestedEvent($user->getId()));
                return false;
            }

            $this->login($user->getId(), $user->email);
            return true;
        }

        $this->recordFailureAndAudit($cleanUsername, $ip, $shieldKey);
        return false;
    }

    public function isTwoFactorPending(): bool
    {
        return $this->storage->has(self::PENDING_2FA_USER_KEY);
    }

    public function verifyTwoFactorCode(string $code): bool
    {
        $ip = $this->resolveClientIp();
        $rawUserId = $this->storage->get(self::PENDING_2FA_USER_KEY, 0);
        $userId = is_numeric($rawUserId) ? (int) $rawUserId : 0;

        if ($userId <= 0) {
            return false;
        }

        $user = $this->db->loadModel(User::class, $userId);
        if ($user->getId() <= 0) {
            $this->storage->remove(self::PENDING_2FA_USER_KEY);
            return false;
        }

        $shieldKey = $ip . ':' . $user->email;
        if ($this->shield->isLocked($shieldKey) || $this->shield->isLocked($ip)) {
            return false;
        }

        $usedKey = 'used_totp_' . $userId . '_' . hash('sha256', $code);
        if ($this->storage->has($usedKey)) {
            $this->recordFailureAndAudit($user->email, $ip, $shieldKey);
            return false;
        }

        if ($this->totpService->verifyCode($user->totpSecret, $code, 1, null, $this->totpAlgo)) {
            $this->storage->set($usedKey, time());
            $this->storage->remove(self::PENDING_2FA_USER_KEY);
            $this->shield->reset($shieldKey);
            $this->login($user->getId(), $user->email);
            return true;
        }

        $this->recordFailureAndAudit($user->email, $ip, $shieldKey);
        return false;
    }

    public function can(User|int $user, string $permission): bool
    {
        $userId = $user instanceof User ? $user->getId() : $user;
        if ($userId <= 0) {
            return false;
        }

        $userModel = $user instanceof User ? $user : $this->db->loadModel(User::class, $userId);
        if ($userModel->getId() <= 0) {
            return false;
        }

        if ($userModel->role === 'admin') {
            return true;
        }

        $directPermission = $this->db->findOneModel(
            UserPermission::class,
            'user_id = ? AND permission_key = ?',
            [$userId, $permission],
        );
        if ($directPermission instanceof UserPermission) {
            return true;
        }

        $userGroups = $this->db->findModels(UserGroup::class, 'user_id = ?', [$userId]);
        $visitedGroups = [];

        foreach ($userGroups as $userGroup) {
            if (!$userGroup instanceof UserGroup) {
                continue;
            }

            $groupId = $userGroup->groupId;
            if ($this->checkGroupPermissionRecursive($groupId, $permission, $visitedGroups)) {
                return true;
            }
        }

        $this->eventDispatcher->dispatch(new PermissionDeniedEvent($userId, $permission));
        return false;
    }

    /**
     * @param array<int, bool> $visited
     */
    private function checkGroupPermissionRecursive(int $groupId, string $permission, array &$visited): bool
    {
        if ($groupId <= 0 || isset($visited[$groupId])) {
            return false;
        }
        $visited[$groupId] = true;

        $groupPermission = $this->db->findOneModel(
            GroupPermission::class,
            'group_id = ? AND permission_key = ?',
            [$groupId, $permission],
        );
        if ($groupPermission instanceof GroupPermission) {
            return true;
        }

        $group = $this->db->loadModel(Group::class, $groupId);
        if ($group->getId() <= 0 || $group->parentId <= 0) {
            return false;
        }

        return $this->checkGroupPermissionRecursive($group->parentId, $permission, $visited);
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
        $this->shield->recordFailure($ip);

        $this->db->transaction(function () use ($username, $ip): void {
            $attempt = $this->db->dispenseModel(LoginAttempt::class);
            $attempt->ip = $ip;
            $attempt->username = $username;
            $attempt->attemptedAt = date('Y-m-d H:i:s');
            $this->db->storeModel($attempt);

            if ($this->shield->isLocked($ip)) {
                $existingLock = $this->db->findOneModel(LockedIp::class, 'ip = ? AND locked_until > ?', [$ip, date('Y-m-d H:i:s')]);
                if (!$existingLock instanceof LockedIp) {
                    $lockedIp = $this->db->dispenseModel(LockedIp::class);
                    $lockedIp->ip = $ip;
                    $lockedIp->lockedUntil = date('Y-m-d H:i:s', time() + 1800);
                    $this->db->storeModel($lockedIp);
                }
            }
        });

        $this->eventDispatcher->dispatch(new FailedLoginAttemptEvent($username, $ip));
    }

    public function login(int $userId, string $username): void
    {
        $this->storage->start();
        $this->storage->regenerate(true);

        $sessId = $this->storage->getId();
        $this->storage->set(self::SESSION_USER_KEY, $userId);
        $this->storage->set(self::SESSION_USERNAME_KEY, $username);

        $userAgent = $this->resolveUserAgent();
        $this->storage->set(self::SESSION_FINGERPRINT_KEY, hash('sha256', $userAgent));

        $user = $this->db->loadModel(User::class, $userId);
        $role = $user->getId() > 0 ? $user->role : 'user';

        $this->storage->set(self::SESSION_SNAPSHOT_KEY, [
            'id' => $userId,
            'email' => $username,
            'role' => $role,
        ]);
        $this->storage->set(self::SESSION_LAST_INTERACTION_KEY, time());

        $ip = $this->resolveClientIp();
        $this->syncUserSessionToDb($sessId, $userId, $username);

        $this->eventDispatcher->dispatch(new UserLoggedInEvent($userId, $username, $ip));
    }

    public function logout(): void
    {
        $sessId = $this->storage->getId();
        $rawUserId = $this->storage->get(self::SESSION_USER_KEY, 0);
        $userId = is_numeric($rawUserId) ? (int) $rawUserId : 0;

        if ($sessId !== '') {
            $this->db->transaction(function () use ($sessId): void {
                $userSession = $this->db->findOneModel(UserSession::class, 'session_id = ?', [$sessId]);
                if ($userSession instanceof UserSession) {
                    $this->db->trashModel($userSession);
                }
            });
        }

        $this->storage->destroy();

        if ($userId > 0) {
            $this->eventDispatcher->dispatch(new UserLoggedOutEvent($userId, $sessId));
        }
    }

    public function check(): bool
    {
        if (!$this->storage->has(self::SESSION_USER_KEY)) {
            return false;
        }

        $lastInteraction = $this->storage->get(self::SESSION_LAST_INTERACTION_KEY);
        $now = time();
        if ($this->maxIdleSeconds > 0 && is_numeric($lastInteraction)) {
            if (($now - (int) $lastInteraction) > $this->maxIdleSeconds) {
                $this->logout();
                return false;
            }
        }
        $this->storage->set(self::SESSION_LAST_INTERACTION_KEY, $now);

        $currentAgent = $this->resolveUserAgent();
        $expectedHash = $this->storage->get(self::SESSION_FINGERPRINT_KEY);
        if (!is_string($expectedHash) || !hash_equals($expectedHash, hash('sha256', $currentAgent))) {
            $this->logout();
            return false;
        }

        $snapshot = $this->storage->get(self::SESSION_SNAPSHOT_KEY);
        $sessId = $this->storage->getId();

        if ($sessId !== '' && !is_array($snapshot)) {
            $rawUserId = $this->storage->get(self::SESSION_USER_KEY, 0);
            $userId = is_numeric($rawUserId) ? (int) $rawUserId : 0;

            if ($userId > 0) {
                $user = $this->db->loadModel(User::class, $userId);
                if ($user->getId() <= 0) {
                    $this->logout();
                    return false;
                }

                $this->storage->set(self::SESSION_SNAPSHOT_KEY, [
                    'id' => $userId,
                    'email' => $user->email,
                    'role' => $user->role,
                ]);
            }
        }

        $rawUserId = $this->storage->get(self::SESSION_USER_KEY, 0);
        $userId = is_numeric($rawUserId) ? (int) $rawUserId : 0;
        $rawUsername = $this->storage->get(self::SESSION_USERNAME_KEY, '');
        $username = is_string($rawUsername) ? $rawUsername : '';

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

        $lastSync = $this->storage->get(self::SESSION_LAST_SYNC_KEY, 0);
        if (is_numeric($lastSync) && (time() - (int) $lastSync < 300)) {
            return;
        }

        $userSession = $existingSession ?? $this->db->findOneModel(UserSession::class, 'session_id = ?', [$sessId]);

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

        $this->storage->set(self::SESSION_LAST_SYNC_KEY, time());
    }
}
