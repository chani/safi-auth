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
use Safi\Extensions\Auth\Models\User;

final class AuthService
{
    private const string SESSION_USER_KEY = 'auth_user_id';
    private const string SESSION_USERNAME_KEY = 'auth_username';
    private const string SESSION_FINGERPRINT_KEY = 'auth_fingerprint';

    public function __construct(
        private readonly BruteForceShield $shield,
        private readonly ?DatabaseDriverInterface $db = null,
    ) {
        // DB side effects removed from constructor to prevent instantiation crashes
    }

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
        if (!$this->db instanceof DatabaseDriverInterface || $this->shield->isLocked($username)) {
            return false;
        }

        $user = $this->db->findOneModel(User::class, 'email = ?', [$username]);
        if (!$user instanceof User) {
            $this->shield->recordFailure($username);
            return false;
        }

        if (password_verify($password, $user->getPassword())) {
            $this->shield->reset($username);
            $this->login($user->getId(), $user->getEmail());
            return true;
        }

        $this->shield->recordFailure($username);
        return false;
    }

public function login(int $userId, string $username = 'admin'): void
    {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_start();
        }

        session_regenerate_id(true);

        $sessId = session_id() ?: '';
        $_SESSION[self::SESSION_USER_KEY] = $userId;
        $_SESSION[self::SESSION_USERNAME_KEY] = $username;
        $rawAgent = $_SERVER['HTTP_USER_AGENT'] ?? null;
        $userAgent = is_string($rawAgent) ? $rawAgent : 'unknown';
        $_SESSION[self::SESSION_FINGERPRINT_KEY] = hash('sha256', $userAgent);

        if ($this->db instanceof DatabaseDriverInterface) {
            $rawRemote = $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
            $ip = is_string($rawRemote) ? $rawRemote : '127.0.0.1';

            /** @var Models\UserSession|null $userSession */
            $userSession = $this->db->findOneModel(Models\UserSession::class, 'session_id = ?', [$sessId]);
            if (!$userSession instanceof Models\UserSession) {
                $userSession = $this->db->dispenseModel(Models\UserSession::class);
                $userSession->setSessionId($sessId);
            }
            $userSession->setUserId($userId);
            $userSession->setUsername($username);
            $userSession->setIpAddress($ip);
            $userSession->setLastActive(date('Y-m-d H:i:s'));
            $this->db->storeModel($userSession);
        }
    }

    public function logout(): void
    {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            session_start();
        }

        $sessId = session_id() ?: '';
        if ($this->db instanceof DatabaseDriverInterface && $sessId !== '') {
            $userSession = $this->db->findOneModel(Models\UserSession::class, 'session_id = ?', [$sessId]);
            if ($userSession instanceof Models\UserSession) {
                $this->db->trashModel($userSession);
            }
        }

        $_SESSION = [];

        if (ini_get('session.use_cookies') !== '') {
            $params = session_get_cookie_params();
            $sessionName = session_name();
            $name = is_string($sessionName) ? $sessionName : 'SAFI_SESSID';

            setcookie($name, '', [
                'expires' => time() - 42000,
                'path' => $params['path'],
                'domain' => $params['domain'],
                'secure' => $params['secure'],
                'httponly' => $params['httponly'],
                'samesite' => $params['samesite'],
            ]);
        }

        session_destroy();
    }

    public function check(): bool
    {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            return false;
        }

        if (!isset($_SESSION[self::SESSION_USER_KEY])) {
            return false;
        }

        $rawAgent = $_SERVER['HTTP_USER_AGENT'] ?? null;
        $currentAgent = is_string($rawAgent) ? $rawAgent : 'unknown';
        $expectedHash = $_SESSION[self::SESSION_FINGERPRINT_KEY] ?? '';

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

    public function ensureAdminUserExists(): void
    {
        if (!$this->db instanceof DatabaseDriverInterface) {
            return;
        }

        try {
            $init = new AuthDatabaseInit($this->db);
            $init->initializeSchema();

            $admin = $this->db->findOneModel(User::class, 'email = ?', ['admin']);

            if (!$admin instanceof \Safi\Core\Contracts\ModelInterface) {
                $user = $this->db->dispenseModel(User::class);
                $user->setEmail('admin');
                $user->setPassword($this->hashPassword('admin'));
                $user->setRole('admin');
                $user->setCreatedAt(date('Y-m-d H:i:s'));

                $this->db->storeModel($user);
            }
        } catch (\Throwable) {
            // Ignored if DB not fully ready
        }
    }
}
