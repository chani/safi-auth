<?php

/**
 * Safi Microframework - safi-auth
 * @author Jean Bruenn
 * @copyright 2026 All Rights Reserved
 * @see https://github.com/chani/safi-auth
 */

declare(strict_types=1);

namespace Safi\Extensions\Auth\Models;

final class UserSession extends AbstractModel
{
    public function getSessionId(): string
    {
        $val = $this->getProperty('session_id', '');
        return is_string($val) ? $val : '';
    }

    public function setSessionId(string $id): void
    {
        $this->setProperty('session_id', $id);
    }

    public function getUserId(): int
    {
        $val = $this->getProperty('user_id', 0);
        return is_numeric($val) ? (int) $val : 0;
    }

    public function setUserId(int $id): void
    {
        $this->setProperty('user_id', $id);
    }

    public function getUsername(): string
    {
        $val = $this->getProperty('username', '');
        return is_string($val) ? $val : '';
    }

    public function setUsername(string $username): void
    {
        $this->setProperty('username', trim($username));
    }

    public function getIpAddress(): string
    {
        $val = $this->getProperty('ip_address', '');
        return is_string($val) ? $val : '';
    }

    public function setIpAddress(string $ip): void
    {
        $this->setProperty('ip_address', $ip);
    }

    public function getLastActive(): string
    {
        $val = $this->getProperty('last_active', '');
        return is_string($val) ? $val : '';
    }

    public function setLastActive(string $dateTime): void
    {
        $this->setProperty('last_active', $dateTime);
    }
}
