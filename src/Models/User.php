<?php

/**
 * Safi Microframework - safi-auth
 * @author Jean Bruenn
 * @copyright 2026 All Rights Reserved
 * @see https://github.com/chani/safi-auth
 */

declare(strict_types=1);

namespace Safi\Extensions\Auth\Models;

final class User extends AbstractModel
{
    public function getEmail(): string
    {
        $email = $this->getProperty('email', '');
        return is_string($email) ? $email : '';
    }

    public function setEmail(string $email): void
    {
        $this->setProperty('email', strtolower(trim($email)));
    }

    public function getPassword(): string
    {
        $password = $this->getProperty('password', '');
        return is_string($password) ? $password : '';
    }

    public function setPassword(string $hash): void
    {
        $this->setProperty('password', $hash);
    }

    public function getRole(): string
    {
        $role = $this->getProperty('role', 'user');
        return is_string($role) ? $role : 'user';
    }

    public function setRole(string $role): void
    {
        $this->setProperty('role', $role);
    }

    public function getCreatedAt(): string
    {
        $time = $this->getProperty('created_at', '');
        return is_string($time) ? $time : '';
    }

    public function setCreatedAt(string $dateTime): void
    {
        $this->setProperty('created_at', $dateTime);
    }
}
