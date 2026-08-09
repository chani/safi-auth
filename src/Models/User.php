<?php

declare(strict_types=1);

namespace Safi\Extensions\Auth\Models;

final class User extends AbstractAuthModel
{
    public string $email {
        get {
            $val = $this->getProperty('email', '');
            return is_string($val) ? $val : '';
        }
        set {
            $this->setProperty('email', strtolower(trim($value)));
        }
    }

    public string $password {
        get {
            $val = $this->getProperty('password', '');
            return is_string($val) ? $val : '';
        }
        set {
            $this->setProperty('password', $value);
        }
    }

    public string $role {
        get {
            $val = $this->getProperty('role', 'user');
            return is_string($val) ? $val : 'user';
        }
        set {
            $this->setProperty('role', $value);
        }
    }

    public bool $mustChangePassword {
        get {
            $val = $this->getProperty('must_change_password', false);
            return (bool) $val;
        }
        set {
            $this->setProperty('must_change_password', $value ? 1 : 0);
        }
    }

    public string $totpSecret {
        get {
            $val = $this->getProperty('totp_secret', '');
            return is_string($val) ? $val : '';
        }
        set {
            $this->setProperty('totp_secret', trim($value));
        }
    }

    public bool $is2faEnabled {
        get {
            $val = $this->getProperty('is_2fa_enabled', false);
            return (bool) $val;
        }
        set {
            $this->setProperty('is_2fa_enabled', $value ? 1 : 0);
        }
    }

    public string $createdAt {
        get {
            $val = $this->getProperty('created_at', '');
            return is_string($val) ? $val : '';
        }
        set {
            $this->setProperty('created_at', $value);
        }
    }
}
