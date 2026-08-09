<?php

declare(strict_types=1);

namespace Safi\Extensions\Auth\Models;

final class User extends AbstractAuthModel
{
    public string $email {
        get => $this->getString('email');
        set {
            $this->setProperty('email', strtolower(trim($value)));
        }
    }

    public string $password {
        get => $this->getString('password');
        set {
            $this->setProperty('password', $value);
        }
    }

    public string $role {
        get => $this->getString('role', 'user');
        set {
            $this->setProperty('role', $value);
        }
    }

    public bool $mustChangePassword {
        get => $this->getBool('must_change_password');
        set {
            $this->setProperty('must_change_password', $value ? 1 : 0);
        }
    }

    public string $totpSecret {
        get => $this->getString('totp_secret');
        set {
            $this->setProperty('totp_secret', trim($value));
        }
    }

    public bool $is2faEnabled {
        get => $this->getBool('is_2fa_enabled');
        set {
            $this->setProperty('is_2fa_enabled', $value ? 1 : 0);
        }
    }

    public string $createdAt {
        get => $this->getString('created_at');
        set {
            $this->setProperty('created_at', $value);
        }
    }
}
