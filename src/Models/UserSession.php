<?php

declare(strict_types=1);

namespace Safi\Extensions\Auth\Models;

final class UserSession extends AbstractAuthModel
{
    public string $sessionId {
        get => $this->getString('session_id');
        set {
            $this->setProperty('session_id', $value);
        }
    }

    public int $userId {
        get => $this->getInt('user_id');
        set {
            $this->setProperty('user_id', $value);
        }
    }

    public string $username {
        get => $this->getString('username');
        set {
            $this->setProperty('username', trim($value));
        }
    }

    public string $ipAddress {
        get => $this->getString('ip_address');
        set {
            $this->setProperty('ip_address', $value);
        }
    }

    public string $lastActive {
        get => $this->getString('last_active');
        set {
            $this->setProperty('last_active', $value);
        }
    }
}
