<?php

declare(strict_types=1);

namespace Safi\Extensions\Auth\Models;

final class LoginAttempt extends AbstractAuthModel
{
    public string $ip {
        get => $this->getString('ip');
        set {
            $this->setProperty('ip', trim($value));
        }
    }

    public string $username {
        get => $this->getString('username');
        set {
            $this->setProperty('username', trim($value));
        }
    }

    public string $attemptedAt {
        get => $this->getString('attempted_at');
        set {
            $this->setProperty('attempted_at', $value);
        }
    }
}
