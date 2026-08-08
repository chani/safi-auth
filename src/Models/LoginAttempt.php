<?php

declare(strict_types=1);

namespace Safi\Extensions\Auth\Models;

final class LoginAttempt extends AbstractAuthModel
{
    public string $ip {
        get {
            $val = $this->getProperty('ip', '');
            return is_string($val) ? $val : '';
        }
        set {
            $this->setProperty('ip', trim($value));
        }
    }

    public string $username {
        get {
            $val = $this->getProperty('username', '');
            return is_string($val) ? $val : '';
        }
        set {
            $this->setProperty('username', trim($value));
        }
    }

    public string $attemptedAt {
        get {
            $val = $this->getProperty('attempted_at', '');
            return is_string($val) ? $val : '';
        }
        set {
            $this->setProperty('attempted_at', $value);
        }
    }
}
