<?php

/**
 * Safi Microframework - safi-auth
 * @author Jean Bruenn
 * @copyright 2026 All Rights Reserved
 * @see https://github.com/chani/safi-auth
 */

declare(strict_types=1);

namespace Safi\Extensions\Auth\Models;

final class LoginAttempt extends AbstractModel
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
