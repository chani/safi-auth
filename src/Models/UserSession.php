<?php

/**
 * Safi Microframework - safi-auth
 * @author Jean Bruenn
 * @copyright 2026 All Rights Reserved
 * @see https://github.com/chani/safi-auth
 */

declare(strict_types=1);

namespace Safi\Extensions\Auth\Models;

use Safi\Extensions\DbRedBean\AbstractModel;

final class UserSession extends AbstractModel
{
    public string $sessionId {
        get {
            $val = $this->getProperty('session_id', '');
            return is_string($val) ? $val : '';
        }
        set {
            $this->setProperty('session_id', $value);
        }
    }

    public int $userId {
        get {
            $val = $this->getProperty('user_id', 0);
            return is_numeric($val) ? (int) $val : 0;
        }
        set {
            $this->setProperty('user_id', $value);
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

    public string $ipAddress {
        get {
            $val = $this->getProperty('ip_address', '');
            return is_string($val) ? $val : '';
        }
        set {
            $this->setProperty('ip_address', $value);
        }
    }

    public string $lastActive {
        get {
            $val = $this->getProperty('last_active', '');
            return is_string($val) ? $val : '';
        }
        set {
            $this->setProperty('last_active', $value);
        }
    }
}
