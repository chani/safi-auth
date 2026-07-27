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

final class User extends AbstractModel
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
