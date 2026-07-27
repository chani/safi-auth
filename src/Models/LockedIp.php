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

final class LockedIp extends AbstractModel
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

    public string $lockedUntil {
        get {
            $val = $this->getProperty('locked_until', '');
            return is_string($val) ? $val : '';
        }
        set {
            $this->setProperty('locked_until', $value);
        }
    }
}
