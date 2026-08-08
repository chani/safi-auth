<?php

declare(strict_types=1);

namespace Safi\Extensions\Auth\Models;

final class LockedIp extends AbstractAuthModel
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
