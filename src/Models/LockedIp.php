<?php

declare(strict_types=1);

namespace Safi\Extensions\Auth\Models;

final class LockedIp extends AbstractAuthModel
{
    public string $ip {
        get => $this->getString('ip');
        set {
            $this->setProperty('ip', trim($value));
        }
    }

    public string $lockedUntil {
        get => $this->getString('locked_until');
        set {
            $this->setProperty('locked_until', $value);
        }
    }
}
