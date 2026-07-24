<?php

/**
 * Safi Microframework - safi-auth
 * @author Jean Bruenn
 * @copyright 2026 All Rights Reserved
 * @see https://github.com/chani/safi-auth
 */

declare(strict_types=1);

namespace Safi\Extensions\Auth\Models;

final class LockedIp extends AbstractModel
{
    public function getIp(): string
    {
        $ip = $this->getProperty('ip', '');
        return is_string($ip) ? $ip : '';
    }

    public function setIp(string $ip): void
    {
        $this->setProperty('ip', trim($ip));
    }

    public function getLockedUntil(): string
    {
        $time = $this->getProperty('locked_until', '');
        return is_string($time) ? $time : '';
    }

    public function setLockedUntil(string $dateTime): void
    {
        $this->setProperty('locked_until', $dateTime);
    }
}
