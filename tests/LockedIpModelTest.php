<?php

/**
 * Safi Microframework - safi-auth
 * @author Jean Bruenn
 * @copyright 2026 All Rights Reserved
 * @see https://github.com/chani/safi-auth
 */

declare(strict_types=1);

namespace Safi\Extensions\Auth\Tests;

use PHPUnit\Framework\TestCase;
use Safi\Extensions\Auth\Models\LockedIp;

final class LockedIpModelTest extends TestCase
{
    public function testHandlesIpAndLockTimeSetters(): void
    {
        $lockedIp = new LockedIp();
        $lockedIp->ip = ' 192.168.1.100 ';
        $lockedIp->lockedUntil = '2026-07-25 18:00:00';

        $this->assertSame('192.168.1.100', $lockedIp->ip);
        $this->assertSame('2026-07-25 18:00:00', $lockedIp->lockedUntil);
    }
}
