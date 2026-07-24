<?php

declare(strict_types=1);

namespace Safi\Extensions\Auth\Tests;

use PHPUnit\Framework\TestCase;
use Safi\Extensions\Auth\Models\LockedIp;

final class LockedIpModelTest extends TestCase
{
    public function testHandlesIpAndLockTimeSetters(): void
    {
        $entity = new \stdClass();
        $model = new LockedIp($entity);

        $model->setIp('192.168.1.1');
        $model->setLockedUntil('2026-12-31 23:59:59');

        $this->assertSame('192.168.1.1', $model->getIp());
        $this->assertSame('2026-12-31 23:59:59', $model->getLockedUntil());
    }
}
