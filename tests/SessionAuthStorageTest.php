<?php

declare(strict_types=1);

namespace Safi\Extensions\Auth\Tests;

use PHPUnit\Framework\TestCase;
use Safi\Extensions\Auth\Storage\SessionAuthStorage;
use Safi\Extensions\Session\SessionServiceInterface;

final class SessionAuthStorageTest extends TestCase
{
    public function testDelegatesAllOperationsToSessionService(): void
    {
        $session = $this->createMock(SessionServiceInterface::class);
        $session->expects($this->once())->method('start');
        $session->expects($this->once())->method('get')->with('key', 'default')->willReturn('value');
        $session->expects($this->once())->method('set')->with('key', 'value');
        $session->expects($this->once())->method('has')->with('key')->willReturn(true);
        $session->expects($this->once())->method('remove')->with('key');
        $session->expects($this->once())->method('regenerateId')->with(true)->willReturn(true);
        $session->expects($this->once())->method('destroy')->willReturn(true);
        $session->expects($this->once())->method('getId')->willReturn('sess_123');

        $storage = new SessionAuthStorage($session);

        $storage->start();
        $this->assertSame('value', $storage->get('key', 'default'));
        $storage->set('key', 'value');
        $this->assertTrue($storage->has('key'));
        $storage->remove('key');
        $this->assertTrue($storage->regenerate(true));
        $this->assertTrue($storage->destroy());
        $this->assertSame('sess_123', $storage->getId());
    }
}
