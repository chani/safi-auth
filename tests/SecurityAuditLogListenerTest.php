<?php

declare(strict_types=1);

namespace Safi\Extensions\Auth\Tests;

use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Safi\Core\Event\EventDispatcher;
use Safi\Extensions\Auth\Events\FailedLoginAttemptEvent;
use Safi\Extensions\Auth\Events\PermissionDeniedEvent;
use Safi\Extensions\Auth\Events\TwoFactorChallengeRequestedEvent;
use Safi\Extensions\Auth\Events\UserLoggedInEvent;
use Safi\Extensions\Auth\Events\UserLoggedOutEvent;
use Safi\Extensions\Auth\Listeners\SecurityAuditLogListener;

final class SecurityAuditLogListenerTest extends TestCase
{
    public function testLogsAuditEventsCorrectly(): void
    {
        $logger = $this->createMock(LoggerInterface::class);
        $logger->expects($this->exactly(3))->method('info');
        $logger->expects($this->exactly(2))->method('warning');

        $listener = new SecurityAuditLogListener($logger);
        $dispatcher = new EventDispatcher();

        $dispatcher->addListener(UserLoggedInEvent::class, [$listener, 'onUserLoggedIn']);
        $dispatcher->addListener(UserLoggedOutEvent::class, [$listener, 'onUserLoggedOut']);
        $dispatcher->addListener(FailedLoginAttemptEvent::class, [$listener, 'onFailedLogin']);
        $dispatcher->addListener(TwoFactorChallengeRequestedEvent::class, [$listener, 'on2faChallenge']);
        $dispatcher->addListener(PermissionDeniedEvent::class, [$listener, 'onPermissionDenied']);

        $dispatcher->dispatch(new UserLoggedInEvent(1, 'admin', '127.0.0.1'));
        $dispatcher->dispatch(new UserLoggedOutEvent(1, 'sess_123'));
        $dispatcher->dispatch(new FailedLoginAttemptEvent('attacker', '192.168.1.1'));
        $dispatcher->dispatch(new TwoFactorChallengeRequestedEvent(1));
        $dispatcher->dispatch(new PermissionDeniedEvent(1, 'admin.secret'));
    }
}
