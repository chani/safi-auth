<?php

declare(strict_types=1);

namespace Safi\Extensions\Auth\Listeners;

use Psr\Log\LoggerInterface;
use Safi\Extensions\Auth\Events\FailedLoginAttemptEvent;
use Safi\Extensions\Auth\Events\PermissionDeniedEvent;
use Safi\Extensions\Auth\Events\TwoFactorChallengeRequestedEvent;
use Safi\Extensions\Auth\Events\UserLoggedInEvent;
use Safi\Extensions\Auth\Events\UserLoggedOutEvent;

final readonly class SecurityAuditLogListener
{
    public function __construct(private LoggerInterface $logger) {}

    public function onUserLoggedIn(UserLoggedInEvent $event): void
    {
        $this->logger->info('[AUDIT] User authenticated successfully', [
            'event' => 'user_logged_in',
            'user_id' => $event->userId,
            'username' => $event->username,
            'ip' => $event->ipAddress,
        ]);
    }

    public function onUserLoggedOut(UserLoggedOutEvent $event): void
    {
        $this->logger->info('[AUDIT] User session terminated', [
            'event' => 'user_logged_out',
            'user_id' => $event->userId,
            'session_id' => $event->sessionId,
        ]);
    }

    public function onFailedLogin(FailedLoginAttemptEvent $event): void
    {
        $this->logger->warning('[AUDIT] Authentication failure recorded', [
            'event' => 'failed_login_attempt',
            'username' => $event->username,
            'ip' => $event->ipAddress,
        ]);
    }

    public function on2faChallenge(TwoFactorChallengeRequestedEvent $event): void
    {
        $this->logger->info('[AUDIT] Two-factor challenge requested', [
            'event' => '2fa_challenge_requested',
            'user_id' => $event->userId,
        ]);
    }

    public function onPermissionDenied(PermissionDeniedEvent $event): void
    {
        $this->logger->warning('[AUDIT] Access permission denied', [
            'event' => 'permission_denied',
            'user_id' => $event->userId,
            'permission' => $event->permissionKey,
        ]);
    }
}
