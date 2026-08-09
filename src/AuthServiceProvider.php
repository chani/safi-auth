<?php

declare(strict_types=1);

namespace Safi\Extensions\Auth;

use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;
use Psr\SimpleCache\CacheInterface;
use Safi\Core\Contracts\ContainerRegistrarInterface;
use Safi\Core\Contracts\DatabaseDriverInterface;
use Safi\Core\Contracts\RouterInterface;
use Safi\Core\Contracts\SecurityServiceInterface;
use Safi\Core\Contracts\ServiceProviderInterface;
use Safi\Core\Event\EventDispatcher;
use Safi\Extensions\Auth\Cli\Commands\AuthInitCommand;
use Safi\Extensions\Auth\Cli\Commands\PermissionsScanCommand;
use Safi\Extensions\Auth\Contracts\AuthenticationStorageInterface;
use Safi\Extensions\Auth\Events\FailedLoginAttemptEvent;
use Safi\Extensions\Auth\Events\PermissionDeniedEvent;
use Safi\Extensions\Auth\Events\TwoFactorChallengeRequestedEvent;
use Safi\Extensions\Auth\Events\UserLoggedInEvent;
use Safi\Extensions\Auth\Events\UserLoggedOutEvent;
use Safi\Extensions\Auth\Listeners\SecurityAuditLogListener;
use Safi\Extensions\Auth\Services\TotpService;
use Safi\Extensions\Auth\Storage\SessionAuthStorage;
use Safi\Extensions\Session\SessionServiceInterface;

final class AuthServiceProvider implements ServiceProviderInterface
{
    /**
     * @param array<string, mixed> $config Auth configuration parameters
     */
    public function __construct(private readonly array $config = []) {}

    #[\Override]
    public function register(ContainerRegistrarInterface $registrar): void
    {
        $registrar->set(BruteForceShield::class, function (ContainerInterface $c): BruteForceShield {
            $cache = $c->has(CacheInterface::class) ? $c->get(CacheInterface::class) : null;
            $logger = $c->has(LoggerInterface::class) ? $c->get(LoggerInterface::class) : null;
            return new BruteForceShield(
                cache: $cache instanceof CacheInterface ? $cache : null,
                logger: $logger instanceof LoggerInterface ? $logger : null,
            );
        });

        $registrar->set(TotpService::class, static fn(): TotpService => new TotpService());

        $registrar->set(AuthenticationStorageInterface::class, static function (ContainerInterface $c): AuthenticationStorageInterface {
            $session = $c->get(SessionServiceInterface::class);
            assert($session instanceof SessionServiceInterface);
            return new SessionAuthStorage($session);
        });

        $registrar->set(AuthDatabaseInit::class, static function (ContainerInterface $c): AuthDatabaseInit {
            $db = $c->get(DatabaseDriverInterface::class);
            assert($db instanceof DatabaseDriverInterface);
            return new AuthDatabaseInit($db);
        });

        $registrar->set(AuthInitCommand::class, static function (ContainerInterface $c): AuthInitCommand {
            $init = $c->get(AuthDatabaseInit::class);
            assert($init instanceof AuthDatabaseInit);
            return new AuthInitCommand($init);
        });

        $registrar->set(PermissionsScanCommand::class, static function (ContainerInterface $c): PermissionsScanCommand {
            $db = $c->get(DatabaseDriverInterface::class);
            assert($db instanceof DatabaseDriverInterface);
            return new PermissionsScanCommand($db);
        });

        $registrar->set(AuthService::class, function (ContainerInterface $c): AuthService {
            $shield = $c->get(BruteForceShield::class);
            assert($shield instanceof BruteForceShield);

            $db = $c->get(DatabaseDriverInterface::class);
            assert($db instanceof DatabaseDriverInterface);

            $storage = $c->get(AuthenticationStorageInterface::class);
            assert($storage instanceof AuthenticationStorageInterface);

            $security = $c->get(SecurityServiceInterface::class);
            assert($security instanceof SecurityServiceInterface);

            $eventDispatcher = $c->has(EventDispatcher::class)
                ? $c->get(EventDispatcher::class)
                : new EventDispatcher();
            assert($eventDispatcher instanceof EventDispatcher);

            $totp = $c->get(TotpService::class);
            assert($totp instanceof TotpService);

            return new AuthService($shield, $db, $storage, $security, $eventDispatcher, $totp, $this->config);
        });

        $registrar->set(AuthMiddleware::class, static function (ContainerInterface $c): AuthMiddleware {
            $auth = $c->get(AuthService::class);
            assert($auth instanceof AuthService);

            $router = $c->has(RouterInterface::class) ? $c->get(RouterInterface::class) : null;
            assert($router === null || $router instanceof RouterInterface);

            return new AuthMiddleware($auth, $router);
        });
    }

    #[\Override]
    public function boot(ContainerInterface $container): void
    {
        if ($container->has(EventDispatcher::class) && $container->has(LoggerInterface::class)) {
            /** @var EventDispatcher $dispatcher */
            $dispatcher = $container->get(EventDispatcher::class);
            /** @var LoggerInterface $logger */
            $logger = $container->get(LoggerInterface::class);

            $auditListener = new SecurityAuditLogListener($logger);

            // PHP 8.1 First-Class Callable Syntax
            $dispatcher->addListener(UserLoggedInEvent::class, $auditListener->onUserLoggedIn(...));
            $dispatcher->addListener(UserLoggedOutEvent::class, $auditListener->onUserLoggedOut(...));
            $dispatcher->addListener(FailedLoginAttemptEvent::class, $auditListener->onFailedLogin(...));
            $dispatcher->addListener(TwoFactorChallengeRequestedEvent::class, $auditListener->on2faChallenge(...));
            $dispatcher->addListener(PermissionDeniedEvent::class, $auditListener->onPermissionDenied(...));
        }
    }
}
