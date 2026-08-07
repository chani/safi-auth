<?php

declare(strict_types=1);

namespace Safi\Extensions\Auth;

use Psr\Container\ContainerInterface;
use Psr\SimpleCache\CacheInterface;
use Safi\Core\Contracts\ContainerRegistrarInterface;
use Safi\Core\Contracts\DatabaseDriverInterface;
use Safi\Core\Contracts\SecurityServiceInterface;
use Safi\Core\Contracts\ServiceProviderInterface;
use Safi\Extensions\Auth\Cli\Commands\AuthInitCommand;
use Safi\Extensions\Session\SessionServiceInterface;

final class AuthServiceProvider implements ServiceProviderInterface
{
    #[\Override]
    public function register(ContainerRegistrarInterface $registrar): void
    {
        $registrar->set(BruteForceShield::class, static function (ContainerInterface $c): BruteForceShield {
            $cache = $c->has(CacheInterface::class) ? $c->get(CacheInterface::class) : null;
            return new BruteForceShield($cache instanceof CacheInterface ? $cache : null);
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

        $registrar->set(AuthService::class, static function (ContainerInterface $c): AuthService {
            $shield = $c->get(BruteForceShield::class);
            assert($shield instanceof BruteForceShield);

            $db = $c->get(DatabaseDriverInterface::class);
            assert($db instanceof DatabaseDriverInterface);

            $session = $c->get(SessionServiceInterface::class);
            assert($session instanceof SessionServiceInterface);

            $security = $c->get(SecurityServiceInterface::class);
            assert($security instanceof SecurityServiceInterface);

            return new AuthService($shield, $db, $session, $security);
        });

        $registrar->set(AuthMiddleware::class, static function (ContainerInterface $c): AuthMiddleware {
            $auth = $c->get(AuthService::class);
            assert($auth instanceof AuthService);

            return new AuthMiddleware($auth);
        });
    }

    #[\Override]
    public function boot(ContainerInterface $container): void {}
}
