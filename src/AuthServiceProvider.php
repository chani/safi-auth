<?php

/**
 * Safi Microframework - safi-auth
 * @author Jean Bruenn
 * @copyright 2026 All Rights Reserved
 * @see https://github.com/chani/safi-auth
 */

declare(strict_types=1);

namespace Safi\Extensions\Auth;

use Psr\Container\ContainerInterface;
use Psr\SimpleCache\CacheInterface;
use Safi\Core\Contracts\ContainerRegistrarInterface;
use Safi\Core\Contracts\DatabaseDriverInterface;
use Safi\Core\Contracts\ServiceProviderInterface;
use Safi\Extensions\Session\SessionService;

final class AuthServiceProvider implements ServiceProviderInterface
{
    #[\Override]
    public function register(ContainerRegistrarInterface $registrar): void
    {
        $registrar->set(BruteForceShield::class, static function (ContainerInterface $c): BruteForceShield {
            $cache = $c->has(CacheInterface::class) ? $c->get(CacheInterface::class) : null;
            return new BruteForceShield($cache instanceof CacheInterface ? $cache : null);
        });

        $registrar->set(AuthService::class, static fn(ContainerInterface$c): AuthService => new AuthService(
            self::getShield($c),
            self::getDb($c),
            self::getSession($c),
        ));

        $registrar->set(AuthMiddleware::class, static fn(ContainerInterface$c): AuthMiddleware => new AuthMiddleware(
            self::getAuth($c),
            self::getSession($c),
        ));
    }

    #[\Override]
    public function boot(ContainerInterface $container): void {}

    private static function getShield(ContainerInterface $container): BruteForceShield
    {
        $shield = $container->get(BruteForceShield::class);
        assert($shield instanceof BruteForceShield);

        return $shield;
    }

    private static function getDb(ContainerInterface $container): DatabaseDriverInterface
    {
        $db = $container->get(DatabaseDriverInterface::class);
        assert($db instanceof DatabaseDriverInterface);

        return $db;
    }

    private static function getAuth(ContainerInterface $container): AuthService
    {
        $auth = $container->get(AuthService::class);
        assert($auth instanceof AuthService);

        return $auth;
    }

    private static function getSession(ContainerInterface $container): SessionService
    {
        $session = $container->get(SessionService::class);
        assert($session instanceof SessionService);

        return $session;
    }
}
