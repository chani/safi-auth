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
use Safi\Core\Contracts\ContainerRegistrarInterface;
use Safi\Core\Contracts\DatabaseDriverInterface;
use Safi\Core\Contracts\ServiceProviderInterface;

final class AuthServiceProvider implements ServiceProviderInterface
{
    #[\Override]
    public function register(ContainerRegistrarInterface $registrar): void
    {
        $registrar->set(BruteForceShield::class, static fn(): BruteForceShield => new BruteForceShield());

        $registrar->set(AuthService::class, static fn(ContainerInterface $c): AuthService => new AuthService(
            self::getShield($c),
            self::getDb($c),
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
}
