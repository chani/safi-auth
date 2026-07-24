<?php

declare(strict_types=1);

namespace Safi\Extensions\Auth\Tests;

use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;
use Psr\Log\LoggerInterface;
use Safi\Core\Http\Context;
use Safi\Core\Http\Request;
use Safi\Core\Http\RequestHandlerInterface;
use Safi\Core\Http\Response;
use Safi\Extensions\Auth\AuthMiddleware;
use Safi\Extensions\Auth\AuthService;
use Safi\Extensions\Auth\BruteForceShield;

final class AuthMiddlewareTest extends TestCase
{
    public function testPassesPublicRoutesUnauthenticated(): void
    {
        $auth = new AuthService(new BruteForceShield());
        $middleware = new AuthMiddleware($auth);

        $request = new Request(server: ['REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/login']);
        $response = new Response();
        $logger = $this->createMock(LoggerInterface::class);
        $container = $this->createMock(ContainerInterface::class);

        $context = new Context($request, $response, $logger, $container);

        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects($this->once())
            ->method('handle')
            ->willReturn(new Response('OK', 200));

        $res = $middleware->process($context, $handler);
        $this->assertSame(200, $res->getStatusCode());
    }

    public function testRedirectsUnauthenticatedUserOnProtectedPath(): void
    {
        $auth = new AuthService(new BruteForceShield());
        $middleware = new AuthMiddleware($auth);

        $request = new Request(server: ['REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/admin/dashboard']);
        $response = new Response();
        $logger = $this->createMock(LoggerInterface::class);
        $container = $this->createMock(ContainerInterface::class);

        $context = new Context($request, $response, $logger, $container);

        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects($this->never())->method('handle');

        $res = $middleware->process($context, $handler);

        $this->assertSame(302, $res->getStatusCode());

        // Unabhängige & universelle Header-Extraktion über Reflection
        $location = null;
        $ref = new \ReflectionClass($res);
        foreach ($ref->getProperties() as $prop) {
            $prop->setAccessible(true);
            $val = $prop->getValue($res);
            if (is_array($val)) {
                foreach ($val as $k => $v) {
                    if (strtolower((string) $k) === 'location') {
                        $location = is_array($v) ? ($v[0] ?? null) : $v;
                        break 2;
                    }
                }
            }
        }

        $this->assertSame('/login', $location);
    }
}
