<?php

declare(strict_types=1);

namespace Safi\Extensions\Auth\Tests;

use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Safi\Core\Contracts\DatabaseDriverInterface;
use Safi\Core\Contracts\SecurityServiceInterface;
use Safi\Core\Event\EventDispatcher;
use Safi\Core\Http\Context;
use Safi\Core\Http\Request;
use Safi\Core\Http\RequestHandlerInterface;
use Safi\Core\Http\Response;
use Safi\Extensions\Auth\AuthMiddleware;
use Safi\Extensions\Auth\AuthService;
use Safi\Extensions\Auth\BruteForceShield;
use Safi\Extensions\Auth\Contracts\AuthenticationStorageInterface;
use Safi\Extensions\Auth\Services\TotpService;

final class AuthMiddlewareTest extends TestCase
{
    public function testPassesPublicRoutesUnauthenticated(): void
    {
        $storage = $this->createStub(AuthenticationStorageInterface::class);
        $db = $this->createStub(DatabaseDriverInterface::class);
        $security = $this->createStub(SecurityServiceInterface::class);
        $dispatcher = new EventDispatcher();
        $totp = new TotpService();

        $auth = new AuthService(new BruteForceShield(), $db, $storage, $security, $dispatcher, $totp);
        $middleware = new AuthMiddleware($auth);

        $request = new Request(server: ['REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/login']);
        $request->setAttribute('route_handler', ['AuthController', 'showLogin']);
        $request->setAttribute('route_options', ['public' => true]);
        $response = new Response();
        $logger = $this->createStub(LoggerInterface::class);

        $context = new Context($request, $response, $logger);

        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects($this->once())
            ->method('handle')
            ->willReturn(new Response('OK', 200));

        $res = $middleware->process($context, $handler);
        $this->assertSame(200, $res->getStatusCode());
    }

    public function testRedirectsUnauthenticatedUserOnProtectedPath(): void
    {
        $storage = $this->createStub(AuthenticationStorageInterface::class);
        $db = $this->createStub(DatabaseDriverInterface::class);
        $security = $this->createStub(SecurityServiceInterface::class);
        $dispatcher = new EventDispatcher();
        $totp = new TotpService();

        $auth = new AuthService(new BruteForceShield(), $db, $storage, $security, $dispatcher, $totp);
        $middleware = new AuthMiddleware($auth);

        $request = new Request(server: ['REQUEST_METHOD' => 'GET', 'REQUEST_URI' => '/admin/dashboard']);
        $request->setAttribute('route_handler', ['AdminController', 'dashboard']);
        $request->setAttribute('route_options', ['public' => false]);
        $response = new Response();
        $logger = $this->createStub(LoggerInterface::class);

        $context = new Context($request, $response, $logger);

        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects($this->never())->method('handle');

        $res = $middleware->process($context, $handler);

        $this->assertSame(302, $res->getStatusCode());
        $this->assertArrayHasKey('Location', $res->getHeaders());
        $this->assertSame('/login', $res->getHeaders()['Location']);
    }

    public function testReturns401OnXhrRequest(): void
    {
        $storage = $this->createStub(AuthenticationStorageInterface::class);
        $db = $this->createStub(DatabaseDriverInterface::class);
        $security = $this->createStub(SecurityServiceInterface::class);
        $dispatcher = new EventDispatcher();
        $totp = new TotpService();

        $auth = new AuthService(new BruteForceShield(), $db, $storage, $security, $dispatcher, $totp);
        $middleware = new AuthMiddleware($auth);

        $request = new Request(server: [
            'REQUEST_METHOD' => 'GET',
            'REQUEST_URI' => '/admin/dashboard',
            'HTTP_X_REQUESTED_WITH' => 'xmlhttprequest',
        ]);
        $request->setAttribute('route_handler', ['AdminController', 'dashboard']);
        $request->setAttribute('route_options', ['public' => false]);
        $response = new Response();
        $logger = $this->createStub(LoggerInterface::class);

        $context = new Context($request, $response, $logger);

        $handler = $this->createMock(RequestHandlerInterface::class);
        $handler->expects($this->never())->method('handle');

        $res = $middleware->process($context, $handler);

        $this->assertSame(401, $res->getStatusCode());
        $this->assertArrayHasKey('HX-Redirect', $res->getHeaders());
        $this->assertSame('/login', $res->getHeaders()['HX-Redirect']);
    }
}
