<?php

/**
 * Safi Microframework - safi-auth
 * @author Jean Bruenn
 * @copyright 2026 All Rights Reserved
 * @see https://github.com/chani/safi-auth
 */

declare(strict_types=1);

namespace Safi\Extensions\Auth;

use Psr\Log\NullLogger;
use Safi\Core\Http\Context;
use Safi\Core\Http\MiddlewareInterface;
use Safi\Core\Http\RequestHandlerInterface;
use Safi\Core\Http\Response;
use Safi\Extensions\Session\SessionService;

final readonly class AuthMiddleware implements MiddlewareInterface
{
    public function __construct(
        private AuthService $auth,
        private ?SessionService $session = null,
    ) {}

    #[\Override]
    public function process(Context $context, RequestHandlerInterface $handler): Response
    {
        $session = $this->getSession();
        $uri = $context->request->getUri();
        $routeOptions = $context->request->getAttribute('route_options');
        $isPublic = is_array($routeOptions) && isset($routeOptions['public']) && $routeOptions['public'] === true;

        if ($isPublic || $uri === '/login' || $uri === '/logout') {
            $session->set('auth_redirect_count', 0);
            return $handler->handle($context);
        }

        $rawCount = $session->get('auth_redirect_count', 0);
        $redirects = is_numeric($rawCount) ? (int) $rawCount : 0;
        if ($redirects > 5) {
            $session->set('auth_redirect_count', 0);
            return new Response('Too Many Redirects (Loop Shield Blocked)', 429);
        }

        if (!$this->auth->isAuthenticated()) {
            $session->set('auth_redirect_count', $redirects + 1);
            return new Response('Redirecting to login...', 302, ['Location' => '/login']);
        }

        $session->set('auth_redirect_count', 0);

        return $handler->handle($context);
    }

    private function getSession(): SessionService
    {
        return $this->session ?? new SessionService(new NullLogger());
    }
}
