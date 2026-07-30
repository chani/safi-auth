<?php

/**
 * Safi Microframework - safi-auth
 * @author Jean Bruenn
 * @copyright 2026 All Rights Reserved
 * @see https://github.com/chani/safi-auth
 */

declare(strict_types=1);

namespace Safi\Extensions\Auth;

use Safi\Core\Http\Context;
use Safi\Core\Http\MiddlewareInterface;
use Safi\Core\Http\RequestHandlerInterface;
use Safi\Core\Http\Response;
use Safi\Extensions\Session\SessionServiceInterface;

final readonly class AuthMiddleware implements MiddlewareInterface
{
    public function __construct(
        private AuthService $auth,
        private SessionServiceInterface $session,
    ) {}

    #[\Override]
    public function process(Context $context, RequestHandlerInterface $handler): Response
    {
        $uri = $context->request->getUri();
        $routeHandler = $context->request->getAttribute('route_handler');
        $routeOptions = $context->request->getAttribute('route_options');
        $isPublic = is_array($routeOptions) && isset($routeOptions['public']) && $routeOptions['public'] === true;

        // Router miss (404/405): Pass through directly to let kernel/router render the error
        if ($routeHandler === null) {
            return $handler->handle($context);
        }

        if ($isPublic || $uri === '/login' || $uri === '/logout') {
            $this->session->set('auth_redirect_count', 0);
            return $handler->handle($context);
        }

        $rawCount = $this->session->get('auth_redirect_count', 0);
        $redirects = is_numeric($rawCount) ? (int) $rawCount : 0;
        if ($redirects > 5) {
            $this->session->set('auth_redirect_count', 0);
            return new Response('Too Many Redirects (Loop Shield Blocked)', 429);
        }

        if (!$this->auth->isAuthenticated()) {
            $this->session->set('auth_redirect_count', $redirects + 1);
            return new Response('Redirecting to login...', 302, ['Location' => '/login']);
        }

        $this->session->set('auth_redirect_count', 0);

        return $handler->handle($context);
    }
}
