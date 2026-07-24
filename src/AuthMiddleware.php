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

final readonly class AuthMiddleware implements MiddlewareInterface
{
    public function __construct(private AuthService $auth) {}

    #[\Override]
    public function process(Context $context, RequestHandlerInterface $handler): Response
    {
        $routeOptions = $context->request->getAttribute('route_options');
        $isPublic = is_array($routeOptions) && isset($routeOptions['public']) && $routeOptions['public'] === true;

        // Allow access if the target route is explicitly flagged as public
        if ($isPublic) {
            if (session_status() === PHP_SESSION_ACTIVE) {
                $_SESSION['auth_redirect_count'] = 0;
            }

            return $handler->handle($context);
        }

        if (session_status() === PHP_SESSION_ACTIVE) {
            $rawCount = $_SESSION['auth_redirect_count'] ?? 0;
            $redirects = is_numeric($rawCount) ? (int) $rawCount : 0;
            if ($redirects > 5) {
                $_SESSION['auth_redirect_count'] = 0;
                return new Response('Too Many Redirects (Loop Shield Blocked)', 429);
            }
        }

        if (!$this->auth->isAuthenticated()) {
            if (session_status() === PHP_SESSION_ACTIVE) {
                $rawCount = $_SESSION['auth_redirect_count'] ?? 0;
                $currentCount = is_numeric($rawCount) ? (int) $rawCount : 0;
                $_SESSION['auth_redirect_count'] = $currentCount + 1;
            }

            return new Response('Redirecting to login...', 302, ['Location' => '/login']);
        }

        if (session_status() === PHP_SESSION_ACTIVE) {
            $_SESSION['auth_redirect_count'] = 0;
        }

        return $handler->handle($context);
    }
}
