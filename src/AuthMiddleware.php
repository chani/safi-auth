<?php

declare(strict_types=1);

namespace Safi\Extensions\Auth;

use Safi\Core\Http\Context;
use Safi\Core\Http\MiddlewareInterface;
use Safi\Core\Http\RequestHandlerInterface;
use Safi\Core\Http\Response;

final readonly class AuthMiddleware implements MiddlewareInterface
{
    public function __construct(
        private AuthService $auth,
    ) {}

    #[\Override]
    public function process(Context $context, RequestHandlerInterface $handler): Response
    {
        $routeHandler = $context->request->getAttribute('route_handler');
        $routeOptions = $context->request->getAttribute('route_options');
        $isPublic = is_array($routeOptions) && isset($routeOptions['public']) && $routeOptions['public'] === true;

        if ($routeHandler === null || $isPublic) {
            return $handler->handle($context);
        }

        if (!$this->auth->isAuthenticated()) {
            if ($context->request->isXhr()) {
                return new Response(
                    (string) json_encode(['error' => 'Unauthorized', 'login_url' => '/login']),
                    401,
                    [
                        'Content-Type' => 'application/json',
                        'HX-Redirect' => '/login',
                    ],
                );
            }

            return new Response('Redirecting to login...', 302, ['Location' => '/login']);
        }

        return $handler->handle($context);
    }
}
