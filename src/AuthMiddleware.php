<?php

declare(strict_types=1);

namespace Safi\Extensions\Auth;

use Safi\Core\Contracts\RouterInterface;
use Safi\Core\Http\Context;
use Safi\Core\Http\MiddlewareInterface;
use Safi\Core\Http\RequestHandlerInterface;
use Safi\Core\Http\Response;

final readonly class AuthMiddleware implements MiddlewareInterface
{
    public function __construct(
        private AuthService $auth,
        private ?RouterInterface $router = null,
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
            $loginUrl = $this->resolveLoginUrl();

            if ($context->request->isXhr()) {
                return new Response(
                    (string) json_encode(['error' => 'Unauthorized', 'login_url' => $loginUrl]),
                    401,
                    [
                        'Content-Type' => 'application/json',
                        'HX-Redirect' => $loginUrl,
                    ],
                );
            }

            return new Response('Redirecting to login...', 302, ['Location' => $loginUrl]);
        }

        return $handler->handle($context);
    }

    private function resolveLoginUrl(): string
    {
        if ($this->router instanceof RouterInterface) {
            try {
                return $this->router->generateUrl('auth.login.show');
            } catch (\Throwable) {
                // Fallback if route name is not registered
            }
        }

        return '/login';
    }
}
