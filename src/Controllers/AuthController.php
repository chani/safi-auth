<?php

declare(strict_types=1);

namespace Safi\Extensions\Auth\Controllers;

use Safi\Core\AbstractController;
use Safi\Core\Attributes\Route;
use Safi\Core\Contracts\DatabaseDriverInterface;
use Safi\Core\Contracts\SecurityServiceInterface;
use Safi\Core\Contracts\ViewEngineInterface;
use Safi\Core\Http\Request;
use Safi\Core\Http\Response;
use Safi\Extensions\Auth\AuthService;

final class AuthController extends AbstractController
{
    public function __construct(
        ViewEngineInterface $view,
        Request $request,
        SecurityServiceInterface $security,
        DatabaseDriverInterface $db,
        private readonly AuthService $authService,
    ) {
        parent::__construct($view, $request, $security, $db);
    }

    #[Route('/login', method: 'GET', name: 'auth.login.show', public: true)]
    public function showLogin(): Response
    {
        if ($this->authService->isAuthenticated()) {
            return $this->redirect('/admin');
        }

        return $this->render('@Auth/login', [
            'title' => 'Sign In - Safi Portal',
        ]);
    }

    #[Route('/login', method: 'POST', name: 'auth.login', public: true)]
    public function login(): Response
    {
        $this->validateCsrf();

        $username = $this->request->post('username');
        $password = $this->request->post('password');

        if (is_string($username) && is_string($password) && $this->authService->loginWithCredentials($username, $password)) {
            if ($this->request->isXhr()) {
                return new Response('Redirecting...', 200, [
                    'HX-Redirect' => '/admin',
                    'Location' => '/admin',
                ]);
            }

            return $this->redirect('/admin');
        }

        return $this->render('@Auth/login', [
            'title' => 'Sign In - Safi Portal',
            'error' => 'Invalid username or password credentials.',
        ]);
    }

    #[Route('/logout', method: 'POST', name: 'auth.logout', public: false)]
    public function logout(): Response
    {
        $this->validateCsrf();
        $this->authService->logout();

        if ($this->request->isXhr()) {
            return new Response('Redirecting...', 200, [
                'HX-Redirect' => '/login',
                'Location' => '/login',
            ]);
        }

        return $this->redirect('/login');
    }
}
