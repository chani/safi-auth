<?php

/**
 * Safi Microframework - safi-auth
 * @author Jean Bruenn
 * @copyright 2026 All Rights Reserved
 * @see https://github.com/chani/safi-auth
 */

declare(strict_types=1);

namespace Safi\Extensions\Auth\Controllers;

use Safi\Core\AbstractController;
use Safi\Core\Attributes\Route;
use Safi\Core\Contracts\DatabaseDriverInterface;
use Safi\Core\Contracts\ViewEngineInterface;
use Safi\Core\Http\Request;
use Safi\Core\Http\Response;
use Safi\Core\Services\SecurityService;
use Safi\Extensions\Auth\AuthService;

final class AuthController extends AbstractController
{
    public function __construct(
        ViewEngineInterface $view,
        Request $request,
        SecurityService $security,
        DatabaseDriverInterface $db,
        private readonly AuthService $authService,
    ) {
        parent::__construct($view, $request, $security, $db);
    }

    #[Route('/login', method: 'GET', public: true)]
    public function showLogin(): Response
    {
        if ($this->authService->isAuthenticated()) {
            return $this->redirect('/hello');
        }

        return $this->render('@Auth/login.twig', [
            'title' => 'Sign In - Safi Portal',
        ]);
    }

    #[Route('/login', method: 'POST', public: true)]
    public function login(): Response
    {
        $this->validateCsrf();

        $username = $this->request->post('username');
        $password = $this->request->post('password');

        if (is_string($username) && is_string($password) && $this->authService->loginWithCredentials($username, $password)) {
            return $this->redirect('/hello');
        }

        return $this->render('@Auth/login.twig', [
            'title' => 'Sign In - Safi Portal',
            'error' => 'Invalid username or password credentials.',
        ]);
    }

    #[Route('/logout', method: 'GET', public: true)]
    public function logout(): Response
    {
        $this->authService->logout();
        return $this->redirect('/login');
    }
}
