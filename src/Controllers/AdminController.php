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
use Safi\Core\Exception\ValidationException;
use Safi\Core\Http\Request;
use Safi\Core\Http\Response;
use Safi\Core\Services\SecurityService;
use Safi\Extensions\Auth\AuthService;
use Safi\Extensions\Auth\Models\LockedIp;
use Safi\Extensions\Auth\Models\User;
use Safi\Extensions\Auth\Models\UserSession;

final class AdminController extends AbstractController
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

    #[Route('/admin/users', method: 'GET')]
    public function userList(): Response
    {
        $this->enforceAdminRole();
        $users = $this->db->findModels(User::class, 'ORDER BY id ASC');

        return $this->render('auth/users.twig', [
            'title' => 'User Directory Management',
            'users' => $users,
        ]);
    }

    #[Route('/admin/users/save', method: 'POST')]
    public function saveUser(): Response
    {
        $this->enforceAdminRole();
        $this->validateCsrf();
        $email = $this->request->post('email');
        $password = $this->request->post('password');

        if (!is_string($email) || filter_var(trim($email), FILTER_VALIDATE_EMAIL) === false) {
            throw new ValidationException('A valid email address is required.');
        }

        if (is_string($password) && trim($password) !== '') {
            $user = $this->db->dispenseModel(User::class);
            $user->email = $email;
            $user->password = $this->authService->hashPassword($password);
            $user->role = 'user';
            $user->createdAt = date('Y-m-d H:i:s');

            $this->db->storeModel($user);
        }

        return $this->redirect('/admin/users');
    }

    #[Route('/admin/users/delete', method: 'POST')]
    public function deleteUser(): Response
    {
        $this->enforceAdminRole();
        $this->validateCsrf();
        $id = $this->request->post('id');

        if (is_numeric($id)) {
            $userId = (int) $id;
            $rawCurrentUserId = $_SESSION['auth_user_id'] ?? 0;
            $currentUserId = is_numeric($rawCurrentUserId) ? (int) $rawCurrentUserId : 0;

            if ($userId !== $currentUserId) {
                $user = $this->db->loadModel(User::class, $userId);
                if ($user->getId() > 0) {
                    $this->db->trashModel($user);
                }
            }
        }

        return $this->redirect('/admin/users');
    }

    #[Route('/admin/sessions', method: 'GET')]
    public function sessions(): Response
    {
        $this->enforceAdminRole();
        $activeSessions = $this->db->findModels(UserSession::class, 'ORDER BY last_active DESC');
        $lockedIps = $this->db->findModels(LockedIp::class, 'ORDER BY id DESC');

        return $this->render('auth/sessions.twig', [
            'title' => 'Security & Session Management',
            'activeSessions' => $activeSessions,
            'lockedIps' => $lockedIps,
        ]);
    }

    #[Route('/admin/sessions/unlock', method: 'POST')]
    public function unlockIp(): Response
    {
        $this->enforceAdminRole();
        $this->validateCsrf();
        $id = $this->request->post('id');

        if (is_numeric($id)) {
            $lockedIp = $this->db->loadModel(LockedIp::class, (int) $id);
            if ($lockedIp->getId() > 0) {
                $this->authService->unlockIp($lockedIp);
            }
        }

        return $this->redirect('/admin/sessions');
    }

    private function enforceAdminRole(): void
    {
        $rawCurrentUserId = $_SESSION['auth_user_id'] ?? 0;
        $currentUserId = is_numeric($rawCurrentUserId) ? (int) $rawCurrentUserId : 0;

        if ($currentUserId <= 0) {
            throw new ValidationException('Access denied: Authentication required.');
        }

        $user = $this->db->loadModel(User::class, $currentUserId);
        if ($user->role !== 'admin') {
            throw new ValidationException('Access denied: Administrative privileges required.');
        }
    }
}
