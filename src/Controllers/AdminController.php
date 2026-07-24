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
use Safi\Extensions\Auth\Models\LockedIp;
use Safi\Extensions\Auth\Models\User;

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
        $users = $this->db->findModels(User::class, 'ORDER BY id ASC');

        return $this->render('auth/users.twig', [
            'title' => 'User Directory Management',
            'users' => $users,
        ]);
    }

    #[Route('/admin/users/save', method: 'POST')]
    public function saveUser(): Response
    {
        $this->validateCsrf();
        $email = $this->request->post('email');
        $password = $this->request->post('password');

        if (is_string($email) && is_string($password) && $email !== '' && $password !== '') {
            $user = $this->db->dispenseModel(User::class);
            $user->setEmail($email);
            $user->setPassword($this->authService->hashPassword($password));
            $user->setRole('user');
            $user->setCreatedAt(date('Y-m-d H:i:s'));

            $this->db->storeModel($user);
        }

        return $this->redirect('/admin/users');
    }

    #[Route('/admin/sessions', method: 'GET')]
    public function sessions(): Response
    {
        $lockedIps = $this->db->findModels(LockedIp::class, 'ORDER BY id DESC');

        return $this->render('auth/sessions.twig', [
            'title' => 'Security & IP Lock Management',
            'lockedIps' => $lockedIps,
        ]);
    }

    #[Route('/admin/sessions/unlock', method: 'POST')]
    public function unlockIp(): Response
    {
        $this->validateCsrf();
        $id = $this->request->post('id');

        if (is_numeric($id)) {
            $lockedIp = $this->db->loadModel(LockedIp::class, (int) $id);
            if ($lockedIp->getId() > 0) {
                $this->db->trashModel($lockedIp);
            }
        }

        return $this->redirect('/admin/sessions');
    }
}
