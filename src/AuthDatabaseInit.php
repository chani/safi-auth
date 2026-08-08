<?php

declare(strict_types=1);

namespace Safi\Extensions\Auth;

use Safi\Core\Contracts\DatabaseDriverInterface;
use Safi\Extensions\Auth\Models\User;

final readonly class AuthDatabaseInit
{
    public function __construct(private DatabaseDriverInterface $db) {}

    public function initializeSchema(?string $customAdminPassword = null): string
    {
        $generatedPassword = $customAdminPassword ?? bin2hex(random_bytes(10));

        $this->db->transaction(function () use ($generatedPassword): void {
            $existingAdmin = $this->db->findOneModel(User::class, 'email = ? OR role = ?', ['admin', 'admin']);
            if (!$existingAdmin instanceof User) {
                $admin = $this->db->dispenseModel(User::class);
                $admin->email = 'admin';
                $admin->password = password_hash($generatedPassword, PASSWORD_DEFAULT);
                $admin->role = 'admin';
                $admin->createdAt = date('Y-m-d H:i:s');
                $this->db->storeModel($admin);
            }
        });

        return $generatedPassword;
    }
}
