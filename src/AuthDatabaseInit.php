<?php

declare(strict_types=1);

namespace Safi\Extensions\Auth;

use Safi\Core\Contracts\DatabaseDriverInterface;
use Safi\Extensions\Auth\Models\User;

final readonly class AuthDatabaseInit
{
    public function __construct(private DatabaseDriverInterface $db) {}

    public function initializeSchema(?string $customAdminPassword = null, string $adminIdentifier = 'admin'): ?string
    {
        $adminPassword = $customAdminPassword ?? 'admin';
        $generatedPassword = null;

        $this->db->transaction(function () use ($adminIdentifier, $adminPassword, &$generatedPassword): void {
            $existingAdmin = $this->db->findOneModel(User::class, 'email = ? OR role = ?', [$adminIdentifier, 'admin']);
            if (!$existingAdmin instanceof User) {
                $generatedPassword = $adminPassword;
                $admin = $this->db->dispenseModel(User::class);
                $admin->email = $adminIdentifier;
                $admin->password = password_hash($generatedPassword, PASSWORD_DEFAULT);
                $admin->role = 'admin';
                $admin->mustChangePassword = true; // Enforce password change on first login
                $admin->createdAt = date('Y-m-d H:i:s');
                $this->db->storeModel($admin);
            }
        });

        return $generatedPassword;
    }
}
