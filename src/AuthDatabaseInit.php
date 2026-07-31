<?php

declare(strict_types=1);

namespace Safi\Extensions\Auth;

use Safi\Core\Contracts\DatabaseDriverInterface;
use Safi\Extensions\Auth\Models\User;

final readonly class AuthDatabaseInit
{
    public function __construct(private DatabaseDriverInterface $db) {}

    public function initializeSchema(): void
    {
        // 1. Create schema
        $this->db->transaction(function (DatabaseDriverInterface $driver): void {
            // User table initialization
            $user = $driver->dispenseModel(User::class);
            $user->email = 'system_init@safi.local';
            $user->password = 'init';
            $user->role = 'system';
            $user->createdAt = date('Y-m-d H:i:s');
            $driver->storeModel($user);
            $driver->trashModel($user);
        });

        // 2. Ensure default admin exists
        $existingAdmin = $this->db->findOneModel(User::class, 'email = ? OR role = ?', ['admin', 'admin']);
        if (!$existingAdmin instanceof User) {
            $admin = $this->db->dispenseModel(User::class);
            $admin->email = 'admin';
            $admin->password = password_hash('admin', PASSWORD_DEFAULT);
            $admin->role = 'admin';
            $admin->createdAt = date('Y-m-d H:i:s');
            $this->db->storeModel($admin);
        }
    }
}
