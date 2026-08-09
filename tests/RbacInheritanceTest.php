<?php

declare(strict_types=1);

namespace Safi\Extensions\Auth\Tests;

use PHPUnit\Framework\TestCase;
use Safi\Core\Contracts\SecurityServiceInterface;
use Safi\Core\Event\EventDispatcher;
use Safi\Extensions\Auth\AuthService;
use Safi\Extensions\Auth\BruteForceShield;
use Safi\Extensions\Auth\Contracts\AuthenticationStorageInterface;
use Safi\Extensions\Auth\Models\Group;
use Safi\Extensions\Auth\Models\GroupPermission;
use Safi\Extensions\Auth\Models\Permission;
use Safi\Extensions\Auth\Models\User;
use Safi\Extensions\Auth\Models\UserGroup;
use Safi\Extensions\Auth\Models\UserPermission;
use Safi\Extensions\Auth\Services\TotpService;
use Safi\Extensions\DbRedBean\RedBeanDatabaseDriver;

final class RbacInheritanceTest extends TestCase
{
    private RedBeanDatabaseDriver $db;

    protected function setUp(): void
    {
        $this->db = new RedBeanDatabaseDriver('sqlite::memory:');
    }

    public function testEvaluatesDirectUserPermission(): void
    {
        $auth = $this->createAuthService();

        $user = $this->db->dispenseModel(User::class);
        $user->email = 'editor@safi.local';
        $user->role = 'user';
        $userId = $this->db->storeModel($user);

        $perm = $this->db->dispenseModel(Permission::class);
        $perm->key = 'article.edit';
        $perm->label = 'Edit Article';
        $this->db->storeModel($perm);

        $userPerm = $this->db->dispenseModel(UserPermission::class);
        $userPerm->userId = $userId;
        $userPerm->permissionKey = 'article.edit';
        $this->db->storeModel($userPerm);

        $this->assertTrue($auth->can($userId, 'article.edit'));
        $this->assertFalse($auth->can($userId, 'article.delete'));
    }

    public function testEvaluatesGroupInheritanceRecursively(): void
    {
        $auth = $this->createAuthService();

        $user = $this->db->dispenseModel(User::class);
        $user->email = 'staff@safi.local';
        $user->role = 'user';
        $userId = $this->db->storeModel($user);

        // Create Parent Group (Managers)
        $parentGroup = $this->db->dispenseModel(Group::class);
        $parentGroup->name = 'Managers';
        $parentGroup->parentId = 0;
        $parentGroupId = $this->db->storeModel($parentGroup);

        // Assign permission to Parent Group
        $groupPerm = $this->db->dispenseModel(GroupPermission::class);
        $groupPerm->groupId = $parentGroupId;
        $groupPerm->permissionKey = 'reports.view';
        $this->db->storeModel($groupPerm);

        // Create Child Group (Editors) inheriting from Managers
        $childGroup = $this->db->dispenseModel(Group::class);
        $childGroup->name = 'Editors';
        $childGroup->parentId = $parentGroupId;
        $childGroupId = $this->db->storeModel($childGroup);

        // Assign User to Child Group
        $userGroup = $this->db->dispenseModel(UserGroup::class);
        $userGroup->userId = $userId;
        $userGroup->groupId = $childGroupId;
        $this->db->storeModel($userGroup);

        // User in Editors group should inherit 'reports.view' from parent group Managers
        $this->assertTrue($auth->can($userId, 'reports.view'));
    }

    private function createAuthService(): AuthService
    {
        $shield = new BruteForceShield();
        $storage = $this->createStub(AuthenticationStorageInterface::class);
        $security = $this->createStub(SecurityServiceInterface::class);
        $dispatcher = new EventDispatcher();
        $totp = new TotpService();

        return new AuthService($shield, $this->db, $storage, $security, $dispatcher, $totp);
    }
}
