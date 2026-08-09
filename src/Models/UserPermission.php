<?php

declare(strict_types=1);

namespace Safi\Extensions\Auth\Models;

final class UserPermission extends AbstractAuthModel
{
    public int $userId {
        get => $this->getInt('user_id');
        set {
            $this->setProperty('user_id', $value);
        }
    }

    public string $permissionKey {
        get => $this->getString('permission_key');
        set {
            $this->setProperty('permission_key', trim($value));
        }
    }
}
