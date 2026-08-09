<?php

declare(strict_types=1);

namespace Safi\Extensions\Auth\Models;

final class GroupPermission extends AbstractAuthModel
{
    public int $groupId {
        get => $this->getInt('group_id');
        set {
            $this->setProperty('group_id', $value);
        }
    }

    public string $permissionKey {
        get => $this->getString('permission_key');
        set {
            $this->setProperty('permission_key', trim($value));
        }
    }
}
