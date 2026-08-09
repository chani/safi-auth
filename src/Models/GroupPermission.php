<?php

declare(strict_types=1);

namespace Safi\Extensions\Auth\Models;

final class GroupPermission extends AbstractAuthModel
{
    public int $groupId {
        get {
            $val = $this->getProperty('group_id', 0);
            return is_numeric($val) ? (int) $val : 0;
        }
        set {
            $this->setProperty('group_id', $value);
        }
    }

    public string $permissionKey {
        get {
            $val = $this->getProperty('permission_key', '');
            return is_string($val) ? $val : '';
        }
        set {
            $this->setProperty('permission_key', trim($value));
        }
    }
}
