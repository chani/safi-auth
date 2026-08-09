<?php

declare(strict_types=1);

namespace Safi\Extensions\Auth\Models;

final class UserGroup extends AbstractAuthModel
{
    public int $userId {
        get {
            $val = $this->getProperty('user_id', 0);
            return is_numeric($val) ? (int) $val : 0;
        }
        set {
            $this->setProperty('user_id', $value);
        }
    }

    public int $groupId {
        get {
            $val = $this->getProperty('group_id', 0);
            return is_numeric($val) ? (int) $val : 0;
        }
        set {
            $this->setProperty('group_id', $value);
        }
    }
}
