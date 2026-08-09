<?php

declare(strict_types=1);

namespace Safi\Extensions\Auth\Models;

final class UserGroup extends AbstractAuthModel
{
    public int $userId {
        get => $this->getInt('user_id');
        set {
            $this->setProperty('user_id', $value);
        }
    }

    public int $groupId {
        get => $this->getInt('group_id');
        set {
            $this->setProperty('group_id', $value);
        }
    }
}
