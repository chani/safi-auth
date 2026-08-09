<?php

declare(strict_types=1);

namespace Safi\Extensions\Auth\Models;

final class Group extends AbstractAuthModel
{
    public string $name {
        get => $this->getString('name');
        set {
            $this->setProperty('name', trim($value));
        }
    }

    public int $parentId {
        get => $this->getInt('parent_id');
        set {
            $this->setProperty('parent_id', $value);
        }
    }

    public string $description {
        get => $this->getString('description');
        set {
            $this->setProperty('description', trim($value));
        }
    }
}
