<?php

declare(strict_types=1);

namespace Safi\Extensions\Auth\Models;

final class Group extends AbstractAuthModel
{
    public string $name {
        get {
            $val = $this->getProperty('name', '');
            return is_string($val) ? $val : '';
        }
        set {
            $this->setProperty('name', trim($value));
        }
    }

    public int $parentId {
        get {
            $val = $this->getProperty('parent_id', 0);
            return is_numeric($val) ? (int) $val : 0;
        }
        set {
            $this->setProperty('parent_id', $value);
        }
    }

    public string $description {
        get {
            $val = $this->getProperty('description', '');
            return is_string($val) ? $val : '';
        }
        set {
            $this->setProperty('description', trim($value));
        }
    }
}
