<?php

declare(strict_types=1);

namespace Safi\Extensions\Auth\Models;

final class Permission extends AbstractAuthModel
{
    public string $key {
        get => $this->getString('key');
        set {
            $this->setProperty('key', trim($value));
        }
    }

    public string $label {
        get => $this->getString('label');
        set {
            $this->setProperty('label', trim($value));
        }
    }

    public string $category {
        get => $this->getString('category', 'general');
        set {
            $this->setProperty('category', trim($value));
        }
    }
}
