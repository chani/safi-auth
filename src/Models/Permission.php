<?php

declare(strict_types=1);

namespace Safi\Extensions\Auth\Models;

final class Permission extends AbstractAuthModel
{
    public string $key {
        get {
            $val = $this->getProperty('key', '');
            return is_string($val) ? $val : '';
        }
        set {
            $this->setProperty('key', trim($value));
        }
    }

    public string $label {
        get {
            $val = $this->getProperty('label', '');
            return is_string($val) ? $val : '';
        }
        set {
            $this->setProperty('label', trim($value));
        }
    }

    public string $category {
        get {
            $val = $this->getProperty('category', 'general');
            return is_string($val) ? $val : 'general';
        }
        set {
            $this->setProperty('category', trim($value));
        }
    }
}
