<?php

declare(strict_types=1);

namespace Safi\Extensions\Auth\Models;

final class RememberToken extends AbstractAuthModel
{
    public string $selector {
        get {
            $val = $this->getProperty('selector', '');
            return is_string($val) ? $val : '';
        }
        set {
            $this->setProperty('selector', trim($value));
        }
    }

    public string $validatorHash {
        get {
            $val = $this->getProperty('validator_hash', '');
            return is_string($val) ? $val : '';
        }
        set {
            $this->setProperty('validator_hash', $value);
        }
    }

    public int $userId {
        get {
            $val = $this->getProperty('user_id', 0);
            return is_numeric($val) ? (int) $val : 0;
        }
        set {
            $this->setProperty('user_id', $value);
        }
    }

    public string $expiresAt {
        get {
            $val = $this->getProperty('expires_at', '');
            return is_string($val) ? $val : '';
        }
        set {
            $this->setProperty('expires_at', $value);
        }
    }
}
