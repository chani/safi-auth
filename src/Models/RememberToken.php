<?php

declare(strict_types=1);

namespace Safi\Extensions\Auth\Models;

final class RememberToken extends AbstractAuthModel
{
    public string $selector {
        get => $this->getString('selector');
        set {
            $this->setProperty('selector', trim($value));
        }
    }

    public string $validatorHash {
        get => $this->getString('validator_hash');
        set {
            $this->setProperty('validator_hash', $value);
        }
    }

    public int $userId {
        get => $this->getInt('user_id');
        set {
            $this->setProperty('user_id', $value);
        }
    }

    public string $expiresAt {
        get => $this->getString('expires_at');
        set {
            $this->setProperty('expires_at', $value);
        }
    }
}
