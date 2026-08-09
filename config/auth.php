<?php

declare(strict_types=1);

return [
    'max_idle_seconds' => 900, // 15 minutes inactivity timeout (0 = disabled)
    'min_password_length' => 12, // Minimum required password length
    'hash_algo' => PASSWORD_BCRYPT,
    'hash_options' => ['cost' => 12],
    'totp_algo' => 'sha256',
];
