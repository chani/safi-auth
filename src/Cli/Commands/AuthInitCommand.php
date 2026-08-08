<?php

declare(strict_types=1);

namespace Safi\Extensions\Auth\Cli\Commands;

use Safi\Core\Cli\CommandInterface;
use Safi\Extensions\Auth\AuthDatabaseInit;

final readonly class AuthInitCommand implements CommandInterface
{
    public function __construct(private AuthDatabaseInit $init) {}

    #[\Override]
    public function getName(): string
    {
        return 'auth:init';
    }

    #[\Override]
    public function getDescription(): string
    {
        return 'Creates authentication database tables and default admin record.';
    }

    #[\Override]
    public function getCategory(): string
    {
        return 'auth';
    }

    #[\Override]
    public function execute(array $args): int
    {
        $customPassword = $args[0] ?? null;
        $password = $this->init->initializeSchema($customPassword);

        echo "Auth database initialized successfully.\n";
        if ($password !== null && $customPassword === null) {
            echo "Generated initial admin password: {$password}\n";
            echo "PLEASE CHANGE THIS PASSWORD IMMEDIATELY UPON FIRST LOGIN!\n";
        } elseif ($password === null) {
            echo "Admin user already exists. Schema verified.\n";
        }

        return 0;
    }
}
