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
        $this->init->initializeSchema();
        return 0;
    }
}
