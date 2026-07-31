<?php

/**
 * Safi Microframework - safi-auth
 * @author Jean Bruenn
 * @copyright 2026 All Rights Reserved
 * @see https://github.com/chani/safi-auth
 */

declare(strict_types=1);

namespace Safi\Extensions\Auth\Cli\Commands;

use Safi\Core\Cli\CommandInterface;
use Safi\Core\Contracts\DatabaseDriverInterface;
use Safi\Extensions\Auth\AuthDatabaseInit;

final readonly class AuthInitCommand implements CommandInterface
{
    public function __construct(private DatabaseDriverInterface $db) {}

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
        $init = new AuthDatabaseInit($this->db);
        $init->initializeSchema();
        echo "Database schema initialized.\n";
        return 0;
    }
}
