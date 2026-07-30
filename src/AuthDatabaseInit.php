<?php

/**
 * Safi Microframework - safi-auth
 * @author Jean Bruenn
 * @copyright 2026 All Rights Reserved
 * @see https://github.com/chani/safi-auth
 */

declare(strict_types=1);

namespace Safi\Extensions\Auth;

use Safi\Core\Contracts\DatabaseDriverInterface;

final readonly class AuthDatabaseInit
{
    public function __construct(private DatabaseDriverInterface $db) {}

    public function initializeSchema(): void
    {
        $this->db->exec("CREATE TABLE IF NOT EXISTS authuser (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE, password TEXT, role TEXT, created_at TEXT)");
        $this->db->exec("CREATE TABLE IF NOT EXISTS authloginattempt (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, username TEXT, attempted_at TEXT)");
        $this->db->exec("CREATE TABLE IF NOT EXISTS authlockedip (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT UNIQUE, locked_until TEXT)");
        $this->db->exec("CREATE TABLE IF NOT EXISTS authusersession (id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT UNIQUE, user_id INTEGER, username TEXT, ip_address TEXT, last_active TEXT)");
    }
}
