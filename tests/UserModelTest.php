<?php

/**
 * Safi Microframework - safi-auth
 * @author Jean Bruenn
 * @copyright 2026 All Rights Reserved
 * @see https://github.com/chani/safi-auth
 */

declare(strict_types=1);

namespace Safi\Extensions\Auth\Tests;

use PHPUnit\Framework\TestCase;
use Safi\Extensions\Auth\Models\User;

final class UserModelTest extends TestCase
{
    public function testHandlesEmailTrimmingAndLowercasing(): void
    {
        $user = new User();
        $user->email = '  TEST@Example.COM  ';
        $this->assertSame('test@example.com', $user->email);
    }

    public function testHandlesPasswordAndRoleSetters(): void
    {
        $user = new User();
        $user->password = 'hashed_secret';
        $user->role = 'admin';

        $this->assertSame('hashed_secret', $user->password);
        $this->assertSame('admin', $user->role);
    }
}
