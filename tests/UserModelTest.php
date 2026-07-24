<?php

declare(strict_types=1);

namespace Safi\Extensions\Auth\Tests;

use PHPUnit\Framework\TestCase;
use Safi\Extensions\Auth\Models\User;

final class UserModelTest extends TestCase
{
    public function testHandlesEmailTrimmingAndLowercasing(): void
    {
        $entity = new \stdClass();
        $user = new User($entity);

        $user->setEmail('  User@Domain.COM  ');
        $this->assertSame('user@domain.com', $user->getEmail());
    }

    public function testHandlesPasswordAndRoleSetters(): void
    {
        $entity = new \stdClass();
        $user = new User($entity);

        $user->setPassword('hashed_pass');
        $user->setRole('admin');

        $this->assertSame('hashed_pass', $user->getPassword());
        $this->assertSame('admin', $user->getRole());
    }
}
