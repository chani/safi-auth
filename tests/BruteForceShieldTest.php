<?php

declare(strict_types=1);

namespace Safi\Extensions\Auth\Tests;

use PHPUnit\Framework\TestCase;
use Safi\Extensions\Auth\BruteForceShield;

final class BruteForceShieldTest extends TestCase
{
    public function testLocksKeyAfterMaxAttempts(): void
    {
        $shield = new BruteForceShield(maxAttempts: 3, decaySeconds: 60);
        $key = '127.0.0.1';

        $this->assertFalse($shield->isLocked($key));

        $shield->recordFailure($key);
        $shield->recordFailure($key);
        $this->assertFalse($shield->isLocked($key));

        $shield->recordFailure($key);
        $this->assertTrue($shield->isLocked($key));
    }

    public function testResetsAttempts(): void
    {
        $shield = new BruteForceShield(maxAttempts: 2, decaySeconds: 60);
        $key = '127.0.0.1';

        $shield->recordFailure($key);
        $shield->recordFailure($key);
        $this->assertTrue($shield->isLocked($key));

        $shield->reset($key);
        $this->assertFalse($shield->isLocked($key));
    }
}
