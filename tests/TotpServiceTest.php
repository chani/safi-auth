<?php

declare(strict_types=1);

namespace Safi\Extensions\Auth\Tests;

use PHPUnit\Framework\TestCase;
use Safi\Extensions\Auth\Services\TotpService;

final class TotpServiceTest extends TestCase
{
    public function testGeneratesSecretAndValidatesCode(): void
    {
        $totp = new TotpService();
        $secret = $totp->generateSecret();

        $this->assertSame(16, strlen($secret));

        $code = $totp->generateCode($secret);
        $this->assertSame(6, strlen($code));
        $this->assertTrue($totp->verifyCode($secret, $code));
        $this->assertFalse($totp->verifyCode($secret, '000000'));
    }

    public function testGeneratesProvisioningUri(): void
    {
        $totp = new TotpService();
        $uri = $totp->getProvisioningUri('jean@safi.local', 'JBSWY3DPEHPK3PXP');

        $this->assertStringStartsWith('otpauth://totp/', $uri);
        $this->assertStringContainsString('secret=JBSWY3DPEHPK3PXP', $uri);
    }
}
