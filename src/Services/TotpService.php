<?php

declare(strict_types=1);

namespace Safi\Extensions\Auth\Services;

final readonly class TotpService
{
    private const string BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

    public function generateSecret(int $length = 16): string
    {
        $length = max(1, $length);
        $secret = '';
        $bytes = random_bytes($length);
        for ($i = 0; $i < $length; $i++) {
            $secret .= self::BASE32_ALPHABET[ord($bytes[$i]) % 32];
        }

        return $secret;
    }

    public function generateCode(string $secret, ?int $timestamp = null, int $period = 30, int $digits = 6, string $algorithm = 'sha256'): string
    {
        $time = $timestamp ?? time();
        $timeSlice = (int) floor($time / $period);

        $secretBin = $this->base32Decode($secret);
        $timeBin = pack('N*', 0, $timeSlice);

        $hmac = hash_hmac(strtolower($algorithm), $timeBin, $secretBin, true);
        $offset = ord($hmac[strlen($hmac) - 1]) & 0x0F;

        $hashPart = substr($hmac, $offset, 4);
        $unpacked = unpack('N', $hashPart);
        $unpackedInt = (is_array($unpacked) && isset($unpacked[1]) && is_numeric($unpacked[1])) ? (int) $unpacked[1] : 0;
        $value = $unpackedInt & 0x7FFFFFFF;

        $modulo = 10 ** $digits;
        return str_pad((string) ($value % $modulo), $digits, '0', STR_PAD_LEFT);
    }

    public function verifyCode(string $secret, string $code, int $discrepancy = 1, ?int $currentTime = null, string $algorithm = 'sha256'): bool
    {
        if ($secret === '' || strlen($code) !== 6 || !ctype_digit($code)) {
            return false;
        }

        $time = $currentTime ?? time();
        for ($i = -$discrepancy; $i <= $discrepancy; $i++) {
            $calculatedCode = $this->generateCode($secret, $time + ($i * 30), 30, 6, $algorithm);
            if (hash_equals($calculatedCode, $code)) {
                return true;
            }
        }

        return false;
    }

    public function getProvisioningUri(string $username, string $secret, string $issuer = 'Safi Portal', string $algorithm = 'sha256'): string
    {
        return sprintf(
            'otpauth://totp/%s:%s?secret=%s&issuer=%s&algorithm=%s&digits=6&period=30',
            rawurlencode($issuer),
            rawurlencode($username),
            $secret,
            rawurlencode($issuer),
            strtoupper($algorithm),
        );
    }

    private function base32Decode(string $secret): string
    {
        $secret = strtoupper($secret);
        $buffer = 0;
        $bitsLeft = 0;
        $output = '';

        for ($i = 0, $length = strlen($secret); $i < $length; $i++) {
            $char = $secret[$i];
            $position = strpos(self::BASE32_ALPHABET, $char);
            if ($position === false) {
                continue;
            }

            $buffer = ($buffer << 5) | $position;
            $bitsLeft += 5;

            if ($bitsLeft >= 8) {
                $bitsLeft -= 8;
                $output .= chr(($buffer >> $bitsLeft) & 0xFF);
            }
        }

        return $output;
    }
}
