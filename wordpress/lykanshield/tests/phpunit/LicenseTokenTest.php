<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class LicenseTokenTest extends TestCase
{
    private string $secretKey = '';

    protected function setUp(): void
    {
        lykanshield_test_reset();

        if (!function_exists('sodium_crypto_sign_keypair')) {
            self::markTestSkipped('The sodium extension is required for signed token tests.');
        }

        $keypair = sodium_crypto_sign_keypair();
        $this->secretKey = sodium_crypto_sign_secretkey($keypair);
        $publicKey = sodium_crypto_sign_publickey($keypair);

        add_filter(
            'lykanshield_license_public_key',
            static fn(string $publicKeyBase64): string => base64_encode($publicKey)
        );
    }

    public function testValidExpiredAndTamperedTokens(): void
    {
        $token = $this->token([
            'token_version' => 1,
            'license_id' => 'lic_test',
            'canonical_domain' => 'www.example.de',
            'installation_id' => '0123456789abcdef0123456789abcdef',
            'tier' => 'premium',
            'licensed_domain' => 'example.de',
            'issued_at' => 1000,
            'expires_at' => 2000,
            'grace_until' => 2300,
            'status' => 'active',
        ]);

        self::assertSame(
            LykanShield_License_Status::PREMIUM_VALID,
            LykanShield_License_Token::verify($token, 'example.de', '0123456789abcdef0123456789abcdef', 1500)['status']
        );
        self::assertSame(
            LykanShield_License_Status::EXPIRED,
            LykanShield_License_Token::verify($token, 'example.de', '0123456789abcdef0123456789abcdef', 3000)['status']
        );

        $parts = explode('.', $token);
        $tampered = $parts[0] . '.' . self::base64urlEncode((string) json_encode([
            'token_version' => 1,
            'license_id' => 'lic_test',
            'canonical_domain' => 'www.example.de',
            'installation_id' => '0123456789abcdef0123456789abcdef',
            'tier' => 'premium',
            'licensed_domain' => 'example.com',
            'issued_at' => 1000,
            'expires_at' => 2000,
            'grace_until' => 2300,
            'status' => 'active',
        ])) . '.' . $parts[2];

        self::assertSame('invalid_signature', LykanShield_License_Token::verify($tampered, 'example.de', '0123456789abcdef0123456789abcdef', 1500)['error_code']);
    }

    public function testRejectsWrongDomainAndInstallationId(): void
    {
        $token = $this->token([
            'token_version' => 1,
            'license_id' => 'lic_test',
            'canonical_domain' => 'www.example.de',
            'installation_id' => '0123456789abcdef0123456789abcdef',
            'tier' => 'premium',
            'licensed_domain' => 'example.de',
            'issued_at' => 1000,
            'expires_at' => 2000,
            'grace_until' => 2300,
            'status' => 'active',
        ]);

        self::assertSame('domain_mismatch', LykanShield_License_Token::verify($token, 'example.com', '0123456789abcdef0123456789abcdef', 1500)['error_code']);
        self::assertSame('installation_mismatch', LykanShield_License_Token::verify($token, 'example.de', 'ffffffffffffffffffffffffffffffff', 1500)['error_code']);
    }

    /**
     * @param array<string,mixed> $payload
     */
    private function token(array $payload): string
    {
        $headerPart = self::base64urlEncode((string) json_encode(['alg' => 'Ed25519', 'typ' => 1]));
        $payloadPart = self::base64urlEncode((string) json_encode($payload));
        $signature = sodium_crypto_sign_detached($headerPart . '.' . $payloadPart, $this->secretKey);

        return $headerPart . '.' . $payloadPart . '.' . self::base64urlEncode($signature);
    }

    private static function base64urlEncode(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }
}
