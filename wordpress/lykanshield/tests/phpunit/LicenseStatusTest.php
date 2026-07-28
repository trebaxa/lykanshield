<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class LicenseStatusTest extends TestCase
{
    protected function setUp(): void
    {
        lykanshield_test_reset();
    }

    public function testFreeWithoutLicenseKeepsProtectionEnabled(): void
    {
        $status = LykanShield_License_Status::from_verification([
            'valid' => false,
            'status' => LykanShield_License_Status::FREE,
            'payload' => null,
            'error_code' => 'free',
            'message' => 'Free plan active.',
        ]);

        self::assertTrue($status['protection_enabled']);
        self::assertFalse($status['premium']);
        self::assertFalse($status['premium_features']['csv_json_export']);
        self::assertFalse($status['premium_features']['automatic_reports']);
    }

    public function testExpiredLicenseOnlyDisablesPremiumFeatures(): void
    {
        $status = LykanShield_License_Status::from_verification([
            'valid' => false,
            'status' => LykanShield_License_Status::EXPIRED,
            'payload' => ['tier' => 'premium', 'licensed_domain' => 'example.de'],
            'error_code' => 'expired',
            'message' => 'Premium license expired.',
        ]);

        self::assertTrue($status['protection_enabled']);
        self::assertFalse($status['premium']);
        self::assertFalse($status['premium_features']['webhooks']);
    }

    public function testPremiumFeaturesAreEnabledOnlyForValidOrGraceStatus(): void
    {
        foreach ([LykanShield_License_Status::PREMIUM_VALID, LykanShield_License_Status::PREMIUM_GRACE] as $licenseStatus) {
            $status = LykanShield_License_Status::from_verification([
                'valid' => true,
                'status' => $licenseStatus,
                'payload' => ['tier' => 'premium', 'licensed_domain' => 'example.de'],
                'error_code' => 'ok',
                'message' => '',
            ]);

            self::assertTrue($status['protection_enabled']);
            self::assertTrue($status['premium']);
            self::assertTrue($status['premium_features']['rest_api_10000_daily']);
        }
    }
}
