<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class TariffLimitsTest extends TestCase
{
    protected function setUp(): void
    {
        lykanshield_test_reset();
    }

    public function testFreeSecurityViewLimitsHistoryExportsListsAndReports(): void
    {
        $status = LykanShield_License_Status::from_verification([
            'valid' => false,
            'status' => LykanShield_License_Status::FREE,
            'payload' => null,
            'error_code' => 'free',
            'message' => '',
        ]);

        self::assertFalse($status['premium_features']['csv_json_export']);
        self::assertFalse($status['premium_features']['automatic_reports']);
        self::assertFalse($status['premium_features']['unlimited_allow_block_list']);

        $securityView = new ReflectionClass(LykanShield_Security_View::class);
        self::assertSame(100, $securityView->getConstant('FREE_ALLOW_BLOCK_LIMIT'));
    }

    public function testPremiumStatusEnablesExportsApiLimitAndReports(): void
    {
        $status = LykanShield_License_Status::from_verification([
            'valid' => true,
            'status' => LykanShield_License_Status::PREMIUM_VALID,
            'payload' => ['tier' => 'premium', 'licensed_domain' => 'example.de'],
            'error_code' => 'ok',
            'message' => '',
        ]);

        self::assertTrue($status['premium_features']['rest_api_10000_daily']);
        self::assertTrue($status['premium_features']['csv_json_export']);
        self::assertTrue($status['premium_features']['automatic_reports']);
        self::assertTrue($status['premium_features']['unlimited_allow_block_list']);
    }
}
