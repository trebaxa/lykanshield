<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class ActivationCronAndApiTest extends TestCase
{
    protected function setUp(): void
    {
        lykanshield_test_reset();
    }

    public function testCronScheduleAndClear(): void
    {
        LykanShield_Cron::schedule();

        self::assertArrayHasKey(LykanShield_Cron::HOOK_RULE_REFRESH, $GLOBALS['lykanshield_test_scheduled_hooks']);
        self::assertArrayHasKey(LykanShield_Cron::HOOK_REPORT_QUEUE, $GLOBALS['lykanshield_test_scheduled_hooks']);
        self::assertArrayHasKey(LykanShield_Cron::HOOK_LICENSE_RENEWAL, $GLOBALS['lykanshield_test_scheduled_hooks']);

        LykanShield_Cron::clear();

        self::assertSame([], $GLOBALS['lykanshield_test_scheduled_hooks']);
    }

    public function testActivationInitializesDefaultsLoaderAndCron(): void
    {
        if (!extension_loaded('sodium')) {
            self::markTestSkipped('Activation requires the sodium extension.');
        }

        LykanShield_Plugin::activate(false);

        self::assertMatchesRegularExpression('/\A[a-f0-9]{32}\z/', (string) get_option(LykanShield_Settings::OPTION_INSTALLATION_ID));
        self::assertSame('1', get_option(LykanShield_Settings::OPTION_LOADER_ENABLED));
        self::assertFileExists(WPMU_PLUGIN_DIR . DIRECTORY_SEPARATOR . LYKANSHIELD_MU_LOADER_FILE);
        self::assertArrayHasKey(LykanShield_Cron::HOOK_RULE_REFRESH, $GLOBALS['lykanshield_test_scheduled_hooks']);

        LykanShield_Plugin::deactivate(false);

        self::assertSame('0', get_option(LykanShield_Settings::OPTION_LOADER_ENABLED));
        self::assertSame([], $GLOBALS['lykanshield_test_scheduled_hooks']);
    }

    public function testLoaderInstallerRefusesForeignLoaderAndReportsMissingWriteAccess(): void
    {
        wp_mkdir_p(WPMU_PLUGIN_DIR);
        file_put_contents(WPMU_PLUGIN_DIR . DIRECTORY_SEPARATOR . LYKANSHIELD_MU_LOADER_FILE, '<?php // foreign loader');

        $result = LykanShield_Loader_Installer::install();

        self::assertFalse($result['ok']);
        self::assertStringContainsString('different MU loader', $result['message']);
    }

    public function testLicenseServerErrorsDoNotDisableProtectionAndDoNotRunOnStatusRead(): void
    {
        $GLOBALS['lykanshield_test_remote_response'] = new WP_Error('timeout');

        $result = LykanShield_License_Client::activate('LS-TEST-KEY-12345678');
        $status = LykanShield_License_Status::server_error();

        self::assertFalse($result['ok']);
        self::assertTrue($status['protection_enabled']);
        self::assertFalse($status['premium']);

        $callCount = count($GLOBALS['lykanshield_test_remote_calls']);
        LykanShield_License_Status::from_verification([
            'valid' => false,
            'status' => LykanShield_License_Status::FREE,
            'payload' => null,
            'error_code' => 'free',
            'message' => '',
        ]);

        self::assertCount($callCount, $GLOBALS['lykanshield_test_remote_calls'], 'Runtime status calculation must not perform synchronous license HTTP requests.');
    }
}
