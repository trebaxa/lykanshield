<?php

declare(strict_types=1);

defined('ABSPATH') || exit;

final class LykanShield_Uninstaller
{
    public static function run(): void
    {
        if (function_exists('is_multisite') && is_multisite() && function_exists('get_sites')) {
            self::uninstall_network();
            return;
        }

        self::uninstall();
    }

    /**
     * @param array{delete_data?:bool} $args
     */
    public static function uninstall(array $args = []): void
    {
        $deleteData = !empty($args['delete_data']) || LykanShield_Settings::delete_data_on_uninstall();

        self::clear_cron();
        LykanShield_Loader_Installer::remove();
        self::deactivate_license();
        self::delete_options($deleteData);
        self::delete_transients();

        if ($deleteData) {
            self::delete_data_directory();
        }
    }

    private static function uninstall_network(): void
    {
        $deleteData = LykanShield_Settings::delete_data_on_uninstall();
        $siteIds = get_sites(['fields' => 'ids', 'number' => 0]);

        foreach ($siteIds as $siteId) {
            switch_to_blog((int) $siteId);
            try {
                self::uninstall(['delete_data' => $deleteData]);
            } finally {
                restore_current_blog();
            }
        }

        if ($deleteData) {
            delete_site_option(LykanShield_Multisite::NETWORK_TOKENS_OPTION);
            delete_site_option(LykanShield_Multisite::NETWORK_KEYS_OPTION);
        }
    }

    public static function clear_cron(): void
    {
        foreach ([
            'lykanshield_refresh_rules',
            'lykanshield_flush_report_queue',
            'lykanshield_renew_license',
            'lykanshield_daily_summary',
            'lykanshield_prune_local_logs',
        ] as $hook) {
            wp_clear_scheduled_hook($hook);
        }
    }

    private static function deactivate_license(): void
    {
        try {
            $result = LykanShield_License_Client::deactivate();
        } catch (Throwable $throwable) {
            update_option(
                'lykanshield_uninstall_license_deactivation_error',
                (string) LykanShield_License_Client::redact_license_key($throwable->getMessage()),
                false
            );

            return;
        }

        if (empty($result['ok'])) {
            update_option('lykanshield_uninstall_license_deactivation_error', $result['message'], false);
        }
    }

    private static function delete_options(bool $deleteData): void
    {
        foreach ([
            LykanShield_Settings::OPTION_LOADER_ENABLED,
            LykanShield_Settings::OPTION_FILTERS,
            LykanShield_Settings::OPTION_TRUSTED_PROXIES,
            LykanShield_Settings::OPTION_CORE_CONFIG,
            LykanShield_Settings::OPTION_AUTOMATION,
            LykanShield_Settings::OPTION_REMOVE_LOADER_ON_DEACTIVATION,
            LykanShield_Settings::OPTION_DELETE_DATA_ON_UNINSTALL,
            'lykanshield_activation_notice',
            'lykanshield_loader_status',
            'lykanshield_license_runtime_status',
            'lykanshield_premium_report_last_sent',
        ] as $option) {
            delete_option($option);
        }

        if (!$deleteData) {
            return;
        }

        foreach ([
            LykanShield_Settings::OPTION_INSTALLATION_ID,
            LykanShield_Settings::OPTION_LICENSE_KEY,
            LykanShield_Settings::OPTION_LICENSE_TOKEN,
            LykanShield_Settings::OPTION_LICENSE_LAST_ERROR,
            LykanShield_Audit_Log::OPTION,
            LykanShield_Multisite::DOMAIN_FINGERPRINT_OPTION,
            'lykanshield_uninstall_license_deactivation_error',
        ] as $option) {
            delete_option($option);
        }
    }

    private static function delete_transients(): void
    {
        global $wpdb;

        if (!isset($wpdb) || !isset($wpdb->options)) {
            return;
        }

        foreach (['_transient_lykanshield_', '_transient_timeout_lykanshield_'] as $prefix) {
            $wpdb->query(
                $wpdb->prepare(
                    "DELETE FROM {$wpdb->options} WHERE option_name LIKE %s",
                    $wpdb->esc_like($prefix) . '%'
                )
            );
        }
    }

    private static function delete_data_directory(): void
    {
        $directory = trailingslashit(WP_CONTENT_DIR) . 'lykan';
        $real = realpath($directory);
        $content = realpath(WP_CONTENT_DIR);

        if (!is_string($real) || !is_string($content) || !str_starts_with($real, $content . DIRECTORY_SEPARATOR)) {
            return;
        }

        self::delete_tree($real);
    }

    private static function delete_tree(string $path): void
    {
        if (is_link($path) || is_file($path)) {
            @unlink($path);
            return;
        }

        if (!is_dir($path)) {
            return;
        }

        $iterator = new DirectoryIterator($path);
        foreach ($iterator as $item) {
            if ($item->isDot()) {
                continue;
            }

            self::delete_tree($item->getPathname());
        }

        @rmdir($path);
    }
}
