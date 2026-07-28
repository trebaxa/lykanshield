<?php

declare(strict_types=1);

defined('ABSPATH') || exit;

final class LykanShield_Admin_Page
{
    public static function register(): void
    {
        add_action('admin_menu', [self::class, 'add_menu_page']);
        add_action('network_admin_menu', [self::class, 'add_network_menu_page']);
        add_action('admin_init', [self::class, 'register_settings']);
        add_action('admin_post_lykanshield_license_action', [self::class, 'handle_license_action']);
        add_action('admin_post_lykanshield_security_action', [self::class, 'handle_security_action']);
        add_action('admin_post_lykanshield_security_export', [self::class, 'handle_security_export']);
        add_action('admin_notices', [self::class, 'activation_notice']);
    }

    public static function add_menu_page(): void
    {
        add_options_page(
            __('LykanShield', 'lykanshield'),
            __('LykanShield', 'lykanshield'),
            'manage_options',
            'lykanshield',
            [self::class, 'render']
        );
    }

    public static function add_network_menu_page(): void
    {
        add_submenu_page(
            'settings.php',
            __('LykanShield', 'lykanshield'),
            __('LykanShield', 'lykanshield'),
            'manage_network_options',
            'lykanshield',
            [self::class, 'render']
        );
    }

    public static function render(): void
    {
        if (!self::can_manage_current_screen()) {
            wp_die(esc_html__('You are not allowed to manage LykanShield settings.', 'lykanshield'));
        }

        defined('ABSPATH') || exit;

        require LYKANSHIELD_PLUGIN_DIR . 'admin/views/settings-page.php';
    }

    public static function register_settings(): void
    {
        register_setting('lykanshield_settings', LykanShield_Settings::OPTION_FILTERS, [
            'type' => 'array',
            'sanitize_callback' => static function ($value): array {
                return LykanShield_Settings::sanitize_filters(is_array($value) ? $value : []);
            },
            'default' => LykanShield_Settings::default_filters(),
        ]);

        register_setting('lykanshield_settings', LykanShield_Settings::OPTION_TRUSTED_PROXIES, [
            'type' => 'string',
            'sanitize_callback' => static function ($value): string {
                return LykanShield_Settings::sanitize_trusted_proxies((string) $value);
            },
            'default' => '',
        ]);

        register_setting('lykanshield_settings', LykanShield_Settings::OPTION_CORE_CONFIG, [
            'type' => 'array',
            'sanitize_callback' => static function ($value): array {
                $input = is_array($value) ? $value : [];
                if (($input['api_key'] ?? '') === '') {
                    $current = LykanShield_Core_Config::values();
                    $input['api_key'] = (string) ($current['api_key'] ?? '');
                }

                $sanitized = LykanShield_Core_Config::sanitize($input);
                LykanShield_Core_Config::ensure_written();

                return $sanitized;
            },
            'default' => LykanShield_Core_Config::defaults(),
        ]);

        register_setting('lykanshield_settings', LykanShield_Settings::OPTION_REMOVE_LOADER_ON_DEACTIVATION, [
            'type' => 'string',
            'sanitize_callback' => static function ($value): string {
                return (string) $value === '1' ? '1' : '0';
            },
            'default' => '1',
        ]);

        register_setting('lykanshield_settings', LykanShield_Settings::OPTION_AUTOMATION, [
            'type' => 'array',
            'sanitize_callback' => static function ($value): array {
                return LykanShield_Settings::sanitize_automation(is_array($value) ? $value : []);
            },
            'default' => LykanShield_Settings::default_automation(),
        ]);

        register_setting('lykanshield_settings', LykanShield_Settings::OPTION_DELETE_DATA_ON_UNINSTALL, [
            'type' => 'string',
            'sanitize_callback' => static function ($value): string {
                return (string) $value === '1' ? '1' : '0';
            },
            'default' => '0',
        ]);

        add_action('updated_option', [self::class, 'maybe_rewrite_core_config'], 10, 3);
        add_action('added_option', [self::class, 'maybe_write_added_core_config'], 10, 2);
    }

    public static function maybe_rewrite_core_config(string $option, mixed $oldValue, mixed $value): void
    {
        unset($oldValue, $value);

        if (in_array($option, [
            LykanShield_Settings::OPTION_FILTERS,
            LykanShield_Settings::OPTION_TRUSTED_PROXIES,
            LykanShield_Settings::OPTION_CORE_CONFIG,
        ], true)) {
            LykanShield_Core_Config::ensure_written();
        }
    }

    public static function maybe_write_added_core_config(string $option, mixed $value): void
    {
        unset($value);

        if (in_array($option, [
            LykanShield_Settings::OPTION_FILTERS,
            LykanShield_Settings::OPTION_TRUSTED_PROXIES,
            LykanShield_Settings::OPTION_CORE_CONFIG,
        ], true)) {
            LykanShield_Core_Config::ensure_written();
        }
    }

    public static function handle_license_action(): void
    {
        if (!self::can_manage_current_screen()) {
            wp_die(esc_html__('You are not allowed to manage LykanShield settings.', 'lykanshield'));
        }

        check_admin_referer('lykanshield_license_action');

        $licenseAction = isset($_POST['license_action'])
            ? sanitize_key((string) wp_unslash($_POST['license_action']))
            : '';
        $result = [
            'ok' => false,
            'message' => __('Unknown license action.', 'lykanshield'),
        ];

        if ($licenseAction === 'activate') {
            $licenseKey = isset($_POST['license_key'])
                ? sanitize_text_field((string) wp_unslash($_POST['license_key']))
                : '';

            LykanShield_Multisite::save_license_key_for_current_domain($licenseKey);
            $result = LykanShield_License_Client::activate($licenseKey);
        } elseif ($licenseAction === 'renew') {
            $result = LykanShield_License_Client::renew();
        } elseif ($licenseAction === 'check') {
            $result = LykanShield_License_Client::status();
        } elseif ($licenseAction === 'deactivate') {
            $result = LykanShield_License_Client::deactivate();
        }

        LykanShield_Audit_Log::record('admin_license_action', !empty($result['ok']) ? 'success' : 'error', [
            'license_action' => $licenseAction,
            'message' => (string) $result['message'],
        ]);

        $redirect = add_query_arg(
            [
                'page' => 'lykanshield',
                'lykanshield_message' => rawurlencode((string) $result['message']),
                'lykanshield_result' => !empty($result['ok']) ? 'success' : 'error',
            ],
            self::settings_url()
        );

        wp_safe_redirect($redirect);
        exit;
    }

    public static function handle_security_action(): void
    {
        if (!self::can_manage_current_screen()) {
            wp_die(esc_html__('You are not allowed to manage LykanShield settings.', 'lykanshield'));
        }

        check_admin_referer('lykanshield_security_action');

        $securityAction = isset($_POST['security_action'])
            ? sanitize_key((string) wp_unslash($_POST['security_action']))
            : '';
        $entry = isset($_POST['block_entry'])
            ? sanitize_text_field((string) wp_unslash($_POST['block_entry']))
            : '';
        $result = $securityAction === 'remove_block'
            ? LykanShield_Security_View::remove_local_block($entry)
            : LykanShield_Security_View::add_local_block($entry);

        self::redirect_with_message($result);
    }

    public static function handle_security_export(): void
    {
        if (!self::can_manage_current_screen()) {
            wp_die(esc_html__('You are not allowed to export LykanShield data.', 'lykanshield'));
        }

        check_admin_referer('lykanshield_security_export');
        $format = isset($_GET['format']) ? sanitize_key((string) wp_unslash($_GET['format'])) : 'json';
        LykanShield_Security_View::export($format);
    }

    public static function activation_notice(): void
    {
        if (!self::can_manage_current_screen()) {
            return;
        }

        $notice = get_option('lykanshield_activation_notice', '');

        if (!is_string($notice) || $notice === '') {
            return;
        }

        printf('<div class="notice notice-warning"><p>%s</p></div>', esc_html($notice));
    }

    /**
     * @param array{ok:bool,message:string} $result
     */
    private static function redirect_with_message(array $result): void
    {
        $redirect = add_query_arg(
            [
                'page' => 'lykanshield',
                'lykanshield_message' => rawurlencode((string) $result['message']),
                'lykanshield_result' => !empty($result['ok']) ? 'success' : 'error',
            ],
            self::settings_url()
        );

        wp_safe_redirect($redirect);
        exit;
    }

    private static function can_manage_current_screen(): bool
    {
        if (function_exists('is_network_admin') && is_network_admin()) {
            return current_user_can('manage_network_options');
        }

        return current_user_can('manage_options');
    }

    private static function settings_url(): string
    {
        return LykanShield_Multisite::settings_url();
    }
}
