<?php

declare(strict_types=1);

defined('ABSPATH') || exit;

final class LykanShield_Settings
{
    public const OPTION_INSTALLATION_ID = 'lykanshield_installation_id';
    public const OPTION_LICENSE_KEY = 'lykanshield_license_key';
    public const OPTION_LICENSE_TOKEN = 'lykanshield_license_token';
    public const OPTION_LICENSE_LAST_ERROR = 'lykanshield_license_last_error';
    public const OPTION_LOADER_ENABLED = 'lykanshield_loader_enabled';
    public const OPTION_FILTERS = 'lykanshield_filters';
    public const OPTION_TRUSTED_PROXIES = 'lykanshield_trusted_proxies';
    public const OPTION_CORE_CONFIG = 'lykanshield_core_config';
    public const OPTION_REMOVE_LOADER_ON_DEACTIVATION = 'lykanshield_remove_loader_on_deactivation';
    public const OPTION_AUTOMATION = 'lykanshield_automation';
    public const OPTION_DELETE_DATA_ON_UNINSTALL = 'lykanshield_delete_data_on_uninstall';

    /**
     * @return array<string,bool>
     */
    public static function default_filters(): array
    {
        return [
            'sql_protection' => true,
            'xss_protection' => true,
            'exploit_protection' => true,
            'upload_mime_protection' => true,
            'bad_ip_bot_protection' => true,
        ];
    }

    public static function ensure_defaults(): void
    {
        self::ensure_installation_id();

        if (get_option(self::OPTION_LOADER_ENABLED, null) === null) {
            update_option(self::OPTION_LOADER_ENABLED, '1', false);
        }

        if (!is_array(get_option(self::OPTION_FILTERS, null))) {
            update_option(self::OPTION_FILTERS, self::default_filters(), false);
        }

        if (get_option(self::OPTION_TRUSTED_PROXIES, null) === null) {
            update_option(self::OPTION_TRUSTED_PROXIES, '', false);
        }

        if (!is_array(get_option(self::OPTION_CORE_CONFIG, null)) && class_exists('LykanShield_Core_Config')) {
            LykanShield_Core_Config::migrate_existing_config();
        }

        if (!is_array(get_option(self::OPTION_CORE_CONFIG, null)) && class_exists('LykanShield_Core_Config')) {
            update_option(self::OPTION_CORE_CONFIG, LykanShield_Core_Config::defaults(), false);
        }

        if (get_option(self::OPTION_REMOVE_LOADER_ON_DEACTIVATION, null) === null) {
            update_option(self::OPTION_REMOVE_LOADER_ON_DEACTIVATION, '1', false);
        }

        if (!is_array(get_option(self::OPTION_AUTOMATION, null))) {
            update_option(self::OPTION_AUTOMATION, self::default_automation(), false);
        }

        if (get_option(self::OPTION_DELETE_DATA_ON_UNINSTALL, null) === null) {
            update_option(self::OPTION_DELETE_DATA_ON_UNINSTALL, '0', false);
        }
    }

    public static function loader_enabled(): bool
    {
        return get_option(self::OPTION_LOADER_ENABLED, '1') === '1';
    }

    public static function set_loader_enabled(bool $enabled): void
    {
        update_option(self::OPTION_LOADER_ENABLED, $enabled ? '1' : '0', false);
    }

    public static function remove_loader_on_deactivation(): bool
    {
        return get_option(self::OPTION_REMOVE_LOADER_ON_DEACTIVATION, '1') === '1';
    }

    public static function delete_data_on_uninstall(): bool
    {
        return get_option(self::OPTION_DELETE_DATA_ON_UNINSTALL, '0') === '1';
    }

    /**
     * @return array{webhook_url:string,report_frequency:string,report_email:string}
     */
    public static function default_automation(): array
    {
        return [
            'webhook_url' => '',
            'report_frequency' => 'none',
            'report_email' => '',
        ];
    }

    /**
     * @return array{webhook_url:string,report_frequency:string,report_email:string}
     */
    public static function automation(): array
    {
        $saved = get_option(self::OPTION_AUTOMATION, []);

        return self::sanitize_automation(is_array($saved) ? $saved : []);
    }

    /**
     * @param array<string,mixed> $input
     * @return array{webhook_url:string,report_frequency:string,report_email:string}
     */
    public static function sanitize_automation(array $input): array
    {
        $webhookUrl = isset($input['webhook_url']) ? esc_url_raw((string) $input['webhook_url']) : '';
        if ($webhookUrl !== '' && !str_starts_with($webhookUrl, 'https://')) {
            $webhookUrl = '';
        }

        $frequency = isset($input['report_frequency']) ? sanitize_key((string) $input['report_frequency']) : 'none';
        if (!in_array($frequency, ['none', 'daily', 'weekly', 'monthly'], true)) {
            $frequency = 'none';
        }

        $email = isset($input['report_email']) ? sanitize_email((string) $input['report_email']) : '';
        if ($email !== '' && !is_email($email)) {
            $email = '';
        }

        return [
            'webhook_url' => $webhookUrl,
            'report_frequency' => $frequency,
            'report_email' => $email,
        ];
    }

    /**
     * @return array<string,bool>
     */
    public static function filters(): array
    {
        $saved = get_option(self::OPTION_FILTERS, []);
        $filters = self::default_filters();

        if (!is_array($saved)) {
            return $filters;
        }

        foreach ($filters as $key => $default) {
            if (array_key_exists($key, $saved)) {
                $filters[$key] = (bool) $saved[$key];
            }
        }

        return $filters;
    }

    /**
     * @param array<string,mixed> $input
     * @return array<string,bool>
     */
    public static function sanitize_filters(array $input): array
    {
        $filters = self::default_filters();

        foreach ($filters as $key => $default) {
            $filters[$key] = isset($input[$key]) && (string) $input[$key] === '1';
        }

        return $filters;
    }

    public static function trusted_proxies(): string
    {
        return trim((string) get_option(self::OPTION_TRUSTED_PROXIES, ''));
    }

    public static function sanitize_trusted_proxies(string $input): string
    {
        $lines = preg_split('/\R+/', $input) ?: [];
        $valid = [];

        foreach ($lines as $line) {
            $line = trim($line);

            if ($line === '') {
                continue;
            }

            if (self::is_valid_ip_or_cidr($line)) {
                $valid[] = $line;
            }
        }

        return implode("\n", array_values(array_unique($valid)));
    }

    public static function installation_id(): string
    {
        $installationId = get_option(self::OPTION_INSTALLATION_ID);

        if (is_string($installationId) && self::is_valid_installation_id($installationId)) {
            return $installationId;
        }

        $installationId = self::generate_installation_id();
        update_option(self::OPTION_INSTALLATION_ID, $installationId, false);

        return $installationId;
    }

    public static function is_valid_installation_id(string $installationId): bool
    {
        return preg_match('/\A[a-f0-9]{32}\z/', $installationId) === 1;
    }

    public static function ensure_installation_id(): string
    {
        return self::installation_id();
    }

    public static function license_token(): string
    {
        $domain = LykanShield_License_Client::domain_context()['registrable_domain'] ?? '';

        return LykanShield_Multisite::token_for_domain((string) $domain);
    }

    public static function license_key(): string
    {
        $domain = LykanShield_License_Client::domain_context()['registrable_domain'] ?? '';

        return LykanShield_Multisite::license_key_for_domain((string) $domain);
    }

    public static function update_license_key(string $licenseKey): bool
    {
        $licenseKey = strtoupper(trim($licenseKey));

        return LykanShield_Multisite::save_license_key_for_current_domain($licenseKey);
    }

    public static function masked_license_key(): string
    {
        $licenseKey = self::license_key();

        if ($licenseKey === '') {
            return '';
        }

        $length = strlen($licenseKey);

        if ($length <= 8) {
            return str_repeat('*', $length);
        }

        return substr($licenseKey, 0, 4) . str_repeat('*', max(4, $length - 8)) . substr($licenseKey, -4);
    }

    public static function update_license_token(string $token): bool
    {
        $token = trim($token);

        return LykanShield_Multisite::save_token_for_current_domain($token);
    }

    private static function generate_installation_id(): string
    {
        try {
            return bin2hex(random_bytes(16));
        } catch (Throwable) {
            return md5(uniqid('lykanshield-', true));
        }
    }

    private static function is_valid_ip_or_cidr(string $value): bool
    {
        if (filter_var($value, FILTER_VALIDATE_IP) !== false) {
            return true;
        }

        if (preg_match('/\A(.+)\/([0-9]{1,3})\z/', $value, $matches) !== 1) {
            return false;
        }

        $ip = $matches[1];
        $prefix = (int) $matches[2];

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
            return $prefix >= 0 && $prefix <= 32;
        }

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
            return $prefix >= 0 && $prefix <= 128;
        }

        return false;
    }
}
