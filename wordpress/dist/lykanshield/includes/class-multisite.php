<?php

declare(strict_types=1);

defined('ABSPATH') || exit;

final class LykanShield_Multisite
{
    public const NETWORK_TOKENS_OPTION = 'lykanshield_domain_license_tokens';
    public const NETWORK_KEYS_OPTION = 'lykanshield_domain_license_keys';
    public const DOMAIN_FINGERPRINT_OPTION = 'lykanshield_domain_fingerprint';

    public static function is_multisite(): bool
    {
        return function_exists('is_multisite') && is_multisite();
    }

    public static function is_network_admin_screen(): bool
    {
        return function_exists('is_network_admin') && is_network_admin();
    }

    public static function can_manage_network(): bool
    {
        return self::is_multisite() && function_exists('is_super_admin') && is_super_admin();
    }

    public static function required_capability(): string
    {
        return self::is_network_admin_screen() ? 'manage_network_options' : 'manage_options';
    }

    public static function settings_url(): string
    {
        if (self::is_network_admin_screen() && function_exists('network_admin_url')) {
            return network_admin_url('settings.php?page=lykanshield');
        }

        return admin_url('options-general.php?page=lykanshield');
    }

    /**
     * @return array{multisite:bool,site_id:int,network_admin:bool,network_config_allowed:bool,canonical_domain:string,registrable_domain:string,token_source:string,domain_changed:bool,warnings:string[]}
     */
    public static function context(): array
    {
        $domain = LykanShield_License_Client::domain_context();
        $registrable = $domain['registrable_domain'];
        $currentFingerprint = self::fingerprint($domain['canonical_host'], $registrable);
        $savedFingerprint = (string) get_option(self::DOMAIN_FINGERPRINT_OPTION, '');
        $domainChanged = $savedFingerprint !== '' && !hash_equals($savedFingerprint, $currentFingerprint);
        $warnings = [];

        if (self::is_multisite()) {
            $warnings[] = 'Multisite uses one Premium entitlement per registrable main domain. Subdirectory sites and subdomains of the same main domain share that entitlement.';
        }

        if ($domainChanged) {
            $warnings[] = 'This site domain changed. Premium must be activated again if the registrable main domain changed.';
        }

        return [
            'multisite' => self::is_multisite(),
            'site_id' => function_exists('get_current_blog_id') ? (int) get_current_blog_id() : 0,
            'network_admin' => self::is_network_admin_screen(),
            'network_config_allowed' => self::can_manage_network(),
            'canonical_domain' => $domain['canonical_host'],
            'registrable_domain' => $registrable,
            'token_source' => self::is_multisite() ? 'network-domain' : 'site',
            'domain_changed' => $domainChanged,
            'warnings' => $warnings,
        ];
    }

    public static function remember_current_domain(): void
    {
        $domain = LykanShield_License_Client::domain_context();

        if ($domain['canonical_host'] === '' && $domain['registrable_domain'] === '') {
            return;
        }

        update_option(self::DOMAIN_FINGERPRINT_OPTION, self::fingerprint($domain['canonical_host'], $domain['registrable_domain']), false);
    }

    public static function license_key_for_domain(string $registrableDomain): string
    {
        if (!self::is_multisite()) {
            return trim((string) get_option(LykanShield_Settings::OPTION_LICENSE_KEY, ''));
        }

        return self::network_value(self::NETWORK_KEYS_OPTION, $registrableDomain);
    }

    public static function save_license_key_for_current_domain(string $licenseKey): bool
    {
        $domain = LykanShield_License_Client::domain_context();

        if (!self::is_multisite()) {
            return $licenseKey === ''
                ? delete_option(LykanShield_Settings::OPTION_LICENSE_KEY)
                : update_option(LykanShield_Settings::OPTION_LICENSE_KEY, $licenseKey, false);
        }

        return self::update_network_value(self::NETWORK_KEYS_OPTION, $domain['registrable_domain'], $licenseKey);
    }

    public static function token_for_domain(string $registrableDomain): string
    {
        if (!self::is_multisite()) {
            return trim((string) get_option(LykanShield_Settings::OPTION_LICENSE_TOKEN, ''));
        }

        return self::network_value(self::NETWORK_TOKENS_OPTION, $registrableDomain);
    }

    public static function save_token_for_current_domain(string $token): bool
    {
        $domain = LykanShield_License_Client::domain_context();

        if (!self::is_multisite()) {
            return $token === ''
                ? delete_option(LykanShield_Settings::OPTION_LICENSE_TOKEN)
                : update_option(LykanShield_Settings::OPTION_LICENSE_TOKEN, $token, false);
        }

        return self::update_network_value(self::NETWORK_TOKENS_OPTION, $domain['registrable_domain'], $token);
    }

    /**
     * @return array<int,array{site_id:int,canonical_domain:string,registrable_domain:string,license_scope:string,domain_changed:bool}>
     */
    public static function site_rows(): array
    {
        if (!self::is_multisite() || !function_exists('get_sites') || !function_exists('switch_to_blog') || !function_exists('restore_current_blog')) {
            $context = self::context();

            return [[
                'site_id' => $context['site_id'],
                'canonical_domain' => $context['canonical_domain'],
                'registrable_domain' => $context['registrable_domain'],
                'license_scope' => $context['registrable_domain'] !== '' ? $context['registrable_domain'] : 'single-site',
                'domain_changed' => $context['domain_changed'],
            ]];
        }

        $rows = [];
        $siteIds = get_sites(['fields' => 'ids', 'number' => 0]);

        foreach ($siteIds as $siteId) {
            switch_to_blog((int) $siteId);
            $context = self::context();
            $rows[] = [
                'site_id' => (int) $siteId,
                'canonical_domain' => $context['canonical_domain'],
                'registrable_domain' => $context['registrable_domain'],
                'license_scope' => $context['registrable_domain'],
                'domain_changed' => $context['domain_changed'],
            ];
            restore_current_blog();
        }

        return $rows;
    }

    public static function initialize_current_site(): void
    {
        LykanShield_Settings::ensure_defaults();
        LykanShield_Core_Config::ensure_written();
        self::remember_current_domain();
    }

    private static function fingerprint(string $canonicalDomain, string $registrableDomain): string
    {
        return hash('sha256', $canonicalDomain . '|' . $registrableDomain);
    }

    private static function network_value(string $option, string $registrableDomain): string
    {
        $values = get_site_option($option, []);

        if (!is_array($values) || $registrableDomain === '') {
            return '';
        }

        return isset($values[$registrableDomain]) && is_string($values[$registrableDomain])
            ? trim($values[$registrableDomain])
            : '';
    }

    private static function update_network_value(string $option, string $registrableDomain, string $value): bool
    {
        if ($registrableDomain === '') {
            return false;
        }

        $values = get_site_option($option, []);
        $values = is_array($values) ? $values : [];
        $value = trim($value);

        if ($value === '') {
            unset($values[$registrableDomain]);
        } else {
            $values[$registrableDomain] = $value;
        }

        return update_site_option($option, $values);
    }
}
