<?php
/**
 * Plugin Name: LykanShield Loader
 * Description: Starts the LykanShield core early from the WordPress MU plugin layer.
 * Version: 0.1.0
 * LykanShield MU loader managed by LykanShield.
 */

declare(strict_types=1);

defined('ABSPATH') || exit;

if (defined('LYKANSHIELD_MU_LOADER_RUNNING')) {
    return;
}

define('LYKANSHIELD_MU_LOADER_RUNNING', true);

$lykanshieldPlugin = WP_PLUGIN_DIR . '/lykanshield/lykanshield.php';
$lykanshieldCore = WP_PLUGIN_DIR . '/lykanshield/includes/lykan.class.php';
$lykanshieldSettings = WP_PLUGIN_DIR . '/lykanshield/includes/class-settings.php';
$lykanshieldDomainResolver = WP_PLUGIN_DIR . '/lykanshield/includes/class-domain-resolver.php';
$lykanshieldLicenseClient = WP_PLUGIN_DIR . '/lykanshield/includes/class-license-client.php';
$lykanshieldCoreConfig = WP_PLUGIN_DIR . '/lykanshield/includes/class-core-config.php';

if (get_option('lykanshield_loader_enabled', '0') !== '1') {
    return;
}

if (!is_readable($lykanshieldPlugin) || !is_readable($lykanshieldCore)) {
    $lastLog = (int) get_option('lykanshield_mu_loader_missing_core_log', 0);

    if ((time() - $lastLog) >= DAY_IN_SECONDS) {
        update_option('lykanshield_mu_loader_missing_core_log', time(), false);
        error_log('LykanShield MU loader could not find the LykanShield plugin or core file.');
    }

    return;
}

if (!class_exists('lykan', false)) {
    require_once $lykanshieldCore;
}

if (!class_exists('LykanShield_Core_Config', false)
    && is_readable($lykanshieldSettings)
    && is_readable($lykanshieldDomainResolver)
    && is_readable($lykanshieldLicenseClient)
    && is_readable($lykanshieldCoreConfig)
) {
    require_once $lykanshieldSettings;
    require_once $lykanshieldDomainResolver;
    require_once $lykanshieldLicenseClient;
    require_once $lykanshieldCoreConfig;
    LykanShield_Core_Config::ensure_written();
}

if (!defined('LYKANSHIELD_LICENSE_RUNTIME_STATUS')) {
    $lykanshieldLicenseStatus = get_option('lykanshield_license_runtime_status', []);
    $lykanshieldRuntimeStatus = is_array($lykanshieldLicenseStatus)
        ? (string) ($lykanshieldLicenseStatus['status'] ?? 'free')
        : 'free';

    define('LYKANSHIELD_LICENSE_RUNTIME_STATUS', $lykanshieldRuntimeStatus);
}

if (class_exists('lykan', false) && method_exists('lykan', 'run')) {
    lykan::run(ABSPATH);
}
