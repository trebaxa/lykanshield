<?php

declare(strict_types=1);

defined('WP_UNINSTALL_PLUGIN') || exit;

defined('LYKANSHIELD_VERSION') || define('LYKANSHIELD_VERSION', '0.1.0');
defined('LYKANSHIELD_PLUGIN_DIR') || define('LYKANSHIELD_PLUGIN_DIR', plugin_dir_path(__FILE__));
defined('LYKANSHIELD_MU_LOADER_FILE') || define('LYKANSHIELD_MU_LOADER_FILE', 'lykanshield-loader.php');

require_once LYKANSHIELD_PLUGIN_DIR . 'includes/class-settings.php';
require_once LYKANSHIELD_PLUGIN_DIR . 'includes/class-core-config.php';
require_once LYKANSHIELD_PLUGIN_DIR . 'includes/class-audit-log.php';
require_once LYKANSHIELD_PLUGIN_DIR . 'includes/class-domain-resolver.php';
require_once LYKANSHIELD_PLUGIN_DIR . 'includes/class-multisite.php';
require_once LYKANSHIELD_PLUGIN_DIR . 'includes/class-loader-installer.php';
require_once LYKANSHIELD_PLUGIN_DIR . 'includes/class-license-client.php';
require_once LYKANSHIELD_PLUGIN_DIR . 'includes/class-license-token.php';
require_once LYKANSHIELD_PLUGIN_DIR . 'includes/class-license-status.php';
require_once LYKANSHIELD_PLUGIN_DIR . 'includes/class-cron.php';
require_once LYKANSHIELD_PLUGIN_DIR . 'includes/class-uninstaller.php';

LykanShield_Uninstaller::run();
