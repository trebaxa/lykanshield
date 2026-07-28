<?php
/**
 * Plugin Name: LykanShield
 * Plugin URI: https://github.com/PetrichorLabs/lykanshield
 * Description: Complete WordPress protection with SQL, XSS, exploit, upload, MIME, bad-IP and bot defenses. Premium unlocks long-term analytics and automation for one main domain.
 * Version: 0.1.0
 * Requires at least: 6.4
 * Requires PHP: 8.2
 * Author: LykanShield
 * License: GPL-3.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-3.0.html
 * Text Domain: lykanshield
 * Domain Path: /languages
 */

declare(strict_types=1);

defined('ABSPATH') || exit;

define('LYKANSHIELD_VERSION', '0.1.0');
define('LYKANSHIELD_MINIMUM_PHP_VERSION', '8.2');
define('LYKANSHIELD_MINIMUM_WORDPRESS_VERSION', '6.4');
define('LYKANSHIELD_PLUGIN_FILE', __FILE__);
define('LYKANSHIELD_PLUGIN_DIR', plugin_dir_path(__FILE__));
define('LYKANSHIELD_PLUGIN_URL', plugin_dir_url(__FILE__));
define('LYKANSHIELD_MU_LOADER_FILE', 'lykanshield-loader.php');

require_once LYKANSHIELD_PLUGIN_DIR . 'includes/class-plugin.php';
LykanShield_Plugin::load_for_uninstall_hook();

register_activation_hook(__FILE__, ['LykanShield_Plugin', 'activate']);
register_deactivation_hook(__FILE__, ['LykanShield_Plugin', 'deactivate']);
register_uninstall_hook(__FILE__, ['LykanShield_Uninstaller', 'uninstall']);

LykanShield_Plugin::instance()->boot();
