<?php

declare(strict_types=1);

defined('ABSPATH') || exit;

final class LykanShield_Plugin
{
    private static ?self $instance = null;

    private bool $booted = false;

    public static function instance(): self
    {
        if (self::$instance === null) {
            self::$instance = new self();
        }

        return self::$instance;
    }

    public static function activate(bool $networkWide = false): void
    {
        self::load_core_classes();

        $errors = self::activation_errors($networkWide);

        if ($errors !== []) {
            wp_die(
                esc_html(implode(' ', $errors)),
                esc_html__('LykanShield activation failed', 'lykanshield'),
                ['back_link' => true]
            );
        }

        self::initialize_sites($networkWide);
        LykanShield_Settings::set_loader_enabled(true);
        $loader = LykanShield_Loader_Installer::install();

        if (!$loader['ok']) {
            update_option('lykanshield_activation_notice', $loader['message'], false);
        } else {
            delete_option('lykanshield_activation_notice');
        }

        LykanShield_Cron::schedule();
    }

    public static function deactivate(bool $networkWide = false): void
    {
        self::load_core_classes();

        self::deactivate_sites($networkWide);

        if (LykanShield_Settings::remove_loader_on_deactivation()) {
            LykanShield_Loader_Installer::remove();
        }
    }

    public function boot(): void
    {
        if ($this->booted) {
            return;
        }

        $this->booted = true;

        self::load_core_classes();

        LykanShield_Cron::register();
        add_action('admin_init', [LykanShield_Loader_Installer::class, 'maybe_install']);
        add_action('init', [LykanShield_Multisite::class, 'remember_current_domain'], 20);

        if (is_admin()) {
            require_once LYKANSHIELD_PLUGIN_DIR . 'admin/class-admin-page.php';
            require_once LYKANSHIELD_PLUGIN_DIR . 'admin/class-dashboard-widget.php';
            LykanShield_Admin_Page::register();
            LykanShield_Dashboard_Widget::register();
        }
    }

    private function __construct()
    {
    }

    public static function load_for_uninstall_hook(): void
    {
        self::load_core_classes();
    }

    private static function load_core_classes(): void
    {
        require_once LYKANSHIELD_PLUGIN_DIR . 'includes/class-settings.php';
        require_once LYKANSHIELD_PLUGIN_DIR . 'includes/class-audit-log.php';
        require_once LYKANSHIELD_PLUGIN_DIR . 'includes/class-multisite.php';
        require_once LYKANSHIELD_PLUGIN_DIR . 'includes/class-core-config.php';
        require_once LYKANSHIELD_PLUGIN_DIR . 'includes/class-loader-installer.php';
        require_once LYKANSHIELD_PLUGIN_DIR . 'includes/class-domain-resolver.php';
        require_once LYKANSHIELD_PLUGIN_DIR . 'includes/class-license-client.php';
        require_once LYKANSHIELD_PLUGIN_DIR . 'includes/class-license-token.php';
        require_once LYKANSHIELD_PLUGIN_DIR . 'includes/class-license-status.php';
        require_once LYKANSHIELD_PLUGIN_DIR . 'includes/class-cron.php';
        require_once LYKANSHIELD_PLUGIN_DIR . 'includes/class-health-check.php';
        require_once LYKANSHIELD_PLUGIN_DIR . 'includes/class-security-view.php';
        require_once LYKANSHIELD_PLUGIN_DIR . 'includes/class-uninstaller.php';
    }

    /**
     * @return string[]
     */
    private static function activation_errors(bool $networkWide): array
    {
        global $wp_version;

        $errors = [];

        if (version_compare(PHP_VERSION, LYKANSHIELD_MINIMUM_PHP_VERSION, '<')) {
            $errors[] = sprintf('PHP %s or newer is required.', LYKANSHIELD_MINIMUM_PHP_VERSION);
        }

        if (isset($wp_version) && version_compare((string) $wp_version, LYKANSHIELD_MINIMUM_WORDPRESS_VERSION, '<')) {
            $errors[] = sprintf('WordPress %s or newer is required.', LYKANSHIELD_MINIMUM_WORDPRESS_VERSION);
        }

        foreach (['json', 'pcre', 'sodium'] as $extension) {
            if (!extension_loaded($extension)) {
                $errors[] = sprintf('The PHP extension %s is required.', $extension);
            }
        }

        $dataDir = trailingslashit(WP_CONTENT_DIR) . 'lykan';
        if (!is_dir($dataDir) && !wp_mkdir_p($dataDir)) {
            $errors[] = sprintf('The LykanShield data directory could not be created: %s', $dataDir);
        } elseif (!is_writable($dataDir)) {
            $errors[] = sprintf('The LykanShield data directory is not writable: %s', $dataDir);
        }

        return $errors;
    }

    private static function initialize_sites(bool $networkWide): void
    {
        if ($networkWide && LykanShield_Multisite::is_multisite() && function_exists('get_sites') && function_exists('switch_to_blog') && function_exists('restore_current_blog')) {
            $siteIds = get_sites(['fields' => 'ids', 'number' => 0]);

            foreach ($siteIds as $siteId) {
                switch_to_blog((int) $siteId);
                LykanShield_Multisite::initialize_current_site();
                LykanShield_Cron::schedule();
                restore_current_blog();
            }

            return;
        }

        LykanShield_Multisite::initialize_current_site();
        LykanShield_Cron::schedule();
    }

    private static function deactivate_sites(bool $networkWide): void
    {
        if ($networkWide && LykanShield_Multisite::is_multisite() && function_exists('get_sites') && function_exists('switch_to_blog') && function_exists('restore_current_blog')) {
            $siteIds = get_sites(['fields' => 'ids', 'number' => 0]);

            foreach ($siteIds as $siteId) {
                switch_to_blog((int) $siteId);
                LykanShield_Cron::clear();
                LykanShield_Settings::set_loader_enabled(false);
                restore_current_blog();
            }

            return;
        }

        LykanShield_Cron::clear();
        LykanShield_Settings::set_loader_enabled(false);
    }
}
