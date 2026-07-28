<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

$options = [];
$scheduled = [];
$wp_version = '6.4';

lykanshield_test_reset_dir(WP_CONTENT_DIR);

function get_option(string $option, mixed $default = false): mixed
{
    return $GLOBALS['options'][$option] ?? $default;
}

function update_option(string $option, mixed $value, bool $autoload = true): bool
{
    unset($autoload);
    $GLOBALS['options'][$option] = $value;

    return true;
}

function delete_option(string $option): bool
{
    unset($GLOBALS['options'][$option]);

    return true;
}

function wp_mkdir_p(string $path): bool
{
    return is_dir($path) || mkdir($path, 0777, true);
}

function trailingslashit(string $path): string
{
    return rtrim($path, '/\\') . DIRECTORY_SEPARATOR;
}

function wp_next_scheduled(string $hook): int|false
{
    return $GLOBALS['scheduled'][$hook]['time'] ?? false;
}

function wp_schedule_event(int $timestamp, string $recurrence, string $hook): bool
{
    $GLOBALS['scheduled'][$hook] = ['time' => $timestamp, 'recurrence' => $recurrence];

    return true;
}

function wp_clear_scheduled_hook(string $hook): void
{
    unset($GLOBALS['scheduled'][$hook]);
}

function add_filter(string $hook, callable $callback): void
{
    unset($hook, $callback);
}

function add_action(string $hook, callable $callback, int $priority = 10): void
{
    unset($hook, $callback, $priority);
}

function __(string $text, string $domain = 'default'): string
{
    unset($domain);

    return $text;
}

function esc_html(string $text): string
{
    return $text;
}

function esc_html__(string $text, string $domain = 'default'): string
{
    unset($domain);

    return $text;
}

function wp_die(string $message): never
{
    throw new RuntimeException($message);
}

function is_multisite(): bool
{
    return false;
}

final class LykanShield_Settings
{
    public static function ensure_defaults(): void
    {
    }

    public static function set_loader_enabled(bool $enabled): void
    {
        update_option('loader_enabled', $enabled, false);
    }

    public static function remove_loader_on_deactivation(): bool
    {
        return true;
    }
}

final class LykanShield_Multisite
{
    public static function is_multisite(): bool
    {
        return false;
    }

    public static function initialize_current_site(): void
    {
        update_option('site_initialized', true, false);
    }
}

final class LykanShield_License_Status
{
    public static function current(): array
    {
        return ['premium' => false];
    }
}

require_once __DIR__ . '/../includes/class-loader-installer.php';
require_once __DIR__ . '/../includes/class-cron.php';

$install = LykanShield_Loader_Installer::install();
lykanshield_test_assert($install['ok'], 'MU loader must install into a writable mu-plugins directory.');
lykanshield_test_assert(is_file(WPMU_PLUGIN_DIR . DIRECTORY_SEPARATOR . LYKANSHIELD_MU_LOADER_FILE), 'MU loader target file must exist.');

file_put_contents(WPMU_PLUGIN_DIR . DIRECTORY_SEPARATOR . LYKANSHIELD_MU_LOADER_FILE, '<?php // foreign loader');
$foreign = LykanShield_Loader_Installer::install();
lykanshield_test_assert(!$foreign['ok'], 'Installer must not overwrite a foreign MU loader.');

file_put_contents(
    WPMU_PLUGIN_DIR . DIRECTORY_SEPARATOR . LYKANSHIELD_MU_LOADER_FILE,
    "<?php\n// LykanShield MU loader managed by LykanShield\n"
);
$remove = LykanShield_Loader_Installer::remove();
lykanshield_test_assert($remove['ok'] && !is_file(WPMU_PLUGIN_DIR . DIRECTORY_SEPARATOR . LYKANSHIELD_MU_LOADER_FILE), 'Managed MU loader must be removable.');

LykanShield_Cron::schedule();
foreach ([LykanShield_Cron::HOOK_RULE_REFRESH, LykanShield_Cron::HOOK_REPORT_QUEUE, LykanShield_Cron::HOOK_LICENSE_RENEWAL, LykanShield_Cron::HOOK_DAILY_SUMMARY, LykanShield_Cron::HOOK_LOG_RETENTION] as $hook) {
    lykanshield_test_assert(isset($scheduled[$hook]), $hook . ' must be scheduled.');
}

LykanShield_Cron::clear();
lykanshield_test_assert($scheduled === [], 'Cron hooks must be cleared on deactivation.');

echo "Cron and loader smoke tests passed." . PHP_EOL;
