<?php

declare(strict_types=1);

define('ABSPATH', dirname(__DIR__, 2) . DIRECTORY_SEPARATOR . 'wordpress-test-root' . DIRECTORY_SEPARATOR);
define('WP_CONTENT_DIR', sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'lykanshield-phpunit-content');
define('WPMU_PLUGIN_DIR', WP_CONTENT_DIR . DIRECTORY_SEPARATOR . 'mu-plugins');
define('LYKANSHIELD_VERSION', '0.1.0-test');
define('LYKANSHIELD_MINIMUM_PHP_VERSION', '8.2');
define('LYKANSHIELD_MINIMUM_WORDPRESS_VERSION', '6.4');
define('LYKANSHIELD_PLUGIN_DIR', dirname(__DIR__, 2) . DIRECTORY_SEPARATOR);
define('LYKANSHIELD_MU_LOADER_FILE', 'lykanshield-loader.php');
define('HOUR_IN_SECONDS', 3600);
define('MINUTE_IN_SECONDS', 60);
define('DAY_IN_SECONDS', 86400);

$GLOBALS['wp_version'] = getenv('WP_VERSION') ?: '6.4';
$GLOBALS['lykanshield_test_options'] = [];
$GLOBALS['lykanshield_test_site_options'] = [];
$GLOBALS['lykanshield_test_transients'] = [];
$GLOBALS['lykanshield_test_scheduled_hooks'] = [];
$GLOBALS['lykanshield_test_filters'] = [];
$GLOBALS['lykanshield_test_actions'] = [];
$GLOBALS['lykanshield_test_current_user_caps'] = ['manage_options', 'activate_plugins'];
$GLOBALS['lykanshield_test_multisite'] = false;
$GLOBALS['lykanshield_test_network_admin'] = false;
$GLOBALS['lykanshield_test_super_admin'] = true;
$GLOBALS['lykanshield_test_current_blog_id'] = 1;
$GLOBALS['lykanshield_test_sites'] = [1];
$GLOBALS['lykanshield_test_home_url'] = 'https://www.example.de';
$GLOBALS['lykanshield_test_site_url'] = 'https://example.de/wp';
$GLOBALS['lykanshield_test_remote_calls'] = [];
$GLOBALS['lykanshield_test_remote_response'] = null;
$GLOBALS['lykanshield_test_mail'] = [];
$GLOBALS['lykanshield_test_wp_die'] = null;

function lykanshield_test_reset(): void
{
    $GLOBALS['lykanshield_test_options'] = [];
    $GLOBALS['lykanshield_test_site_options'] = [];
    $GLOBALS['lykanshield_test_transients'] = [];
    $GLOBALS['lykanshield_test_scheduled_hooks'] = [];
    $GLOBALS['lykanshield_test_filters'] = [];
    $GLOBALS['lykanshield_test_actions'] = [];
    $GLOBALS['lykanshield_test_current_user_caps'] = ['manage_options', 'activate_plugins'];
    $GLOBALS['lykanshield_test_multisite'] = false;
    $GLOBALS['lykanshield_test_network_admin'] = false;
    $GLOBALS['lykanshield_test_super_admin'] = true;
    $GLOBALS['lykanshield_test_current_blog_id'] = 1;
    $GLOBALS['lykanshield_test_sites'] = [1];
    $GLOBALS['lykanshield_test_home_url'] = 'https://www.example.de';
    $GLOBALS['lykanshield_test_site_url'] = 'https://example.de/wp';
    $GLOBALS['lykanshield_test_remote_calls'] = [];
    $GLOBALS['lykanshield_test_remote_response'] = null;
    $GLOBALS['lykanshield_test_mail'] = [];
    $GLOBALS['lykanshield_test_wp_die'] = null;
    $_SERVER['HTTP_HOST'] = 'www.example.de';

    if (is_dir(WP_CONTENT_DIR)) {
        lykanshield_test_remove_directory(WP_CONTENT_DIR);
    }
    mkdir(WP_CONTENT_DIR, 0777, true);
}

function lykanshield_test_remove_directory(string $directory): void
{
    if (!is_dir($directory)) {
        return;
    }

    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );

    foreach ($iterator as $item) {
        $item->isDir() ? rmdir($item->getPathname()) : unlink($item->getPathname());
    }

    rmdir($directory);
}

function get_option(string $option, mixed $default = false): mixed
{
    return array_key_exists($option, $GLOBALS['lykanshield_test_options'])
        ? $GLOBALS['lykanshield_test_options'][$option]
        : $default;
}

function update_option(string $option, mixed $value, bool $autoload = true): bool
{
    unset($autoload);
    $GLOBALS['lykanshield_test_options'][$option] = $value;
    return true;
}

function delete_option(string $option): bool
{
    unset($GLOBALS['lykanshield_test_options'][$option]);
    return true;
}

function get_site_option(string $option, mixed $default = false): mixed
{
    return array_key_exists($option, $GLOBALS['lykanshield_test_site_options'])
        ? $GLOBALS['lykanshield_test_site_options'][$option]
        : $default;
}

function update_site_option(string $option, mixed $value): bool
{
    $GLOBALS['lykanshield_test_site_options'][$option] = $value;
    return true;
}

function set_transient(string $transient, mixed $value, int $expiration = 0): bool
{
    $GLOBALS['lykanshield_test_transients'][$transient] = ['value' => $value, 'expiration' => $expiration];
    return true;
}

function get_transient(string $transient): mixed
{
    return $GLOBALS['lykanshield_test_transients'][$transient]['value'] ?? false;
}

function delete_transient(string $transient): bool
{
    unset($GLOBALS['lykanshield_test_transients'][$transient]);
    return true;
}

function add_filter(string $hook, callable $callback, int $priority = 10, int $accepted_args = 1): bool
{
    $GLOBALS['lykanshield_test_filters'][$hook][] = [$callback, $accepted_args];
    return true;
}

function apply_filters(string $hook, mixed $value, mixed ...$args): mixed
{
    foreach ($GLOBALS['lykanshield_test_filters'][$hook] ?? [] as [$callback, $acceptedArgs]) {
        $value = $callback(...array_slice(array_merge([$value], $args), 0, $acceptedArgs));
    }

    return $value;
}

function add_action(string $hook, callable $callback, int $priority = 10, int $accepted_args = 1): bool
{
    unset($priority, $accepted_args);
    $GLOBALS['lykanshield_test_actions'][$hook][] = $callback;
    return true;
}

function wp_next_scheduled(string $hook): int|false
{
    return isset($GLOBALS['lykanshield_test_scheduled_hooks'][$hook])
        ? $GLOBALS['lykanshield_test_scheduled_hooks'][$hook]['timestamp']
        : false;
}

function wp_schedule_event(int $timestamp, string $recurrence, string $hook): bool
{
    $GLOBALS['lykanshield_test_scheduled_hooks'][$hook] = [
        'timestamp' => $timestamp,
        'recurrence' => $recurrence,
    ];
    return true;
}

function wp_clear_scheduled_hook(string $hook): int
{
    $hadHook = isset($GLOBALS['lykanshield_test_scheduled_hooks'][$hook]);
    unset($GLOBALS['lykanshield_test_scheduled_hooks'][$hook]);
    return $hadHook ? 1 : 0;
}

function current_user_can(string $capability): bool
{
    return in_array($capability, $GLOBALS['lykanshield_test_current_user_caps'], true);
}

function is_multisite(): bool
{
    return $GLOBALS['lykanshield_test_multisite'];
}

function is_network_admin(): bool
{
    return $GLOBALS['lykanshield_test_network_admin'];
}

function is_super_admin(): bool
{
    return $GLOBALS['lykanshield_test_super_admin'];
}

function get_current_blog_id(): int
{
    return $GLOBALS['lykanshield_test_current_blog_id'];
}

function get_sites(array $args = []): array
{
    unset($args);
    return $GLOBALS['lykanshield_test_sites'];
}

function switch_to_blog(int $siteId): bool
{
    $GLOBALS['lykanshield_test_current_blog_id'] = $siteId;
    $GLOBALS['lykanshield_test_home_url'] = $siteId === 2 ? 'https://shop.example.de' : 'https://www.example.de';
    $GLOBALS['lykanshield_test_site_url'] = $GLOBALS['lykanshield_test_home_url'];
    return true;
}

function restore_current_blog(): bool
{
    $GLOBALS['lykanshield_test_current_blog_id'] = 1;
    $GLOBALS['lykanshield_test_home_url'] = 'https://www.example.de';
    $GLOBALS['lykanshield_test_site_url'] = 'https://example.de/wp';
    return true;
}

function wp_safe_remote_post(string $url, array $args): array|WP_Error
{
    $GLOBALS['lykanshield_test_remote_calls'][] = ['url' => $url, 'args' => $args];

    return $GLOBALS['lykanshield_test_remote_response']
        ?? ['response' => ['code' => 200], 'body' => '{"message":"ok","token":"token"}'];
}

function wp_remote_retrieve_response_code(array $response): int
{
    return (int) ($response['response']['code'] ?? 0);
}

function wp_remote_retrieve_body(array $response): string
{
    return (string) ($response['body'] ?? '');
}

function is_wp_error(mixed $value): bool
{
    return $value instanceof WP_Error;
}

final class WP_Error
{
    public function __construct(private string $message)
    {
    }

    public function get_error_message(): string
    {
        return $this->message;
    }
}

function wp_die(string $message = '', string $title = '', array $args = []): never
{
    $GLOBALS['lykanshield_test_wp_die'] = compact('message', 'title', 'args');
    throw new RuntimeException($message);
}

function home_url(string $path = ''): string
{
    return rtrim($GLOBALS['lykanshield_test_home_url'], '/') . $path;
}

function site_url(string $path = ''): string
{
    return rtrim($GLOBALS['lykanshield_test_site_url'], '/') . $path;
}

function admin_url(string $path = ''): string
{
    return 'https://www.example.de/wp-admin/' . ltrim($path, '/');
}

function network_admin_url(string $path = ''): string
{
    return 'https://www.example.de/wp-admin/network/' . ltrim($path, '/');
}

function get_bloginfo(string $show): string
{
    return $show === 'version' ? (string) $GLOBALS['wp_version'] : '';
}

function wp_parse_url(string $url, int $component = -1): mixed
{
    return parse_url($url, $component);
}

function trailingslashit(string $path): string
{
    return rtrim($path, '/\\') . DIRECTORY_SEPARATOR;
}

function wp_mkdir_p(string $path): bool
{
    return is_dir($path) || mkdir($path, 0777, true);
}

function wp_json_encode(mixed $data, int $flags = 0): string|false
{
    return json_encode($data, $flags);
}

function wp_strip_all_tags(string $text): string
{
    return strip_tags($text);
}

function esc_html__(string $text, string $domain = 'default'): string
{
    unset($domain);
    return $text;
}

function __(string $text, string $domain = 'default'): string
{
    unset($domain);
    return $text;
}

function esc_url_raw(string $url): string
{
    return filter_var(trim($url), FILTER_SANITIZE_URL);
}

function sanitize_key(string $key): string
{
    return preg_replace('/[^a-z0-9_\-]/', '', strtolower($key)) ?? '';
}

function sanitize_email(string $email): string
{
    return filter_var(trim($email), FILTER_SANITIZE_EMAIL);
}

function is_email(string $email): bool
{
    return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
}

function wp_mail(string $to, string $subject, string $message): bool
{
    $GLOBALS['lykanshield_test_mail'][] = compact('to', 'subject', 'message');
    return true;
}

function wp_remote_post(string $url, array $args): array
{
    $GLOBALS['lykanshield_test_remote_calls'][] = ['url' => $url, 'args' => $args];
    return ['response' => ['code' => 200], 'body' => '{}'];
}

function nocache_headers(): void
{
}

require_once LYKANSHIELD_PLUGIN_DIR . 'includes/class-settings.php';
require_once LYKANSHIELD_PLUGIN_DIR . 'includes/class-audit-log.php';
require_once LYKANSHIELD_PLUGIN_DIR . 'includes/class-domain-resolver.php';
require_once LYKANSHIELD_PLUGIN_DIR . 'includes/class-license-client.php';
require_once LYKANSHIELD_PLUGIN_DIR . 'includes/class-license-status.php';
require_once LYKANSHIELD_PLUGIN_DIR . 'includes/class-license-token.php';
require_once LYKANSHIELD_PLUGIN_DIR . 'includes/class-core-config.php';
require_once LYKANSHIELD_PLUGIN_DIR . 'includes/class-cron.php';
require_once LYKANSHIELD_PLUGIN_DIR . 'includes/class-loader-installer.php';
require_once LYKANSHIELD_PLUGIN_DIR . 'includes/class-multisite.php';
require_once LYKANSHIELD_PLUGIN_DIR . 'includes/class-security-view.php';
require_once LYKANSHIELD_PLUGIN_DIR . 'includes/class-plugin.php';

lykanshield_test_reset();
