<?php

declare(strict_types=1);

define('ABSPATH', __DIR__);
define('WP_CONTENT_DIR', sys_get_temp_dir() . '/lykanshield-core-config-test');
define('LYKANSHIELD_VERSION', '0.1.0');

$options = [
    'lykanshield_filters' => [
        'sql_protection' => true,
        'xss_protection' => true,
        'exploit_protection' => false,
        'upload_mime_protection' => true,
        'bad_ip_bot_protection' => true,
    ],
    'lykanshield_trusted_proxies' => "192.0.2.1\n2001:db8::/32",
    'lykanshield_core_config' => [
        'api_key' => 'core-api-key-1',
        'notification_email' => 'security@example.com',
        'rules_unavailable_action' => 'block',
        'sql_injection_block_score' => 99,
        'log_lines_count' => 5,
        'local_bad_ip_lifetime_hours' => 100000,
        'local_bad_ip_max_entries' => 1,
        'report_queue_max_entries' => 60000,
        'request_inspection_max_bytes' => 100,
        'unknown_key' => 'drop-me',
    ],
];

function get_option(string $option, mixed $default = false): mixed
{
    global $options;

    return array_key_exists($option, $options) ? $options[$option] : $default;
}

function update_option(string $option, mixed $value, bool $autoload = true): bool
{
    unset($autoload);

    global $options;
    $options[$option] = $value;

    return true;
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

function is_email(string $email): bool
{
    return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
}

function sanitize_email(string $email): string
{
    return filter_var(trim($email), FILTER_SANITIZE_EMAIL);
}

function wp_parse_url(string $url, int $component = -1): mixed
{
    return parse_url($url, $component);
}

function apply_filters(string $hook, mixed $value): mixed
{
    return $value;
}

function home_url(): string
{
    return 'https://www.example.de';
}

function site_url(): string
{
    return 'https://example.de/wp';
}

require_once __DIR__ . '/../includes/class-settings.php';
require_once __DIR__ . '/../includes/class-domain-resolver.php';
require_once __DIR__ . '/../includes/class-license-client.php';
require_once __DIR__ . '/../includes/class-core-config.php';

$sanitized = LykanShield_Core_Config::sanitize($options['lykanshield_core_config']);

if (array_key_exists('unknown_key', $sanitized)) {
    fwrite(STDERR, "Unknown config key was not dropped.\n");
    exit(1);
}

if ($sanitized['sql_injection_block_score'] !== 10 || $sanitized['log_lines_count'] !== 20) {
    fwrite(STDERR, "Integer bounds were not enforced.\n");
    exit(1);
}

$options['lykanshield_core_config'] = $sanitized;
$config = LykanShield_Core_Config::build();

if (($config['filter_active']['exploit'] ?? true) !== false) {
    fwrite(STDERR, "Filter mapping did not disable exploit protection.\n");
    exit(1);
}

if (($config['apikey'] ?? '') !== 'core-api-key-1' || isset($config['license_key'])) {
    fwrite(STDERR, "API key and license key separation failed.\n");
    exit(1);
}

if (!LykanShield_Core_Config::ensure_written() || !is_file(LykanShield_Core_Config::config_path())) {
    fwrite(STDERR, "Config file was not written.\n");
    exit(1);
}

echo "Core config smoke tests passed.\n";
