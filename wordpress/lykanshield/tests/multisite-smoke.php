<?php

declare(strict_types=1);

define('ABSPATH', __DIR__);

$options = [];
$siteOptions = [];
$currentBlogId = 1;
$blogs = [
    1 => ['home' => 'https://example.de', 'site' => 'https://example.de/wp'],
    2 => ['home' => 'https://shop.example.de', 'site' => 'https://shop.example.de'],
    3 => ['home' => 'https://example.com', 'site' => 'https://example.com'],
];

function is_multisite(): bool
{
    return true;
}

function is_network_admin(): bool
{
    return false;
}

function is_super_admin(): bool
{
    return true;
}

function get_current_blog_id(): int
{
    global $currentBlogId;

    return $currentBlogId;
}

function get_sites(array $args): array
{
    unset($args);

    return [1, 2, 3];
}

function switch_to_blog(int $blogId): void
{
    global $currentBlogId;

    $currentBlogId = $blogId;
}

function restore_current_blog(): void
{
    global $currentBlogId;

    $currentBlogId = 1;
}

function home_url(): string
{
    global $blogs, $currentBlogId;

    return $blogs[$currentBlogId]['home'];
}

function site_url(): string
{
    global $blogs, $currentBlogId;

    return $blogs[$currentBlogId]['site'];
}

function admin_url(string $path = ''): string
{
    return 'https://example.de/wp-admin/' . ltrim($path, '/');
}

function wp_parse_url(string $url, int $component = -1): mixed
{
    return parse_url($url, $component);
}

function wp_unslash(mixed $value): mixed
{
    return $value;
}

function apply_filters(string $hook, mixed $value): mixed
{
    unset($hook);

    return $value;
}

function get_option(string $option, mixed $default = false): mixed
{
    global $options, $currentBlogId;

    return $options[$currentBlogId][$option] ?? $default;
}

function update_option(string $option, mixed $value, bool $autoload = true): bool
{
    global $options, $currentBlogId;
    unset($autoload);

    $options[$currentBlogId][$option] = $value;

    return true;
}

function delete_option(string $option): bool
{
    global $options, $currentBlogId;

    unset($options[$currentBlogId][$option]);

    return true;
}

function get_site_option(string $option, mixed $default = false): mixed
{
    global $siteOptions;

    return $siteOptions[$option] ?? $default;
}

function update_site_option(string $option, mixed $value): bool
{
    global $siteOptions;

    $siteOptions[$option] = $value;

    return true;
}

require_once __DIR__ . '/../includes/class-domain-resolver.php';

final class LykanShield_License_Client
{
    public static function domain_context(): array
    {
        return LykanShield_Domain_Resolver::current();
    }
}

final class LykanShield_Settings
{
    public const OPTION_LICENSE_KEY = 'lykanshield_license_key';
    public const OPTION_LICENSE_TOKEN = 'lykanshield_license_token';

    public static function ensure_defaults(): void
    {
    }
}

final class LykanShield_Core_Config
{
    public static function ensure_written(): void
    {
    }
}

require_once __DIR__ . '/../includes/class-multisite.php';

LykanShield_Multisite::save_token_for_current_domain('token-for-example-de');
switch_to_blog(2);
$shopToken = LykanShield_Multisite::token_for_domain('example.de');
$shopContext = LykanShield_Multisite::context();
restore_current_blog();

switch_to_blog(3);
LykanShield_Multisite::save_token_for_current_domain('token-for-example-com');
$comToken = LykanShield_Multisite::token_for_domain('example.com');
$comContext = LykanShield_Multisite::context();
LykanShield_Multisite::remember_current_domain();
restore_current_blog();

if ($shopToken !== 'token-for-example-de' || $shopContext['registrable_domain'] !== 'example.de') {
    fwrite(STDERR, "Subdomain multisite did not map to the shared example.de license scope.\n");
    exit(1);
}

if ($comToken !== 'token-for-example-com' || $comContext['registrable_domain'] !== 'example.com') {
    fwrite(STDERR, "Separate main domain did not use its own license scope.\n");
    exit(1);
}

switch_to_blog(3);
$blogs[3]['home'] = 'https://changed-example.com';
$changed = LykanShield_Multisite::context();
restore_current_blog();

if (!$changed['domain_changed']) {
    fwrite(STDERR, "Domain change was not detected.\n");
    exit(1);
}

$rows = LykanShield_Multisite::site_rows();

if (count($rows) !== 3 || $rows[1]['license_scope'] !== 'example.de' || $rows[2]['license_scope'] !== 'changed-example.com') {
    fwrite(STDERR, "Multisite site rows do not expose the expected license scopes.\n");
    exit(1);
}

echo "Multisite smoke tests passed.\n";
