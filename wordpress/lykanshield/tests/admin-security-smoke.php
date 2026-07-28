<?php

declare(strict_types=1);

$adminPage = (string) file_get_contents(__DIR__ . '/../admin/class-admin-page.php');
$settingsView = (string) file_get_contents(__DIR__ . '/../admin/views/settings-page.php');

assert_contains($adminPage, 'manage_options', 'Admin page must require manage_options.');
assert_contains($adminPage, 'current_user_can', 'Admin actions must check current user capabilities.');
assert_contains($adminPage, 'check_admin_referer', 'Admin POST actions must verify nonces.');
assert_contains($settingsView, 'settings_fields', 'Settings form must use the WordPress Settings API nonce field.');
assert_contains($settingsView, 'wp_nonce_field', 'Manual dashboard actions must include nonces.');

echo "Admin security smoke tests passed." . PHP_EOL;

function assert_contains(string $source, string $needle, string $message): void
{
    if (!str_contains($source, $needle)) {
        fwrite(STDERR, $message . PHP_EOL);
        exit(1);
    }
}
