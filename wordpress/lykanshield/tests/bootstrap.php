<?php

declare(strict_types=1);

if (!defined('ABSPATH')) {
    define('ABSPATH', dirname(__DIR__, 3) . DIRECTORY_SEPARATOR);
}

if (!defined('LYKANSHIELD_PLUGIN_DIR')) {
    define('LYKANSHIELD_PLUGIN_DIR', dirname(__DIR__) . DIRECTORY_SEPARATOR);
}

if (!defined('LYKANSHIELD_VERSION')) {
    define('LYKANSHIELD_VERSION', '0.1.0-test');
}

if (!defined('LYKANSHIELD_MINIMUM_PHP_VERSION')) {
    define('LYKANSHIELD_MINIMUM_PHP_VERSION', '8.2');
}

if (!defined('LYKANSHIELD_MINIMUM_WORDPRESS_VERSION')) {
    define('LYKANSHIELD_MINIMUM_WORDPRESS_VERSION', '6.4');
}

if (!defined('LYKANSHIELD_MU_LOADER_FILE')) {
    define('LYKANSHIELD_MU_LOADER_FILE', 'lykanshield-loader.php');
}

if (!defined('WP_CONTENT_DIR')) {
    define('WP_CONTENT_DIR', sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'lykanshield-wp-content-test');
}

if (!defined('WPMU_PLUGIN_DIR')) {
    define('WPMU_PLUGIN_DIR', WP_CONTENT_DIR . DIRECTORY_SEPARATOR . 'mu-plugins');
}

if (!defined('HOUR_IN_SECONDS')) {
    define('HOUR_IN_SECONDS', 3600);
}

if (!defined('MINUTE_IN_SECONDS')) {
    define('MINUTE_IN_SECONDS', 60);
}

if (!defined('DAY_IN_SECONDS')) {
    define('DAY_IN_SECONDS', 86400);
}

function lykanshield_test_assert(bool $condition, string $message): void
{
    if (!$condition) {
        fwrite(STDERR, $message . PHP_EOL);
        exit(1);
    }
}

function lykanshield_test_reset_dir(string $directory): void
{
    if (!is_dir($directory)) {
        return;
    }

    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($directory, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );

    foreach ($iterator as $entry) {
        if ($entry->isDir()) {
            rmdir($entry->getPathname());
            continue;
        }

        unlink($entry->getPathname());
    }

    rmdir($directory);
}
