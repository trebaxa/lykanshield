<?php

declare(strict_types=1);

$testRoot = sys_get_temp_dir() . DIRECTORY_SEPARATOR . 'lykanshield-loader-test-' . bin2hex(random_bytes(4));
$pluginDir = $testRoot . DIRECTORY_SEPARATOR . 'plugin' . DIRECTORY_SEPARATOR;
$muDir = $testRoot . DIRECTORY_SEPARATOR . 'mu-plugins';
mkdir($pluginDir . 'mu-loader', 0777, true);
mkdir($muDir, 0777, true);

define('ABSPATH', $testRoot);
define('LYKANSHIELD_PLUGIN_DIR', $pluginDir);
define('LYKANSHIELD_MU_LOADER_FILE', 'lykanshield-loader.php');
define('WPMU_PLUGIN_DIR', $muDir);

$options = [];
$source = $pluginDir . 'mu-loader' . DIRECTORY_SEPARATOR . LYKANSHIELD_MU_LOADER_FILE;
file_put_contents($source, "<?php\n// LykanShield MU loader managed by LykanShield\n");

function trailingslashit(string $path): string
{
    return rtrim($path, '/\\') . DIRECTORY_SEPARATOR;
}

function wp_mkdir_p(string $path): bool
{
    return is_dir($path) || mkdir($path, 0777, true);
}

function get_option(string $option, mixed $default = false): mixed
{
    global $options;

    return $options[$option] ?? $default;
}

function update_option(string $option, mixed $value, bool $autoload = true): bool
{
    global $options;
    unset($autoload);

    $options[$option] = $value;

    return true;
}

function current_user_can(string $capability): bool
{
    unset($capability);

    return true;
}

require_once dirname(__DIR__) . '/includes/class-loader-installer.php';

$installed = LykanShield_Loader_Installer::install();
assert_true($installed['ok'], 'Managed MU loader should install.');
assert_true(is_file($muDir . DIRECTORY_SEPARATOR . LYKANSHIELD_MU_LOADER_FILE), 'Managed MU loader file should exist.');

$removed = LykanShield_Loader_Installer::remove();
assert_true($removed['ok'], 'Managed MU loader should be removable.');
assert_true(!is_file($muDir . DIRECTORY_SEPARATOR . LYKANSHIELD_MU_LOADER_FILE), 'Managed MU loader file should be removed.');

file_put_contents($muDir . DIRECTORY_SEPARATOR . LYKANSHIELD_MU_LOADER_FILE, "<?php\n// foreign loader\n");
$foreign = LykanShield_Loader_Installer::install();
assert_true(!$foreign['ok'], 'Foreign MU loader must not be overwritten.');

remove_tree($testRoot);

function assert_true(bool $condition, string $message): void
{
    if (!$condition) {
        fwrite(STDERR, $message . PHP_EOL);
        exit(1);
    }
}

function remove_tree(string $path): void
{
    if (!is_dir($path)) {
        return;
    }

    $items = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($path, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );

    foreach ($items as $item) {
        if ($item->isDir()) {
            rmdir($item->getPathname());
            continue;
        }

        unlink($item->getPathname());
    }

    rmdir($path);
}

echo "Loader installer smoke tests passed.\n";
