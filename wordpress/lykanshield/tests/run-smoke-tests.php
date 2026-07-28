<?php

declare(strict_types=1);

$tests = [
    'admin-security-smoke.php',
    'core-config-smoke.php',
    'cron-smoke.php',
    'cron-loader-smoke.php',
    'dashboard-widget-smoke.php',
    'domain-resolver-smoke.php',
    'frontend-license-smoke.php',
    'license-entitlement-smoke.php',
    'license-status-smoke.php',
    'license-token-smoke.php',
    'loader-installer-smoke.php',
    'multisite-smoke.php',
    'security-limits-smoke.php',
];

$php = PHP_BINARY;
$failed = false;

foreach ($tests as $test) {
    $path = __DIR__ . DIRECTORY_SEPARATOR . $test;
    $command = escapeshellarg($php) . ' ' . escapeshellarg($path);
    $output = [];
    $exitCode = 0;

    exec($command, $output, $exitCode);

    foreach ($output as $line) {
        echo $test . ': ' . $line . PHP_EOL;
    }

    if ($exitCode !== 0) {
        fwrite(STDERR, $test . ' failed with exit code ' . $exitCode . PHP_EOL);
        $failed = true;
    }
}

exit($failed ? 1 : 0);
