<?php

declare(strict_types=1);

$files = [
    __DIR__ . '/../mu-loader/lykanshield-loader.php',
    __DIR__ . '/../includes/class-cron.php',
];

$loader = (string) file_get_contents($files[0]);
lykanshield_test_static_assert(!str_contains($loader, 'renew_license'), 'MU loader must not renew licenses during frontend bootstrap.');
lykanshield_test_static_assert(!str_contains($loader, 'wp_remote_'), 'MU loader must not perform remote HTTP calls during frontend bootstrap.');
lykanshield_test_static_assert(str_contains($loader, 'lykan::run'), 'MU loader must start the local protection core.');

$cron = (string) file_get_contents($files[1]);
lykanshield_test_static_assert(str_contains($cron, 'HOOK_LICENSE_RENEWAL'), 'License renewal must be isolated in Cron.');
lykanshield_test_static_assert(str_contains($cron, 'LykanShield_License_Client::renew'), 'Cron must own synchronous license renewal.');

echo "Frontend license smoke tests passed." . PHP_EOL;

function lykanshield_test_static_assert(bool $condition, string $message): void
{
    if (!$condition) {
        fwrite(STDERR, $message . PHP_EOL);
        exit(1);
    }
}
