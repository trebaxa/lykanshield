<?php

declare(strict_types=1);

define('ABSPATH', __DIR__);
define('LYKANSHIELD_PLUGIN_DIR', dirname(__DIR__) . DIRECTORY_SEPARATOR);
define('WP_CONTENT_DIR', sys_get_temp_dir() . '/lykanshield-security-view-test');
define('DAY_IN_SECONDS', 86400);
define('HOUR_IN_SECONDS', 3600);

$premiumMode = false;

function trailingslashit(string $path): string
{
    return rtrim($path, '/\\') . DIRECTORY_SEPARATOR;
}

function wp_strip_all_tags(string $value): string
{
    return strip_tags($value);
}

final class LykanShield_License_Status
{
    public static function current(): array
    {
        global $premiumMode;

        return ['premium' => $premiumMode];
    }
}

final class LykanShield_Core_Config
{
    public static function values(): array
    {
        return ['local_bad_ip_lifetime_hours' => 720];
    }
}

final class lykan
{
    public static function init(string $root): void
    {
        unset($root);
    }

    public static function read_logs(): array
    {
        $rows = [];
        for ($i = 0; $i < 120; $i++) {
            $rows[] = [
                gmdate('c', 1700000000 + $i),
                'Agent token=secret-' . $i,
                $i % 2 === 0 ? 'sql' : 'xss',
                '192.0.2.' . ($i % 50),
            ];
        }

        return [
            'request_count_estimate' => 120,
            'request_bucket_count' => 4,
            'statistics_are_approximate' => true,
            'blocked_bots' => $rows,
        ];
    }

    public static function read_local_bad_ip_records(): array
    {
        $records = [];
        for ($i = 0; $i < 100; $i++) {
            $records['198.51.100.' . $i] = 1700000000 + $i;
        }

        return $records;
    }
}

require_once dirname(__DIR__) . '/includes/class-security-view.php';

$free = LykanShield_Security_View::context();
assert_true($free['event_limit'] === 25, 'Free event limit must be 25.');
assert_true($free['attacker_limit'] === 10, 'Free attacker limit must be 10.');
assert_true($free['history_days'] === 1, 'Free central history must be 24 hours.');
assert_true($free['local_retention_days'] === 30, 'Free local retention must be 30 days.');
assert_true(!$free['exports_enabled'] && !$free['reports_enabled'], 'Free exports and reports must be disabled.');

$limitResult = LykanShield_Security_View::add_local_block('203.0.113.10');
assert_true(!$limitResult['ok'], 'Free must reject more than 100 local allow/block entries.');

$premiumMode = true;
$premium = LykanShield_Security_View::context();
assert_true($premium['event_limit'] === 250, 'Premium event limit must be 250.');
assert_true($premium['attacker_limit'] === 100, 'Premium attacker limit must be 100.');
assert_true($premium['history_days'] === 365, 'Premium central history must be 365 days.');
assert_true($premium['local_retention_days'] === 395, 'Premium local retention must cover 13 months.');
assert_true($premium['exports_enabled'] && $premium['reports_enabled'], 'Premium exports and reports must be enabled.');

function assert_true(bool $condition, string $message): void
{
    if (!$condition) {
        fwrite(STDERR, $message . PHP_EOL);
        exit(1);
    }
}

echo "Security limits smoke tests passed.\n";
