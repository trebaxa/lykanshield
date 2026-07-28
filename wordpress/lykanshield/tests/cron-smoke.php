<?php

declare(strict_types=1);

define('ABSPATH', __DIR__);
define('LYKANSHIELD_PLUGIN_DIR', dirname(__DIR__) . DIRECTORY_SEPARATOR);
define('HOUR_IN_SECONDS', 3600);
define('MINUTE_IN_SECONDS', 60);
define('DAY_IN_SECONDS', 86400);

$scheduled = [];
$cleared = [];
$premiumMode = false;

function __(string $text, string $domain = 'default'): string
{
    unset($domain);

    return $text;
}

function add_filter(string $hook, callable $callback): void
{
    unset($hook, $callback);
}

function add_action(string $hook, callable $callback): void
{
    unset($hook, $callback);
}

function wp_next_scheduled(string $hook): int|false
{
    global $scheduled;

    return isset($scheduled[$hook]) ? 1 : false;
}

function wp_schedule_event(int $timestamp, string $schedule, string $hook): bool
{
    global $scheduled;

    $scheduled[$hook] = ['timestamp' => $timestamp, 'schedule' => $schedule];

    return true;
}

function wp_clear_scheduled_hook(string $hook): void
{
    global $scheduled, $cleared;

    unset($scheduled[$hook]);
    $cleared[] = $hook;
}

function home_url(string $path = ''): string
{
    return 'https://example.de' . $path;
}

final class LykanShield_License_Status
{
    public static function current(): array
    {
        global $premiumMode;

        return ['premium' => $premiumMode];
    }
}

require_once dirname(__DIR__) . '/includes/class-cron.php';

$schedules = LykanShield_Cron::schedules([]);
assert_true($schedules['lykanshield_hourly']['interval'] === HOUR_IN_SECONDS, 'Free rule interval must be hourly.');
assert_true($schedules['lykanshield_15_minutes']['interval'] === 15 * MINUTE_IN_SECONDS, 'Premium rule interval must be 15 minutes.');
assert_true($schedules['lykanshield_5_minutes']['interval'] === 5 * MINUTE_IN_SECONDS, 'Report queue interval must be 5 minutes.');

LykanShield_Cron::schedule();
assert_true($scheduled[LykanShield_Cron::HOOK_RULE_REFRESH]['schedule'] === 'lykanshield_hourly', 'Free rules must be scheduled hourly.');
assert_true(isset($scheduled[LykanShield_Cron::HOOK_REPORT_QUEUE]), 'Report queue must be scheduled.');
assert_true(isset($scheduled[LykanShield_Cron::HOOK_LICENSE_RENEWAL]), 'License renewal must be scheduled.');
assert_true(isset($scheduled[LykanShield_Cron::HOOK_DAILY_SUMMARY]), 'Daily summary must be scheduled.');
assert_true(isset($scheduled[LykanShield_Cron::HOOK_LOG_RETENTION]), 'Log retention must be scheduled.');

$premiumMode = true;
LykanShield_Cron::reschedule_rules_if_needed();
assert_true($scheduled[LykanShield_Cron::HOOK_RULE_REFRESH]['schedule'] === 'lykanshield_15_minutes', 'Premium rules must be scheduled every 15 minutes.');

LykanShield_Cron::clear();
assert_true(count($scheduled) === 0, 'Cron clear must remove all scheduled hooks.');
assert_true(in_array(LykanShield_Cron::HOOK_RULE_REFRESH, $cleared, true), 'Rule hook must be cleared.');

function assert_true(bool $condition, string $message): void
{
    if (!$condition) {
        fwrite(STDERR, $message . PHP_EOL);
        exit(1);
    }
}

echo "Cron smoke tests passed.\n";
