<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

$actions = [];

function add_action(string $hook, $callback): void
{
    global $actions;
    $actions[$hook] = $callback;
}

function wp_date(string $format, int $timestamp): string
{
    return gmdate($format, $timestamp);
}

require_once LYKANSHIELD_PLUGIN_DIR . 'admin/class-dashboard-widget.php';

LykanShield_Dashboard_Widget::register();
lykanshield_test_assert(
    isset($actions['wp_dashboard_setup']),
    'The dashboard widget must register on wp_dashboard_setup.'
);

$series = LykanShield_Dashboard_Widget::daily_series([
    'data' => [
        ['date' => '2026-07-27 08:00:00', 'count' => 4],
        ['timestamp' => strtotime('2026-07-27 12:00:00 UTC'), 'blocked' => 3],
        '2026-07-28' => 9,
        ['date' => 'invalid', 'count' => 100],
    ],
    'summary' => ['total' => 16],
]);

lykanshield_test_assert(
    $series === ['2026-07-27' => 7, '2026-07-28' => 9],
    'Dashboard event rows must be grouped into daily totals.'
);

echo 'Dashboard widget smoke test passed.' . PHP_EOL;
