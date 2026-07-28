<?php

declare(strict_types=1);

defined('ABSPATH') || exit;

final class LykanShield_Dashboard_Widget
{
    private const CACHE_KEY = 'lykanshield_dashboard_lock_data';
    private const HISTORY_DAYS = 31;
    private const EVENT_LIMIT = 250;

    public static function register(): void
    {
        add_action('wp_dashboard_setup', [self::class, 'add_widget']);
    }

    public static function add_widget(): void
    {
        if (!current_user_can('manage_options')) {
            return;
        }

        wp_add_dashboard_widget(
            'lykanshield_dashboard_widget',
            __('LykanShield security', 'lykanshield'),
            [self::class, 'render']
        );
    }

    public static function render(): void
    {
        $response = self::lock_data();

        echo '<style>
            #lykanshield_dashboard_widget .inside{margin:0;padding:0}
            .lykan-dashboard{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#17202b}
            .lykan-dashboard__header{display:flex;align-items:center;justify-content:space-between;padding:20px 22px;background:linear-gradient(120deg,#fff 65%,#fff3f8);border-bottom:1px solid #e2e8f0}
            .lykan-dashboard__brand{display:flex;align-items:center;gap:12px}.lykan-dashboard__mark{display:block;width:46px;height:46px;object-fit:contain}
            .lykan-dashboard__brand strong{display:block;font-size:21px}.lykan-dashboard__brand small{color:#66758a}
            .lykan-dashboard__body{padding:20px 22px}.lykan-dashboard__stats{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-bottom:22px}
            .lykan-dashboard__stat{padding:12px;border:1px solid #e2e8f0;border-radius:9px;background:#f8fafc}.lykan-dashboard__stat strong{display:block;font-size:23px}.lykan-dashboard__stat span{font-size:12px;color:#66758a}
            .lykan-dashboard__title{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px}.lykan-dashboard__title strong{font-size:15px}.lykan-dashboard__title span{font-size:12px;color:#66758a}
            .lykan-dashboard__chart{display:flex;align-items:flex-end;gap:3px;height:130px;padding:10px 5px 22px;border-bottom:1px solid #dbe2ea;background:repeating-linear-gradient(to bottom,#fff 0,#fff 32px,#eef2f6 33px)}
            .lykan-dashboard__bar{position:relative;flex:1;min-width:3px;height:var(--height);background:linear-gradient(#dc1370,#970041);border-radius:3px 3px 0 0}.lykan-dashboard__bar:hover:after{content:attr(data-label);position:absolute;bottom:calc(100% + 5px);left:50%;transform:translateX(-50%);z-index:2;white-space:nowrap;padding:4px 6px;border-radius:4px;background:#17202b;color:#fff;font-size:11px}
            .lykan-dashboard__empty{padding:25px;border:1px dashed #cbd5e1;border-radius:9px;text-align:center;color:#66758a}.lykan-dashboard__empty strong{display:block;color:#17202b;margin-bottom:5px}
            .lykan-dashboard__footer{display:flex;justify-content:space-between;padding:12px 22px;border-top:1px solid #e2e8f0;font-size:12px;color:#66758a}
            @media(max-width:600px){.lykan-dashboard__stats{grid-template-columns:1fr}.lykan-dashboard__header{align-items:flex-start}}
        </style>';

        echo '<div class="lykan-dashboard">';
        echo '<div class="lykan-dashboard__header"><div class="lykan-dashboard__brand"><img class="lykan-dashboard__mark" src="' . esc_url(LYKANSHIELD_PLUGIN_URL . 'assets/images/logo.svg') . '" alt="' . esc_attr__('LykanShield logo', 'lykanshield') . '"><div><strong>LykanShield</strong><small>' . esc_html__('Detected and blocked attacks on your website', 'lykanshield') . '</small></div></div>';
        echo '<a href="' . esc_url(admin_url('options-general.php?page=lykanshield')) . '">' . esc_html__('Details', 'lykanshield') . '</a></div>';
        echo '<div class="lykan-dashboard__body">';

        if ($response === null) {
            echo '<div class="lykan-dashboard__empty"><strong>' . esc_html__('Security data is currently unavailable', 'lykanshield') . '</strong>' . esc_html__('LykanShield could not load the analytics data. Please try again later.', 'lykanshield') . '</div>';
        } else {
            $series = self::daily_series($response);
            $total = self::summary_number($response, ['total', 'count', 'blocked', 'attacks'], array_sum($series));
            $today = $series !== [] ? (int) end($series) : 0;
            $maximum = max(1, $series !== [] ? max($series) : 0);

            echo '<div class="lykan-dashboard__stats">';
            self::render_stat($total, __('Blocked attacks', 'lykanshield'));
            self::render_stat($today, __('Today', 'lykanshield'));
            self::render_stat(count($series), __('Days evaluated', 'lykanshield'));
            echo '</div>';
            echo '<div class="lykan-dashboard__title"><strong>' . esc_html__('Attack history', 'lykanshield') . '</strong><span>' . esc_html(sprintf(__('Last %d days', 'lykanshield'), self::HISTORY_DAYS)) . '</span></div>';

            if (array_sum($series) === 0) {
                echo '<div class="lykan-dashboard__empty"><strong>' . esc_html__('No attacks recorded', 'lykanshield') . '</strong>' . esc_html__('New LykanShield events will automatically appear here.', 'lykanshield') . '</div>';
            } else {
                echo '<div class="lykan-dashboard__chart" role="img" aria-label="' . esc_attr__('Blocked attacks by day', 'lykanshield') . '">';
                foreach ($series as $date => $count) {
                    $height = max(2, (int) round(((int) $count / $maximum) * 100));
                    $label = sprintf('%s: %s', $date, number_format_i18n((int) $count));
                    echo '<span class="lykan-dashboard__bar" style="--height:' . esc_attr((string) $height) . '%" data-label="' . esc_attr($label) . '"></span>';
                }
                echo '</div>';
            }
        }

        echo '</div><div class="lykan-dashboard__footer"><span>' . esc_html__('Protection data from LykanShield', 'lykanshield') . '</span><a href="https://lykanshield.io" target="_blank" rel="noopener noreferrer">lykanshield.io</a></div></div>';
    }

    /**
     * Load analytics through the Lykan core and cache successful responses briefly.
     *
     * @return array<string,mixed>|null
     */
    public static function lock_data(): ?array
    {
        $cached = get_transient(self::CACHE_KEY);
        if (is_array($cached)) {
            return $cached;
        }

        if (!class_exists('lykan', false)) {
            $core = LYKANSHIELD_PLUGIN_DIR . 'includes/lykan.class.php';
            if (!is_readable($core)) {
                return null;
            }
            require_once $core;
        }

        if (method_exists('lykan', 'init')) {
            lykan::init(ABSPATH);
        }

        if (!method_exists('lykan', 'get_lock')) {
            return null;
        }

        $response = lykan::get_lock(self::HISTORY_DAYS, self::EVENT_LIMIT);
        if (!is_array($response)) {
            return null;
        }

        set_transient(self::CACHE_KEY, $response, 5 * MINUTE_IN_SECONDS);

        return $response;
    }

    /**
     * @param array<string,mixed> $response
     * @return array<string,int>
     */
    public static function daily_series(array $response): array
    {
        $series = [];
        $rows = isset($response['data']) && is_array($response['data']) ? $response['data'] : [];

        foreach ($rows as $key => $row) {
            $dateValue = is_string($key) ? $key : '';
            $count = is_numeric($row) ? (int) $row : 0;

            if (is_array($row)) {
                foreach (['date', 'day', 'time', 'timestamp', 'created_at'] as $dateKey) {
                    if (isset($row[$dateKey]) && (is_string($row[$dateKey]) || is_numeric($row[$dateKey]))) {
                        $dateValue = (string) $row[$dateKey];
                        break;
                    }
                }
                foreach (['count', 'total', 'value', 'blocked', 'attacks'] as $countKey) {
                    if (isset($row[$countKey]) && is_numeric($row[$countKey])) {
                        $count = (int) $row[$countKey];
                        break;
                    }
                }
            }

            $timestamp = is_numeric($dateValue) ? (int) $dateValue : strtotime($dateValue);
            if ($timestamp === false || $timestamp <= 0) {
                continue;
            }

            $day = wp_date('Y-m-d', $timestamp);
            $series[$day] = ($series[$day] ?? 0) + max(0, $count);
        }

        ksort($series);

        return array_slice($series, -self::HISTORY_DAYS, null, true);
    }

    private static function render_stat(int $value, string $label): void
    {
        echo '<div class="lykan-dashboard__stat"><strong>' . esc_html(number_format_i18n(max(0, $value))) . '</strong><span>' . esc_html($label) . '</span></div>';
    }

    /**
     * @param array<string,mixed> $response
     * @param string[] $keys
     */
    private static function summary_number(array $response, array $keys, int $fallback): int
    {
        $summary = isset($response['summary']) && is_array($response['summary']) ? $response['summary'] : [];
        foreach ($keys as $key) {
            if (isset($summary[$key]) && is_numeric($summary[$key])) {
                return max(0, (int) $summary[$key]);
            }
        }

        return max(0, $fallback);
    }
}
