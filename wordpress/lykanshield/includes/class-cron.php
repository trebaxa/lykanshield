<?php

declare(strict_types=1);

defined('ABSPATH') || exit;

final class LykanShield_Cron
{
    public const HOOK_RULE_REFRESH = 'lykanshield_refresh_rules';
    public const HOOK_REPORT_QUEUE = 'lykanshield_flush_report_queue';
    public const HOOK_LICENSE_RENEWAL = 'lykanshield_renew_license';
    public const HOOK_DAILY_SUMMARY = 'lykanshield_daily_summary';
    public const HOOK_LOG_RETENTION = 'lykanshield_prune_local_logs';

    private const SCHEDULE_RULES_FREE = 'lykanshield_hourly';
    private const SCHEDULE_RULES_PREMIUM = 'lykanshield_15_minutes';
    private const SCHEDULE_REPORT_QUEUE = 'lykanshield_5_minutes';
    private const LOCK_TTL_SECONDS = 300;

    public static function register(): void
    {
        add_filter('cron_schedules', [self::class, 'schedules']);
        add_action(self::HOOK_RULE_REFRESH, [self::class, 'refresh_rules']);
        add_action(self::HOOK_REPORT_QUEUE, [self::class, 'flush_report_queue']);
        add_action(self::HOOK_LICENSE_RENEWAL, [self::class, 'renew_license']);
        add_action(self::HOOK_DAILY_SUMMARY, [self::class, 'send_daily_summary']);
        add_action(self::HOOK_LOG_RETENTION, [self::class, 'prune_local_logs']);
    }

    /**
     * @param array<string,array{interval:int,display:string}> $schedules
     * @return array<string,array{interval:int,display:string}>
     */
    public static function schedules(array $schedules): array
    {
        $schedules[self::SCHEDULE_RULES_FREE] = [
            'interval' => HOUR_IN_SECONDS,
            'display' => __('LykanShield hourly', 'lykanshield'),
        ];
        $schedules[self::SCHEDULE_RULES_PREMIUM] = [
            'interval' => 15 * MINUTE_IN_SECONDS,
            'display' => __('LykanShield every 15 minutes', 'lykanshield'),
        ];
        $schedules[self::SCHEDULE_REPORT_QUEUE] = [
            'interval' => 5 * MINUTE_IN_SECONDS,
            'display' => __('LykanShield every 5 minutes', 'lykanshield'),
        ];

        return $schedules;
    }

    public static function schedule(): void
    {
        self::register();
        $ruleSchedule = self::rule_refresh_schedule();

        if (!wp_next_scheduled(self::HOOK_RULE_REFRESH)) {
            wp_schedule_event(time() + MINUTE_IN_SECONDS, $ruleSchedule, self::HOOK_RULE_REFRESH);
        }

        if (!wp_next_scheduled(self::HOOK_REPORT_QUEUE)) {
            wp_schedule_event(time() + 5 * MINUTE_IN_SECONDS, self::SCHEDULE_REPORT_QUEUE, self::HOOK_REPORT_QUEUE);
        }

        if (!wp_next_scheduled(self::HOOK_LICENSE_RENEWAL)) {
            wp_schedule_event(time() + DAY_IN_SECONDS, 'daily', self::HOOK_LICENSE_RENEWAL);
        }

        if (!wp_next_scheduled(self::HOOK_DAILY_SUMMARY)) {
            wp_schedule_event(time() + DAY_IN_SECONDS, 'daily', self::HOOK_DAILY_SUMMARY);
        }

        if (!wp_next_scheduled(self::HOOK_LOG_RETENTION)) {
            wp_schedule_event(time() + DAY_IN_SECONDS, 'daily', self::HOOK_LOG_RETENTION);
        }
    }

    public static function clear(): void
    {
        wp_clear_scheduled_hook(self::HOOK_RULE_REFRESH);
        wp_clear_scheduled_hook(self::HOOK_REPORT_QUEUE);
        wp_clear_scheduled_hook(self::HOOK_LICENSE_RENEWAL);
        wp_clear_scheduled_hook(self::HOOK_DAILY_SUMMARY);
        wp_clear_scheduled_hook(self::HOOK_LOG_RETENTION);
    }

    public static function reschedule_rules_if_needed(): void
    {
        wp_clear_scheduled_hook(self::HOOK_RULE_REFRESH);
        wp_schedule_event(time() + MINUTE_IN_SECONDS, self::rule_refresh_schedule(), self::HOOK_RULE_REFRESH);
    }

    public static function refresh_rules(): void
    {
        self::run_locked(self::HOOK_RULE_REFRESH, static function (): void {
            self::load_lykan();
            $ok = lykan::refresh_rules(ABSPATH);
            self::store_backoff(self::HOOK_RULE_REFRESH, $ok);
        });
    }

    public static function flush_report_queue(): void
    {
        self::run_locked(self::HOOK_REPORT_QUEUE, static function (): void {
            self::load_lykan();
            lykan::flush_report_queue(20);
            self::send_premium_webhook();
        });
    }

    public static function renew_license(): void
    {
        self::run_locked(self::HOOK_LICENSE_RENEWAL, static function (): void {
            $result = LykanShield_License_Client::renew();
            self::store_backoff(self::HOOK_LICENSE_RENEWAL, !empty($result['ok']));
        });
    }

    public static function send_daily_summary(): void
    {
        $status = LykanShield_License_Status::current();
        if (!empty($status['premium'])) {
            self::send_premium_report();
            return;
        }

        $email = get_option('admin_email');
        if (!is_string($email) || !is_email($email)) {
            return;
        }

        $subject = __('LykanShield daily security summary', 'lykanshield');
        $message = __('Free protection is active. Review the LykanShield dashboard for recent local events.', 'lykanshield');
        wp_mail($email, $subject, $message);
    }

    private static function send_premium_webhook(): void
    {
        if (empty(LykanShield_License_Status::current()['premium'])) {
            return;
        }

        $automation = LykanShield_Settings::automation();
        if ($automation['webhook_url'] === '') {
            return;
        }

        wp_remote_post($automation['webhook_url'], [
            'timeout' => 5,
            'headers' => ['Content-Type' => 'application/json'],
            'body' => wp_json_encode([
                'event' => 'lykanshield.report_queue_flushed',
                'site' => home_url(),
                'generated_at' => gmdate('c'),
            ]),
        ]);
    }

    private static function send_premium_report(): void
    {
        $automation = LykanShield_Settings::automation();
        if ($automation['report_frequency'] === 'none') {
            return;
        }

        $email = $automation['report_email'] !== '' ? $automation['report_email'] : get_option('admin_email');
        if (!is_string($email) || !is_email($email)) {
            return;
        }

        $lastSent = (int) get_option('lykanshield_premium_report_last_sent', 0);
        $interval = match ($automation['report_frequency']) {
            'monthly' => 30 * DAY_IN_SECONDS,
            'weekly' => 7 * DAY_IN_SECONDS,
            default => DAY_IN_SECONDS,
        };

        if ($lastSent > 0 && (time() - $lastSent) < $interval) {
            return;
        }

        wp_mail(
            $email,
            __('LykanShield Premium security report', 'lykanshield'),
            __('Your Premium security report is ready in the LykanShield dashboard.', 'lykanshield')
        );
        update_option('lykanshield_premium_report_last_sent', (string) time(), false);
    }

    public static function prune_local_logs(): void
    {
        if (class_exists('LykanShield_Security_View')) {
            LykanShield_Security_View::context();
        }
    }

    public static function wp_cron_warning(): string
    {
        return defined('DISABLE_WP_CRON') && DISABLE_WP_CRON
            ? __('DISABLE_WP_CRON is active. Configure a real system cron to call wp-cron.php regularly.', 'lykanshield')
            : '';
    }

    public static function system_cron_hint(): string
    {
        return '*/5 * * * * curl -fsS ' . home_url('/wp-cron.php?doing_wp_cron') . ' >/dev/null 2>&1';
    }

    private static function rule_refresh_schedule(): string
    {
        return !empty(LykanShield_License_Status::current()['premium'])
            ? self::SCHEDULE_RULES_PREMIUM
            : self::SCHEDULE_RULES_FREE;
    }

    private static function run_locked(string $name, callable $callback): void
    {
        if (self::backoff_active($name)) {
            return;
        }

        $lock = '_transient_lykanshield_lock_' . md5($name);
        if (get_transient($lock) !== false) {
            return;
        }

        set_transient($lock, '1', self::LOCK_TTL_SECONDS);

        try {
            $callback();
        } finally {
            delete_transient($lock);
        }
    }

    private static function backoff_active(string $name): bool
    {
        $until = (int) get_option('lykanshield_backoff_' . md5($name), 0);

        return $until > time();
    }

    private static function store_backoff(string $name, bool $ok): void
    {
        $option = 'lykanshield_backoff_' . md5($name);

        if ($ok) {
            delete_option($option);
            return;
        }

        update_option($option, (string) (time() + 15 * MINUTE_IN_SECONDS), false);
    }

    private static function load_lykan(): void
    {
        if (!class_exists('lykan', false)) {
            require_once LYKANSHIELD_PLUGIN_DIR . 'includes/lykan.class.php';
        }

        lykan::init(ABSPATH);
    }
}
