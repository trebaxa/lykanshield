<?php

declare(strict_types=1);

defined('ABSPATH') || exit;

final class LykanShield_Security_View
{
    private const FREE_EVENT_LIMIT = 25;
    private const PREMIUM_EVENT_LIMIT = 250;
    private const FREE_ATTACKER_LIMIT = 10;
    private const PREMIUM_ATTACKER_LIMIT = 100;
    private const FREE_ALLOW_BLOCK_LIMIT = 100;
    /**
     * @return array{
     *     stats:array<string,mixed>,
     *     events:array<int,array{time:string,type:string,ip:string,user_agent:string}>,
     *     local_blocks:array<int,array{entry:string,created_at:string,expires_at:int,expires_label:string}>,
     *     attacker_limit:int,
     *     event_limit:int,
     *     history_days:int,
     *     local_retention_days:int,
     *     exports_enabled:bool,
     *     custom_rules_enabled:bool,
     *     webhooks_enabled:bool,
     *     reports_enabled:bool,
     *     countries:array<string,int>,
     *     attack_types:array<string,int>,
     *     premium:bool
     * }
     */
    public static function context(): array
    {
        self::load_core();

        $licenseStatus = LykanShield_License_Status::current();
        $premium = !empty($licenseStatus['premium']);
        self::prune_local_logs($premium);
        $stats = class_exists('lykan', false) && method_exists('lykan', 'read_logs') ? lykan::read_logs() : [];
        $eventLimit = $premium ? self::PREMIUM_EVENT_LIMIT : self::FREE_EVENT_LIMIT;

        return [
            'stats' => self::safe_stats($stats),
            'events' => self::events($stats, $eventLimit),
            'local_blocks' => self::local_blocks(),
            'attacker_limit' => $premium ? self::PREMIUM_ATTACKER_LIMIT : self::FREE_ATTACKER_LIMIT,
            'event_limit' => $eventLimit,
            'history_days' => $premium ? 365 : 1,
            'local_retention_days' => $premium ? 395 : 30,
            'exports_enabled' => $premium,
            'custom_rules_enabled' => $premium,
            'webhooks_enabled' => $premium,
            'reports_enabled' => $premium,
            'countries' => self::country_stats($stats, $premium),
            'attack_types' => self::attack_type_stats($stats, $premium),
            'premium' => $premium,
        ];
    }

    /**
     * @return array{ok:bool,message:string}
     */
    public static function add_local_block(string $entry): array
    {
        self::load_core();
        $entry = self::normalize_ip_or_cidr($entry);

        if ($entry === '') {
            return ['ok' => false, 'message' => 'Enter a valid IP address or CIDR range.'];
        }

        if (!LykanShield_License_Status::current()['premium'] && count(self::local_blocks()) >= self::FREE_ALLOW_BLOCK_LIMIT) {
            return ['ok' => false, 'message' => 'Free allows up to 100 local allow/block entries.'];
        }

        if (!class_exists('lykan', false) || !method_exists('lykan', 'add_ip')) {
            return ['ok' => false, 'message' => 'LykanShield core is not available.'];
        }

        lykan::add_ip($entry);

        return ['ok' => true, 'message' => 'The local block entry was added.'];
    }

    /**
     * @return array{ok:bool,message:string}
     */
    public static function remove_local_block(string $entry): array
    {
        self::load_core();
        $entry = self::normalize_ip_or_cidr($entry);

        if ($entry === '') {
            return ['ok' => false, 'message' => 'Enter a valid IP address or CIDR range.'];
        }

        if (!class_exists('lykan', false) || !method_exists('lykan', 'remove_ip')) {
            return ['ok' => false, 'message' => 'LykanShield core is not available.'];
        }

        return lykan::remove_ip($entry)
            ? ['ok' => true, 'message' => 'The local block entry was removed.']
            : ['ok' => false, 'message' => 'The local block entry was not found.'];
    }

    public static function export(string $format): void
    {
        if (!LykanShield_License_Status::current()['premium']) {
            wp_die(esc_html__('CSV and JSON export requires Premium.', 'lykanshield'));
        }

        $context = self::context();
        if ($format === 'csv') {
            nocache_headers();
            header('Content-Type: text/csv; charset=utf-8');
            header('Content-Disposition: attachment; filename="lykanshield-security-export.csv"');
            $output = fopen('php://output', 'wb');
            if ($output !== false) {
                fputcsv($output, ['time', 'type', 'ip', 'user_agent']);
                foreach ($context['events'] as $event) {
                    fputcsv($output, [$event['time'], $event['type'], $event['ip'], $event['user_agent']]);
                }
            }
            exit;
        }

        $payload = [
            'generated_at' => gmdate('c'),
            'stats' => $context['stats'],
            'events' => $context['events'],
            'local_blocks' => $context['local_blocks'],
            'countries' => $context['countries'],
            'attack_types' => $context['attack_types'],
        ];

        nocache_headers();
        header('Content-Type: application/json; charset=utf-8');
        header('Content-Disposition: attachment; filename="lykanshield-security-export.json"');
        echo wp_json_encode($payload, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        exit;
    }

    /**
     * @param array<string,mixed> $stats
     * @return array<string,mixed>
     */
    private static function safe_stats(array $stats): array
    {
        return [
            'request_count_estimate' => max(0, (int) ($stats['request_count_estimate'] ?? 0)),
            'request_bucket_count' => max(0, (int) ($stats['request_bucket_count'] ?? 0)),
            'statistics_are_approximate' => !empty($stats['statistics_are_approximate']),
        ];
    }

    /**
     * @param array<string,mixed> $stats
     * @return array<int,array{time:string,type:string,ip:string,user_agent:string}>
     */
    private static function events(array $stats, int $limit): array
    {
        $events = [];
        $rows = isset($stats['blocked_bots']) && is_array($stats['blocked_bots']) ? $stats['blocked_bots'] : [];

        foreach ($rows as $row) {
            if (!is_array($row)) {
                continue;
            }

            $events[] = self::event_from_row($row);
        }

        return array_slice(array_reverse($events), 0, $limit);
    }

    /**
     * @return array<int,array{entry:string,created_at:string,expires_at:int,expires_label:string}>
     */
    private static function local_blocks(): array
    {
        self::load_core();

        $entries = self::read_local_block_entries();

        $blocks = [];
        foreach ($entries as $entry => $addedAt) {
            $entry = self::normalize_ip_or_cidr((string) $entry);
            $addedAt = (int) $addedAt;

            if ($entry === '') {
                continue;
            }

            $expiresAt = $addedAt > 0 ? $addedAt + self::local_block_lifetime_seconds() : 0;

            $blocks[] = [
                'entry' => $entry,
                'created_at' => $addedAt > 0 ? gmdate('Y-m-d H:i:s', $addedAt) . ' UTC' : '-',
                'expires_at' => $expiresAt,
                'expires_label' => $expiresAt > 0
                    ? gmdate('Y-m-d H:i:s', $expiresAt) . ' UTC'
                    : 'managed by local retention',
            ];
        }

        return $blocks;
    }

    private static function prune_local_logs(bool $premium): void
    {
        $days = $premium ? 395 : 30;
        $cutoff = time() - ($days * DAY_IN_SECONDS);
        $directory = trailingslashit(WP_CONTENT_DIR) . 'lykan/accesslog';

        if (!is_dir($directory) || !is_readable($directory)) {
            return;
        }

        $iterator = new DirectoryIterator($directory);
        foreach ($iterator as $file) {
            if (!$file->isFile()) {
                continue;
            }

            $name = $file->getFilename();
            if (preg_match('/\A(?:payload_|sql_inject|hacklogblock_|[a-f0-9]{32})/', $name) !== 1) {
                continue;
            }

            if ($file->getMTime() < $cutoff) {
                @unlink($file->getPathname());
            }
        }
    }

    private static function load_core(): void
    {
        if (!class_exists('lykan', false) && is_readable(LYKANSHIELD_PLUGIN_DIR . 'includes/lykan.class.php')) {
            require_once LYKANSHIELD_PLUGIN_DIR . 'includes/lykan.class.php';
        }

        if (class_exists('lykan', false) && method_exists('lykan', 'init')) {
            lykan::init(ABSPATH);
        }
    }

    /**
     * @return array<string,int>
     */
    private static function read_local_block_entries(): array
    {
        if (class_exists('lykan', false) && method_exists('lykan', 'read_local_bad_ip_records')) {
            $records = lykan::read_local_bad_ip_records();
            arsort($records);

            return $records;
        }

        return [];
    }

    private static function local_block_lifetime_seconds(): int
    {
        $values = LykanShield_Core_Config::values();

        return max(1, (int) ($values['local_bad_ip_lifetime_hours'] ?? 720)) * HOUR_IN_SECONDS;
    }

    /**
     * @param array<int,string> $row
     * @return array{time:string,type:string,ip:string,user_agent:string}
     */
    private static function event_from_row(array $row): array
    {
        return [
            'time' => self::short_text((string) ($row[0] ?? '')),
            'type' => self::short_text((string) ($row[2] ?? 'blocked')),
            'ip' => self::short_text((string) ($row[3] ?? '')),
            'user_agent' => self::short_text((string) ($row[1] ?? ''), 120),
        ];
    }

    /**
     * @param array<string,mixed> $stats
     * @return array<string,int>
     */
    private static function country_stats(array $stats, bool $premium): array
    {
        $countries = [];

        foreach (self::events($stats, $premium ? self::PREMIUM_EVENT_LIMIT : self::FREE_EVENT_LIMIT) as $event) {
            $ip = $event['ip'];
            $bucket = strpos($ip, ':') !== false ? 'IPv6/unknown' : 'IPv4/unknown';
            $countries[$bucket] = ($countries[$bucket] ?? 0) + 1;
        }

        arsort($countries);

        return array_slice($countries, 0, $premium ? 20 : 5, true);
    }

    /**
     * @param array<string,mixed> $stats
     * @return array<string,int>
     */
    private static function attack_type_stats(array $stats, bool $premium): array
    {
        $types = [];

        foreach (self::events($stats, $premium ? self::PREMIUM_EVENT_LIMIT : self::FREE_EVENT_LIMIT) as $event) {
            $type = $event['type'] !== '' ? $event['type'] : 'unknown';
            $types[$type] = ($types[$type] ?? 0) + 1;
        }

        arsort($types);

        return array_slice($types, 0, $premium ? 20 : 5, true);
    }

    private static function normalize_ip_or_cidr(string $entry): string
    {
        $entry = trim($entry);

        if ($entry === '') {
            return '';
        }

        if (filter_var($entry, FILTER_VALIDATE_IP) !== false) {
            return $entry;
        }

        if (preg_match('/\A(.+)\/([0-9]{1,3})\z/', $entry, $matches) !== 1) {
            return '';
        }

        $ip = (string) $matches[1];
        $prefix = (int) $matches[2];

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false && $prefix >= 0 && $prefix <= 32) {
            return $ip . '/' . $prefix;
        }

        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false && $prefix >= 0 && $prefix <= 128) {
            return $ip . '/' . $prefix;
        }

        return '';
    }

    private static function short_text(string $value, int $limit = 80): string
    {
        $value = preg_replace('/(?:access_?token|api_?key|authorization|cookie|password|secret|token)=([^&\s]+)/i', '$1=[redacted]', $value) ?? $value;
        $value = trim(wp_strip_all_tags($value));

        return strlen($value) > $limit ? substr($value, 0, $limit - 3) . '...' : $value;
    }
}
