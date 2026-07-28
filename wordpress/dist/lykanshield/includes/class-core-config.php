<?php

declare(strict_types=1);

defined('ABSPATH') || exit;

final class LykanShield_Core_Config
{
    private const CONFIG_VERSION = 1;

    /**
     * @return array<string,mixed>
     */
    public static function defaults(): array
    {
        return [
            'api_key' => '',
            'notification_email' => '',
            'rules_unavailable_action' => 'monitor',
            'sql_injection_block_score' => 3,
            'log_lines_count' => 100,
            'local_bad_ip_lifetime_hours' => 720,
            'local_bad_ip_max_entries' => 5000,
            'report_queue_max_entries' => 1000,
            'request_inspection_max_bytes' => 8192,
        ];
    }

    /**
     * @return array<string,mixed>
     */
    public static function values(): array
    {
        $saved = get_option(LykanShield_Settings::OPTION_CORE_CONFIG, []);
        $values = self::defaults();

        if (!is_array($saved)) {
            return $values;
        }

        foreach ($values as $key => $default) {
            if (array_key_exists($key, $saved)) {
                $values[$key] = self::sanitize_value($key, $saved[$key]);
            }
        }

        return $values;
    }

    /**
     * @param array<string,mixed> $input
     * @return array<string,mixed>
     */
    public static function sanitize(array $input): array
    {
        $values = self::defaults();

        foreach ($values as $key => $default) {
            if (array_key_exists($key, $input)) {
                $values[$key] = self::sanitize_value($key, $input[$key]);
            }
        }

        return $values;
    }

    public static function ensure_written(): bool
    {
        self::ensure_data_directories();

        $config = self::build();
        $path = self::config_path();
        $previous = self::read_json_file($path);
        $json = wp_json_encode($config, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

        if (!is_string($json)) {
            self::log_runtime_error('Unable to encode LykanShield core configuration.');
            return false;
        }

        if (is_array($previous) && $previous == $config) {
            return true;
        }

        $tmp = $path . '.' . getmypid() . '.tmp';
        $written = file_put_contents($tmp, $json . "\n", LOCK_EX);

        if ($written === false) {
            self::log_runtime_error('Unable to write temporary LykanShield core configuration.');
            return false;
        }

        if (!@chmod($tmp, 0640)) {
            self::log_runtime_error('Unable to set permissions on temporary LykanShield core configuration.');
        }

        if (!@rename($tmp, $path)) {
            @unlink($tmp);
            self::log_runtime_error('Unable to replace LykanShield core configuration atomically.');
            return false;
        }

        self::log_config_changes(is_array($previous) ? $previous : [], $config);

        return true;
    }

    public static function migrate_existing_config(): void
    {
        $existing = self::read_json_file(self::config_path());

        if (!is_array($existing)) {
            return;
        }

        $current = get_option(LykanShield_Settings::OPTION_CORE_CONFIG, null);

        if (is_array($current)) {
            return;
        }

        $migrated = [];

        if (isset($existing['apikey']) && is_string($existing['apikey'])) {
            $migrated['api_key'] = $existing['apikey'];
        }

        if (isset($existing['email']) && is_string($existing['email'])) {
            $migrated['notification_email'] = $existing['email'];
        }

        foreach (self::defaults() as $key => $default) {
            if (array_key_exists($key, $existing)) {
                $migrated[$key] = $existing[$key];
            }
        }

        if ($migrated !== []) {
            update_option(LykanShield_Settings::OPTION_CORE_CONFIG, self::sanitize($migrated), false);
            self::append_audit_line('migrated existing config keys: ' . implode(', ', array_keys($migrated)));
        }
    }

    public static function config_path(): string
    {
        return trailingslashit(self::data_dir()) . 'config.json';
    }

    public static function data_dir(): string
    {
        return trailingslashit(WP_CONTENT_DIR) . 'lykan';
    }

    /**
     * @return array<string,mixed>
     */
    public static function build(): array
    {
        $core = self::values();
        $filters = LykanShield_Settings::filters();
        $domainContext = LykanShield_License_Client::domain_context();
        $host = self::safe_host_segment((string) $domainContext['registrable_domain']);
        $root = trailingslashit(self::data_dir());
        $accessLogPath = $root . 'accesslog/';

        return [
            'config_version' => self::CONFIG_VERSION,
            'apikey' => $core['api_key'],
            'email' => $core['notification_email'],
            'trusted_proxies' => self::trusted_proxy_list(),
            'rules_unavailable_action' => $core['rules_unavailable_action'],
            'sql_injection_block_score' => $core['sql_injection_block_score'],
            'log_lines_count' => $core['log_lines_count'],
            'local_bad_ip_lifetime_hours' => $core['local_bad_ip_lifetime_hours'],
            'local_bad_ip_max_entries' => $core['local_bad_ip_max_entries'],
            'report_queue_max_entries' => $core['report_queue_max_entries'],
            'request_inspection_max_bytes' => $core['request_inspection_max_bytes'],
            'root' => $root,
            'hpath' => $accessLogPath,
            'lykan_blocked_file' => $root . 'hacklogblock_' . $host . '.txt',
            'lykan_blacklist' => $root . 'blacklist.json',
            'badips_file' => $root . 'badips_' . $host . '.txt',
            'badbots_file' => $root . 'badbots_' . $host . '.txt',
            'filter_active' => [
                'mime_types' => !empty($filters['upload_mime_protection']),
                'file_inject' => !empty($filters['upload_mime_protection']),
                'bad_bots' => !empty($filters['bad_ip_bot_protection']),
                'bad_user_post' => false,
                'bad_ips' => !empty($filters['bad_ip_bot_protection']),
                'sql_injection' => !empty($filters['sql_protection']),
                'worm_injection' => !empty($filters['xss_protection']),
                'exploit' => !empty($filters['exploit_protection']),
                'payloadlog' => false,
            ],
        ];
    }

    public static function ensure_data_directories(): bool
    {
        $ok = true;

        foreach ([self::data_dir(), trailingslashit(self::data_dir()) . 'accesslog'] as $directory) {
            if (!is_dir($directory) && !wp_mkdir_p($directory)) {
                self::log_runtime_error('Unable to create LykanShield directory: ' . $directory);
                $ok = false;
                continue;
            }

            if (is_dir($directory) && !is_writable($directory)) {
                self::log_runtime_error('LykanShield directory is not writable: ' . $directory);
                $ok = false;
            }
        }

        return $ok;
    }

    /**
     * @return array<int,string>
     */
    private static function trusted_proxy_list(): array
    {
        $trustedProxies = LykanShield_Settings::trusted_proxies();

        if ($trustedProxies === '') {
            return [];
        }

        return preg_split('/\R+/', $trustedProxies) ?: [];
    }

    private static function sanitize_value(string $key, mixed $value): mixed
    {
        return match ($key) {
            'api_key' => self::sanitize_api_key((string) $value),
            'notification_email' => is_email((string) $value) ? sanitize_email((string) $value) : '',
            'rules_unavailable_action' => in_array((string) $value, ['monitor', 'block'], true) ? (string) $value : 'monitor',
            'sql_injection_block_score' => self::bounded_int($value, 2, 10, 3),
            'log_lines_count' => self::bounded_int($value, 20, 1000, 100),
            'local_bad_ip_lifetime_hours' => self::bounded_int($value, 1, 9500, 720),
            'local_bad_ip_max_entries' => self::bounded_int($value, 100, 100000, 5000),
            'report_queue_max_entries' => self::bounded_int($value, 100, 50000, 1000),
            'request_inspection_max_bytes' => self::bounded_int($value, 1024, 65536, 8192),
            default => self::defaults()[$key] ?? null,
        };
    }

    private static function sanitize_api_key(string $value): string
    {
        $value = trim($value);

        if ($value === '') {
            return '';
        }

        return preg_match('/\A[A-Za-z0-9._:-]{8,128}\z/', $value) === 1 ? $value : '';
    }

    private static function bounded_int(mixed $value, int $min, int $max, int $default): int
    {
        if (!is_numeric($value)) {
            return $default;
        }

        return max($min, min($max, (int) $value));
    }

    private static function safe_host_segment(string $host): string
    {
        $host = strtolower($host);
        $host = preg_replace('/[^a-z0-9.-]+/', '-', $host);

        return trim((string) $host, '.-') !== '' ? trim((string) $host, '.-') : 'wordpress';
    }

    /**
     * @return array<string,mixed>|null
     */
    private static function read_json_file(string $path): ?array
    {
        if (!is_file($path) || !is_readable($path)) {
            return null;
        }

        $json = file_get_contents($path);

        if (!is_string($json)) {
            return null;
        }

        $decoded = json_decode($json, true);

        return is_array($decoded) ? $decoded : null;
    }

    /**
     * @param array<string,mixed> $previous
     * @param array<string,mixed> $current
     */
    private static function log_config_changes(array $previous, array $current): void
    {
        $changed = [];

        foreach ($current as $key => $value) {
            if (!array_key_exists($key, $previous) || $previous[$key] !== $value) {
                $changed[] = $key;
            }
        }

        if ($changed === []) {
            return;
        }

        self::append_audit_line('updated config keys: ' . implode(', ', $changed));
    }

    private static function append_audit_line(string $message): void
    {
        $line = gmdate('c') . ' ' . $message . "\n";
        @file_put_contents(trailingslashit(self::data_dir()) . 'config-audit.log', $line, FILE_APPEND | LOCK_EX);
    }

    private static function log_runtime_error(string $message): void
    {
        error_log('LykanShield: ' . $message);
    }
}
