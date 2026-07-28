<?php

declare(strict_types=1);

defined('ABSPATH') || exit;

final class LykanShield_License_Client
{
    public const API_VERSION = '2026-07-27';
    public const DEFAULT_API_BASE = 'https://license.lykanshield.com/v1';
    public const TIMEOUT_SECONDS = 5;
    public const MAX_RESPONSE_BYTES = 65536;
    public const RATE_LIMIT_ACTIVATION_ATTEMPTS = 5;
    public const RATE_LIMIT_WINDOW_SECONDS = 900;
    private const NONCE_TTL_SECONDS = 600;

    public const ENDPOINTS = [
        'activate' => '/licenses/activate',
        'renew' => '/licenses/renew',
        'status' => '/licenses/status',
        'deactivate' => '/licenses/deactivate',
    ];

    public const ERROR_INVALID = 'license_invalid';
    public const ERROR_EXPIRED = 'license_expired';
    public const ERROR_REVOKED = 'license_revoked';
    public const ERROR_ALREADY_USED = 'license_already_used';
    public const ERROR_DOMAIN_MISMATCH = 'license_domain_mismatch';
    public const ERROR_RATE_LIMITED = 'rate_limited';
    public const ERROR_SERVER_UNAVAILABLE = 'server_unavailable';

    /**
     * @return array{
     *     home_host:string,
     *     site_host:string,
     *     request_host:string,
     *     canonical_host:string,
     *     registrable_domain:string,
     *     host_header_matches:bool,
     *     warnings:string[]
     * }
     */
    public static function domain_context(): array
    {
        return LykanShield_Domain_Resolver::current();
    }

    /**
     * @return array{
     *     api_version:string,
     *     license_key:string,
     *     canonical_domain:string,
     *     registrable_domain:string,
     *     installation_id:string,
     *     plugin_version:string,
     *     wordpress_version:string,
     *     php_version:string
     * }
     */
    public static function activation_payload(string $licenseKey): array
    {
        $domainContext = self::domain_context();

        return [
            'api_version' => self::API_VERSION,
            'license_key' => trim($licenseKey),
            'request_nonce' => self::request_nonce('activate'),
            'canonical_domain' => $domainContext['canonical_host'],
            'registrable_domain' => $domainContext['registrable_domain'],
            'installation_id' => LykanShield_Settings::installation_id(),
            'plugin_version' => LYKANSHIELD_VERSION,
            'wordpress_version' => get_bloginfo('version'),
            'php_version' => PHP_VERSION,
        ];
    }

    /**
     * @return array{
     *     api_version:string,
     *     installation_id:string,
     *     canonical_domain:string,
     *     registrable_domain:string,
     *     plugin_version:string,
     *     wordpress_version:string,
     *     php_version:string
     * }
     */
    public static function license_context_payload(): array
    {
        $domainContext = self::domain_context();

        return [
            'api_version' => self::API_VERSION,
            'request_nonce' => self::request_nonce('context'),
            'installation_id' => LykanShield_Settings::installation_id(),
            'canonical_domain' => $domainContext['canonical_host'],
            'registrable_domain' => $domainContext['registrable_domain'],
            'plugin_version' => LYKANSHIELD_VERSION,
            'wordpress_version' => get_bloginfo('version'),
            'php_version' => PHP_VERSION,
        ];
    }

    public static function endpoint_url(string $name): string
    {
        $path = self::ENDPOINTS[$name] ?? '';

        if ($path === '') {
            return '';
        }

        $base = rtrim((string) apply_filters('lykanshield_license_api_base', self::DEFAULT_API_BASE), '/');
        if (!self::is_allowed_https_url($base)) {
            return '';
        }

        return $base . $path;
    }

    /**
     * @return array<string,mixed>
     */
    public static function http_args(array $payload): array
    {
        return [
            'timeout' => self::TIMEOUT_SECONDS,
            'redirection' => 0,
            'limit_response_size' => self::MAX_RESPONSE_BYTES,
            'headers' => [
                'Accept' => 'application/json',
                'Content-Type' => 'application/json',
                'X-LykanShield-API-Version' => self::API_VERSION,
            ],
            'body' => wp_json_encode($payload, JSON_UNESCAPED_SLASHES),
        ];
    }

    /**
     * @return array{ok:bool,message:string,token:string}
     */
    public static function activate(string $licenseKey): array
    {
        $licenseKey = trim($licenseKey);

        if ($licenseKey === '') {
            return [
                'ok' => false,
                'message' => 'Enter a license key before activating Premium.',
                'token' => '',
            ];
        }

        return self::request_token('activate', self::activation_payload($licenseKey));
    }

    /**
     * @return array{ok:bool,message:string,token:string}
     */
    public static function renew(): array
    {
        return self::request_token('renew', self::license_context_payload());
    }

    /**
     * @return array{ok:bool,message:string,token:string}
     */
    public static function status(): array
    {
        return self::request_token('status', self::license_context_payload());
    }

    /**
     * @return array{ok:bool,message:string,token:string}
     */
    public static function deactivate(): array
    {
        $result = self::request_token('deactivate', self::license_context_payload());

        if ($result['ok'] || $result['message'] !== '') {
            if (class_exists('LykanShield_Multisite')) {
                LykanShield_Multisite::save_license_key_for_current_domain('');
                LykanShield_Multisite::save_token_for_current_domain('');
            } else {
                LykanShield_Settings::update_license_key('');
                LykanShield_Settings::update_license_token('');
            }
        }

        return [
            'ok' => true,
            'message' => $result['ok'] ? $result['message'] : 'Premium was removed locally. Free protection remains active.',
            'token' => '',
        ];
    }

    /**
     * @param array<string,mixed> $payload
     * @return array{ok:bool,message:string,token:string}
     */
    private static function request_token(string $endpoint, array $payload): array
    {
        $url = self::endpoint_url($endpoint);
        if ($url === '') {
            return self::license_error('License API endpoint must use HTTPS.', 'invalid_endpoint');
        }

        self::audit('request_started', ['endpoint' => $endpoint]);
        $response = wp_safe_remote_post($url, self::http_args($payload));

        if (is_wp_error($response)) {
            self::license_error($response->get_error_message(), 'transport_error');

            return [
                'ok' => false,
                'message' => 'The license server is unavailable. Free protection remains active.',
                'token' => '',
            ];
        }

        $statusCode = (int) wp_remote_retrieve_response_code($response);
        $body = (string) wp_remote_retrieve_body($response);
        if (strlen($body) > self::MAX_RESPONSE_BYTES) {
            return self::license_error('License server response exceeded the configured size limit.', 'response_too_large');
        }

        $decoded = json_decode($body, true);

        if (!self::valid_response($decoded)) {
            return self::license_error('The license server returned an invalid response.', 'invalid_response');
        }

        if ($statusCode < 200 || $statusCode >= 300) {
            $message = isset($decoded['message']) && is_string($decoded['message'])
                ? $decoded['message']
                : 'The license server rejected the request. Free protection remains active.';

            self::license_error($message, 'server_rejected');

            return [
                'ok' => false,
                'message' => $message,
                'token' => '',
            ];
        }

        $token = isset($decoded['token']) && is_string($decoded['token']) ? trim($decoded['token']) : '';

        if ($token !== '') {
            if (class_exists('LykanShield_Multisite')) {
                LykanShield_Multisite::save_token_for_current_domain($token);
                LykanShield_Multisite::remember_current_domain();
            } else {
                LykanShield_Settings::update_license_token($token);
            }
        }

        delete_option(LykanShield_Settings::OPTION_LICENSE_LAST_ERROR);
        self::audit('request_completed', ['endpoint' => $endpoint, 'status_code' => $statusCode]);

        return [
            'ok' => true,
            'message' => isset($decoded['message']) && is_string($decoded['message']) ? $decoded['message'] : 'License request completed.',
            'token' => $token,
        ];
    }

    /**
     * @param array<string,mixed>|string $value
     *
     * @return array<string,mixed>|string
     */
    public static function redact_license_key(array|string $value): array|string
    {
        if (is_string($value)) {
            return self::redact_string($value);
        }

        foreach ($value as $key => $item) {
            if (is_array($item)) {
                $value[$key] = self::redact_license_key($item);
                continue;
            }

            if (!is_string($item)) {
                continue;
            }

            $keyName = strtolower((string) $key);
            $value[$key] = str_contains($keyName, 'license') || str_contains($keyName, 'key')
                ? '[redacted]'
                : self::redact_string($item);
        }

        return $value;
    }

    private static function redact_string(string $value): string
    {
        return preg_replace('/LS-[A-Z0-9-]{8,}/i', 'LS-[redacted]', $value) ?? $value;
    }

    private static function is_allowed_https_url(string $url): bool
    {
        $parts = wp_parse_url($url);

        if (!is_array($parts)
            || ($parts['scheme'] ?? '') !== 'https'
            || !isset($parts['host'])
            || !is_string($parts['host'])
            || $parts['host'] === '') {
            return false;
        }

        $host = strtolower((string) ($parts['host'] ?? ''));
        $defaultHost = strtolower((string) (wp_parse_url(self::DEFAULT_API_BASE, PHP_URL_HOST) ?: ''));
        $filteredHost = strtolower((string) (wp_parse_url((string) apply_filters('lykanshield_license_api_base', self::DEFAULT_API_BASE), PHP_URL_HOST) ?: ''));

        return $host !== '' && in_array($host, array_filter([$defaultHost, $filteredHost]), true);
    }

    private static function request_nonce(string $scope): string
    {
        try {
            $nonce = bin2hex(random_bytes(16));
        } catch (Throwable) {
            $nonce = md5(uniqid('lykanshield-', true));
        }

        set_transient('lykanshield_license_nonce_' . md5($scope . $nonce), '1', self::NONCE_TTL_SECONDS);

        return $nonce;
    }

    /**
     * @param mixed $decoded
     */
    private static function valid_response(mixed $decoded): bool
    {
        if (!is_array($decoded)) {
            return false;
        }

        foreach (['message', 'token', 'error_code'] as $key) {
            if (isset($decoded[$key]) && !is_string($decoded[$key])) {
                return false;
            }
        }

        return true;
    }

    /**
     * @return array{ok:bool,message:string,token:string}
     */
    private static function license_error(string $message, string $code): array
    {
        $sanitized = self::redact_string(wp_strip_all_tags($message));
        update_option(LykanShield_Settings::OPTION_LICENSE_LAST_ERROR, $sanitized, false);
        self::audit('request_failed', ['code' => $code, 'message' => $sanitized]);

        return [
            'ok' => false,
            'message' => $sanitized . ' Free protection remains active.',
            'token' => '',
        ];
    }

    /**
     * @param array<string,mixed> $context
     */
    private static function audit(string $event, array $context): void
    {
        if (class_exists('LykanShield_Audit_Log')) {
            LykanShield_Audit_Log::record('license_' . $event, 'recorded', $context);
        }
    }
}
