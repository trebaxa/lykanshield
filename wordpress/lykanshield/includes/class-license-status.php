<?php

declare(strict_types=1);

defined('ABSPATH') || exit;

final class LykanShield_License_Status
{
    public const FREE = 'free';
    public const PREMIUM_VALID = 'premium_valid';
    public const PREMIUM_GRACE = 'premium_grace';
    public const EXPIRED = 'expired';
    public const SUSPENDED = 'suspended';
    public const REVOKED = self::SUSPENDED;
    public const SERVER_ERROR = 'server_error';
    private const CACHE_OPTION = 'lykanshield_license_runtime_status';

    /**
     * @return array{
     *     status:string,
     *     tier:string,
     *     premium:bool,
     *     protection_enabled:bool,
     *     premium_features:array<string,bool>,
     *     warnings:string[],
     *     token:array<string,mixed>|null
     * }
     */
    public static function current(): array
    {
        static $cached = null;

        if (is_array($cached)) {
            return $cached;
        }

        $domainContext = LykanShield_License_Client::domain_context();
        $networkToken = class_exists('LykanShield_Multisite')
            ? LykanShield_Multisite::token_for_domain($domainContext['registrable_domain'])
            : '';
        $verification = LykanShield_License_Token::verify(
            $networkToken !== '' ? $networkToken : LykanShield_Settings::license_token(),
            $domainContext['registrable_domain'],
            LykanShield_Settings::installation_id()
        );

        $cached = self::from_verification($verification);
        update_option(self::CACHE_OPTION, $cached, false);

        return $cached;
    }

    /**
     * @param array{valid:bool,status:string,payload:array<string,mixed>|null,error_code:string,message:string} $verification
     * @return array{
     *     status:string,
     *     tier:string,
     *     premium:bool,
     *     protection_enabled:bool,
     *     premium_features:array<string,bool>,
     *     warnings:string[],
     *     token:array<string,mixed>|null
     * }
     */
    public static function from_verification(array $verification): array
    {
        $warnings = [];
        $status = $verification['status'];
        $payload = $verification['payload'];
        if ($status === self::REVOKED) {
            $status = self::SUSPENDED;
        }

        $premium = in_array($status, [self::PREMIUM_VALID, self::PREMIUM_GRACE], true);

        if (!$verification['valid'] && $verification['message'] !== '') {
            $warnings[] = $verification['message'];
        }

        if ($status === self::PREMIUM_GRACE) {
            $warnings[] = 'Premium license is in grace period. Renew the token before premium analytics are disabled.';
        }

        if ($status === self::SERVER_ERROR) {
            $warnings[] = 'The license server is currently unavailable. Free protection remains active.';
        }

        return [
            'status' => $status,
            'tier' => $premium ? 'premium' : 'free',
            'premium' => $premium,
            'protection_enabled' => true,
            'premium_features' => self::premium_features($premium),
            'warnings' => $warnings,
            'token' => $payload,
        ];
    }

    /**
     * @return array<string,mixed>
     */
    public static function mu_loader_snapshot(): array
    {
        $snapshot = get_option(self::CACHE_OPTION, []);

        return is_array($snapshot) ? $snapshot : [];
    }

    /**
     * @return array{
     *     status:string,
     *     tier:string,
     *     premium:bool,
     *     protection_enabled:bool,
     *     premium_features:array<string,bool>,
     *     warnings:string[],
     *     token:array<string,mixed>|null
     * }
     */
    public static function server_error(): array
    {
        return self::from_verification([
            'valid' => false,
            'status' => self::SERVER_ERROR,
            'payload' => null,
            'error_code' => 'server_error',
            'message' => 'The license server is currently unavailable. Free protection remains active.',
        ]);
    }

    /**
     * @return array<string,bool>
     */
    private static function premium_features(bool $enabled): array
    {
        return [
            'central_stats_365_days' => $enabled,
            'full_domain_analysis' => $enabled,
            'attacker_top_100' => $enabled,
            'country_time_filter' => $enabled,
            'attack_type_trends' => $enabled,
            'full_ip_history' => $enabled,
            'rest_api_10000_daily' => $enabled,
            'csv_json_export' => $enabled,
            'instant_email_notifications' => $enabled,
            'webhooks' => $enabled,
            'extended_custom_rules' => $enabled,
            'unlimited_allow_block_list' => $enabled,
            'automatic_reports' => $enabled,
        ];
    }
}
