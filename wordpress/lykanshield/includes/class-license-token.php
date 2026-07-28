<?php

declare(strict_types=1);

defined('ABSPATH') || exit;

final class LykanShield_License_Token
{
    private const TOKEN_VERSION = 1;
    private const MAX_TOKEN_BYTES = 16384;
    private const ALGORITHM = 'Ed25519';
    private const MAX_CLOCK_SKEW_SECONDS = 300;
    private const PUBLIC_KEY_BASE64 = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=';

    /**
     * @return array{valid:bool,status:string,payload:array<string,mixed>|null,error_code:string,message:string}
     */
    public static function verify(string $token, string $registrableDomain, string $installationId, ?int $now = null): array
    {
        $now ??= time();
        $token = trim($token);

        if ($token === '') {
            return self::result(false, LykanShield_License_Status::FREE, null, 'free', 'Free plan active. No premium license token is installed.');
        }

        if (strlen($token) > self::MAX_TOKEN_BYTES) {
            return self::result(false, LykanShield_License_Status::FREE, null, 'token_too_large', 'License token is too large.');
        }

        $parts = explode('.', $token);

        if (count($parts) !== 3) {
            return self::result(false, LykanShield_License_Status::FREE, null, 'malformed_token', 'License token format is invalid.');
        }

        [$headerPart, $payloadPart, $signaturePart] = $parts;
        $headerJson = self::base64url_decode($headerPart);
        $payloadJson = self::base64url_decode($payloadPart);
        $signature = self::base64url_decode($signaturePart);

        if ($headerJson === null || $payloadJson === null || $signature === null) {
            return self::result(false, LykanShield_License_Status::FREE, null, 'malformed_token', 'License token encoding is invalid.');
        }

        $header = json_decode($headerJson, true);

        if (!is_array($header) || ($header['alg'] ?? '') !== self::ALGORITHM || (int) ($header['typ'] ?? 0) !== self::TOKEN_VERSION) {
            return self::result(false, LykanShield_License_Status::FREE, null, 'invalid_header', 'License token header is invalid.');
        }

        if (!self::verify_signature($headerPart . '.' . $payloadPart, $signature)) {
            return self::result(false, LykanShield_License_Status::FREE, null, 'invalid_signature', 'License token signature is invalid.');
        }

        $payload = json_decode($payloadJson, true);

        if (!is_array($payload)) {
            return self::result(false, LykanShield_License_Status::FREE, null, 'invalid_payload', 'License token payload is invalid.');
        }

        $payload = self::normalize_payload($payload);

        if ((int) ($payload['token_version'] ?? 0) !== self::TOKEN_VERSION) {
            return self::result(false, LykanShield_License_Status::FREE, $payload, 'unsupported_token_version', 'License token version is unsupported.');
        }

        if (($payload['installation_id'] ?? '') !== $installationId) {
            return self::result(false, LykanShield_License_Status::FREE, $payload, 'installation_mismatch', 'License token belongs to another installation.');
        }

        if (($payload['licensed_domain'] ?? '') !== $registrableDomain) {
            return self::result(false, LykanShield_License_Status::FREE, $payload, 'domain_mismatch', 'License token belongs to another domain.');
        }

        if (($payload['status'] ?? 'active') === 'revoked') {
            return self::result(false, LykanShield_License_Status::REVOKED, $payload, 'revoked', 'Premium license is revoked. Free protection remains active.');
        }

        $issuedAt = (int) ($payload['issued_at'] ?? 0);
        $expiresAt = (int) ($payload['expires_at'] ?? 0);
        $graceEndsAt = (int) ($payload['grace_until'] ?? $payload['grace_ends_at'] ?? $expiresAt);

        if ($issuedAt <= 0 || $expiresAt <= 0 || $graceEndsAt < $expiresAt) {
            return self::result(false, LykanShield_License_Status::FREE, $payload, 'invalid_dates', 'License token dates are invalid.');
        }

        if ($issuedAt > ($now + self::MAX_CLOCK_SKEW_SECONDS)) {
            return self::result(false, LykanShield_License_Status::FREE, $payload, 'clock_skew', 'License token was issued in the future.');
        }

        if ($now <= $expiresAt) {
            return self::result(true, LykanShield_License_Status::PREMIUM_VALID, $payload, 'ok', '');
        }

        if ($now <= ($graceEndsAt + self::MAX_CLOCK_SKEW_SECONDS)) {
            return self::result(true, LykanShield_License_Status::PREMIUM_GRACE, $payload, 'grace', '');
        }

        return self::result(false, LykanShield_License_Status::EXPIRED, $payload, 'expired', 'Premium license expired. Free protection remains active.');
    }

    public static function unsigned_payload_part(array $payload): string
    {
        return self::base64url_encode((string) wp_json_encode($payload));
    }

    public static function unsigned_header_part(): string
    {
        return self::base64url_encode((string) wp_json_encode([
            'alg' => self::ALGORITHM,
            'typ' => self::TOKEN_VERSION,
        ]));
    }

    private static function verify_signature(string $signedData, string $signature): bool
    {
        if (!function_exists('sodium_crypto_sign_verify_detached')) {
            return false;
        }

        $publicKey = base64_decode((string) apply_filters('lykanshield_license_public_key', self::PUBLIC_KEY_BASE64), true);

        if (!is_string($publicKey) || strlen($publicKey) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
            return false;
        }

        return sodium_crypto_sign_verify_detached($signature, $signedData, $publicKey);
    }

    /**
     * @param array<string,mixed> $payload
     * @return array<string,mixed>
     */
    private static function normalize_payload(array $payload): array
    {
        foreach (['domain', 'licensed_domain'] as $key) {
            if (isset($payload[$key]) && is_string($payload[$key])) {
                $payload[$key] = LykanShield_Domain_Resolver::registrable_domain($payload[$key]);
            }
        }

        return $payload;
    }

    private static function base64url_decode(string $value): ?string
    {
        $padding = strlen($value) % 4;

        if ($padding > 0) {
            $value .= str_repeat('=', 4 - $padding);
        }

        $decoded = base64_decode(strtr($value, '-_', '+/'), true);

        return is_string($decoded) ? $decoded : null;
    }

    private static function base64url_encode(string $value): string
    {
        return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
    }

    /**
     * @param array<string,mixed>|null $payload
     * @return array{valid:bool,status:string,payload:array<string,mixed>|null,error_code:string,message:string}
     */
    private static function result(bool $valid, string $status, ?array $payload, string $errorCode, string $message): array
    {
        return [
            'valid' => $valid,
            'status' => $status,
            'payload' => $payload,
            'error_code' => $errorCode,
            'message' => $message,
        ];
    }
}
