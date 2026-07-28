<?php

declare(strict_types=1);

define('ABSPATH', dirname(__DIR__, 4) . DIRECTORY_SEPARATOR);

function apply_filters(string $hookName, mixed $value): mixed
{
    if ($hookName === 'lykanshield_license_public_key') {
        return $GLOBALS['lykanshield_test_public_key'];
    }

    return $value;
}

function wp_json_encode(mixed $value, int $flags = 0): string|false
{
    return json_encode($value, $flags);
}

function wp_parse_url(string $url, int $component = -1): mixed
{
    return parse_url($url, $component);
}

require_once dirname(__DIR__) . '/includes/class-license-status.php';
require_once dirname(__DIR__) . '/includes/class-domain-resolver.php';
require_once dirname(__DIR__) . '/includes/class-license-token.php';

if (!function_exists('sodium_crypto_sign_keypair')) {
    fwrite(STDOUT, 'Skipped: sodium extension is not available in this PHP runtime.' . PHP_EOL);
    exit(0);
}

$keypair = sodium_crypto_sign_keypair();
$secretKey = sodium_crypto_sign_secretkey($keypair);
$publicKey = sodium_crypto_sign_publickey($keypair);
$GLOBALS['lykanshield_test_public_key'] = base64_encode($publicKey);

$headerPart = base64url_encode((string) json_encode([
    'alg' => 'Ed25519',
    'typ' => 1,
]));
$payloadPart = base64url_encode((string) json_encode([
    'token_version' => 1,
    'license_id' => 'lic_test',
    'canonical_domain' => 'www.example.de',
    'installation_id' => '0123456789abcdef0123456789abcdef',
    'tier' => 'premium',
    'features' => ['analytics', 'exports', 'webhooks', 'reports'],
    'licensed_domain' => 'example.de',
    'issued_at' => 1000,
    'expires_at' => 2000,
    'grace_until' => 2300,
    'status' => 'active',
]));
$signature = sodium_crypto_sign_detached($headerPart . '.' . $payloadPart, $secretKey);
$token = $headerPart . '.' . $payloadPart . '.' . base64url_encode($signature);

$result = LykanShield_License_Token::verify($token, 'example.de', '0123456789abcdef0123456789abcdef', 1500);

assert_true($result['valid'], 'Valid signed token must verify.');
assert_true($result['status'] === LykanShield_License_Status::PREMIUM_VALID, 'Valid token must enable Premium.');

$expiredResult = LykanShield_License_Token::verify($token, 'example.de', '0123456789abcdef0123456789abcdef', 2701);
assert_true(!$expiredResult['valid'], 'Expired token must not stay Premium after grace period.');
assert_true($expiredResult['status'] === LykanShield_License_Status::EXPIRED, 'Expired token must report expired status.');

$wrongDomainResult = LykanShield_License_Token::verify($token, 'example.com', '0123456789abcdef0123456789abcdef', 1500);
assert_true(!$wrongDomainResult['valid'], 'Token must not verify for a different main domain.');

$wrongInstallationResult = LykanShield_License_Token::verify($token, 'example.de', 'ffffffffffffffffffffffffffffffff', 1500);
assert_true(!$wrongInstallationResult['valid'], 'Token must not verify for a different installation ID.');

$tampered = $headerPart . '.' . base64url_encode((string) json_encode([
    'token_version' => 1,
    'license_id' => 'lic_test',
    'canonical_domain' => 'www.example.de',
    'installation_id' => '0123456789abcdef0123456789abcdef',
    'tier' => 'premium',
    'features' => ['analytics'],
    'licensed_domain' => 'evil.example',
    'issued_at' => 1000,
    'expires_at' => 2000,
    'grace_until' => 2300,
    'status' => 'active',
])) . '.' . base64url_encode($signature);

$tamperedResult = LykanShield_License_Token::verify($tampered, 'example.de', '0123456789abcdef0123456789abcdef', 1500);

assert_true(!$tamperedResult['valid'], 'Tampered token must not verify.');

echo "License token smoke tests passed.\n";

function base64url_encode(string $value): string
{
    return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
}

function assert_true(bool $condition, string $message): void
{
    if (!$condition) {
        fwrite(STDERR, $message . PHP_EOL);
        exit(1);
    }
}
