<?php

declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';
require_once __DIR__ . '/../includes/class-domain-resolver.php';
require_once __DIR__ . '/../includes/class-license-status.php';
require_once __DIR__ . '/../includes/class-license-token.php';

if (!function_exists('sodium_crypto_sign_keypair')) {
    fwrite(STDOUT, 'Skipped: sodium extension is not available in this PHP runtime.' . PHP_EOL);
    exit(0);
}

function apply_filters(string $hookName, mixed $value): mixed
{
    return $hookName === 'lykanshield_license_public_key'
        ? $GLOBALS['lykanshield_test_public_key']
        : $value;
}

function wp_json_encode(mixed $value, int $flags = 0): string|false
{
    return json_encode($value, $flags);
}

function wp_parse_url(string $url, int $component = -1): mixed
{
    return parse_url($url, $component);
}

$keypair = sodium_crypto_sign_keypair();
$GLOBALS['lykanshield_test_public_key'] = base64_encode(sodium_crypto_sign_publickey($keypair));
$secretKey = sodium_crypto_sign_secretkey($keypair);

$payload = [
    'token_version' => 1,
    'license_id' => 'lic_entitlement',
    'canonical_domain' => 'www.example.de',
    'installation_id' => '0123456789abcdef0123456789abcdef',
    'tier' => 'premium',
    'features' => ['analytics', 'exports', 'webhooks', 'reports'],
    'licensed_domain' => 'example.de',
    'issued_at' => 1000,
    'expires_at' => 2000,
    'grace_until' => 2300,
    'status' => 'active',
];

$token = lykanshield_test_sign_token($payload, $secretKey);

foreach (['example.de', 'www.example.de', 'shop.example.de', 'api.example.de'] as $host) {
    $domain = LykanShield_Domain_Resolver::registrable_domain($host);
    $result = LykanShield_License_Token::verify($token, $domain, '0123456789abcdef0123456789abcdef', 1500);
    lykanshield_test_assert($result['valid'], $host . ' must use the example.de entitlement.');
}

$wrongDomain = LykanShield_License_Token::verify($token, 'example.com', '0123456789abcdef0123456789abcdef', 1500);
lykanshield_test_assert(!$wrongDomain['valid'] && $wrongDomain['error_code'] === 'domain_mismatch', 'example.com must need a separate entitlement.');

$wrongInstallation = LykanShield_License_Token::verify($token, 'example.de', 'fedcba9876543210fedcba9876543210', 1500);
lykanshield_test_assert(!$wrongInstallation['valid'] && $wrongInstallation['error_code'] === 'installation_mismatch', 'Wrong installation ID must not verify.');

$expired = LykanShield_License_Token::verify($token, 'example.de', '0123456789abcdef0123456789abcdef', 3000);
lykanshield_test_assert(!$expired['valid'] && $expired['status'] === LykanShield_License_Status::EXPIRED, 'Expired token must disable Premium.');

echo "License entitlement smoke tests passed." . PHP_EOL;

function lykanshield_test_sign_token(array $payload, string $secretKey): string
{
    $header = rtrim(strtr(base64_encode((string) json_encode(['alg' => 'Ed25519', 'typ' => 1])), '+/', '-_'), '=');
    $body = rtrim(strtr(base64_encode((string) json_encode($payload)), '+/', '-_'), '=');
    $signature = sodium_crypto_sign_detached($header . '.' . $body, $secretKey);

    return $header . '.' . $body . '.' . rtrim(strtr(base64_encode($signature), '+/', '-_'), '=');
}
