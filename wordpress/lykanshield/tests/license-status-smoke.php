<?php

declare(strict_types=1);

define('ABSPATH', __DIR__);
require_once __DIR__ . '/../includes/class-license-status.php';

$valid = LykanShield_License_Status::from_verification([
    'valid' => true,
    'status' => LykanShield_License_Status::PREMIUM_VALID,
    'payload' => ['tier' => 'premium', 'licensed_domain' => 'example.de'],
    'error_code' => 'ok',
    'message' => '',
]);

if ($valid['status'] !== LykanShield_License_Status::PREMIUM_VALID || !$valid['protection_enabled'] || !$valid['premium_features']['csv_json_export']) {
    fwrite(STDERR, "Expected valid Premium with active protection and premium features.\n");
    exit(1);
}

$expired = LykanShield_License_Status::from_verification([
    'valid' => false,
    'status' => LykanShield_License_Status::EXPIRED,
    'payload' => ['tier' => 'premium', 'licensed_domain' => 'example.de'],
    'error_code' => 'expired',
    'message' => 'Premium license expired. Free protection remains active.',
]);

if ($expired['status'] !== LykanShield_License_Status::EXPIRED || !$expired['protection_enabled'] || $expired['premium_features']['csv_json_export']) {
    fwrite(STDERR, "Expected expired Premium to fall back to Free while protection stays active.\n");
    exit(1);
}

$free = LykanShield_License_Status::from_verification([
    'valid' => false,
    'status' => LykanShield_License_Status::FREE,
    'payload' => null,
    'error_code' => 'free',
    'message' => 'Free plan active. No premium license token is installed.',
]);

if ($free['status'] !== LykanShield_License_Status::FREE || !$free['protection_enabled'] || $free['premium_features']['csv_json_export']) {
    fwrite(STDERR, "Expected Free status with protection active and premium features disabled.\n");
    exit(1);
}

$suspended = LykanShield_License_Status::from_verification([
    'valid' => false,
    'status' => LykanShield_License_Status::SUSPENDED,
    'payload' => ['tier' => 'premium', 'licensed_domain' => 'example.de'],
    'error_code' => 'license_revoked',
    'message' => 'Premium license is suspended. Free protection remains active.',
]);

if ($suspended['status'] !== LykanShield_License_Status::SUSPENDED || !$suspended['protection_enabled'] || $suspended['premium_features']['csv_json_export']) {
    fwrite(STDERR, "Expected suspended Premium to fall back to Free while protection stays active.\n");
    exit(1);
}

$serverError = LykanShield_License_Status::server_error();

if ($serverError['status'] !== LykanShield_License_Status::SERVER_ERROR || !$serverError['protection_enabled'] || $serverError['premium_features']['csv_json_export']) {
    fwrite(STDERR, "Expected server error to keep Free protection active and Premium features disabled.\n");
    exit(1);
}

echo "License status smoke tests passed.\n";
