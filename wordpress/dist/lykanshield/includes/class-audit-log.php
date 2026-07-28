<?php

declare(strict_types=1);

defined('ABSPATH') || exit;

final class LykanShield_Audit_Log
{
    public const OPTION = 'lykanshield_audit_log';
    private const MAX_ENTRIES = 100;

    /**
     * @param array<string,mixed> $context
     */
    public static function record(string $action, string $result, array $context = []): void
    {
        $entries = get_option(self::OPTION, []);
        if (!is_array($entries)) {
            $entries = [];
        }

        $entries[] = [
            'time' => time(),
            'user_id' => get_current_user_id(),
            'site_id' => function_exists('get_current_blog_id') ? get_current_blog_id() : 0,
            'action' => sanitize_key($action),
            'result' => sanitize_key($result),
            'context' => self::redact($context),
        ];

        update_option(self::OPTION, array_slice($entries, -self::MAX_ENTRIES), false);
    }

    /**
     * @param array<string,mixed> $context
     * @return array<string,mixed>
     */
    private static function redact(array $context): array
    {
        foreach ($context as $key => $value) {
            $keyName = strtolower((string) $key);

            if (is_array($value)) {
                $context[$key] = self::redact($value);
                continue;
            }

            if (is_string($value) && (
                str_contains($keyName, 'license')
                || str_contains($keyName, 'token')
                || str_contains($keyName, 'secret')
                || str_contains($keyName, 'key')
            )) {
                $context[$key] = '[redacted]';
            }
        }

        return $context;
    }
}
