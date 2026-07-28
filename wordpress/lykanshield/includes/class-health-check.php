<?php

declare(strict_types=1);

defined('ABSPATH') || exit;

final class LykanShield_Health_Check
{
    /**
     * @return array<string,array{ok:bool,label:string,value:string,message:string}>
     */
    public static function checks(): array
    {
        return [
            'php_version' => [
                'ok' => version_compare(PHP_VERSION, LYKANSHIELD_MINIMUM_PHP_VERSION, '>='),
                'label' => 'PHP version',
                'value' => PHP_VERSION,
                'message' => 'PHP ' . LYKANSHIELD_MINIMUM_PHP_VERSION . ' or newer is required.',
            ],
            'wordpress_version' => [
                'ok' => version_compare(get_bloginfo('version'), LYKANSHIELD_MINIMUM_WORDPRESS_VERSION, '>='),
                'label' => 'WordPress version',
                'value' => get_bloginfo('version'),
                'message' => 'WordPress ' . LYKANSHIELD_MINIMUM_WORDPRESS_VERSION . ' or newer is required.',
            ],
            'json_extension' => self::extension_check('json'),
            'pcre_extension' => self::extension_check('pcre'),
            'sodium_extension' => self::extension_check('sodium'),
            'data_directory' => self::data_directory_check(),
            'core_config' => self::core_config_check(),
            'rules_file' => self::rules_file_check(),
        ];
    }

    /**
     * @return array{ok:bool,label:string,value:string,message:string}
     */
    private static function extension_check(string $extension): array
    {
        $loaded = extension_loaded($extension);

        return [
            'ok' => $loaded,
            'label' => 'PHP extension: ' . $extension,
            'value' => $loaded ? 'loaded' : 'missing',
            'message' => $loaded ? 'Loaded.' : 'The extension is not loaded.',
        ];
    }

    /**
     * @return array{ok:bool,label:string,value:string,message:string}
     */
    private static function data_directory_check(): array
    {
        $path = trailingslashit(WP_CONTENT_DIR) . 'lykan';
        $exists = is_dir($path);
        $writable = $exists && is_writable($path);

        return [
            'ok' => $writable,
            'label' => 'LykanShield data directory',
            'value' => $path,
            'message' => $writable ? 'Writable.' : 'Directory is missing or not writable.',
        ];
    }

    /**
     * @return array{ok:bool,label:string,value:string,message:string}
     */
    private static function core_config_check(): array
    {
        $path = LykanShield_Core_Config::config_path();
        $exists = is_file($path);
        $readable = $exists && is_readable($path);
        $decoded = null;

        if ($readable) {
            $json = file_get_contents($path);
            $decoded = is_string($json) ? json_decode($json, true) : null;
        }

        return [
            'ok' => $readable && is_array($decoded),
            'label' => 'Core configuration',
            'value' => $path,
            'message' => $readable && is_array($decoded) ? 'Valid JSON config is available.' : 'Config file is missing, unreadable or invalid.',
        ];
    }

    /**
     * @return array{ok:bool,label:string,value:string,message:string}
     */
    private static function rules_file_check(): array
    {
        $candidates = [
            trailingslashit(WP_CONTENT_DIR) . 'lykan/rules.json',
            trailingslashit(WP_CONTENT_DIR) . 'lykan/rules.dat',
            trailingslashit(WP_CONTENT_DIR) . 'lykan/cache/rules.json',
        ];

        foreach ($candidates as $path) {
            if (is_file($path)) {
                $mtime = filemtime($path);

                return [
                    'ok' => true,
                    'label' => 'Protection rules',
                    'value' => $path,
                    'message' => $mtime === false ? 'Rules file exists.' : 'Last updated ' . gmdate('Y-m-d H:i:s', $mtime) . ' UTC.',
                ];
            }
        }

        return [
            'ok' => false,
            'label' => 'Protection rules',
            'value' => 'not found',
            'message' => 'Rules file has not been downloaded yet.',
        ];
    }
}
