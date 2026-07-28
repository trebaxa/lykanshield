<?php

declare(strict_types=1);

defined('ABSPATH') || exit;

final class LykanShield_Loader_Installer
{
    private const STATUS_OPTION = 'lykanshield_loader_status';
    private const SIGNATURE = 'LykanShield MU loader managed by LykanShield';

    public static function maybe_install(): void
    {
        if (!current_user_can('activate_plugins')) {
            return;
        }

        $status = self::status();

        if ($status['installed'] === true && $status['managed'] === true) {
            return;
        }

        self::install();
    }

    /**
     * @return array{ok:bool,message:string,path:string}
     */
    public static function install(): array
    {
        $source = self::source_path();
        $target = self::target_path();
        $muDir = dirname($target);

        if (!is_readable($source)) {
            return self::save_status(false, 'MU loader source file is missing or not readable.', $target);
        }

        if (!is_dir($muDir) && !wp_mkdir_p($muDir)) {
            return self::save_status(false, 'The mu-plugins directory could not be created.', $target);
        }

        if (!is_writable($muDir)) {
            return self::save_status(false, 'The mu-plugins directory is not writable.', $target);
        }

        if (is_file($target) && !self::is_managed_loader($target)) {
            return self::save_status(false, 'A different MU loader already exists at the target path.', $target);
        }

        if (is_link($target)) {
            return self::save_status(false, 'The MU loader target is a symlink and will not be overwritten.', $target);
        }

        $loader = (string) file_get_contents($source);
        $temporary = $target . '.tmp.' . bin2hex(random_bytes(4));

        if (file_put_contents($temporary, $loader, LOCK_EX) === false) {
            return self::save_status(false, 'The temporary MU loader file could not be written.', $target);
        }

        if (!rename($temporary, $target)) {
            @unlink($temporary);

            return self::save_status(false, 'The MU loader could not be moved into place.', $target);
        }

        return self::save_status(true, 'The MU loader is installed.', $target);
    }

    /**
     * @return array{ok:bool,message:string,path:string}
     */
    public static function remove(): array
    {
        $target = self::target_path();

        if (!is_file($target)) {
            return self::save_status(true, 'The MU loader is not installed.', $target);
        }

        if (!self::is_managed_loader($target)) {
            return self::save_status(false, 'The existing MU loader is not managed by LykanShield.', $target);
        }

        if (!is_writable($target)) {
            return self::save_status(false, 'The MU loader file is not writable.', $target);
        }

        if (!unlink($target)) {
            return self::save_status(false, 'The MU loader could not be removed.', $target);
        }

        return self::save_status(true, 'The MU loader was removed.', $target);
    }

    /**
     * @return array{installed:bool,managed:bool,writable:bool,path:string,message:string}
     */
    public static function status(): array
    {
        $target = self::target_path();
        $muDir = dirname($target);
        $installed = is_file($target);
        $managed = $installed && self::is_managed_loader($target);
        $writable = is_dir($muDir) ? is_writable($muDir) : is_writable(dirname($muDir));
        $saved = get_option(self::STATUS_OPTION, []);
        $message = is_array($saved) && isset($saved['message']) ? (string) $saved['message'] : '';

        if ($installed && $managed) {
            $message = 'The MU loader is installed and managed by LykanShield.';
        } elseif ($installed) {
            $message = 'A different MU loader exists at the target path.';
        } elseif ($message === '') {
            $message = 'The MU loader is not installed yet.';
        }

        return [
            'installed' => $installed,
            'managed' => $managed,
            'writable' => $writable,
            'path' => $target,
            'message' => $message,
        ];
    }

    public static function manual_installation_text(): string
    {
        return sprintf(
            'Copy %s to %s. Create the mu-plugins directory first if it does not exist.',
            self::source_path(),
            self::target_path()
        );
    }

    private static function source_path(): string
    {
        return LYKANSHIELD_PLUGIN_DIR . 'mu-loader/' . LYKANSHIELD_MU_LOADER_FILE;
    }

    private static function target_path(): string
    {
        return trailingslashit(WPMU_PLUGIN_DIR) . LYKANSHIELD_MU_LOADER_FILE;
    }

    private static function is_managed_loader(string $path): bool
    {
        if (is_link($path) || !is_readable($path)) {
            return false;
        }

        $contents = file_get_contents($path, false, null, 0, 512);

        return is_string($contents) && str_contains($contents, self::SIGNATURE);
    }

    /**
     * @return array{ok:bool,message:string,path:string}
     */
    private static function save_status(bool $ok, string $message, string $path): array
    {
        $status = [
            'ok' => $ok,
            'message' => $message,
            'path' => $path,
            'checked_at' => time(),
        ];

        update_option(self::STATUS_OPTION, $status, false);

        return [
            'ok' => $ok,
            'message' => $message,
            'path' => $path,
        ];
    }
}
