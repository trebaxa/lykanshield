<?php

declare(strict_types=1);

/**
 * lykan class
 *
 * @see       https://github.com/trebaxa/lykanshield
 * @version   2.0
 * @requires  PHP 8.2 or newer
 * @author    Harald Petrich <service@trebaxa.com>
 * @copyright 2018 - 2026 Harald Petrich
 * @license   GNU LESSER GENERAL PUBLIC LICENSE Version 2.1, February 1999
 * @note      This program is distributed in the hope that it will be useful - WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. This project should help us developer to protect our PHP projects from hacking. Bad IPs will be reported to central server 
 * and lykan updates hisself with a current list of bad ips, bots and SQL injection rules.
 * Be part of the network and help us to get the web safer!
 *  
 * This version is compatible with keimeno CMS, but can easly changed to be compatible with Wordpress, Joomla and Typo3.
 * Just change the path to files and ensure the lykan_ROOT is successfully set.
 * 
 * Install WordPress
 * 1. add lykan.class.php to folder /wp-include
 * 2. add PHP code to index.php in root: require ( './wp-includes/lykan.class.php');lykan::run(dirname(__FILE__));
 * 
 * Install TYPO3
 * 1. add lykan.class.php to folder / where index.php is located
 * 2. add PHP code to index.php in root: require ( './typo3_src/lykan.class.php');lykan::run(dirname(__FILE__));
 * 
 * Install Keimeno
 * 1. already implemented ;-)
 * 2. Take the better CMS -> www.keimeno.de
 */

class lykan_config {
    public static array $config = array(
        'apikey' => '', # from lykanshield.io, not needed for protection
        'hcache_lifetime_hours' => 3, # cache lifetime in hours of filter files
        'blacklist_lifetime_hours' => 1, #locale blocked IPs life time
        'log_lines_count' => 98,
        'email' => '', #mail to send an info about sql injection attack
        'subscription_plan' => 'free',
        'subscription_domain' => '',
        'license_entitlement' => array(),
        'analytics_max_days' => 1,
        'analytics_leaderboard_limit' => 10,
        'api_daily_limit' => 100,
        'custom_list_max_entries' => 100,
        'lykan_capabilities' => array(),
        'allowed_ips' => array(),
        'custom_rules' => array(),
        'notification_mode' => 'daily',
        'webhook_url' => '',
        'webhook_secret' => '',
        'trusted_proxies' => array(), # exact IP addresses or CIDR ranges
        'client_connect_timeout_seconds' => 10,
        'client_timeout_seconds' => 30,
        'client_max_download_bytes' => 10 * 1024 * 1024,
        'blacklist_max_entries_per_section' => 50000,
        'remote_regex_max_pattern_bytes' => 512,
        'request_inspection_max_bytes' => 8192,
        'rules_unavailable_action' => 'monitor', # monitor or block
        'sql_injection_block_score' => 3,
        'report_queue_max_entries' => 1000,
        'local_bad_ip_max_entries' => 5000,
        'local_bad_ip_lifetime_hours' => 720,
        'request_cache_bucket_count' => 1024,
        'request_cache_cleanup_probability' => 100,
        'runtime_artifact_lifetime_hours' => 24,
        'refresh_rules_after_response' => true,
        'bad_user_post_action' => 'log', # log or block; blocking requires explicit opt-in
        'filter_active' => array(
            'mime_types' => true, #activates mime filter
            'file_inject' => true, # file injection filter
            'bad_bots' => true, # bad bot filter
            'bad_user_post' => false, # heuristic; disabled by default to avoid blocking API clients
            'bad_ips' => true, # bad IP filter
            'sql_injection' => true, # SQL Injection filter
            'worm_injection' => true, # WORM Injection filter
            'exploit' => true, # common query-string exploit signatures
            'payloadlog' => false, # WORM Injection filter
            ),
        # forbidden file extentions on file upload
        'forbidden_file_ext' => array(
            'php',
            'php3',
            'php5',
            'pl',
            'cgi',
            'asp',
            'exe',
            'cmd',
            'bat'));
}


class lykan {

    protected static string $lykan_root = '';
    protected static string $host = '';
    private static bool $report_flush_scheduled = false;
    private static ?string $blacklist_raw_cache = null;
    private static ?array $blacklist_data_cache = null;
    private static string $blacklist_cache_path = '';
    private static ?array $blacklist_shard_manifest_cache = null;
    private static array $blacklist_ip_shard_cache = array();
    private static bool $rules_unavailable_reported = false;
    private static bool $initialized = false;
    private static bool $config_loaded = false;
    private static bool $rule_refresh_scheduled = false;
    private static bool $response_finished = false;

    /**
     * Unknown capabilities are denied by default.
     */
    public static function has_capability(string $capability): bool {
        $capabilities = (array)(lykan_config::$config['lykan_capabilities'] ?? array());
        return isset($capabilities[$capability]) && $capabilities[$capability] === true;
    }

    /**
     * lykan::auto_detect_system()
     *
     * @return void
     */
    protected static function auto_detect_system() {
        static::$host = self::get_host();
        # default
        self::set_config_arr(array(
            'hpath' => static::$lykan_root . 'lykan/accesslog/',
            'root' => static::$lykan_root . 'lykan/',
            'lykan_blocked_file' => static::$lykan_root . 'lykan/hacklogblock_' . static::$host . '.txt',
            'lykan_blacklist' => static::$lykan_root . 'lykan/blacklist.json',
            'badips_file' => static::$lykan_root . 'lykan/badips_' . static::$host . '.txt',
            'badbots_file' => static::$lykan_root . 'lykan/badbots_' . static::$host . '.txt',
            ));

        # detect Keimeno CMS
        if (is_dir(static::$lykan_root . 'admin') && is_file(static::$lykan_root . 'admin/inc/keimeno.class.php')) {
            self::set_config_arr(array(
                'hpath' => static::$lykan_root . 'file_data/lykan/accesslog/',
                'root' => static::$lykan_root . 'file_data/lykan/',
                'lykan_blocked_file' => static::$lykan_root . 'file_data/lykan/hacklogblock_' . static::$host . '.txt',
                'lykan_blacklist' => static::$lykan_root . 'file_data/lykan/blacklist.json',
                'badips_file' => static::$lykan_root . 'file_data/lykan/badips_' . static::$host . '.txt',
                'badbots_file' => static::$lykan_root . 'file_data/lykan/badbots_' . static::$host . '.txt',
                ));
        }

        # detect WordPress
        if (is_dir(static::$lykan_root . 'wp-admin')) {
            self::set_config_arr(array(
                'root' => static::$lykan_root . 'wp-content/lykan/',
                'hpath' => static::$lykan_root . 'wp-content/lykan/accesslog/',
                'lykan_blocked_file' => static::$lykan_root . 'wp-content/lykan/hacklogblock_' . static::$host . '.txt',
                'lykan_blacklist' => static::$lykan_root . 'wp-content/lykan/blacklist.json',
                'badips_file' => static::$lykan_root . 'wp-content/lykan/badips_' . static::$host . '.txt',
                'badbots_file' => static::$lykan_root . 'wp-content/lykan/badbots_' . static::$host . '.txt',
                ));
        }

        #detect TYPO3
        if (is_dir(static::$lykan_root . 'fileadmin') && is_dir(static::$lykan_root . 'typo3conf')) {
            self::set_config_arr(array(
                'root' => static::$lykan_root . 'fileadmin/lykan/',
                'hpath' => static::$lykan_root . 'fileadmin/lykan/accesslog/',
                'lykan_blocked_file' => static::$lykan_root . 'fileadmin/lykan/hacklogblock_' . static::$host . '.txt',
                'lykan_blacklist' => static::$lykan_root . 'fileadmin/lykan/blacklist.json',
                'badips_file' => static::$lykan_root . 'fileadmin/lykan/badips_' . static::$host . '.txt',
                'badbots_file' => static::$lykan_root . 'fileadmin/lykan/badbots_' . static::$host . '.txt',
                ));
        }


        if (!is_dir(lykan_config::$config['hpath']) && !mkdir(lykan_config::$config['hpath'], 0750, true)) {
            self::log_runtime_error('Unable to create access-log directory: ' . lykan_config::$config['hpath']);
        }

        $dir = rtrim(self::get_root(), DIRECTORY_SEPARATOR);
        if (!is_dir($dir) || !is_file($dir . DIRECTORY_SEPARATOR . 'index.html')) {
            // create directory
            if (!is_dir($dir) && !mkdir($dir, 0750, true)) {
                self::log_runtime_error('Unable to create data directory: ' . $dir);
            }

            // try to set strict permissions (best-effort)
            if (is_dir($dir) && !chmod($dir, 0750)) {
                self::log_runtime_error('Unable to set data-directory permissions: ' . $dir);
            }

            // create a simple index.html so directory listings show nothing (fallback)
            $index_file = $dir . DIRECTORY_SEPARATOR . 'index.html';
            if (!is_file($index_file)) {
                if (file_put_contents($index_file, '<!doctype html><meta charset="utf-8"><title>Forbidden</title>', LOCK_EX) === false) {
                    self::log_runtime_error('Unable to create directory index protection: ' . $index_file);
                }
                elseif (!chmod($index_file, 0640)) {
                    self::log_runtime_error('Unable to set index permissions: ' . $index_file);
                }
            }

            // create an Apache .htaccess that denies access (best for Apache setups)
            $htaccess = $dir . DIRECTORY_SEPARATOR . '.htaccess';
            if (!is_file($htaccess)) {
                // For modern Apache: "Require all denied" is preferred, but include both for compatibility
                $ht_content = "Order deny,allow\nDeny from all\n<IfModule mod_authz_core.c>\n  Require all denied\n</IfModule>\n";
                if (file_put_contents($htaccess, $ht_content, LOCK_EX) === false) {
                    self::log_runtime_error('Unable to create Apache directory protection: ' . $htaccess);
                }
                elseif (!chmod($htaccess, 0640)) {
                    self::log_runtime_error('Unable to set Apache protection permissions: ' . $htaccess);
                }
            }

            // create an empty .user.ini (optional) to prevent php settings exposure (shared hosts)
            $userini = $dir . DIRECTORY_SEPARATOR . '.user.ini';
            if (!is_file($userini)) {
                if (file_put_contents($userini, "display_errors = Off\n", LOCK_EX) === false) {
                    self::log_runtime_error('Unable to create PHP directory protection: ' . $userini);
                }
                elseif (!chmod($userini, 0640)) {
                    self::log_runtime_error('Unable to set PHP protection permissions: ' . $userini);
                }
            }
        }
        else {
            // try to tighten permissions on existing dir (best-effort)
            if (!chmod($dir, 0750)) {
                self::log_runtime_error('Unable to tighten data-directory permissions: ' . $dir);
            }
        }
    }

    /**
     * lykan::get_the_ip()
     *
     * @return string
     */
    public static function get_the_ip(): string {
        $remote_addr = isset($_SERVER['REMOTE_ADDR']) ? trim((string)$_SERVER['REMOTE_ADDR']) : '';
        if (!filter_var($remote_addr, FILTER_VALIDATE_IP)) {
            return '0.0.0.0';
        }

        if (!self::is_trusted_proxy($remote_addr)) {
            return $remote_addr;
        }

        $forwarded_for = isset($_SERVER['HTTP_X_FORWARDED_FOR'])
            ? array_reverse(explode(',', (string)$_SERVER['HTTP_X_FORWARDED_FOR']))
            : array();

        foreach ($forwarded_for as $forwarded_ip) {
            $forwarded_ip = trim($forwarded_ip);
            if (!filter_var($forwarded_ip, FILTER_VALIDATE_IP)) {
                continue;
            }
            if (!self::is_trusted_proxy($forwarded_ip)) {
                return $forwarded_ip;
            }
        }

        if (isset($_SERVER['HTTP_X_REAL_IP'])) {
            $real_ip = trim((string)$_SERVER['HTTP_X_REAL_IP']);
            if (filter_var($real_ip, FILTER_VALIDATE_IP)) {
                return $real_ip;
            }
        }

        return $remote_addr;
    }

    /**
     * Determine whether an IP address belongs to a configured trusted proxy.
     *
     * @param string $ip Proxy IP address.
     * @return bool
     */
    private static function is_trusted_proxy($ip) {
        foreach ((array)(lykan_config::$config['trusted_proxies'] ?? array()) as $trusted_proxy) {
            $trusted_proxy = trim((string)$trusted_proxy);
            if ($trusted_proxy === '') {
                continue;
            }
            if ($trusted_proxy === $ip || self::ip_matches_cidr($ip, $trusted_proxy)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Determine whether an IPv4 or IPv6 address belongs to a CIDR range.
     *
     * @param string $ip IP address to test.
     * @param string $cidr Network range in CIDR notation.
     * @return bool
     */
    private static function ip_matches_cidr($ip, $cidr) {
        if (strpos($cidr, '/') === false) {
            return false;
        }

        list($network, $prefix_length) = array_pad(explode('/', $cidr, 2), 2, null);
        $ip_binary = @inet_pton($ip);
        $network_binary = @inet_pton($network);
        if ($ip_binary === false || $network_binary === false || strlen($ip_binary) !== strlen($network_binary)) {
            return false;
        }
        if (!ctype_digit((string)$prefix_length)) {
            return false;
        }

        $prefix_length = (int)$prefix_length;
        $max_bits = strlen($ip_binary) * 8;
        if ($prefix_length < 0 || $prefix_length > $max_bits) {
            return false;
        }

        $full_bytes = intdiv($prefix_length, 8);
        $remaining_bits = $prefix_length % 8;
        if ($full_bytes > 0 && substr($ip_binary, 0, $full_bytes) !== substr($network_binary, 0, $full_bytes)) {
            return false;
        }
        if ($remaining_bits === 0) {
            return true;
        }

        $mask = (0xFF << (8 - $remaining_bits)) & 0xFF;
        return (ord($ip_binary[$full_bytes]) & $mask) === (ord($network_binary[$full_bytes]) & $mask);
    }

    /**
     * lykan::_p()
     * 
     * @param mixed $arr
     * @return void
     */
    protected static function _p($arr) {
        echo '<pre>' . print_r((array )$arr, true) . '</pre>';
    }

    /**
     * lykan::set_config_value()
     * 
     * @param mixed $key
     * @param mixed $value
     * @return void
     */
    protected static function set_config_value($key, $value) {
        lykan_config::$config[$key] = $value;
    }

    /**
     * lykan::set_config_arr()
     * 
     * @param mixed $arr
     * @return void
     */
    protected static function set_config_arr($arr) {
        lykan_config::$config = array_merge(lykan_config::$config, $arr);
    }

    /**
     * Write an internal Lykan error to the configured PHP error log.
     *
     * @param string $message Error message without the Lykan prefix.
     * @return void
     */
    private static function log_runtime_error($message) {
        error_log('Lykan: ' . $message);
    }

    /**
     * Write a recurring runtime error at most once per configured interval.
     * State is shared between PHP workers and capped to known recent keys.
     *
     * @param string $key Stable, non-user-controlled error identifier.
     * @param string $message Error message.
     * @param int $interval Minimum interval in seconds.
     * @return void
     */
    private static function log_runtime_error_rate_limited($key, $message, $interval = 3600) {
        if (!isset(lykan_config::$config['root'])) {
            self::log_runtime_error($message);
            return;
        }

        $path = rtrim(self::get_root(), '/\\') . DIRECTORY_SEPARATOR . 'error_rate_limits.json';
        $now = time();
        $interval = max(60, (int)$interval);
        $should_log = false;
        $updated = self::update_locked_file($path, function ($current) use ($key, $now, $interval, &$should_log) {
            $state = json_decode((string)$current, true);
            $state = is_array($state) ? $state : array();
            foreach ($state as $state_key => $timestamp) {
                if (!is_numeric($timestamp) || ($now - (int)$timestamp) > ($interval * 2)) {
                    unset($state[$state_key]);
                }
            }
            $key = substr(preg_replace('/[^a-z0-9_.-]+/i', '-', (string)$key), 0, 80);
            $last = isset($state[$key]) ? (int)$state[$key] : 0;
            if (($now - $last) >= $interval) {
                $state[$key] = $now;
                $should_log = true;
            }
            if (count($state) > 100) {
                asort($state, SORT_NUMERIC);
                $state = array_slice($state, -100, null, true);
            }
            $json = json_encode($state, JSON_UNESCAPED_SLASHES);
            return is_string($json) ? $json : '{}';
        });

        if (!$updated || $should_log) {
            self::log_runtime_error($message);
        }
    }

    /**
     * Replace a file while holding an exclusive lock.
     *
     * @param string $path Destination file path.
     * @param string $contents Complete file contents.
     * @return bool
     */
    private static function write_locked_file($path, $contents) {
        $fp = @fopen($path, 'c+b');
        if ($fp === false) {
            self::log_runtime_error('Unable to open file for writing: ' . $path);
            return false;
        }

        $success = false;
        if (!flock($fp, LOCK_EX)) {
            self::log_runtime_error('Unable to lock file for writing: ' . $path);
        }
        else {
            rewind($fp);
            if (!ftruncate($fp, 0)) {
                self::log_runtime_error('Unable to truncate file: ' . $path);
            }
            else {
                $written = fwrite($fp, (string)$contents);
                $success = ($written !== false && $written === strlen((string)$contents));
                if (!$success) {
                    self::log_runtime_error('Unable to write complete file: ' . $path);
                }
                fflush($fp);
            }
            flock($fp, LOCK_UN);
        }
        fclose($fp);
        return $success;
    }

    /**
     * Read and update a file under one exclusive lock.
     *
     * @param string $path File path to update.
     * @param callable $update Callback receiving and returning file contents.
     * @return bool
     */
    private static function update_locked_file($path, callable $update) {
        $fp = @fopen($path, 'c+b');
        if ($fp === false) {
            self::log_runtime_error('Unable to open file for update: ' . $path);
            return false;
        }
        if (!flock($fp, LOCK_EX)) {
            self::log_runtime_error('Unable to lock file for update: ' . $path);
            fclose($fp);
            return false;
        }

        rewind($fp);
        $current = stream_get_contents($fp);
        $updated = $update($current === false ? '' : $current);
        $success = is_string($updated);
        if ($success) {
            rewind($fp);
            $success = ftruncate($fp, 0);
            if ($success) {
                $written = fwrite($fp, $updated);
                $success = ($written !== false && $written === strlen($updated));
                fflush($fp);
            }
        }
        if (!$success) {
            self::log_runtime_error('Unable to update file: ' . $path);
        }

        flock($fp, LOCK_UN);
        fclose($fp);
        return $success;
    }

    /**
     * Append data to a file while holding an exclusive lock.
     *
     * @param string $path Destination file path.
     * @param string $line Data to append.
     * @return bool
     */
    private static function append_locked_file($path, $line) {
        $fp = @fopen($path, 'ab');
        if ($fp === false) {
            self::log_runtime_error('Unable to open log file: ' . $path);
            return false;
        }
        if (!flock($fp, LOCK_EX)) {
            self::log_runtime_error('Unable to lock log file: ' . $path);
            fclose($fp);
            return false;
        }
        $line = (string)$line;
        $written = fwrite($fp, $line);
        $success = ($written !== false && $written === strlen($line));
        fflush($fp);
        flock($fp, LOCK_UN);
        fclose($fp);
        if (!$success) {
            self::log_runtime_error('Unable to append complete log entry: ' . $path);
        }
        return $success;
    }

    /**
     * Read a file while holding a shared lock.
     *
     * @param string $path Source file path.
     * @return string|false
     */
    private static function read_locked_file($path) {
        $fp = @fopen($path, 'rb');
        if ($fp === false) {
            self::log_runtime_error('Unable to open file for reading: ' . $path);
            return false;
        }
        if (!flock($fp, LOCK_SH)) {
            self::log_runtime_error('Unable to lock file for reading: ' . $path);
            fclose($fp);
            return false;
        }
        $contents = stream_get_contents($fp);
        flock($fp, LOCK_UN);
        fclose($fp);
        if ($contents === false) {
            self::log_runtime_error('Unable to read file: ' . $path);
        }
        return $contents;
    }

    /**
     * lykan::is_valid_json()
     * 
     * @param mixed $str
     * @return bool
     */
    protected static function is_valid_json($str) {
        json_decode($str);
        return json_last_error() == JSON_ERROR_NONE;
    }

    /**
     * lykan::load_config()
     * 
     * @return void
     */
    public static function load_config(): array {
        if (!self::$initialized) {
            self::init();
        }
        $conf_file = self::get_root() . 'config.json';
        if (is_file($conf_file)) {
            $json = self::read_locked_file($conf_file);
            if (is_string($json) && self::is_valid_json($json)) {
                $arr = json_decode($json, true);
                if (isset($arr['filter_active']) && is_array($arr['filter_active'])) {
                    $arr['filter_active'] = array_merge(
                        lykan_config::$config['filter_active'],
                        $arr['filter_active']
                    );
                }
                lykan_config::$config = array_merge(lykan_config::$config, $arr);
            }
        }
        self::$config_loaded = true;
        return lykan_config::$config;
    }

    /**
     * lykan::save_config()
     * 
     * @param mixed $arr
     * @return void
     */
    public static function save_config(array $arr): bool {
        self::ensure_initialized();
        $json = json_encode($arr, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
        if ($json === false) {
            self::log_runtime_error('Unable to encode configuration as JSON.');
            return false;
        }
        return self::write_locked_file(self::get_root() . 'config.json', $json);
    }

    /**
     * lykan::get_root()
     * 
     * @return string
     */
    public static function get_root(): string {
        if (!self::$initialized) {
            self::init();
        }
        return lykan_config::$config['root'];
    }

    /**
     * lykan::set_root()
     * 
     * @param mixed $path
     * @return void
     */
    protected static function set_root($path) {
        if (empty($path)) {
            $path = realpath($_SERVER['DOCUMENT_ROOT']);
        }
        static::$lykan_root = $path . (substr($path, -1) == DIRECTORY_SEPARATOR ? '' : DIRECTORY_SEPARATOR);
    }

    /**
     * lykan::check_filename()
     * 
     * @param mixed $name
     * @return void
     */
    public static function check_filename(string $name): void {
        self::ensure_initialized();
        if (self::is_filter_active('file_inject') === true) {
            $normalized_name = str_replace('\\', '/', trim($name));
            $normalized_name = rtrim(basename($normalized_name), ". \t\n\r\0\x0B");
            $ext = strtolower((string)pathinfo($normalized_name, PATHINFO_EXTENSION));
            $forbidden_extensions = array_map(
                'strtolower',
                array_map('strval', (array)lykan_config::$config['forbidden_file_ext'])
            );

            if (
                in_array($ext, $forbidden_extensions, true)
                || preg_match('/^.*\.([a-z]{3})\.html$/i', $normalized_name)
                || preg_match('/^.*\.([a-z]{3})\.htm$/i', $normalized_name)
            ) {
                self::report_hack(lykan_types::FILE_INJECT, $ext, false);
                self::exit_env(lykan_types::FILE_INJECT . ' ' . $ext);
            }
        }
    }

    /**
     * lykan::is_filter_active()
     * 
     * @param mixed $type
     * @return bool
     */
    private static function is_filter_active($type) {
        return isset(lykan_config::$config['filter_active'][$type]) && (boolean)lykan_config::$config['filter_active'][$type] === true;
    }

    /**
     * lykan::check_mime()
     *
     * Determine the MIME type from the uploaded temporary file and compare it
     * with the configured allowlist. Client-provided MIME values are never used
     * as the basis for the security decision.
     *
     * @param array $file Normalized element from the $_FILES superglobal.
     * @return void
     */
    protected static function check_mime($file) {
        if (self::is_filter_active('mime_types') !== true) {
            return;
        }

        if (!is_array($file)) {
            self::log_runtime_error('MIME check received an invalid upload structure.');
            self::exit_env(lykan_types::MIME_FILE_UPLOAD . ' invalid upload structure');
        }

        $upload_error = isset($file['error']) ? (int)$file['error'] : UPLOAD_ERR_OK;
        if ($upload_error === UPLOAD_ERR_NO_FILE) {
            return;
        }
        if ($upload_error !== UPLOAD_ERR_OK) {
            self::log_runtime_error('MIME check skipped a failed upload with error code ' . $upload_error . '.');
            return;
        }

        $tmp_name = isset($file['tmp_name']) ? (string)$file['tmp_name'] : '';
        if ($tmp_name === '' || !is_file($tmp_name) || !is_readable($tmp_name)) {
            self::log_runtime_error('MIME check could not read the temporary upload file.');
            self::exit_env(lykan_types::MIME_FILE_UPLOAD . ' unreadable upload');
        }

        if (!class_exists('finfo')) {
            self::log_runtime_error('PHP Fileinfo extension is required for MIME validation.');
            self::exit_env(lykan_types::MIME_FILE_UPLOAD . ' fileinfo unavailable');
        }

        $finfo = new finfo(FILEINFO_MIME_TYPE);
        $detected_mime = $finfo->file($tmp_name);
        $detected_mime = is_string($detected_mime) ? strtolower(trim($detected_mime)) : '';
        if ($detected_mime === '') {
            self::log_runtime_error('Fileinfo could not determine the upload MIME type.');
            self::exit_env(lykan_types::MIME_FILE_UPLOAD . ' unknown MIME type');
        }

        $json = self::get_current_pattern_data();
        $allowed_mimes = array();
        if (isset($json['mime']) && is_array($json['mime'])) {
            foreach ($json['mime'] as $mime) {
                if (is_array($mime) && isset($mime['m_mime'])) {
                    $allowed_mime = strtolower(trim((string)$mime['m_mime']));
                    if ($allowed_mime !== '') {
                        $allowed_mimes[] = $allowed_mime;
                    }
                }
            }
        }

        if (count($allowed_mimes) === 0) {
            if (self::should_block_when_rules_unavailable('MIME allowlist')) {
                self::exit_env(lykan_types::MIME_FILE_UPLOAD . ' empty MIME allowlist');
            }
            return;
        }

        if (in_array($detected_mime, array_unique($allowed_mimes), true)) {
            return;
        }

        $client_mime = isset($file['type']) ? trim((string)$file['type']) : '';
        $report_info = $detected_mime . ($client_mime !== '' ? ' (client claimed ' . $client_mime . ')' : '');
        self::report_hack(lykan_types::MIME_FILE_UPLOAD, $report_info, false);
        self::exit_env(lykan_types::MIME_FILE_UPLOAD . ' ' . $detected_mime);
    }

    /**
     * lykan::file_upload_protection()
     *
     * Normalize all upload shapes and validate every individual file.
     *
     * @return void
     */
    public static function file_upload_protection(): void {
        self::ensure_initialized();
        $uploads = isset($_FILES) && is_array($_FILES) ? $_FILES : array();
        foreach ($uploads as $upload) {
            if (!is_array($upload)) {
                self::log_runtime_error('Upload protection received an invalid $_FILES entry.');
                continue;
            }

            foreach (self::normalize_uploaded_files($upload) as $file) {
                $upload_error = isset($file['error']) ? (int)$file['error'] : UPLOAD_ERR_OK;
                if ($upload_error === UPLOAD_ERR_NO_FILE || trim((string)$file['name']) === '') {
                    continue;
                }

                self::check_filename((string)$file['name']);
                self::check_mime($file);
            }
        }
    }

    /**
     * Convert a single or nested $_FILES entry into individual upload records.
     *
     * @param array $upload One top-level entry from the $_FILES superglobal.
     * @return array
     */
    private static function normalize_uploaded_files(array $upload): array {
        if (!array_key_exists('name', $upload)) {
            return array();
        }

        $files = array();
        self::append_normalized_uploads(
            $files,
            $upload['name'],
            $upload['type'] ?? '',
            $upload['tmp_name'] ?? '',
            $upload['error'] ?? UPLOAD_ERR_OK,
            $upload['size'] ?? 0,
            $upload['full_path'] ?? ''
        );
        return $files;
    }

    /**
     * Recursively align the parallel arrays used by PHP for multiple uploads.
     *
     * @param array $files Destination list of normalized file records.
     * @param mixed $name Original filename or nested filename array.
     * @param mixed $type Client-provided MIME value or matching nested array.
     * @param mixed $tmp_name Temporary filename or matching nested array.
     * @param mixed $error Upload error code or matching nested array.
     * @param mixed $size File size or matching nested array.
     * @param mixed $full_path Browser-provided relative path or matching array.
     * @return void
     */
    private static function append_normalized_uploads(
        array &$files,
        $name,
        $type,
        $tmp_name,
        $error,
        $size,
        $full_path
    ) {
        if (is_array($name)) {
            foreach ($name as $key => $child_name) {
                self::append_normalized_uploads(
                    $files,
                    $child_name,
                    is_array($type) && array_key_exists($key, $type) ? $type[$key] : '',
                    is_array($tmp_name) && array_key_exists($key, $tmp_name) ? $tmp_name[$key] : '',
                    is_array($error) && array_key_exists($key, $error) ? $error[$key] : UPLOAD_ERR_OK,
                    is_array($size) && array_key_exists($key, $size) ? $size[$key] : 0,
                    is_array($full_path) && array_key_exists($key, $full_path) ? $full_path[$key] : ''
                );
            }
            return;
        }

        $files[] = array(
            'name' => (string)$name,
            'type' => is_scalar($type) ? (string)$type : '',
            'tmp_name' => is_scalar($tmp_name) ? (string)$tmp_name : '',
            'error' => is_numeric($error) ? (int)$error : UPLOAD_ERR_OK,
            'size' => is_numeric($size) ? (int)$size : 0,
            'full_path' => is_scalar($full_path) ? (string)$full_path : ''
        );
    }

    /**
     * lykan::init()
     * 
     * @return void
     */
    public static function init(string $path = ''): void {
        self::set_root($path);
        self::$initialized = true;
        self::$config_loaded = false;
        self::auto_detect_system();
    }

    /**
     * Initialize paths and load configuration exactly once for public APIs.
     *
     * @param string $path Optional application root.
     * @return void
     */
    private static function ensure_initialized(string $path = ''): void {
        if (!self::$initialized || $path !== '') {
            self::init($path);
        }
        if (!self::$config_loaded) {
            self::load_config();
        }
    }

    /**
     * lykan::run()
     * 
     * @return void
     */
    public static function run(string $path = ''): void {
        self::ensure_initialized($path);
        self::maybe_cleanup_request_cache();

        if (self::client_is_allowlisted()) {
            return;
        }

        $user_agent = self::get_user_agent();
        $identity = (stripos($user_agent, 'bot') !== false) ? $user_agent : $user_agent . self::get_the_ip();
        $bucket_count = max(16, min(65536, (int)(lykan_config::$config['request_cache_bucket_count'] ?? 1024)));
        // Seven hexadecimal digits also stay within the integer range on
        // 32-bit PHP builds.
        $bucket = hexdec(substr(hash('sha256', $identity), 0, 7)) % $bucket_count;
        $hfile = lykan_config::$config['hpath'] . md5('request-cache-bucket:' . $bucket);
        self::update_locked_file($hfile, function ($current) use ($user_agent, $hfile) {
            $modified_at = is_file($hfile) ? filemtime($hfile) : false;
            $max_age = max(1, (int)lykan_config::$config['hcache_lifetime_hours']) * 3600;
            if ($modified_at !== false && (time() - $modified_at) > $max_age) {
                $current = '';
            }
            $arr = explode(PHP_EOL, $current);
            $hcount = ($current === '') ? 1 : ((int)($arr[0] ?? 0) + 1);
            return implode(PHP_EOL, array(
                $hcount,
                $user_agent,
                self::get_the_ip(),
                date('Y-m-d H:i:s'),
            ));
        });

        self::block_bad_user_post();
        self::file_upload_protection();
        self::block_bad_bots();
        self::block_locale_bad_ips();
        self::apply_custom_rules();
        self::worm_detect();
        self::sql_detect();
        self::clear_blocked();
        self::block_ips_and_bots_from_blacklist();
        if (self::is_filter_active('exploit')) {
            lykan_exploit::check_for_exploit();
        }
        self::payloadlog();
        #self::check_agent();

        /*
         * Public diagnostics are intentionally disabled. Exposing the request
         * logs and blocked-client list through ?lykan requires an authenticated
         * administration endpoint and must not be enabled in the request filter.
         *
         * if (isset($_GET['lykan'])) {
         *     self::get_current_pattern();
         *     $result = self::read_logs();
         *     self::echo_table($result['hour_log'], $result['hour_log_count'] . ' Clients (last hour)');
         *     self::echo_table($result['blocked_bots'], 'Bad Bot blocked list');
         *     die();
         * }
        */
    }

    /**
     * Allow exact IPs and CIDR ranges to bypass request blocking.
     */
    private static function client_is_allowlisted(): bool {
        $client_ip = self::get_the_ip();
        foreach ((array)(lykan_config::$config['allowed_ips'] ?? array()) as $entry) {
            $entry = trim((string)$entry);
            if (
                (filter_var($entry, FILTER_VALIDATE_IP) && $entry === $client_ip)
                || (self::is_valid_cidr($entry) && self::ip_matches_cidr($client_ip, $entry))
            ) {
                return true;
            }
        }
        return false;
    }

    /**
     * Apply locally configured Premium request rules.
     */
    private static function apply_custom_rules(): void {
        if (!self::has_capability('extended_rules')) {
            return;
        }
        $sources = array(
            'uri' => (string)($_SERVER['REQUEST_URI'] ?? ''),
            'query' => self::get_query_string(),
            'user_agent' => self::get_user_agent(),
        );
        foreach (array_slice((array)(lykan_config::$config['custom_rules'] ?? array()), 0, 250) as $rule) {
            if (!is_array($rule) || empty($rule['enabled'])) {
                continue;
            }
            $target = (string)($rule['target'] ?? 'query');
            $source = (string)($sources[$target] ?? '');
            $pattern = substr((string)($rule['pattern'] ?? ''), 0, 512);
            if ($pattern === '') {
                continue;
            }
            $matches = ($rule['match'] ?? 'contains') === 'regex'
                ? @preg_match($pattern, $source) === 1
                : stripos($source, $pattern) !== false;
            if (!$matches) {
                continue;
            }
            $name = substr(
                preg_replace('/[^a-z0-9_. -]+/i', '', (string)($rule['name'] ?? 'Custom rule')),
                0,
                80
            );
            self::report_hack('CUSTOM_RULE', $name, true);
            if (($rule['action'] ?? 'log') === 'block') {
                self::exit_env('CUSTOM_RULE: ' . $name);
            }
        }
    }

    /**
     * Determine whether a filename is a Lykan request-cache hash.
     *
     * Request-cache files are created from md5() and therefore consist of
     * exactly 32 hexadecimal characters without a filename extension.
     *
     * @param string $filename Filename without its directory path.
     * @return bool
     */
    private static function is_request_cache_filename($filename) {
        return preg_match('/^[a-f0-9]{32}$/i', (string)$filename) === 1;
    }

    /**
     * Remove expired request-cache buckets occasionally instead of scanning the
     * directory on every request. Bucketed filenames put a hard upper bound on
     * the number of files that new client identities can create.
     *
     * @return void
     */
    private static function maybe_cleanup_request_cache() {
        $probability = max(1, (int)(lykan_config::$config['request_cache_cleanup_probability'] ?? 100));
        if (mt_rand(1, $probability) !== 1) {
            return;
        }

        self::prune_local_bad_ips_file();
        self::cleanup_runtime_artifacts();

        $max_age = max(1, (int)lykan_config::$config['hcache_lifetime_hours']) * 3600;
        $handle = @opendir(lykan_config::$config['hpath']);
        if ($handle === false) {
            return;
        }

        while (false !== ($file = readdir($handle))) {
            if (!self::is_request_cache_filename($file)) {
                continue;
            }
            $path = lykan_config::$config['hpath'] . $file;
            $modified_at = is_file($path) ? filemtime($path) : false;
            if ($modified_at !== false && (time() - $modified_at) > $max_age && !unlink($path)) {
                self::log_runtime_error('Unable to remove expired request cache: ' . $path);
            }
        }
        closedir($handle);
    }

    /**
     * lykan::payloadlog()
     *
     * @return void
     */
    protected static function payloadlog() {
        if (self::is_filter_active('payloadlog') === true) {
            payload_logger::log_request(lykan_config::$config['hpath']);
        }
    }

    /**
     * lykan::block_bad_user_post()
     *
     * Handle POST requests without a user agent and referer. These headers are
     * optional for API clients and webhooks, so the heuristic only logs by
     * default. Blocking requires bad_user_post_action=block explicitly.
     *
     * @return void
     */
    protected static function block_bad_user_post() {
        if (self::is_filter_active('bad_user_post') !== true) {
            return;
        }

        $request_method = isset($_SERVER['REQUEST_METHOD']) ? strtoupper((string)$_SERVER['REQUEST_METHOD']) : '';
        if ($request_method !== 'POST' || self::get_user_agent() !== '' || !empty($_SERVER['HTTP_REFERER'])) {
            return;
        }

        $message = 'POST request without user agent and referer from ' . self::get_the_ip();
        $action = strtolower(trim((string)(lykan_config::$config['bad_user_post_action'] ?? 'log')));
        if ($action !== 'block') {
            self::log_runtime_error($message . ' (monitor only).');
            return;
        }

        self::report_hack(lykan_types::BAD_USER_POST, 'POST without user agent and referer');
        self::exit_env(lykan_types::BAD_USER_POST . ' ' . self::get_the_ip());
    }

    /**
     * lykan::block_ips_and_bots_from_blacklist()
     * blocks IPs and bots save manually by backend
     * @return void
     */
    private static function block_ips_and_bots_from_blacklist() {
        $user_agent = self::get_user_agent();
        $json = self::get_current_pattern_data();
        $client_ip = self::get_the_ip();

        # check bad IPs ( include IPs from stock DB and lykan network )
        if (isset($json['badips']) && is_array($json['badips'])) {
            if (isset($json['badips'][$client_ip])) {
                self::report_hack(lykan_types::BAD_IP, "", false);
                self::exit_env(lykan_types::BAD_IP . ' ' . $client_ip);
            }
        }
        elseif (self::is_ip_in_blacklist_shard($client_ip)) {
            self::report_hack(lykan_types::BAD_IP, "", false);
            self::exit_env(lykan_types::BAD_IP . ' ' . $client_ip);
        }

        #check bots
        if (isset($json['bots']) && is_array($json['bots'])) {
            foreach ((array )$json['bots'] as $row) {
                $bot_key = isset($row['b_bot']) ? trim((string)$row['b_bot']) : '';
                if ($bot_key !== '' && stripos($user_agent, $bot_key) !== false) {
                    self::report_hack(lykan_types::BLACK_LIST_BOT, "", false);
                    self::exit_env('BLACK_LIST_BOT');
                }
            }
        }
    }


    /**
     * lykan::block_bad_bots()
     * 
     * @return void
     */
    protected static function block_bad_bots() {
        if (self::is_filter_active('bad_bots') === true) {
            $user_agent = self::get_user_agent();
            foreach (self::read_bad_bots_from_cachefile() as $badbot) {
                $badbot = trim((string)$badbot);
                if ($badbot === '' || stripos($user_agent, $badbot) === false) {
                    continue;
                }
                self::append_locked_file(lykan_config::$config['lykan_blocked_file'], implode("\t", array(
                    date('Y-m-d H:i:s'),
                    $user_agent,
                    'AGENT',
                    self::get_the_ip())) . PHP_EOL);
                self::report_hack(lykan_types::BLACK_LIST_BOT, $user_agent);
                self::exit_env('BOT');
            }
        }
    }

    /**
     * lykan::check_agent()
     * 
     * @return void
     */
    private static function check_agent() {
        # invalid USER AGENT
        $user_agent = self::get_user_agent();
        if (strlen($user_agent) < 2) {
            self::report_hack(lykan_types::INVALID_USER_AGENT, $user_agent);
            self::exit_env('USER_AGENT');
        }
    }

    /**
     * lykan::get_user_agent()
     * 
     * @return string
     */
    public static function get_user_agent(): string {
        return isset($_SERVER['HTTP_USER_AGENT']) ? substr($_SERVER['HTTP_USER_AGENT'], 0, 254) : '';
    }

    /**
     * lykan::read_logs()
     * 
     * @param mixed $k
     * @return void
     */
    public static function read_logs(): array {
        self::ensure_initialized();
        $result = array(
            'hour_log' => array(),
            'request_buckets' => array(),
            'blocked_bots' => array(),
            'hour_log_count' => 0,
            'request_bucket_count' => 0,
            'request_count_estimate' => 0,
            'statistics_are_approximate' => true
        );
        $max_age = max(1, (int)lykan_config::$config['hcache_lifetime_hours']) * 3600;
        if ($handle = opendir(lykan_config::$config['hpath'])) {
            while (false !== ($file = readdir($handle))) {
                if (!self::is_request_cache_filename($file)) {
                    continue;
                }
                $path = lykan_config::$config['hpath'] . $file;
                $modified_at = is_file($path) ? filemtime($path) : false;
                if ($modified_at === false || (time() - $modified_at) > $max_age) {
                    continue;
                }
                $contents = self::read_locked_file($path);
                if (!is_string($contents)) {
                    continue;
                }
                $row = preg_split('/\R/', trim($contents));
                $count = max(0, (int)($row[0] ?? 0));
                $bucket = array(
                    'request_count' => $count,
                    'sample_user_agent' => (string)($row[1] ?? ''),
                    'sample_ip' => (string)($row[2] ?? ''),
                    'last_seen' => (string)($row[3] ?? '')
                );
                $result['request_buckets'][] = $bucket;
                $result['hour_log'][] = array($count, $bucket['sample_user_agent'], $bucket['sample_ip'], $bucket['last_seen']);
                $result['request_count_estimate'] += $count;
            }
            closedir($handle);
        }
        if (is_file(lykan_config::$config['lykan_blocked_file'])) {
            $contents = self::read_locked_file(lykan_config::$config['lykan_blocked_file']);
            $blocked = is_string($contents) ? preg_split('/\R/', $contents) : array();
            foreach ($blocked as $key => $line) {
                $result['blocked_bots'][] = explode("\t", $line);
            }
        }
        $result['request_bucket_count'] = count($result['request_buckets']);
        // Backward-compatible key: this is a bucket count, not a unique-client count.
        $result['hour_log_count'] = $result['request_bucket_count'];
        return $result;
    }

    /**
     * lykan::clear_blocked()
     * 
     * @return void
     */
    protected static function clear_blocked() {
        $path = lykan_config::$config['lykan_blocked_file'];
        if (is_file($path) && filesize($path) > 6000) {
            self::update_locked_file($path, function ($current) {
                $lines = preg_split('/\R/', trim($current));
                $lines = array_slice((array)$lines, -(int)lykan_config::$config['log_lines_count']);
                return implode(PHP_EOL, $lines) . PHP_EOL;
            });
        }
    }


    /**
     * lykan::block()
     * 
     * @return void
     */
    public static function exit_env(string $reason = ''): never {
        if (!headers_sent()) {
            http_response_code(403);
            header('Content-Type: text/plain; charset=UTF-8');
            header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
            header('X-Content-Type-Options: nosniff');
        }

        echo 'Forbidden';
        exit;
    }


    /**
     * lykan::block_locale_bad_ips()
     * locale stored bad ips
     * @return void
     */
    protected static function block_locale_bad_ips() {
        if (self::is_filter_active('bad_ips') === true) {
            $client_ip = self::get_the_ip();
            $locale_badips = self::get_locale_bad_ips();
            foreach ($locale_badips as $blocked_entry) {
                $blocked_entry = trim((string)$blocked_entry);
                if ($blocked_entry === '') {
                    continue;
                }

                $matches = filter_var($blocked_entry, FILTER_VALIDATE_IP)
                    ? inet_pton($blocked_entry) === inet_pton($client_ip)
                    : (
                        self::is_valid_cidr($blocked_entry)
                            ? self::ip_matches_cidr($client_ip, $blocked_entry)
                            : self::matches_legacy_ipv4_wildcard($client_ip, $blocked_entry)
                    );
                if ($matches) {
                    self::block_this_locale_bad_ip();
                }
            }
        }
    }

    /**
     * Validate an IPv4 or IPv6 CIDR expression.
     *
     * @param string $cidr Network range in CIDR notation.
     * @return bool
     */
    private static function is_valid_cidr($cidr) {
        if (strpos((string)$cidr, '/') === false) {
            return false;
        }
        list($network, $prefix) = array_pad(explode('/', (string)$cidr, 2), 2, '');
        $binary = @inet_pton($network);
        if ($binary === false || !ctype_digit($prefix)) {
            return false;
        }
        $prefix = (int)$prefix;
        return $prefix >= 0 && $prefix <= (strlen($binary) * 8);
    }

    /**
     * Match a legacy IPv4 wildcard such as 192.0.2.*.
     *
     * IPv6 wildcard strings are intentionally unsupported; use CIDR instead.
     *
     * @param string $ip Client IP address.
     * @param string $pattern Legacy IPv4 wildcard.
     * @return bool
     */
    private static function matches_legacy_ipv4_wildcard($ip, $pattern) {
        if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
            return false;
        }
        if (!self::is_valid_legacy_ipv4_wildcard($pattern)) {
            return false;
        }

        $regex = '/^' . str_replace(array('.', '*'), array('\.', '\d{1,3}'), $pattern) . '$/';
        return preg_match($regex, $ip) === 1;
    }

    /**
     * Validate a legacy four-part IPv4 wildcard.
     *
     * @param string $pattern Legacy IPv4 wildcard.
     * @return bool
     */
    private static function is_valid_legacy_ipv4_wildcard($pattern) {
        $pattern_parts = explode('.', (string)$pattern);
        if (count($pattern_parts) !== 4) {
            return false;
        }
        $has_wildcard = false;
        foreach ($pattern_parts as $part) {
            if ($part === '*') {
                $has_wildcard = true;
                continue;
            }
            if (!ctype_digit($part) || (int)$part < 0 || (int)$part > 255) {
                return false;
            }
        }
        return $has_wildcard;
    }

    /**
     * lykan::block_this_locale_bad_ip()
     * 
     * @return void
     */
    private static function block_this_locale_bad_ip() {
        self::append_locked_file(lykan_config::$config['lykan_blocked_file'], implode("\t", array(
            date('Y-m-d H:i:s'),
            self::get_user_agent(),
            'IP',
            self::get_the_ip())) . PHP_EOL);
        self::report_hack(lykan_types::BAD_IP, self::get_the_ip(), false);
        self::exit_env(lykan_types::BAD_IP);
    }


    /**
     * lykan::read_bad_bots_from_cachefile()
     * 
     * @return array
     */
    protected static function read_bad_bots_from_cachefile() {
        if (is_file(lykan_config::$config['badbots_file'])) {
            $contents = self::read_locked_file(lykan_config::$config['badbots_file']);
            return is_string($contents) ? preg_split('/\R/', $contents, -1, PREG_SPLIT_NO_EMPTY) : array();
        }
        else
            return array();
    }

    /**
     * lykan::get_locale_bad_ips()
     * 
     * @return array
     */
    protected static function get_locale_bad_ips() {
        if (is_file(lykan_config::$config['badips_file'])) {
            $contents = self::read_locked_file(lykan_config::$config['badips_file']);
            if (!is_string($contents)) {
                return array();
            }
            $fallback = filemtime(lykan_config::$config['badips_file']);
            $records = self::decode_local_bad_ip_records($contents, $fallback === false ? time() : $fallback);
            $records = self::prune_local_bad_ip_records($records);
            return array_keys($records);
        }
        else
            return array();
    }

    /**
     * lykan::echo_table()
     * 
     * @param mixed $table
     * @param mixed $title
     * @return void
     */
    protected static function echo_table($table, $title) {
        echo '<h3>' . $title . '</h3><table>';
        foreach ((array )$table as $key => $row) {
            echo '<tr>';
            foreach ($row as $value) {
                echo '<td>' . $value . '</td>';
            }
            echo '</tr>';
        }
        echo '</table>';
    }

    /**
     * lykan::get_backend()
     * 
     * @return array
     */
    public static function get_backend(): array {
        self::ensure_initialized();
        return array(
            'bad_ips' => (implode(PHP_EOL, self::get_locale_bad_ips())),
            'bad_bots' => (implode(PHP_EOL, self::read_bad_bots_from_cachefile())),
            );
    }


    /**
     * lykan::add_ip()
     * 
     * @param mixed $ip
     * @return void
     */
    public static function add_ip(string $ip): void {
        self::ensure_initialized();
        $ip = self::normalize_blocked_ip_entry($ip);
        if ($ip !== '') {
            self::update_locked_file(lykan_config::$config['badips_file'], function ($current) use ($ip) {
                $records = self::decode_local_bad_ip_records($current, time());
                $records[$ip] = time();
                return self::encode_local_bad_ip_records(self::prune_local_bad_ip_records($records));
            });
        }
    }

    /**
     * lykan::save()
     * 
     * @param mixed $ip_list
     * @return void
     */
    public static function save(array $ip_list): bool {
        self::ensure_initialized();
        $ip_list = array_unique($ip_list);
        $arr = [];
        foreach ($ip_list as $ip) {
            $ip = self::normalize_blocked_ip_entry($ip);
            if ($ip !== '') {
                $arr[$ip] = time();
            }
        }
        return self::write_locked_file(
            lykan_config::$config['badips_file'],
            self::encode_local_bad_ip_records(self::prune_local_bad_ip_records($arr))
        );
    }

    /**
     * lykan::remove_ip()
     * 
     * @param mixed $ip
     * @return void
     */
    public static function remove_ip(string $ip): bool {
        self::ensure_initialized();
        $ip = self::normalize_blocked_ip_entry($ip);
        if ($ip === '') {
            return false;
        }
        return self::update_locked_file(lykan_config::$config['badips_file'], function ($current) use ($ip) {
            $records = self::decode_local_bad_ip_records($current, time());
            unset($records[$ip]);
            return self::encode_local_bad_ip_records(self::prune_local_bad_ip_records($records));
        });
    }

    /**
     * Decode both legacy one-IP-per-line files and timestamped entries.
     *
     * @param string $contents File contents.
     * @param int $legacy_timestamp Timestamp assigned to legacy entries.
     * @return array<string,int>
     */
    private static function decode_local_bad_ip_records($contents, $legacy_timestamp) {
        $records = array();
        foreach (preg_split('/\R/', trim((string)$contents), -1, PREG_SPLIT_NO_EMPTY) as $line) {
            $parts = explode("\t", (string)$line, 2);
            if (count($parts) === 2 && ctype_digit($parts[0])) {
                $timestamp = (int)$parts[0];
                $entry = self::normalize_blocked_ip_entry($parts[1]);
            }
            else {
                $timestamp = (int)$legacy_timestamp;
                $entry = self::normalize_blocked_ip_entry($line);
            }
            if ($entry !== '') {
                $records[$entry] = max($timestamp, (int)($records[$entry] ?? 0));
            }
        }
        return $records;
    }

    /**
     * Apply expiry and entry-count limits, retaining the newest entries.
     *
     * @param array<string,int> $records IP entry to creation timestamp.
     * @return array<string,int>
     */
    private static function prune_local_bad_ip_records(array $records) {
        $lifetime = max(1, (int)(lykan_config::$config['local_bad_ip_lifetime_hours'] ?? 720)) * 3600;
        $cutoff = time() - $lifetime;
        foreach ($records as $entry => $timestamp) {
            if ((int)$timestamp < $cutoff) {
                unset($records[$entry]);
            }
        }
        arsort($records, SORT_NUMERIC);
        $max_entries = (int)(lykan_config::$config['local_bad_ip_max_entries'] ?? 5000);
        return $max_entries > 0 ? array_slice($records, 0, $max_entries, true) : $records;
    }

    /**
     * Encode timestamped local blocked-IP records.
     *
     * @param array<string,int> $records IP entry to creation timestamp.
     * @return string
     */
    private static function encode_local_bad_ip_records(array $records) {
        $lines = array();
        foreach ($records as $entry => $timestamp) {
            $lines[] = (int)$timestamp . "\t" . $entry;
        }
        return count($lines) > 0 ? implode(PHP_EOL, $lines) . PHP_EOL : '';
    }

    /**
     * Persist expiry/count pruning without changing active entries.
     *
     * @return void
     */
    private static function prune_local_bad_ips_file() {
        $path = lykan_config::$config['badips_file'];
        if (!is_file($path)) {
            return;
        }
        $fallback = filemtime($path);
        self::update_locked_file($path, function ($current) use ($fallback) {
            $records = self::decode_local_bad_ip_records(
                $current,
                $fallback === false ? time() : $fallback
            );
            return self::encode_local_bad_ip_records(self::prune_local_bad_ip_records($records));
        });
    }

    /**
     * lykan::is_valid_ip()
     * 
     * @param mixed $ip
     * @return bool
     */
    public static function is_valid_ip(string $ip): bool {
        if (!filter_var($ip, FILTER_VALIDATE_IP) && !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return false;
        }
        return true;
    }

    /**
     * Normalize and validate an entry for the local blocked-IP list.
     *
     * @param mixed $entry Exact IP, CIDR range or legacy IPv4 wildcard.
     * @return string Empty when the entry is invalid.
     */
    private static function normalize_blocked_ip_entry($entry) {
        $entry = trim((string)$entry);
        if (filter_var($entry, FILTER_VALIDATE_IP)) {
            return strtolower($entry);
        }
        if (self::is_valid_cidr($entry)) {
            list($network, $prefix) = explode('/', $entry, 2);
            return strtolower($network) . '/' . (int)$prefix;
        }
        if (strpos($entry, ':') === false && self::is_valid_legacy_ipv4_wildcard($entry)) {
            return $entry;
        }
        return '';
    }

    /**
     * lykan::get_query_string()
     * 
     * @return string
     */
    private static function get_query_string() {
        $query = isset($_SERVER['QUERY_STRING']) ? (string)$_SERVER['QUERY_STRING'] : '';
        $max_bytes = max(256, (int)(lykan_config::$config['request_inspection_max_bytes'] ?? 8192));
        return strlen($query) > $max_bytes ? substr($query, 0, $max_bytes) : $query;
    }

    /**
     * lykan::worm_detect()
     * 
     * @return void
     */
    private static function worm_detect() {
        self::detect_worm_injection('worm', lykan_types::WORM_INJECT);
        $check = $cracktrack = self::get_query_string();
        $json = self::get_current_pattern_data();
        if (isset($json['xssinject']) && is_array($json['xssinject'])) {
            foreach ((array )$json['xssinject'] as $row) {
                $matched = false;
                $updated = self::apply_remote_regex((string)$row['i_term'], $cracktrack, $matched);
                if ($updated === false) {
                    continue;
                }
                $cracktrack = $updated;
            }
            if ($cracktrack != $check) {
                self::report_hack(lykan_types::XSS_INJECT);
                self::exit_env(lykan_types::XSS_INJECT);
            }
        }
    }

    /**
     * write_sql_inject_log
     *
     * Writes a detailed, capped log entry for SQL injection detections.
     * Accepts the detection array ($d) and the prepared $log_line.
     */
    private static function write_sql_inject_log(array $d, string $log_line) {
        try {
            $log_file = rtrim(lykan_config::$config['hpath'], '/\\') . DIRECTORY_SEPARATOR . 'sql_inject.log';
            $log_dir = dirname($log_file);
            if (!is_dir($log_dir) && !mkdir($log_dir, 0750, true)) {
                self::log_runtime_error('Unable to create SQL injection log directory: ' . $log_dir);
                return;
            }

            $max_entries = 10000;
            $ip = self::get_the_ip();
            $host = self::get_host();
            $ua = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
            $url = isset($_SERVER['REQUEST_URI'])
                ? preg_replace('/[?#].*$/', '', (string)$_SERVER['REQUEST_URI'])
                : (isset($_SERVER['PHP_SELF']) ? (string)$_SERVER['PHP_SELF'] : '');

            $extra = '';
            if (isset($d['pattern']))
                $extra .= ' pattern=' . $d['pattern'];
            if (isset($d['matched_variant']))
                $extra .= ' matched=' . $d['matched_variant'];
            if (isset($d['value_snippet']))
                $extra .= ' snippet=' . $d['value_snippet'];

            // sanitize newlines and clamp lengths
            $safe_extra = preg_replace('/[\r\n\t]+/', ' ', $extra);
            $safe_ua = preg_replace('/[\r\n\t]+/', ' ', substr($ua, 0, 512));
            $safe_url = preg_replace('/[\r\n\t]+/', ' ', substr($url, 0, 1024));

            $entry = date('c') . ' - IP=' . $ip . ' - Host=' . $host . ' - ' . $log_line . ' -' . $safe_extra . ' - UA=' . $safe_ua . ' - URL=' . $safe_url;

            self::update_locked_file($log_file, function ($current) use ($entry, $max_entries) {
                $lines = preg_split('/\R/', trim($current), -1, PREG_SPLIT_NO_EMPTY);
                $lines[] = $entry;
                $lines = array_slice($lines, -$max_entries);
                return implode(PHP_EOL, $lines) . PHP_EOL;
            });
            if (!chmod($log_file, 0640)) {
                self::log_runtime_error('Unable to set SQL injection log permissions: ' . $log_file);
            }
        }
        catch (\Throwable $t) {
            self::log_runtime_error('SQL injection logging failed: ' . $t->getMessage());
        }
    }

    /**
     * lykan::sql_detect()
     * 
     * @return void
     */
    private static function sql_detect() {
        // If the simpler pattern-based SQL injection filter flags a problem, exit
        # self::detect_injection('sql', lykan_types::SQL_INJECT);

        if (self::is_filter_active('sql_injection') !== true) {
            return;
        }

        $patterns = array();

        // load JSON patterns (tolerant)
        $json = self::get_current_pattern_data();
        if (is_array($json)) {
            foreach ($json as $section_key => $section) {
                if (!is_array($section))
                    continue;
                if ($section_key === 'sqlinject') {
                    foreach ($section as $row) {
                        if (isset($row['i_term'])) {
                            $term = (string )$row['i_term'];
                            $term = trim($term);
                            if ($term !== '') {
                                $patterns[] = $term;
                            }
                        }
                    }
                }
            }
        }

        // deduplicate patterns and normalize to lower case for case-insensitive matching
        $patterns = array_values(array_unique(array_map('trim', $patterns)));
        $lc_patterns = array();
        foreach ($patterns as $p) {
            $lc_patterns[] = self::lower_utf8($p);
        }

        // collect inputs (uses your existing helper)
        $inputs = self::collect_inputs_for_sqli_check();

        $detections = array();

        foreach ($inputs as $val) {
            // safety: ensure string and not empty
            if (!is_string($val) && !is_numeric($val))
                continue;
            $s = (string )$val;
            $s_trim = trim($s);
            if ($s_trim === '')
                continue;


            // prepare variants to detect encoded payloads
            $variants = array();
            $variants[] = $s_trim;
            // rawurldecode handles %xx sequences; do both rawurldecode and urldecode
            $rawurld = @rawurldecode($s_trim);
            if ($rawurld !== false && $rawurld !== $s_trim)
                $variants[] = $rawurld;
            $urld = @urldecode($s_trim);
            if ($urld !== false && $urld !== $s_trim)
                $variants[] = $urld;
            // double decode (attackers sometimes double-encode)
            $double = @rawurldecode(@rawurldecode($s_trim));
            if ($double !== false && $double !== $s_trim && $double !== $rawurld && $double !== $urld) {
                $variants[] = $double;
            }

            // also lowercased variants for case-insensitive substring search
            $lc_variants = array();
            foreach ($variants as $v) {
                $lc_variants[] = self::lower_utf8($v);
            }

            // 2) pattern matching (plain substring, case-insensitive)
            foreach ($lc_patterns as $idx => $pattern) {
                if ($pattern === '')
                    continue;
                foreach ($lc_variants as $v) {
                    if ($v === '')
                        continue;
                    if (self::strpos_utf8($v, $pattern) !== false) {
                        $detections[] = array(
                            'type' => 'pattern',
                            'pattern' => $patterns[$idx], // original pattern
                            'matched_variant' => substr($v, 0, 200),
                            'value_snippet' => substr($s_trim, 0, 120),
                            'score' => self::score_sql_injection_candidate($v, $patterns[$idx]));
                        // once matched for this pattern against this input, skip to next pattern
                        break 2;
                    }
                }
            }
        }

        // Log all candidates, but block only candidates that reach the
        // configured confidence threshold.
        if (!empty($detections)) {
            $block_score = max(2, (int)(lykan_config::$config['sql_injection_block_score'] ?? 3));
            $blocking_detection = null;
            foreach ($detections as $d) {
                $log_line = date('c') . " - sql_detect: type=" . $d['type'] . ' score=' . (int)$d['score'];
                if (isset($d['reason']))
                    $log_line .= " reason=" . $d['reason'];
                if (isset($d['pattern']))
                    $log_line .= " pattern=" . $d['pattern'];
                $log_line .= " snippet=" . (isset($d['value_snippet']) ? $d['value_snippet'] : 'n/a');

                // write the detection to a dedicated SQL injection log file
                // delegate logging to helper (writes capped log and extra meta)
                self::write_sql_inject_log($d, $log_line);
                if ((int)$d['score'] >= $block_score && $blocking_detection === null) {
                    $blocking_detection = array('detection' => $d, 'log_line' => $log_line);
                }
            }

            if ($blocking_detection === null) {
                return;
            }

            self::add_ip(self::get_the_ip());
            self::report_hack(lykan_types::SQL_INJECT);
            self::send_sql_injection_notification($blocking_detection['log_line']);
            self::exit_env('INJECT');
        }
    }

    /**
     * Score a SQL-injection candidate using structural SQL indicators.
     *
     * A remote substring match alone scores one point and is monitor-only.
     *
     * @param string $value Decoded candidate value.
     * @param string $pattern Matched remote pattern.
     * @return int
     */
    private static function score_sql_injection_candidate($value, $pattern) {
        $value = strtolower((string)$value);
        $score = 1;
        if (preg_match('/\b(?:union\s+(?:all\s+)?select|select\b.+\bfrom|insert\s+into|update\b.+\bset|delete\s+from|drop\s+table|information_schema|sleep\s*\(|benchmark\s*\(|load_file\s*\()/is', $value)) {
            $score += 2;
        }
        if (preg_match('/(?:--(?:\s|$)|#(?:\s|$)|\/\*)/', $value)) {
            $score++;
        }
        if (preg_match('/[\'"]\s*(?:or|and)\s+(?:[\'"]?\w+[\'"]?\s*=\s*[\'"]?\w+|true)\b/i', $value)) {
            $score += 2;
        }
        if (strlen(trim((string)$pattern)) >= 8) {
            $score++;
        }
        return $score;
    }

    /**
     * Send an optional email after a high-confidence SQL injection detection.
     *
     * @param string $log_line Sanitized detection summary.
     * @return void
     */
    private static function send_sql_injection_notification($log_line) {
        $email = trim((string)lykan_config::$config['email']);
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return;
        }

        $mail_msg = 'Hacking blocked [SQL_INJECTION]:' . PHP_EOL
            . 'IP:' . "\t" . self::get_the_ip() . PHP_EOL
            . 'Host:' . "\t" . self::get_host() . PHP_EOL
            . 'User-Agent:' . "\t" . self::get_user_agent() . PHP_EOL
            . 'Detection:' . "\t" . preg_replace('/[\r\n]+/', ' ', $log_line);
        $headers = 'From: ' . $email . "\r\n"
            . 'Reply-To: ' . $email . "\r\n"
            . 'X-Mailer: PHP/' . phpversion();
        if (!mail($email, 'IP blocked: [SQLINJECTION] ' . self::get_host(), $mail_msg, $headers, '-f' . $email)) {
            self::log_runtime_error('Unable to send SQL injection notification email.');
        }
    }


    /**
     * Collect all candidate input strings to run SQLi heuristics on.
     * - collects $_GET, $_POST (recursive), JSON body for application/json
     * - skips sensitive keys (password, token, secret, auth, etc.)
     * - normalizes and limits lengths
     *
     * Returns array of strings (non-empty, utf8, trimmed).
     */
    private static function collect_inputs_for_sqli_check() : array {
        $result = array();

        // Keys to skip (sensitive)
        $skip_keys_regex = '/pass(word)?$|pwd$|token$|secret$|auth($|orization)/i';

        // Helper: recursive walk
        $walk = function ($data, $prefix = '')use (&$walk, &$result, $skip_keys_regex) {
            if (is_array($data)) {
                foreach ($data as $k => $v) {
                    // if key looks sensitive - skip entire subtree/value
                    if (is_string($k) && preg_match($skip_keys_regex, $k)) {
                        continue;
                    }
                    $walk($v, $prefix === '' ? (string )$k : ($prefix . '.' . $k));
                }
                return;
            }

            // Only check scalar types
            if (is_scalar($data)) {
                $s = (string )$data;
                $s = trim($s);
                if ($s === '')
                    return;

                // limit length (protect from huge payloads)
                $max_len = 2048;
                if (strlen($s) > $max_len) {
                    $s = substr($s, 0, $max_len);
                }

                // ensure UTF-8 (json_encode later requires UTF-8)
                $s = self::normalize_utf8($s);

                $result[] = $s;
            }
        }
        ;

        // GET and POST (recursive)
        $walk($_GET);
        $walk($_POST);


        // Also add decoded query-string forms and URL-decoded variants to catch encoded payloads
        if (isset($_SERVER['QUERY_STRING']) && $_SERVER['QUERY_STRING'] !== '') {
            // parse_str decodes percent-encoding
            $qs = $_SERVER['QUERY_STRING'];
            parse_str($qs, $qs_arr);
            $walk($qs_arr);
            // also test raw and raw urldecoded once (shortened)
            $rawq = rawurldecode($qs);
            if ($rawq !== '') {
                $result[] = substr($rawq, 0, 2048);
            }
        }

        // optionally include cookies (be careful, cookies may contain session tokens)
        // $walk($_COOKIE);

        // remove duplicates, keep order
        $seen = array();
        $out = array();
        foreach ($result as $v) {
            if ($v === '')
                continue;
            if (isset($seen[$v]))
                continue;
            $seen[$v] = true;
            $out[] = $v;
        }

        return $out;
    }


    /**
     * lykan::detect_worm_injection()
     * 
     * @param mixed $type
     * @param mixed $itype
     * @return void
     */
    public static function detect_worm_injection(string $type, string $itype): bool {
        self::ensure_initialized();
        // quick guard: is detection active?
        if (!self::is_filter_active($type . '_injection')) {
            return false;
        }

        // get raw query string (original behaviour)
        $cracktrack = self::get_query_string();
        if (!is_string($cracktrack) || $cracktrack === '') {
            return false;
        }

        // load JSON patterns once, tolerant parsing
        $json = self::get_current_pattern_data();
        if (!is_array($json)) {
            return false;
        }

        // collect patterns from any section named like "$typeinject" or fallback to any i_term
        $patterns = array();
        $needle_key = $type . 'inject';
        foreach ($json as $section_key => $section) {
            if (!is_array($section))
                continue;
            // if JSON has the specific key, prefer it
            if ($section_key === $needle_key) {
                foreach ($section as $row) {
                    if (isset($row['i_term']))
                        $patterns[] = (string )$row['i_term'];
                }
                break;
            }
        }
        // if none found under specific key, collect all i_term entries in the JSON
        if (empty($patterns)) {
            foreach ($json as $section) {
                if (!is_array($section))
                    continue;
                foreach ($section as $row) {
                    if (isset($row['i_term']))
                        $patterns[] = (string )$row['i_term'];
                }
            }
        }

        if (empty($patterns)) {
            return false;
        }

        // normalize patterns (trim, lowercase) and dedupe
        $lc_patterns = array();
        foreach ($patterns as $p) {
            $p = trim($p);
            if ($p === '')
                continue;
            $lc_patterns[self::lower_utf8($p)] = $p; // keep original as value for reporting
        }
        if (empty($lc_patterns))
            return false;

        // variants to check: raw and rawurldecode (to catch url-encoded payloads)
        $variants = array($cracktrack);
        $decoded = @rawurldecode($cracktrack);
        if ($decoded !== false && $decoded !== $cracktrack) {
            $variants[] = $decoded;
        }

        // lowercased variants for case-insensitive search
        $lc_variants = array();
        foreach ($variants as $v) {
            $lc_variants[] = self::lower_utf8($v);
        }

        // iterate patterns and variants and stop on first match (fast path)
        $matched_pattern = null;
        $matched_variant_snippet = null;
        foreach ($lc_patterns as $lc_pat => $orig_pat) {
            foreach ($lc_variants as $variant) {
                if ($variant === '')
                    continue;
                if (self::strpos_utf8($variant, $lc_pat) !== false) {
                    $matched_pattern = $orig_pat;
                    $matched_variant_snippet = self::substr_utf8($variant, 0, 300);
                    break 2;
                }
            }
        }

        if ($matched_pattern === null) {
            // no pattern match found; nothing to do
            return false;
        }

        // pattern matched: take action (log, block, notify)
        $ip = self::get_the_ip();
        self::add_ip($ip);
        self::report_hack($itype);

        // prepare limited mail / log content (NO full payloads)
        $snippet = substr($matched_variant_snippet, 0, 300);
        $safe_snip = preg_replace('/[\r\n\t]+/', ' ', $snippet);

        // only send mail if configured
        $to = isset(lykan_config::$config['email']) ? lykan_config::$config['email'] : null;
        if ($to && filter_var($to, FILTER_VALIDATE_EMAIL)) {
            $mail_msg = 'Hacking blocked [' . strtoupper($type) . '_INJECTION]' . PHP_EOL . PHP_EOL;
            $info = array(
                'IP' => $ip,
                'Host' => self::get_host(),
                'Trace' => 'https://www.ip-tracker.org/locator/ip-lookup.php?ip=' . $ip,
                'HTTP_USER_AGENT' => isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '',
                'DetectedPattern' => $matched_pattern,
                'MatchedSnippet' => $safe_snip,
                );
            foreach ($info as $k => $v) {
                $mail_msg .= $k . ":\t" . $v . PHP_EOL;
            }
            $headers = 'From: ' . $to . "\r\n" . 'Reply-To: ' . $to . "\r\n" . 'X-Mailer: PHP/' . phpversion();
            @mail($to, 'IP blocked: [SQLINJECTION] ' . self::get_host(), $mail_msg, $headers, '-f' . $to);
        }

        // final action: exit environment (preserves existing behaviour)
        self::exit_env('INJECT');

        // detection handled
        return true;
    }


    /**
     * lykan::get_host()
     * 
     * @return string
     */
    public static function get_host(): string {
        $raw_host = isset($_SERVER['HTTP_HOST'])
            ? (string)$_SERVER['HTTP_HOST']
            : (isset($_SERVER['SERVER_NAME']) ? (string)$_SERVER['SERVER_NAME'] : '');

        // Reject header-injection characters before parsing the optional port.
        $raw_host = trim(str_replace(array("\r", "\n", "\0"), '', $raw_host));
        $parsed_host = parse_url('//' . $raw_host, PHP_URL_HOST);
        $host = is_string($parsed_host) ? $parsed_host : $raw_host;
        $host = trim(strtolower($host), "[] \t\n\r\0\x0B.");

        if ($host !== '' && function_exists('idn_to_ascii') && !filter_var($host, FILTER_VALIDATE_IP)) {
            $idn_flags = defined('IDNA_DEFAULT') ? IDNA_DEFAULT : 0;
            $idn_variant = defined('INTL_IDNA_VARIANT_UTS46') ? INTL_IDNA_VARIANT_UTS46 : 0;
            $ascii_host = @idn_to_ascii($host, $idn_flags, $idn_variant);
            if (is_string($ascii_host) && $ascii_host !== '') {
                $host = strtolower($ascii_host);
            }
        }

        // The host is also used inside filenames, so keep a deliberately small
        // character set and prevent dot sequences from becoming path markers.
        $host = preg_replace('/[^a-z0-9.-]+/', '-', $host);
        $host = preg_replace('/\.{2,}/', '.', (string)$host);
        $host = preg_replace('/-{2,}/', '-', (string)$host);
        $host = trim((string)$host, '.-');

        if (strpos($host, 'www.') === 0) {
            $host = substr($host, 4);
        }
        if ($host === '') {
            return 'unknown-host';
        }

        return substr($host, 0, 253);
    }

    /**
     * lykan::report_hack()
     *
     * Queue a sanitized report locally without delaying the blocked response.
     *
     * @param mixed $h_type
     * @param string $h_type_info
     * @param bool $adddb Whether the central service should persist the report.
     * @return bool
     */
    public static function report_hack(string $h_type, string $h_type_info = '', bool $adddb = true): bool {
        self::ensure_initialized();
        $type_info = preg_replace('/[\r\n\t\0]+/', ' ', (string)$h_type_info);
        $event = array(
            'cmd' => 'report_hack',
            'adddb' => (bool)$adddb,
            'user_agent' => self::get_user_agent(),
            'FORM' => array(
                'type' => substr((string)$h_type, 0, 100),
                'type_info' => substr(trim((string)$type_info), 0, 500),
                'domain' => self::get_host(),
                'ip' => self::get_the_ip(),
                'url' => isset($_SERVER['PHP_SELF'])
                    ? substr((string)$_SERVER['PHP_SELF'], 0, 500)
                    : '',
                'reported_at' => time()
            )
        );

        $json = json_encode($event, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($json === false) {
            self::log_runtime_error('Unable to encode hack report for the local queue.');
            return false;
        }

        $queued = self::update_locked_file(self::get_report_queue_path(), function ($current) use ($json) {
            $lines = preg_split('/\R/', trim($current), -1, PREG_SPLIT_NO_EMPTY);
            $lines[] = $json;
            $max_entries = max(1, (int)(lykan_config::$config['report_queue_max_entries'] ?? 1000));
            $lines = array_slice($lines, -$max_entries);
            return implode(PHP_EOL, $lines) . PHP_EOL;
        });
        if ($queued) {
            self::schedule_report_queue_flush();
            self::schedule_premium_notification($event);
        }
        return $queued;
    }

    private static function schedule_premium_notification(array $event): void {
        if (!self::has_capability('instant_notifications')
            || (lykan_config::$config['notification_mode'] ?? '') !== 'instant') {
            return;
        }
        register_shutdown_function(function () use ($event) {
            self::finish_response_once();
            $form = (array)($event['FORM'] ?? array());
            $email = trim((string)(lykan_config::$config['email'] ?? ''));
            if ($email !== '' && filter_var($email, FILTER_VALIDATE_EMAIL)) {
                $subject = 'LykanShield: ' . ($form['type'] ?? 'Sicherheitsereignis');
                $body = "Domain: " . ($form['domain'] ?? '') . PHP_EOL
                    . "Typ: " . ($form['type'] ?? '') . PHP_EOL
                    . "IP: " . ($form['ip'] ?? '') . PHP_EOL
                    . "Zeit: " . date('c', (int)($form['reported_at'] ?? time()));
                @mail($email, $subject, $body);
            }
            self::send_premium_webhook($event);
        });
    }

    public static function send_premium_webhook(array $event): bool {
        if (!self::has_capability('webhooks') || !function_exists('curl_init')) {
            return false;
        }
        $url = trim((string)(lykan_config::$config['webhook_url'] ?? ''));
        $parts = parse_url($url);
        if (!is_array($parts) || ($parts['scheme'] ?? '') !== 'https'
            || empty($parts['host']) || isset($parts['user']) || isset($parts['pass'])
            || (isset($parts['port']) && (int)$parts['port'] !== 443)) {
            return false;
        }
        $ips = gethostbynamel((string)$parts['host']);
        if (!is_array($ips) || count($ips) === 0) {
            return false;
        }
        foreach ($ips as $ip) {
            if (!filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                return false;
            }
        }
        $payload = json_encode($event, JSON_UNESCAPED_SLASHES);
        if (!is_string($payload)) {
            return false;
        }
        $secret = (string)(lykan_config::$config['webhook_secret'] ?? '');
        $headers = array(
            'Content-Type: application/json',
            'X-LykanShield-Signature: sha256=' . hash_hmac('sha256', $payload, $secret),
        );
        $curl = curl_init($url);
        curl_setopt_array($curl, array(
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => $payload,
            CURLOPT_HTTPHEADER => $headers,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => 3,
            CURLOPT_TIMEOUT => 5,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_PROTOCOLS => CURLPROTO_HTTPS,
            CURLOPT_RESOLVE => array($parts['host'] . ':443:' . $ips[0]),
        ));
        curl_exec($curl);
        $status = (int)curl_getinfo($curl, CURLINFO_RESPONSE_CODE);
        curl_close($curl);
        return $status >= 200 && $status < 300;
    }

    /**
     * Send queued hack reports to the central service.
     *
     * This method can be called by a cronjob on SAPIs that do not provide
     * fastcgi_finish_request().
     *
     * @param int $limit Maximum number of reports to send.
     * @return int Number of successfully delivered reports.
     */
    public static function flush_report_queue(int $limit = 20): int {
        self::ensure_initialized();
        $limit = max(1, min(100, (int)$limit));
        $queue_path = self::get_report_queue_path();
        if (!is_file($queue_path)) {
            return 0;
        }

        $claimed = array();
        if (!self::update_locked_file($queue_path, function ($current) use ($limit, &$claimed) {
            $lines = preg_split('/\R/', trim($current), -1, PREG_SPLIT_NO_EMPTY);
            $claimed = array_slice($lines, 0, $limit);
            return implode(PHP_EOL, array_slice($lines, count($claimed)))
                . (count($lines) > count($claimed) ? PHP_EOL : '');
        })) {
            return 0;
        }

        $delivered = 0;
        $failed = array();
        foreach ($claimed as $line) {
            $event = json_decode($line, true);
            if (!is_array($event) || ($event['cmd'] ?? '') !== 'report_hack') {
                self::log_runtime_error('Discarded an invalid hack-report queue entry.');
                continue;
            }
            if (lykan_client::call('POST', $event) === false) {
                $failed[] = $line;
            }
            else {
                $delivered++;
            }
        }

        if (count($failed) > 0) {
            self::update_locked_file($queue_path, function ($current) use ($failed) {
                $remaining = preg_split('/\R/', trim($current), -1, PREG_SPLIT_NO_EMPTY);
                $lines = array_merge($failed, $remaining);
                $max_entries = max(1, (int)(lykan_config::$config['report_queue_max_entries'] ?? 1000));
                return implode(PHP_EOL, array_slice($lines, 0, $max_entries)) . PHP_EOL;
            });
        }

        return $delivered;
    }

    /**
     * Return the protected local queue path.
     *
     * @return string
     */
    private static function get_report_queue_path() {
        return rtrim(self::get_root(), '/\\') . DIRECTORY_SEPARATOR . 'report_queue.jsonl';
    }

    /**
     * Schedule post-response queue processing when PHP-FPM supports it.
     *
     * @return void
     */
    private static function schedule_report_queue_flush() {
        if (self::$report_flush_scheduled || !function_exists('fastcgi_finish_request')) {
            return;
        }
        self::$report_flush_scheduled = true;
        register_shutdown_function(function () {
            self::finish_response_once();
            self::flush_report_queue(5);
        });
    }

    /**
     * Finish a PHP-FPM response once before post-response maintenance.
     *
     * @return void
     */
    private static function finish_response_once() {
        if (!self::$response_finished && function_exists('fastcgi_finish_request')) {
            self::$response_finished = true;
            fastcgi_finish_request();
        }
    }


    /**
     * lykan::get_lock()
     *
     * @param mixed $days
     * @param integer $limit
     * @return array|null
     */
    public static function get_lock(int $days, int $limit = 0): ?array {
        self::ensure_initialized();
        $domain = self::get_host();
        $days = max(1, min($days, (int)(lykan_config::$config['analytics_max_days'] ?? 1)));
        $max_limit = max(1, (int)(lykan_config::$config['analytics_leaderboard_limit'] ?? 10));
        $limit = $limit > 0 ? min($limit, $max_limit) : $max_limit;
        $arr = array(
            'cmd' => 'get_lock',
            'd' => $domain,
            'days' => $days,
            'limit' => $limit,
            'hash' => hash('sha256', $domain . $days . lykan::get_timestamp()));
        $str = lykan_client::call('FORM', $arr);
        if (!is_string($str)) {
            return null;
        }
        $decoded = json_decode($str, true);
        if (!is_array($decoded)
            || isset($decoded['error'])
            || isset($decoded['msge'])
            || (isset($decoded['status']) && $decoded['status'] === false)
            || !isset($decoded['data'], $decoded['summary'])
            || !is_array($decoded['data'])
            || !is_array($decoded['summary'])) {
            return null;
        }
        return $decoded;
    }

    public static function get_ip_history(string $ip, int $days = 365): ?array {
        self::ensure_initialized();
        if (!filter_var($ip, FILTER_VALIDATE_IP)) {
            return null;
        }
        $domain = self::get_host();
        $days = max(1, min($days, (int)(lykan_config::$config['analytics_max_days'] ?? 1)));
        $str = lykan_client::call('POST', array(
            'cmd' => 'get_ip_history',
            'days' => $days,
            'ip' => $ip,
            'domain' => $domain,
            'khash' => hash('sha256', $domain . $days . strtolower($ip) . self::get_timestamp()),
        ));
        $decoded = is_string($str) ? json_decode($str, true) : null;
        return is_array($decoded) ? $decoded : null;
    }

    public static function get_dimension_history(
        string $dimension,
        string $value = '',
        int $days = 31
    ): ?array {
        self::ensure_initialized();
        $dimension = $dimension === 'type' ? 'type' : 'country';
        $value = substr(trim($value), 0, 190);
        $domain = self::get_host();
        $days = max(1, min($days, (int)(lykan_config::$config['analytics_max_days'] ?? 1)));
        $str = lykan_client::call('POST', array(
            'cmd' => $dimension === 'type' ? 'get_type_history' : 'get_country_history',
            'days' => $days,
            'dimension' => $dimension,
            'value' => $value,
            'domain' => $domain,
            'khash' => hash(
                'sha256',
                $domain . $days . $dimension . $value . self::get_timestamp()
            ),
        ));
        $decoded = is_string($str) ? json_decode($str, true) : null;
        return is_array($decoded) ? $decoded : null;
    }

    /**
     * lykan::get_current_pattern()
     *
     * @return string Current blacklist JSON or an empty JSON object.
     */
    public static function get_current_pattern(): string {
        self::ensure_initialized();
        $path = lykan_config::$config['lykan_blacklist'];
        $lifetime_hours = isset(lykan_config::$config['blacklist_lifetime_hours']) ? (int)lykan_config::$config['blacklist_lifetime_hours'] : 0;

        if (self::$blacklist_cache_path !== $path) {
            self::reset_blacklist_cache($path);
        }
        elseif (is_string(self::$blacklist_raw_cache)) {
            return self::$blacklist_raw_cache;
        }

        $refresh_due = false;
        $has_usable_rules = false;

        // 1) Use inexpensive file metadata to decide whether a refresh is due.
        if (is_file($path)) {
            $modified_at = filemtime($path);
            if ($modified_at === false) {
                self::log_runtime_error('Unable to read blacklist modification time: ' . $path);
                $refresh_due = true;
            }
            elseif ((time() - $modified_at) > ($lifetime_hours * 3600)) {
                $refresh_due = true;
            }
        }
        else {
            $refresh_due = true;
        }

        // 2) Decode an existing file once per request. Entry-by-entry validation
        // is intentionally reserved for newly downloaded data.
        if (is_file($path)) {
            $size = filesize($path);
            if ($size === false) {
                self::log_runtime_error('Unable to read blacklist size: ' . $path);
                $refresh_due = true;
            }
            elseif ($size === 0) {
                $refresh_due = true;
            }
            elseif (!self::load_blacklist_cache($path)) {
                $refresh_due = true;
            }
            else {
                $has_usable_rules = true;
            }
        }

        // Serve valid stale rules immediately. PHP-FPM can refresh them after
        // the response; other SAPIs should invoke refresh_rules() from cron.
        if ($refresh_due && $has_usable_rules) {
            self::schedule_rule_refresh();
            return self::$blacklist_raw_cache;
        }

        // Never make a remote refresh part of request filtering. A first
        // installation temporarily follows rules_unavailable_action while
        // PHP-FPM refreshes after the response or a scheduled CLI task runs.
        if ($refresh_due && !$has_usable_rules) {
            self::schedule_rule_refresh();
        }

        // 4) A successful download has already populated the request cache.
        // Otherwise keep using a syntactically valid existing file while another
        // process performs the refresh.
        if (is_string(self::$blacklist_raw_cache)) {
            return self::$blacklist_raw_cache;
        }
        if (is_file($path) && self::load_blacklist_cache($path)) {
            return self::$blacklist_raw_cache;
        }

        // Do not overwrite a previously usable file with fallback data.
        return json_encode(array());
    }

    /**
     * Explicitly refresh remote rules. Intended for cron jobs and CLI workers.
     *
     * @param string $path Optional application root.
     * @return bool True when new rules were installed.
     */
    public static function refresh_rules(string $path = ''): bool {
        self::ensure_initialized($path);
        $target = lykan_config::$config['lykan_blacklist'];
        $lock_path = $target . '.lock';
        $lock_ttl = max(30, (int)(lykan_config::$config['download_lock_ttl_seconds'] ?? 300));

        if (is_file($lock_path)) {
            $modified_at = filemtime($lock_path);
            if ($modified_at !== false && (time() - $modified_at) >= $lock_ttl && !unlink($lock_path)) {
                self::log_runtime_error('Unable to remove stale blacklist lock: ' . $lock_path);
            }
        }

        $lock_handle = @fopen($lock_path, 'x');
        if ($lock_handle === false) {
            return false;
        }

        try {
            fwrite($lock_handle, getmypid() . "\t" . time());
            fflush($lock_handle);
            return self::download_pattern();
        }
        catch (\Throwable $e) {
            self::log_runtime_error('Blacklist update failed: ' . $e->getMessage());
            return false;
        }
        finally {
            fclose($lock_handle);
            if (is_file($lock_path) && !unlink($lock_path)) {
                self::log_runtime_error('Unable to remove blacklist lock: ' . $lock_path);
            }
        }
    }

    /**
     * Schedule stale-rule refresh after a PHP-FPM response.
     *
     * @return void
     */
    private static function schedule_rule_refresh() {
        if (self::$rule_refresh_scheduled
            || empty(lykan_config::$config['refresh_rules_after_response'])
            || !function_exists('fastcgi_finish_request')) {
            return;
        }
        self::$rule_refresh_scheduled = true;
        register_shutdown_function(function () {
            self::finish_response_once();
            self::refresh_rules();
        });
    }

    /**
     * Return the decoded blacklist and reuse it in every filter during this request.
     *
     * @return array
     */
    private static function get_current_pattern_data(): array {
        self::get_current_pattern();
        $rules = is_array(self::$blacklist_data_cache) ? self::$blacklist_data_cache : array();
        if (count($rules) === 0 && self::should_block_when_rules_unavailable('blacklist and detection rules')) {
            self::exit_env('RULES_UNAVAILABLE');
        }
        return $rules;
    }

    /**
     * Apply the configured policy when remotely maintained rules are missing.
     *
     * @param string $context Missing rule set.
     * @return bool True when the request must be blocked.
     */
    private static function should_block_when_rules_unavailable($context) {
        $action = strtolower(trim((string)(lykan_config::$config['rules_unavailable_action'] ?? 'monitor')));
        $block = $action === 'block';
        if (!self::$rules_unavailable_reported) {
            self::$rules_unavailable_reported = true;
            self::log_runtime_error_rate_limited(
                'rules-unavailable-' . ($block ? 'block' : 'monitor'),
                $context . ' unavailable; request policy is ' . ($block ? 'block' : 'monitor') . '.'
            );
        }
        return $block;
    }

    /**
     * Execute a downloaded regular expression with local PCRE resource limits.
     *
     * @param string $pattern Validated delimited PCRE pattern.
     * @param string $subject Input to inspect.
     * @param bool $matched Set to true when the expression matched.
     * @return string|false Replaced subject, or false for an invalid/failed regex.
     */
    private static function apply_remote_regex($pattern, $subject, &$matched = false) {
        $matched = false;
        $pattern = (string)$pattern;
        $max_pattern = max(32, (int)(lykan_config::$config['remote_regex_max_pattern_bytes'] ?? 512));
        if ($pattern === '' || strlen($pattern) > $max_pattern) {
            return false;
        }

        $max_subject = max(256, (int)(lykan_config::$config['request_inspection_max_bytes'] ?? 8192));
        $subject = substr((string)$subject, 0, $max_subject);
        $limited_pattern = substr($pattern, 0, 1)
            . '(*LIMIT_MATCH=100000)(*LIMIT_DEPTH=1000)'
            . substr($pattern, 1);
        $result = @preg_replace($limited_pattern, '*', $subject, -1, $count);
        if ($result === null || preg_last_error() !== PREG_NO_ERROR) {
            self::log_runtime_error_rate_limited(
                'remote-regex-failure',
                'Remote regular expression exceeded limits or failed.'
            );
            return false;
        }
        $matched = $count > 0;
        return $result;
    }

    /**
     * UTF-8 helpers that keep detection operational without ext-mbstring.
     */
    private static function lower_utf8($value) {
        return function_exists('mb_strtolower')
            ? mb_strtolower((string)$value, 'UTF-8')
            : strtolower((string)$value);
    }

    private static function strpos_utf8($haystack, $needle) {
        return function_exists('mb_strpos')
            ? mb_strpos((string)$haystack, (string)$needle, 0, 'UTF-8')
            : strpos((string)$haystack, (string)$needle);
    }

    private static function substr_utf8($value, $start, $length) {
        return function_exists('mb_substr')
            ? mb_substr((string)$value, (int)$start, (int)$length, 'UTF-8')
            : substr((string)$value, (int)$start, (int)$length);
    }

    private static function normalize_utf8($value) {
        $value = (string)$value;
        if (!function_exists('mb_check_encoding') || mb_check_encoding($value, 'UTF-8')) {
            return $value;
        }
        return function_exists('mb_convert_encoding')
            ? mb_convert_encoding($value, 'UTF-8', 'auto')
            : $value;
    }

    /**
     * Reset the in-memory blacklist cache when its configured path changes.
     *
     * @param string $path Blacklist file path.
     * @return void
     */
    private static function reset_blacklist_cache($path) {
        self::$blacklist_raw_cache = null;
        self::$blacklist_data_cache = null;
        self::$blacklist_cache_path = (string)$path;
        self::$blacklist_shard_manifest_cache = null;
        self::$blacklist_ip_shard_cache = array();
    }

    /**
     * Read and decode an installed blacklist once without revalidating all entries.
     *
     * @param string $path Blacklist file path.
     * @return bool
     */
    private static function load_blacklist_cache($path) {
        if (is_string(self::$blacklist_raw_cache) && is_array(self::$blacklist_data_cache)) {
            return true;
        }

        $json = @file_get_contents($path);
        if ($json === false) {
            self::log_runtime_error('Unable to read current blacklist: ' . $path);
            return false;
        }

        $data = json_decode($json, true);
        if (json_last_error() !== JSON_ERROR_NONE || !is_array($data) || count($data) === 0) {
            self::log_runtime_error('Installed blacklist contains invalid JSON: ' . $path);
            return false;
        }

        self::$blacklist_raw_cache = $json;
        self::$blacklist_data_cache = $data;
        self::$blacklist_cache_path = (string)$path;
        return true;
    }

    /**
     * Check an IP address in the small prefix shard assigned to that address.
     *
     * @param string $ip Client IP address.
     * @return bool
     */
    private static function is_ip_in_blacklist_shard($ip) {
        $normalized_ip = self::normalize_blacklist_ip($ip);
        $shard_key = self::get_blacklist_shard_key($normalized_ip);
        if ($normalized_ip === false || $shard_key === false) {
            return false;
        }

        $manifest = self::get_blacklist_shard_manifest();
        if (!is_array($manifest) || empty($manifest['version'])) {
            return false;
        }

        $cache_key = $manifest['version'] . ':' . $shard_key;
        if (!array_key_exists($cache_key, self::$blacklist_ip_shard_cache)) {
            $target = lykan_config::$config['lykan_blacklist'];
            $shard_file = $target . '.shards.' . $manifest['version'] . DIRECTORY_SEPARATOR . $shard_key . '.json';
            $json = @file_get_contents($shard_file);
            $entries = $json === false ? null : json_decode($json, true);
            self::$blacklist_ip_shard_cache[$cache_key] = is_array($entries) ? $entries : array();
        }

        return isset(self::$blacklist_ip_shard_cache[$cache_key][$normalized_ip]);
    }

    /**
     * Read the atomically published shard manifest once per request.
     *
     * @return array|null
     */
    private static function get_blacklist_shard_manifest() {
        if (self::$blacklist_shard_manifest_cache !== null) {
            return self::$blacklist_shard_manifest_cache;
        }

        $manifest_file = lykan_config::$config['lykan_blacklist'] . '.shards.json';
        $json = @file_get_contents($manifest_file);
        $manifest = $json === false ? null : json_decode($json, true);
        if (!is_array($manifest)
            || !isset($manifest['version'])
            || preg_match('/^[a-f0-9]{16}$/D', (string)$manifest['version']) !== 1) {
            self::$blacklist_shard_manifest_cache = array();
            return self::$blacklist_shard_manifest_cache;
        }

        self::$blacklist_shard_manifest_cache = $manifest;
        return self::$blacklist_shard_manifest_cache;
    }

    /**
     * Return a canonical representation of an IPv4 or IPv6 address.
     *
     * @param string $ip IP address.
     * @return string|false
     */
    private static function normalize_blacklist_ip($ip) {
        $binary = @inet_pton((string)$ip);
        return $binary === false ? false : inet_ntop($binary);
    }

    /**
     * Map an IP address to one of at most 512 first-byte shards.
     *
     * @param string|false $ip Canonical IP address.
     * @return string|false
     */
    private static function get_blacklist_shard_key($ip) {
        if (!is_string($ip)) {
            return false;
        }
        $binary = @inet_pton($ip);
        if ($binary === false) {
            return false;
        }
        $family = strlen($binary) === 4 ? '4' : (strlen($binary) === 16 ? '6' : '');
        return $family === '' ? false : $family . '-' . bin2hex($binary[0]);
    }


    /**
     * lykan::download_pattern()
     *
     * Download, validate and atomically install the current blacklist.
     *
     * @return bool
     */
    protected static function download_pattern() {
        $target = lykan_config::$config['lykan_blacklist'];
        $target_dir = dirname($target);
        if (!is_dir($target_dir) || !is_writable($target_dir)) {
            error_log('Lykan blacklist update failed: target directory is not writable.');
            return false;
        }

        // Keep the temporary file on the same filesystem as the destination so
        // that the final rename can replace the blacklist atomically.
        $temp_file = tempnam($target_dir, basename($target) . '.tmp.');
        if ($temp_file === false) {
            error_log('Lykan blacklist update failed: unable to create temporary file.');
            return false;
        }

        $data = array('cmd' => 'get_black_iplist');
        try {
            if (lykan_client::call('DOWNLOAD', $data, $temp_file) !== true) {
                return false;
            }

            $json = file_get_contents($temp_file);
            $decoded_data = null;
            if (!self::is_valid_blacklist_json($json, $decoded_data)) {
                error_log('Lykan blacklist update rejected: downloaded data is not a valid blacklist.');
                return false;
            }

            $badips = isset($decoded_data['badips']) && is_array($decoded_data['badips'])
                ? $decoded_data['badips']
                : array();
            $ip_entry_count = count($badips);
            $shard_version = self::install_blacklist_ip_shards($target, $badips, $json);
            if ($shard_version === false) {
                error_log('Lykan blacklist update failed: IP shards could not be installed.');
                return false;
            }

            unset($decoded_data['badips']);
            $decoded_data['_lykan'] = array(
                'ip_shards' => $shard_version,
                'ip_entries' => $ip_entry_count
            );
            $rules_json = json_encode($decoded_data, JSON_UNESCAPED_SLASHES);
            if (!is_string($rules_json)) {
                error_log('Lykan blacklist update failed: compact rules could not be encoded.');
                return false;
            }
            if (file_put_contents($temp_file, $rules_json, LOCK_EX) === false) {
                error_log('Lykan blacklist update failed: compact rules could not be written.');
                return false;
            }

            if (!chmod($temp_file, 0640)) {
                self::log_runtime_error('Unable to set blacklist file permissions: ' . $temp_file);
                return false;
            }
            if (!rename($temp_file, $target)) {
                error_log('Lykan blacklist update failed: atomic replacement was not possible.');
                return false;
            }

            $temp_file = '';
            self::$blacklist_raw_cache = $rules_json;
            self::$blacklist_data_cache = $decoded_data;
            self::$blacklist_cache_path = (string)$target;
            self::$blacklist_shard_manifest_cache = array('version' => $shard_version);
            self::$blacklist_ip_shard_cache = array();
            return true;
        }
        finally {
            if ($temp_file !== '' && is_file($temp_file)) {
                if (!unlink($temp_file)) {
                    self::log_runtime_error('Unable to remove temporary blacklist file: ' . $temp_file);
                }
            }
        }
    }

    /**
     * Build prefix-sharded IP files and publish their manifest atomically.
     *
     * @param string $target Blacklist JSON path.
     * @param array $badips Validated bad-IP map.
     * @param string $source_json Original downloaded document.
     * @return string|false Published shard version or false.
     */
    private static function install_blacklist_ip_shards($target, array $badips, $source_json) {
        $version = substr(hash('sha256', (string)$source_json), 0, 16);
        $shard_dir = $target . '.shards.' . $version;
        $created_dir = false;

        if (!is_dir($shard_dir)) {
            if (!mkdir($shard_dir, 0750)) {
                return false;
            }
            $created_dir = true;

            $shards = array();
            foreach ($badips as $ip => $entry) {
                $normalized_ip = self::normalize_blacklist_ip($ip);
                $shard_key = self::get_blacklist_shard_key($normalized_ip);
                if ($normalized_ip === false || $shard_key === false) {
                    self::remove_blacklist_shard_directory($shard_dir);
                    return false;
                }
                $shards[$shard_key][$normalized_ip] = true;
            }

            foreach ($shards as $shard_key => $entries) {
                $shard_json = json_encode($entries, JSON_UNESCAPED_SLASHES);
                $shard_file = $shard_dir . DIRECTORY_SEPARATOR . $shard_key . '.json';
                if (!is_string($shard_json)
                    || file_put_contents($shard_file, $shard_json, LOCK_EX) === false
                    || !chmod($shard_file, 0640)) {
                    self::remove_blacklist_shard_directory($shard_dir);
                    return false;
                }
            }
        }

        $manifest = json_encode(array(
            'version' => $version,
            'entries' => count($badips),
            'created_at' => time()
        ), JSON_UNESCAPED_SLASHES);
        $manifest_file = $target . '.shards.json';
        $manifest_temp = tempnam(dirname($target), basename($manifest_file) . '.tmp.');
        if (!is_string($manifest)
            || $manifest_temp === false
            || file_put_contents($manifest_temp, $manifest, LOCK_EX) === false
            || !chmod($manifest_temp, 0640)
            || !rename($manifest_temp, $manifest_file)) {
            if ($manifest_temp !== false && is_file($manifest_temp)) {
                unlink($manifest_temp);
            }
            if ($created_dir) {
                self::remove_blacklist_shard_directory($shard_dir);
            }
            return false;
        }

        self::remove_old_blacklist_shards($target, $version);
        return $version;
    }

    /**
     * Remove obsolete shard versions after a new manifest was published.
     *
     * @param string $target Blacklist JSON path.
     * @param string $active_version Version that must be retained.
     * @return void
     */
    private static function remove_old_blacklist_shards($target, $active_version) {
        $pattern = $target . '.shards.*';
        $previous_versions = array();
        foreach ((array)glob($pattern, GLOB_ONLYDIR) as $directory) {
            $suffix = substr($directory, strlen($target . '.shards.'));
            if ($directory === $target . '.shards.' . $active_version
                || preg_match('/^[a-f0-9]{16}$/D', (string)$suffix) !== 1) {
                continue;
            }
            $modified_at = filemtime($directory);
            $previous_versions[$directory] = $modified_at === false ? 0 : $modified_at;
        }

        // Keep one previous generation so requests that already read the former
        // manifest can finish safely while the new generation becomes active.
        arsort($previous_versions, SORT_NUMERIC);
        $keep_previous = true;
        foreach ($previous_versions as $directory => $modified_at) {
            if ($keep_previous) {
                $keep_previous = false;
                continue;
            }
            self::remove_blacklist_shard_directory($directory);
        }
    }

    /**
     * Remove abandoned download files and incomplete obsolete shard trees.
     *
     * Only Lykan-generated names inside the configured blacklist directory are
     * considered. Recent artifacts are retained to avoid racing an update.
     *
     * @return void
     */
    private static function cleanup_runtime_artifacts() {
        $target = isset(lykan_config::$config['lykan_blacklist'])
            ? (string)lykan_config::$config['lykan_blacklist']
            : '';
        if ($target === '' || !is_dir(dirname($target))) {
            return;
        }

        $ttl = max(1, (int)(lykan_config::$config['runtime_artifact_lifetime_hours'] ?? 24)) * 3600;
        $cutoff = time() - $ttl;
        $temp_patterns = array(
            $target . '.tmp.*',
            $target . '.shards.json.tmp.*'
        );
        foreach ($temp_patterns as $pattern) {
            foreach ((array)glob($pattern) as $file) {
                $modified_at = is_file($file) ? filemtime($file) : false;
                if ($modified_at !== false && $modified_at < $cutoff && !unlink($file)) {
                    self::log_runtime_error_rate_limited(
                        'runtime-artifact-cleanup-file',
                        'Unable to remove abandoned Lykan temporary file.'
                    );
                }
            }
        }

        $manifest = self::get_blacklist_shard_manifest();
        if (is_array($manifest) && !empty($manifest['version'])) {
            self::remove_old_blacklist_shards($target, (string)$manifest['version']);
            return;
        }

        foreach ((array)glob($target . '.shards.*', GLOB_ONLYDIR) as $directory) {
            $suffix = substr($directory, strlen($target . '.shards.'));
            $modified_at = filemtime($directory);
            if (preg_match('/^[a-f0-9]{16}$/D', (string)$suffix) === 1
                && $modified_at !== false
                && $modified_at < $cutoff) {
                self::remove_blacklist_shard_directory($directory);
            }
        }
    }

    /**
     * Remove a generated shard directory containing only flat JSON files.
     *
     * @param string $directory Generated shard directory.
     * @return void
     */
    private static function remove_blacklist_shard_directory($directory) {
        if (!is_dir($directory)) {
            return;
        }
        foreach ((array)glob($directory . DIRECTORY_SEPARATOR . '*.json') as $file) {
            if (is_file($file) && !unlink($file)) {
                self::log_runtime_error('Unable to remove obsolete blacklist shard: ' . $file);
                return;
            }
        }
        if (!rmdir($directory)) {
            self::log_runtime_error('Unable to remove obsolete blacklist shard directory: ' . $directory);
        }
    }

    /**
     * Accept only non-empty JSON objects containing known blacklist sections.
     *
     * @param string|false $json Downloaded JSON document.
     * @param array|null $decoded_data Validated decoded document.
     * @return bool
     */
    private static function is_valid_blacklist_json($json, &$decoded_data = null) {
        $decoded_data = null;
        if (!is_string($json) || trim($json) === '') {
            return false;
        }

        $data = json_decode($json, true);
        if (json_last_error() !== JSON_ERROR_NONE || !is_array($data) || count($data) === 0) {
            return false;
        }

        $validators = array(
            'badips' => 'is_valid_blacklist_ip_entry',
            'bots' => 'is_valid_blacklist_bot_entry',
            'mime' => 'is_valid_blacklist_mime_entry',
            'xssinject' => 'is_valid_blacklist_regex_entry',
            'sqlinject' => 'is_valid_blacklist_sql_entry',
            'worm' => 'is_valid_blacklist_regex_entry'
        );
        $max_entries = max(1, (int)(lykan_config::$config['blacklist_max_entries_per_section'] ?? 50000));
        $validated_entries = 0;

        foreach ($validators as $section => $validator) {
            if (!array_key_exists($section, $data)) {
                continue;
            }
            if (!is_array($data[$section]) || count($data[$section]) > $max_entries) {
                return false;
            }
            foreach ($data[$section] as $key => $entry) {
                if (!self::{$validator}($entry, $key)) {
                    return false;
                }
                $validated_entries++;
            }
        }

        if ($validated_entries === 0) {
            return false;
        }

        $decoded_data = $data;
        return true;
    }

    /**
     * Validate an entry from the remote bad-IP map.
     *
     * @param mixed $entry Entry value.
     * @param mixed $key Entry key containing the IP address.
     * @return bool
     */
    private static function is_valid_blacklist_ip_entry($entry, $key) {
        if (!is_string($key) || filter_var($key, FILTER_VALIDATE_IP) === false) {
            return false;
        }
        if (is_scalar($entry) || $entry === null) {
            return true;
        }
        if (!is_array($entry) || count($entry) > 10) {
            return false;
        }
        foreach ($entry as $value) {
            if (!is_scalar($value) && $value !== null) {
                return false;
            }
        }
        return true;
    }

    /**
     * Validate a remote bot signature.
     *
     * @param mixed $entry Bot record.
     * @param mixed $key Entry key.
     * @return bool
     */
    private static function is_valid_blacklist_bot_entry($entry, $key) {
        if (!is_array($entry) || !isset($entry['b_bot'])) {
            return false;
        }
        $signature = trim((string)$entry['b_bot']);
        return strlen($signature) >= 2 && strlen($signature) <= 255;
    }

    /**
     * Validate a remote MIME allowlist record.
     *
     * @param mixed $entry MIME record.
     * @param mixed $key Entry key.
     * @return bool
     */
    private static function is_valid_blacklist_mime_entry($entry, $key) {
        if (!is_array($entry) || !isset($entry['m_mime'])) {
            return false;
        }
        return preg_match('/^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+*-]+$/i', trim((string)$entry['m_mime'])) === 1;
    }

    /**
     * Validate a plain SQL-injection signature.
     *
     * @param mixed $entry SQL signature record.
     * @param mixed $key Entry key.
     * @return bool
     */
    private static function is_valid_blacklist_sql_entry($entry, $key) {
        if (!is_array($entry) || !isset($entry['i_term'])) {
            return false;
        }
        $term = trim((string)$entry['i_term']);
        return $term !== '' && strlen($term) <= 1000 && strpos($term, "\0") === false;
    }

    /**
     * Validate a regular-expression injection signature.
     *
     * @param mixed $entry Regex signature record.
     * @param mixed $key Entry key.
     * @return bool
     */
    private static function is_valid_blacklist_regex_entry($entry, $key) {
        if (!self::is_valid_blacklist_sql_entry($entry, $key)) {
            return false;
        }
        $pattern = (string)$entry['i_term'];
        $max_pattern = max(32, (int)(lykan_config::$config['remote_regex_max_pattern_bytes'] ?? 512));
        if (strlen($pattern) > $max_pattern) {
            return false;
        }
        $limited_pattern = substr($pattern, 0, 1)
            . '(*LIMIT_MATCH=100000)(*LIMIT_DEPTH=1000)'
            . substr($pattern, 1);
        return @preg_match($limited_pattern, '') !== false && preg_last_error() === PREG_NO_ERROR;
    }

    /**
     * lykan::get_timestamp()
     * 
     * @return string
     */
    public static function get_timestamp(): string {
        $now = new DateTime("now", new DateTimeZone('CET'));
        return date('YmdHi', strtotime($now->format('Y-m-d H:i:s')) - $now->format('Z'));
    }
}

class lykan_client {

    protected static string $endpoint = 'https://www.lykanshield.io/rest/';

    /**
     * append_error_log()
     * Keeps only the last 30 error lines inside the Lykan data/download directory.
     */
    protected static function append_error_log($message) {
        $root = rtrim(lykan_config::$config['root'], DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
        $path = $root . 'lykan_error.log';

        $entry = date('c') . "\t" . $message;
        $fp = @fopen($path, 'c+b');
        if ($fp === false) {
            error_log('Lykan: unable to open its error log: ' . $path);
            return false;
        }
        if (!flock($fp, LOCK_EX)) {
            error_log('Lykan: unable to lock its error log: ' . $path);
            fclose($fp);
            return false;
        }

        $current = stream_get_contents($fp);
        $lines = preg_split('/\R/', trim((string)$current), -1, PREG_SPLIT_NO_EMPTY);
        $lines[] = $entry;
        $lines = array_slice($lines, -30);
        $contents = implode(PHP_EOL, $lines) . PHP_EOL;
        rewind($fp);
        $success = ftruncate($fp, 0) && fwrite($fp, $contents) === strlen($contents);
        fflush($fp);
        flock($fp, LOCK_UN);
        fclose($fp);
        if (!$success) {
            error_log('Lykan: unable to write its error log: ' . $path);
        }
        return $success;
    }

    /**
     * Send a hardened HTTPS request to the Lykan service.
     *
     * @param string $method GET, POST, FORM or DOWNLOAD.
     * @param array $data Request payload.
     * @param string $local_file Download destination for DOWNLOAD requests.
     * @return string|bool Response body, download status or false on failure.
     */
    public static function call(string $method, array $data, string $local_file = ''): string|bool {
        $method = strtoupper(trim((string)$method));
        if (!in_array($method, array('GET', 'POST', 'FORM', 'DOWNLOAD'), true)) {
            self::append_error_log('Unsupported Lykan HTTP method: ' . $method);
            return false;
        }
        if (!function_exists('curl_init')) {
            self::append_error_log('Lykan connection failure: PHP cURL extension is unavailable.');
            return false;
        }

        $is_form_request = $method === 'FORM';
        $url = static::$endpoint;
        $scheme = strtolower((string)parse_url($url, PHP_URL_SCHEME));
        if ($scheme !== 'https') {
            self::append_error_log('Lykan connection failure: endpoint must use HTTPS.');
            return false;
        }

        if (!$is_form_request) {
            $data['apikey'] = (lykan_config::$config['apikey'] != "") ? lykan_config::$config['apikey'] : "";
            $data['host'] = lykan::get_host();
            $entitlement = (array)(lykan_config::$config['license_entitlement'] ?? array());
            if (!empty($entitlement['signature'])) {
                $data['entitlement'] = $entitlement;
            }
            $data['hash'] = hash('sha512', implode(':', [$data['apikey'], $data['host'], lykan::get_timestamp()]));
        }
        if ($method === 'GET') {
            $query = http_build_query($data, '', '&', PHP_QUERY_RFC3986);
            $url .= (strpos($url, '?') === false ? '?' : '&') . $query;
        }

        $json_data = json_encode($data, JSON_UNESCAPED_SLASHES);
        if ($json_data === false) {
            self::append_error_log('Lykan connection failure: unable to encode request JSON: ' . json_last_error_msg());
            return false;
        }

        $curl = curl_init();
        if ($curl === false) {
            self::append_error_log('Lykan connection failure: unable to initialize cURL.');
            return false;
        }

        $connect_timeout = max(1, (int)(lykan_config::$config['client_connect_timeout_seconds'] ?? 10));
        $total_timeout = max($connect_timeout, (int)(lykan_config::$config['client_timeout_seconds'] ?? 30));
        $max_download_bytes = max(1024, (int)(lykan_config::$config['client_max_download_bytes'] ?? (10 * 1024 * 1024)));
        $options = array(
            CURLOPT_URL => $url,
            CURLOPT_USERAGENT => 'LykanShield/1.9',
            CURLOPT_CONNECTTIMEOUT => $connect_timeout,
            CURLOPT_TIMEOUT => $total_timeout,
            CURLOPT_NOSIGNAL => true,
            CURLOPT_FRESH_CONNECT => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_MAXREDIRS => 0,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_HEADER => false,
            CURLOPT_HTTPHEADER => array(
                'Content-Type: ' . ($is_form_request
                    ? 'application/x-www-form-urlencoded'
                    : 'application/json'),
                'Accept: application/json',
                'Cache-Control: no-cache, no-store, must-revalidate'
            )
        );
        if (defined('CURLOPT_PROTOCOLS') && defined('CURLPROTO_HTTPS')) {
            $options[CURLOPT_PROTOCOLS] = CURLPROTO_HTTPS;
        }
        if (defined('CURLOPT_REDIR_PROTOCOLS') && defined('CURLPROTO_HTTPS')) {
            $options[CURLOPT_REDIR_PROTOCOLS] = CURLPROTO_HTTPS;
        }

        $fp = null;
        switch ($method) {
            case 'FORM':
                $options[CURLOPT_POST] = true;
                $options[CURLOPT_RETURNTRANSFER] = true;
                $options[CURLOPT_POSTFIELDS] = http_build_query(
                    $data,
                    '',
                    '&',
                    PHP_QUERY_RFC3986
                );
                break;
            case 'POST':
                $options[CURLOPT_POST] = true;
                $options[CURLOPT_RETURNTRANSFER] = true;
                $options[CURLOPT_POSTFIELDS] = $json_data;
                break;
            case 'DOWNLOAD':
                if ($local_file === '') {
                    curl_close($curl);
                    self::append_error_log('Lykan connection failure: download target is empty.');
                    return false;
                }
                $fp = fopen($local_file, 'wb');
                if ($fp === false) {
                    curl_close($curl);
                    error_log('Lykan connection failure: unable to write to ' . $local_file);
                    self::append_error_log('Lykan connection failure: unable to write to ' . $local_file);
                    return false;
                }
                $options[CURLOPT_POST] = true;
                $options[CURLOPT_POSTFIELDS] = $json_data;
                $options[CURLOPT_FILE] = $fp;
                if (defined('CURLOPT_MAXFILESIZE_LARGE')) {
                    $options[CURLOPT_MAXFILESIZE_LARGE] = $max_download_bytes;
                }
                else {
                    $options[CURLOPT_MAXFILESIZE] = $max_download_bytes;
                }
                break;
            case 'GET':
                $options[CURLOPT_HTTPGET] = true;
                $options[CURLOPT_RETURNTRANSFER] = true;
                break;
        }

        if (!curl_setopt_array($curl, $options)) {
            if (is_resource($fp)) {
                fclose($fp);
            }
            curl_close($curl);
            if ($method === 'DOWNLOAD' && is_file($local_file) && !unlink($local_file)) {
                self::append_error_log('Unable to remove unconfigured download target: ' . $local_file);
            }
            self::append_error_log('Lykan connection failure: unable to configure cURL.');
            return false;
        }
        $result = curl_exec($curl);
        $curl_error = curl_error($curl);
        $http_code = (int)curl_getinfo($curl, CURLINFO_HTTP_CODE);
        $content_type = strtolower((string)curl_getinfo($curl, CURLINFO_CONTENT_TYPE));
        curl_close($curl);
        if (is_resource($fp)) {
            fflush($fp);
            fclose($fp);
        }

        // Only explicit HTTP success responses are accepted. Redirects are
        // rejected so the client never sends credentials to another endpoint.
        $is_failure = ($result === false)
            || $http_code < 200
            || $http_code >= 300
            || ($is_form_request && strpos($content_type, 'application/json') === false);
        if ($is_failure) {
            if ($method === 'DOWNLOAD' && !empty($local_file) && is_file($local_file)) {
                if (!unlink($local_file)) {
                    self::append_error_log('Unable to remove incomplete download: ' . $local_file);
                }
            }
            $log_msg = 'Lykan connection failure';
            if (!empty($curl_error)) {
                $log_msg .= ': ' . $curl_error;
            }
            elseif ($http_code > 0) {
                $log_msg .= ': HTTP ' . $http_code;
                if ($is_form_request && strpos($content_type, 'application/json') === false) {
                    $log_msg .= ', unexpected content type ' . ($content_type !== '' ? $content_type : 'unknown');
                }
            }
            else {
                $log_msg .= ': no HTTP response';
            }
            error_log($log_msg);
            self::append_error_log($log_msg);
            return false;
        }

        if ($method === 'DOWNLOAD') {
            if (!is_file($local_file)) {
                return false;
            }
            $download_size = filesize($local_file);
            if ($download_size === false || $download_size > $max_download_bytes) {
                if (is_file($local_file) && !unlink($local_file)) {
                    self::append_error_log('Unable to remove oversized download: ' . $local_file);
                }
                self::append_error_log('Lykan connection failure: invalid download size.');
                return false;
            }
            return true;
        }

        return $result;
    }
}

class lykan_exploit {

    private static string $queryString = '';

    /**
     * Inspect the current query string for common exploit signatures.
     *
     * @return void
     */
    public static function check_for_exploit(): void {
        if (isset($_SERVER['QUERY_STRING'])) {
            static::$queryString = $_SERVER['QUERY_STRING'];
        }
        else {
            static::$queryString = http_build_query(array_merge($_POST, $_GET));
        }

        if (!empty(static::$queryString)) {
            if (self::contains_base64encode(static::$queryString) || self::contains_script_tag(static::$queryString) || self::contains_global_variable(static::$queryString) ||
                self::contains_request_variable(static::$queryString)) {
                self::deny_access();
            }
        }
    }

    /**
     * Check for an attempted base64_encode function call.
     *
     * @param string $query Query string to inspect.
     * @return bool
     */
    private static function contains_base64encode(string $query): bool {
        return preg_match('/base64_encode\([^)]*\)/', $query) === 1;
    }

    /**
     * Check for literal or URL-encoded script tags.
     *
     * @param string $query Query string to inspect.
     * @return bool
     */
    private static function contains_script_tag(string $query): bool {
        return preg_match('/<\s*script\b[^>]*>|%3C(?:%20)*script\b.*?%3E/i', $query) === 1;
    }

    /**
     * Check for attempts to manipulate the GLOBALS array.
     *
     * @param string $query Query string to inspect.
     * @return bool
     */
    private static function contains_global_variable(string $query): bool {
        return preg_match('/GLOBALS(=|\[|\%[0-9A-Z]{0,2})/', $query) === 1;
    }

    /**
     * Check for attempts to manipulate the request superglobal.
     *
     * @param string $query Query string to inspect.
     * @return bool
     */
    private static function contains_request_variable(string $query): bool {
        return preg_match('/_REQUEST(=|\[|\%[0-9A-Z]{0,2})/', $query) === 1;
    }

    /**
     * Report the detected exploit and stop request processing.
     *
     * @return void
     */
    private static function deny_access(): never {
        lykan::report_hack(lykan_types::EXPLOIT, static::$queryString, false);
        lykan::exit_env(lykan_types::EXPLOIT);
    }
}

class lykan_types {
    public const BAD_IP = 'BAD_IP';
    public const STD = 'DEFAULT';
    public const SQL_INJECT = 'SQL_INJECT';
    public const EXPLOIT = 'EXPLOIT';
    public const MIME_FILE_UPLOAD = 'MIME_FILE_UPLOAD';
    public const DOUBLEUSE_ACCOUNT = 'DOUBLEUSE_ACCOUNT';
    public const FILE_INJECT = 'FILE_INJECT';
    public const XSS_INJECT = 'XSS_INJECT';
    public const BAD_USER_POST = 'BAD_USER_POST';
    public const BLACK_LIST_BOT = 'BLACK_LIST_BOT';
    public const INVALID_USER_AGENT = 'INVALID_USER_AGENT';
    public const WORM_INJECT = 'WORM_INJECT';
    public const HTTP_INJECTION = 'HTTP_INJECTION';
    public const CONTACTFORM_HIDDENMAILFIELD = 'CONTACTFORM_HIDDENMAILFIELD';
    public const B8 = 'B8';
    public const REDIRECT_PARAM = 'REDIRECT_PARAM';
    public const INVALIDHASH = 'INVALIDHASH';
    public const SECUREDOWNLOAD = 'SECUREDOWNLOAD';
    public const CMD_WITH_NO_PERMISSIONS = 'CMD_WITH_NO_PERMISSIONS';
    public const MAIL_HACKING = 'MAIL_HACKING';
    public const ADMINLOGIN = 'ADMINLOGIN';
    public const BAD_LOCAL_IP = 'BAD_LOCAL_IP';
}

/**
 * payload_logger
 *
 * Static logger that writes a TSV (tab-separated) log line for every page request to:
 *   CMS_ROOT . 'file_data/lykan/pageload.xls'
 *
 * - Uses fputcsv with "\t" delimiter (Excel opens it directly)
 * - Creates directory + .htaccess / web.config protection
 * - Restrictive chmod and simple file rotation
 * - Collects maximum request and client info (IP, headers, payload, etc.)
 *
 * Conventions:
 * - Function names snake_case
 * - Arrays use array()
 * - Comments in English
 */

class payload_logger {
    private static string $rel_path = 'pageload.xls';
    private static int $dir_mode = 0750;
    private static int $file_mode = 0640;
    private static int $max_bytes = 10 * 1024 * 1024; // rotate at 10MB
    private static int $max_age_seconds = 3600; // delete the active log after one hour

    /**
     * log_request()
     * 
     * @param mixed $root
     * @return bool
     */
    public static function log_request(string $root): bool {
        try {
            $full_dir = dirname($root . self::$rel_path);
            if (!self::ensure_dir_and_protect($full_dir)) {
                return false;
            }

            $file = $root . self::$rel_path;
            if (!self::rotate_if_needed($file)) {
                return false;
            }

            $fp = @fopen($file, 'a+b');
            if ($fp === false) {
                self::log_error('Unable to open payload log: ' . $file);
                return false;
            }
            if (!flock($fp, LOCK_EX)) {
                self::log_error('Unable to lock payload log: ' . $file);
                fclose($fp);
                return false;
            }

            $stats = fstat($fp);
            $is_new = !is_array($stats) || (int)$stats['size'] === 0;
            $record = self::build_record();
            if ($is_new) {
                $header = array(
                    'iso_ts',
                    'ts',
                    'remote_ip',
                    'forwarded_for',
                    'remote_port',
                    'host',
                    'request_method',
                    'request_uri',
                    'query_string',
                    'script_name',
                    'php_sapi',
                    'server_name',
                    'server_addr',
                    'user_agent',
                    'referer',
                    'accept_language',
                    'cookies',
                    'get',
                    'post',
                    'raw_body_meta',
                    'headers',
                    'env',
                    'process_id',
                    'session_id');
                if (fputcsv($fp, $header, "\t", '"') === false) {
                    self::log_error('Unable to write payload-log header: ' . $file);
                }
            }

            $success = fputcsv($fp, $record, "\t", '"') !== false;
            fflush($fp);
            flock($fp, LOCK_UN);
            fclose($fp);
            if ($is_new && !chmod($file, self::$file_mode)) {
                self::log_error('Unable to set payload-log permissions: ' . $file);
            }
            if (!$success) {
                self::log_error('Unable to write payload-log record: ' . $file);
            }

            return $success;
        }
        catch (\Throwable $e) {
            self::log_error('Payload logging failed: ' . $e->getMessage());
            return false;
        }
    }

    /**
     * Rotate the payload log when it exceeds the configured size limit.
     *
     * @param string $file Payload-log file path.
     * @return bool
     */
    private static function rotate_if_needed($file) {
        $lock_file = $file . '.rotation.lock';
        $lock = @fopen($lock_file, 'c');
        if ($lock === false) {
            self::log_error('Unable to open payload rotation lock: ' . $lock_file);
            return false;
        }
        if (!flock($lock, LOCK_EX)) {
            self::log_error('Unable to acquire payload rotation lock: ' . $lock_file);
            fclose($lock);
            return false;
        }

        $success = true;
        if (is_file($file)) {
            $modified_at = filemtime($file);
            if ($modified_at === false) {
                self::log_error('Unable to read payload-log modification time: ' . $file);
                $success = false;
            }
            elseif ((time() - $modified_at) >= self::$max_age_seconds) {
                if (!unlink($file)) {
                    self::log_error('Unable to delete expired payload log: ' . $file);
                    $success = false;
                }
            }
        }

        if ($success && is_file($file)) {
            $size = filesize($file);
            if ($size === false) {
                self::log_error('Unable to read payload-log size: ' . $file);
                $success = false;
            }
            elseif ($size > self::$max_bytes) {
                $success = self::rotate_file($file);
                if ($success) {
                    self::remove_old_backups($file);
                }
            }
        }

        flock($lock, LOCK_UN);
        fclose($lock);
        return $success;
    }

    /**
     * Remove the oldest payload-log backups above the retention limit.
     *
     * @param string $file Base payload-log file path.
     * @return void
     */
    private static function remove_old_backups($file) {
        $backups = glob($file . '.*.bak');
        if (!is_array($backups) || count($backups) <= 10) {
            return;
        }
        usort($backups, function ($a, $b) {
            return (int)filemtime($a) <=> (int)filemtime($b);
        });
        foreach (array_slice($backups, 0, count($backups) - 10) as $old_file) {
            if (!unlink($old_file)) {
                self::log_error('Unable to remove old payload-log backup: ' . $old_file);
            }
        }
    }

    /**
     * Write a payload-logger error to the configured PHP error log.
     *
     * @param string $message Error message without the logger prefix.
     * @return void
     */
    private static function log_error($message) {
        error_log('Lykan payload logger: ' . $message);
    }


    /**
     * build_record()
     * 
     * @return array
     */
    private static function build_record() {
        $now = time();
        $iso = date('c', $now);

        $remote_ip = self::get_the_ip();
        $forwarded_for = isset($_SERVER['HTTP_X_FORWARDED_FOR']) ? $_SERVER['HTTP_X_FORWARDED_FOR'] : '';
        $remote_port = isset($_SERVER['REMOTE_PORT']) ? $_SERVER['REMOTE_PORT'] : '';
        $host = lykan::get_host();
        $method = isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : '-';
        $request_uri = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '-';
        $query_string = isset($_SERVER['QUERY_STRING']) ? $_SERVER['QUERY_STRING'] : '';
        $script_name = isset($_SERVER['SCRIPT_NAME']) ? $_SERVER['SCRIPT_NAME'] : '';
        $php_sapi = php_sapi_name();
        $server_name = isset($_SERVER['SERVER_NAME']) ? $_SERVER['SERVER_NAME'] : '';
        $server_addr = isset($_SERVER['SERVER_ADDR']) ? $_SERVER['SERVER_ADDR'] : '';
        $user_agent = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
        $referer = isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : '';
        $accept_language = isset($_SERVER['HTTP_ACCEPT_LANGUAGE']) ? $_SERVER['HTTP_ACCEPT_LANGUAGE'] : '';
        $get = isset($_GET) ? $_GET : array();
        $post = isset($_POST) ? $_POST : array();
        $headers = self::get_request_headers();

        $env = array(
            'REMOTE_ADDR' => isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '',
            'SERVER_PROTOCOL' => isset($_SERVER['SERVER_PROTOCOL']) ? $_SERVER['SERVER_PROTOCOL'] : '',
            'HTTPS' => (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 1 : 0,
            'HTTP_X_REQUESTED_WITH' => isset($_SERVER['HTTP_X_REQUESTED_WITH']) ? $_SERVER['HTTP_X_REQUESTED_WITH'] : '',
            );

        $process_id = getmypid();
        // Do not retain cookie values, raw request bodies or session IDs.
        $cookies = array('captured' => false);
        $raw_body_meta = array(
            'captured' => false,
            'content_type' => isset($_SERVER['CONTENT_TYPE']) ? (string)$_SERVER['CONTENT_TYPE'] : ''
        );
        $session_id = '';

        $get = self::sanitize_sensitive_data($get);
        $post = self::sanitize_sensitive_data($post);
        $headers = self::sanitize_sensitive_data($headers);
        $query_string = self::sanitize_query_string($query_string);
        $request_uri = preg_replace('/[?#].*$/', '', $request_uri);
        $referer = preg_replace('/[?#].*$/', '', $referer);

        $json_cookies = self::json_safe($cookies);
        $json_get = self::json_safe($get);
        $json_post = self::json_safe($post);
        $json_headers = self::json_safe($headers);
        $json_env = self::json_safe($env);
        $json_raw_body_meta = self::json_safe($raw_body_meta);

        return array(
            $iso,
            $now,
            $remote_ip,
            $forwarded_for,
            $remote_port,
            $host,
            $method,
            $request_uri,
            $query_string,
            $script_name,
            $php_sapi,
            $server_name,
            $server_addr,
            $user_agent,
            $referer,
            $accept_language,
            $json_cookies,
            $json_get,
            $json_post,
            $json_raw_body_meta,
            $json_headers,
            $json_env,
            $process_id,
            $session_id);
    }

    /**
     * Recursively remove secrets from request arrays before logging.
     *
     * @param mixed $data Request data to sanitize.
     * @return mixed
     */
    private static function sanitize_sensitive_data($data) {
        if (!is_array($data)) {
            return $data;
        }

        $clean = array();
        foreach ($data as $key => $value) {
            if (self::is_sensitive_key((string)$key)) {
                continue;
            }
            $clean[$key] = is_array($value)
                ? self::sanitize_sensitive_data($value)
                : $value;
        }
        return $clean;
    }

    /**
     * Identify field and header names that commonly contain credentials.
     *
     * @param string $key Field or header name.
     * @return bool
     */
    private static function is_sensitive_key($key) {
        $normalized = strtolower(str_replace(array('-', ' ', '.'), '_', trim($key)));
        return preg_match(
            '/(?:^|_)(?:access_?token|api_?key|auth(?:orization)?|client_?secret|cookie|credential|csrf|jwt|pass(?:word|wort|wd)?|private_?key|refresh_?token|session|secret|token|xsrf)(?:_|$)/',
            $normalized
        ) === 1;
    }

    /**
     * Remove sensitive parameters from a URL query string.
     *
     * @param string $query_string Raw query string.
     * @return string
     */
    private static function sanitize_query_string($query_string) {
        if (trim($query_string) === '') {
            return '';
        }

        $parameters = array();
        parse_str($query_string, $parameters);
        $parameters = self::sanitize_sensitive_data($parameters);
        return http_build_query($parameters, '', '&', PHP_QUERY_RFC3986);
    }


    /**
     * ensure_dir_and_protect()
     *
     * Create and protect the payload-log directory.
     *
     * @param string $dir Directory path.
     * @return bool
     */
    private static function ensure_dir_and_protect($dir) {
        if (!is_dir($dir) && !mkdir($dir, self::$dir_mode, true)) {
            self::log_error('Unable to create payload-log directory: ' . $dir);
            return false;
        }
        if (!chmod($dir, self::$dir_mode)) {
            self::log_error('Unable to set payload-log directory permissions: ' . $dir);
            return false;
        }

        // .htaccess
        $htaccess = $dir . DIRECTORY_SEPARATOR . '.htaccess';
        if (!is_file($htaccess)) {
            $content = implode("\n", array(
                "# Prevent web access to this directory",
                "<IfModule mod_authz_core.c>",
                "    Require all denied",
                "</IfModule>",
                "<IfModule !mod_authz_core.c>",
                "    Order allow,deny",
                "    Deny from all",
                "</IfModule>"));
            if (file_put_contents($htaccess, $content, LOCK_EX) === false || !chmod($htaccess, 0640)) {
                self::log_error('Unable to create Apache payload-log protection: ' . $htaccess);
                return false;
            }
        }

        // IIS: web.config
        $webconfig = $dir . DIRECTORY_SEPARATOR . 'web.config';
        if (!is_file($webconfig)) {
            $wcontent = '<?xml version="1.0" encoding="UTF-8"?>
<configuration>
  <system.webServer>
    <security>
      <authorization>
        <remove users="?" roles="" verbs=""/>
        <add accessType="Deny" users="*" />
      </authorization>
    </security>
  </system.webServer>
</configuration>';
            if (file_put_contents($webconfig, $wcontent, LOCK_EX) === false || !chmod($webconfig, 0640)) {
                self::log_error('Unable to create IIS payload-log protection: ' . $webconfig);
                return false;
            }
        }

        // index.html for safety
        $index = $dir . DIRECTORY_SEPARATOR . 'index.html';
        if (!is_file($index)) {
            if (
                file_put_contents($index, '<!doctype html><html><head><meta charset="utf-8"><title>Forbidden</title></head><body>Forbidden.</body></html>', LOCK_EX) === false
                || !chmod($index, 0644)
            ) {
                self::log_error('Unable to create payload-log directory index: ' . $index);
                return false;
            }
        }
        return true;
    }

    /**
     * rotate_file()
     *
     * Rename the current payload log to a timestamped backup.
     *
     * @param string $file Payload-log file path.
     * @return bool
     */
    private static function rotate_file($file) {
        $bak = $file . '.' . date('Ymd_His') . '.bak';
        if (!rename($file, $bak)) {
            self::log_error('Unable to rotate payload log: ' . $file);
            return false;
        }
        return true;
    }

    /**
     * get_the_ip()
     * 
     * @return string
     */
    private static function get_the_ip() {
        return lykan::get_the_ip();
    }

    /**
     * get_request_headers()
     * 
     * @return array
     */
    private static function get_request_headers() {
        if (function_exists('getallheaders')) {
            $h = @getallheaders();
            return is_array($h) ? $h : array();
        }
        $headers = array();
        foreach ($_SERVER as $name => $value) {
            if (substr($name, 0, 5) == 'HTTP_') {
                $key = str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($name, 5)))));
                $headers[$key] = $value;
            }
        }
        return $headers;
    }

    /**
     * json_safe()
     * 
     * @param mixed $data
     * @return string
     */
    private static function json_safe($data) {
        $j = json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($j === false) {
            self::log_error('Unable to JSON-encode payload-log data: ' . json_last_error_msg());
            return '{"encoding_error":true}';
        }
        return $j;
    }
}
