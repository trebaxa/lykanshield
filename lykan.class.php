<?php

/**
 * lykan class
 *
 * @see       https://github.com/trebaxa/lykanshield
 * @version   1.9  
 * @author    Harald Petrich <service@trebaxa.com>
 * @copyright 2018 - 2024 Harald Petrich
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
    public static $config = array(
        'apikey' => '', # from lykanshield.io, not needed for protection
        'hcache_lifetime_hours' => 3, # cache lifetime in hours of filter files
        'blacklist_lifetime_hours' => 1, #locale blocked IPs life time
        'log_lines_count' => 98,
        'email' => '', #mail to send an info about sql injection attack
        'filter_active' => array(
            'mime_types' => true, #activates mime filter
            'file_inject' => true, # file injection filter
            'bad_bots' => true, # bad bot filter
            'bad_user_post' => true, # bad user post
            'bad_ips' => true, # bad IP filter
            'sql_injection' => true, # SQL Injection filter
            'worm_injection' => true, # WORM Injection filter
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

    protected static $lykan_root = "";
    protected static $host = "";

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


        if (!is_dir(lykan_config::$config['hpath']))
            mkdir(lykan_config::$config['hpath'], 0755);

        $dir = rtrim(self::get_root(), DIRECTORY_SEPARATOR);
        if (!is_dir($dir) || !is_file($dir . DIRECTORY_SEPARATOR . 'index.html')) {
            // create directory
            @mkdir($dir, 0750, true);

            // try to set strict permissions (best-effort)
            @chmod($dir, 0750);

            // create a simple index.html so directory listings show nothing (fallback)
            $index_file = $dir . DIRECTORY_SEPARATOR . 'index.html';
            if (!is_file($index_file)) {
                @file_put_contents($index_file, '<!doctype html><meta charset="utf-8"><title>Forbidden</title>');
                @chmod($index_file, 0640);
            }

            // create an Apache .htaccess that denies access (best for Apache setups)
            $htaccess = $dir . DIRECTORY_SEPARATOR . '.htaccess';
            if (!is_file($htaccess)) {
                // For modern Apache: "Require all denied" is preferred, but include both for compatibility
                $ht_content = "Order deny,allow\nDeny from all\n<IfModule mod_authz_core.c>\n  Require all denied\n</IfModule>\n";
                @file_put_contents($htaccess, $ht_content);
                @chmod($htaccess, 0640);
            }

            // create an empty .user.ini (optional) to prevent php settings exposure (shared hosts)
            $userini = $dir . DIRECTORY_SEPARATOR . '.user.ini';
            if (!is_file($userini)) {
                @file_put_contents($userini, "display_errors = Off\n");
                @chmod($userini, 0640);
            }
        }
        else {
            // try to tighten permissions on existing dir (best-effort)
            @chmod($dir, 0750);
        }
    }

    /**
     * lykan::get_the_ip()
     * 
     * @return
     */
    public static function get_the_ip() {
        return (isset($_SERVER['HTTP_CLIENT_IP']) ? $_SERVER['HTTP_CLIENT_IP'] : isset($_SERVER['HTTP_X_FORWARDED_FOR'])) ? $_SERVER['HTTP_X_FORWARDED_FOR'] : $_SERVER['REMOTE_ADDR'];
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
     * lykan::is_valid_json()
     * 
     * @param mixed $str
     * @return
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
    public static function load_config() {
        $conf_file = self::get_root() . 'config.json';
        if (is_file($conf_file)) {
            $json = file_get_contents($conf_file);
            if (self::is_valid_json($json)) {
                $arr = json_decode($json, true);
                lykan_config::$config = array_merge(lykan_config::$config, $arr);
            }
        }
        return lykan_config::$config;
    }

    /**
     * lykan::save_config()
     * 
     * @param mixed $arr
     * @return void
     */
    public static function save_config(array $arr) {
        file_put_contents(self::get_root() . 'config.json', json_encode($arr));
    }

    /**
     * lykan::get_root()
     * 
     * @return
     */
    public static function get_root() {
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
    public static function check_filename(string $name) {
        if (self::is_filter_active('file_inject') === true) {
            $arr = explode(".", $name);
            $ext = end($arr);
            if (in_array($ext, lykan_config::$config['forbidden_file_ext']) || preg_match("/^.*\.([a-zA-Z]{3}).html$/", $name) || preg_match("/^.*\.([a-zA-Z]{3}).htm$/", $name)) {
                self::report_hack(lykan_types::FILE_INJECT, $ext, false);
                self::exit_env(lykan_types::FILE_INJECT . ' ' . $ext);
            }
        }
    }

    /**
     * lykan::is_filter_active()
     * 
     * @param mixed $type
     * @return
     */
    private static function is_filter_active($type) {
        return isset(lykan_config::$config['filter_active'][$type]) && (boolean)lykan_config::$config['filter_active'][$type] === true;
    }

    /**
     * lykan::check_mime()
     * 
     * @param mixed $file
     * @return void
     */
    protected static function check_mime($file) {
        if (!isset($file["type"])) {
            return;
        }
        if (self::is_filter_active('mime_types') === true) {
            $json = json_decode(self::get_current_pattern(), true);
            if (isset($json['mime']) && count($json['mime']) > 0) {
                $json['mime'] = (array )$json['mime'];
                foreach ($json['mime'] as $key => $mime) {
                    if (strtolower($file["type"]) == strtolower($mime['m_mime'])) {
                        return;
                    }
                }
                self::report_hack(lykan_types::MIME_FILE_UPLOAD, $file["type"], false);
                self::exit_env(lykan_types::MIME_FILE_UPLOAD . ' ' . $file["type"]);
            }
        }
    }

    /**
     * lykan::file_upload_protection()
     * 
     * @return void
     */
    public static function file_upload_protection() {
        if (isset($_FILES)) {
            foreach ($_FILES as $key => $row) {
                if (!is_array($_FILES[$key]["name"]) && !empty($_FILES[$key]["name"])) {
                    self::check_filename($_FILES[$key]["name"]);
                    self::check_mime($row);
                }
                else {
                    foreach ($_FILES[$key]['name'] as $keya => $row2) {
                        if (!empty($_FILES[$key]["name"][$keya])) {
                            self::check_filename($_FILES[$key]["name"][$keya]);
                            self::check_mime($row2);
                        }
                    }
                }
            }
        }
    }

    /**
     * lykan::init()
     * 
     * @return void
     */
    public static function init($path = "") {
        self::set_root($path);
        self::auto_detect_system();
    }

    /**
     * lykan::run()
     * 
     * @return void
     */
    public static function run($path = "") {
        self::init($path);
        self::load_config();
        if ($handle = opendir(lykan_config::$config['hpath'])) {
            while (false !== ($file = readdir($handle))) {
                $fname = lykan_config::$config['hpath'] . $file;
                if (is_file($fname) && $file !== '.' && $file !== '..' && (integer)(time() - filemtime($fname)) > (lykan_config::$config['hcache_lifetime_hours'] * 3600)) {
                    @unlink($fname);
                }
            }
        }

        $fname = (strstr($_SERVER['HTTP_USER_AGENT'], 'bot')) ? $_SERVER['HTTP_USER_AGENT'] : $_SERVER['HTTP_USER_AGENT'] . self::get_the_ip();
        $hfile = lykan_config::$config['hpath'] . md5($fname);
        $hcount = 0;
        if (is_file($hfile)) {
            $arr = explode(PHP_EOL, file_get_contents($hfile));
            $hcount = (int)$arr[0];
            $hcount++;
        }
        file_put_contents($hfile, implode(PHP_EOL, array(
            $hcount,
            $_SERVER['HTTP_USER_AGENT'],
            self::get_the_ip(),
            date('Y-m-d H:i:s'),
            )));

        self::block_bad_user_post();
        self::file_upload_protection();
        self::block_bad_bots();
        self::block_locale_bad_ips();
        self::worm_detect();
        self::sql_detect();
        self::clear_blocked();
        self::block_ips_and_bots_from_blacklist();
        lykan_exploit::check_for_exploit();
        self::payloadlog();
        #self::check_agent();

        if (isset($_GET['lykan'])) {
            self::get_current_pattern();
            $result = self::read_logs();
            self::echo_table($result['hour_log'], $result['hour_log_count'] . ' Clients (last hour)');
            self::echo_table($result['blocked_bots'], 'Bad Bot blocked list');
            die();
        }
    }

    /**
     * lykan::payloadlog()
     * 
     * @return
     */
    protected static function payloadlog() {
        if (self::is_filter_active('payloadlog') === true) {
            payload_logger::log_request(lykan_config::$config['hpath']);
        }
    }

    /**
     * lykan::block_bad_user_post()
     * 
     * @return void
     */
    protected static function block_bad_user_post() {
        return;
        if (self::is_filter_active('bad_user_post') === true) {
            if ($_SERVER['REQUEST_METHOD'] == 'POST' && empty($_SERVER['HTTP_USER_AGENT']) && empty($_SERVER['HTTP_REFERER'])) {
                self::report_hack(lykan_types::BAD_USER_POST, "POST with blank user-agent and referer");
                self::exit_env(lykan_types::BAD_USER_POST . ' ' . $row['i_ip']);
            }
        }
    }

    /**
     * lykan::block_ips_and_bots_from_blacklist()
     * blocks IPs and bots save manually by backend
     * @return void
     */
    private static function block_ips_and_bots_from_blacklist() {
        $user_agent = self::get_user_agent();
        $json = json_decode(self::get_current_pattern(), true);

        # check bad IPs ( include IPs from stock DB and lykan network )
        if (isset($json['badips']) && is_array($json['badips'])) {
            if (isset($json['badips'][self::get_the_ip()])) {
                self::report_hack(lykan_types::BAD_IP, "", false);
                self::exit_env(lykan_types::BAD_IP . ' ' . $row['i_ip']);
            }
        }

        #check bots
        if (isset($json['bots']) && is_array($json['bots'])) {
            foreach ((array )$json['bots'] as $row) {
                $bot_key = trim(strtolower($row['b_bot']));
                if (!empty($bot_key) && strstr($user_agent, $bot_key)) {
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
            $badbots = self::read_bad_bots_from_cachefile();
            if ($_SERVER['HTTP_USER_AGENT'] != str_ireplace($badbots, '*', $_SERVER['HTTP_USER_AGENT'])) {
                $fp = fopen(lykan_config::$config['lykan_blocked_file'], 'a+');
                fwrite($fp, implode("\t", array(
                    date('Y-m-d H:i:s'),
                    $_SERVER['HTTP_USER_AGENT'],
                    'AGENT',
                    self::get_the_ip())) . PHP_EOL);
                fclose($fp);
                self::report_hack(lykan_types::BAD_BOT, $_SERVER['HTTP_USER_AGENT']);
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
     * @return
     */
    public static function get_user_agent() {
        return isset($_SERVER['HTTP_USER_AGENT']) ? substr($_SERVER['HTTP_USER_AGENT'], 0, 254) : '';
    }

    /**
     * lykan::read_logs()
     * 
     * @param mixed $k
     * @return void
     */
    public static function read_logs() {
        $k = 0;
        $result['hour_log'] = $result['blocked_bots'] = array();
        if ($handle = opendir(lykan_config::$config['hpath'])) {
            while (false !== ($file = readdir($handle))) {
                if ($file !== '.' && $file !== '..') {
                    $result['hour_log'][] = explode(PHP_EOL, file_get_contents(lykan_config::$config['hpath'] . $file));
                }
                $k++;
            }
        }
        if (is_file(lykan_config::$config['lykan_blocked_file'])) {
            $blocked = explode(PHP_EOL, file_get_contents(lykan_config::$config['lykan_blocked_file']));
            foreach ($blocked as $key => $line) {
                $result['blocked_bots'][] = explode("\t", $line);
            }
        }
        $result['hour_log_count'] = $k;
        return $result;
    }

    /**
     * lykan::read_lines_from_file()
     * 
     * @param mixed $file
     * @param mixed $maxLines
     * @param bool $reverse
     * @return
     */
    protected static function read_lines_from_file($file, $maxLines, $reverse = false) {
        $lines = file($file);
        if ($reverse) {
            $lines = array_reverse($lines);
        }
        $tmpArr = array();
        if ($maxLines > count($lines)) {
            return false;
        }

        for ($i = 0; $i < $maxLines; $i++) {
            array_push($tmpArr, $lines[$i]);
        }
        if ($reverse) {
            $tmpArr = array_reverse($tmpArr);
        }
        $out = "";
        for ($i = 0; $i < $maxLines; $i++) {
            $out .= $tmpArr[$i] . PHP_EOL;
        }
        return $out;
    }

    /**
     * lykan::clear_blocked()
     * 
     * @return void
     */
    protected static function clear_blocked() {
        if (is_file(lykan_config::$config['lykan_blocked_file']) && filesize(lykan_config::$config['lykan_blocked_file']) > 6000) {
            $lines = self::read_lines_from_file(lykan_config::$config['lykan_blocked_file'], lykan_config::$config['log_lines_count'], true);
            if ($lines !== false && is_string($lines))
                file_put_contents(lykan_config::$config['lykan_blocked_file'], $lines);
        }
    }


    /**
     * lykan::block()
     * 
     * @return void
     */
    public static function exit_env($reason = "") {
        #   header('HTTP/1.0 403 Forbidden');
        #   die('Bad agent [' . $reason . ']');
    }


    /**
     * lykan::create_ip_range()
     * 
     * @param mixed $ip
     * @return
     */
    private static function create_ip_range(string $ip, int $star_count = 1) : string {
        if (strpos($ip, ".") == true) {
            return preg_replace('#(?:\.\d+){' . (int)$star_count . '}$#', str_repeat('.*', $star_count), $ip);
        }
        else {
            # return preg_replace('~:[0-9a-z]+$~', ':*', $ip);
            return preg_replace('#(?:\:[0-9a-z]+){{' . (int)$star_count . '}}$#', str_repeat(':*', $star_count), $ip);
        }
    }

    /**
     * lykan::block_locale_bad_ips()
     * locale stored bad ips
     * @return void
     */
    protected static function block_locale_bad_ips() {
        if (self::is_filter_active('bad_ips') === true) {
            $locale_badips = self::get_locale_bad_ips();
            foreach ($locale_badips as $ip) {
                if (strstr($ip, '*')) {
                    # IPv4 / IPv6 block range
                    for ($i = 1; $i <= 3; $i++) {
                        if (self::create_ip_range(self::get_the_ip(), $i) == $ip) {
                            self::block_this_locale_bad_ip();
                        }
                    }
                }
                else {
                    # block a specific ip
                    if (self::get_the_ip() == $ip) {
                        self::block_this_locale_bad_ip();
                    }
                }
            }
        }
    }

    /**
     * lykan::block_this_locale_bad_ip()
     * 
     * @return void
     */
    private static function block_this_locale_bad_ip() {
        $fp = fopen(lykan_config::$config['lykan_blocked_file'], 'a+');
        fwrite($fp, implode("\t", array(
            date('Y-m-d H:i:s'),
            $_SERVER['HTTP_USER_AGENT'],
            'IP',
            self::get_the_ip())) . PHP_EOL);
        fclose($fp);
        self::report_hack(lykan_types::BAD_IP, self::get_the_ip(), false);
        self::exit_env(lykan_types::BAD_IP);
    }


    /**
     * lykan::read_bad_bots_from_cachefile()
     * 
     * @return
     */
    protected static function read_bad_bots_from_cachefile() {
        if (is_file(lykan_config::$config['badbots_file'])) {
            return explode(PHP_EOL, file_get_contents(lykan_config::$config['badbots_file']));
        }
        else
            return array();
    }

    /**
     * lykan::get_locale_bad_ips()
     * 
     * @return
     */
    protected static function get_locale_bad_ips() {
        if (is_file(lykan_config::$config['badips_file'])) {
            return explode(PHP_EOL, file_get_contents(lykan_config::$config['badips_file']));
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
     * @return
     */
    public static function get_backend() {
        self::init();
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
    public static function add_ip($ip) {
        $ip = trim(strtoupper($ip));
        $ip = preg_replace("/[^A-Z0-9.:*]+/", "", $ip);
        if (strstr($ip, '*') || self::is_valid_ip($ip)) {
            $ip_list = self::get_locale_bad_ips();
            $ip_list[] = trim($ip);
            $ip_list = array_unique($ip_list);
            file_put_contents(lykan_config::$config['badips_file'], implode(PHP_EOL, $ip_list));
        }
    }

    /**
     * lykan::save()
     * 
     * @param mixed $ip_list
     * @return void
     */
    public static function save(array $ip_list) {
        self::init();
        $ip_list = array_unique($ip_list);
        $arr = [];
        foreach ($ip_list as $ip) {
            $ip = trim(strtoupper($ip));
            $ip = preg_replace("/[^A-Z0-9.:*]+/", "", $ip);
            if (strstr($ip, '*') || self::is_valid_ip($ip)) {
                $arr[] = $ip;
            }
        }
        $arr = array_unique($arr);
        file_put_contents(lykan_config::$config['badips_file'], implode(PHP_EOL, $arr));
    }

    /**
     * lykan::remove_ip()
     * 
     * @param mixed $ip
     * @return void
     */
    public static function remove_ip($ip) {
        $ip_list = self::get_locale_bad_ips();
        $ip_list = array_diff($ip_list, array($ip));
        file_put_contents(lykan_config::$config['badips_file'], implode(PHP_EOL, $ip_list));
    }

    /**
     * lykan::is_valid_ip()
     * 
     * @param mixed $ip
     * @return
     */
    public static function is_valid_ip($ip) {
        if (!filter_var($ip, FILTER_VALIDATE_IP) && !filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            return false;
        }
        return true;
    }

    /**
     * lykan::get_query_string()
     * 
     * @return
     */
    private static function get_query_string() {
        return $_SERVER['QUERY_STRING'];
    }

    /**
     * lykan::worm_detect()
     * 
     * @return void
     */
    private static function worm_detect() {
        self::detect_worm_injection('worm', lykan_types::WORM_INJECT);
        $check = $cracktrack = self::get_query_string();
        $json = json_decode(self::get_current_pattern(), true);
        if (isset($json['xssinject']) && is_array($json['xssinject'])) {
            foreach ((array )$json['xssinject'] as $row) {
                $cracktrack = preg_replace((string )$row['i_term'], '*', $cracktrack);
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
            $log_file = static::$lykan_root . 'lykan/accesslog/sql_inject.log';
            $log_dir = dirname($log_file);
            if (!is_dir($log_dir)) {
                @mkdir($log_dir, 0755, true);
            }

            $max_entries = 10000;
            $lines = @file($log_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            if (!is_array($lines)) {
                $lines = array();
            }

            $ip = self::get_the_ip();
            $host = self::get_host();
            $ua = isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
            $url = (isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : (isset($_SERVER['PHP_SELF']) ? $_SERVER['PHP_SELF'] : '')) . (isset($_SERVER['QUERY_STRING']) &&
                $_SERVER['QUERY_STRING'] !== '' ? ('?' . $_SERVER['QUERY_STRING']) : '');

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

            $lines[] = $entry;

            // keep only most recent $max_entries entries
            if (count($lines) > $max_entries) {
                $lines = array_slice($lines, -$max_entries);
            }

            @file_put_contents($log_file, implode(PHP_EOL, $lines) . PHP_EOL, LOCK_EX);
            @chmod($log_file, 0640);
        }
        catch (\Throwable $t) {
            // ignore logging failures so detection still blocks
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
        $json_raw = self::get_current_pattern();
        $json = json_decode($json_raw, true);
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
            $lc_patterns[] = mb_strtolower($p, 'UTF-8');
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
                $lc_variants[] = mb_strtolower($v, 'UTF-8');
            }

            // 2) pattern matching (plain substring, case-insensitive)
            foreach ($lc_patterns as $idx => $pattern) {
                if ($pattern === '')
                    continue;
                foreach ($lc_variants as $v) {
                    if ($v === '')
                        continue;
                    if (mb_strpos($v, $pattern, 0, 'UTF-8') !== false) {
                        $detections[] = array(
                            'type' => 'pattern',
                            'pattern' => $patterns[$idx], // original pattern
                            'matched_variant' => substr($v, 0, 200),
                            'value_snippet' => substr($s_trim, 0, 120));
                        // once matched for this pattern against this input, skip to next pattern
                        break 2;
                    }
                }
            }
        }

        // optional: log detections (only short snippet, no full value)
        if (!empty($detections)) {
            foreach ($detections as $d) {
                $log_line = date('c') . " - sql_detect: type=" . $d['type'];
                if (isset($d['reason']))
                    $log_line .= " reason=" . $d['reason'];
                if (isset($d['pattern']))
                    $log_line .= " pattern=" . $d['pattern'];
                $log_line .= " snippet=" . (isset($d['value_snippet']) ? $d['value_snippet'] : 'n/a');

                // write the detection to a dedicated SQL injection log file
                // delegate logging to helper (writes capped log and extra meta)
                self::write_sql_inject_log($d, $log_line);

                // record the offending IP in the local bad IP list
                self::add_ip(self::get_the_ip());
                // report the hack to the central service
                self::report_hack(lykan_types::SQL_INJECT);
                if (filter_var(lykan_config::$config['email'], FILTER_VALIDATE_EMAIL)) {
                    $mail_msg = 'Hacking blocked [SQL_INJECTION]: ' . PHP_EOL;
                    $arr = array(
                        'IP' => self::get_the_ip(),
                        'Host' => self::get_host(),
                        'Trace' => 'https://www.ip-tracker.org/locator/ip-lookup.php?ip=' . self::get_the_ip(),
                        'HTTP_USER_AGENT' => $_SERVER['HTTP_USER_AGENT'],
                        'cracktrack' => $log_line,
                        );
                    foreach ($arr as $key => $value) {
                        $mail_msg .= $key . ":\t" . $value . PHP_EOL;
                    }
                    $header = 'From: ' . lykan_config::$config['email'] . "\r\n" . 'Reply-To: ' . lykan_config::$config['email'] . "\r\n" . 'X-Mailer: PHP/' . phpversion();
                    mail(lykan_config::$config['email'], 'IP blocked: [SQLINJECTION] ' . self::get_host(), $mail_msg, $header, '-f' . lykan_config::$config['email']);
                }
                self::exit_env('INJECT');
            }
        }

        // return array of detections (empty = no detection)
        # return $detections;
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
                if (!mb_check_encoding($s, 'UTF-8')) {
                    $s = mb_convert_encoding($s, 'UTF-8', 'auto');
                }

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
    public static function detect_worm_injection($type, $itype) {
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
        $json_raw = self::get_current_pattern();
        $json = @json_decode($json_raw, true);
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
            $lc_patterns[mb_strtolower($p, 'UTF-8')] = $p; // keep original as value for reporting
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
            $lc_variants[] = mb_strtolower($v, 'UTF-8');
        }

        // iterate patterns and variants and stop on first match (fast path)
        $matched_pattern = null;
        $matched_variant_snippet = null;
        foreach ($lc_patterns as $lc_pat => $orig_pat) {
            foreach ($lc_variants as $variant) {
                if ($variant === '')
                    continue;
                if (mb_strpos($variant, $lc_pat, 0, 'UTF-8') !== false) {
                    $matched_pattern = $orig_pat;
                    $matched_variant_snippet = mb_substr($variant, 0, 300, 'UTF-8');
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
     * @return
     */
    public static function get_host() {
        return str_replace('www.', '', $_SERVER['HTTP_HOST']);
    }

    /**
     * lykan::report_hack()
     * 
     * @param mixed $h_type
     * @param string $h_type_info
     * @return void
     */
    public static function report_hack($h_type, $h_type_info = "", $adddb = true) {
        #return;
        $arr = array(
            'cmd' => 'report_hack',
            'adddb' => $adddb,
            'user_agent' => self::get_user_agent(),
            'FORM' => array(
                'type' => $h_type,
                'type_info' => $h_type_info,
                'domain' => self::get_host(),
                'ip' => self::get_the_ip(),
                'url' => base64_encode($_SERVER['PHP_SELF'] . '###' . $_SERVER['QUERY_STRING'] . '###' . http_build_query($_REQUEST)),
                ));
        return lykan_client::call('POST', $arr);
    }


    /**
     * lykan::get_lock()
     * 
     * @param mixed $days
     * @param integer $limit
     * @return
     */
    public static function get_lock($days, $limit = 0) {
        $domain = self::get_host();
        $days = (int)$days;
        $arr = array(
            'cmd' => 'get_lock',
            'days' => $days,
            'limit' => (int)$limit,
            'domain' => $domain,
            'khash' => hash('sha256', $domain . $days . lykan::get_timestamp()));
        $str = lykan_client::call('POST', $arr);
        return json_decode($str, true);
    }

    /**
     * lykan::get_current_pattern()
     * 
     * @return void
     */
    public static function get_current_pattern() {
        $path = lykan_config::$config['lykan_blacklist'];
        $lifetime_hours = isset(lykan_config::$config['blacklist_lifetime_hours']) ? (int)lykan_config::$config['blacklist_lifetime_hours'] : 0;
        $lock_ttl = isset(lykan_config::$config['download_lock_ttl_seconds']) ? (int)lykan_config::$config['download_lock_ttl_seconds'] : 300; // 5 minutes
        $lock_path = $path . '.lock';

        $need_download = false;


        // 1) Decide if refresh is needed
        if (is_file($path)) {
            $age = time() - @filemtime($path);
            if ($age > ($lifetime_hours * 3600)) {
                $need_download = true;
            }
        }
        else {
            // Missing file -> need initial download
            $need_download = true;
        }

        // 2) Empty or invalid JSON -> refresh
        if (is_file($path)) {
            if (@filesize($path) === 0) {
                $need_download = true;
            }
            else {
                $json_str = @file_get_contents($path);
                if ($json_str === false || !self::is_valid_json($json_str)) {
                    $need_download = true;
                }
                else {
                    $data = json_decode($json_str, true);
                    // Refresh empty array/object
                    if ((is_array($data) && count($data) === 0) || (is_object($data) && count((array )$data) === 0)) {
                        $need_download = true;
                    }
                }
            }
        }

        // 3) Respect lock: if another process is downloading, skip download attempt
        if ($need_download) {
            $locked = false;

            // lock exists and is fresh -> do not download now (avoid recursion / endless loops)
            if (is_file($lock_path)) {
                $lock_age = time() - @filemtime($lock_path);
                if ($lock_age < $lock_ttl) {
                    $locked = true;
                }
                else {
                    // stale lock -> remove it
                    @unlink($lock_path);
                }
            }

            if (!$locked) {
                // Try to acquire lock atomically
                // Note: file_put_contents with LOCK_EX is not an inter-process mutex by itself,
                // but creating a new lock file is usually atomic on POSIX filesystems.
                $lock_created = @file_put_contents($lock_path, (string )time(), LOCK_EX) !== false;

                if ($lock_created) {
                    try {
                        // Optional: write a small placeholder to indicate refresh intent (not required)
                        // @file_put_contents($path, json_encode(array('status' => 'updating')));

                        self::download_pattern(); // must overwrite $path on success
                    }
                    catch (\Throwable $e) {
                        // swallow; we'll fall through to reading whatever exists
                    }
                    finally {
                        // Always remove lock to prevent deadlocks
                        @unlink($lock_path);
                    }
                }
            }
        }

        // 4) Return the best available JSON
        if (is_file($path)) {
            $json_str = @file_get_contents($path);
            if ($json_str !== false && self::is_valid_json($json_str)) {
                return $json_str;
            }
        }

        // 5) Fallback to empty JSON array (and write it once)
        $empty = json_encode(array());
        @file_put_contents($path, $empty);
        return $empty;
    }


    /**
     * lykan::download_pattern()
     * 
     * @return void
     */
    protected static function download_pattern() {
        $data = array('cmd' => 'get_black_iplist');
        lykan_client::call('DOWNLOAD', $data, lykan_config::$config['lykan_blacklist']);
    }

    /**
     * lykan::get_timestamp()
     * 
     * @return
     */
    public static function get_timestamp() {
        $now = new DateTime("now", new DateTimeZone('CET'));
        return date('YmdHi', strtotime($now->format('Y-m-d H:i:s')) - $now->format('Z'));
    }
}

class lykan_client {

    protected static $endpoint = 'https://www.lykanshield.io/rest/';

    /**
     * call()
     * 
     * @param mixed $method
     * @param mixed $data
     * @return
     */
    public static function call($method, array $data, $local_file = "") {
        $url = static::$endpoint;
        $data['apikey'] = (lykan_config::$config['apikey'] != "") ? lykan_config::$config['apikey'] : "";
        $data['host'] = lykan::get_host();
        $data['hash'] = hash('sha512', implode(':', [$data['apikey'], $data['host'], lykan::get_timestamp()]));
        $data = json_encode($data);
        $curl = curl_init();
        curl_setopt($curl, CURLOPT_USERAGENT, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:100.0) Gecko/20100101 Firefox/100.0');
        curl_setopt($curl, CURLOPT_CONNECTTIMEOUT, 30);
        curl_setopt($curl, CURLOPT_FRESH_CONNECT, TRUE);
        curl_setopt($curl, CURLOPT_URL, $url);
        curl_setopt($curl, CURLOPT_HTTPHEADER, array(
            'Content-Type: application/json',
            'Accept: application/json',
            'Cache-Control: no-cache, no-store, must-revalidate',
            ));
        switch ($method) {
            case "POST":
                curl_setopt($curl, CURLOPT_POST, 1);
                curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
                if ($data)
                    curl_setopt($curl, CURLOPT_POSTFIELDS, $data);
                break;
            case "DOWNLOAD":
                curl_setopt($curl, CURLOPT_POST, 1);
                curl_setopt($curl, CURLOPT_POSTFIELDS, $data);
                $fp = fopen($local_file, 'w');
                curl_setopt($curl, CURLOPT_FILE, $fp);
                break;
            default:
                curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
                if ($data)
                    $url = sprintf("%s?%s", $url, http_build_query(json_decode($data)));
                break;
        }


        $result = curl_exec($curl);
        if (!$result) {
            die("Lykan Connection failure");
        }
        curl_close($curl);
        if ($method == 'DOWNLOAD') {
            fclose($fp);
            if (filesize($local_file) < 10000) {
                if (strstr(file_get_contents($local_file), '302 Found')) {
                    @unlink($local_file);
                    return false;
                }
            }
        }
        return $result;
    }
}

class lykan_exploit {

    private static $queryString = "";

    public static function check_for_exploit() {
        if (isset($_SERVER['QUERY_STRING'])) {
            static::$queryString = $_SERVER['QUERY_STRING'];
        }
        else {
            static::$queryString = http_build_query(array_merge($_POST, $_GET));
        }

        if (!empty(static::$queryString)) {
            if (self::contains_base64encode(static::$queryString) || self::contains_script_tag(static::$queryString) || self::contains_global_variable(static::$queryString) ||
                self::contains_request_variable(static::$queryString) || self::contains_http_in_query(static::$queryString)) {
                self::deny_access();
            }
        }
    }

    private static function contains_base64encode($query) {
        return preg_match('/base64_encode\([^)]*\)/', $query);
    }

    private static function contains_script_tag($query) {
        return preg_match('/<s*cript.*>|%3Cs*cript.*%3E/i', $query);
    }

    private static function contains_global_variable($query) {
        return preg_match('/GLOBALS(=|\[|\%[0-9A-Z]{0,2})/', $query);
    }

    private static function contains_request_variable($query) {
        return preg_match('/_REQUEST(=|\[|\%[0-9A-Z]{0,2})/', $query);
    }

    private static function contains_http_in_query($query) {
        return strpos($query, 'http:') !== false || strpos($query, 'http:%') !== false;
    }

    private static function deny_access() {
        lykan::report_hack(lykan_types::EXPLOIT, static::$queryString, false);
        lykan::exit_env(lykan_types::EXPLOIT);
    }
}

class lykan_types {
    CONST BAD_IP = 'BAD_IP';
    CONST STD = 'DEFAULT';
    CONST SQL_INJECT = 'SQL_INJECT';
    CONST EXPLOIT = 'EXPLOIT';
    CONST MIME_FILE_UPLOAD = 'MIME_FILE_UPLOAD';
    CONST DOUBLEUSE_ACCOUNT = 'DOUBLEUSE_ACCOUNT';
    CONST FILE_INJECT = 'FILE_INJECT';
    CONST XSS_INJECT = 'XSS_INJECT';
    CONST BAD_USER_POST = 'BAD_USER_POST';
    CONST BLACK_LIST_BOT = 'BLACK_LIST_BOT';
    CONST INVALID_USER_AGENT = 'INVALID_USER_AGENT';
    CONST WORM_INJECT = 'WORM_INJECT';
    CONST HTTP_INJECTION = 'HTTP_INJECTION';
    CONST CONTACTFORM_HIDDENMAILFIELD = 'CONTACTFORM_HIDDENMAILFIELD';
    CONST B8 = 'B8';
    CONST REDIRECT_PARAM = 'REDIRECT_PARAM';
    CONST INVALIDHASH = 'INVALIDHASH';
    CONST SECUREDOWNLOAD = 'SECUREDOWNLOAD';
    CONST CMD_WITH_NO_PERMISSIONS = 'CMD_WITH_NO_PERMISSIONS';
    CONST MAIL_HACKING = 'MAIL_HACKING';
    CONST ADMINLOGIN = 'ADMINLOGIN';
    CONST BAD_LOCAL_IP = 'BAD_LOCAL_IP';
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
    private static $rel_path = 'pageload.xls';
    private static $dir_mode = 0750;
    private static $file_mode = 0640;
    private static $max_bytes = 10 * 1024 * 1024; // rotate at 10MB

    /**
     * Call this once per request to log the event
     */
    /**
     * log_request()
     * 
     * @param mixed $root
     * @return
     */
    public static function log_request($root) {
        try {
            $full_dir = dirname($root . self::$rel_path);
            self::ensure_dir_and_protect($full_dir);

            $file = $root . self::$rel_path;

            // Rotate if needed
            if (is_file($file) && filesize($file) > self::$max_bytes) {
                self::rotate_file($file);

                // --- Enforce max 10 .bak files (delete oldest) ---
                // Works for both "<file>.bak" and "<file>.bak.*" naming schemes
                $bak_files = array();
                $glob_a = glob($file . '.bak');
                $glob_b = glob($file . '.bak.*');

                if (is_array($glob_a)) {
                    $bak_files = array_merge($bak_files, $glob_a);
                }
                if (is_array($glob_b)) {
                    $bak_files = array_merge($bak_files, $glob_b);
                }

                if (is_array($bak_files) && count($bak_files) > 10) {
                    // Sort by modification time (oldest first)
                    usort($bak_files, function ($a, $b) {
                        $ma = @filemtime($a); $mb = @filemtime($b); if ($ma === false && $mb === false)return 0; if ($ma === false)return - 1; if ($mb === false)return 1; return ($ma <
                            $mb) ? -1 : (($ma > $mb) ? 1 : 0); }
                    );

                    // Delete oldest so that only 10 remain
                    $to_delete = array_slice($bak_files, 0, count($bak_files) - 10);
                    foreach ($to_delete as $old_file) {
                        @unlink($old_file)
                            ;
                    }
                }
                // --- End backup cap enforcement ---
            }

            $is_new = !is_file($file);
            $fp = @fopen($file, 'a');
            if ($fp === false) {
                return false;
            }

            if ($is_new) {
                @chmod($file, self::$file_mode);
            }

            $record = self::build_record();

            // Header line for new file
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
                    'raw_body',
                    'headers',
                    'env',
                    'reverse_dns',
                    'process_id',
                    'session_id');
                @flock($fp, LOCK_EX);
                fputcsv($fp, $header, "\t", '"');
                @flock($fp, LOCK_UN);
            }

            @flock($fp, LOCK_EX);
            fputcsv($fp, $record, "\t", '"');
            @flock($fp, LOCK_UN);
            fclose($fp);

            return true;
        }
        catch (Exception $e) {
            return false;
        }
    }


    /**
     * Build a TSV record with maximum client + request context
     */
    /**
     * build_record()
     * 
     * @return
     */
    private static function build_record() {
        $now = time();
        $iso = date('c', $now);

        $remote_ip = self::get_the_ip();
        $forwarded_for = isset($_SERVER['HTTP_X_FORWARDED_FOR']) ? $_SERVER['HTTP_X_FORWARDED_FOR'] : '';
        $remote_port = isset($_SERVER['REMOTE_PORT']) ? $_SERVER['REMOTE_PORT'] : '';
        $host = isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : (isset($_SERVER['SERVER_NAME']) ? $_SERVER['SERVER_NAME'] : '');
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
        $cookies = isset($_COOKIE) ? $_COOKIE : array();
        $get = isset($_GET) ? $_GET : array();
        $post = isset($_POST) ? $_POST : array();
        $raw_body = @file_get_contents('php://input');
        $headers = self::get_request_headers();

        $env = array(
            'REMOTE_ADDR' => isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '',
            'SERVER_PROTOCOL' => isset($_SERVER['SERVER_PROTOCOL']) ? $_SERVER['SERVER_PROTOCOL'] : '',
            'HTTPS' => (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 1 : 0,
            'HTTP_X_REQUESTED_WITH' => isset($_SERVER['HTTP_X_REQUESTED_WITH']) ? $_SERVER['HTTP_X_REQUESTED_WITH'] : '',
            );

        $reverse_dns = @gethostbyaddr($remote_ip);
        $process_id = getmypid();
        $session_id = (session_status() == PHP_SESSION_ACTIVE && isset($_SESSION) && session_id() != '') ? session_id() : '';

        // --- Helper: remove any keys that contain "password" or "passwort" (case-insensitive) ---
        $sanitize_sensitive = null; // declare first so we can reference by use(&...)
        $sanitize_sensitive = function ($arr)use (&$sanitize_sensitive) {
            if (!is_array($arr)) {
                return $arr;
            }
            $clean = array();
            foreach ($arr as $key => $value) {
                // Cast key to string for regex safety (numeric keys won't match anyway)
                $key_str = (string )$key;

                // Skip any key that looks like a password field
                if (preg_match('/pass(?:word|wort)/i', $key_str)) {
                    continue;
                }

                // Recurse into nested arrays
                if (is_array($value)) {
                    $clean[$key] = $sanitize_sensitive($value);
                }
                else {
                    $clean[$key] = $value;
                }
            }
            return $clean;
        }
        ;

        // Sanitize arrays before JSON encoding
        $cookies = $sanitize_sensitive($cookies);
        $get = $sanitize_sensitive($get);
        $post = $sanitize_sensitive($post);
        $headers = $sanitize_sensitive($headers);

        $json_cookies = self::json_safe($cookies);
        $json_get = self::json_safe($get);
        $json_post = self::json_safe($post);
        $json_headers = self::json_safe($headers);
        $json_env = self::json_safe($env);

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
            (string )$raw_body,
            $json_headers,
            $json_env,
            $reverse_dns,
            $process_id,
            $session_id);
    }


    /**
     * ensure_dir_and_protect()
     * 
     * @param mixed $dir
     * @return void
     */
    private static function ensure_dir_and_protect($dir) {
        if (!is_dir($dir)) {
            @mkdir($dir, self::$dir_mode, true);
            @chmod($dir, self::$dir_mode);
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
            @file_put_contents($htaccess, $content);
            @chmod($htaccess, 0640);
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
            @file_put_contents($webconfig, $wcontent);
            @chmod($webconfig, 0640);
        }

        // index.html for safety
        $index = $dir . DIRECTORY_SEPARATOR . 'index.html';
        if (!is_file($index)) {
            @file_put_contents($index, '<!doctype html><html><head><meta charset="utf-8"><title>Forbidden</title></head><body>Forbidden.</body></html>');
            @chmod($index, 0644);
        }
    }

    /**
     * rotate_file()
     * 
     * @param mixed $file
     * @return void
     */
    private static function rotate_file($file) {
        $bak = $file . '.' . date('Ymd_His') . '.bak';
        @rename($file, $bak);
    }

    /**
     * get_the_ip()
     * 
     * @return
     */
    private static function get_the_ip() {
        $keys = array(
            'HTTP_CLIENT_IP',
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_REAL_IP',
            'REMOTE_ADDR');
        foreach ($keys as $k) {
            if (!empty($_SERVER[$k])) {
                $ip = $_SERVER[$k];
                if (strpos($ip, ',') !== false) {
                    $parts = explode(',', $ip);
                    $ip = trim($parts[0]);
                }
                if (filter_var($ip, FILTER_VALIDATE_IP)) {
                    return $ip;
                }
            }
        }
        return '0.0.0.0';
    }

    /**
     * get_request_headers()
     * 
     * @return
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
     * @return
     */
    private static function json_safe($data) {
        $j = json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        if ($j === false) {
            return base64_encode(serialize($data));
        }
        return $j;
    }
}
