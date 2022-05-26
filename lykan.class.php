<?php

/**
 * lykan class
 *
 * @see       https://github.com/trebaxa/lykan
 * @version   1.6  
 * @author    Harald Petrich <service@trebaxa.com>
 * @copyright 2018 - 2019 Harald Petrich
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

# define subpath of your project. last char must be a /
define('SUB_PATH_OF_SYSTEM', '/');
date_default_timezone_set('Europe/Berlin');

class lykan_config {
    public static $config = array(
        'apikey' => '', # from lykanshield.io, not need for free version
        'hcache_lifetime_hours' => 3, # cache lifetime of filters
        'blacklist_lifetime_hours' => 1, #locale blocked IPs life time
        'log_lines_count' => 98,
        'email' => '', #mail to send an info about sql injection attack
        'filter_active' => array(
            'mime_types' => true, #activates mime filter
            'file_inject' => true, # file injection filter
            'bad_bots' => true, # bad bot filter
            'bad_ips' => true, # bad IP filter
            'sql_injection' => true, # SQL Injection filter
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
            'sub_folder' => static::$lykan_root . 'lykan/',
            'lykan_blocked_file' => static::$lykan_root . 'lykan/hacklogblock_' . static::$host . '.txt',
            'lykan_blacklist' => static::$lykan_root . 'lykan/blacklist.json',
            'badips_file' => static::$lykan_root . 'lykan/badips_' . static::$host . '.txt',
            'badbots_file' => static::$lykan_root . 'lykan/badbots_' . static::$host . '.txt',
            ));

        # detect Keimeno CMS
        if (is_dir(static::$lykan_root . 'admin') && is_file(static::$lykan_root . 'admin/inc/keimeno.class.php')) {
            self::set_config_arr(array(
                'hpath' => static::$lykan_root . 'includes/lib/lykan/accesslog/',
                'sub_folder' => static::$lykan_root . 'includes/lib/lykan/',
                'lykan_blocked_file' => static::$lykan_root . 'includes/lib/lykan/hacklogblock_' . static::$host . '.txt',
                'lykan_blacklist' => static::$lykan_root . 'includes/lib/lykan/blacklist.json',
                'badips_file' => static::$lykan_root . 'includes/lib/lykan/badips_' . static::$host . '.txt',
                'badbots_file' => static::$lykan_root . 'includes/lib/lykan/badbots_' . static::$host . '.txt',
                ));
        }

        # detect WordPress
        if (is_dir(static::$lykan_root . 'wp-admin')) {
            self::set_config_arr(array(
                'sub_folder' => static::$lykan_root . 'wp-content/lykan/',
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
                'sub_folder' => static::$lykan_root . 'fileadmin/lykan/',
                'hpath' => static::$lykan_root . 'fileadmin/lykan/accesslog/',
                'lykan_blocked_file' => static::$lykan_root . 'fileadmin/lykan/hacklogblock_' . static::$host . '.txt',
                'lykan_blacklist' => static::$lykan_root . 'fileadmin/lykan/blacklist.json',
                'badips_file' => static::$lykan_root . 'fileadmin/lykan/badips_' . static::$host . '.txt',
                'badbots_file' => static::$lykan_root . 'fileadmin/lykan/badbots_' . static::$host . '.txt',
                ));
        }

        if (!is_dir(lykan_config::$config['sub_folder']))
            mkdir(lykan_config::$config['sub_folder'], 0755);
        if (!is_dir(lykan_config::$config['hpath']))
            mkdir(lykan_config::$config['hpath'], 0755);
    }

    /**
     * lykan::get_the_ip()
     * 
     * @return
     */
    public static function get_the_ip() {
        return isset($_SERVER['HTTP_CLIENT_IP']) ? $_SERVER['HTTP_CLIENT_IP'] : isset($_SERVER['HTTP_X_FORWARDED_FOR']) ? $_SERVER['HTTP_X_FORWARDED_FOR'] : $_SERVER['REMOTE_ADDR'];
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
     * lykan::set_root()
     * 
     * @param mixed $path
     * @return void
     */
    protected static function set_root($path) {
        if (empty($path)) {
            static::$lykan_root = $_SERVER['DOCUMENT_ROOT'] . (substr($_SERVER['DOCUMENT_ROOT'], -1) == DIRECTORY_SEPARATOR ? '' : DIRECTORY_SEPARATOR) . SUB_PATH_OF_SYSTEM;
        }
        else {
            static::$lykan_root = $path . (substr($path, -1) == DIRECTORY_SEPARATOR ? '' : DIRECTORY_SEPARATOR);
        }
    }

    /**
     * lykan::check_filename()
     * 
     * @param mixed $name
     * @return void
     */
    public static function check_filename($name) {
        if (lykan_config::$config['filter_active']['file_inject'] === true) {
            $ext = end((explode(".", $name)));
            if (in_array($ext, lykan_config::$config['forbidden_file_ext']) || preg_match("/^.*\.([a-zA-Z]{3}).html$/", $name) || preg_match("/^.*\.([a-zA-Z]{3}).htm$/", $name)) {
                self::report_hack(lykan_types::FILE_INJECT, $ext);
                self::exit_env(lykan_types::FILE_INJECT . ' ' . $ext);
            }
        }
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
        if (lykan_config::$config['filter_active']['mime_types'] == true) {
            $json = json_decode(self::get_current_pattern(), true);
            $json['mime'] = (array )$json['mime'];
            foreach ($json['mime'] as $mime => $ext) {
                if ($file["type"] == $mime) {
                    return;
                }
            }
            self::report_hack(lykan_types::MIME_FILE_UPLOAD, $file["type"]);
            self::exit_env(lykan_types::MIME_FILE_UPLOAD . ' ' . $file["type"]);
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
                #$ext = end((explode(".", $_FILES[$key]["name"])));
                if (!is_array($_FILES[$key]["name"])) {
                    self::check_filename($_FILES[$key]["name"]);
                    self::check_mime($row);
                }
                else {
                    foreach ($_FILES[$key]['name'] as $keya => $row2) {
                        self::check_filename($_FILES[$key]["name"][$keya]);
                        self::check_mime($row2);
                    }
                }
            }
        }
    }

    /**
     * lykan::run()
     * 
     * @return void
     */
    public static function run($path = "") {
        self::set_root($path);
        self::auto_detect_system();

        if ($handle = opendir(lykan_config::$config['hpath'])) {
            while (false !== ($file = readdir($handle))) {
                if ((integer)(time() - filemtime(lykan_config::$config['hpath'] . $file)) > (lykan_config::$config['hcache_lifetime_hours'] * 3600) && $file !== '.' && $file
                    !== '..') {
                    @unlink(lykan_config::$config['hpath'] . $file);
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

        self::file_upload_protection();
        self::block_bad_bots();
        self::block_bad_ips();
        self::detect_sqlinjection();
        self::clear_blocked();
        self::block_ips_and_bots_from_blacklist();
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
     * lykan::block_ips_and_bots_from_blacklist()
     * blocks IPs and bots save manually by backend
     * @return void
     */
    private static function block_ips_and_bots_from_blacklist() {
        $user_agent = self::get_user_agent();
        $json = json_decode(self::get_current_pattern(), true);

        # check bad IPs
        $json['badips'] = (array )$json['badips'];
        if (isset($json['badips'][self::get_the_ip()])) {
            self::report_hack(lykan_types::BAD_LOCAL_IP, "", false);
            self::exit_env(lykan_types::BAD_LOCAL_IP . ' ' . $row['i_ip']);
        }

        #check bots
        foreach ((array )$json['bots'] as $row) {
            $bot_key = trim(strtolower($row['b_bot']));
            if (!empty($bot_key) && strstr($user_agent, $bot_key)) {
                self::report_hack(lykan_types::BLACK_LIST_BOT, "", false);
                self::exit_env('BLACK_LIST_BOT');
            }
        }
    }


    /**
     * lykan::block_bad_bots()
     * 
     * @return void
     */
    protected static function block_bad_bots() {
        if (lykan_config::$config['filter_active']['bad_bots'] == true) {
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
    protected static function exit_env($reason = "") {
        header('HTTP/1.0 403 Forbidden');
        die('Bad agent [' . $reason . ']');
    }

    /**
     * lykan::block_bad_ips()
     * 
     * @return void
     */
    protected static function block_bad_ips() {
        if (lykan_config::$config['filter_active']['bad_ips'] == true) {
            $badips = self::get_bad_ips();
            if (in_array(self::get_the_ip(), $badips)) {
                $fp = fopen(lykan_config::$config['lykan_blocked_file'], 'a+');
                fwrite($fp, implode("\t", array(
                    date('Y-m-d H:i:s'),
                    $_SERVER['HTTP_USER_AGENT'],
                    'IP',
                    self::get_the_ip())) . PHP_EOL);
                fclose($fp);
                self::report_hack(lykan::BAD_IP, self::get_the_ip());
                self::exit_env('IP');
            }
        }
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
     * lykan::get_bad_ips()
     * 
     * @return
     */
    protected static function get_bad_ips() {
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
    public function get_backend() {
        self::set_root($path);
        self::auto_detect_system();
        return array(
            'bad_ips' => (implode(PHP_EOL, self::get_bad_ips())),
            'bad_bots' => (implode(PHP_EOL, self::read_bad_bots_from_cachefile())),
            );
    }

    /**
     * lykan::save()
     * 
     * @return void
     */
    public function save() {
        $ip_list = array();
        $FORM = (array )$_POST['FORM'];
        $arr = explode(PHP_EOL, stripslashes($FORM['bad_ips']));
        foreach ($arr as $ip) {
            $ip = trim($ip);
            if (self::is_valid_ip($ip)) {
                $ip_list[] = $ip;
            }
        }
        $ip_list = array_unique($ip_list);
        file_put_contents(lykan_config::$config['badips_file'], trim(implode(PHP_EOL, $ip_list)));
        file_put_contents(lykan_config::$config['badbots_file'], stripslashes($FORM['bad_bots']));
    }

    /**
     * lykan::add_ip()
     * 
     * @param mixed $ip
     * @return void
     */
    public static function add_ip($ip) {
        $ip = trim($ip);
        if (self::is_valid_ip($ip)) {
            $ip_list = self::get_bad_ips();
            $ip_list[] = trim($ip);
            $ip_list = array_unique($ip_list);
            file_put_contents(lykan_config::$config['badips_file'], implode(PHP_EOL, $ip_list));
        }
    }

    /**
     * lykan::remove_ip()
     * 
     * @param mixed $ip
     * @return void
     */
    public static function remove_ip($ip) {
        $ip_list = self::get_bad_ips();
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
     * lykan::detect_sqlinjection()
     * 
     * @return void
     */
    public static function detect_sqlinjection() {
        if (lykan_config::$config['filter_active']['sql_injection'] == true) {
            $cracktrack = self::get_query_string();
            $json = json_decode(self::get_current_pattern(), true);
            foreach ((array )$json['sqlinject'] as $row) {
                $wormprotector[] = $row['i_term'];
            }

            $checkworm = str_ireplace($wormprotector, '*', $cracktrack);
            if ($cracktrack != $checkworm) {
                self::add_ip(self::get_the_ip());
                self::report_hack(lykan_types::SQL_INJECT);
                if (filter_var(static::$email, FILTER_VALIDATE_EMAIL)) {
                    $mail_msg = 'Hacking blocked [SQLINJECTION]: ' . PHP_EOL;
                    $arr = array(
                        'IP' => self::get_the_ip(),
                        'Host' => self::get_host(),
                        'Trace' => 'https://www.ip-tracker.org/locator/ip-lookup.php?ip=' . self::get_the_ip(),
                        'HTTP_USER_AGENT' => $_SERVER['HTTP_USER_AGENT'],
                        'cracktrack' => $cracktrack,
                        "Hacked" => $checkworm);
                    foreach ($arr as $key => $value) {
                        $mail_msg .= $key . ":\t" . $value . PHP_EOL;
                    }
                    $header = 'From: ' . lykan_config::$config['email'] . "\r\n" . 'Reply-To: ' . lykan_config::$config['email'] . "\r\n" . 'X-Mailer: PHP/' . phpversion();
                    mail(lykan_config::$config['email'], 'IP blocked: [SQLINJECTION] ' . self::get_host(), $mail_msg, $header, '-f' . lykan_config::$config['email']);
                }
                self::exit_env('INJECT');
            }
        }
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
        $arr = array(
            'cmd' => 'report_hack',
            'adddb' => $adddb,
            'FORM' => array(
                'type' => $h_type,
                'type_info' => 'HL ' . $h_type_info,
                'domain' => self::get_host(),
                'ip' => self::get_the_ip(),
                'url' => base64_encode($_SERVER['PHP_SELF'] . '###' . $_SERVER['QUERY_STRING'] . '###' . http_build_query($_REQUEST)),
                ),
            'FORM_IP' => array(
                'b_iphash' => md5(self::get_the_ip()),
                'b_ua' => self::get_user_agent(),
                'b_ip' => self::get_the_ip(),
                ));
        return lykan_client::call('POST', $arr);
    }

    /**
     * lykan::get_lock()
     * 
     * @param mixed $days
     * @return void
     */
    public static function get_lock($days, $limit = 0) {
        $domain = self::get_host();
        $days = (int)$days;
        $arr = array(
            'cmd' => 'get_lock',
            'days' => $days,
            'limit' => (int)$limit,
            'domain' => $domain,
            'khash' => hash('sha256', $domain . $days . date('YmdHi')));
        $str = lykan_client::call('POST', $arr);
        return json_decode($str, true);
    }

    /**
     * lykan::get_current_pattern()
     * 
     * @return void
     */
    public static function get_current_pattern() {
        if (is_file(lykan_config::$config['lykan_blacklist']) && (integer)(time() - filemtime(lykan_config::$config['lykan_blacklist'])) > (lykan_config::$config['blacklist_lifetime_hours'] *
            3600)) {
            @unlink(lykan_config::$config['lykan_blacklist']);
        }

        if (!is_file(lykan_config::$config['lykan_blacklist'])) {
            $data = array('cmd' => 'get_black_iplist');
            lykan_client::call('DOWNLOAD', $data, lykan_config::$config['lykan_blacklist']);
        }
        if (file_exists(lykan_config::$config['lykan_blacklist'])) {
            return file_get_contents(lykan_config::$config['lykan_blacklist']);
        }
        else
            json_encode(array());
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
        $data['hash'] = hash('sha512', implode(':', [$data['apikey'], $data['host'], date('Ymdhi')]));
        $data = json_encode($data);

        $curl = curl_init();
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
        curl_setopt($curl, CURLOPT_URL, $url);
        curl_setopt($curl, CURLOPT_HTTPHEADER, array(
            'Content-Type: application/json',
            'Accept: application/json',
            ));

        $result = curl_exec($curl);
        if (!$result) {
            die("Connection failure");
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

class lykan_types {
    CONST BAD_IP = 'BAD_IP';
    CONST STD = 'DEFAULT';
    CONST SQL_INJECT = 'SQL_INJECT';
    CONST DOUBLEUSE_ACCOUNT = 'DOUBLEUSE_ACCOUNT';
    CONST FILE_INJECT = 'FILE_INJECT';
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
