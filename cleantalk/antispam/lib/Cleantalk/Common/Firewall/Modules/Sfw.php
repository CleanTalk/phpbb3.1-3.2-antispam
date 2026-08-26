<?php

namespace Cleantalk\Common\Firewall\Modules;

use Cleantalk\Common\Firewall\Firewall;
use Cleantalk\Common\Helper\Helper;
use Cleantalk\Common\Mloader\Mloader;
use Cleantalk\Common\Variables\Cookie;
use Cleantalk\Common\Variables\Get;
use Cleantalk\Common\Variables\Server;

#[\AllowDynamicProperties]
class Sfw extends \Cleantalk\Common\Firewall\FirewallModule
{
    public $module_name = 'SFW';

    private $test_status;
    private $test_entry;
    private $blocked_ips = array();

    /**
     * @var string Content of the die page
     */
    private $sfw_die_page;

    /**
     * @var string|null
     */
    private $db__table__data;

    /**
     * @var string|null
     */
    private $db__table__data_personal;

    /**
     * @var string|null
     */
    private $db__table__logs;

    /**
     * FireWall_module constructor.
     * Use this method to prepare any data for the module working.
     *
     * @param string $log_table
     * @param string $data_table
     * @param $params
     */
    public function __construct($log_table, $data_table, $params = array())
    {
        parent::__construct($log_table, $data_table, $params);

        /** @var \Cleantalk\Common\Db\Db $db_class */
        $db_class = Mloader::get('Db');
        $db = $db_class::getInstance();
        $this->db = $db;

        $this->db__table__data = $db->prefix . $data_table ?: null;
        $this->db__table__logs = $db->prefix . $log_table ?: null;

        // Set personal table name from params or default
        if ( !empty($params['data_table_personal']) ) {
            $this->db__table__data_personal = $db->prefix . $params['data_table_personal'];
        } elseif ( defined('APBCT_TBL_FIREWALL_DATA_PERSONAL') ) {
            $this->db__table__data_personal = $db->prefix . APBCT_TBL_FIREWALL_DATA_PERSONAL;
        }

        foreach ( $params as $param_name => $param ) {
            $this->$param_name = isset($this->$param_name) ? $param : false;
        }

        $this->debug = (bool)static::getVariable('debug');
    }

    /**
     * @param $name
     * @return mixed
     * @psalm-taint-source input
     */
    public static function getVariable($name)
    {
        return Get::get($name);
    }

    /**
     * @inheritDoc
     */
    public function ipAppendAdditional(&$ips)
    {
        $this->real_ip = isset($ips['real']) ? $ips['real'] : null;
        $helper_class = $this->helper;

        if ( static::getVariable('sfw_test_ip') ) {
            if ( $helper_class::ipValidate(static::getVariable('sfw_test_ip')) !== false ) {
                $ips['sfw_test'] = static::getVariable('sfw_test_ip');
                $this->test_ip = htmlentities(static::getVariable('sfw_test_ip'), ENT_QUOTES);
                $this->test = true;
            }
        }
    }

    /**
     * Use this method to execute main logic of the module.
     *
     * @return array  Array of the check results
     */
    public function check()
    {
        $results = array();
        $status = 0;
        $helper_class = $this->helper;

        if ( $this->test ) {
            unset($_COOKIE['ct_sfw_pass_key']);
            Cookie::set('ct_sfw_pass_key', '0');
        }

        // Skip by cookie
        foreach ( $this->ip_array as $current_ip ) {
            if (
                Cookie::get('ct_sfw_pass_key')
                && strpos(Cookie::get('ct_sfw_pass_key'), md5($current_ip . $this->api_key)) === 0
            ) {
                if ( Cookie::get('ct_sfw_passed') ) {
                    if ( !headers_sent() ) {
                        Cookie::set(
                            'ct_sfw_passed',
                            '0',
                            time() + 86400 * 3,
                            '/',
                            '',
                            null,
                            true
                        );
                    } else {
                        $results[] = array(
                            'ip' => $current_ip,
                            'is_personal' => false,
                            'status' => 'PASS_SFW__BY_COOKIE'
                        );
                    }

                    // Do logging one passed request
                    $this->updateLog($current_ip, 'PASS_SFW');
                }

                if ( strlen(Cookie::get('ct_sfw_pass_key')) > 32 ) {
                    $status = substr(Cookie::get('ct_sfw_pass_key'), -1);
                }

                if ( $status ) {
                    $results[] = array(
                        'ip' => $current_ip,
                        'is_personal' => false,
                        'status' => 'PASS_SFW__BY_WHITELIST'
                    );
                }

                return $results;
            }
        }

        // Common check
        foreach ( $this->ip_array as $_origin => $current_ip ) {
            $current_ip_v4 = sprintf("%u", ip2long($current_ip));
            for ( $needles = array(), $m = 6; $m <= 32; $m++ ) {
                $mask = str_repeat('1', $m);
                $mask = str_pad($mask, 32, '0');
                $needles[] = sprintf("%u", bindec($mask & base_convert($current_ip_v4, 10, 2)));
            }
            $needles = array_unique($needles);

            $query = $this->db->sfwGetFromBlacklist($this->db__table__data, $this->db__table__data_personal, $needles, $current_ip_v4);

            $db_results = $this->db->fetchAll($query);

            $test_status = 1;
            if ( !empty($db_results) ) {
                // Personal lists have priority over common lists
                // Sort: personal entries first
                usort($db_results, function ($a, $b) {
                    return (int)$b['is_personal'] - (int)$a['is_personal'];
                });

                $result_entry = null;
                foreach ( $db_results as $db_result ) {
                    $is_personal = !empty($db_result['is_personal']);
                    $entry = array(
                        'ip' => $current_ip,
                        'network' => $helper_class::ipLong2ip($db_result['network'])
                            . '/'
                            . $helper_class::ipMaskLongToNumber((int)$db_result['mask']),
                        'is_personal' => $is_personal,
                    );

                    if ( (int)$db_result['status'] === 1 ) {
                        $entry['status'] = 'PASS_SFW__BY_WHITELIST';
                    }
                    if ( (int)$db_result['status'] === 0 ) {
                        $this->blocked_ips[] = $helper_class::ipLong2ip($db_result['network']);
                        $entry['status'] = 'DENY_SFW';
                    }

                    // Personal entry is decisive - use it and stop
                    if ( $is_personal ) {
                        $result_entry = $entry;
                        $test_status = (int)$db_result['status'];
                        break;
                    }

                    // Common entry - use as fallback if no personal found
                    if ( $result_entry === null ) {
                        $result_entry = $entry;
                        $test_status = (int)$db_result['status'];
                    }
                }
            } else {
                $result_entry = array(
                    'ip' => $current_ip,
                    'is_personal' => false,
                    'status' => 'PASS_SFW',
                );
            }

            $results[] = $result_entry;

            if ( $this->test && $_origin === 'sfw_test' ) {
                $this->test_status = $test_status;
                $this->test_entry = $result_entry;
            }
        }

        return $results;
    }

    /**
     * Add entry to SFW log.
     * Writes to database.
     *
     * @param string $ip
     * @param $status
     * @param string $network
     * @param string $source
     */
    public function updateLog($ip, $status, $network = 'NULL', $source = 'NULL')
    {
        $query = $this->db->getUpdateLogQuery($this->db__table__logs, $this->module_name, $status, $ip, $source);

        $this->db->prepareAndExecute(
            $query,
            array(
                Server::get('HTTP_USER_AGENT'),
                $network,
                substr(Server::get('HTTP_HOST') . Server::get('REQUEST_URI'), 0, 100),
                substr(Server::get('HTTP_HOST') . Server::get('REQUEST_URI'), 0, 100),

                Server::get('HTTP_USER_AGENT'),
                $network,
                substr(Server::get('HTTP_HOST') . Server::get('REQUEST_URI'), 0, 100),
            )
        );
    }

    public function actionsForDenied($result)
    {
        // Additional actions for the denied requests here
    }

    public function actionsForPassed($result)
    {
        // Additional actions for the passed requests here

        /*if ($this->data__cookies_type === 'native' && ! headers_sent()) {
            $status     = $result['status'] === 'PASS_SFW__BY_WHITELIST' ? '1' : '0';
            $cookie_val = md5($result['ip'] . $this->api_key) . $status;
            Cookie::setNativeCookie(
                'ct_sfw_pass_key',
                $cookie_val,
                time() + 86400 * 30,
                '/'
            );
        }*/
    }

    /**
     * Shows DIE page.
     * Stops script executing.
     *
     * @param array $result
     */
    public function diePage($result)
    {
        $fw_stats = Firewall::getFwStats();

        /** @var \Cleantalk\Common\RemoteCalls\Remotecalls $remote_calls_class */
        $remote_calls_class = Mloader::get('RemoteCalls');

        /** @var \Cleantalk\Common\StorageHandler\StorageHandler $storage_handler */
        $storage_handler = Mloader::get('StorageHandler');

        // File exists?
        if ( file_exists(__DIR__ . "/die_page_sfw.html") ) {
            $this->sfw_die_page = file_get_contents(__DIR__ . "/die_page_sfw.html");

            $net_count = $fw_stats->entries;

            $status = $result['status'] === 'PASS_SFW__BY_WHITELIST' ? '1' : '0';
            $cookie_val = md5($result['ip'] . $this->api_key) . $status;

            $block_message = sprintf(
                $this->localize->translate('SpamFireWall is checking your browser and IP %s for spam bots'),
                '<a href="https://cleantalk.org/blacklists/' . $result['ip'] . '" target="_blank">' . $result['ip'] . '</a>'
            );

            $request_uri = Server::get('REQUEST_URI');
            if ( $this->test ) {
                // Remove "sfw_test_ip" get parameter from the uri
                $request_uri = preg_replace('%sfw_test_ip=\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}&?%', '', $request_uri);
            }

            $request_uri = htmlspecialchars($request_uri, ENT_QUOTES | ENT_HTML5, 'UTF-8');

            // @ToDo not implemented yet
            // Custom Logo
            //$custom_logo_img = '';

            // Translation
            $replaces = array(
                '{SFW_DIE_NOTICE_IP}' => $block_message,
                '{SFW_DIE_MAKE_SURE_JS_ENABLED}' => $this->localize->translate('To continue working with the web site, please make sure that you have enabled JavaScript.'),
                '{SFW_DIE_CLICK_TO_PASS}' => $this->localize->translate('Please click the link below to pass the protection,'),
                '{SFW_DIE_YOU_WILL_BE_REDIRECTED}' => sprintf(
                    $this->localize->translate('Or you will be automatically redirected to the requested page after %d seconds.'),
                    3
                ),
                '{CLEANTALK_TITLE}' => ($this->test ? $this->localize->translate('This is the testing page for SpamFireWall') : ''),
                '{REMOTE_ADDRESS}' => $result['ip'],
                '{SERVICE_ID}' => $net_count,
                '{HOST}' => $remote_calls_class::getSiteUrl(),
                '{GENERATED}' => '<p>' . $this->localize->translate('The page was generated at') . '&nbsp;' . date('D, d M Y H:i:s') . '</p>',
                '{REQUEST_URI}' => $request_uri,

                // Cookie
                '{COOKIE_PREFIX}' => '',
                '{COOKIE_DOMAIN}' => '',
                '{COOKIE_SFW}' => $cookie_val,
                '{COOKIE_ANTICRAWLER}' => hash('sha256', $this->api_key . ''),

                // Test
                '{TEST_TITLE}' => '',
                '{REAL_IP__HEADER}' => '',
                '{TEST_IP__HEADER}' => '',
                '{TEST_IP}' => '',
                '{REAL_IP}' => '',
                '{SCRIPT_URL}' => $storage_handler::getJsLocation(),

                // Message about IP status
                '{MESSAGE_IP_STATUS}' => '',

                // Custom Logo
                '{CUSTOM_LOGO}' => ''
            );

            /**
             * Message about IP status
             */
            $message_ip_status = '';
            $message_ip_status_color = 'green';

            // Determine entry to use: test_entry for test mode, $result for live mode
            $status_entry = $this->test ? $this->test_entry : $result;
            $entry_status = isset($status_entry['status']) ? $status_entry['status'] : null;
            $is_personal = isset($status_entry['is_personal']) && (int)$status_entry['is_personal'] === 1;

            $common_text_passed = $this->localize->translate('This IP is passed');
            $common_text_blocked = $this->localize->translate('This IP is blocked');
            $global_text = $this->localize->translate('(in global lists)');
            $personal_text = $this->localize->translate('(in personal lists)');
            $lists_text = $is_personal ? $personal_text : $global_text;

            if ( $entry_status === 'PASS_SFW__BY_WHITELIST' ) {
                $message_ip_status = $common_text_passed . ' ' . $lists_text;
                $message_ip_status_color = 'green';
            } elseif ( $entry_status === 'DENY_SFW' ) {
                $message_ip_status = $common_text_blocked . ' ' . $lists_text;
                $message_ip_status_color = 'red';
            } elseif ( $entry_status === 'PASS_SFW' || $entry_status === 'PASS_SFW__BY_COOKIE' ) {
                $message_ip_status = $this->localize->translate('This IP is passed (not in any lists)');
                $message_ip_status_color = 'green';
            }

            if ( !empty($message_ip_status) ) {
                $replaces['{MESSAGE_IP_STATUS}'] = "<h3 style='color:$message_ip_status_color;'>$message_ip_status</h3>";
            }

            // Test
            if ( $this->test ) {
                $replaces['{TEST_TITLE}'] = $this->localize->translate('This is the testing page for SpamFireWall');
                $replaces['{REAL_IP__HEADER}'] = $this->localize->translate('Real IP:');
                $replaces['{TEST_IP__HEADER}'] = $this->localize->translate('Test IP:');
                $replaces['{TEST_IP}'] = $this->test_ip;
                $replaces['{REAL_IP}'] = $this->real_ip;
            }

            // Debug
            if ( $this->debug ) {
                $debug = '<h1>Headers</h1>'
                    . var_export(Helper::httpGetHeaders(), true)
                    . '<h1>REMOTE_ADDR</h1>'
                    . Server::get('REMOTE_ADDR')
                    . '<h1>SERVER_ADDR</h1>'
                    . Server::get('REMOTE_ADDR')
                    . '<h1>IP_ARRAY</h1>'
                    . var_export($this->ip_array, true)
                    . '<h1>ADDITIONAL</h1>'
                    . var_export($this->debug_data, true);
            }
            $replaces['{DEBUG}'] = isset($debug) ? $debug : '';

            foreach ( $replaces as $place_holder => $replace ) {
                $replace = is_null($replace) ? '' : $replace;
                $this->sfw_die_page = str_replace($place_holder, $replace, $this->sfw_die_page);
            }
        }

        $this->printDiePage($result);
    }

    public function printDiePage($result)
    {
        parent::diePage($result);

        $localize_js = array(
            'sfw__random_get' => '1',
        );

        $localize_js_public = array();


        $replaces = array(
            '{JQUERY_SCRIPT_URL}' => '',
            '{LOCALIZE_SCRIPT}' => 'var ct_setcookie = 1; var ctPublicFunctions = ' . json_encode($localize_js) . ';' .
                'var ctPublic = ' . json_encode($localize_js_public) . ';',
        );

        foreach ( $replaces as $place_holder => $replace ) {
            $replace = is_null($replace) ? '' : $replace;
            $this->sfw_die_page = str_replace($place_holder, $replace, $this->sfw_die_page);
        }

        // File exists?
        if ( file_exists(__DIR__ . "/die_page_sfw.html") ) {
            die($this->sfw_die_page);
        }

        die("IP BLACKLISTED. Blocked by SFW " . $result['ip']);
    }

    /**
     * Sends and wipe SFW log
     *
     * @param $db
     * @param $log_table
     * @param string $ct_key Access key
     * @param bool $_use_delete_command Determs whether use DELETE or TRUNCATE to delete the logs table data
     *
     * @return array|bool array('error' => STRING)
     */
    public static function sendLog($db, $log_table, $ct_key, $_use_delete_command)
    {
        //Getting logs
        $query = "SELECT * FROM $log_table ORDER BY entries_timestamp DESC LIMIT 0," . APBCT_SFW_SEND_LOGS_LIMIT . ";";
        $db->fetchAll($query);

        if ( count($db->result) ) {
            $logs = $db->result;

            //Compile logs
            $ids_to_delete = array();
            $data = array();
            foreach ( $logs as $_key => &$value ) {
                $ids_to_delete[] = $value['id'];

                // Converting statuses to API format
                $value['status'] = $value['status'] === 'DENY_ANTICRAWLER' ? 'BOT_PROTECTION' : $value['status'];
                $value['status'] = $value['status'] === 'PASS_ANTICRAWLER' ? 'BOT_PROTECTION' : $value['status'];
                $value['status'] = $value['status'] === 'DENY_ANTICRAWLER_UA' ? 'BOT_PROTECTION' : $value['status'];
                $value['status'] = $value['status'] === 'PASS_ANTICRAWLER_UA' ? 'BOT_PROTECTION' : $value['status'];

                $value['status'] = $value['status'] === 'DENY_ANTIFLOOD' ? 'FLOOD_PROTECTION' : $value['status'];
                $value['status'] = $value['status'] === 'PASS_ANTIFLOOD' ? 'FLOOD_PROTECTION' : $value['status'];
                $value['status'] = $value['status'] === 'DENY_ANTIFLOOD_UA' ? 'FLOOD_PROTECTION' : $value['status'];
                $value['status'] = $value['status'] === 'PASS_ANTIFLOOD_UA' ? 'FLOOD_PROTECTION' : $value['status'];

                $value['status'] = $value['status'] === 'PASS_SFW__BY_COOKIE' ? 'DB_MATCH' : $value['status'];
                $value['status'] = $value['status'] === 'PASS_SFW' ? 'DB_MATCH' : $value['status'];
                $value['status'] = $value['status'] === 'DENY_SFW' ? 'DB_MATCH' : $value['status'];

                $value['status'] = $value['source'] ? 'PERSONAL_LIST_MATCH' : $value['status'];

                $additional = array();
                if ( $value['network'] ) {
                    $additional['nd'] = $value['network'];
                }
                if ( $value['first_url'] ) {
                    $additional['fu'] = $value['first_url'];
                }
                if ( $value['last_url'] ) {
                    $additional['lu'] = $value['last_url'];
                }
                $additional = $additional ?: 'EMPTY_ASSOCIATIVE_ARRAY';

                $data[] = array(
                    trim($value['ip']),
                    // IP
                    $value['blocked_entries'],
                    // Count showing of block pages
                    $value['all_entries'] - $value['blocked_entries'],
                    // Count passed requests after block pages
                    $value['entries_timestamp'],
                    // Last timestamp
                    $value['status'],
                    // Status
                    $value['ua_name'],
                    // User-Agent name
                    $value['ua_id'],
                    // User-Agent ID
                    $additional
                    // Network, first URL, last URL
                );
            }
            unset($value);

            /** @var \Cleantalk\Common\Api\Api $api_class */
            $api_class = Mloader::get('Api');

            //Sending the request
            $result = $api_class::methodSfwLogs($ct_key, $data);
            //Checking answer and deleting all lines from the table
            if ( empty($result['error']) ) {
                if ( $result['rows'] == count($data) ) {
                    $db->execute("BEGIN;");
                    $db->execute("DELETE FROM $log_table WHERE id IN ( '" . implode('\',\'', $ids_to_delete) . "' );");
                    $db->execute("COMMIT;");

                    return $result;
                }

                return array('error' => 'SENT_AND_RECEIVED_LOGS_COUNT_DOESNT_MACH');
            } else {
                return $result;
            }
        } else {
            return array('rows' => 0);
        }
    }

    public static function directUpdateGetBlackLists($api_key)
    {
        /** @var \Cleantalk\Common\Api\Api $api_class */
        $api_class = Mloader::get('Api');
        /** @var \Cleantalk\Common\Helper\Helper $helper_class */
        $helper_class = Mloader::get('Helper');

        // Getting common blacklists via multifiles v3_2 (common_lists=1 means ONLY common)
        $result = $api_class::methodGet2sBlacklistsDb($api_key, 'multifiles', '3_2', 1);

        if ( !empty($result['error']) ) {
            return $result;
        }

        if ( empty($result['file_url']) ) {
            return array('error' => 'COMMON_LISTS_FILE_URL_IS_EMPTY');
        }

        // Get the index of file URLs from the multifiles response
        $file_urls = $helper_class::httpGetDataFromRemoteGzAndParseCsv($result['file_url']);
        if ( !empty($file_urls['error']) ) {
            return array('error' => 'COMMON_LISTS_GET_INDEX: ' . $file_urls['error']);
        }

        // Download and parse each common list file from the index
        $all_entries = array();

        foreach ( $file_urls as $file_url_entry ) {
            if ( empty($file_url_entry[0]) ) {
                continue;
            }

            $url = $file_url_entry[0];

            $file_data = $helper_class::httpGetDataFromRemoteGz($url);
            if ( !is_string($file_data) ) {
                continue;
            }

            $parsed = $helper_class::bufferParseCsv($file_data);
            if ( !is_array($parsed) ) {
                continue;
            }

            foreach ( $parsed as $entry ) {
                if ( !empty($entry[0]) && !empty($entry[1]) ) {
                    $all_entries[] = $entry;
                }
            }
        }

        // Get useragents from separate API response field
        $useragents = null;
        if ( !empty($result['file_ua_url']) ) {
            $ua_data = $helper_class::httpGetDataFromRemoteGz($result['file_ua_url']);
            if ( is_string($ua_data) ) {
                $useragents = $helper_class::bufferParseCsv($ua_data);
                if ( !is_array($useragents) ) {
                    $useragents = null;
                }
            }
        }

        if ( empty($all_entries) ) {
            return array('error' => 'COMMON_LISTS_NO_ENTRIES');
        }

        return array(
            'blacklist' => $all_entries,
            'useragents' => $useragents,
            'bl_count' => count($all_entries),
            'ua_count' => is_array($useragents) ? count($useragents) : 0,
        );
    }

    public static function directUpdateGetBlackListsPersonal($api_key)
    {
        /** @var \Cleantalk\Common\Api\Api $api_class */
        $api_class = Mloader::get('Api');
        /** @var \Cleantalk\Common\Helper\Helper $helper_class */
        $helper_class = Mloader::get('Helper');

        // Getting personal blacklists file URL (common_lists=0 means personal only)
        $result = $api_class::methodGet2sBlacklistsDb($api_key, 'multifiles', '3_2', 0);

        if ( !empty($result['error']) ) {
            return $result;
        }

        if ( empty($result['file_url']) ) {
            return array('error' => 'PERSONAL_LISTS_FILE_URL_IS_EMPTY');
        }

        // Get the index of file URLs from the multifiles response
        $file_urls = $helper_class::httpGetDataFromRemoteGzAndParseCsv($result['file_url']);
        if ( !empty($file_urls['error']) ) {
            return array('error' => 'PERSONAL_LISTS_GET_INDEX: ' . $file_urls['error']);
        }

        // Download and parse each personal list file
        $all_entries = array();
        foreach ( $file_urls as $file_url_entry ) {
            if ( empty($file_url_entry[0]) ) {
                continue;
            }

            $url = $file_url_entry[0];

            // Skip non-blacklist files (ua_list, ck_list)
            if ( strpos($url, 'bl_list') === false ) {
                continue;
            }

            $file_data = $helper_class::httpGetDataFromRemoteGz($url);
            if ( !is_string($file_data) ) {
                continue;
            }

            $parsed = $helper_class::bufferParseCsv($file_data);
            if ( !is_array($parsed) ) {
                continue;
            }

            foreach ( $parsed as $entry ) {
                if ( !empty($entry[0]) && !empty($entry[1]) ) {
                    $all_entries[] = $entry;
                }
            }
        }

        if ( empty($all_entries) ) {
            return array('error' => 'PERSONAL_LISTS_NO_ENTRIES');
        }

        return array(
            'blacklist' => $all_entries,
        );
    }

    public static function directUpdate($db, $db__table__data, $blacklists)
    {
        if ( !is_array($blacklists) ) {
            return array('error' => 'BlackLists is not an array.');
        }
        for ( $count_result = 0; current($blacklists) !== false; ) {
            $query = "INSERT INTO " . $db__table__data . " (network, mask, status) VALUES ";

            for (
                $i = 0, $values = array();
                APBCT_WRITE_LIMIT !== $i && current($blacklists) !== false;
                $i++, $count_result++, next($blacklists)
            ) {
                $entry = current($blacklists);

                if ( empty($entry) ) {
                    continue;
                }

                // Cast result to int
                $ip = preg_replace('/[^\d]*/', '', $entry[0]);
                $mask = preg_replace('/[^\d]*/', '', $entry[1]);
                $private = isset($entry[2]) ? $entry[2] : 0;

                $values[] = '(' . $ip . ',' . $mask . ',' . $private . ')';
            }

            if ( !empty($values) ) {
                $query .= implode(',', $values) . ';';
                $result = $db->execute($query);
                if ( $result === false ) {
                    return array('error' => $db->getLastError());
                }
            }
        }

        return $count_result;
    }

    /**
     * Updates SFW local base
     *
     * @param $db
     * @param $db__table__data
     * @param null|string $file_url File URL with SFW data.
     *
     * @return array|int array('error' => STRING)
     */
    public static function updateWriteToDb($db, $db__table__data, $file_url = null, $include_source = true)
    {
        $file_content = file_get_contents($file_url);

        if ( function_exists('gzdecode') ) {
            $unzipped_content = @gzdecode($file_content);

            if ( $unzipped_content !== false ) {
                /** @var \Cleantalk\Common\Helper\Helper $helper_class */
                $helper_class = Mloader::get('Helper');
                $data = $helper_class::bufferParseCsv($unzipped_content);

                if ( empty($data['errors']) ) {
                    reset($data);

                    for ( $count_result = 0; current($data) !== false; ) {
                        $columns = $include_source
                            ? '(network, mask, status, source)'
                            : '(network, mask, status)';
                        $query = "INSERT INTO " . $db__table__data . " $columns VALUES ";

                        for (
                            $i = 0, $values = array();
                            APBCT_WRITE_LIMIT !== $i && current($data) !== false;
                            $i++, $count_result++, next($data)
                        ) {
                            $entry = current($data);

                            if ( empty($entry) || empty($entry[0]) || empty($entry[1]) ) {
                                continue;
                            }

                            // Cast result to int
                            $ip = preg_replace('/[^\d]*/', '', $entry[0]);
                            $mask = preg_replace('/[^\d]*/', '', $entry[1]);
                            $status = isset($entry[2]) ? $entry[2] : 0;
                            if ( $include_source ) {
                                $source = isset($entry[3]) ? (int)$entry[3] : 'NULL';
                                $values[] = "($ip, $mask, $status, $source)";
                            } else {
                                $values[] = "($ip, $mask, $status)";
                            }
                        }

                        if ( !empty($values) ) {
                            $query .= implode(',', $values) . ';';
                            if ( !$db->execute($query) ) {
                                return array(
                                    'error' => 'WRITE ERROR: FAILED TO INSERT DATA: ' . $db__table__data
                                        . ' DB Error: ' . $db->getLastError()
                                );
                            }
                            if ( file_exists($file_url) ) {
                                unlink($file_url);
                            }
                        }
                    }

                    return $count_result;
                } else {
                    return $data;
                }
            } else {
                return array('error' => 'Can not unpack datafile');
            }
        } else {
            return array('error' => 'Function gzdecode not exists. Please update your PHP at least to version 5.4 ');
        }
    }

    /**
     * @param $db
     * @param $db__table__data
     * @param $exclusions
     *
     * @return int|string[]
     *
     * @since version
     */
    public static function updateWriteToDbExclusions($db, $db__table__data, $exclusions = array())
    {
        $fw_stats = Firewall::getFwStats();

        /** @var \Cleantalk\Common\Helper\Helper $helper_class */
        $helper_class = Mloader::get('Helper');

        $query = 'INSERT INTO ' . $db__table__data . ' (network, mask, status) VALUES ';

        //Exclusion for servers IP (SERVER_ADDR)
        if ( Server::get('HTTP_HOST') ) {
            // Do not add exceptions for local hosts
            if ( !in_array(Server::getDomain(), array('lc', 'loc', 'lh')) ) {
                $exclusions[] = $helper_class::dnsResolve(Server::get('HTTP_HOST'));
                $exclusions[] = '127.0.0.1';
                // And delete all 127.0.0.1 entries for local hosts
            } else {
                // @ToDo Implement this after moving queries in the separate model class
            }
        }

        foreach ( $exclusions as $exclusion ) {
            if ( $helper_class::ipValidate($exclusion) && sprintf('%u', ip2long($exclusion)) ) {
                $query .= '('
                    . sprintf('%u', ip2long($exclusion))
                    . ', '
                    . sprintf('%u', bindec(str_repeat('1', 32)))
                    . ', 1),';
            }
        }

        if ( $exclusions ) {
            $sql_result = $db->execute(substr($query, 0, -1) . ';');

            return $sql_result === false
                ? array('error' => 'COULD_NOT_WRITE_TO_DB 4: ' . $db->getLastError())
                : count($exclusions);
        }

        return 0;
    }

    /**
     * Creating a temporary updating table
     *
     * @param \Cleantalk\Common\Db\Db $db database handler
     * @param array|string $table_names Array with table names to create
     *
     * @return bool|array
     */
    public static function createTempTables($db, $table_names)
    {
        // Cast it to array for simple input
        $table_names = (array)$table_names;

        foreach ( $table_names as $table_name ) {
            $table_name__temp = $table_name . '_temp';

            // Delete temporary table if it exists, to avoid errors after bad db migration
            if ( $db->isTableExists($table_name__temp) && !$db->execute('DROP TABLE ' . $table_name__temp . ';') ) {
                return array(
                    'error' => 'DELETE TEMP TABLES: COULD NOT DROP ' . $table_name__temp
                        . ' DB Error: ' . $db->getLastError()
                );
            }

            if ( !$db->execute('CREATE TABLE `' . $table_name__temp . '` LIKE `' . $table_name . '`;') ) {
                return array(
                    'error' => 'CREATE TEMP TABLES: COULD NOT CREATE ' . $table_name__temp
                        . ' DB Error: ' . $db->getLastError()
                );
            }
        }

        return true;
    }

    /**
     * Delete tables with given names if they exists
     *
     * @param \Cleantalk\Common\Db\Db $db
     * @param array|string $table_names Array with table names to delete
     *
     * @return bool|array
     */
    public static function dataTablesDelete($db, $table_names)
    {
        // Cast it to array for simple input
        $table_names = (array)$table_names;

        foreach ( $table_names as $table_name ) {
            if ( $db->isTableExists($table_name) && !$db->execute('DROP TABLE ' . $table_name . ';') ) {
                return array(
                    'error' => 'DELETE TABLE: FAILED TO DROP: ' . $table_name
                        . ' DB Error: ' . $db->getLastError()
                );
            }
        }

        return true;
    }

    /**
     * Renaming a temporary updating table into production table name
     *
     * @param \Cleantalk\Common\Db\Db $db database handler
     * @param array|string $table_names Array with table names to rename
     *
     * @return bool|array
     */
    public static function renameDataTablesFromTempToMain($db, $table_names)
    {
        // Cast it to array for simple input
        $table_names = (array)$table_names;

        foreach ( $table_names as $table_name ) {
            $table_name__temp = $table_name . '_temp';

            if ( !$db->isTableExists($table_name__temp) ) {
                return array('error' => 'RENAME TABLE: TEMPORARY TABLE IS NOT EXISTS: ' . $table_name__temp);
            }

            if ( $db->isTableExists($table_name) ) {
                //return array('error' => 'RENAME TABLE: MAIN TABLE IS STILL EXISTS: ' . $table_name);
            }

            $rename_res = $db->renameTable($table_name__temp, $table_name);
            if ( !$rename_res ) {
                return array(
                    'error' => 'RENAME TABLE: FAILED TO RENAME: ' . $table_name
                        . ' DB Error: ' . $db->getLastError()
                );
            }
        }

        return true;
    }

    /**
     * Replace main table with temp table atomically using RENAME TABLE.
     * Main is renamed to _old, temp to main in one statement so the table is never missing.
     *
     * @param \Cleantalk\Common\Db\Db $db database handler
     * @param array|string $table_names Array with table names to replace
     *
     * @return bool|array true on success, array with 'error' key on failure
     */
    public static function replaceDataTablesAtomically($db, $table_names)
    {
        // Cast it to array for simple input
        $table_names = (array)$table_names;

        foreach ( $table_names as $table_name ) {
            $table_name__temp = $table_name . '_temp';
            $table_name__old = $table_name . '_old';

            if ( !$db->isTableExists($table_name__temp) ) {
                return array('error' => 'ATOMIC RENAME: TEMP TABLE NOT EXISTS: ' . $table_name__temp);
            }

            // Drop old table if exists from previous update
            if ( $db->isTableExists($table_name__old) ) {
                if ( !$db->execute('DROP TABLE IF EXISTS `' . $table_name__old . '`;') ) {
                    return array(
                        'error' => 'ATOMIC RENAME: FAILED TO DROP OLD TABLE: ' . $table_name__old
                            . ' DB Error: ' . $db->getLastError()
                    );
                }
            }

            // Atomic rename: main -> old, temp -> main (or just temp -> main if main not exists)
            if ( $db->isTableExists($table_name) ) {
                $query = 'RENAME TABLE `' . $table_name . '` TO `' . $table_name__old . '`, '
                       . '`' . $table_name__temp . '` TO `' . $table_name . '`;';
            } else {
                $query = 'RENAME TABLE `' . $table_name__temp . '` TO `' . $table_name . '`;';
            }

            if ( !$db->execute($query) ) {
                return array(
                    'error' => 'ATOMIC RENAME: FAILED: ' . $query
                        . ' DB Error: ' . $db->getLastError()
                );
            }

            // Clean up old table
            if ( $db->isTableExists($table_name__old) ) {
                $db->execute('DROP TABLE IF EXISTS `' . $table_name__old . '`;');
            }
        }

        return true;
    }

    /**
     * Add records to the personal SFW table.
     *
     * @param \Cleantalk\Common\Db\Db $db
     * @param string $db__table__data Personal table name
     * @param array $metadata Array of records with 'network', 'mask', 'status' keys
     *
     * @return array Result with 'total', 'added', 'updated', 'ignored' counts
     * @throws \RuntimeException
     */
    public static function privateRecordsAdd($db, $db__table__data, $metadata)
    {
        $added_count = 0;
        $updated_count = 0;
        $ignored_count = 0;

        foreach ( $metadata as $_key => $row ) {
            // Find duplicate to use it on updating
            $has_duplicate = false;
            $query = "SELECT id, status FROM " . $db__table__data . " WHERE "
                . "network = '" . (int)$row['network'] . "' AND "
                . "mask = '" . (int)$row['mask'] . "'";

            $db_result = $db->fetch($query);
            if ( $db_result === false ) {
                throw new \RuntimeException($db->getLastError());
            }

            // If the record is same - pass
            if ( isset($db_result['status']) && (int)$db_result['status'] === (int)$row['status'] ) {
                $ignored_count++;
                continue;
            }

            // If duplicate found create a chunk
            if ( isset($db_result['id']) ) {
                $id_chunk = "id = '" . (int)$db_result['id'] . "',";
                $has_duplicate = true;
            } else {
                $id_chunk = '';
            }

            // Insertion
            $query = "INSERT INTO " . $db__table__data . " SET "
                . $id_chunk
                . "network = '" . (int)$row['network'] . "',"
                . "mask = '" . (int)$row['mask'] . "',"
                . "status = '" . (int)$row['status'] . "' "
                . "ON DUPLICATE KEY UPDATE "
                . "id = id,"
                . "network = network,"
                . "mask = mask,"
                . "status = '" . (int)$row['status'] . "';";

            $db_result = $db->execute($query);
            if ( $db_result === false ) {
                throw new \RuntimeException($db->getLastError());
            }

            $added_count = $has_duplicate ? $added_count : $added_count + 1;
            $updated_count = $has_duplicate ? $updated_count + 1 : $updated_count;
        }

        return array(
            'total' => $added_count + $updated_count + $ignored_count,
            'added' => $added_count,
            'updated' => $updated_count,
            'ignored' => $ignored_count,
        );
    }

    /**
     * Delete records from the personal SFW table.
     *
     * @param \Cleantalk\Common\Db\Db $db
     * @param string $db__table__data Personal table name
     * @param array $metadata Array of records with 'network', 'mask' keys
     *
     * @return array Result with 'total', 'deleted', 'ignored' counts
     * @throws \Exception
     */
    public static function privateRecordsDelete($db, $db__table__data, $metadata)
    {
        $success_count = 0;
        $ignored_count = 0;

        foreach ( $metadata as $_key => $row ) {
            $query = "DELETE FROM " . $db__table__data . " WHERE "
                . "network = '" . (int)$row['network'] . "' AND "
                . "mask = '" . (int)$row['mask'] . "';";
            $db_result = $db->execute($query);
            if ( $db_result === false ) {
                throw new \Exception($db->getLastError());
            }

            $affected = (int)$db->getAffectedRows();
            if ( $affected === 0 ) {
                $ignored_count++;
            } else {
                $success_count += $affected;
            }
        }

        return array(
            'total' => $success_count + $ignored_count,
            'deleted' => $success_count,
            'ignored' => $ignored_count,
        );
    }
}
