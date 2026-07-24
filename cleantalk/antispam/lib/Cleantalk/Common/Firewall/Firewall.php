<?php

/**
 * CleanTalk FireWall core class.
 * Compatible with any CMS.
 *
 * @version       3.4
 * @author        Cleantalk team (welcome@cleantalk.org)
 * @copyright (C) 2014 CleanTalk team (http://cleantalk.org)
 * @license       GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 * @see           https://github.com/CleanTalk/php-antispam
 */

namespace Cleantalk\Common\Firewall;

use Cleantalk\Common\Mloader\Mloader;
use Cleantalk\Common\Variables\Cookie;
use Cleantalk\Common\Variables\Get;
use Cleantalk\Common\Variables\Server;

class Firewall
{
    const FW_STATS_SETTING_NAME = 'apbct_fw_stats';

    /**
     * @var string
     */
    public $api_key;

    /**
     * @var array
     */
    private $ip_array;

    /**
     * @var \Cleantalk\Common\Db\Db
     */
    public $db;

    /**
     * @var string
     */
    private $log_table_name;

    /**
     * @var \Cleantalk\Common\Helper\Helper
     */
    public $helper;

    /**
     * @var \Cleantalk\Common\Api\Api
     */
    public $api;

    /**
     * @var bool
     */
    private $debug;

    /**
     * Hard-coded available FW result statuses.
     * This order using for the results prioritizing too.
     *
     * @var array
     */
    private $statuses_priority = array(
        // Lowest
        'PASS_SFW',
        'PASS_SFW__BY_COOKIE',
        'PASS_ANTIFLOOD_UA',
        'PASS_ANTIFLOOD',
        'PASS_ANTICRAWLER_UA',
        'PASS_ANTICRAWLER',
        'DENY_ANTIFLOOD_UA',
        'DENY_ANTIFLOOD',
        'DENY_ANTICRAWLER_UA',
        'DENY_ANTICRAWLER',
        'DENY_SFW',
        'PASS_SFW__BY_WHITELIST',
        'PASS_SFW__BY_STATUS',
        // Highest
    );

    /**
     * Array of FW modules objects (FirewallModule)
     *
     * @var array
     */
    private $fw_modules = array();

    /**
     * Array of FW modules names (strings)
     *
     * @var array
     */
    private $module_names = array();

    /**
     * @var \Cleantalk\Common\Localize\Localize
     */
    private $localize;

    /**
     * Set FW success checked cookies for 20 min.
     * For emergency usage only.
     *
     * @return bool
     */
    public static function temporarySkip()
    {
        global $apbct, $spbc;

        if ( !empty($_GET['access']) ) {
            $apbct_key = !empty($apbct->api_key) ? $apbct->api_key : false;
            $spbc_key = !empty($spbc->api_key) ? $spbc->api_key : false;
            if ( ($apbct_key !== false && $_GET['access'] === $apbct_key) || ($spbc_key !== false && $_GET['access'] === $spbc_key) ) {
                Cookie::set(
                    'spbc_firewall_pass_key',
                    md5(Server::get('REMOTE_ADDR') . $spbc_key),
                    time() + 1200,
                    '/',
                    ''
                );
                Cookie::set('ct_sfw_pass_key', md5(Server::get('REMOTE_ADDR') . $apbct_key), time() + 1200, '/', null);
                return true;
            }
        }
        return false;
    }

    /**
     * Creates Database driver instance.
     *
     * @param string $api_key
     * @param string $log_table_name
     */
    public function __construct($api_key, $log_table_name, $locale = 'en')
    {
        $this->helper = Mloader::get('Helper');
        /** @var \Cleantalk\Common\Db\Db $db_class */
        $db_class = Mloader::get('Db');
        $this->db = $db_class::getInstance();
        $this->api = Mloader::get('Api');

        $this->api_key = $api_key;
        $this->log_table_name = $this->db->prefix . $log_table_name;
        $this->debug = (bool)static::getVariable('debug');
        $this->ip_array = $this->ipGet();
        $localize_class = Mloader::get('Localize');
        $this->localize = new $localize_class(__DIR__ . '/lang', $locale);
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
     * Loads the FireWall module to the array.
     * Factory method for configure instance of FirewallModule.
     * Not returns anything, the result is private storage of the modules.
     *
     * @param FirewallModule $module
     */
    public function loadFwModule(FirewallModule $module)
    {
        if ( !in_array($module, $this->fw_modules) ) {
            // Configure the Module Obj
            $module->setApiKey($this->api_key);
            $module->setLogTableName($this->log_table_name);
            $module->ipAppendAdditional($this->ip_array);
            $module->setIpArray($this->ip_array);
            $module->setIsDebug($this->debug);
            $module->setLocalize($this->localize);

            // Store the Module Obj
            $this->fw_modules[$module->module_name] = $module;
        }
    }

    /**
     * Do main logic of the module.
     *
     * @return void   returns die page or set cookies
     */
    public function run()
    {
        $this->module_names = array_keys($this->fw_modules);

        $results = array();

        // Checking
        foreach ( $this->fw_modules as $module ) {
            if ( isset($module->isExcluded) && $module->isExcluded ) {
                continue;
            }

            $module_results = $module->check();
            if ( !empty($module_results) ) {
                $results[$module->module_name] = $module_results;
            }

            if ( $this->isWhitelisted($results) ) {
                // Break protection logic if it whitelisted or trusted network.
                break;
            }
        }

        // Write Logs
        foreach ( $this->fw_modules as $module ) {
            if ( array_key_exists($module->module_name, $results) ) {
                foreach ( $results[$module->module_name] as $result ) {
                    if (
                        in_array(
                            $result['status'],
                            array(
                                'PASS_SFW__BY_WHITELIST',
                                'PASS_SFW__BY_STATUS',
                                'PASS_SFW',
                                'PASS_ANTIFLOOD',
                                'PASS_ANTICRAWLER',
                                'PASS_ANTICRAWLER_UA',
                                'PASS_ANTIFLOOD_UA'
                            )
                        )
                    ) {
                        continue;
                    }
                    $module->updateLog(
                        $result['ip'],
                        $result['status'],
                        isset($result['network']) ? $result['network'] : null,
                        !empty($result['is_personal']) ? 1 : 'NULL'
                    );
                }
            }
        }

        // Get the primary result
        $result = $this->prioritize($results);

        // Do finish action - die or set cookies
        foreach ( $this->module_names as $module_name ) {
            if ( strpos($result['status'], $module_name) ) {
                // Blocked
                if ( strpos($result['status'], 'DENY') !== false ) {
                    $this->fw_modules[$module_name]->actionsForDenied($result);
                    $this->fw_modules[$module_name]->diePage($result);
                    // Allowed
                } elseif ( $result['status'] === 'PASS_SFW__BY_STATUS' ) {
                    $this->fw_modules[$module_name]->actionsForPassed($result);
                    $this->fw_modules[$module_name]->diePage($result);
                } else {
                    if ( Get::get('sfw_test_ip') ) {
                        $this->fw_modules[$module_name]->diePage($result);
                    }
                    $this->fw_modules[$module_name]->actionsForPassed($result);
                }
            }
        }
    }

    /**
     * Getting arrays of IP (REMOTE_ADDR, X-Forwarded-For, X-Real-Ip, Cf_Connecting_Ip)
     *
     * @param string $ips_input type of IP you want to receive
     * @param bool $v4_only
     *
     * @return array
     */
    public function ipGet($ips_input = 'real', $v4_only = true)
    {
        $helper_class = $this->helper;
        $result = $helper_class::ipGet($ips_input, $v4_only);

        return !empty($result) ? array('real' => $result) : array();
    }

    /**
     * Sets priorities for firewall results.
     * It generates one main result from multi-level results array.
     *
     * @param array $results
     *
     * @return array Single element array of result
     */
    private function prioritize($results)
    {
        $current_fw_result_priority = 0;
        $result = array('status' => 'PASS', 'passed_ip' => '');

        if ( is_array($results) ) {
            foreach ( $this->fw_modules as $module ) {
                if ( array_key_exists($module->module_name, $results) ) {
                    foreach ( $results[$module->module_name] as $fw_result ) {
                        $priority = array_search($fw_result['status'], $this->statuses_priority) +
                            (isset($fw_result['is_personal']) && $fw_result['is_personal'] ? count(
                                $this->statuses_priority
                            ) : 0);
                        if ( $priority >= $current_fw_result_priority ) {
                            $current_fw_result_priority = $priority;
                            $result['status'] = $fw_result['status'];
                            $result['passed_ip'] = isset($fw_result['ip']) ? $fw_result['ip'] : $fw_result['passed_ip'];
                            $result['blocked_ip'] = isset($fw_result['ip']) ? $fw_result['ip'] : $fw_result['blocked_ip'];
                            $result['pattern'] = isset($fw_result['pattern']) ? $fw_result['pattern'] : array();
                            $result['is_personal'] = !empty($fw_result['is_personal']) ? 1 : 0;
                        }
                    }
                }
            }
        }

        $result['ip'] = strpos($result['status'], 'PASS') !== false ? $result['passed_ip'] : $result['blocked_ip'];
        $result['passed'] = strpos($result['status'], 'PASS') !== false;

        return $result;
    }

    /**
     * Check the result if it whitelisted or trusted network
     *
     * @param array $results
     *
     * @return bool
     */
    private function isWhitelisted($results)
    {
        foreach ( $this->fw_modules as $module ) {
            if ( array_key_exists($module->module_name, $results) ) {
                foreach ( $results[$module->module_name] as $fw_result ) {
                    if (
                        strpos($fw_result['status'], 'PASS_BY_TRUSTED_NETWORK') !== false ||
                        strpos($fw_result['status'], 'PASS_BY_WHITELIST') !== false ||
                        strpos($fw_result['status'], 'PASS_SFW__BY_WHITELIST') !== false
                    ) {
                        return true;
                    }
                }
            }
        }
        return false;
    }

    /**
     * Sends and wipe SFW log
     *
     * @return array|bool array('error' => STRING)
     */
    public function sendLogs()
    {
        //Getting logs
        $query = "SELECT * FROM " . $this->log_table_name . ";";
        $this->db->fetchAll($query);

        if ( count($this->db->result) ) {
            //Compile logs
            $data = array();
            foreach ( $this->db->result as $key => $value ) {
                // Converting statuses to API format
                $value['status'] = $value['status'] === 'DENY_ANTICRAWLER' ? 'BOT_PROTECTION' : $value['status'];
                $value['status'] = $value['status'] === 'PASS_ANTICRAWLER' ? 'BOT_PROTECTION' : $value['status'];
                $value['status'] = $value['status'] === 'DENY_ANTICRAWLER_UA' ? 'BOT_PROTECTION' : $value['status'];
                $value['status'] = $value['status'] === 'PASS_ANTICRAWLER_UA' ? 'BOT_PROTECTION' : $value['status'];

                $value['status'] = $value['status'] === 'DENY_ANTIFLOOD' ? 'FLOOD_PROTECTION' : $value['status'];
                $value['status'] = $value['status'] === 'PASS_ANTIFLOOD' ? 'FLOOD_PROTECTION' : $value['status'];

                $value['status'] = $value['status'] === 'PASS_SFW__BY_COOKIE' ? null : $value['status'];
                $value['status'] = $value['status'] === 'PASS_SFW' ? null : $value['status'];
                $value['status'] = $value['status'] === 'DENY_SFW' ? null : $value['status'];

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
                );
            }
            unset($key, $value);

            //Sending the request
            $api_class = $this->api;
            $result = $api_class::methodSfwLogs($this->api_key, $data);

            //Checking answer and deleting all lines from the table
            if ( empty($result['error']) ) {
                if ( $result['rows'] == count($data) ) {
                    $this->db->execute("TRUNCATE TABLE " . $this->log_table_name . ";");
                    return $result;
                }

                return array('error' => 'SENT_AND_RECEIVED_LOGS_COUNT_DOESNT_MACH');
            }

            return $result;
        }

        return array('rows' => 0);
    }

    /**
     * Get and configure the FirewallUpdater object.
     *
     * @return FirewallUpdater
     */
    public function getUpdater()
    {
        return new FirewallUpdater($this);
    }

    public static function getFwStats()
    {
        $fw_stats = new FwStats();
        /** @var \Cleantalk\Common\StorageHandler\StorageHandler $storage_handler_class */
        $storage_handler_class = Mloader::get('StorageHandler');
        $storage_handler_class = new $storage_handler_class();
        $stats = $storage_handler_class->getSetting(self::FW_STATS_SETTING_NAME);
        if ( $stats !== null ) {
            foreach ( $stats as $stat_key => $stat_val ) {
                $fw_stats->$stat_key = $stat_val;
            }
        }
        return $fw_stats;
    }

    public static function saveFwStats(FwStats $fw_stats)
    {
        $stats = [];
        foreach ( $fw_stats as $stat_key => $stat_val ) {
            $stats[$stat_key] = $stat_val;
        }
        /** @var \Cleantalk\Common\StorageHandler\StorageHandler $storage_handler_class */
        $storage_handler_class = Mloader::get('StorageHandler');
        $storage_handler_class = new $storage_handler_class();
        return $storage_handler_class->saveSetting(self::FW_STATS_SETTING_NAME, $stats);
    }
}
