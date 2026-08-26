<?php

/**
 * The abstract class for any FireWall modules.
 * Compatible with any CMS.
 *
 * @version       1.0
 * @author        Cleantalk team (welcome@cleantalk.org)
 * @copyright (C) 2014 CleanTalk team (http://cleantalk.org)
 * @license       GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 * @since 2.49
 */

namespace Cleantalk\Common\Firewall;

use Cleantalk\Common\Helper\Helper;
use Cleantalk\Common\Mloader\Mloader;
use Cleantalk\Common\Variables\Get;

abstract class FirewallModule
{
    /**
     * @var string
     */
    protected $api_key;

    /**
     * @var string
     */
    public $module_name = 'FireWall Module';

    /**
     * @var array
     */
    protected $ip_array = array();

    /**
     * @var \Cleantalk\Common\Db\Db
     */
    protected $db;

    /**
     * @var string
     */
    protected $db_log_table_name;

    /**
     * @var string
     */
    protected $db_data_table_name;

    /**
     * @var \Cleantalk\Common\Helper\Helper
     */
    protected $helper;

    /**
     * @var string
     */
    protected $real_ip;

    /**
     * @var string
     */
    protected $test_ip;

    /**
     * @var bool
     */
    protected $test;

    /**
     * @var bool
     */
    protected $debug;

    /**
     * @var array
     */
    protected $debug_data = array();

    /**
     * @var \Cleantalk\Common\Localize\Localize
     */
    protected $localize;

    /**
     * FirewallModule constructor.
     * Use this method to prepare any data for the module working.
     *
     * @param string $log_table
     * @param string $data_table
     * @param array $params
     */
    public function __construct($log_table, $data_table, $params = array())
    {
        $this->helper = Mloader::get('Helper');
        /** @var \Cleantalk\Common\Db\Db $db_class */
        $db_class = Mloader::get('Db');
        $this->db = $db_class::getInstance();
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
     * Use this method to execute main logic of the module.
     *
     * @return array  Array of the check results
     */
    abstract public function check();

    /**
     * Do logic for denied request.
     *
     * @param string $result
     * @return void
     */
    abstract public function actionsForDenied($result);

    /**
     * Do logic for allowed request.
     *
     * @param string $result
     * @return void
     */
    abstract public function actionsForPassed($result);

    /**
     * Configure and set additional properties: real_ip, test_ip, test
     *
     * @param array $ips
     * @return void
     */
    public function ipAppendAdditional(&$ips)
    {
        $this->real_ip = isset($ips['real']) ? $ips['real'] : null;

        /** @var Helper $helper_class */
        $helper_class = Mloader::get('Helper');

        if ( static::getVariable('sfw_test_ip') && $helper_class::ipValidate(static::getVariable('sfw_test_ip')) !== false ) {
            $this->ip_array['sfw_test'] = static::getVariable('sfw_test_ip');
            $this->test_ip = static::getVariable('sfw_test_ip');
            $this->test = true;
        }
    }

    /**
     * Set Log Table name
     *
     * @param string $log_table_name
     */
    public function setLogTableName($log_table_name)
    {
        $this->db_data_table_name = $this->db->prefix . $this->db_data_table_name;
        $this->db_log_table_name = $log_table_name;
    }

    /**
     * Set API KEY
     *
     * @param string $api_key
     */
    public function setApiKey($api_key)
    {
        $this->api_key = $api_key;
    }

    /**
     * Set is debug property.
     *
     * @param bool $debug
     */
    public function setIsDebug($debug)
    {
        $this->debug = $debug;
    }

    /**
     * Set visitor's IP
     *
     * @param array $ip_array $ip_array = array( 'real' => '1.2.3.4' )
     */
    public function setIpArray($ip_array)
    {
        $this->ip_array = $ip_array;
    }

    /**
     * @param \Cleantalk\Common\Localize\Localize $localize
     * @return void
     */
    public function setLocalize(\Cleantalk\Common\Localize\Localize $localize)
    {
        $this->localize = $localize;
    }

    /**
     * Default die page for blocked requests.
     *
     * @param array $result
     */
    public function diePage($result)
    {
        // Headers
        if ( headers_sent() === false ) {
            header('Expires: ' . date(DATE_RFC822, mktime(0, 0, 0, 1, 1, 1971)));
            header('Cache-Control: no-store, no-cache, must-revalidate');
            header('Cache-Control: post-check=0, pre-check=0', false);
            header('Pragma: no-cache');
            header("HTTP/1.0 403 Forbidden");
        }
    }
}
