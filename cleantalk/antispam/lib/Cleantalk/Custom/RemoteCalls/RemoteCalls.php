<?php

namespace Cleantalk\Custom\RemoteCalls;

use Cleantalk\Common\Mloader\Mloader;

/**
 * phpBB-specific Remote Calls handler for CleanTalk common libraries.
 * Defines available RC actions and their implementations.
 */
class RemoteCalls extends \Cleantalk\Common\RemoteCalls\RemoteCalls
{
    /**
     * Returns site root URL for self-requests.
     * Overrides parent to always return the root URL (without REQUEST_URI path),
     * so that test/worker RC requests are sent to the correct endpoint
     * regardless of whether update was initiated from ACP, cron, or another page.
     *
     * @return string
     */
    public static function getSiteUrl()
    {
        $scheme = (
            isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on'
                ? 'https'
                : 'http'
        );

        $host = isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : '';
        $host = preg_replace('/[^A-Za-z0-9.\-:\[\]]/', '', $host);

        return $scheme . '://' . $host . '/';
    }

    /**
     * Performs remote call to the current website.
     * Overrides parent to fix PHP 8.3 TypeError: parent checks !empty($result['error'])
     * on a string response which crashes in PHP 8.3.
     *
     * @param string $rc_action
     * @param string $plugin_name
     * @param string $api_key
     * @param array $params
     * @param array $patterns
     * @param bool $do_check
     *
     * @return array|bool|string
     */
    public static function perform($rc_action, $plugin_name, $api_key, $params, $patterns = array(), $do_check = true)
    {
        $host = static::getSiteUrl();
        $params = static::buildParameters($rc_action, $plugin_name, $api_key, $params);

        if ( $do_check ) {
            $result__rc_check_website = static::performTest($host, $params, $patterns);
            if ( is_array($result__rc_check_website) && !empty($result__rc_check_website['error']) ) {
                return $result__rc_check_website;
            }
        }

        $http = new \Cleantalk\Common\Http\Request();
        $result = $http
            ->setUrl($host)
            ->setData($params)
            ->setPresets($patterns)
            ->request();

        // Return error arrays as-is, convert successful string responses to true
        // to prevent PHP 8.3 TypeError when caller checks $result['error'] on a string
        if ( is_array($result) && !empty($result['error']) ) {
            return $result;
        }

        return true;
    }

    /**
     * Performs test remote call to the current website.
     * Overrides parent to fix PHP 8.3 TypeError when accessing string offset
     * with non-numeric key (e.g. "OK"['error']).
     *
     * @param string $host
     * @param array $params
     * @param array $patterns
     *
     * @return array|string
     */
    public static function performTest($host, $params, $patterns = array())
    {
        // Delete async pattern to get the result in this process
        $key = array_search('async', $patterns, true);
        if ( $key !== false ) {
            unset($patterns[$key]);
        }

        // Adding test flag
        $params = array_merge($params, array('test' => 'test'));

        // Perform test request
        $http = new \Cleantalk\Common\Http\Request();
        $result = $http
            ->setUrl($host)
            ->setData($params)
            ->setPresets($patterns)
            ->request();

        // Considering empty response as error
        if ( $result === '' ) {
            return array('error' => 'WRONG_SITE_RESPONSE TEST ACTION : ' . $params['spbc_remote_call_action'] . ' ERROR: EMPTY_RESPONSE');
        }

        // Error returned as array
        if ( is_array($result) && !empty($result['error']) ) {
            return array('error' => 'WRONG_SITE_RESPONSE TEST ACTION: ' . $params['spbc_remote_call_action'] . ' ERROR: ' . $result['error']);
        }

        // Expects 'OK' string as good response otherwise - error
        if ( is_string($result) && !preg_match('@^.*?OK$@', $result) ) {
            return array(
                'error' => 'WRONG_SITE_RESPONSE ACTION: '
                    . $params['spbc_remote_call_action']
                    . ' RESPONSE: '
                    . '"'
                    . htmlspecialchars(substr($result, 0, 400))
                    . '"'
            );
        }

        return $result;
    }

    /**
     * @var array Available remote call actions
     */
    protected $available_rc_actions = array(
        'close_renew_banner' => array(
            'last_call' => 0,
            'cooldown'  => self::COOLDOWN,
        ),
        'sfw_update' => array(
            'last_call' => 0,
            'cooldown'  => 0,
        ),
        'sfw_send_logs' => array(
            'last_call' => 0,
            'cooldown'  => self::COOLDOWN,
        ),
        'private_record_add' => array(
            'last_call' => 0,
            'cooldown'  => 0,
        ),
        'private_record_delete' => array(
            'last_call' => 0,
            'cooldown'  => 0,
        ),
    );

    /**
     * SFW update remote call action
     *
     * @return bool
     */
    public function action__sfw_update()
    {
        $firewall = new \Cleantalk\Common\Firewall\Firewall(
            $this->api_key,
            'cleantalk_sfw_logs'
        );

        return $firewall->getUpdater()->update();
    }

    /**
     * SFW send logs remote call action
     *
     * @return array|bool
     */
    public function action__sfw_send_logs()
    {
        $firewall = new \Cleantalk\Common\Firewall\Firewall(
            $this->api_key,
            'cleantalk_sfw_logs'
        );

        return $firewall->sendLogs();
    }

    /**
     * Close renew banner remote call action
     *
     * @return true
     */
    public function action__close_renew_banner()
    {
        return true;
    }

    /**
     * Add private/personal SFW record
     *
     * @return bool|int
     */
    public function action__private_record_add()
    {
        /** @var \Cleantalk\Common\Db\Db $db_class */
        $db_class = Mloader::get('Db');
        $db = $db_class::getInstance();

        return \Cleantalk\Common\Firewall\Modules\Sfw::privateRecordsAdd(
            $db,
            $db->prefix . 'cleantalk_sfw_personal'
        );
    }

    /**
     * Delete private/personal SFW record
     *
     * @return bool
     */
    public function action__private_record_delete()
    {
        /** @var \Cleantalk\Common\Db\Db $db_class */
        $db_class = Mloader::get('Db');
        $db = $db_class::getInstance();

        return \Cleantalk\Common\Firewall\Modules\Sfw::privateRecordsDelete(
            $db,
            $db->prefix . 'cleantalk_sfw_personal'
        );
    }
}
