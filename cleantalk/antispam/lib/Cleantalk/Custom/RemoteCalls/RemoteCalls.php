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
