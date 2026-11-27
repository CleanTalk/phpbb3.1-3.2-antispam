<?php

namespace cleantalk\antispam\cron\task;

use cleantalk\antispam\model\main_model;
use cleantalk\antispam\model\RequestBridge;

class cleantalk_antispam_sfw_update extends \phpbb\cron\task\base
{
    protected $config;
    protected $request;

    /** @var main_model */
    protected $main_model;

    public function __construct(\phpbb\config\config $config, \phpbb\request\request $request, main_model $main_model)
    {
        $this->config = $config;
        $this->request = $request;
        $this->main_model = $main_model;
    }

    public function run()
    {
        require_once(dirname(dirname(__DIR__)) . '/lib/autoload.php');
        RequestBridge::init($this->request);

        try {
            $firewall = new \Cleantalk\Common\Firewall\Firewall(
                $this->config['cleantalk_antispam_apikey'],
                APBCT_TBL_FIREWALL_LOG
            );

            $result = $firewall->getUpdater()->update();

            if (empty($result['error'])) {
                $this->config->set('cleantalk_antispam_sfw_update_last_gc', time());
            }
        } catch (\Exception $e) {
            $this->main_model->log_error('SpamFireWall update: ' . $e->getMessage());
        }
    }

    public function is_runnable()
    {
        return $this->config['cleantalk_antispam_sfw_enabled'] && $this->main_model->is_active();
    }

    public function should_run()
    {
        return (int) $this->config['cleantalk_antispam_sfw_update_last_gc'] < time() - (int) $this->config['cleantalk_antispam_sfw_update_gc'];
    }
}
