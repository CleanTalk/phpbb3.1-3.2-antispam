<?php

namespace cleantalk\antispam\cron\task;

use cleantalk\antispam\model\SuperGlobals;

class cleantalk_antispam_sfw_update extends \phpbb\cron\task\base
{
    protected $config;
    protected $request;

    public function __construct(\phpbb\config\config $config, \phpbb\request\request $request)
    {
        $this->config = $config;
        $this->request = $request;
    }

    public function run()
    {
        $autoload_path = dirname(dirname(__DIR__)) . '/lib/autoload.php';
        if (file_exists($autoload_path)) {
            require_once($autoload_path);
        }

        $super_globals_were_disabled = SuperGlobals::areDisabled($this->request);

        try {
            if ($super_globals_were_disabled) {
                $this->request->enable_super_globals();
            }

            $api_key = $this->config['cleantalk_antispam_apikey'];
            $firewall = new \Cleantalk\Common\Firewall\Firewall(
                $api_key,
                APBCT_TBL_FIREWALL_LOG
            );

            $result = $firewall->getUpdater()->update();

            if (empty($result['error'])) {
                $this->config->set('cleantalk_antispam_sfw_update_last_gc', time());
            }
        } catch (\Exception $e) {
            error_log('CleanTalk SFW update error: ' . $e->getMessage());
        } finally {
            SuperGlobals::restore($this->request, $super_globals_were_disabled);
        }
    }

    public function is_runnable()
    {
        return ($this->config['cleantalk_antispam_sfw_enabled'] && $this->config['cleantalk_antispam_key_is_ok']);
    }

    public function should_run()
    {
        return (int) $this->config['cleantalk_antispam_sfw_update_last_gc'] < time() - (int) $this->config['cleantalk_antispam_sfw_update_gc'];
    }
}
