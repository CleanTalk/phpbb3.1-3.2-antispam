<?php

namespace cleantalk\antispam\cron\task;

class cleantalk_antispam_sfw_logs_send extends \phpbb\cron\task\base
{
	protected $config;

	public function __construct(\phpbb\config\config $config)
	{
		$this->config = $config;
	}

	public function run()
	{
		$autoload_path = dirname(dirname(__DIR__)) . '/lib/autoload.php';
		if (file_exists($autoload_path)) {
			require_once($autoload_path);
		}

		try {
			$api_key = $this->config['cleantalk_antispam_apikey'];
			$firewall = new \Cleantalk\Common\Firewall\Firewall(
				$api_key,
				APBCT_TBL_FIREWALL_LOG
			);

			$result = $firewall->sendLogs();

			if (!isset($result['error'])) {
				$this->config->set('cleantalk_antispam_sfw_logs_send_last_gc', time());
			}
		} catch (\Exception $e) {
			error_log('CleanTalk SFW send logs error: ' . $e->getMessage());
		}
	}

	public function is_runnable()
	{
		return ($this->config['cleantalk_antispam_sfw_enabled'] && $this->config['cleantalk_antispam_key_is_ok']);
	}

	public function should_run()
	{
		return (int) $this->config['cleantalk_antispam_sfw_logs_send_last_gc'] < time() - (int) $this->config['cleantalk_antispam_sfw_logs_send_gc'];
	}
}

