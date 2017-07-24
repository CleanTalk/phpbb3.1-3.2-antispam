<?php

namespace cleantalk\antispam\cron\task;

class cleantalk_antispam_check_payment_status extends \phpbb\cron\task\base
{

	protected $config;

	public function __construct(\phpbb\config\config $config)
	{
		$this->config = $config;
	}
		
	public function run()
	{
		\cleantalk\antispam\model\main_model::check_payment_status($this->config['cleantalk_antispam_apikey']);
		$this->config->set('cleantalk_antispam_check_payment_status_last_gc', time());
	}
	
	// Is allow to run?
	public function is_runnable()
	{	
		return true;
	}
	
	// Next run
	public function should_run()
	{
		return $this->config['cleantalk_antispam_check_payment_status_last_gc'] < time() - $this->config['cleantalk_antispam_check_payment_status_send_gc'];
	}
	
}

