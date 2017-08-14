<?php

namespace cleantalk\antispam\cron\task;

class cleantalk_antispam_sfw_update extends \phpbb\cron\task\base
{

	protected $config;

	public function __construct(\phpbb\config\config $config)
	{
		$this->config = $config;
	}
		
	public function run()
	{
		
		\cleantalk\antispam\model\main_model::sfw_update($this->config['cleantalk_antispam_apikey']);
		
		$this->config->set('cleantalk_antispam_sfw_update_last_gc', time());
	}
	
	// Is allow to run?
	public function is_runnable()
	{	
		return ($this->config['cleantalk_antispam_sfw_enabled'] && $this->config['cleantalk_antispam_key_is_ok']);
	}
	
	// Next run
	public function should_run()
	{
		return (int)$this->config['cleantalk_antispam_sfw_update_last_gc'] < time() - (int)$this->config['cleantalk_antispam_sfw_update_gc'];
	}
	
}

