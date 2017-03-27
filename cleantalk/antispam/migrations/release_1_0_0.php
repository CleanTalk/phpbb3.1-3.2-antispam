<?php
/**
*
* @package phpBB Extension - Antispam by CleanTalk
* @author Сleantalk team (welcome@cleantalk.org)
* @copyright (C) 2014 СleanTalk team (http://cleantalk.org)
* @license GNU/GPL: http://www.gnu.org/copyleft/gpl.html
*
*/

namespace cleantalk\antispam\migrations;

class release_1_0_0 extends \phpbb\db\migration\migration
{
	public function effectively_installed()
	{
		return isset($this->config['cleanalk_antispam_apikey']);
	}

	static public function depends_on()
	{
		return array('\phpbb\db\migration\data\v310\alpha2');
	}

	public function update_data()
	{
		return array(
			//Visible settings
			array('config.add', array('cleantalk_antispam_regs', 1)),
			array('config.add', array('cleantalk_antispam_guests', 1)),
			array('config.add', array('cleantalk_antispam_nusers', 1)),
			array('config.add', array('cleantalk_antispam_sfw_enabled', 0)),
			array('config.add', array('cleantalk_antispam_apikey', '')),
			//System settings
			array('config.add', array('cleantalk_antispam_work_url', 'http://moderate.cleantalk.org')),
			array('config.add', array('cleantalk_antispam_server_url', 'http://moderate.cleantalk.org')),
			array('config.add', array('cleantalk_antispam_server_ttl', 0)),
			array('config.add', array('cleantalk_antispam_server_changed', 0)),
			array('config.add', array('cleantalk_antispam_error_time', 0)),
			array('config.add', array('cleantalk_antispam_key_is_ok', 0)),
			array('config.add', array('cleantalk_antispam_user_token', '')),
			array('config.add', array('cleantalk_antispam_sfw_networks', '')), //Count of SFW networks. inactive.
			
			//SFW update cron task
			array('config.add', array('cleantalk_antispam_sfw_update_last_gc', 0)),
			array('config.add', array('cleantalk_antispam_sfw_update_gc', (86400))),
			//SFW logs send cron task
			array('config.add', array('cleantalk_antispam_sfw_logs_send_last_gc', 0)),
			array('config.add', array('cleantalk_antispam_sfw_logs_send_gc', (3600))),
			
			array('module.add', array(
				'acp',
				'ACP_CAT_DOT_MODS',
				'ACP_CLEANTALK_TITLE'
			)),
			array('module.add', array(
				'acp',
				'ACP_CLEANTALK_TITLE',
				array(
					'module_basename'	=> '\cleantalk\antispam\acp\main_module',
					'modes'			=> array('settings'),
				),
			)),
		);
	}

	public function update_schema()
	{
		//* Fix for ct_marked in USERS_TABLE without defaul value
		global $db;		
		$sql = "SHOW COLUMNS 
			FROM `".USERS_TABLE."`
			LIKE 'ct_marked'";
		$result = $db->sql_query($sql);
		if($result->num_rows){
			$sql = 'ALTER TABLE ' . USERS_TABLE .
			' ALTER  `ct_marked`
			 SET DEFAULT 0';
			$result = $db->sql_query($sql);
		}
		//*/
		
		$sql = "SHOW COLUMNS 
			FROM `".USERS_TABLE."`
			LIKE 'ct_marked'";
		$result = $db->sql_query($sql);
				
		return array(	
			'add_columns'	=> array(
				SESSIONS_TABLE			=> array(
					'ct_submit_time'	=> array('INT:11', '0'),
				),
				USERS_TABLE			=> array(
					'ct_marked'	=> array('INT:11', '0'),
				),
			),
			'add_tables'    => array(
				$this->table_prefix . 'cleantalk_sfw_logs' => array(
					'COLUMNS' => array(
						'ip'				=> array('VCHAR_UNI:15', ''),
						'all_entries'		=> array('INT:11', NULL),
						'blocked_entries'   => array('INT:11', NULL),
						'entries_timestamp' => array('INT:11', NULL),
					),
					'PRIMARY_KEY' => 'ip',
				),
				$this->table_prefix . 'cleantalk_sfw' => array(
					'COLUMNS' => array(
						'network'	=> array('UINT:11', '0'),
						'mask'		=> array('UINT:11', '0'),
					),
				),
			),
		);
	}

	public function revert_schema()
	{	
		return array(
			'drop_columns' => array(
				SESSIONS_TABLE			=> array('ct_submit_time'),
				USERS_TABLE			=> array('ct_marked'),
			),
			'drop_tables' => array(
				$this->table_prefix . 'cleantalk_sfw_logs',
				$this->table_prefix . 'cleantalk_sfw',
			),
		);
	}

}
