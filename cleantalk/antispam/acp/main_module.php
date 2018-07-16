<?php
/**
*
* @package phpBB Extension - Antispam by CleanTalk
* @author Сleantalk team (welcome@cleantalk.org)
* @copyright (C) 2014 СleanTalk team (http://cleantalk.org)
* @license GNU/GPL: http://www.gnu.org/copyleft/gpl.html
*
*/

namespace cleantalk\antispam\acp;

use phpbb\config\config;
use phpbb\template\template;
use phpbb\request\request;
use phpbb\user;

class main_module
{
	/* @var \phpbb\template\template */
	protected $template;

	/* @var \phpbb\config\config */
	protected $config;

	/* @var \phpbb\user */
	protected $user;

	/* @var \phpbb\request\request */
	protected $request;

	/* @var \phpbb\db\driver\driver_interface */
	protected $db;
	
	/** @var string phpBB Root Path */
	protected $phpbb_root_path;

	/** @var string php file extension  */
	protected $php_ext;

	/* @var \cleantalk\antispam\model\CleantalkSFW */
	protected $cleantalk_sfw;

	/* @var \cleantalk\antispam\model\CleantalkHelper */
	protected $cleantalk_helper;

	/* @var \cleantalk\antispam\model\main_model */
	protected $main_model;		

	/**
	* Constructor
	*
	* @param template		$template	Template object
	* @param config			$config		Config object
	* @param user			$user		User object
	* @param request		$request	Request object
	* @param driver_interface 	$db 		The database object
	*/
	public function __construct(config $config, user $user, request $request, \cleantalk\antispam\model\CleantalkHelper $cleantalk_helper, \cleantalk\antispam\model\CleantalkSFW $cleantalk_sfw, \cleantalk\antispam\model\main_model $main_model, $phpbb_root_path, $php_ext )
	{	
		$this->config = $config;
		$this->user = $user;
		$this->request = $request;
		$this->phpbb_root_path = $phpbb_root_path;
		$this->php_ext = $php_ext;		
		$this->cleantalk_helper = $cleantalk_helper;
		$this->cleantalk_sfw = $cleantalk_sfw;
		$this->main_model = $main_model;
	}
	
	function main($id, $mode)
	{	
		$this->user->add_lang('acp/common');
		$this->tpl_name = 'settings_body';
		$this->page_title = $this->user->lang('ACP_CLEANTALK_TITLE');
		add_form_key('cleantalk/antispam');
		if ($this->request->is_set_post('submit') || $this->request->is_set_post('get_key_auto')){
			
			if (!check_form_key('cleantalk/antispam')){
				trigger_error('FORM_INVALID');
			}

			$this->config->set('cleantalk_antispam_regs', $this->request->variable('cleantalk_antispam_regs', 0));
			$this->config->set('cleantalk_antispam_guests', $this->request->variable('cleantalk_antispam_guests', 0));
			$this->config->set('cleantalk_antispam_nusers', $this->request->variable('cleantalk_antispam_nusers', 0));
			$this->config->set('cleantalk_antispam_ccf', $this->request->variable('cleantalk_antispam_ccf',0));
			$this->config->set('cleantalk_antispam_sfw_enabled', $this->request->variable('cleantalk_antispam_sfw_enabled', 0));
			
			$key_is_valid = false;
			$user_token_is_valid = false;
			
			if($this->request->is_set_post('submit')){
				$this->config->set('cleantalk_antispam_apikey', $this->request->variable('cleantalk_antispam_apikey', ''));
			}
			
			if($this->request->is_set_post('get_key_auto')){
							
				$result = $this->cleantalk_helper->getApiKey(
					$this->config['board_email'],
					$this->request->server('SERVER_NAME'),
					'phpbb31',
					$this->config['board_timezone']
				);
				
				if(empty($result['error'])){
						
					$this->config->set('cleantalk_antispam_apikey', $result['auth_key']);
					$savekey = $result['auth_key'];
					$key_is_valid = true;
					if(!empty($result['user_token'])){
						$this->config->set('cleantalk_antispam_user_token', $result['user_token']);
						$user_token_is_valid = true;
					}else{
						$this->config->set('cleantalk_antispam_user_token', '');
						$user_token_is_valid = false;
					}
				}
			}
			
			$savekey = $key_is_valid ? $savekey : $this->request->variable('cleantalk_antispam_apikey', '');
			
			if($savekey != ''){
				
				if(!$key_is_valid){
					$result = $this->cleantalk_helper->noticeValidateKey($savekey);
					if(empty($result['error'])){
						$key_is_valid = $result['valid'] ? true : false;
					}
				}
				
				if($key_is_valid){
					
					$this->config->set('cleantalk_antispam_key_is_ok', 1);
					
					if($this->config['cleantalk_antispam_sfw_enabled']){
						$this->cleantalk_sfw->sfw_update($savekey);
						$this->cleantalk_sfw->send_logs($savekey);
					}
					
					if(!$user_token_is_valid){
						
						$result =$this->cleantalk_helper->noticePaidTill($savekey);
						
						if(empty($result['error'])){
							$this->config->set('cleantalk_antispam_show_notice', ($result['show_notice']) ? $result['show_notice'] : 0);
							$this->config->set('cleantalk_antispam_renew',       ($result['renew']) ? $result['renew'] : 0);
							$this->config->set('cleantalk_antispam_trial',       ($result['trial']) ? $result['trial'] : 0);
							$this->config->set('cleantalk_antispam_user_token',  ($result['user_token']) ? $result['user_token'] : '');
							$this->config->set('cleantalk_antispam_spam_count',  ($result['spam_count']) ? $result['spam_count'] : 0);
							$this->config->set('cleantalk_antispam_moderate_ip', ($result['moderate_ip']) ? $result['moderate_ip'] : 0);
							$this->config->set('cleantalk_antispam_ip_license',  ($result['ip_license']) ? $result['ip_license'] : 0);
						}
					}	
					$composer_json = json_decode(file_get_contents($this->phpbb_root_path . 'ext/cleantalk/antispam/composer.json'));
					
					$ct_feedback = array();
					$ct_feedback['auth_key'] = $savekey;
					$ct_feedback['type'] = 'send_feedback';
					$ct_feedback['feedback'] = '0:phpbb31-' . preg_replace("/(\d+)\.(\d*)\.?(\d*)/", "$1$2$3", $composer_json->version);
					$this->main_model->check_spam($ct_feedback);
				}else{
					$this->config->set('cleantalk_antispam_key_is_ok', 0);
					$this->config->set('cleantalk_antispam_user_token', '');
				}
			}else{
				$this->config->set('cleantalk_antispam_key_is_ok', 0);
				$this->config->set('cleantalk_antispam_user_token', '');
			}
			
			trigger_error($this->user->lang('ACP_CLEANTALK_SETTINGS_SAVED') . adm_back_link($this->u_action));
		}
		
		$this->template->assign_vars(array(
			'U_ACTION'				=> $this->u_action,
			'CLEANTALK_ANTISPAM_REGS'		=> $this->config['cleantalk_antispam_regs'] ? true : false,
			'CLEANTALK_ANTISPAM_GUESTS'		=> $this->config['cleantalk_antispam_guests'] ? true : false,
			'CLEANTALK_ANTISPAM_NUSERS'		=> $this->config['cleantalk_antispam_nusers'] ? true : false,
			'CLEANTALK_ANTISPAM_CCF'		=> $this->config['cleantalk_antispam_ccf'] ? true: false,
			'CLEANTALK_ANTISPAM_SFW_ENABLED'=> $this->config['cleantalk_antispam_sfw_enabled'] ? true : false,
			'CLEANTALK_ANTISPAM_APIKEY'		=> $this->config['cleantalk_antispam_apikey'],
			'CLEANTALK_ANTISPAM_KEY_IS_OK'	=> $this->config['cleantalk_antispam_key_is_ok'] ? true : false,
			'CLEANTALK_ANTISPAM_USER_TOKEN'	=> $this->config['cleantalk_antispam_user_token'],
			'CLEANTALK_ANTISPAM_REG_EMAIL'	=> $this->config['board_email'],
			'CLEANTALK_ANTISPAM_REG_URL'	=> $this->request->server('SERVER_NAME'),
		));

		$this->user->add_lang_ext('cleantalk/antispam', 'common');

		$ct_del_user = $this->request->variable('ct_del_user',   array(0), false, \phpbb\request\request_interface::POST);
		$ct_del_all  = $this->request->variable('ct_delete_all', '',       false, \phpbb\request\request_interface::POST);
				
		if($ct_del_all!=''){

			if (!check_form_key('cleantalk/antispam')){
				trigger_error('FORM_INVALID');
			}
			
			if (!function_exists('user_delete')){
				include_once($this->phpbb_root_path . 'includes/functions_user.' . $this->php_ext);
			}
			$sql = 'SELECT * 
				FROM ' . USERS_TABLE . ' 
				WHERE ct_marked=1';
			$result = $this->db->sql_query($sql);
			while($row = $this->db->sql_fetchrow($result)){
				user_delete('remove', $row['user_id']);
			}
			$this->db->sql_freeresult($result);
		}
		
		if(sizeof($ct_del_user)>0){
			if (!check_form_key('cleantalk/antispam')){
				trigger_error('FORM_INVALID');
			}
			if (!function_exists('user_delete')){
				include_once($this->phpbb_root_path . 'includes/functions_user.' . $this->php_ext);
			}
			foreach($ct_del_user as $key=>$value){
				user_delete('remove', $key);
			}
		}
		if($this->request->variable('check_spam', '',       false, \phpbb\request\request_interface::POST)){
			if (!check_form_key('cleantalk/antispam')){
				trigger_error('FORM_INVALID');
			}
			$sql = 'UPDATE ' . USERS_TABLE . ' 
				SET ct_marked=0';
			$result = $this->db->sql_query($sql);
			$sql = "SELECT user_id, username, user_regdate, user_lastvisit, user_ip, user_email
				FROM " . USERS_TABLE . " 
				WHERE user_password<>''
				ORDER BY user_regdate DESC;";
			$result = $this->db->sql_query($sql);
			
			$users  = array(0 => array());
			$data   = array(0 => array());
			$cnt    = 0;
			while($row = $this->db->sql_fetchrow($result))
			{
				$users[$cnt][] = array(
					'name'   => $row['username'],
					'id'     => $row['user_id'],
					'email'  => $row['user_email'],
					'ip'     => $row['user_ip'],
					'joined' => $row['user_regdate'],
					'visit'  => $row['user_lastvisit'],
				);
				$data[$cnt][]=$row['user_email'];
				$data[$cnt][]=$row['user_ip'];
				
				if(sizeof($users[$cnt])>450)
				{
					$cnt++;
					$users[$cnt]=array();
					$data[$cnt]=array();
				}
			}
			
			$this->db->sql_freeresult($result);
			$error="";
			for($i=0;$i<sizeof($users);$i++)
			{
				
				$result = $this->cleantalk_helper->spamCheckCms($this->config['cleantalk_antispam_apikey'], $data[$i]);
				
				if(!empty($result['error']))
				{					
					if($result['error_string'] == 'CONNECTION_ERROR'){
						$error = $this->user->lang('ACP_CHECKUSERS_DONE_3');
					}
					else {
						$error = $result['error_message'];
					}
				}
				else
				{
					foreach($result as $key => $value)
					{
						if($key === filter_var($key, FILTER_VALIDATE_IP))
						{
							if(strval($value['appears']) == 1)
							{
								$sql = "UPDATE " . USERS_TABLE . " 
								SET ct_marked=1 
								WHERE user_ip='".$this->db->sql_escape($key)."'";
								$this->db->sql_query($sql);
							}
						}
						else
						{
							if(strval($value['appears']) == 1)
							{
								$sql = "UPDATE " . USERS_TABLE . "
									SET ct_marked=1 
									WHERE user_email='".$this->db->sql_escape($key)."'";
								$this->db->sql_query($sql);
							}
						}
					}
				}
			}

			if($error!='')
			{
				$this->template->assign_var('CT_ERROR', $error);
			}
			else
			{
				$this->template->assign_var('CT_ACP_CHECKUSERS_DONE_1',1);
			}
		}
		$start_entry = 0;		
		if($this->request->is_set('start_entry', \phpbb\request\request_interface::GET))
		{
			$start_entry = $this->request->variable('start_entry', 1);
		}
		$on_page = 20;
		$sql = 'SELECT COUNT(user_id) AS user_count
			FROM ' . USERS_TABLE . '
			WHERE ct_marked = 1';
		$this->db->sql_query($sql);
		$spam_users_count = (int)$this->db->sql_fetchfield('user_count');

		$sql = 'SELECT * 
			FROM ' . USERS_TABLE . '
			WHERE ct_marked = 1';
		$result = $this->db->sql_query_limit($sql, $on_page, $start_entry);
		$found = false;
		while($row = $this->db->sql_fetchrow($result))
		{			
			$found = true;
			$this->template->assign_block_vars('CT_SPAMMERS', array(
				'USER_POSTS_LINK'	=> append_sid($this->phpbb_root_path.'search.'.$this->php_ext, array('author_id' => $row['user_id'], 'sr' => 'posts'), false),
			    'USER_ID'			=> $row['user_id'],
			    'USER_POSTS'		=> $row['user_posts'],
			    'USERNAME'			=> get_username_string('username', $row['user_id'], $row['username'], $row['user_colour']),
			    'JOINED'			=> (!$row['user_regdate']) ? ' - ' : $this->user->format_date(intval($row['user_regdate'])),
			    'USER_EMAIL'		=> $row['user_email'],
			    'USER_IP'			=> $row['user_ip'],
			    'LAST_VISIT'		=> (!$row['user_lastvisit']) ? ' - ' : $this->user->format_date(intval($row['user_lastvisit'])),
			));
		}
		$this->db->sql_freeresult($result);
		$pages = ceil($spam_users_count / $on_page); 
		$server_uri = append_sid('index.'.$this->php_ext,array('i'=>$this->request->variable('i','1')));
		if ($pages>1)
		{
			$this->template->assign_var('CT_PAGES_TITLE',1);
			for ($i=1; $pages >= $i; $i++){
				$this->template->assign_block_vars('CT_PAGES_CHECKUSERS', array(
					'PAGE_LINK' => $server_uri.'&start_entry='.($i-1)*$on_page.'&curr_page='.$i,
					'PAGE_NUMBER' => $i, 
					'PAGE_STYLE' => 'background: rgba(23,96,147,'.(($this->request->variable('curr_page',1) == $i) ? '0.6' : '0.3').');',

				));							
			}			
		}
		if ($found)
		{
			$this->template->assign_var('CT_TABLE_USERS_SPAM', '1');
		}
		if(!$found && $this->request->variable('check_spam', '',       false, \phpbb\request\request_interface::POST))
		{
			$this->template->assign_var('CT_ACP_CHECKUSERS_DONE_2', '1');
		}
	}
}
