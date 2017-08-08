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

class main_module
{
	function main($id, $mode)
	{
		global $user, $template, $request, $config, $db, $phpbb_root_path, $phpEx;
		
		$user->add_lang('acp/common');
		$this->tpl_name = 'settings_body';
		$this->page_title = $user->lang('ACP_CLEANTALK_TITLE');
		add_form_key('cleantalk/antispam');
		
		if ($request->is_set_post('submit') || $request->is_set_post('get_key_auto')){
			
			if (!check_form_key('cleantalk/antispam'))
				trigger_error('FORM_INVALID');

			$config->set('cleantalk_antispam_regs', $request->variable('cleantalk_antispam_regs', 0));
			$config->set('cleantalk_antispam_guests', $request->variable('cleantalk_antispam_guests', 0));
			$config->set('cleantalk_antispam_nusers', $request->variable('cleantalk_antispam_nusers', 0));
			$config->set('cleantalk_antispam_sfw_enabled', $request->variable('cleantalk_antispam_sfw_enabled', 0));
			
			$key_is_valid = false;
			$user_token_is_valid = false;
			
			if($request->is_set_post('submit')){
				$config->set('cleantalk_antispam_apikey', $request->variable('cleantalk_antispam_apikey', ''));
			}
			
			if($request->is_set_post('get_key_auto')){
							
				$result = \cleantalk\antispam\acp\cleantalkHelper::getAutoKey(
					$config['board_email'],
					$request->server('SERVER_NAME'),
					'phpbb31',
					$config['board_timezone']
				);
				$result = ($result != false ? json_decode($result, true): false);
				
				if(isset($result['data']) && is_array($result['data'])){
						
					$config->set('cleantalk_antispam_apikey', $result['data']['auth_key']);
					$savekey = $result['data']['auth_key'];
					$key_is_valid = true;
					if(!empty($result['data']['user_token'])){
						$config->set('cleantalk_antispam_user_token', $result['data']['user_token']);
						$user_token_is_valid = true;
					}else{
						$config->set('cleantalk_antispam_user_token', '');
						$user_token_is_valid = false;
					}
				}
			}
			
			$savekey = $key_is_valid ? $savekey : $request->variable('cleantalk_antispam_apikey', '');
			
			if($savekey != ''){
				
				if(!$key_is_valid){
					
					$result = \cleantalk\antispam\acp\cleantalkHelper::noticeValidateKey($savekey);
					$result = json_decode($result, true);
					$key_is_valid = $result['valid'] ? true : false;
				}
				
				if($key_is_valid){
					
					$config->set('cleantalk_antispam_key_is_ok', 1);
					
					if($config['cleantalk_antispam_sfw_enabled']){
						\cleantalk\antispam\model\main_model::sfw_update($savekey);
						\cleantalk\antispam\model\main_model::sfw_send_logs($savekey);
					}
					
					if(!$user_token_is_valid){
						
						$result = \cleantalk\antispam\acp\cleantalkHelper::noticePaidTill($savekey);
						$result = json_decode($result, true);
						if(!empty($result['data'])){
							$config->set('cleantalk_antispam_show_notice', $result['data']['show_notice']);
							$config->set('cleantalk_antispam_renew',       $result['data']['renew']);
							$config->set('cleantalk_antispam_trial',       $result['data']['trial']);
							$config->set('cleantalk_antispam_user_token',  $result['data']['user_token']);
							$config->set('cleantalk_antispam_spam_count',  $result['data']['spam_count']);
							$config->set('cleantalk_antispam_moderate_ip', $result['data']['moderate_ip']);
							$config->set('cleantalk_antispam_ip_license',  $result['data']['ip_license']);
						}
					}	
					$composer_json = json_decode(file_get_contents($phpbb_root_path . 'ext/cleantalk/antispam/composer.json'));
					
					$ct_feedback = array();
					$ct_feedback['auth_key'] = $savekey;
					$ct_feedback['type'] = 'send_feedback';
					$ct_feedback['feedback'] = '0:phpbb31-' . preg_replace("/(\d+)\.(\d*)\.?(\d*)/", "$1$2$3", $composer_json->version);
					$result = \cleantalk\antispam\model\main_model::check_spam($ct_feedback);
				}else{
					$config->set('cleantalk_antispam_key_is_ok', 0);
					$config->set('cleantalk_antispam_user_token', '');
				}
			}else{
				$config->set('cleantalk_antispam_key_is_ok', 0);
				$config->set('cleantalk_antispam_user_token', '');
			}
			
			trigger_error($user->lang('ACP_CLEANTALK_SETTINGS_SAVED') . adm_back_link($this->u_action));
		}
		
		$template->assign_vars(array(
			'U_ACTION'				=> $this->u_action,
			'CLEANTALK_ANTISPAM_REGS'		=> $config['cleantalk_antispam_regs'] ? true : false,
			'CLEANTALK_ANTISPAM_GUESTS'		=> $config['cleantalk_antispam_guests'] ? true : false,
			'CLEANTALK_ANTISPAM_NUSERS'		=> $config['cleantalk_antispam_nusers'] ? true : false,
			'CLEANTALK_ANTISPAM_SFW_ENABLED'=> $config['cleantalk_antispam_sfw_enabled'] ? true : false,
			'CLEANTALK_ANTISPAM_APIKEY'		=> $config['cleantalk_antispam_apikey'],
			'CLEANTALK_ANTISPAM_KEY_IS_OK'	=> $config['cleantalk_antispam_key_is_ok'] ? true : false,
			'CLEANTALK_ANTISPAM_USER_TOKEN'	=> $config['cleantalk_antispam_user_token'],
			'CLEANTALK_ANTISPAM_REG_EMAIL'	=> $config['board_email'],
			'CLEANTALK_ANTISPAM_REG_URL'	=> $request->server('SERVER_NAME'),
		));

		$user->add_lang_ext('cleantalk/antispam', 'common');

		$ct_del_user = $request->variable('ct_del_user',   array(0), false, \phpbb\request\request_interface::POST);
		$ct_del_all  = $request->variable('ct_delete_all', '',       false, \phpbb\request\request_interface::POST);
				
		if($ct_del_all!=''){
			
			if (!function_exists('user_delete')){
				include_once($phpbb_root_path . 'includes/functions_user.' . $phpEx);
			}
			$sql = 'SELECT * 
				FROM ' . USERS_TABLE . ' 
				WHERE ct_marked=1';
			$result = $db->sql_query($sql);
			while($row = $db->sql_fetchrow($result)){
				user_delete('remove', $row['user_id']);
			}
			$db->sql_freeresult($result);
		}
		
		if(sizeof($ct_del_user)>0){
			
			if (!function_exists('user_delete')){
				include_once($phpbb_root_path . 'includes/functions_user.' . $phpEx);
			}
			foreach($ct_del_user as $key=>$value){
				user_delete('retain', $key);
			}
		}
		
		if(isset($_GET['check_users_spam'])){
			
			$sql = 'UPDATE ' . USERS_TABLE . ' 
				SET ct_marked=0';
			$result = $db->sql_query($sql);
			$sql = "SELECT * 
				FROM " . USERS_TABLE . " 
				WHERE user_password<>'';";
			$result = $db->sql_query($sql);
			$users  = array(0 => array());
			$data   = array(0 => array());
			$cnt    = 0;
			while($row = $db->sql_fetchrow($result))
			{
				$users[$cnt][] = array('name' => $row['username'],
									'id' => $row['user_id'],
									'email' => $row['user_email'],
									'ip' => $row['user_ip'],
									'joined' => $row['user_regdate'],
									'visit' => $row['user_lastvisit'],
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
			$db->sql_freeresult($result);
			
			$error="";
			for($i=0;$i<sizeof($users);$i++)
			{
				
				$result = \cleantalk\antispam\acp\cleantalkHelper::spamCheckCms($config['cleantalk_antispam_apikey'], implode(',',$data[$i]));
								
				$result=json_decode($result);
				
				if(isset($result->error_message))
				{
					$error = $result->error_message;
				}
				elseif($result == false)
				{
					$error = $user->lang('ACP_CHECKUSERS_DONE_3');
				}
				else
				{
					if(isset($result->data))
					{
						foreach($result->data as $key=>$value)
						{
							if($key === filter_var($key, FILTER_VALIDATE_IP))
							{
								if($value->appears==1)
								{
									$sql = "UPDATE " . USERS_TABLE . " 
									SET ct_marked=1 
									WHERE user_ip='".$db->sql_escape($key)."'";
									$result = $db->sql_query($sql);
								}
							}
							else
							{
								if($value->appears==1)
								{
									$sql = "UPDATE " . USERS_TABLE . "
										SET ct_marked=1 
										WHERE user_email='".$db->sql_escape($key)."'";
									$result = $db->sql_query($sql);
								}
							}
						}
					}
				}
			}

			if($error!='')
			{
				$template->assign_var('CT_ERROR', $error);
			}
			else
			{
				@header("Location: ".str_replace('&check_users_spam=1', '&finish_check=1', html_entity_decode($request->server('REQUEST_URI'))));
			}
		}
		$start_entry = '0';		
		if(isset($_GET['start_entry']) && intval($request->variable('start_entry',1)))
			$start_entry = strval(intval($request->variable('start_entry',1)));
		$on_page = '20';
		$end_entry = strval(intval($start_entry) + intval($on_page));
		$sql = 'SELECT COUNT(user_id) AS user_count
			FROM ' . USERS_TABLE . '
			where ct_marked = 1';
		$result = $db->sql_query($sql);
		$spam_users_count = (int)$db->sql_fetchfield('user_count');

		$sql = 'SELECT * 
			FROM ' . USERS_TABLE . '
			where ct_marked = 1
			LIMIT '.$start_entry.','.$end_entry.'';
		$result = $db->sql_query($sql);
		if($request->variable('finish_check', '', false, \phpbb\request\request_interface::GET)!='')
		{
			$template->assign_var('CT_ACP_CHECKUSERS_DONE_1', '1');
		}
		$found = false;
		while($row = $db->sql_fetchrow($result))
		{			
			$found = true;
			$template->assign_block_vars('CT_SPAMMERS', array(
				'USER_POSTS_LINK'	=> append_sid($phpbb_root_path.'search.'.$phpEx, array('author_id' => $row['user_id'], 'sr' => 'posts'), false),
			    'USER_ID'			=> $row['user_id'],
			    'USER_POSTS'		=> $row['user_posts'],
			    'USERNAME'			=> get_username_string('username', $row['user_id'], $row['username'], $row['user_colour']),
			    'JOINED'			=> (!$row['user_regdate']) ? ' - ' : $user->format_date(intval($row['user_regdate'])),
			    'USER_EMAIL'		=> $row['user_email'],
			    'USER_IP'			=> $row['user_ip'],
			    'LAST_VISIT'		=> (!$row['user_lastvisit']) ? ' - ' : $user->format_date(intval($row['user_lastvisit'])),
			));
		}
		$db->sql_freeresult($result);
		$pages = ceil(intval($spam_users_count) / $on_page);
		$server_uri = 'index.php?sid='.$request->variable('sid','1').'&i='.$request->variable('i','1');
		if ($pages>1)
		{
			$pages_str = "<ul><li style='display: inline-block; margin: 10px 5px;'>Pages:</li>";
			for($i=1; $pages >= $i; $i++){
				$pages_str  .= "					
					<li style='display: inline-block; padding: 3px 5px; background: rgba(23,96,147,".((isset($_GET['curr_page']) && $request->variable('start_entry',1) == $i) || (!isset($_GET['curr_page']) && $i == 1) ? "0.6" : "0.3")."); border-radius: 3px;'>
								<a href=".$server_uri."&start_entry=".($i-1)*$on_page."&curr_page=$i>$i</a>
					</li>";
				}
			$page_str.="</ul>";
			$template->assign_var('CT_CHECKUSERS_PAGES', $pages_str);
		}
		if ($found)
		{
			$template->assign_var('CT_TABLE_USERS_SPAM', '1');
		}
		if(!$found && $request->variable('finish_check', '', false, \phpbb\request\request_interface::GET) != '')
		{
			$template->assign_var('CT_ACP_CHECKUSERS_DONE_2', '1');
		}
	}
}
