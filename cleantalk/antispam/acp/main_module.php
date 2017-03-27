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
				
		if ($request->is_set_post('submit') || $request->is_set_post('get_key_auto'))
		{
			if (!check_form_key('cleantalk/antispam'))
				trigger_error('FORM_INVALID');

			$config->set('cleantalk_antispam_regs', $request->variable('cleantalk_antispam_regs', 0));
			$config->set('cleantalk_antispam_guests', $request->variable('cleantalk_antispam_guests', 0));
			$config->set('cleantalk_antispam_nusers', $request->variable('cleantalk_antispam_nusers', 0));
			$config->set('cleantalk_antispam_sfw_enabled', $request->variable('cleantalk_antispam_sfw_enabled', 0));
			
			$key_is_valid = false;
			$user_token_is_valid = false;
			
			if($request->is_set_post('submit'))
				$config->set('cleantalk_antispam_apikey', $request->variable('cleantalk_antispam_apikey', ''));
			
			if($request->is_set_post('get_key_auto')){
				
				if(!function_exists('sendRawRequest'))
					require_once(__DIR__."/../model/cleantalk.class.php");
				
				$req=Array();
				$req['method_name'] = 'get_api_key'; 
				$req['email'] = $config['board_email'];
				$req['website'] = $request->server('SERVER_NAME');
				$req['platform'] = 'phpbb31';
				$req['timezone'] = $config['board_timezone'];
				$req['product_name'] = 'antispam';
				$url = 'https://api.cleantalk.org';
				
				$result = \CleanTalkBase\sendRawRequest($url,$req);
				$result = ($result != false ? json_decode($result, true): false);
				
				if(isset($result['data']) && is_array($result['data'])){			
					$config->set('cleantalk_antispam_user_token', $result['data']['user_token']);
					$config->set('cleantalk_antispam_apikey', $result['data']['auth_key']);
					$savekey = $result['data']['auth_key'];
					$key_is_valid = true;
					$user_token_is_valid = true;					
				}
			}
			
			$savekey = $key_is_valid ? $savekey : $request->variable('cleantalk_antispam_apikey', '');
			
			if($savekey != ''){
								
				if(!$key_is_valid){
					if(!function_exists('noticePaidTill'))
						require_once(__DIR__."/../model/cleantalk.class.php");
					$result = \CleanTalkBase\sendRawRequest("https://api.cleantalk.org?method_name=notice_validate_key&auth_key=$savekey", array());
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
						
						if(!function_exists('noticePaidTill'))
							require_once(__DIR__."/../model/cleantalk.class.php");
					
						$result = \CleanTalkBase\noticePaidTill($savekey);
						$result = json_decode($result, true);
						if(isset($result['data']) && isset($result['data']['user_token']))
						$config->set('cleantalk_antispam_user_token', $result['data']['user_token']);
					
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

		$ct_del_user = $request->variable('ct_del_user', array(0), 		false, \phpbb\request\request_interface::POST);
		$ct_del_all = $request->variable('ct_delete_all', 			'', false, \phpbb\request\request_interface::POST);
				
		if($ct_del_all!='')
		{
			if (!function_exists('user_delete'))
			{
				include_once($phpbb_root_path . 'includes/functions_user.' . $phpEx);
			}
			$sql = 'SELECT * 
				FROM ' . USERS_TABLE . ' 
				WHERE ct_marked=1';
			$result = $db->sql_query($sql);
			while($row = $db->sql_fetchrow($result))
			{
				user_delete('remove', $row['user_id']);
			}
			$db->sql_freeresult($result);
		}
		
		if(sizeof($ct_del_user)>0)
		{
			if (!function_exists('user_delete'))
			{
				include_once($phpbb_root_path . 'includes/functions_user.' . $phpEx);
			}
			foreach($ct_del_user as $key=>$value)
			{
				user_delete('retain', $key);
			}
		}
		
		if(isset($_GET['check_users_spam']))
		{
			$sql = 'UPDATE ' . USERS_TABLE . ' 
				SET ct_marked=0';
			$result = $db->sql_query($sql);
			$sql = "SELECT * 
				FROM " . USERS_TABLE . " 
				WHERE user_password<>'';";
			$result = $db->sql_query($sql);
			$users = array(0 => array());
			$data=array(0 => array());
			$cnt=0;
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
				$send=implode(',',$data[$i]);
				$req="data=$send";
				$opts = array(
				    'http'=>array(
				        'method'=>"POST",
				        'content'=>$req,
				    )
				);
				$context = stream_context_create($opts);
				$result = @file_get_contents("https://api.cleantalk.org/?method_name=spam_check_cms&auth_key=".$config['cleantalk_antispam_apikey'], 0, $context);
								
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
		$sql = 'SELECT * 
			FROM ' . USERS_TABLE . '
			where ct_marked = 1';
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
