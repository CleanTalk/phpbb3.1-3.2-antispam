<?php
/**
*
* @package phpBB Extension - Antispam by CleanTalk
* @author Сleantalk team (welcome@cleantalk.org)
* @copyright (C) 2014 СleanTalk team (http://cleantalk.org)
* @license GNU/GPL: http://www.gnu.org/copyleft/gpl.html
*
*/

namespace cleantalk\antispam\event;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;

/**
* Event listener
*/
class main_listener implements EventSubscriberInterface
{
	static public function getSubscribedEvents()
	{
		return array(
			'core.user_setup'				=> 'load_language_on_setup',
			'core.page_header_after'            		=> 'add_js_to_head',
			'core.add_form_key'				=> 'form_set_time',
			'core.posting_modify_submission_errors'		=> 'check_comment',
			'core.posting_modify_submit_post_before'	=> 'change_comment_approve',
			'core.user_add_modify_data'                     => 'check_newuser',
			'core.common'                     => 'check_users_spam',
		);
	}

	/* @var \phpbb\controller\helper */
	protected $helper;

	/* @var \phpbb\template\template */
	protected $template;

	/* @var array Stores result of spam checking of post or topic when needed*/
	private $ct_comment_result;

	/**
	* Constructor
	*
	* @param \phpbb\controller\helper	$helper		Controller helper object
	* @param \phpbb\template		$template	Template object
	*/
	public function __construct(\phpbb\controller\helper $helper, \phpbb\template\template $template)
	{
		$this->helper = $helper;
		$this->template = $template;
	}

	/**
	* Loads language
	*
	* @param array	$event		Array with event variable values
	*/
	public function load_language_on_setup($event)
	{
		$lang_set_ext = $event['lang_set_ext'];
		$lang_set_ext[] = array(
			'ext_name' => 'cleantalk/antispam',
			'lang_set' => 'common',
		);
		$event['lang_set_ext'] = $lang_set_ext;
	}

	/**
	* Fills tamplate variable by generated JS-code with unique hash
	*
	* @param array	$event		Array with event variable values
	*/
	public function add_js_to_head($event)
	{
		global $config;

		if (empty($config['cleantalk_antispam_apikey']) || $config['cleantalk_antispam_apikey'] == 'enter key') return;

		$this->template->assign_var('CT_JS_ADDON', \cleantalk\antispam\model\main_model::get_check_js_script());
	}

	/**
	* Sets from display time in table
	*
	* @param array	$event		Array with event variable values
	*/
	public function form_set_time($event)
	{
		global $config;

		if (empty($config['cleantalk_antispam_apikey']) || $config['cleantalk_antispam_apikey'] == 'enter key') return;

		$data = $event->get_data();
		$form_id = $data['form_name'];
		if ($config['cleantalk_antispam_guests'] && $form_id == 'posting' || $config['cleantalk_antispam_regs'] && $form_id == 'ucp_register')
		{
			\cleantalk\antispam\model\main_model::set_submit_time();
		}
	}

	/**
	* Checks post or topic to spam
	*
	* @param array	$event		Array with event variable values
	*/
	public function check_comment($event)
	{
		global $config, $user, $db, $request;

		if (empty($config['cleantalk_antispam_apikey']) || $config['cleantalk_antispam_apikey'] == 'enter key') return;

		$moderate = false;
		$this->ct_comment_result = null;

		if ($config['cleantalk_antispam_guests'] && $user->data['is_registered'] == 0)
		{
			$moderate = true;
		}
		else if ($config['cleantalk_antispam_nusers'] && $user->data['is_registered'] == 1)
		{
			$sql = 'SELECT g.group_name FROM ' . USER_GROUP_TABLE
			. ' ug JOIN ' . GROUPS_TABLE
			. ' g ON (ug.group_id = g.group_id) WHERE ug.user_id = '
			. (int) $user->data['user_id'] . ' AND '
			. 'g.group_name = \'NEWLY_REGISTERED\'';
			$result = $db->sql_query($sql);
			$row = $db->sql_fetchrow($result);
			if ($row !== false && isset($row['group_name']))
			{
				$moderate = true;
			}
			$db->sql_freeresult($result);
		}

		if ($moderate)
		{
			$data = $event->get_data();
			if (
				array_key_exists('post_data', $data) &&
				is_array($data['post_data']) &&
				array_key_exists('username', $data['post_data']) &&
				array_key_exists('post_subject', $data['post_data'])
			)
			{
				$spam_check = array();
				$spam_check['type'] = 'comment';
				$spam_check['sender_email'] = '';
				$spam_check['sender_nickname'] = '';
				if (array_key_exists('user_email', $data['post_data'])) $spam_check['sender_email'] = $data['post_data']['user_email'];
				if (array_key_exists('username', $data['post_data'])) $spam_check['sender_nickname'] = $data['post_data']['username'];
				if (array_key_exists('post_subject', $data['post_data'])) $spam_check['message_title'] = $data['post_data']['post_subject'];
				$spam_check['message_body'] = utf8_normalize_nfc($request->variable('message', '', true));
				if($spam_check['sender_email'] == '' && isset($user->data))
				{
					$spam_check['sender_email'] = $user->data['user_email'];
				}
				if($spam_check['sender_nickname'] == '' && isset($user->data))
				{
					$spam_check['sender_nickname'] = $user->data['username'];
				}
				
				$result = \cleantalk\antispam\model\main_model::check_spam($spam_check);
				if ($result['errno'] == 0 && $result['allow'] == 0) // Spammer exactly.
				{ 
					if ($result['stop_queue'] == 1)
					{
						// Output error
						array_push($data['error'], $result['ct_result_comment']);
						$event->set_data($data);
					}
					else
					{
						// No error output but send comment to manual approvement
						$this->ct_comment_result = $result;
					}
				}
			}
		}
	}

	/**
	* Marks soft-spam post or comment as manual approvement needed
	*
	* @param array	$event		Array with event variable values
	*/
	public function change_comment_approve($event)
	{
		global $config, $user, $db;

		if (empty($config['cleantalk_antispam_apikey']) || $config['cleantalk_antispam_apikey'] == 'enter key') return;

		// 'stop_queue' = 0 means to manual approvement
		if (isset($this->ct_comment_result) && is_array($this->ct_comment_result) && $this->ct_comment_result['stop_queue'] == 0)
		{
			$data = $event->get_data();
			$data['data']['post_visibility'] = ITEM_UNAPPROVED;
			$data['data']['topic_visibility'] = ITEM_UNAPPROVED;
			$data['data']['force_approved_state'] = 0;
			$event->set_data($data);
		}
	}

	/**
	* Checks user registration to spam
	*
	* @param array	$event		Array with event variable values
	*/
	public function check_newuser($event)
	{
		global $config;

		if (empty($config['cleantalk_antispam_apikey']) || $config['cleantalk_antispam_apikey'] == 'enter key') return;

		if ($config['cleantalk_antispam_regs'])
		{
			$data = $event->get_data();
			if (
				array_key_exists('user_row', $data) &&
				is_array($data['user_row']) &&
				array_key_exists('username', $data['user_row']) &&
				array_key_exists('user_email', $data['user_row'])
			)
			{
				$spam_check = array();
				$spam_check['type'] = 'register';
				$spam_check['sender_email'] = $data['user_row']['user_email'];
				$spam_check['sender_nickname'] = $data['user_row']['username'];
				if (array_key_exists('user_timezone', $data['user_row'])) $spam_check['timezone'] = $data['user_row']['user_timezone'];
				$result = \cleantalk\antispam\model\main_model::check_spam($spam_check);
				if ($result['errno'] == 0 && $result['allow'] == 0) // Spammer exactly.
				{
					trigger_error($result['ct_result_comment']);
				}
			}
		}
	}
	
	public function check_users_spam($event)
	{
		global $db, $config, $request, $phpbb_root_path, $phpEx;
		$ct_del_user=request_var('ct_del_user', Array(0));
		$ct_del_all=$request->variable('ct_delete_all', '', false, \phpbb\request\request_interface::POST);
		if($ct_del_all!='')
		{
			if (!function_exists('user_delete'))
			{
				include_once($phpbb_root_path . 'includes/functions_user.' . $phpEx);
			}
			$sql = 'SELECT * FROM ' . USERS_TABLE . ' where ct_marked=1';
			$result = $db->sql_query($sql);
			while($row = $db->sql_fetchrow($result))
			{
				user_delete('remove', $row['user_id']);
			}
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
			$sql = 'select * from '.USERS_TABLE.' limit 1;';
			$result = $db->sql_query($sql);
			$row = $db->sql_fetchrow($result);
			if(!isset($row['ct_marked']))
			{
				$sql = 'ALTER TABLE  ' . USERS_TABLE . ' ADD  `ct_marked` INT NOT NULL ';
				$result = $db->sql_query($sql);
			}
		
			$sql = 'UPDATE ' . USERS_TABLE . ' set ct_marked=0';
			$result = $db->sql_query($sql);
			$sql = 'SELECT * FROM ' . USERS_TABLE . ' where user_password<>"";';
			$result = $db->sql_query($sql);
			$users=Array();
			$users[0]=Array();
			$data=Array();
			$data[0]=Array();
			$cnt=0;
			while($row = $db->sql_fetchrow($result))
			{
				$users[$cnt][] = Array('name' => $row['username'],
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
					$users[$cnt]=Array();
					$data[$cnt]=Array();
				}
			}
			
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
				$result = @file_get_contents("https://api.cleantalk.org/?method_name=spam_check&auth_key=".$config['cleantalk_antispam_apikey'], 0, $context);
				$result=json_decode($result);
				if(isset($result->error_message))
				{
					$error=$result->error_message;
				}
				else
				{
					for($j=0;$j<sizeof($users[$i]);$j++)
					{
						$uip=$users[$i][$j]['ip'];
						if(empty($uip))continue;
						$uim=$users[$i][$j]['email'];
						if(empty($uim))continue;
						if($result->data->$uip->appears==1||$result->data->$uim->appears==1)
						{
							$sql = 'UPDATE ' . USERS_TABLE . ' set ct_marked=1 where user_id='.$users[$i][$j]['id'];
							$result = $db->sql_query($sql);
						}
					}
				}
				
			}
			
			
			
			if($error!='')
			{
				$error='<center><div style="border:2px solid red;color:red;font-size:16px;width:300px;padding:5px;"><b>'.$error.'</b></div></center>';
				$this->template->assign_var('CT_TABLE_USERS_SPAM', $error);
			}
			else
			{
				@header("Location: ".str_replace('&check_users_spam=1', '&finish_check=1', html_entity_decode($request->server('REQUEST_URI'))));
				
			}
		}
		if(strpos(__FILE__, 'cleantalk')!==false)
		{
			$sql = 'select * from '.USERS_TABLE.' limit 1;';
			$result = $db->sql_query($sql);
			$row = $db->sql_fetchrow($result);
			if(!isset($row['ct_marked']))
			{
				$sql = 'ALTER TABLE  ' . USERS_TABLE . ' ADD  `ct_marked` INT NOT NULL ';
				$result = $db->sql_query($sql);
			}
			
			$sql = 'SELECT * FROM ' . USERS_TABLE . ' where ct_marked=1';
			$result = $db->sql_query($sql);
			$html='';
			if($request->variable('finish_check', '', false, \phpbb\request\request_interface::GET)!='')
			{
				$html.='<h3>Done. All users tested via blacklists database, please see result below.</h3><br /><br />';
			}
			$html.='<form method="post"><center>All posts of deleted users will be deleted, too.<br /><h2>Spam checking results</h2><br /><br /><table class="table1 zebra-table">
	<thead>
	<tr>
		<th>Select</th>
		<th>Username</th>
		<th>Joined</th>
		<th>E-mail</th>
		<th>IP</th>
		<th>Last visit</th>
	</tr>
	</thead>
	<tbody>';
			$found=false;
			while($row = $db->sql_fetchrow($result))
			{
				$found=true;
				$html.="<tr>
				<td><input type='checkbox' name=ct_del_user[".$row['user_id']."] value='1' /></td>
				<td>".$row['username']."</td>
				<td>".date("Y-m-d H:i:s",$row['user_regdate'])."</td>
				<td><a target='_blank' href='https://cleantalk.org/blacklists/".$row['user_email']."'>".$row['user_email']."</a></td>
				<td><a target='_blank' href='https://cleantalk.org/blacklists/".$row['user_ip']."'>".$row['user_ip']."</a></td>
				<td>".date("Y-m-d H:i:s",$row['user_lastvisit'])."</td>
				</tr>";
				
			}
			$html.="</tbody></table><br /><input type=submit name='ct_delete_checked' value='Delete selected'> <input type=submit name='ct_delete_all' value='Delete all'><br /></center></form>";
			if($found)
			{
				$this->template->assign_var('CT_TABLE_USERS_SPAM', $html);
			}
		}
	}
}
