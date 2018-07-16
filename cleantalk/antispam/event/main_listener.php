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
use phpbb\config\config;
use phpbb\template\template;
use phpbb\request\request;
use phpbb\user;
use phpbb\db\driver\driver_interface;
use cleantalk\antispam\model\CleantalkSFW;
use cleantalk\antispam\model\main_model;

/**
* Event listener
*/
class main_listener implements EventSubscriberInterface
{
	static public function getSubscribedEvents()
	{
		return array(
			'core.user_setup'				=> 'load_language_on_setup',
			'core.page_header_after'        => 'add_js_to_head',
			'core.posting_modify_submission_errors'		=> 'check_comment',
			'core.posting_modify_submit_post_before'	=> 'change_comment_approve',
			'core.user_add_modify_data'                 => 'check_newuser',
			'core.common'					=> 'global_check',
		);
	}

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

	/* @var \cleantalk\antispam\model\CleantalkSFW */
	protected $cleantalk_sfw;

	/* @var \cleantalk\antispam\model\main_model */
	protected $main_model;

	/* @var array Stores result of spam checking of post or topic when needed*/
	private $ct_comment_result;

	/**
	* Constructor
	*
	* @param template		$template	Template object
	* @param config			$config		Config object
	* @param user			$user		User object
	* @param request		$request	Request object
	* @param driver_interface 	$db 		The database object
	*/
	public function __construct(template $template, config $config, user $user, request $request, driver_interface $db, CleantalkSFW $cleantalk_sfw, main_model $main_model)
	{
		$this->template = $template;
		$this->config = $config;
		$this->user = $user;
		$this->request = $request;
		$this->db = $db;
		$this->cleantalk_sfw = $cleantalk_sfw;
		$this->main_model = $main_model;
	}
	/**
	* Loads language
	*
	* @param array	$event		array with event variable values
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
	* @param array	$event		array with event variable values
	*/
	public function add_js_to_head($event)
	{		
		if (empty($this->config['cleantalk_antispam_apikey'])){
			return;
		}
		$this->template->assign_var('CT_JS_ADDON', $this->main_model->cleantalk_get_checkjs_code());
		$this->main_model->set_cookie();	

	}
	/**
	* Checks post or topic to spam
	*
	* @param array	$event		array with event variable values
	*/
	public function check_comment($event)
	{
		if (empty($this->config['cleantalk_antispam_apikey']))
		{
			return;
		}

		$moderate = false;
		$this->ct_comment_result = null;

		if ($this->config['cleantalk_antispam_guests'] && $this->user->data['is_registered'] == 0)
		{
			$moderate = true;
		}
		else if ($this->config['cleantalk_antispam_nusers'] && $this->user->data['is_registered'] == 1)
		{
			$user_group_table = USER_GROUP_TABLE;
			$group_table = GROUPS_TABLE;
			$user_id = (int) $this->user->data['user_id'];
			$sql = "SELECT g.group_name 
				FROM $user_group_table ug 
				JOIN $group_table g
				ON (ug.group_id = g.group_id)
				WHERE ug.user_id = $user_id 
				AND	g.group_name = 'NEWLY_REGISTERED'";
			$result = $this->db->sql_query($sql);
			$row = $this->db->sql_fetchrow($result);
			if ($row !== false && isset($row['group_name']))
			{
				$moderate = true;
			}
			$this->db->sql_freeresult($result);
			//check numposts also
			if (!$moderate)
			{
				$users_table = USERS_TABLE;
				$sql = "SELECT u.user_id
					FROM $users_table u
					WHERE u.user_id = $user_id 
					AND	u.user_posts <= 3";
				$result = $this->db->sql_query($sql);
				$row = $this->db->sql_fetchrow($result);
				if ($row !== false && isset($row['user_id']))
				{
					$moderate = true;
				}
				$this->db->sql_freeresult($result);								
			}

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
				if (isset($this->user->data))
				{
					$spam_check['sender_email'] = $this->user->data['user_email'];
					$spam_check['sender_nickname'] = $this->user->data['username'];
				}
				else
				{
					if (array_key_exists('user_email', $data['post_data']))
					{
						$spam_check['sender_email'] = $data['post_data']['user_email'];
					}
					if (array_key_exists('username', $data['post_data']))
					{
						$spam_check['sender_nickname'] = $data['post_data']['username'];
					}					
				}

				if (array_key_exists('post_subject', $data['post_data'])) 
				{
					$spam_check['message_title'] = $data['post_data']['post_subject'];
				}
				$spam_check['message_body'] = utf8_normalize_nfc($this->request->variable('message', '', true));
				$result = $this->main_model->check_spam($spam_check);
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
	* @param array	$event		array with event variable values
	*/
	public function change_comment_approve($event)
	{
		if (empty($this->config['cleantalk_antispam_apikey']))
		{
			return;
		}

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
	* @param array	$event		array with event variable values
	*/
	public function check_newuser($event)
	{
		if (empty($this->config['cleantalk_antispam_apikey']))
		{
			return;
		}

		if ($this->config['cleantalk_antispam_regs'])
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
				if (array_key_exists('user_timezone', $data['user_row'])) {
					$spam_check['timezone'] = $data['user_row']['user_timezone'];
				}
				$result = $this->main_model->check_spam($spam_check);
				if ($result['errno'] == 0 && $result['allow'] == 0) // Spammer exactly.
				{
					trigger_error($result['ct_result_comment']);
				}
			}
		}
	}	
	/**
	* Global checks
	* @void
	*/
	public function global_check()
	{
		$this->cleantalk_sfw->sfw_check();
		if ($this->config['cleantalk_antispam_ccf'] && !in_array($this->request->server('PHP_SELF',''), array('/adm/index.php','/ucp.php','/posting.php')) && $this->request->variable('submit',''))
		{
			
			//Checking contact form
			$this->ct_comment_result = null;
			$spam_check = array();	

			//Getting request params
			$ct_temp_msg_data = $this->main_model->get_fields_any($this->request->get_super_global());

			$sender_email    = ($ct_temp_msg_data['email']    ? $ct_temp_msg_data['email']    : '');
			$sender_nickname = ($ct_temp_msg_data['nickname'] ? $ct_temp_msg_data['nickname'] : '');
			$subject         = ($ct_temp_msg_data['subject']  ? $ct_temp_msg_data['subject']  : '');
			$message         = ($ct_temp_msg_data['message']  ? implode(',',$ct_temp_msg_data['message'])  : '');	

			if ($sender_email)
			{
				$spam_check['sender_email'] = $sender_email;
			}
			if ($sender_nickname)
			{
				$spam_check['sender_nickname'] = $sender_nickname;
			}
			if ($subject)
			{
				$spam_check['message_title'] = $subject;
			}
			if ($message)
			{
				$spam_check['message_body'] = $message;
			}
			
			if (isset($spam_check['sender_email']) || isset($spam_check['message_title']) || isset($spam_check['message_body']) )
			{
				$spam_check['type'] = 'comment';

				$result = $this->main_model->check_spam($spam_check);

				if ($result['errno'] == 0 && $result['allow'] == 0) // Spammer exactly.
				{				 
					// Output error
					trigger_error($result['ct_result_comment']);
				}
			}
		}			
	}
}
