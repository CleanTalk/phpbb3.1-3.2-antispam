<?php

namespace cleantalk\antispam\event;

/**
* @ignore
*/
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
		);
	}

	/* @var \phpbb\controller\helper */
	protected $helper;

	/* @var \phpbb\template\template */
	protected $template;

	/* @var array */
	private $ct_comment_result;

	/**
	* Constructor
	*
	* @param \phpbb\controller\helper	$helper		Controller helper object
	* @param \phpbb\template			$template	Template object
	*/
	public function __construct(\phpbb\controller\helper $helper, \phpbb\template\template $template)
	{
		$this->helper = $helper;
		$this->template = $template;
	}

	public function load_language_on_setup($event)
	{
		$lang_set_ext = $event['lang_set_ext'];
		$lang_set_ext[] = array(
			'ext_name' => 'cleantalk/antispam',
			'lang_set' => 'common',
		);
		$event['lang_set_ext'] = $lang_set_ext;
	}

	public function add_js_to_head($event)
	{
		global $config;

		if (empty($config['cleantalk_antispam_apikey']) || $config['cleantalk_antispam_apikey'] == 'enter key') return;

                $this->template->assign_var('CT_JS_ADDON', \cleantalk\antispam\model\main_model::get_check_js_script());
	}

	public function form_set_time($event)
	{
		global $config;

		if (empty($config['cleantalk_antispam_apikey']) || $config['cleantalk_antispam_apikey'] == 'enter key') return;

		$data = $event->get_data();
		$form_id = $data['form_name'];
		if ($config['cleantalk_antispam_guests'] && $form_id == 'posting' || $config['cleantalk_antispam_regs'] && $form_id == 'ucp_register') {
		    \cleantalk\antispam\model\main_model::set_submit_time();
		}
	}

        public function check_comment($event)
	{
		global $config, $user, $db;

		if (empty($config['cleantalk_antispam_apikey']) || $config['cleantalk_antispam_apikey'] == 'enter key') return;

                $moderate = false;
		$this->ct_comment_result = null;

                if ($config['cleantalk_antispam_guests'] && $user->data['is_registered'] == 0) {
                    $moderate = true;
                } else if ($config['cleantalk_antispam_nusers'] && $user->data['is_registered'] == 1) {
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

		if ($moderate){
            		$data = $event->get_data();
                        if (
                                array_key_exists('post_data', $data) &&
                                is_array($data['post_data']) &&
                                array_key_exists('username', $data['post_data']) &&
                                array_key_exists('post_subject', $data['post_data'])
                        ){
                                $spam_check = array();
                                $spam_check['type'] = 'comment';
                                if (array_key_exists('user_email', $data['post_data'])) $spam_check['sender_email'] = $data['post_data']['user_email'];
                                if (array_key_exists('username', $data['post_data'])) $spam_check['sender_nickname'] = $data['post_data']['username'];
                                if (array_key_exists('post_subject', $data['post_data'])) $spam_check['message_title'] = $data['post_data']['post_subject'];
				$spam_check['message_body'] = utf8_normalize_nfc(request_var('message', '', true));

                                $result = \cleantalk\antispam\model\main_model::check_spam($spam_check);

                                if ($result['errno'] == 0 && $result['allow'] == 0) { // Spammer exactly.
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
                                array_key_exists('user_new', $data['user_row']) &&
                                $data['user_row']['user_new'] == 1
                        )
			{
                                $spam_check = array();
				$spam_check['type'] = 'register';
                                if (array_key_exists('user_email', $data['user_row'])) $spam_check['sender_email'] = $data['user_row']['user_email'];
                                if (array_key_exists('username', $data['user_row'])) $spam_check['sender_nickname'] = $data['user_row']['username'];
                                if (array_key_exists('user_timezone', $data['user_row'])) $spam_check['timezone'] = $data['user_row']['user_timezone'];
                                $result = \cleantalk\antispam\model\main_model::check_spam($spam_check);
                        	if ($result['errno'] == 0 && $result['allow'] == 0) { // Spammer exactly.
?>
<html>
          <head>
            <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
            <style>
              .ct {
                width: 500px;
                border: 1px solid gray;
                box-shadow: 0 0 10px gray;
                font: normal 14px Arial;
                padding: 30px;
                margin: 30px auto;
              }
            </style>
          </head>
          <body>
            <div class="ct">
<?php
                                    echo $result['ct_result_comment'];
?>
              <br /><br /><a href="#" onclick="history.back()">Go back</a>
              <script>setTimeout("history.back()", 5000);</script>
            </div>
          </body>
</html>
<?php
                                    exit();
                            }
                        }
		}
	}
}
