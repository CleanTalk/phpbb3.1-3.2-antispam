<?php

/**
*
* @package phpBB Extension - Antispam by CleanTalk
* @author Сleantalk team (welcome@cleantalk.org)
* @copyright (C) 2014 СleanTalk team (https://cleantalk.org)
* @license GNU/GPL: http://www.gnu.org/copyleft/gpl.html
*
*/

namespace cleantalk\antispam\event;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use phpbb\config\config;
use phpbb\config\db_text;
use phpbb\language\language;
use phpbb\template\template;
use phpbb\request\request;
use phpbb\user;
use phpbb\db\driver\driver_interface;
use cleantalk\antispam\model\main_model;
use cleantalk\antispam\model\RequestBridge;
use phpbb\symfony_request;

/**
* Event listener
*/
class main_listener implements EventSubscriberInterface
{
    public static function getSubscribedEvents()
    {
        return array(
            'core.user_setup'                           => 'load_language_on_setup',
            'core.user_setup_after'                     => array(
                array('sfw_check', 1),
                array('ccf_check', 2),
            ),
            'core.page_header_after'                    => 'add_bot_detector_script',
            'core.page_footer'                          => 'append_privacy_policy',
            'core.page_footer_after'                    => 'add_js_to_footer',
            'core.posting_modify_submission_errors'     => 'check_comment',
            'core.posting_modify_submit_post_before'    => 'change_comment_approve',
            'core.user_add_modify_data'                 => 'check_newuser',
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

    /* @var \cleantalk\antispam\model\main_model */
    protected $main_model;

    /** @var \phpbb\symfony_request */
    protected $symfony_request;

    /** @var string php file extension  */
    protected $php_ext;

    /** @var \phpbb\config\db_text */
    protected $config_text;

    /* @var array Stores result of spam checking of post or topic when needed*/
    private $ct_comment_result;

    /** @var string table_prefix */
    protected $table_prefix;

    /** @var \phpbb\language\language */
    protected $language;

    /**
    * Constructor
    *
    * @param template           $template   Template object
    * @param config             $config     Config object
    * @param db_text            $config_text
    * @param user               $user       User object
    * @param language           $language   Language object
    * @param request            $request    Request object
    * @param driver_interface   $db         The database object
    * @param main_model         $main_model Main model
    * @param symfony_request    $symfony_request
    * @param string             $php_ext
    * @param string             $table_prefix
    */
    public function __construct(template $template, config $config, db_text $config_text, user $user, language $language, request $request, driver_interface $db, main_model $main_model, symfony_request $symfony_request, $php_ext, $table_prefix)
    {
        $this->template = $template;
        $this->config = $config;
        $this->config_text = $config_text;
        $this->user = $user;
        $this->language = $language;
        $this->request = $request;
        $this->db = $db;
        $this->main_model = $main_model;
        $this->symfony_request = $symfony_request;
        $this->php_ext = $php_ext;
        $this->table_prefix = $table_prefix;

        require_once(dirname(__DIR__) . '/lib/autoload.php');
        RequestBridge::init($this->request);
    }
    /**
    * Loads language
    *
    * @param \phpbb\event\data $event
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
    * SpamFirewall Check using Common Firewall library
    *
    * @param \phpbb\event\data $event
    */
    public function sfw_check($event)
    {
        if (!$this->config['cleantalk_antispam_sfw_enabled'] || !$this->main_model->is_active()) {
            return;
        }

        try {
            $firewall = new \Cleantalk\Common\Firewall\Firewall(
                $this->config['cleantalk_antispam_apikey'],
                APBCT_TBL_FIREWALL_LOG
            );

            $firewall->loadFwModule(new \Cleantalk\Common\Firewall\Modules\Sfw(
                APBCT_TBL_FIREWALL_LOG,
                APBCT_TBL_FIREWALL_DATA,
                array(
                    'sfw_counter'   => 0,
                    'cookie_domain' => $this->request->server('HTTP_HOST', ''),
                    'set_cookies'   => 1,
                )
            ));

            $firewall->run();
        } catch (\Exception $e) {
            $this->main_model->log_error('SpamFireWall: ' . $e->getMessage());
        }
    }

    /**
    * Fills tamplate variable by generated JS-code with unique hash
    *
    * @param \phpbb\event\data $event
    */
    public function add_bot_detector_script($event)
    {
        if (!$this->main_model->is_active() || !$this->config['cleantalk_antispam_bot_detector']) {
            return;
        }
        $bot_detector_class = \Cleantalk\Common\Mloader\Mloader::get('BotDetectorService');
        $bot_detector = $bot_detector_class::getInstance();
        $this->template->assign_var('CT_BOT_DETECTOR_URL', $bot_detector->getWrapperURL());
    }

    public function add_js_to_footer($event)
    {
        if (!$this->main_model->is_active()) {
            return;
        }
        $this->template->assign_var('CT_JS_VALUE', $this->main_model->cleantalk_get_checkjs_code());
    }

    /**
    * Appends the CleanTalk data processing disclosure to the board's Privacy Policy (ucp.php?mode=privacy)
    */
    public function append_privacy_policy()
    {
        if (!$this->main_model->is_active()
            || !$this->template->retrieve_var('S_AGREEMENT')
            || $this->template->retrieve_var('AGREEMENT_TITLE') !== $this->language->lang('PRIVACY')
        ) {
            return;
        }

        $this->template->assign_vars(array(
            'S_CLEANTALK_PRIVACY_SFW'           => (bool) $this->config['cleantalk_antispam_sfw_enabled'],
            'S_CLEANTALK_PRIVACY_BOT_DETECTOR'  => (bool) $this->config['cleantalk_antispam_bot_detector'],
        ));
        $this->template->set_filenames(array(
            'cleantalk_privacy_policy' => '@cleantalk_antispam/privacy_policy.html',
        ));
        $this->template->append_var('AGREEMENT_TEXT', $this->template->assign_display('cleantalk_privacy_policy'));
    }

    /**
    * Checks post or topic to spam
    *
    * @param \phpbb\event\data $event
    */
    public function check_comment($event)
    {
        $data = $event->get_data();
        if (!$this->main_model->is_active() || !isset($data['submit']) || $data['submit'] != 1) {
            return;
        }

        $moderate = false;
        $this->ct_comment_result = null;

        if ($this->config['cleantalk_antispam_guests'] && $this->user->data['is_registered'] == 0) {
            $moderate = true;
        } else if ($this->config['cleantalk_antispam_allusers'] && $this->user->data['is_registered'] == 1) {
            // Check ALL registered users regardless of their group or posts count
            $moderate = true;
        } else if ($this->config['cleantalk_antispam_nusers'] && $this->user->data['is_registered'] == 1) {
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
            if ($row !== false && isset($row['group_name'])) {
                $moderate = true;
            }
            $this->db->sql_freeresult($result);
            //check numposts also
            if (!$moderate) {
                $users_table = USERS_TABLE;
                $sql = "SELECT u.user_id
					FROM $users_table u
					WHERE u.user_id = $user_id 
					AND	u.user_posts <= 3";
                $result = $this->db->sql_query($sql);
                $row = $this->db->sql_fetchrow($result);
                if ($row !== false && isset($row['user_id'])) {
                    $moderate = true;
                }
                $this->db->sql_freeresult($result);
            }
        }

        if ($moderate) {
            if (
                isset($data['post_data']) &&
                is_array($data['post_data']) &&
                isset($data['post_data']['username'], $data['post_data']['post_subject'])
            ) {
                $spam_check = array();
                $spam_check['type'] = 'comment';
                $spam_check['sender_email'] = '';
                $spam_check['sender_nickname'] = '';
                if (isset($this->user->data)) {
                    $spam_check['sender_email'] = $this->user->data['user_email'];
                    $spam_check['sender_nickname'] = $this->user->data['username'];
                } else {
                    if (isset($data['post_data']['user_email'])) {
                        $spam_check['sender_email'] = $data['post_data']['user_email'];
                    }
                    if (isset($data['post_data']['username'])) {
                        $spam_check['sender_nickname'] = $data['post_data']['username'];
                    }
                }

                if (isset($data['post_data']['post_subject'])) {
                    $spam_check['message_title'] = $data['post_data']['post_subject'];
                }
                $spam_check['message_body'] = $this->request->variable('message', '', true);
                $result = $this->main_model->check_spam($spam_check);

                if ($result['errno'] == 0 && $result['allow'] == 0) { // Spammer exactly.
                    if (isset($result['stop_queue']) && $result['stop_queue'] == 1) {
                        // Output error
                        $data['error'] = isset($data['error']) && is_array($data['error']) ? $data['error'] : array();
                        array_push($data['error'], isset($result['ct_result_comment']) ? $result['ct_result_comment'] : '');
                        $event->set_data($data);
                    } else {
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
    * @param \phpbb\event\data $event
    */
    public function change_comment_approve($event)
    {
        if (!$this->main_model->is_active()) {
            return;
        }

        // 'stop_queue' = 0 means to manual approvement
        if (isset($this->ct_comment_result) && is_array($this->ct_comment_result)
            && isset($this->ct_comment_result['stop_queue'])
            && $this->ct_comment_result['stop_queue'] == 0
        ) {
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
    * @param \phpbb\event\data $event
    */
    public function check_newuser($event)
    {
        if (!$this->main_model->is_active()) {
            return;
        }

        if ($this->config['cleantalk_antispam_regs']) {
            $data = $event->get_data();
            if (
                isset($data['user_row']) &&
                is_array($data['user_row']) &&
                isset($data['user_row']['username'], $data['user_row']['user_email'])
            ) {
                $spam_check = array();
                $spam_check['type'] = 'register';
                $spam_check['sender_email'] = isset($data['user_row']['user_email'])
                    ? $data['user_row']['user_email']
                    : '';
                $spam_check['sender_nickname'] = isset($data['user_row']['username'])
                    ? $data['user_row']['username']
                    : '';
                if (isset($data['user_row']['user_timezone'])) {
                    $spam_check['timezone'] = $data['user_row']['user_timezone'];
                }
                $result = $this->main_model->check_spam($spam_check);
                if ($result['errno'] == 0 && $result['allow'] == 0) { // Spammer exactly.
                    trigger_error($result['ct_result_comment']);
                }
            }
        }
    }
    /**
    * CCF check
    *
    * @param \phpbb\event\data $event
    */
    public function ccf_check($event)
    {
        if (!$this->main_model->is_active()) {
            return;
        }

        $this->main_model->set_cookie();

        try {
            $rc_class = \Cleantalk\Common\Mloader\Mloader::get('RemoteCalls');
            if ($rc_class::check()) {
                // Prevent PHP from aborting when async RC caller disconnects (3s timeout)
                ignore_user_abort(true);

                $storage_handler_class = \Cleantalk\Common\Mloader\Mloader::get('StorageHandler');
                $remote_calls = new $rc_class($this->config['cleantalk_antispam_apikey'], new $storage_handler_class());
                try {
                    $rc_result = $remote_calls->process();
                } catch (\Cleantalk\Common\RemoteCalls\Exceptions\RemoteCallsException $exception) {
                    $this->main_model->log_error('Remote call: ' . $exception->getMessage());
                    $rc_result = 'FAIL ' . json_encode(array('error' => $exception->getMessage()));
                }
                $this->send_remote_call_response($rc_result);
            }
        } catch (\Exception $e) {
            $this->main_model->log_error('Remote call init: ' . $e->getMessage());
        }

        if ($this->config['cleantalk_antispam_ccf'] && !in_array($this->symfony_request->getScriptName(), array('/adm/index.' . $this->php_ext,'/ucp.' . $this->php_ext,'/posting.' . $this->php_ext)) && $this->request->variable('submit', '')) {
            //Checking contact form
            $this->ct_comment_result = null;
            $spam_check = array();

            $spam_check['sender_email'] = $this->request->variable('email', '');
            $spam_check['sender_nickname'] = $this->request->variable('name', '');
            $spam_check['message_title'] = $this->request->variable('subject', '');
            $spam_check['message_body'] = $this->request->variable('message', '');

            if ($spam_check['sender_email'] !== '' || $spam_check['message_title'] !== '' || $spam_check['message_body'] !== '' ) {
                $spam_check['type'] = 'contact';

                $result = $this->main_model->check_spam($spam_check);

                if ($result['errno'] == 0 && $result['allow'] == 0) { // Spammer exactly.
                // Output error
                    @trigger_error($result['ct_result_comment']);
                }
            }
        }
    }

    /**
    * Outputs the remote call result and ends the request the phpBB way
    *
    * @param string $output
    */
    protected function send_remote_call_response($output)
    {
        $response = new \Symfony\Component\HttpFoundation\Response((string) $output);
        $response->send();
        garbage_collection();
        exit_handler();
    }
}
