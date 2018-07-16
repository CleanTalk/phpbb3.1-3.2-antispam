<?php
/**
*
* @package phpBB Extension - Antispam by CleanTalk
* @author Сleantalk team (welcome@cleantalk.org)
* @copyright (C) 2014 СleanTalk team (http://cleantalk.org)
* @license GNU/GPL: http://www.gnu.org/copyleft/gpl.html
*
*/

namespace cleantalk\antispam\model;
use phpbb\config\config;
use phpbb\request\request;
use phpbb\user;
use phpbb\log\log;
use Symfony\Component\DependencyInjection\ContainerBuilder;
class main_model
{
	const JS_FIELD_NAME = 'ct_checkjs';
	const JS_TIME_ZONE_FIELD_NAME = 'ct_timezone';
	const JS_POINTER_DATA_FIELD_NAME = 'ct_pointer_data';
	const JS_PREVIOUS_REFERER = 'ct_prev_referer';
	const JS_FKP_TIMESTAMP = 'ct_fkp_timestamp';
	const JS_PS_TIMESTAMP = 'ct_ps_timestamp';

	/* @var \phpbb\config\config */
	protected $config;

	/* @var \phpbb\user */
	protected $user;

	/* @var \phpbb\request\request */
	protected $request;

	/* @var \cleantalk\antispam\model\Cleantalk */
	protected $cleantalk;

	/* @var \cleantalk\antispam\model\CleantalkRequest */
	protected $cleantalk_request;

	/** @var string phpBB Root Path */
	protected $phpbb_root_path;

	/** @var string php file extension  */
	protected $php_ext;

	/* @var $phpbb_log \phpbb\log\log_interface */
	protected $phpbb_log;

	/** @var ContainerBuilder */
	protected $phpbb_container;

	/**
	* Constructor
	*
	* @param config			$config		Config object
	* @param user			$user		User object
	* @param request		$request	Request object
	* @param driver_interface 	$db 		The database object
	*/
	public function __construct(config $config, user $user, request $request, log $phpbb_log, \cleantalk\antispam\model\Cleantalk $cleantalk, \cleantalk\antispam\model\CleantalkRequest $cleantalk_request, ContainerBuilder $phpbb_container, $phpbb_root_path, $php_ext )
	{	
		$this->config = $config;
		$this->user = $user;
		$this->request = $request;
		$this->phpbb_log = $phpbb_log;
		$this->phpbb_container = $phpbb_container;
		$this->phpbb_root_path = $phpbb_root_path;
		$this->php_ext = $php_ext;		
		$this->cleantalk = $cleantalk;
		$this->cleantalk_request = $cleantalk_request;
	}
	/**
	* Checks user registration to spam
	*
	* @param array	$spam_check		array with values to check
	* @return array				array with result flags
	*/
	
	public function check_spam( $spam_check )
	{
		$this->user->add_lang('acp/common');
		$checkjs = $this->cleantalk_is_valid_js() ? 1 : 0;
	
		$this->cleantalk->work_url       = $this->config['cleantalk_antispam_work_url'];
		$this->cleantalk->server_url     = $this->config['cleantalk_antispam_server_url'];
		$this->cleantalk->server_ttl     = $this->config['cleantalk_antispam_server_ttl'];
		$this->cleantalk->server_changed = $this->config['cleantalk_antispam_server_changed'];
		//Pointer data, Timezone from JS, First key press timestamp, Page set timestamp
		$pointer_data 			= $this->request->variable(self::JS_POINTER_DATA_FIELD_NAME, 	"none", false, \phpbb\request\request_interface::COOKIE);
		$page_set_timestamp 	= $this->request->variable(self::JS_PS_TIMESTAMP, 			"none", false, \phpbb\request\request_interface::COOKIE);
		$js_timezone 			= $this->request->variable(self::JS_TIME_ZONE_FIELD_NAME, 	"none", false, \phpbb\request\request_interface::COOKIE);
		$first_key_timestamp 	= $this->request->variable(self::JS_FKP_TIMESTAMP, 			"none", false, \phpbb\request\request_interface::COOKIE);
		$previous_referer       = $this->request->variable($this->config['cookie_name'].'_'.self::JS_PREVIOUS_REFERER, "none", false, \phpbb\request\request_interface::COOKIE);
		
		$pointer_data 			= ($pointer_data 		=== "none" ? 0 : json_decode ($pointer_data));
		$js_timezone 			= ($js_timezone 		=== "none" ? 0 : $js_timezone);
		$first_key_timestamp 	= ($first_key_timestamp === "none" ? 0 : intval($first_key_timestamp));
		$page_set_timestamp 	= ($page_set_timestamp 	=== "none" ? 0 : intval($page_set_timestamp));
		$previous_referer       = ($previous_referer    === "none" ? 0 : $previous_referer);
				
		$user_agent  = $this->request->server('HTTP_USER_AGENT');
		$refferrer   = $this->request->server('HTTP_REFERER');	
		$page_url    = $this->request->server('SERVER_NAME').$this->request->server('REQUEST_URI');	
		$sender_info = json_encode(
			array(
			'cms_lang'               => $this->config['default_lang'],
			'REFFERRER'              => $refferrer,
			'page_url'               => $page_url,
			'USER_AGENT'             => $user_agent,
			'js_timezone'            => $js_timezone,
			'mouse_cursor_positions' => $pointer_data,
			'key_press_timestamp'    => $first_key_timestamp,
			'page_set_timestamp'     => $page_set_timestamp,
			'REFFERRER_PREVIOUS'     => $previous_referer,
			'fields_number'          => sizeof($spam_check),
			'cookies_enabled'        => $this->test_cookie(),	
			)
		);
		$post_info = json_encode(
			array(
			'comment_type'			 => $spam_check['type'],
			'post_url'               => $refferrer,
			)

		);
		$composer_json = json_decode(file_get_contents($this->phpbb_root_path . 'ext/cleantalk/antispam/composer.json'));

		if(isset($spam_check['auth_key'])){
			$this->cleantalk_request->auth_key = $spam_check['auth_key'];
		}else{
			$this->cleantalk_request->auth_key = $this->config['cleantalk_antispam_apikey'];
		}
		
		$this->cleantalk_request->agent = 'phpbb31-' . preg_replace("/(\d+)\.(\d*)\.?(\d*)/", "$1$2$3", $composer_json->version);
		$this->cleantalk_request->js_on = $checkjs;
		$this->cleantalk_request->sender_info = $sender_info;
		$this->cleantalk_request->post_info = $post_info;
		$this->cleantalk_request->sender_email = array_key_exists('sender_email', $spam_check) ? $spam_check['sender_email'] : '';
		$this->cleantalk_request->sender_nickname = array_key_exists('sender_nickname', $spam_check) ? $spam_check['sender_nickname'] : '';
		$this->cleantalk_request->sender_ip = $this->cleantalk->cleantalk_get_real_ip();
		$this->cleantalk_request->submit_time = ($page_set_timestamp !== 0) ? time() - $page_set_timestamp : null;
		
		switch ($spam_check['type'])
		{
		case 'comment':
			$this->cleantalk_request->message = (array_key_exists('message_title', $spam_check) ? $spam_check['message_title'] : '' ).
				" \n\n" .
				(array_key_exists('message_body', $spam_check) ? $spam_check['message_body'] : '');
			$ct_result = $this->cleantalk->isAllowMessage($this->cleantalk_request);
			 break;
		case 'register':
			$this->cleantalk_request->tz = array_key_exists('timezone', $spam_check) ? $spam_check['timezone'] : '';
			$ct_result = $this->cleantalk->isAllowUser($this->cleantalk_request);
			break;
		case 'send_feedback':
			$this->cleantalk_request->feedback = $spam_check['feedback'];
			$ct_result = $this->cleantalk->sendFeedback($this->cleantalk_request);
			break;
		}
		$ret_val = array();
		$ret_val['errno'] = 0;
		$ret_val['allow'] = 1;
		$ret_val['ct_request_id'] = $ct_result->id;

		if ($this->cleantalk->server_change)
		{
			$this->config->set('cleantalk_antispam_work_url',   $this->cleantalk->work_url);
			$this->config->set('cleantalk_antispam_server_ttl',     $this->cleantalk->server_ttl);
			$this->config->set('cleantalk_antispam_server_changed', time());
		}
		if ($ct_result)
		{
			// First check errstr flag.
			if (!empty($ct_result->errstr) && $checkjs = 1
				|| (!empty($ct_result->inactive) && $ct_result->inactive == 1)
			)
			{
				// Cleantalk error so we go default way (no action at all).
				$ret_val['errno'] = 1;
				$ct_result->allow = 1;
				
				if (!empty($ct_result->errstr)){
					
					if($ct_result->curl_err){
						$ct_result->errstr = $this->user->lang('CLEANTALK_ERROR_CURL', $ct_result->curl_err);
					}else{
						$ct_result->errstr = $this->user->lang('CLEANTALK_ERROR_NO_CURL');
					}
					$ct_result->errstr = $ct_result->errstr . " ". $this->user->lang('CLEANTALK_ERROR_ADDON');
								
					$ret_val['errstr'] = $this->filter_response($ct_result->errstr);
				}else{
					$ret_val['errstr'] = $this->filter_response($ct_result->comment);
				}

				$this->phpbb_log->add('admin', ANONYMOUS, '127.0.0.1', 'CLEANTALK_ERROR_LOG', time(), array($ret_val['errstr']));

				// Email to admin once per 15 min
				if (time() - 900 > $this->config['cleantalk_antispam_error_time'])
				{
					$this->config->set('cleantalk_antispam_error_time', time());
					if (!function_exists('phpbb_mail'))
					{
						include($this->phpbb_root_path . 'includes/functions_messenger.' . $this->php_ext);
					}

					$hr_url = str_replace(array('http://', 'https://'), array('', ''), generate_board_url());
					$err_title = $hr_url. ' - ' . $this->user->lang['CLEANTALK_ERROR_MAIL'];
					$err_message = $hr_url. ' - ' . $this->user->lang['CLEANTALK_ERROR_MAIL'] . " :\n" . $ret_val['errstr'];

					$headers = array();
					$headers[] = 'Reply-To: ' . $this->config['board_email'];
					$headers[] = 'Return-Path: <' . $this->config['board_email'] . '>';
					$headers[] = 'Sender: <' . $this->config['board_email'] . '>';
					$headers[] = 'MIME-Version: 1.0';
					$headers[] = 'X-Mailer: phpBB3';
					$headers[] = 'X-MimeOLE: phpBB3';
					$headers[] = 'X-phpBB-Origin: phpbb://' . $hr_url;
					$headers[] = 'Content-Type: text/plain; charset=UTF-8'; // format=flowed
					$headers[] = 'Content-Transfer-Encoding: 8bit'; // 7bit

					$dummy = '';
					phpbb_mail($this->config['board_email'], $err_title, $err_message, $headers, "\n", $dummy);
				}

				return $ret_val;
			}
			else if (!empty($ct_result->errstr) && $checkjs = 0)
			{
				$ct_result->allow = 0;
			}

			if ($ct_result->allow == 0)
			{
				// Spammer.
				$ret_val['allow'] = 0;
				$ret_val['ct_result_comment'] = $this->filter_response($ct_result->comment);

				// Check stop_queue flag.
				if ($spam_check['type'] == 'comment' && $ct_result->stop_queue == 0)
				{
					// Spammer and stop_queue == 0 - to manual approvement.
					$ret_val['stop_queue'] = 0;
				}
				else
				{
					// New user or Spammer and stop_queue == 1 - display form error message.
					$ret_val['stop_queue'] = 1;
				}
			}			
		}

	return $ret_val;
	}

	/**
	* Filters raw CleanTalk cloud response
	*
	* @param string	$ct_response		Raw CleanTalk cloud response
	* @return string			Filtered CleanTalk cloud response
	*/
	public function filter_response( $ct_response )
	{
		if (preg_match('//u', $ct_response))
		{
			$err_str = preg_replace('/\*\*\*/iu', '', $ct_response);
		}
		else
		{
			$err_str = preg_replace('/\*\*\*/i', '', $ct_response);
		}
		return $err_str;
	}
	/*
	* Get data from an ARRAY recursively
	* @return array
	*/ 
	public function get_fields_any($arr, $message=array(), $email = null, $nickname = array('nick' => '', 'first' => '', 'last' => ''), $subject = null, $contact = true, $prev_name = ''){
		//Skip request if fields exists
		$skip_params = array(
		    'ipn_track_id', 	// PayPal IPN #
		    'txn_type', 		// PayPal transaction type
		    'payment_status', 	// PayPal payment status
		    'ccbill_ipn', 		// CCBill IPN 
			'ct_checkjs', 		// skip ct_checkjs field
			'api_mode',         // DigiStore-API
			'loadLastCommentId' // Plugin: WP Discuz. ticket_id=5571
	    );
		
		// Fields to replace with ****
	    $obfuscate_params = array(
	        'password',
	        'pass',
	        'pwd',
			'pswd'
	    );
		
		// Skip feilds with these strings and known service fields
		$skip_fields_with_strings = array( 
			// Common
			'ct_checkjs', //Do not send ct_checkjs
			'nonce', //nonce for strings such as 'rsvp_nonce_name'
			'security',
			// 'action',
			'http_referer',
			'timestamp',
			'captcha',
			// Formidable Form
			'form_key',
			'submit_entry',
			// Custom Contact Forms
			'form_id',
			'ccf_form',
			'form_page',
			// Qu Forms
			'iphorm_uid',
			'form_url',
			'post_id',
			'iphorm_ajax',
			'iphorm_id',
			// Fast SecureContact Froms
			'fs_postonce_1',
			'fscf_submitted',
			'mailto_id',
			'si_contact_action',
			// Ninja Forms
			'formData_id',
			'formData_settings',
			'formData_fields_\d+_id',
			'formData_fields_\d+_files.*',		
			// E_signature
			'recipient_signature',
			'output_\d+_\w{0,2}',
			// Contact Form by Web-Settler protection
	        '_formId',
	        '_returnLink',
			// Social login and more
			'_save',
			'_facebook',
			'_social',
			'user_login-',
			'submit',
			'form_token',
			'creation_time',
		);
				
	   	foreach($skip_params as $value){
	   		if(array_key_exists($value,$this->request->get_super_global()))
	   		{
	   			$contact = false;
	   		}
	   	} unset($value);
			
		if(count($arr)){
			foreach($arr as $key => $value){
				
				if(gettype($value)=='string'){
					$decoded_json_value = json_decode($value, true);
					if($decoded_json_value !== null)
					{
						$value = $decoded_json_value;
					}
				}
				
				if(!is_array($value) && !is_object($value)){
					
					if (in_array($key, $skip_params, true) && $key != 0 && $key != '' || preg_match("/^ct_checkjs/", $key))
					{
						$contact = false;
					}
					
					if($value === '')
					{
						continue;
					}
					
					// Skipping fields names with strings from (array)skip_fields_with_strings
					foreach($skip_fields_with_strings as $needle){
						if (preg_match("/".$needle."/", $prev_name.$key) == 1){
							continue(2);
						}
					}unset($needle);
					// Obfuscating params
					foreach($obfuscate_params as $needle){
						if (strpos($key, $needle) !== false){
							$value = $this->obfuscate_param($value);
							continue(2);
						}
					}unset($needle);
					

					// Decodes URL-encoded data to string.
					$value = urldecode($value);	

					// Email
					if (!$email && preg_match("/^\S+@\S+\.\S+$/", $value)){
						$email = $value;
						
					// Names
					}elseif (preg_match("/name/i", $key)){
						
						preg_match("/(first.?name)?(name.?first)?(forename)?/", $key, $match_forename);
						preg_match("/(last.?name)?(family.?name)?(second.?name)?(surname)?/", $key, $match_surname);
						preg_match("/(nick.?name)?(user.?name)?(nick)?/", $key, $match_nickname);
						
						if(count($match_forename) > 1)
						{
							$nickname['first'] = $value;
						}
						elseif(count($match_surname) > 1)
						{
							$nickname['last'] = $value;
						}
						elseif(count($match_nickname) > 1)
						{
							$nickname['nick'] = $value;
						}
						else
						{
							$message[$prev_name.$key] = $value;
						}
					
					// Subject
					}elseif ($subject === null && preg_match("/subject/i", $key)){
						$subject = $value;
					
					// Message
					}else{
						$message[$prev_name.$key] = $value;					
					}
					
				}elseif(!is_object($value)){
					
					$prev_name_original = $prev_name;
					$prev_name = ($prev_name === '' ? $key.'_' : $prev_name.$key.'_');
					
					$temp = $this->get_fields_any($value, $message, $email, $nickname, $subject, $contact, $prev_name);
					
					$message 	= $temp['message'];
					$email 		= ($temp['email'] 		? $temp['email'] : null);
					$nickname 	= ($temp['nickname'] 	? $temp['nickname'] : null);				
					$subject 	= ($temp['subject'] 	? $temp['subject'] : null);
					if($contact === true)
					{
						$contact = ($temp['contact'] === false ? false : true);
					}
					$prev_name 	= $prev_name_original;
				}
			} unset($key, $value);
		}
				
		//If top iteration, returns compiled name field. Example: "Nickname Firtsname Lastname".
		if($prev_name === ''){
			if(!empty($nickname)){
				$nickname_str = '';
				foreach($nickname as $value){
					$nickname_str .= ($value ? $value." " : "");
				}unset($value);
			}
			$nickname = $nickname_str;
		}
		
	    $return_param = array(
			'email' 	=> $email,
			'nickname' 	=> $nickname,
			'subject' 	=> $subject,
			'contact' 	=> $contact,
			'message' 	=> $message
		);	
		return $return_param;
	}
	/**
	* Masks a value with asterisks (*)
	* @return string
	*/
	public function obfuscate_param($value = null) {
	    if ($value && (!is_object($value) || !is_array($value))) {
	        $length = strlen($value);
	        $value = str_repeat('*', $length);
	    }
	    return $value;
	}
	/**
	* Sets cookie
	*/	
	public function set_cookie()
	{
		// Cookie names to validate
		$cookie_test_value = array(
			'cookies_names' => array(),
			'check_value' => $this->config['cleantalk_antispam_apikey'],
		);

		// Pervious referer
		if($this->request->server('HTTP_REFERER','') !== ''){
			$this->user->set_cookie('ct_prev_referer', $this->request->server('HTTP_REFERER',''), 0);
			$cookie_test_value['cookies_names'][] = 'ct_prev_referer';
			$cookie_test_value['check_value'] .= $this->request->server('HTTP_REFERER','');
		}
		// Cookies test
		$cookie_test_value['check_value'] = md5($cookie_test_value['check_value']);
		$this->user->set_cookie('ct_cookies_test', json_encode($cookie_test_value), 0);		
	} 
	/**
	* Test cookie
	*/
	public function test_cookie()
	{

        if($this->request->is_set($this->config['cookie_name'].'_ct_cookies_test', \phpbb\request\request_interface::COOKIE))
        {           
            $cookie_test = json_decode(htmlspecialchars_decode($this->request->variable($this->config['cookie_name'].'_ct_cookies_test','', false, \phpbb\request\request_interface::COOKIE)),true);
            
            $check_srting = $this->config['cleantalk_antispam_apikey'];
            foreach($cookie_test['cookies_names'] as $cookie_name){
                $check_srting .= $this->request->variable($this->config['cookie_name'].'_'.$cookie_name,'', false, \phpbb\request\request_interface::COOKIE);
            } unset($cokie_name);
            
            if($cookie_test['check_value'] == md5($check_srting)){
                return 1;
            }else{
                return 0;
            }
        }
        else{
            return null;
        }

	}
    public function cleantalk_get_checkjs_code()
    {
		$config_text = $this->phpbb_container->get('config_text');
		$config_text_data = $config_text->get_array(array(
			'cleantalk_antispam_js_keys'
		));
		$js_keys = isset($config_text_data['cleantalk_antispam_js_keys']) ? json_decode($config_text_data['cleantalk_antispam_js_keys'], true) : null;
    	$api_key = isset($this->config['cleantalk_antispam_apikey']) ? $this->config['cleantalk_antispam_apikey'] : null;
    	if($js_keys == null){
		
		$js_key = strval(md5($api_key . time()));
		
		$js_keys = array(
			'keys' => array(
				array(
					time() => $js_key
				)
			), // Keys to do JavaScript antispam test 
			'js_keys_amount' => 24, // JavaScript keys store days - 2 days now
			'js_key_lifetime' => 86400, // JavaScript key life time in seconds - 1 day now
		);
		
		}else{
			
			$keys_times = array();
			
			foreach($js_keys['keys'] as $time => $key){
				
				if($time + $js_keys['js_key_lifetime'] < time())
					unset($js_keys['keys'][$time]);
				
				$keys_times[] = $time;
			}unset($time, $key);
			
			if(max($keys_times) + 3600 < time()){
				$js_key =  strval(md5($api_key . time()));
				$js_keys['keys'][time()] = $js_key;
			}else{
				$js_key = $js_keys['keys'][max($keys_times)];
			}
		
			}
					$config_text->set_array(array(
					'cleantalk_antispam_js_keys'	=> json_encode($js_keys),
				));
		return $js_key;	

    }  
	
	/** Return array of JS-keys for checking
	*
	* @return array
	*/
	public function cleantalk_is_valid_js()
	{
		$ct_checkjs_val = $this->request->variable(self::JS_FIELD_NAME, '', false, \phpbb\request\request_interface::COOKIE);
		if(isset($ct_checkjs_val)){
			
		$config_text = $this->phpbb_container->get('config_text');
		$config_text_data = $config_text->get_array(array(
			'cleantalk_antispam_js_keys'
		));
		$js_keys = isset($config_text_data['cleantalk_antispam_js_keys']) ? json_decode($config_text_data['cleantalk_antispam_js_keys'], true) : null;
			if($js_keys){
				$result = in_array($ct_checkjs_val, $js_keys['keys']);
			}else{
				$result = false;
			}
			
		}else
			$result = false;
	    return  $result;
	}
		
}
