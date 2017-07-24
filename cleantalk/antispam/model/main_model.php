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

class main_model
{
	const JS_FIELD_NAME = 'ct_checkjs';
	const JS_TIME_ZONE_FIELD_NAME = 'ct_timezone';
	const JS_POINTER_DATA_FIELD_NAME = 'ct_pointer_data';

	/**
	* Checks user registration to spam
	*
	* @param array	$spam_check		array with values to check
	* @return array				array with result flags
	*/
	
	static public function check_spam( $spam_check )
	{
		global $config, $user, $request, $phpbb_root_path, $phpEx, $phpbb_log;
		
		$checkjs = self::cleantalk_is_valid_js() ? 1 : 0;

		$ct = new \cleantalk\antispam\model\Cleantalk();
		
		$root_dir= realpath(dirname(__FILE__).'/../../../../');
		if(file_exists($root_dir."/cleantalk.pem")){
			$ct->ssl_on = true;
			$ct->ssl_path = $root_dir."/cleantalk.pem";
		}

		$ct->work_url       = $config['cleantalk_antispam_work_url'];
		$ct->server_url     = $config['cleantalk_antispam_server_url'];
		$ct->server_ttl     = $config['cleantalk_antispam_server_ttl'];
		$ct->server_changed = $config['cleantalk_antispam_server_changed'];

		//Pointer data, Timezone from JS, First key press timestamp, Page set timestamp
		$pointer_data 			= $request->variable(self::JS_POINTER_DATA_FIELD_NAME, 	"none", false, \phpbb\request\request_interface::COOKIE);
		$page_set_timestamp 	= $request->variable("ct_ps_timestamp", 				"none", false, \phpbb\request\request_interface::COOKIE);
		$js_timezone 			= $request->variable(self::JS_TIME_ZONE_FIELD_NAME, 	"none", false, \phpbb\request\request_interface::COOKIE);
		$first_key_timestamp 	= $request->variable("ct_fkp_timestamp", 				"none", false, \phpbb\request\request_interface::COOKIE);
		
		$pointer_data 			= ($pointer_data 		=== "none" ? 0 : json_decode ($pointer_data));
		$js_timezone 			= ($js_timezone 		=== "none" ? 0 : $js_timezone);
		$first_key_timestamp 	= ($first_key_timestamp === "none" ? 0 : intval($first_key_timestamp));
		$page_set_timestamp 	= ($page_set_timestamp 	=== "none" ? 0 : intval($page_set_timestamp));
				
		$user_agent = $request->server('HTTP_USER_AGENT');
		$refferrer = $request->server('HTTP_REFERER');		
		$sender_info = json_encode(
			array(
			'cms_lang' => $config['default_lang'],
			'REFFERRER' => $refferrer,
			'post_url' => $refferrer,
			'USER_AGENT' => $user_agent,
			'js_timezone' => $js_timezone,
			'mouse_cursor_positions' => $pointer_data,
			'key_press_timestamp' => $first_key_timestamp,
			'page_set_timestamp' => $page_set_timestamp	
			)
		);
		
		$composer_json = json_decode(file_get_contents($phpbb_root_path . 'ext/cleantalk/antispam/composer.json'));

		$ct_request = new \cleantalk\antispam\model\CleantalkRequest();
		if(isset($spam_check['auth_key'])){
			$ct_request->auth_key = $spam_check['auth_key'];
		}else{
			$ct_request->auth_key = $config['cleantalk_antispam_apikey'];
		}
		
		$ct_request->agent = 'phpbb31-' . preg_replace("/(\d+)\.(\d*)\.?(\d*)/", "$1$2$3", $composer_json->version);
		$ct_request->js_on = $checkjs;
		$ct_request->sender_info = $sender_info;
		$ct_request->sender_email = array_key_exists('sender_email', $spam_check) ? $spam_check['sender_email'] : '';
		$ct_request->sender_nickname = array_key_exists('sender_nickname', $spam_check) ? $spam_check['sender_nickname'] : '';
		$ct_request->sender_ip = $user->ip;
		$ct_request->submit_time = (!empty($user->data['ct_submit_time'])) ? time() - $user->data['ct_submit_time'] : null;

		switch ($spam_check['type'])
		{
		case 'comment':
			$ct_request->message = (array_key_exists('message_title', $spam_check) ? $spam_check['message_title'] : '' ).
				" \n\n" .
				(array_key_exists('message_body', $spam_check) ? $spam_check['message_body'] : '');
			$ct_result = $ct->isAllowMessage($ct_request);
			 break;
		case 'register':
			$ct_request->tz = array_key_exists('timezone', $spam_check) ? $spam_check['timezone'] : '';
			$ct_result = $ct->isAllowUser($ct_request);
			break;
		case 'send_feedback':
			$ct_request->feedback = $spam_check['feedback'];
			$ct_result = $ct->sendFeedback($ct_request);
			break;
		}
		$ret_val = array();
		$ret_val['errno'] = 0;
		$ret_val['allow'] = 1;
		$ret_val['ct_request_id'] = $ct_result->id;

		if ($ct->server_change)
		{
			$config->set('cleantalk_antispam_work_url',       $ct->work_url);
			$config->set('cleantalk_antispam_server_url',     $ct->server_url);
			$config->set('cleantalk_antispam_server_ttl',     $ct->server_ttl);
			$config->set('cleantalk_antispam_server_changed', time());
		}
		
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
					$ct_result->errstr = $user->lang('CLEANTALK_ERROR_CURL', $ct_result->curl_err);
				}else{
					$ct_result->errstr = $user->lang('CLEANTALK_ERROR_NO_CURL');
				}
				$ct_result->errstr .= $user->lang('CLEANTALK_ERROR_ADDON');
							
				$ret_val['errstr'] = self::filter_response($ct_result->errstr);
			}else{
				$ret_val['errstr'] = self::filter_response($ct_result->comment);
			}

			$phpbb_log->add('admin', ANONYMOUS, '127.0.0.1', 'CLEANTALK_ERROR_LOG', time(), array($ret_val['errstr']));

			// Email to admin once per 15 min
			if (time() - 900 > $config['cleantalk_antispam_error_time'])
			{
				$config->set('cleantalk_antispam_error_time', time());
				if (!function_exists('phpbb_mail'))
				{
					include($phpbb_root_path . 'includes/functions_messenger.' . $phpEx);
				}

				$hr_url = str_replace(array('http://', 'https://'), array('', ''), generate_board_url());
				$err_title = $hr_url. ' - ' . $user->lang['CLEANTALK_ERROR_MAIL'];
				$err_message = $hr_url. ' - ' . $user->lang['CLEANTALK_ERROR_MAIL'] . " :\n" . $ret_val['errstr'];

				$headers = array();
				$headers[] = 'Reply-To: ' . $config['board_email'];
				$headers[] = 'Return-Path: <' . $config['board_email'] . '>';
				$headers[] = 'Sender: <' . $config['board_email'] . '>';
				$headers[] = 'MIME-Version: 1.0';
				$headers[] = 'X-Mailer: phpBB3';
				$headers[] = 'X-MimeOLE: phpBB3';
				$headers[] = 'X-phpBB-Origin: phpbb://' . $hr_url;
				$headers[] = 'Content-Type: text/plain; charset=UTF-8'; // format=flowed
				$headers[] = 'Content-Transfer-Encoding: 8bit'; // 7bit

				$dummy = '';
				phpbb_mail($config['board_email'], $err_title, $err_message, $headers, "\n", $dummy);
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
			$ret_val['ct_result_comment'] = self::filter_response($ct_result->comment);

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
	return $ret_val;
	}

	/**
	* Filters raw CleanTalk cloud response
	*
	* @param string	$ct_response		Raw CleanTalk cloud response
	* @return string			Filtered CleanTalk cloud response
	*/
	static public function filter_response( $ct_response )
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

	/**
	* Sets from display time in table
	*/
	static public function set_submit_time()
	{
		global $db, $user;
		$sql = 'UPDATE ' . SESSIONS_TABLE . 
			' SET ct_submit_time = ' . time() .
			' WHERE session_id = \'' . $db->sql_escape($user->session_id) . '\'';
		$db->sql_query($sql);
	}
    static public function cleantalk_get_checkjs_code()
    {
		global $config,$phpbb_container;
		$config_text = $phpbb_container->get('config_text');
		$config_text_data = $config_text->get_array(array(
			'cleantalk_antispam_js_keys'
		));
		$js_keys = isset($config_text_data['cleantalk_antispam_js_keys']) ? json_decode($config_text_data['cleantalk_antispam_js_keys'], true) : null;
    	$api_key = isset($config['cleantalk_antispam_apikey']) ? $config['cleantalk_antispam_apikey'] : null;
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
	static public function cleantalk_is_valid_js()
	{
		global $request;
		$ct_checkjs_val = $request->variable(self::JS_FIELD_NAME, '', false, \phpbb\request\request_interface::COOKIE);
		if(isset($ct_checkjs_val)){
					
			global $config,$phpbb_container;
			
		$config_text = $phpbb_container->get('config_text');
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
	/**
	* Gets conplete JS-code with session-unique hash to insert into template for JS-ebabled checkibg
	*
	* @return string JS-code
	*/
	static public function get_check_js_script()
	{	
		global $request;

		$ct_check_value = self::cleantalk_get_checkjs_code();
		$js_template = '<script type="text/javascript">
			function ctSetCookie(c_name, value) {
				document.cookie = c_name + "=" + encodeURIComponent(value) + "; path=/";
			}

			ctSetCookie("ct_ps_timestamp", Math.floor(new Date().getTime()/1000));
			ctSetCookie("ct_fkp_timestamp", "0");
			ctSetCookie("ct_pointer_data", "0");
			ctSetCookie("ct_timezone", "0");

			setTimeout(function(){
				ctSetCookie("%s", "%s");
				ctSetCookie("ct_timezone", new Date().getTimezoneOffset()/60*(-1));
			},1000);

			//Stop observing function
			function ctMouseStopData(){
				if(typeof window.addEventListener == "function"){
					window.removeEventListener("mousemove", ctFunctionMouseMove);
				}else{
					window.detachEvent("onmousemove", ctFunctionMouseMove);
				}
				clearInterval(ctMouseReadInterval);
				clearInterval(ctMouseWriteDataInterval);				
			}

			//Stop key listening function
			function ctKeyStopStopListening(){
				if(typeof window.addEventListener == "function"){
					window.removeEventListener("mousedown", ctFunctionFirstKey);
					window.removeEventListener("keydown", ctFunctionFirstKey);
				}else{
					window.detachEvent("mousedown", ctFunctionFirstKey);
					window.detachEvent("keydown", ctFunctionFirstKey);
				}			
			}

			var d = new Date(), 
				ctTimeMs = new Date().getTime(),
				ctMouseEventTimerFlag = true, //Reading interval flag
				ctMouseData = "[",
				ctMouseDataCounter = 0;
				
			//Reading interval
			var ctMouseReadInterval = setInterval(function(){
					ctMouseEventTimerFlag = true;
				}, 100);
				
			//Writting interval
			var ctMouseWriteDataInterval = setInterval(function(){ 
					var ctMouseDataToSend = ctMouseData.slice(0,-1).concat("]");
					ctSetCookie("ct_pointer_data", ctMouseDataToSend);
				}, 1000);

			//Logging mouse position each 300 ms
			var ctFunctionMouseMove = function output(event){
				if(ctMouseEventTimerFlag == true){
					var mouseDate = new Date();
					ctMouseData += "[" + event.pageY + "," + event.pageX + "," + (mouseDate.getTime() - ctTimeMs) + "],";
					ctMouseDataCounter++;
					ctMouseEventTimerFlag = false;
					if(ctMouseDataCounter >= 100){
						ctMouseStopData();
					}
				}
			}
			//Writing first key press timestamp
			var ctFunctionFirstKey = function output(event){
				var KeyTimestamp = Math.floor(new Date().getTime()/1000);
				ctSetCookie("ct_fkp_timestamp", KeyTimestamp);
				ctKeyStopStopListening();
			}

			if(typeof window.addEventListener == "function"){
				window.addEventListener("mousemove", ctFunctionMouseMove);
				window.addEventListener("mousedown", ctFunctionFirstKey);
				window.addEventListener("keydown", ctFunctionFirstKey);
			}else{
				window.attachEvent("onmousemove", ctFunctionMouseMove);
				window.attachEvent("mousedown", ctFunctionFirstKey);
				window.attachEvent("keydown", ctFunctionFirstKey);
			}
		</script>';
		
		$ct_addon_body = sprintf($js_template, self::JS_FIELD_NAME, $ct_check_value);
				
		return $ct_addon_body;
	}
	
	/**
	* Check new visitors for SFW database
	* @return void
	*/
	static public function sfw_check(){
		
		global $config, $request, $user;
		
		if($config['cleantalk_antispam_sfw_enabled'] && $config['cleantalk_antispam_key_is_ok']){
			
			$is_sfw_check = true;
			$sfw = new \cleantalk\antispam\model\CleantalkSFW();
			
			$ip = $sfw->cleantalk_get_real_ip();
			
			$cookie_prefix = $config['cookie_name']   ? $config['cookie_name'].'_'           : '';
			$cookie_domain = $config['cookie_domain'] ? " domain={$config['cookie_domain']};" : ''; 
			
			$ct_sfw_pass_key 	= $request->variable($cookie_prefix.'ct_sfw_pass_key', '', false, \phpbb\request\request_interface::COOKIE);
			$ct_sfw_passed 		= $request->variable($cookie_prefix.'ct_sfw_passed',   '', false, \phpbb\request\request_interface::COOKIE);
			
			foreach($ip as $ct_cur_ip){
								
				if($ct_sfw_pass_key == md5($ct_cur_ip.$config['cleantalk_antispam_apikey'])){
					
					$is_sfw_check = false;
					if($ct_sfw_passed){
						$sfw->sfw_update_logs($ct_cur_ip, 'passed');
						$user->set_cookie('ct_sfw_passed', '0', 1);
					}
				}else
					$is_sfw_check = true;
				
			} unset($ct_cur_ip);
			
			if($is_sfw_check){
				$sfw->check_ip();
				if($sfw->result){
					$sfw->sfw_update_logs($sfw->blocked_ip, 'blocked');
					$sfw->sfw_die($config['cleantalk_antispam_apikey'], $cookie_prefix, $cookie_domain);
				}else{
					$user->set_cookie('ct_sfw_pass_key', md5($sfw->passed_ip.$config['cleantalk_antispam_apikey']), 0, false);
				}
			}			
		}
	}
	
	/**
	* Update SFW database
	* @return void
	*/
	static public function sfw_update($api_key){
		$sfw = new \cleantalk\antispam\model\CleantalkSFW();
		$result = $sfw->sfw_update($api_key);
	}
	
	/**
	* Send SFW logs
	* @return void
	*/
	static public function sfw_send_logs($api_key){
		$sfw = new \cleantalk\antispam\model\CleantalkSFW();
		$result = $sfw->send_logs($api_key);
	}
	
	static public function check_payment_status($api_key){
		
		global $config;
		
		$result = \cleantalk\antispam\acp\cleantalkHelper::noticePaidTill($api_key);
		$result = json_decode($result, true);
		if(!empty($result['data'])){
			$config->set('cleantalk_antispam_show_notice', $result['data']['show_notice']);
			$config->set('cleantalk_antispam_renew',       $result['data']['renew']);
			$config->set('cleantalk_antispam_trial',       $result['data']['trial']);
			$config->set('cleantalk_antispam_user_token',  $result['data']['user_token']);
			$config->set('cleantalk_antispam_spam_count',  $result['data']['spam_count']);
			$config->set('cleantalk_antispam_moderate_ip', $result['data']['moderate_ip']);
			$config->set('cleantalk_antispam_show_review', $result['data']['show_review']);
			$config->set('cleantalk_antispam_ip_license',  $result['data']['ip_license']);
		}
	}
	
}
