<?php

namespace cleantalk\antispam\model;

class main_model {

    const JS_FIELD_NAME = 'ct_checkjs';

    public function checkSpam($spam_check) {
	global $config, $user, $request;
	require_once 'cleantalk.class.php';

	$ct_checkjs_val = request_var(self::JS_FIELD_NAME, '', false, true);
	if ($ct_checkjs_val === '') {
	    $checkjs = NULL;
	}
	elseif ($ct_checkjs_val == self::getCheckJSValue()) {
	    $checkjs = 1;
	}
	else {
	    $checkjs = 0;
	}

	$ct = new \Cleantalk();

	$ct->work_url       = $config['cleantalk_antispam_work_url'];
	$ct->server_url     = $config['cleantalk_antispam_server_url'];
	$ct->server_ttl     = $config['cleantalk_antispam_server_ttl'];
	$ct->server_changed = $config['cleantalk_antispam_server_changed'];

	$user_agent = htmlspecialchars((string)$request->server('HTTP_USER_AGENT'));
	$refferrer = htmlspecialchars((string)$request->server('HTTP_REFERER'));
	$sender_info = json_encode(
	    array(
    		'cms_lang' => $config['default_lang'],
    		'REFFERRER' => $refferrer,
    		'post_url' => $refferrer,
    		'USER_AGENT' => $user_agent,
	    )
	);

	$ct_request = new \CleantalkRequest();
	$ct_request->auth_key = $config['cleantalk_antispam_apikey'];
	$ct_request->agent = 'ct-phpbb-42';	// TODO - брать из composer.json
	$ct_request->js_on = $checkjs;
	$ct_request->sender_info = $sender_info;
	$ct_request->sender_email = array_key_exists('sender_email', $spam_check) ? $spam_check['sender_email'] : '';
	$ct_request->sender_nickname = array_key_exists('sender_nickname', $spam_check) ? $spam_check['sender_nickname'] : '';
	$ct_request->sender_ip = $ct->ct_session_ip($user->data['session_ip']);
	$ct_request->submit_time = (!empty($user->data['ct_submit_time'])) ? time() - $user->data['ct_submit_time'] : null;

	switch ($spam_check['type']) {
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

	  }
	  $ret_val = array();
          $ret_val['errno'] = 0;
          $ret_val['allow'] = 1;
	  $ret_val['ct_request_id'] = $ct_result->id;

	  if ($ct->server_change) {
		$config->set('cleantalk_antispam_work_url',       $ct->work_url);
		$config->set('cleantalk_antispam_server_url',     $ct->server_url);
		$config->set('cleantalk_antispam_server_ttl',     $ct->server_ttl);
		$config->set('cleantalk_antispam_server_changed', time());
	  }

	// First check errstr flag.
	if (!empty($ct_result->errstr)
	      || (!empty($ct_result->inactive) && $ct_result->inactive == 1)
	) {
	    // Cleantalk error so we go default way (no action at all).
	    $ret_val['errno'] = 1;
	    if (!empty($ct_result->errstr)) {
	      $ret_val['errstr'] = self::filterResponse($ct_result->errstr);
            }
            else {
	      $ret_val['errstr'] = self::filterResponse($ct_result->comment);
	    }
	    // TODO - слать письмо админу об ошибке раз в 15 минут

	    return $ret_val;
	}

	if ($ct_result->allow == 0) {
	    // Spammer.
	    $ret_val['allow'] = 0;
	    $ret_val['ct_result_comment'] = self::filterResponse($ct_result->comment);

	    // Check stop_queue flag.
	    if ($spam_check['type'] == 'comment' && $ct_result->stop_queue == 0) {
	      // Spammer and stop_queue == 0 - to manual approvement.
	      $ret_val['stop_queue'] = 0;
	    } else {
	      // New user or Spammer and stop_queue == 1 - display form error message.
	      $ret_val['stop_queue'] = 1;
	    }
	}
	return $ret_val;
    }

    public function filterResponse($ct_response) {
	if (preg_match('//u', $ct_response)) {
	    $err_str = preg_replace('/\*\*\*/iu', '', $ct_response);
	}
	else {
	    $err_str = preg_replace('/\*\*\*/i', '', $ct_response);
	}
	return $err_str;
    }

    public function setSubmitTime() {
	global $db, $user;

	$sql = "UPDATE " . SESSIONS_TABLE . "
    	    SET ct_submit_time = " . time() . "
    	    WHERE session_id = '" . $db->sql_escape($user->session_id) . "'";
	$db->sql_query($sql);
    }

    public function getCheckJSValue() {
	global $user;
	return md5($user->data['user_form_salt'] . $user->session_id);
    }

    public function checkJSScript() {
	    $ct_check_def = '0';
	    if (!isset($_COOKIE[self::JS_FIELD_NAME])) setcookie(self::JS_FIELD_NAME, $ct_check_def, 0, '/');
	    $ct_check_value = self::GetCheckJSValue();
	    $js_template = '<script type="text/javascript">function ctSetCookie(c_name,value){document.cookie=c_name+"="+escape(value)+"; path=/";} setTimeout("ctSetCookie(\"%s\", \"%s\");",1000);</script>';
	    $ct_addon_body = sprintf($js_template, self::JS_FIELD_NAME, $ct_check_value);
	    return $ct_addon_body;
    }
}
