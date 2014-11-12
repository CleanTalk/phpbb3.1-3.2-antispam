<?php

/*

  Process phpBB 3 posts to detect SPAM and offtopic.
  Copyright (C) Denis Shagimuratov shagimuratov@cleantalk.org

  This program is free software; you can redistribute it and/or
  modify it under the terms of the GNU General Public License
  as published by the Free Software Foundation; either version 2
  of the License, or (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

*/

if (!defined('IN_PHPBB'))
{
	exit;
}

// JavaScript test flags
define('CT_JS_UKNOWN', null);
define('CT_JS_PASSED', 1);
define('CT_JS_FAILED', 0);

function ct_error_mail( $message = '', $subject = null )
{

	global $config, $user, $phpbb_root_path, $phpEx;
	
	$user->add_lang('mods/info_acp_cleantalk');

	if (!function_exists('phpbb_mail'))
	{
		include($phpbb_root_path . 'includes/functions_messenger.' . $phpEx);
	}

	$headers[]	 = 'Reply-To: ' . $config['board_email'];
	$headers[]	 = 'Return-Path: <' . $config['board_email'] . '>';
	$headers[]	 = 'Sender: <' . $config['board_email'] . '>';
	$headers[]	 = 'MIME-Version: 1.0';
	$headers[]	 = 'X-Mailer: phpBB3';
	$headers[]	 = 'X-MimeOLE: phpBB3';
	$headers[]	 = 'X-phpBB-Origin: phpbb://' . str_replace(array('http://', 'https://'), array('', ''), generate_board_url());
	$headers[]	 = 'Content-Type: text/plain; charset=UTF-8'; // format=flowed
	$headers[]	 = 'Content-Transfer-Encoding: 8bit'; // 7bit

	$err_msg = '';
	$subject = ($subject == null) ? $config['ct_server_url'] : $subject;
	$err_str = sprintf($user->lang['CT_ERROR'], $config['ct_server_url']);
	$result	 = phpbb_mail($config['board_email'], $subject, $err_str, $headers, "\n", $err_msg);

	if (!$result)
	{
		return false;
	}

	return true;
}

/*
	Get value of $ct_check_js
	JavaScript avaibility test. Work only if S_FORM_TOKEN have filled.
	
	Possible return status:
	null - JS html code not inserted into phpBB templates
	0 - JS disabled at the client browser
	1 - JS enabled at the client broswer
*/
function get_ct_checkjs()
{
	
	global $template, $user;

	$ct_checkjs = request_var('ct_checkjs', '');

	$ct_checkjs_key = md5($user->data['user_form_salt'] . $user->session_id);

	if ($ct_checkjs === $ct_checkjs_key)
    {
		$result = CT_JS_PASSED;
    }
	else
    {
		$result = CT_JS_FAILED;
	}

	// If default value we should null variable to correctly processing request at the server side
	if ($ct_checkjs === '')
    {
		$result = CT_JS_UKNOWN; 
	}

	return $result;
}

/*
	Creates sender info.
	Returning JSON array or null.
*/
function get_sender_info($profile = false)
{
	global $config;

	$result = null;
	if (function_exists('json_encode'))
	{
		$refferrer	 = null;
		if (isset($_SERVER['HTTP_REFERER']))
        {
			$refferrer	 = htmlspecialchars((string) $_SERVER['HTTP_REFERER']);
        }

		$user_agent	 = null;
		if (isset($_SERVER['HTTP_USER_AGENT']))
        {
			$user_agent	 = htmlspecialchars((string) $_SERVER['HTTP_USER_AGENT']);
        }

		$result = array(
			'cms_lang' => $config['default_lang'],
			'REFFERRER' => $refferrer,
			'USER_AGENT' => $user_agent,
			'site_url' => generate_board_url(true) 
		);
		
		if ($profile)
        {
			$result['profile'] = 1;
        }

		$result = json_encode($result);
	}

	return $result;
}

/**
* Saves form load time to sessions table
*/
function ct_set_submit_time () 
{
    global $db, $user;

    $sql = "UPDATE " . SESSIONS_TABLE . "
        SET ct_submit_time = " . time() . "
        WHERE session_id = '" . $db->sql_escape($user->session_id) . "'";
	$db->sql_query($sql);
    
    return null;
}

?>
