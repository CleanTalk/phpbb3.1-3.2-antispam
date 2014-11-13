<?php

if (!defined('IN_PHPBB'))
{
	exit;
}

if (empty($lang) || !is_array($lang))
{
	$lang = array();
}

$lang = array_merge($lang, array(
	'ACP_CLEANTALK_TITLE'			=> 'Antispam by CleanTalk',

	'ACP_CLEANTALK_SETTINGS'		=> 'Spam protection settings',
	'ACP_CLEANTALK_SETTINGS_SAVED'		=> 'Spam protection settings have been saved successfully!',

	'ACP_CLEANTALK_REGS_LABEL'		=> 'Check Registrations',
	'ACP_CLEANTALK_REGS_DESCR'		=> 'Spam-bots will be rejected with a statement of reasons.',

	'ACP_CLEANTALK_GUESTS_LABEL'		=> 'Moderate Guests',
	'ACP_CLEANTALK_GUESTS_DESCR'		=> 'Posts and topics from guests will be test for spam. Spam will be rejected with a statement of reasons.',

	'ACP_CLEANTALK_NUSERS_LABEL'		=> 'Moderate Newly Registered Users',
	'ACP_CLEANTALK_NUSERS_DESCR'		=> 'Posts and topics from new users will be test for spam. Spam will be rejected with a statement of reasons.',

	'ACP_CLEANTALK_APIKEY_LABEL'		=> 'Access key',
	'ACP_CLEANTALK_APIKEY_DESCR1'		=> 'To get an access key please register at site ',
	'ACP_CLEANTALK_APIKEY_DESCR2'		=> '',

));
