<?php
/**
*
* @package phpBB Extension - Cleantalk
* @copyright (c) 2013 phpBB Group
* @license http://opensource.org/licenses/gpl-2.0.php GNU General Public License v2
*
*/

namespace cleantalk\antispam\acp;

class main_module
{
	var $u_action;

	function main($id, $mode)
	{
		global $db, $user, $auth, $template, $cache, $request;
		global $config, $phpbb_root_path, $phpbb_admin_path, $phpEx;

		$user->add_lang('acp/common');
		$this->tpl_name = 'settings_body';
		$this->page_title = $user->lang('ACP_CLEANTALK_TITLE');
		add_form_key('cleantalk/antispam');

		if ($request->is_set_post('submit'))
		{
			if (!check_form_key('cleantalk/antispam'))
			{
				trigger_error('FORM_INVALID');
			}

			$config->set('cleantalk_antispam_regs', $request->variable('cleantalk_antispam_regs', 0));
			$config->set('cleantalk_antispam_guests', $request->variable('cleantalk_antispam_guests', 0));
			$config->set('cleantalk_antispam_nusers', $request->variable('cleantalk_antispam_nusers', 0));
			$config->set('cleantalk_antispam_apikey', $request->variable('cleantalk_antispam_apikey', 'enter key'));

			trigger_error($user->lang('ACP_CLEANTALK_SETTINGS_SAVED') . adm_back_link($this->u_action));
		}

		$template->assign_vars(array(
			'U_ACTION'				=> $this->u_action,
			'CLEANTALK_ANTISPAM_REGS'		=> $config['cleantalk_antispam_regs'],
			'CLEANTALK_ANTISPAM_GUESTS'		=> $config['cleantalk_antispam_guests'],
			'CLEANTALK_ANTISPAM_NUSERS'		=> $config['cleantalk_antispam_nusers'],
			'CLEANTALK_ANTISPAM_APIKEY'		=> $config['cleantalk_antispam_apikey'],
		));
	}
}
