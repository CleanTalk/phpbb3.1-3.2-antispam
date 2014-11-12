<?php
/**
*
* @package phpBB Extension - Cleantalk
* @copyright (c) 2013 phpBB Group
* @license http://opensource.org/licenses/gpl-2.0.php GNU General Public License v2
*
*/

namespace cleantalk\antispam\acp;

class main_info
{
	function module()
	{
		return array(
			'filename'	=> '\cleantalk\antispam\acp\main_module',
			'title'		=> 'ACP_CLEANTALK_TITLE',
			'version'	=> '1.0.0',
			'modes'		=> array(
				'settings'	=> array('title' => 'ACP_CLEANTALK_SETTINGS', 'auth' => 'ext_cleantalk/antispam && acl_a_board', 'cat' => array('ACP_CLEANTALK_TITLE')),
			),
		);
	}
}
