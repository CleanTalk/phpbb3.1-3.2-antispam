<?php
/**
*
* @package phpBB Extension - Antispam by CleanTalk
* @author Сleantalk team (welcome@cleantalk.org)
* @copyright (C) 2014 СleanTalk team (http://cleantalk.org)
* @license GNU/GPL: http://www.gnu.org/copyleft/gpl.html
*
*/

namespace cleantalk\antispam\migrations;

class release_5_7_3 extends \phpbb\db\migration\migration
{
	public function effectively_installed()
	{
		return isset($this->config['cleanalk_antispam_apikey']);
	}

	static public function depends_on()
	{
		return array('\cleantalk\antispam\migrations\release_5_7_0');
	}

	public function update_data()
	{
		return array(
			//Custom contact forms
			array('config.add', array('check_spam_number', '')),			
		);
	}
}
