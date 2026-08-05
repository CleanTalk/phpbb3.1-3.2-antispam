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

class release_5_7_8 extends \phpbb\db\migration\migration
{
	public function effectively_installed()
	{
		return isset($this->config['cleantalk_antispam_allusers']);
	}

	static public function depends_on()
	{
		return array('\cleantalk\antispam\migrations\release_5_7_7');
	}

	public function update_data()
	{
		return array(
			// Moderate All Registered Users (not only newly registered). Off by default.
			array('config.add', array('cleantalk_antispam_allusers', 0)),
		);
	}
}
