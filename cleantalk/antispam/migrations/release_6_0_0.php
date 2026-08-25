<?php
/**
 * @package phpBB Extension - Antispam by CleanTalk
 * @author  CleanTalk team (welcome@cleantalk.org)
 * @copyright (C) 2014 CleanTalk team (https://cleantalk.org)
 * @license GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 */

namespace cleantalk\antispam\migrations;

class release_6_0_0 extends \phpbb\db\migration\migration
{
    public function effectively_installed()
    {
        return isset($this->config['cleantalk_antispam_bot_detector']);
    }

    static public function depends_on()
    {
        return array('\cleantalk\antispam\migrations\release_5_9_0');
    }

    public function update_data()
    {
        return array(
            array('config.add', array('cleantalk_antispam_bot_detector', 1)),
        );
    }
}
