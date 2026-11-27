<?php

/**
 * @package phpBB Extension - Antispam by CleanTalk
 * @author  CleanTalk team (welcome@cleantalk.org)
 * @copyright (C) 2014 CleanTalk team (https://cleantalk.org)
 * @license GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 */

namespace cleantalk\antispam\migrations;

class release_6_2_0 extends \phpbb\db\migration\migration
{
    public function effectively_installed()
    {
        return isset($this->config['cleantalk_antispam_privacy_confirmed']);
    }

    public static function depends_on()
    {
        return array('\cleantalk\antispam\migrations\release_6_0_0');
    }

    public function update_data()
    {
        return array(
            array('config.add', array('cleantalk_antispam_privacy_confirmed', 0)),
            array('custom', array(array($this, 'keep_protection_on_upgrade'))),
        );
    }

    /**
     * New installations start with the confirmation off. Boards upgrading with
     * a working access key keep their spam protection running.
     */
    public function keep_protection_on_upgrade()
    {
        if (!empty($this->config['cleantalk_antispam_apikey']) && !empty($this->config['cleantalk_antispam_key_is_ok'])) {
            $this->config->set('cleantalk_antispam_privacy_confirmed', 1);
        }
    }
}
