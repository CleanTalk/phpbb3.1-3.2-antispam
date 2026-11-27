<?php

/**
*
* @package phpBB Extension - Antispam by CleanTalk
* @author Сleantalk team (welcome@cleantalk.org)
* @copyright (C) 2014 СleanTalk team (https://cleantalk.org)
* @license GNU/GPL: http://www.gnu.org/copyleft/gpl.html
*
*/

namespace cleantalk\antispam;

/**
 * @psalm-suppress UnusedClass Loaded by phpBB's extension manager.
 */
class ext extends \phpbb\extension\base
{
    /**
     * Requires phpBB 3.3.0+ and PHP 7.2+
     *
     * @return bool|array
     */
    public function is_enableable()
    {
        // phpBB older than 3.3 does not support an array of messages here
        if (phpbb_version_compare(PHPBB_VERSION, '3.3.0', '<')) {
            return false;
        }

        if (PHP_VERSION_ID < 70200) {
            $language = $this->container->get('language');
            $language->add_lang('common', 'cleantalk/antispam');

            return array($language->lang('CLEANTALK_REQUIREMENTS_PHP', '7.2'));
        }

        return true;
    }
}
