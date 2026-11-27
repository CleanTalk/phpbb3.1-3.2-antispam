<?php

require_once __DIR__ . '/fixtures/phpbb.inc';

use cleantalk\antispam\event\main_listener;
use cleantalk\antispam\model\main_model;
use phpbb\config\config;
use phpbb\template\template;
use PHPUnit\Framework\TestCase;

class PrivacyPolicyTest extends TestCase
{
    private function listener(template $template, $is_active)
    {
        $main_model = $this->createMock(main_model::class);
        $main_model->method('is_active')->willReturn($is_active);

        return new main_listener(
            $template,
            new config(array(
                'cleantalk_antispam_sfw_enabled'  => 1,
                'cleantalk_antispam_bot_detector' => 0,
            )),
            new \phpbb\config\db_text(),
            new \phpbb\user(),
            new \phpbb\language\language(),
            new \phpbb\request\request(),
            $this->createMock(\phpbb\db\driver\driver_interface::class),
            $main_model,
            new \phpbb\symfony_request(),
            'php',
            'phpbb_'
        );
    }

    public function append_privacy_policy_data()
    {
        return array(
            'privacy page'          => array(true, true, 'PRIVACY', true),
            'protection is paused'  => array(false, true, 'PRIVACY', false),
            'terms of use page'     => array(true, true, 'TERMS_USE', false),
            'not an agreement page' => array(true, false, null, false),
        );
    }

    /**
     * @dataProvider append_privacy_policy_data
     */
    public function test_append_privacy_policy($is_active, $s_agreement, $agreement_title, $expect_append)
    {
        $privacy_policy = '<br><br><h3>Spam protection by CleanTalk</h3>Text';

        $template = $this->createMock(template::class);
        $template->method('retrieve_var')->willReturnMap(array(
            array('S_AGREEMENT', $s_agreement),
            array('AGREEMENT_TITLE', $agreement_title),
        ));

        $template->expects($expect_append ? $this->once() : $this->never())
            ->method('assign_vars')
            ->with(array(
                'S_CLEANTALK_PRIVACY_SFW'          => true,
                'S_CLEANTALK_PRIVACY_BOT_DETECTOR' => false,
            ));
        $template->expects($expect_append ? $this->once() : $this->never())
            ->method('set_filenames')
            ->with(array('cleantalk_privacy_policy' => '@cleantalk_antispam/privacy_policy.html'));
        $template->expects($expect_append ? $this->once() : $this->never())
            ->method('assign_display')
            ->with('cleantalk_privacy_policy')
            ->willReturn($privacy_policy);
        $template->expects($expect_append ? $this->once() : $this->never())
            ->method('append_var')
            ->with('AGREEMENT_TEXT', $privacy_policy);

        $this->listener($template, $is_active)->append_privacy_policy();
    }

    public function test_privacy_language_is_complete_and_has_no_markup()
    {
        $language_dir = __DIR__ . '/../../cleantalk/antispam/language';
        $privacy_keys = function (array $lang) {
            return array_values(array_filter(array_keys($lang), function ($key) {
                return strpos($key, 'CLEANTALK_PRIVACY_POLICY_') === 0
                    || strpos($key, 'ACP_CLEANTALK_PRIVACY_') === 0
                    || in_array($key, array('ACP_CLEANTALK_DATA_NOTICE', 'CLEANTALK_REQUIREMENTS_PHP'), true);
            }));
        };

        $lang = array();
        include $language_dir . '/en/common.php';
        $expected_keys = $privacy_keys($lang);
        $this->assertNotEmpty($expected_keys);

        foreach (glob($language_dir . '/*/common.php') as $file) {
            $lang = array();
            include $file;

            $this->assertSame($expected_keys, $privacy_keys($lang), $file);
            foreach ($expected_keys as $key) {
                if (strpos($key, 'CLEANTALK_PRIVACY_POLICY_') === 0) {
                    $this->assertStringNotContainsString('<', $lang[$key], $file . ': ' . $key);
                }
            }
        }
    }
}
