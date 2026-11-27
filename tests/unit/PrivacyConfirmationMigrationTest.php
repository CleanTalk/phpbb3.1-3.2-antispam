<?php

require_once __DIR__ . '/fixtures/phpbb.inc';

use cleantalk\antispam\migrations\release_6_2_0;
use phpbb\config\config;
use PHPUnit\Framework\TestCase;

class PrivacyConfirmationMigrationTest extends TestCase
{
    public function keep_protection_data()
    {
        return array(
            'new installation'         => array('', 0, 0),
            'upgrade with working key' => array('key', 1, 1),
            'upgrade with invalid key' => array('key', 0, 0),
        );
    }

    /**
     * @dataProvider keep_protection_data
     */
    public function test_keep_protection_on_upgrade($apikey, $key_is_ok, $expected)
    {
        $config = new config(array(
            'cleantalk_antispam_apikey'            => $apikey,
            'cleantalk_antispam_key_is_ok'         => $key_is_ok,
            'cleantalk_antispam_privacy_confirmed' => 0,
        ));

        (new release_6_2_0($config))->keep_protection_on_upgrade();

        $this->assertSame($expected, $config['cleantalk_antispam_privacy_confirmed']);
    }
}
