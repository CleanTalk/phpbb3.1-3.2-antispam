<?php

namespace Cleantalk\Common\StorageHandler;

interface StorageHandler
{
    public function getSetting($setting_name);

    public function deleteSetting($setting_name);

    public function saveSetting($setting_name, $setting_value);

    public static function getUpdatingFolder();

    public static function getJsLocation();
}
