<?php

namespace Cleantalk\Custom\BotDetectorService;

use Cleantalk\Common\Mloader\Mloader;

class BotDetectorService extends \Cleantalk\Common\BotDetectorService\BotDetectorService
{
    /**
     * @param string $wrapper_url
     * @return void
     */
    public function saveWrapperURL($wrapper_url)
    {
        $storage_class = Mloader::get('StorageHandler');
        $storage = new $storage_class();
        $storage->saveSetting(self::OPTION_NAME, $wrapper_url);
    }

    /**
     * @return string|false
     */
    public function loadWrapperURL()
    {
        $storage_class = Mloader::get('StorageHandler');
        $storage = new $storage_class();
        $value = $storage->getSetting(self::OPTION_NAME);

        return $value ? $value : false;
    }
}
