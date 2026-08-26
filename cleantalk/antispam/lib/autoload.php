<?php

/**
 * Autoloader for CleanTalk common libraries (phpBB extension).
 * Loads constants and registers PSR-4 style class autoloader.
 */

require_once __DIR__ . '/constants.php';

/**
 * @param string $class
 * @return void
 */
spl_autoload_register(function ($class) {
    if (strpos($class, 'Cleantalk') !== false) {
        $class = str_replace('\\', DIRECTORY_SEPARATOR, $class);
        $class_file = __DIR__ . DIRECTORY_SEPARATOR . $class . '.php';
        if (file_exists($class_file)) {
            require_once($class_file);
        }
    }
});


