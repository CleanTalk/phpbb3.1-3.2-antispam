<?php

namespace Cleantalk\Common\Localize;

class Localize
{
    /**
     * @var string
     */
    private $lang_dir;

    /**
     * @var string
     */
    public $locale = 'en';

    /**
     * @param string $lang_dir
     * @param string $locale
     */
    public function __construct($lang_dir, $locale = 'en')
    {
        $this->lang_dir = $lang_dir;
        $this->locale = $locale;
    }

    public function translate($string)
    {
        $lang_file = $this->lang_dir . '/' . $this->locale . '.lang';

        if ( ! file_exists($lang_file) ) {
            return $string;
        }

        $phrases = file($lang_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

        if ( $phrases === false ) {
            return $string;
        }

        // Loop through the lines to find the target string
        foreach ($phrases as $index => $line) {
            // Check if the next line exists
            if ( ( strpos($line, $string) !== false ) && isset($phrases[$index + 1]) ) {
                return $phrases[$index + 1];
            }
        }

        return $string;
    }
}
