<?php

/**
 * Minimal phpBB classes, so the extension code can run in unit tests without a board.
 */

namespace phpbb\request {
    if (!interface_exists(request_interface::class)) {
        interface request_interface
        {
            const POST = 0;
            const GET = 1;
            const REQUEST = 2;
            const COOKIE = 3;
            const SERVER = 4;

            public function get_super_global($super_global = self::REQUEST);
        }
    }

    if (!class_exists(request::class)) {
        class request implements request_interface
        {
            /** @var array */
            private $input;

            public function __construct(array $input = array())
            {
                $this->input = $input;
            }

            public function get_super_global($super_global = self::REQUEST)
            {
                return isset($this->input[$super_global]) ? $this->input[$super_global] : array();
            }

            public function server($var_name, $default = '')
            {
                return isset($this->input[self::SERVER][$var_name]) ? $this->input[self::SERVER][$var_name] : $default;
            }
        }
    }
}

namespace phpbb\config {
    if (!class_exists(config::class)) {
        class config extends \ArrayObject
        {
            public function set($key, $value, $use_cache = true)
            {
                $this[$key] = $value;
            }
        }
    }

    if (!class_exists(db_text::class)) {
        class db_text
        {
        }
    }
}

namespace phpbb\template {
    if (!class_exists(template::class)) {
        class template
        {
            public function assign_vars(array $vars)
            {
            }

            public function assign_var($name, $value)
            {
            }

            public function set_filenames(array $filename_array)
            {
            }

            public function assign_display($handle, $template_var = '', $return_content = true)
            {
            }

            public function append_var($varname, $varval)
            {
            }

            public function retrieve_var($varname)
            {
            }
        }
    }
}

namespace phpbb\language {
    if (!class_exists(language::class)) {
        class language
        {
            public function lang()
            {
                return func_get_arg(0);
            }
        }
    }
}

namespace phpbb\db\driver {
    if (!interface_exists(driver_interface::class)) {
        interface driver_interface
        {
        }
    }
}

namespace phpbb\db\migration {
    if (!class_exists(migration::class)) {
        abstract class migration
        {
            /** @var \phpbb\config\config */
            public $config;

            public function __construct($config)
            {
                $this->config = $config;
            }
        }
    }
}

namespace phpbb {
    if (!class_exists(user::class)) {
        class user
        {
        }
    }

    if (!class_exists(symfony_request::class)) {
        class symfony_request
        {
        }
    }
}

namespace Symfony\Component\EventDispatcher {
    if (!interface_exists(EventSubscriberInterface::class)) {
        interface EventSubscriberInterface
        {
            public static function getSubscribedEvents();
        }
    }
}

namespace {
    if (!function_exists('utf8_htmlspecialchars')) {
        function utf8_htmlspecialchars($value)
        {
            return htmlspecialchars($value, ENT_COMPAT, 'UTF-8');
        }
    }

    spl_autoload_register(function ($class) {
        $prefix = 'cleantalk\\antispam\\';
        if (strpos($class, $prefix) === 0) {
            $file = __DIR__ . '/../../../cleantalk/antispam/' . str_replace('\\', '/', substr($class, strlen($prefix))) . '.php';
            if (file_exists($file)) {
                require_once $file;
            }
        }
    });
}
