<?php

namespace Cleantalk\Custom\Helper;

use Cleantalk\Custom\Variables\Source;

/**
 * phpBB-specific helper, resolved through Mloader::get('Helper').
 */
class Helper extends \Cleantalk\Common\Helper\Helper
{
    /**
     * Passes HTTP headers from phpBB request data, so the parent does not iterate the disabled $_SERVER.
     *
     * @param string $ip_type_to_get
     * @param bool $v4_only
     * @param array $headers
     *
     * @return string|null
     */
    public static function ipGet($ip_type_to_get = 'real', $v4_only = true, $headers = array())
    {
        return parent::ipGet($ip_type_to_get, $v4_only, $headers ?: Source::headers());
    }
}
