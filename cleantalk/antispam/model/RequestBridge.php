<?php

/**
*
* @package phpBB Extension - Antispam by CleanTalk
* @author Сleantalk team (welcome@cleantalk.org)
* @copyright (C) 2014 СleanTalk team (https://cleantalk.org)
* @license GNU/GPL: http://www.gnu.org/copyleft/gpl.html
*
*/

namespace cleantalk\antispam\model;

use Cleantalk\Custom\Variables\Source;
use phpbb\request\request_interface;

/**
* Feeds the CleanTalk Common libraries with request data from the phpBB request object,
* so the superglobals never have to be re-enabled.
*/
class RequestBridge
{
    /**
    * @param request_interface $request
    *
    * @return void
    */
    public static function init(request_interface $request)
    {
        Source::set(array(
            Source::SERVER => $request->get_super_global(request_interface::SERVER),
            Source::GET    => $request->get_super_global(request_interface::GET),
            Source::POST   => $request->get_super_global(request_interface::POST),
            Source::COOKIE => $request->get_super_global(request_interface::COOKIE),
        ));

        // The Custom readers share the static $instance of their Common parents,
        // so installing them redirects every Common\Variables\*::get() call.
        $readers = array(
            \Cleantalk\Custom\Variables\Server::class,
            \Cleantalk\Custom\Variables\Get::class,
            \Cleantalk\Custom\Variables\Post::class,
            \Cleantalk\Custom\Variables\Cookie::class,
            \Cleantalk\Custom\Variables\Request::class,
        );
        foreach ($readers as $reader) {
            $reader::resetInstance();
            $reader::getInstance();
        }

        // Some Common code calls Helper::httpGetHeaders() directly, which iterates $_SERVER
        // unless the headers are already cached in the helper's private property.
        \Cleantalk\Common\Helper\Helper::resetInstance();
        $cache_headers = \Closure::bind(
            /** @psalm-suppress InvalidScope Bound to the helper instance below */
            function (array $headers) {
                $this->headers = $headers;
            },
            \Cleantalk\Common\Helper\Helper::getInstance(),
            \Cleantalk\Common\Helper\Helper::class
        );
        if ($cache_headers) {
            $cache_headers(Source::headers());
        }
    }
}
