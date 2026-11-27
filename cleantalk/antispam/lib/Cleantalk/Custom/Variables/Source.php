<?php

namespace Cleantalk\Custom\Variables;

/**
 * Request data handed over by phpBB.
 *
 * phpBB replaces $_SERVER, $_GET, $_POST, $_COOKIE and $_REQUEST with objects that trigger
 * a fatal error on read. The Custom\Variables classes read request data from here instead.
 */
class Source
{
    const SERVER = 'server';
    const GET = 'get';
    const POST = 'post';
    const COOKIE = 'cookie';

    /**
     * @var array{server: array, get: array, post: array, cookie: array}
     */
    private static $data = array(
        self::SERVER => array(),
        self::GET    => array(),
        self::POST   => array(),
        self::COOKIE => array(),
    );

    /**
     * @param array<string, mixed> $data Keyed by the class constants
     *
     * @return void
     */
    public static function set(array $data)
    {
        foreach (array_keys(self::$data) as $type) {
            self::$data[$type] = isset($data[$type]) && is_array($data[$type]) ? $data[$type] : array();
        }
    }

    /**
     * @param string $type
     * @param string $name
     *
     * @return mixed|null Null when the variable is not set
     */
    public static function get($type, $name)
    {
        return isset(self::$data[$type][$name]) ? self::$data[$type][$name] : null;
    }

    /**
     * HTTP headers in the same format as \Cleantalk\Common\Helper\Helper::httpGetHeaders()
     *
     * @return array<string, mixed>
     */
    public static function headers()
    {
        $headers = array();

        foreach (self::$data[self::SERVER] as $key => $val) {
            if (0 !== stripos((string) $key, 'http_')) {
                continue;
            }

            $server_key = preg_replace('/^http_/i', '', (string) $key);
            if (strlen($server_key) > 2) {
                $key_parts = explode('_', $server_key);
                foreach ($key_parts as $part_index => $part) {
                    if ($part === '') {
                        continue;
                    }
                    $part = function_exists('mb_strtolower') ? mb_strtolower($part) : strtolower($part);
                    $key_parts[$part_index] = ucfirst($part);
                }
                $server_key = implode('-', $key_parts);
            }
            $headers[$server_key] = $val;
        }

        return $headers;
    }
}
