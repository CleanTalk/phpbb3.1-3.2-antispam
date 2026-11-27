<?php

namespace Cleantalk\Custom\Variables;

/**
 * $_SERVER reader backed by phpBB request data.
 *
 * Does not redeclare $instance, so once installed it is shared with
 * \Cleantalk\Common\Variables\Server and serves its static calls.
 */
class Server extends \Cleantalk\Common\Variables\Server
{
    /**
     * @param string $name
     *
     * @return mixed|string
     *
     * @psalm-suppress PossiblyInvalidCast, PossiblyInvalidArgument The parent stores arrays from form fields too
     */
    protected function getVariable($name)
    {
        $name = strtoupper($name);

        if (isset(static::$instance->variables[$name])) {
            return static::$instance->variables[$name];
        }

        $value = Source::get(Source::SERVER, $name);
        $value = $value !== null ? $this->getAndSanitize($value) : '';

        if ($name === 'REQUEST_METHOD' && is_string($value)) {
            $value = strtoupper($value);
        }

        if (in_array($name, array('HTTP_USER_AGENT', 'SERVER_NAME'), true) && is_string($value)) {
            $value = utf8_htmlspecialchars($value);
        }

        static::getInstance()->rememberVariable($name, $value);

        return $value;
    }
}
