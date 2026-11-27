<?php

namespace Cleantalk\Custom\Variables;

/**
 * $_POST reader backed by phpBB request data. Shares $instance with the Common parent.
 */
class Post extends \Cleantalk\Common\Variables\Post
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
        if (!isset(static::$instance->variables[$name])) {
            $value = Source::get(Source::POST, $name);
            $value = $value !== null ? $this->getAndSanitize($value) : '';
            static::getInstance()->rememberVariable($name, $value);

            return $value;
        }

        return static::$instance->variables[$name];
    }
}
