<?php

namespace Cleantalk\Custom\Variables;

/**
 * $_REQUEST reader. The parent resolves Post/Get/Cookie from the namespace of the
 * installed instance, so installing this class routes it to the Custom readers.
 */
class Request extends \Cleantalk\Common\Variables\Request
{
}
