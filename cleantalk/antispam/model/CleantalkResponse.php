<?php

/**
 * Cleantalk Base class
 * Compatible only with phpBB 3.1+
 * @version 2.3-phpbb
 * @subpackage Response
 * @author Cleantalk team (welcome@cleantalk.org)
 * @copyright (C) 2014 CleanTalk team (https://cleantalk.org)
 * @license GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 * @see https://github.com/CleanTalk/php-antispam
 *
 */

namespace cleantalk\antispam\model;

/**
 * @psalm-suppress PossiblyUnusedProperty Response fields are read dynamically by the extension.
 */
class CleantalkResponse
{
    /**
     * Received feedback nubmer
     * @var int|null
     */
    public $received = null;

    /**
     *  Is stop words
     * @var string|null
     */
    public $stop_words = null;

    /**
     * Cleantalk comment
     * @var string|null
     */
    public $comment = null;

    /**
     * Is blacklisted
     * @var int|null
     */
    public $blacklisted = null;

    /**
     * Is allow, 1|0
     * @var int|null
     */
    public $allow = null;

    /**
     * Request ID
     * @var int|null
     */
    public $id = null;

    /**
     * Request errno
     * @var int|null
     */
    public $errno = null;

    /**
     * Error string
     * @var string|null
     */
    public $errstr = null;

    /**
     * Error string
     * @var string|false|null
     */
    public $curl_err = null;

    /**
     * Is fast submit, 1|0
     * @var string|int|null
     */
    public $fast_submit = null;

    /**
     * Is spam comment
     * @var string|int|null
     */
    public $spam = null;

    /**
     * Is JS
     * @var mixed|null
     */
    public $js_disabled = null;

    /**
     * Sms check
     * @var mixed|null
     */
    public $sms_allow = null;

    /**
     * Sms code result
     * @var mixed|null
     */
    public $sms = null;

    /**
     * Sms error code
     * @var mixed|null
     */
    public $sms_error_code = null;

    /**
     * Sms error code
     * @var mixed|null
     */
    public $sms_error_text = null;

    /**
     * Stop queue message, 1|0
     * @var int|null
     */
    public $stop_queue = null;

    /**
     * Account shuld by deactivated after registration, 1|0
     * @var int|null
     */
    public $inactive = null;

    /**
     * Account status
     * @var int
     */
    public $account_status = -1;

    /**
     * Create server response
     *
     * @param array<string, mixed>|null $response
     * @param object|null $obj
     */
    public function __construct($response = null, $obj = null)
    {
        if (is_array($response) && $response !== array()) {
            foreach ($response as $param => $value) {
                $this->{$param} = $value;
            }
        } elseif (is_object($obj)) {
            $this->errno = $obj->errno;
            $this->errstr = $obj->errstr;
            $this->curl_err = !empty($obj->curl_err) ? $obj->curl_err : false;

            if (is_string($this->errstr)) {
                $this->errstr = preg_replace("/.+(\*\*\*.+\*\*\*).+/", "$1", $this->errstr);
            }

            $this->stop_words = isset($obj->stop_words) && is_string($obj->stop_words) ? utf8_decode($obj->stop_words) : null;
            $this->comment = isset($obj->comment) && is_string($obj->comment) ? utf8_decode($obj->comment) : null;
            $this->blacklisted = (isset($obj->blacklisted)) ? $obj->blacklisted : null;
            $this->allow = (isset($obj->allow)) ? $obj->allow : 0;
            $this->id = (isset($obj->id)) ? $obj->id : null;
            $this->fast_submit = (isset($obj->fast_submit)) ? $obj->fast_submit : 0;
            $this->spam = (isset($obj->spam)) ? $obj->spam : 0;
            $this->js_disabled = (isset($obj->js_disabled)) ? $obj->js_disabled : 0;
            $this->sms_allow = (isset($obj->sms_allow)) ? $obj->sms_allow : null;
            $this->sms = (isset($obj->sms)) ? $obj->sms : null;
            $this->sms_error_code = (isset($obj->sms_error_code)) ? $obj->sms_error_code : null;
            $this->sms_error_text = (isset($obj->sms_error_text)) ? $obj->sms_error_text : null;
            $this->stop_queue = (isset($obj->stop_queue)) ? $obj->stop_queue : 0;
            $this->inactive = (isset($obj->inactive)) ? $obj->inactive : 0;
            $this->account_status = (isset($obj->account_status)) ? $obj->account_status : -1;
            $this->received = (isset($obj->received)) ? $obj->received : -1;

            if ($this->errno !== 0 && $this->errstr !== null && $this->comment === null) {
                $this->comment = $this->errstr;
            }
        } else {
            $this->errno = 1;
            $this->errstr = 'Empty response';
        }
    }
}
