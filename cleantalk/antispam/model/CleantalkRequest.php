<?php

/**
 * Cleantalk Base class
 * Compatible only with phpBB 3.1+
 * @version 2.3-phpbb
 * @subpackage Request
 * @author Cleantalk team (welcome@cleantalk.org)
 * @copyright (C) 2014 CleanTalk team (https://cleantalk.org)
 * @license GNU/GPL: http://www.gnu.org/copyleft/gpl.html
 * @see https://github.com/CleanTalk/php-antispam
 *
 */

namespace cleantalk\antispam\model;

/**
 * @psalm-suppress PossiblyUnusedProperty Properties are consumed dynamically by the API serializer.
 */
class CleantalkRequest
{
     /**
     *  All http request headers
     * @var string|null
     */
     public $all_headers = null;

     /**
     *  IP address of connection
     * @var string
     */
     //public $remote_addr = null;

     /**
     *  Last error number
     * @var integer|null
     */
     public $last_error_no = null;

     /**
     *  Last error time
     * @var integer|null
     */
     public $last_error_time = null;

     /**
     *  Last error text
     * @var string|null
     */
     public $last_error_text = null;

    /**
     * User message
     * @var string|null
     */
    public $message = null;

    /**
     * Post example with last comments
     * @var string|null
     */
    public $example = null;

    /**
     * Auth key
     * @var string|null
     */
    public $auth_key = null;

    /**
     * Engine
     * @var string|null
     */
    public $agent = null;

    /**
     * Is check for stoplist,
     * valid are 0|1
     * @var int|null
     */
    public $stoplist_check = null;

    /**
     * Language server response,
     * valid are 'en' or 'ru'
     * @var string|null
     */
    public $response_lang = null;

    /**
     * User IP
     * @var string|null
     */
    public $sender_ip = null;

    /**
     * User email
     * @var string|null
     */
    public $sender_email = null;

    /**
     * User nickname
     * @var string|null
     */
    public $sender_nickname = null;

    /**
     * Sender info JSON string
     * @var string|null
     */
    public $sender_info = null;

    /**
     * Post info JSON string
     * @var string|null
     */
    public $post_info = null;

    /**
     * Is allow links, email and icq,
     * valid are 1|0
     * @var int|null
     */
    public $allow_links = null;

    /**
     * Time form filling
     * @var int|null
     */
    public $submit_time = null;

    /** @var string */
    public $x_forwarded_for = '';
    /** @var string */
    public $x_real_ip = '';

    /**
     * Is enable Java Script,
     * valid are 0|1|2
     * Status:
     *  null - JS html code not inserted into phpBB templates
     *  0 - JS disabled at the client browser
     *  1 - JS enabled at the client broswer
     * @var int|null
     */
    public $js_on = null;

    /**
     * user time zone
     * @var string|null
     */
    public $tz = null;

    /**
     * Feedback string,
     * valid are 'requset_id:(1|0)'
     * @var string|null
     */
    public $feedback = null;

    /**
     * Phone number
     * @var mixed
     */
    public $phone = null;

    /**
     * Bot detector event token
     * @var string|null
     */
    public $event_token = null;

    /**
    * Method name
    * @var string
    */
    public $method_name = 'check_message';

    /**
     * Fill params with constructor
     * @param array<string, mixed>|null $params
     * @psalm-suppress PossiblyUnusedMethod Constructor is used through extension callbacks.
     */
    public function __construct($params = null)
    {
        if (is_array($params) && count($params) > 0) {
            foreach ($params as $param => $value) {
                $this->{$param} = $value;
            }
        }
    }
}
