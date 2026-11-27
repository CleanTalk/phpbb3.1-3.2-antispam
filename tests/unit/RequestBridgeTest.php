<?php

require_once __DIR__ . '/fixtures/phpbb.inc';

use cleantalk\antispam\model\RequestBridge;
use Cleantalk\Common\Mloader\Mloader;
use Cleantalk\Common\Variables\Cookie;
use Cleantalk\Common\Variables\Get;
use Cleantalk\Common\Variables\Request;
use Cleantalk\Common\Variables\Server;
use phpbb\request\request as phpbb_request;
use phpbb\request\request_interface;
use PHPUnit\Framework\TestCase;

/**
 * Replacement phpBB puts into the superglobals: any read is fatal.
 */
class DeactivatedSuperGlobal implements ArrayAccess, IteratorAggregate, Countable
{
    private $name;

    public function __construct($name)
    {
        $this->name = $name;
    }

    public function offsetExists($offset)
    {
        return true;
    }

    public function offsetGet($offset)
    {
        throw new LogicException('Illegal use of $' . $this->name);
    }

    public function offsetSet($offset, $value)
    {
        throw new LogicException('Illegal use of $' . $this->name);
    }

    public function offsetUnset($offset)
    {
        throw new LogicException('Illegal use of $' . $this->name);
    }

    public function getIterator()
    {
        throw new LogicException('Illegal use of $' . $this->name);
    }

    public function count()
    {
        throw new LogicException('Illegal use of $' . $this->name);
    }
}

class RequestBridgeTest extends TestCase
{
    private $super_globals = array();

    protected function setUp(): void
    {
        foreach (array('_SERVER', '_GET', '_POST', '_COOKIE', '_REQUEST') as $name) {
            $this->super_globals[$name] = $GLOBALS[$name];
            $GLOBALS[$name] = new DeactivatedSuperGlobal($name);
        }
        \Cleantalk\Common\Helper\Helper::resetInstance();
    }

    protected function tearDown(): void
    {
        foreach ($this->super_globals as $name => $value) {
            $GLOBALS[$name] = $value;
        }
    }

    private function init(array $input)
    {
        RequestBridge::init(new phpbb_request($input));
    }

    public function test_common_readers_use_phpbb_request_data()
    {
        $this->init(array(
            request_interface::SERVER => array(
                'REMOTE_ADDR'     => '203.0.113.5',
                'REQUEST_METHOD'  => 'post',
                'HTTP_USER_AGENT' => 'Bot <script>',
            ),
            request_interface::GET    => array('sfw_test_ip' => '192.0.2.1'),
            request_interface::POST   => array('metadata' => array('network' => '192.0.2.0')),
            request_interface::COOKIE => array('ct_sfw_pass_key' => 'abc'),
        ));

        $this->assertSame('203.0.113.5', Server::get('REMOTE_ADDR'));
        $this->assertSame('POST', Server::get('REQUEST_METHOD'));
        $this->assertSame('Bot &lt;script&gt;', Server::get('HTTP_USER_AGENT'));
        $this->assertSame('192.0.2.1', Get::get('sfw_test_ip'));
        $this->assertSame('abc', Cookie::get('ct_sfw_pass_key'));
        $this->assertSame(array('network' => '192.0.2.0'), Request::get('metadata'));
        $this->assertSame('', Get::get('missing'));
    }

    public function test_init_drops_values_of_previous_request()
    {
        $this->init(array(request_interface::SERVER => array('REMOTE_ADDR' => '203.0.113.5')));
        Server::get('REMOTE_ADDR');

        $this->init(array(request_interface::SERVER => array('REMOTE_ADDR' => '203.0.113.6')));

        $this->assertSame('203.0.113.6', Server::get('REMOTE_ADDR'));
    }

    public function test_ip_detection_reads_headers_from_phpbb_request()
    {
        $this->init(array(request_interface::SERVER => array(
            'REMOTE_ADDR'          => '10.0.0.1',
            'HTTP_X_FORWARDED_FOR' => '198.51.100.7, 10.0.0.1',
        )));

        $helper = Mloader::get('Helper');

        $this->assertSame('198.51.100.7', $helper::ipGet('real'));
    }

    public function test_common_helper_headers_come_from_phpbb_request()
    {
        $this->init(array(request_interface::SERVER => array(
            'HTTP_X_REAL_IP' => '198.51.100.8',
        )));

        // SpamFireWall debug page calls the Common helper directly, bypassing Mloader
        $this->assertSame(
            array('X-Real-Ip' => '198.51.100.8'),
            \Cleantalk\Common\Helper\Helper::httpGetHeaders()
        );
    }

    public function test_remote_calls_site_url_uses_phpbb_request_data()
    {
        $this->init(array(request_interface::SERVER => array(
            'HTTPS'     => 'on',
            'HTTP_HOST' => 'forum.example.com<script>',
        )));

        $rc_class = Mloader::get('RemoteCalls');

        $this->assertSame('https://forum.example.comscript/', $rc_class::getSiteUrl());
    }
}
