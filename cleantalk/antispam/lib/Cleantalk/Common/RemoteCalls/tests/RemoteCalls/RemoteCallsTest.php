<?php

namespace RemoteCalls;

use Cleantalk\Common\RemoteCalls\RemoteCalls;
use Cleantalk\Common\Variables\Request;
use PHPUnit\Framework\TestCase;

class RemoteCallsTest extends TestCase
{
    public function setUp(): void
    {
        /** @var \Cleantalk\Common\StorageHandler\StorageHandler $storage_handler */
        $storage_handler = $this->generateStorageHandlerMockObject();
        $api_key = getenv("CLEANTALK_TEST_API_KEY");
        $this->rc = new RemoteCalls($api_key, $storage_handler);
        $request_class = Request::getInstance();
        $request_class->variables['spbc_remote_call_token'] = md5($api_key);
        $request_class->variables['spbc_remote_call_action'] = 'sfw_update';
        $request_class->variables['plugin_name'] = 'antispam';
    }

    public function testCheckRemoteCalls()
    {
        self::assertTrue($this->rc::check());
    }

    private function generateStorageHandlerMockObject()
    {
        $mock = $this->createMock('\Cleantalk\Common\StorageHandler\StorageHandler');
        $mock->method('getSetting')->willReturn(
            [
                'sfw_update' => [
                    'last_call' => 0,
                    'cooldown' => 0
                ],
                'sfw_send_logs' => [
                    'last_call' => 0,
                    'cooldown' => 10
                ]
            ]
        );
        $mock->method('deleteSetting')->willReturn(true);
        return $mock;
    }

    public function tearDown(): void
    {
        Request::resetInstance();
    }
}
