<?php

namespace RemoteCalls;

use Cleantalk\Common\RemoteCalls\Exceptions\RemoteCallsException;
use Cleantalk\Common\RemoteCalls\RemoteCalls;
use Cleantalk\Common\Variables\Request;
use PHPUnit\Framework\TestCase;

class RemoteCallsTestWrongRequest extends TestCase
{
    public function setUp(): void
    {
        /** @var \Cleantalk\Common\StorageHandler\StorageHandler $storage_handler */
        $storage_handler = $this->generateStorageHandlerMockObject();
        $api_key = getenv("CLEANTALK_TEST_API_KEY");
        $this->rc = new RemoteCalls($api_key, $storage_handler);
        $request_class = Request::getInstance();
        $request_class->variables['spbc_remote_call_token'] = 'O_o';
    }

    public function testCheckRemoteCallsFailed()
    {
        self::assertFalse($this->rc::check());
    }

    public function testNoAvailableRemoteCalls()
    {
        $this->expectException(RemoteCallsException::class);
        $this->rc->process();
    }

    private function generateStorageHandlerMockObject()
    {
        $mock = $this->createMock('\Cleantalk\Common\StorageHandler\StorageHandler');
        $mock->method('getSetting')->willReturn(false);
        return $mock;
    }

    public function tearDown(): void
    {
        Request::resetInstance();
    }
}

