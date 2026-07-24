<?php

namespace RemoteCalls;

use Cleantalk\Common\RemoteCalls\RemoteCalls;
use PHPUnit\Framework\TestCase;

class RemoteCallsGetSiteUrlTest extends TestCase
{
    private $server_backup = [];

    public function setUp(): void
    {
        $this->server_backup = $_SERVER;
    }

    public function tearDown(): void
    {
        $_SERVER = $this->server_backup;
    }

    public function testGetSiteUrlSanitizesScriptUrl()
    {
        $_SERVER['HTTPS'] = 'on';
        $_SERVER['HTTP_HOST'] = 'example.com';
        $_SERVER['SCRIPT_URL'] = '/<img src=x onerror=alert(1)>';

        $result = RemoteCalls::getSiteUrl();

        self::assertSame('https://example.com/imgsrcxonerroralert1', $result);
        self::assertStringNotContainsString('<', $result);
        self::assertStringNotContainsString('>', $result);
        self::assertStringNotContainsString('"', $result);
        self::assertStringNotContainsString("'", $result);
    }

    public function testGetSiteUrlFallsBackToRequestUri()
    {
        unset($_SERVER['SCRIPT_URL']);
        unset($_SERVER['HTTPS']);
        $_SERVER['HTTP_HOST'] = 'example.com';
        $_SERVER['REQUEST_URI'] = '/path/to/page?x=<script>alert(1)</script>';

        $result = RemoteCalls::getSiteUrl();

        self::assertSame('http://example.com/path/to/page', $result);
    }

    public function testGetSiteUrlPreservesEncodedPathFromScriptUrl()
    {
        $_SERVER['HTTP_HOST'] = 'example.com';
        $_SERVER['SCRIPT_URL'] = '/a%20b/c%2fd';

        $result = RemoteCalls::getSiteUrl();

        self::assertSame('http://example.com/a%20b/c%2Fd', $result);
    }

    public function testGetSiteUrlRemovesInvalidPercentFromRequestUri()
    {
        unset($_SERVER['SCRIPT_URL']);
        $_SERVER['HTTP_HOST'] = 'example.com';
        $_SERVER['REQUEST_URI'] = '/a%2gb%zz';

        $result = RemoteCalls::getSiteUrl();

        self::assertSame('http://example.com/a2gbzz', $result);
    }
}
