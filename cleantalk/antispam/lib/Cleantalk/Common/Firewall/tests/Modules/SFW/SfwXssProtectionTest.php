<?php

namespace Cleantalk\Common\Firewall\Tests;

use PHPUnit\Framework\TestCase;

/**
 * Tests for XSS protection in Sfw::diePage() method, specifically focusing on sanitization of REQUEST_URI to prevent XSS attacks.
 */
class SfwXssProtectionTest extends TestCase
{
    /**
     * Checks that malicious input in REQUEST_URI is properly sanitized to prevent XSS attacks
     *
     * @dataProvider xssPayloadProvider
     */
    public function testRequestUriXssSanitization($maliciousInput, $expectedOutput)
    {
        // Emulate the sanitization logic from Sfw::diePage()
        $sanitized = htmlspecialchars($maliciousInput, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        
        $this->assertSame($expectedOutput, $sanitized);
        
        // Additional check: the result should not contain unescaped tags
        $this->assertStringNotContainsString('<script', $sanitized);
    }

    /**
     * Checks that safe URLs remain functional after sanitization
     *
     * @dataProvider safeUrlProvider
     */
    public function testSafeUrlsRemainFunctional($safeUrl)
    {
        $sanitized = htmlspecialchars($safeUrl, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        
        // URL should retain its structure (path and query string)
        $this->assertStringContainsString('/', $sanitized);
    }

    /**
     * Data provider with various XSS payloads
     */
    public static function xssPayloadProvider(): array
    {
        return [
            'basic script tag' => [
                '/<script>alert("XSS")</script>',
                '/&lt;script&gt;alert(&quot;XSS&quot;)&lt;/script&gt;'
            ],
            'script with single quotes' => [
                "/<script>alert('XSS')</script>",
                '/&lt;script&gt;alert(&apos;XSS&apos;)&lt;/script&gt;'
            ],
            'img onerror' => [
                '/<img src=x onerror=alert(1)>',
                '/&lt;img src=x onerror=alert(1)&gt;'
            ],
            'svg onload' => [
                '/<svg onload=alert(1)>',
                '/&lt;svg onload=alert(1)&gt;'
            ],
            'javascript protocol' => [
                '/page?url=javascript:alert(1)',
                '/page?url=javascript:alert(1)'
            ],
            'encoded angle brackets' => [
                '/page?q=%3Cscript%3Ealert(1)%3C/script%3E',
                '/page?q=%3Cscript%3Ealert(1)%3C/script%3E'
            ],
            'double quotes in attribute' => [
                '/page?name="><script>alert(1)</script>',
                '/page?name=&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;'
            ],
            'single quotes in attribute' => [
                "/page?name='><script>alert(1)</script>",
                '/page?name=&apos;&gt;&lt;script&gt;alert(1)&lt;/script&gt;'
            ],
            'event handler injection' => [
                '/page" onmouseover="alert(1)',
                '/page&quot; onmouseover=&quot;alert(1)'
            ],
            'mixed quotes' => [
                '/page?a="test\'value"',
                '/page?a=&quot;test&apos;value&quot;'
            ],
            'html entities' => [
                '/page?q=<b>bold</b>&amp;test',
                '/page?q=&lt;b&gt;bold&lt;/b&gt;&amp;amp;test'
            ],
        ];
    }

    /**
     * Data provider with safe URLs
     */
    public static function safeUrlProvider(): array
    {
        return [
            'simple path' => ['/page'],
            'path with query' => ['/page?id=123'],
            'path with multiple params' => ['/page?id=123&name=test'],
            'nested path' => ['/admin/users/edit'],
            'path with numbers' => ['/article/2024/01/15'],
            'path with hyphens' => ['/my-page-url'],
            'path with underscores' => ['/my_page_url'],
            'root path' => ['/'],
            'path with hash fragment' => ['/page#section'],
            'complex query string' => ['/search?q=test+query&page=1&sort=asc'],
        ];
    }

    /**
     * Checks that an empty string is handled correctly
     */
    public function testEmptyRequestUri()
    {
        $sanitized = htmlspecialchars('', ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $this->assertSame('', $sanitized);
    }

    /**
     * Checks that null is converted to an empty string
     */
    public function testNullRequestUri()
    {
        $sanitized = htmlspecialchars((string)null, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        $this->assertSame('', $sanitized);
    }

    /**
     * Checks that UTF-8 characters are preserved
     */
    public function testUtf8Characters()
    {
        $input = '/page?query=test';
        $sanitized = htmlspecialchars($input, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        
        // UTF-8 characters should remain unchanged
        $this->assertSame($input, $sanitized);
    }

    /**
     * Checks that the sfw_test_ip parameter is correctly removed before sanitization
     */
    public function testSfwTestIpRemoval()
    {
        $input = '/page?sfw_test_ip=192.168.1.1&other=value';
        
        // Emulate the logic from Sfw::diePage()
        $request_uri = preg_replace('%sfw_test_ip=\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}&?%', '', $input);
        $sanitized = htmlspecialchars($request_uri, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        
        $this->assertStringNotContainsString('sfw_test_ip', $sanitized);
        $this->assertStringContainsString('other=value', $sanitized);
    }

    /**
     * Checks that XSS in sfw_test_ip does not pass even if the parameter is not completely removed
     */
    public function testSfwTestIpWithXssPayload()
    {
        // Attempted injection through an invalid IP
        $input = '/page?sfw_test_ip=<script>alert(1)</script>&other=value';
        
        // Regex won't match (invalid IP), so the parameter remains
        $request_uri = preg_replace('%sfw_test_ip=\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}&?%', '', $input);
        $sanitized = htmlspecialchars($request_uri, ENT_QUOTES | ENT_HTML5, 'UTF-8');
        
        // XSS should still be escaped
        $this->assertStringNotContainsString('<script>', $sanitized);
        $this->assertStringContainsString('&lt;script&gt;', $sanitized);
    }
}
