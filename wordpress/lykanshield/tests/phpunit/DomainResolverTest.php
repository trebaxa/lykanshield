<?php

declare(strict_types=1);

use PHPUnit\Framework\TestCase;

final class DomainResolverTest extends TestCase
{
    protected function setUp(): void
    {
        lykanshield_test_reset();
    }

    public function testNormalizesWwwPortsSubdomainsAndPublicSuffixes(): void
    {
        $cases = [
            ['https://www.example.de', 'https://example.de/wp', 'shop.example.de', 'example.de', true],
            ['https://shop.example.de:8443', 'https://example.de', 'api.example.de', 'example.de', true],
            ['https://blog.example.co.uk', 'https://example.co.uk', 'www.example.co.uk', 'example.co.uk', true],
            ['https://example.com.', 'https://example.com', 'example.com:443', 'example.com', true],
            ['https://xn--bcher-kva.example', 'https://xn--bcher-kva.example/wp', 'xn--bcher-kva.example', 'xn--bcher-kva.example', true],
        ];

        foreach ($cases as [$homeUrl, $siteUrl, $requestHost, $expectedDomain, $expectedHostMatch]) {
            $context = LykanShield_Domain_Resolver::resolve($homeUrl, $siteUrl, $requestHost);

            self::assertSame($expectedDomain, $context['registrable_domain']);
            self::assertSame($expectedHostMatch, $context['host_header_matches']);
        }
    }

    public function testHostHeaderMismatchDoesNotChangeCanonicalLicenseDomain(): void
    {
        $context = LykanShield_Domain_Resolver::resolve(
            'https://www.example.de',
            'https://example.de/wp',
            'attacker.example.com'
        );

        self::assertSame('example.de', $context['registrable_domain']);
        self::assertFalse($context['host_header_matches']);
        self::assertNotEmpty($context['warnings']);
    }
}
