<?php

declare(strict_types=1);

define('ABSPATH', __DIR__);

function wp_parse_url(string $url, int $component = -1): mixed
{
    return parse_url($url, $component);
}

function apply_filters(string $hook, mixed $value): mixed
{
    return $value;
}

require_once __DIR__ . '/../includes/class-domain-resolver.php';

$cases = [
    ['https://www.example.de', 'https://example.de/wp', 'shop.example.de', 'example.de', true],
    ['https://shop.example.de:8443', 'https://example.de', 'api.example.de', 'example.de', true],
    ['https://blog.example.co.uk', 'https://example.co.uk', 'www.example.co.uk', 'example.co.uk', true],
    ['https://example.com', 'https://example.com', 'example.net', 'example.com', false],
    ['https://example.com.', 'https://example.com', 'example.com:443', 'example.com', true],
];

if (function_exists('idn_to_ascii')) {
    $idnHomeUrl = "https://www.b\xC3\xBCcher.example";
    $cases[] = [$idnHomeUrl, 'https://xn--bcher-kva.example', 'shop.xn--bcher-kva.example', 'xn--bcher-kva.example', true];
}

foreach ($cases as [$homeUrl, $siteUrl, $requestHost, $expectedDomain, $expectedMatch]) {
    $context = LykanShield_Domain_Resolver::resolve($homeUrl, $siteUrl, $requestHost);

    if ($context['registrable_domain'] !== $expectedDomain) {
        fwrite(STDERR, sprintf(
            "Expected %s for %s, got %s\n",
            $expectedDomain,
            $homeUrl,
            $context['registrable_domain']
        ));
        exit(1);
    }

    if ($context['host_header_matches'] !== $expectedMatch) {
        fwrite(STDERR, sprintf(
            "Expected host_header_matches=%s for %s, got %s\n",
            $expectedMatch ? 'true' : 'false',
            $requestHost,
            $context['host_header_matches'] ? 'true' : 'false'
        ));
        exit(1);
    }
}

echo "Domain resolver smoke tests passed.\n";
