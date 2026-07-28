<?php

declare(strict_types=1);

defined('ABSPATH') || exit;

final class LykanShield_Domain_Resolver
{
    /**
     * @return array{
     *     home_host:string,
     *     site_host:string,
     *     request_host:string,
     *     canonical_host:string,
     *     registrable_domain:string,
     *     host_header_matches:bool,
     *     warnings:string[]
     * }
     */
    public static function current(): array
    {
        return self::resolve(
            (string) home_url(),
            (string) site_url(),
            isset($_SERVER['HTTP_HOST']) ? (string) wp_unslash($_SERVER['HTTP_HOST']) : ''
        );
    }

    /**
     * @return array{
     *     home_host:string,
     *     site_host:string,
     *     request_host:string,
     *     canonical_host:string,
     *     registrable_domain:string,
     *     host_header_matches:bool,
     *     warnings:string[]
     * }
     */
    public static function resolve(string $homeUrl, string $siteUrl, string $requestHost = ''): array
    {
        $homeHost = self::host_from_url($homeUrl);
        $siteHost = self::host_from_url($siteUrl);
        $requestHost = self::normalize_host($requestHost);
        $canonicalHost = $homeHost !== '' ? $homeHost : $siteHost;
        $warnings = [];

        if ($canonicalHost === '') {
            $warnings[] = 'No canonical WordPress host could be determined from home_url() or site_url().';
        }

        if ($homeHost !== '' && $siteHost !== '' && $homeHost !== $siteHost) {
            $warnings[] = 'home_url() and site_url() use different hosts.';
        }

        $registrableDomain = $canonicalHost !== '' ? self::registrable_domain($canonicalHost) : '';
        $requestRegistrableDomain = $requestHost !== '' ? self::registrable_domain($requestHost) : '';
        $hostHeaderMatches = $requestHost === ''
            || $requestHost === $canonicalHost
            || ($registrableDomain !== '' && $requestRegistrableDomain === $registrableDomain);

        if (!$hostHeaderMatches) {
            $warnings[] = 'The current Host header does not match the canonical WordPress domain.';
        }

        return [
            'home_host' => $homeHost,
            'site_host' => $siteHost,
            'request_host' => $requestHost,
            'canonical_host' => $canonicalHost,
            'registrable_domain' => $registrableDomain,
            'host_header_matches' => $hostHeaderMatches,
            'warnings' => $warnings,
        ];
    }

    public static function host_from_url(string $url): string
    {
        $url = trim($url);

        if ($url === '') {
            return '';
        }

        $host = wp_parse_url($url, PHP_URL_HOST);

        if (!is_string($host) || $host === '') {
            $host = wp_parse_url('//' . $url, PHP_URL_HOST);
        }

        return is_string($host) ? self::normalize_host($host) : '';
    }

    public static function normalize_host(string $host): string
    {
        $host = trim(str_replace(["\r", "\n", "\0"], '', $host));
        $parsedHost = wp_parse_url('//' . $host, PHP_URL_HOST);

        if (is_string($parsedHost) && $parsedHost !== '') {
            $host = $parsedHost;
        }

        $host = trim(strtolower($host), "[] \t\n\r\0\x0B.");

        if ($host === '') {
            return '';
        }

        if (function_exists('idn_to_ascii') && !filter_var($host, FILTER_VALIDATE_IP)) {
            $variant = defined('INTL_IDNA_VARIANT_UTS46') ? INTL_IDNA_VARIANT_UTS46 : 0;
            $ascii = @idn_to_ascii($host, IDNA_DEFAULT, $variant);

            if (is_string($ascii) && $ascii !== '') {
                $host = strtolower($ascii);
            }
        }

        $host = preg_replace('/[^a-z0-9:.-]+/', '-', $host);
        $host = preg_replace('/\.{2,}/', '.', (string) $host);
        $host = trim((string) $host, '.-');

        return substr($host, 0, 253);
    }

    public static function registrable_domain(string $host): string
    {
        $host = self::normalize_host($host);

        if ($host === '' || filter_var($host, FILTER_VALIDATE_IP)) {
            return $host;
        }

        $labels = explode('.', $host);

        if (count($labels) <= 2) {
            return $host;
        }

        $suffix = self::matching_public_suffix($labels);
        $suffixLabelCount = substr_count($suffix, '.') + 1;
        $registrableLabelCount = min(count($labels), $suffixLabelCount + 1);

        return implode('.', array_slice($labels, -$registrableLabelCount));
    }

    /**
     * @param string[] $labels
     */
    private static function matching_public_suffix(array $labels): string
    {
        $suffixes = self::public_suffixes();
        $best = end($labels);

        for ($offset = 0; $offset < count($labels); $offset++) {
            $candidate = implode('.', array_slice($labels, $offset));

            if (isset($suffixes[$candidate])) {
                $best = $candidate;
                continue;
            }

            $wildcard = '*.' . implode('.', array_slice($labels, $offset + 1));

            if (isset($suffixes[$wildcard])) {
                $best = $candidate;
            }
        }

        return is_string($best) ? $best : '';
    }

    /**
     * @return array<string,true>
     */
    private static function public_suffixes(): array
    {
        $suffixes = [
            'com' => true,
            'net' => true,
            'org' => true,
            'de' => true,
            'at' => true,
            'ch' => true,
            'fr' => true,
            'it' => true,
            'nl' => true,
            'es' => true,
            'eu' => true,
            'co.uk' => true,
            'org.uk' => true,
            'ac.uk' => true,
            'com.au' => true,
            'net.au' => true,
            'org.au' => true,
            'co.nz' => true,
            'com.br' => true,
            'com.tr' => true,
            'co.jp' => true,
            'ne.jp' => true,
            'com.cn' => true,
            'com.pl' => true,
            'github.io' => true,
            'wordpress.com' => true,
        ];

        /**
         * Allows replacing or extending the bundled Public Suffix fallback list.
         *
         * @param array<string,true> $suffixes Public suffixes keyed by suffix.
         */
        $filtered = apply_filters('lykanshield_public_suffixes', $suffixes);

        return is_array($filtered) ? array_fill_keys(array_map('strval', array_keys($filtered)), true) : $suffixes;
    }
}
