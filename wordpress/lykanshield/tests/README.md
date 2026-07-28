# LykanShield WordPress Plugin Tests

## Local checks

Run the lightweight smoke tests without external dependencies:

```bash
composer run test:smoke
```

Run the PHPUnit suite:

```bash
composer install
composer test
```

## Coverage intent

The PHPUnit suite covers the plugin-specific rules that must not regress:

- canonical domain normalization for `www.`, ports, IDN/Punycode, subdomains and selected public suffixes
- entitlement scope: `example.de` and its subdomains share Premium, `example.com` does not
- Free protection remains active without a license
- expired, suspended or unavailable Premium falls back only to Free analytics limits
- valid, expired, tampered, wrong-domain and wrong-installation license tokens
- tariff boundaries for exports, reports, API quota flags and allow/block list limits
- activation, deactivation, MU-loader install conflicts and cron cleanup
- license transport failures without synchronous runtime license calls

The GitHub Actions workflow runs the suite against PHP 8.2, 8.3 and 8.4, and sets `WP_VERSION`
for the supported WordPress matrix.
