# LykanShield WordPress Test Matrix

This matrix defines the required automated test coverage before a public plugin release.

## Runtime matrix

| Layer | Required coverage |
|---|---|
| PHP | 8.2, 8.3, 8.4 |
| WordPress | 6.4, 6.5, 6.6, latest stable |
| Server mode | Apache + mod_php/FPM, Nginx + PHP-FPM, WP-CLI |
| WordPress mode | Single site, multisite subdomain, multisite mapped domains |

## Local smoke tests

Run from the repository root:

```bash
php wordpress/lykanshield/tests/run-smoke-tests.php
```

The smoke suite covers:

- canonical domain normalization for `www.`, ports, subdomains and selected public suffix rules;
- Premium entitlement sharing for subdomains and separation for unrelated main domains;
- Free fallback with protection still enabled;
- expired and suspended Premium fallback behavior;
- valid and manipulated offline license tokens when Sodium signing is available;
- core configuration mapping and atomic config writes;
- multisite license scope mapping and domain-change detection.

## PHPUnit

The plugin ships a minimal PHPUnit configuration in `phpunit.xml.dist`.

```bash
cd wordpress/lykanshield
vendor/bin/phpunit
```

The PHPUnit suite is intentionally small until the plugin is wired into a full WordPress test harness. It mirrors critical pure-PHP behavior that can run without a database-backed WordPress install.

## WordPress integration tests to run in CI

- activation and deactivation hooks create/remove the managed MU-loader and cron events;
- activation fails cleanly below PHP 8.2 or below the supported WordPress version;
- MU-loader install path works when `wp-content/mu-plugins` exists, is missing, is writable and is not writable;
- settings actions enforce `manage_options` and valid nonces;
- no frontend request performs a synchronous license-server call;
- license-server outage, timeout, invalid JSON and HTTP error responses fall back to Free without disabling protection;
- tariff limits are enforced for local history, exports, REST API quotas, reports, allow/block lists and webhook access;
- multisite network activation stores Premium tokens per registrable main domain and never shares Premium across unrelated domains.
