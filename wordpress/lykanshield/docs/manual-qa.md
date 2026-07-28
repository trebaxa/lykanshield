# LykanShield Manual QA Runbook

Use this checklist before publishing a WordPress plugin release. Record the WordPress version, PHP version, web server, SAPI and operating system for every run.

## Required environments

- Fresh single-site WordPress installation.
- Existing WordPress installation with a previous LykanShield version.
- Apache hosting.
- Nginx hosting.
- PHP-FPM.
- Shared hosting or local simulation where `wp-content/mu-plugins` is not writable.
- WordPress Multisite with at least two mapped main domains and one subdomain site.
- Environment without `mbstring`, if supported by the PHP build.

## Installation and lifecycle

- Install LykanShield from a plugin ZIP on a fresh WordPress instance.
- Activate the plugin and confirm no PHP warnings are emitted.
- Confirm the settings page appears for administrators only.
- Confirm the canonical domain matches `home_url()` / `site_url()` and ignores hostile `Host` headers.
- Confirm the MU-loader is installed when `wp-content/mu-plugins` is writable.
- Confirm the admin page shows a manual installation instruction when the MU-loader directory is not writable.
- Deactivate and reactivate the plugin.
- Confirm scheduled LykanShield cron events are removed on deactivation and recreated on activation.
- Uninstall once with data retention enabled.
- Uninstall once with data deletion enabled.

## Upgrade

- Upgrade from the previous plugin ZIP to the new ZIP.
- Confirm stored options migrate without losing installation ID, license token or safe defaults.
- Confirm an installed MU-loader still points to the active plugin path.
- Confirm old cron schedules are replaced by the current schedule.

## Protection traffic

- Test normal homepage, admin, login, REST API and WP-Cron requests.
- Test WooCommerce cart, checkout and account flows when WooCommerce is installed.
- Confirm common legitimate form submissions do not trigger false positives.
- Confirm obvious SQL injection, XSS and exploit probes are blocked or logged according to configuration.
- Confirm suspicious upload and MIME mismatch cases are handled.

## License behavior

- Run Free without a license key and confirm all protection filters remain active.
- Activate Premium for the canonical main domain.
- Confirm `www` and subdomains of the same main domain receive Premium entitlement.
- Confirm another main domain does not receive Premium entitlement from the first domain token.
- Simulate expired, revoked, malformed and wrong-domain tokens.
- Confirm expired or invalid Premium only disables Premium analytics and automation.
- Simulate license server timeout and slow responses.
- Confirm frontend requests do not perform synchronous license-server calls.

## Cron and outage handling

- Run with normal WordPress cron.
- Run with `DISABLE_WP_CRON` and a real system cron.
- Simulate rule server outage.
- Confirm rule refresh failures use backoff and do not block requests.
- Confirm daily summaries, report queue flushing and retention cleanup run once per interval.

## Multisite

- Network-activate LykanShield.
- Confirm only Super Admins can change network-level configuration.
- Confirm individual site admins cannot bypass domain licensing.
- Confirm subdirectory Multisite does not require duplicate Premium licenses for the same main domain.
- Confirm subdomain Multisite on the same main domain shares Premium entitlement.
- Confirm mapped domains on different main domains require separate Premium licenses or run as Free.

## Release sign-off

- Attach automated test output.
- Attach manual QA notes for every environment.
- Attach the generated plugin ZIP checksum.
- Confirm no private keys, real license keys, production logs or internal credentials are included.
