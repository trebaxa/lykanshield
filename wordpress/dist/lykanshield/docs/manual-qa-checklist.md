# Manual QA Checklist

Use this checklist before publishing a LykanShield WordPress release. Record the WordPress version, PHP version, hosting stack and result for every run.

## Installation and lifecycle

- Install the plugin on a fresh single-site WordPress instance.
- Activate the plugin and confirm the settings page loads for administrators only.
- Confirm `wp-content/mu-plugins/lykanshield-loader.php` is installed when the directory is writable.
- Confirm the dashboard reports the canonical main domain, request host and MU-loader state.
- Deactivate and reactivate the plugin. Confirm options persist, cron events are rescheduled and the managed MU-loader is restored.
- Upgrade from the previous plugin build by replacing the normal plugin directory. Confirm the MU-loader points to the new plugin path.
- Uninstall with local data retained. Confirm options needed for retained data remain and no cron events are left behind.
- Uninstall with local data deletion enabled. Confirm plugin options, local LykanShield data and the managed MU-loader are removed.

## Hosting stacks

- Test Apache with common shared-hosting defaults.
- Test Nginx with PHP-FPM.
- Test PHP-FPM after-response behavior for non-blocking refresh work.
- Test WP-CLI activation, deactivation and cron execution.
- Test a host where `wp-content/mu-plugins` is not writable. Confirm the plugin shows manual installation instructions and does not fail activation fatally.
- Test PHP without `mbstring`. Confirm request filtering, logging and dashboard rendering still work.

## Failure behavior

- Simulate license-server DNS failure, timeout, HTTP 500, HTTP 429 and invalid JSON. Confirm protection remains active and Premium-only features fall back or remain based on the last valid offline token.
- Simulate rule-server outage. Confirm configured unavailable-rule behavior is applied and frontend requests are not blocked by synchronous network calls.
- Confirm slow license responses never delay normal frontend requests.
- Confirm repeated errors are rate-limited in logs and do not fill the webspace.

## WordPress traffic

- Browse public pages, previews, search, feeds and sitemaps.
- Submit login, lost-password and comment forms.
- Run REST API requests as anonymous and authenticated users.
- Run WP-Cron manually and via normal traffic.
- Run WooCommerce cart, checkout, account login and webhook-like callbacks when WooCommerce is installed.
- Confirm no false positives for normal WordPress nonces, admin-ajax requests and block editor saves.

## Multisite and domains

- Test single-site `example.de` with `www.example.de`, `shop.example.de` and `api.example.de` mapped as subdomains.
- Confirm all subdomains share the Premium entitlement for `example.de`.
- Add `example.com` to the same network and confirm it needs its own Premium entitlement.
- Expire the Premium token for one main domain and confirm only that domain falls back to Free.
- Change a site's mapped domain and confirm the dashboard flags the domain change.
