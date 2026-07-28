# LykanShield Troubleshooting

## MU-loader cannot be installed

LykanShield installs a small loader in `/wp-content/mu-plugins/` so protection can start before normal plugins. If WordPress cannot write to that directory:

1. Create `/wp-content/mu-plugins/` if it does not exist.
2. Copy `mu-loader/lykanshield-loader.php` to `/wp-content/mu-plugins/lykanshield-loader.php`.
3. Reload Settings > LykanShield and check the MU-loader status.

The loader exits when the main plugin or bundled core file is missing.

## Required PHP features

LykanShield requires PHP 8.2 or newer. Ed25519 token verification requires the Sodium extension in production. The plugin has fallbacks for selected string handling when `mbstring` is unavailable, but production hosts should still provide `mbstring`.

## DISABLE_WP_CRON is enabled

If `DISABLE_WP_CRON` is enabled, configure a real system cron as described in `docs/system-cron.md`. Otherwise rule refreshes, report processing, license renewal and retention cleanup may run late.

## License activation fails

Check:

- The displayed canonical domain is the domain you want to license.
- The license key was entered without extra spaces.
- The server can perform outbound HTTPS requests.
- The license was issued for the shown registrable main domain.

Never place private keys or license-server secrets in the plugin directory.

## Premium is no longer active

Protection remains active. Expired, revoked or unrenewable Premium entitlement only disables Premium analytics, exports, webhooks, configurable notifications and automated reports for the affected main domain.
