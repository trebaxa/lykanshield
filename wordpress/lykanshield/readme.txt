=== LykanShield ===
Contributors: lykanshield
Tags: security, firewall, xss, sql injection, bot protection
Requires at least: 6.4
Requires PHP: 8.2
Tested up to: 6.6
Stable tag: 0.1.0
License: GPL-3.0-or-later
License URI: https://www.gnu.org/licenses/gpl-3.0.html

Complete WordPress protection with SQL, XSS, exploit, upload, MIME, bad-IP and bot defenses.

== Description ==

LykanShield adds an early WordPress protection layer for SQL injection, XSS, exploit payloads, suspicious uploads, MIME mismatches, bad IPs and hostile bots.

Protection is complete in both Free and Premium. Free does not require a paid license. Premium unlocks longer history, detailed domain analytics, exports, webhooks, configurable notifications and automated reports for one licensed main domain including its subdomains.

= Free and Premium =

* SQL, XSS and exploit protection: complete in Free and Premium.
* Upload and MIME protection: complete in Free and Premium.
* Bad-IP and bot protection: complete in Free and Premium.
* Central protection lists: hourly in Free, every 5 to 15 minutes in Premium.
* Local log retention: 30 days in Free, 13 months in Premium.
* Central statistics: 24 hours in Free, 365 days in Premium.
* Dashboard: basic overview in Free, full domain analysis in Premium.
* Top attackers: Top 10 in Free, Top 100 in Premium.
* Country statistics: basic values in Free, full time-filtered view in Premium.
* Attack types: basic values in Free, trends and filters in Premium.
* IP details: recent events in Free, full available history in Premium.
* REST API: 100 requests daily in Free, 10,000 requests daily in Premium.
* CSV and JSON export: Premium only.
* Email notification: daily summary in Free, instant or configurable in Premium.
* Webhooks: Premium only.
* Custom rules: limited in Free, extended in Premium.
* Allow/block list: up to 100 entries in Free, unlimited in Premium.
* Automated reports: Premium only, daily, weekly or monthly.

= Domain licensing =

Free works without a paid license.

Premium applies to exactly one registrable main domain. For example, `example.de`, `www.example.de`, `shop.example.de` and `api.example.de` belong to one Premium license for `example.de`. `example.com` needs a separate Premium license.

If a Premium license expires, is cancelled or cannot be renewed, only Premium analytics and automation fall back to Free for the affected main domain. Protection remains active.

Multitenancy, custom roles, white label and SLA are not part of the product scope.

= Privacy =

LykanShield can process security events, IP addresses, request metadata, domain information, WordPress/PHP versions and license status data. License checks transmit the canonical domain, installation ID, plugin version, WordPress version and PHP version to the license server. Secrets, passwords, cookies and full payloads must not be logged or transmitted.

== Installation ==

1. Upload the `lykanshield` folder to `/wp-content/plugins/`.
2. Activate LykanShield in the WordPress admin area.
3. Open Settings > LykanShield.
4. Confirm the canonical license domain shown by the plugin.
5. Keep Free active without a license key, or enter a Premium license key for the shown main domain.

On activation, LykanShield tries to install a small MU-plugin loader into `/wp-content/mu-plugins/` so the protection layer starts before normal plugins.

= Manual MU-loader installation =

If WordPress cannot write to `/wp-content/mu-plugins/`, copy `mu-loader/lykanshield-loader.php` to:

`/wp-content/mu-plugins/lykanshield-loader.php`

The loader only starts LykanShield when the main plugin and bundled core file are present. If the normal plugin is deactivated or missing, the loader exits without loading protection code.

= WP-Cron and system cron =

LykanShield uses WordPress cron for rule refreshes, report queue processing, license token renewal, email summaries and retention cleanup. On production sites with `DISABLE_WP_CRON` enabled, configure a real system cron as described in `docs/system-cron.md`.

= Troubleshooting =

If `/wp-content/mu-plugins/` is not writable, install the MU-loader manually as described above. If PHP extensions such as `mbstring` are missing, LykanShield uses compatibility fallbacks; the settings page still reports relevant runtime limitations.

= Release verification =

Development builds include `docs/test-matrix.md`, `docs/manual-qa-checklist.md` and `docs/release.md`. Public ZIP packages should be built reproducibly with `tools/build-release.ps1`, checksummed and signed before distribution.

== Frequently Asked Questions ==

= Does Free include full protection? =

Yes. Free and Premium use the same protection filters. Premium unlocks longer history, richer analysis, exports, webhooks, notifications and reports.

= Does one Premium license cover subdomains? =

Yes. A Premium license covers the licensed registrable main domain and its subdomains. A different main domain needs a separate Premium license.

= What happens if the license server is unavailable? =

Frontend protection does not wait for the license server. The plugin uses a locally verified signed token. If renewal fails, protection remains active and the domain falls back to Free behavior when Premium entitlement is no longer valid.

= Are staging domains included? =

Staging, development and local-domain policy must be defined by the license server. The plugin always derives and displays the canonical domain before activation.

= Does LykanShield support Multisite? =

Yes. Multisite sites on subdomains of the same registrable main domain can share the same Premium entitlement. Sites on other main domains need their own Premium license or run as Free.

== Changelog ==

= 0.1.0 =

* Initial WordPress integration scaffold.
* Early MU-plugin loader.
* Canonical domain resolver.
* Offline signed license-token verification.
* Free/Premium license status handling.
* Settings page, cron hooks, security overview and uninstall flow.
* Test matrix, manual QA checklist and release packaging documentation.

== Upgrade Notice ==

= 0.1.0 =

Initial development release. Verify the canonical domain and MU-loader status after activation.
