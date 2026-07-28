# LykanShield Privacy Notes

LykanShield processes security data to provide request filtering, local logging, license validation and security analytics.

## Data processed locally

- Canonical WordPress domain and registrable main domain.
- Security event timestamps.
- Source IP addresses or CIDR entries.
- Attack type and approximate request bucket information.
- Local allow/block list entries.
- Plugin configuration and installation ID.
- Locally stored signed license token.

The plugin must not store full passwords, cookies, authorization headers, private keys or complete sensitive request payloads in local logs.

## Data sent to the license server

License activation and renewal may send:

- License key during activation or deactivation.
- Canonical domain and licensed main domain.
- Random installation ID.
- Plugin version.
- WordPress version.
- PHP version.
- Token renewal metadata and request nonce.

License keys must be redacted from logs and browser output.

## Data sent for Premium analytics

Premium analytics, exports, webhooks and automated reports may use security event metadata needed for the selected feature. The license server must enforce tariff limits for history, REST API usage, exports, webhooks and reports.

## Retention

Free keeps local logs for 30 days. Premium keeps local logs for 13 months. Central statistics are limited to 24 hours in Free and 365 days in Premium.
