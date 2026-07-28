# LykanShield License Server API

API version: `2026-07-27`

The license API only unlocks Premium analytics and automation. Core protection must remain fully active when the license server is unavailable, slow, invalid, or unreachable.

## Transport

- Base URL: `https://license.lykanshield.com/v1`
- Protocol: HTTPS only
- Request body: JSON
- Response body: JSON
- Request header: `X-LykanShield-API-Version: 2026-07-27`
- Timeout: 5 seconds
- Maximum response size: 65,536 bytes
- Frontend requests must not call this API synchronously.

## Endpoints

| Operation | Method | Path |
|---|---|---|
| Activate Premium | `POST` | `/licenses/activate` |
| Renew offline token | `POST` | `/licenses/renew` |
| Read status | `POST` | `/licenses/status` |
| Deactivate installation | `POST` | `/licenses/deactivate` |

## Activation Request

```json
{
  "api_version": "2026-07-27",
  "license_key": "LS-...",
  "canonical_domain": "www.example.de",
  "registrable_domain": "example.de",
  "installation_id": "d7069da643cc1e7df09a348cf697be15",
  "plugin_version": "0.1.0",
  "wordpress_version": "6.6",
  "php_version": "8.2.0"
}
```

The plugin must redact `license_key` before logging payloads, errors, or diagnostics.

## Successful Response

```json
{
  "api_version": "2026-07-27",
  "status": "premium",
  "licensed_domain": "example.de",
  "installation_id": "d7069da643cc1e7df09a348cf697be15",
  "token": "base64url(header).base64url(payload).base64url(signature)",
  "rate_limits": {
    "rest_api_daily": 10000
  }
}
```

`token` is the signed offline license token verified locally by the plugin.

## Offline Token

Token format:

```text
base64url(header).base64url(payload).base64url(signature)
```

Header:

```json
{
  "alg": "Ed25519",
  "typ": 1
}
```

Payload:

```json
{
  "token_version": 1,
  "license_id": "lic_...",
  "canonical_domain": "www.example.de",
  "installation_id": "d7069da643cc1e7df09a348cf697be15",
  "tier": "premium",
  "features": ["analytics", "exports", "webhooks", "reports"],
  "licensed_domain": "example.de",
  "issued_at": 1785168000,
  "expires_at": 1816704000,
  "grace_until": 1817312400,
  "status": "active"
}
```

The server signs `base64url(header) + "." + base64url(payload)` with Ed25519. The plugin stores only the public verification key. The private signing key must stay on the license server.

## Error Response

```json
{
  "api_version": "2026-07-27",
  "error": {
    "code": "license_domain_mismatch",
    "message": "The license is not valid for this domain."
  }
}
```

Defined error codes:

- `license_invalid`
- `license_expired`
- `license_revoked`
- `license_already_used`
- `license_domain_mismatch`
- `rate_limited`
- `server_unavailable`

Error messages must not include full license keys.

## Server Rules

- Free works without a license key and without activation.
- Premium applies to exactly one registrable main domain and its subdomains.
- `www.example.de`, `shop.example.de`, and `api.example.de` belong to `example.de`.
- `example.com` requires a separate Premium license.
- The server must enforce Premium limits for REST API usage, history, exports, webhooks, and reports.
- Activation attempts are rate-limited to 5 attempts per installation and domain per 15 minutes.
- Domain changes and deactivations are stored in an append-only audit trail.
- The private signing key never leaves the license server.
