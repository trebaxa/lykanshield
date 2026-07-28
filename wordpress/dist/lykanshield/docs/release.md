# Release Preparation

## Public release checklist

- Replace the placeholder Ed25519 public key in `LykanShield_License_Token` with the production public key.
- Run PHP syntax checks for all plugin PHP files.
- Run `php tests/run-smoke-tests.php`.
- Run PHPUnit from `wordpress/lykanshield` when dependencies are installed.
- Run the runtime matrix from `docs/test-matrix.md`.
- Complete the manual QA checklist in `docs/manual-qa-checklist.md`.
- Run WordPress Coding Standards.
- Generate translation template files.
- Build the plugin ZIP with `tools/build-release.ps1`.
- Generate SHA-256 checksums for the ZIP.
- Sign the final ZIP and checksum file with the release signing key.

## Reproducible ZIP

From `wordpress/lykanshield`:

```powershell
.\tools\build-release.ps1
```

The release ZIP excludes tests, local caches, development dependencies and generated release files. The ZIP contains the plugin directory as `lykanshield/`.

## Data handling summary

The plugin stores local settings, local security data, audit events and an offline Premium token. Premium analytics, exports, webhooks and reports can require requests to the LykanShield license/statistics API. The server must enforce all Premium limits; the plugin-side checks are only user-interface and local fallback controls.

Never include private keys, real customer tokens, productive logs, admin credentials or internal server secrets in a public release archive.
