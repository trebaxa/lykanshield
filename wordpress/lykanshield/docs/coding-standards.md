# Coding Standards

LykanShield targets PHP 8.2 or newer and WordPress 6.4 or newer.

## Required Checks

- PHP syntax check for all `*.php` files.
- WordPress Coding Standards with PHP_CodeSniffer when available.
- Smoke tests in `tests/`.

Recommended command when WPCS is installed:

```powershell
phpcs --standard=WordPress wordpress\lykanshield
```

The current repository does not vendor PHP_CodeSniffer or WordPress Coding Standards. Do not mark WPCS as passed unless that external toolchain has actually run.
