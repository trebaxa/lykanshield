# LykanShield

LykanShield is a lightweight request filter for PHP applications. It runs at the
start of a request and can reject suspicious traffic before the application
handles it.

It provides:

- SQL injection, worm and common query-string exploit detection
- blocking of known malicious IP addresses and bots
- local blocking of clients that trigger a rule
- upload filename and server-side MIME-type validation
- automatically refreshed blacklist and detection rules
- local request statistics and security-event logs
- queued security reports that can contribute to the shared LykanShield network

LykanShield works with a generic PHP front controller and automatically selects
suitable data directories for WordPress, TYPO3 and Keimeno installations. It is
a defence-in-depth component, not a replacement for parameterized SQL queries,
output escaping, authentication, authorization, secure upload handling or
regular application updates.

## Requirements

- PHP 8.2 or newer with the cURL, JSON and Fileinfo extensions
- the optional mbstring extension for full Unicode-aware signature matching
- permission for the PHP process to create and write the LykanShield data
  directory
- outbound HTTPS access to `https://www.lykanshield.io/` for rule updates and
  reports

An API key is not required for the request filters. It is only needed for
account-related service and dashboard features.

## Integration

### 1. Add the class

Copy `lykan.class.php` into a directory that is loaded by your application. It
is safer to keep the class outside the public document root when your hosting
setup permits it.

Example layout:

```text
project/
├── app/
│   └── security/
│       └── lykan.class.php
└── public/
    └── index.php
```

### 2. Run LykanShield before the application

Add the following code at the very beginning of the front controller, before
the framework bootstrap, session handling or any response output:

```php
<?php

require_once dirname(__DIR__) . '/app/security/lykan.class.php';

// Pass the project/CMS root, not necessarily the public directory.
lykan::run(dirname(__DIR__));

// Continue with the normal application bootstrap.
require_once dirname(__DIR__) . '/app/bootstrap.php';
```

Every public entry point that can receive an HTTP request must execute
`lykan::run()`. Applications with several entry scripts should put the call in
a shared bootstrap or configure PHP's `auto_prepend_file`.

The supplied root path is important: LykanShield uses it to detect the CMS and
to choose where its runtime files are stored. On the first request it creates
the required directories and protection files.

### 3. Verify the runtime directory

After the first request, confirm that the PHP process created a writable data
directory:

| Application | Default directory |
| --- | --- |
| Generic PHP | `<project-root>/lykan/` |
| WordPress | `<wordpress-root>/wp-content/lykan/` |
| TYPO3 | `<typo3-root>/fileadmin/lykan/` |
| Keimeno | `<keimeno-root>/file_data/lykan/` |

LykanShield creates an Apache `.htaccess` file in this directory. If you use
Nginx or another web server and the directory is below the document root, deny
direct web access to it in the server configuration as well.

### CMS examples

For WordPress, load the class from a persistent custom bootstrap (for example,
an MU plugin) and call:

```php
lykan::run(ABSPATH);
```

For TYPO3 or Keimeno, place the call in an early project bootstrap and pass the
installation root. Avoid editing CMS core files when an extension or persistent
bootstrap is available, because updates can overwrite core changes.

## Configuration

Defaults are declared in `lykan_config::$config`. After initialization,
LykanShield also loads `config.json` from the runtime directory. Top-level
values in that file override the defaults.

Example `config.json`:

```json
{
  "apikey": "",
  "trusted_proxies": [
    "192.0.2.10",
    "2001:db8:1234::/48"
  ],
  "blacklist_lifetime_hours": 1,
  "local_bad_ip_max_entries": 5000,
  "local_bad_ip_lifetime_hours": 720,
  "runtime_artifact_lifetime_hours": 24,
  "refresh_rules_after_response": true,
  "rules_unavailable_action": "monitor",
  "sql_injection_block_score": 3,
  "bad_user_post_action": "log",
  "filter_active": {
    "mime_types": true,
    "file_inject": true,
    "bad_bots": true,
    "bad_user_post": false,
    "bad_ips": true,
    "sql_injection": true,
    "worm_injection": true,
    "exploit": true,
    "payloadlog": false
  }
}
```

Values in `filter_active` are merged with the default filter map, so individual
filters can be overridden without copying the complete map. The `bad_user_post`
heuristic is disabled by default to avoid false positives for API clients. Its
action defaults to logging; set `bad_user_post_action` to `block` only after
testing your real traffic.

If the application is behind a reverse proxy or load balancer, list only proxy
addresses or CIDR ranges that you control in `trusted_proxies`. Forwarded client
IP headers from untrusted peers are ignored.

Payload logging is also disabled by default because it records extensive
request information. Enable it only with an appropriate retention and privacy
policy.

`rules_unavailable_action` controls requests when no valid downloaded rule set
is available. The default `monitor` mode records the condition and continues;
`block` rejects requests until valid rules are available.

Locally blocked IP entries expire after `local_bad_ip_lifetime_hours` and the
newest `local_bad_ip_max_entries` entries are retained. Existing legacy
one-IP-per-line files are migrated automatically. Recurring rule and regex
errors are rate-limited so an outage cannot write one PHP error-log entry per
request.

Valid but expired rules remain active while they are refreshed. On PHP-FPM,
`refresh_rules_after_response` refreshes them after the response has been sent.
The request filter never waits for a remote rule download, including on first
installation. For other SAPIs, initial setup, or predictable update timing, run
a scheduled CLI task:

```php
<?php

require_once '/path/to/lykan.class.php';
exit(lykan::refresh_rules('/path/to/project-root') ? 0 : 1);
```

## Dashboard/API data

Register at [lykanshield.io](https://www.lykanshield.io/register.html), place
the provided API key in `config.json`, and initialize LykanShield before calling
the API method:

```php
<?php

require_once __DIR__ . '/lykan.class.php';

lykan::init(__DIR__);
lykan::load_config();

// Security events from the last 30 days; 100 limits the returned records.
$events = lykan::get_lock(30, 100);

if (is_array($events)) {
    // Build charts or tables from $events.
}
```

`get_lock()` returns decoded data as an array (or `null` if the response cannot
be decoded), not a JSON string.

## Operational notes

- Test the integration in a staging environment before enabling it in
  production. Request filtering can reject legitimate input that resembles an
  attack.
- Monitor the PHP error log and the files in the LykanShield runtime directory.
- Periodic request-cache maintenance also removes expired local IP blocks and
  abandoned download or shard artifacts older than
  `runtime_artifact_lifetime_hours`.
- On PHP-FPM, queued reports and stale-rule updates are normally processed after
  the response. Other SAPIs should call `lykan::flush_report_queue()` and
  `lykan::refresh_rules()` from scheduled tasks.
- Keep `lykan.class.php` current so that code-level fixes are installed in
  addition to automatically downloaded detection data.

## License

See the repository's `LICENSE` file for the applicable license terms.
