# LykanShield System Cron

WordPress cron only runs when WordPress receives traffic. If `DISABLE_WP_CRON` is enabled or the site has low traffic, configure a real system cron to call WordPress cron regularly.

Recommended interval:

```cron
*/5 * * * * curl -fsS https://example.com/wp-cron.php?doing_wp_cron >/dev/null 2>&1
```

Replace `https://example.com` with the WordPress site URL.

LykanShield uses WordPress cron for:

- central rule refreshes, hourly in Free and every 15 minutes in Premium
- local report queue flushing
- license token renewal
- daily Free email summaries
- local log retention cleanup

