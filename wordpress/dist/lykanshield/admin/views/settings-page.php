<?php

declare(strict_types=1);

defined('ABSPATH') || exit;

$loaderStatus = LykanShield_Loader_Installer::status();
$domainContext = LykanShield_License_Client::domain_context();
$multisiteContext = LykanShield_Multisite::context();
$multisiteRows = LykanShield_Multisite::site_rows();
$licenseStatus = LykanShield_License_Status::current();
$healthChecks = LykanShield_Health_Check::checks();
$securityContext = LykanShield_Security_View::context();
$filters = LykanShield_Settings::filters();
$trustedProxies = LykanShield_Settings::trusted_proxies();
$coreConfig = LykanShield_Core_Config::values();
$automation = LykanShield_Settings::automation();
$removeLoader = LykanShield_Settings::remove_loader_on_deactivation();
$deleteDataOnUninstall = LykanShield_Settings::delete_data_on_uninstall();
$displayedLicenseKey = LykanShield_Multisite::license_key_for_domain($domainContext['registrable_domain']);
$displayedLicenseKey = $displayedLicenseKey !== '' ? (string) LykanShield_License_Client::redact_license_key($displayedLicenseKey) : '-';
$tokenPayload = is_array($licenseStatus['token']) ? $licenseStatus['token'] : [];
$expiresAt = isset($tokenPayload['expires_at']) ? (int) $tokenPayload['expires_at'] : 0;
$graceUntil = isset($tokenPayload['grace_until']) ? (int) $tokenPayload['grace_until'] : (int) ($tokenPayload['grace_ends_at'] ?? 0);
$notice = isset($_GET['lykanshield_message']) ? sanitize_text_field((string) wp_unslash($_GET['lykanshield_message'])) : '';
$noticeType = isset($_GET['lykanshield_result']) && $_GET['lykanshield_result'] === 'success' ? 'success' : 'error';

$featureRows = [
    ['SQL, XSS and exploit protection', 'complete', 'complete'],
    ['Upload and MIME protection', 'complete', 'complete'],
    ['Bad-IP and bot protection', 'complete', 'complete'],
    ['Central protection lists', 'hourly', 'every 5-15 minutes'],
    ['Local log retention', '30 days', '13 months'],
    ['Central statistics', '24 hours', '365 days'],
    ['Dashboard', 'basic overview', 'full domain analysis'],
    ['Attacker leaderboard', 'top 10', 'top 100'],
    ['CSV/JSON export', 'no', 'yes'],
    ['Webhooks', 'no', 'yes'],
    ['Automatic reports', 'no', 'daily, weekly or monthly'],
];
?>
<div class="wrap">
    <h1><?php echo esc_html__('LykanShield', 'lykanshield'); ?></h1>

    <?php if ($notice !== '') : ?>
        <div class="notice notice-<?php echo esc_attr($noticeType); ?> inline">
            <p><?php echo esc_html($notice); ?></p>
        </div>
    <?php endif; ?>

    <h2><?php echo esc_html__('License', 'lykanshield'); ?></h2>
    <p><?php echo esc_html__('Free protection is active without a license. Premium unlocks long-term analytics and automation for the licensed main domain.', 'lykanshield'); ?></p>
    <table class="form-table" role="presentation">
        <tr>
            <th scope="row"><?php echo esc_html__('Status', 'lykanshield'); ?></th>
            <td><code><?php echo esc_html($licenseStatus['status']); ?></code></td>
        </tr>
        <tr>
            <th scope="row"><?php echo esc_html__('Protection', 'lykanshield'); ?></th>
            <td><code><?php echo esc_html($licenseStatus['protection_enabled'] ? 'active' : 'inactive'); ?></code></td>
        </tr>
        <tr>
            <th scope="row"><?php echo esc_html__('Premium features', 'lykanshield'); ?></th>
            <td><code><?php echo esc_html($licenseStatus['premium'] ? 'active' : 'free tier'); ?></code></td>
        </tr>
        <tr>
            <th scope="row"><?php echo esc_html__('Canonical domain', 'lykanshield'); ?></th>
            <td><code><?php echo esc_html($domainContext['registrable_domain']); ?></code></td>
        </tr>
        <tr>
            <th scope="row"><?php echo esc_html__('WordPress host', 'lykanshield'); ?></th>
            <td><code><?php echo esc_html($domainContext['canonical_host']); ?></code></td>
        </tr>
        <tr>
            <th scope="row"><?php echo esc_html__('Request host', 'lykanshield'); ?></th>
            <td><code><?php echo esc_html($domainContext['request_host'] !== '' ? $domainContext['request_host'] : '-'); ?></code></td>
        </tr>
        <tr>
            <th scope="row"><?php echo esc_html__('License key', 'lykanshield'); ?></th>
            <td><code><?php echo esc_html($displayedLicenseKey); ?></code></td>
        </tr>
        <tr>
            <th scope="row"><?php echo esc_html__('Multisite scope', 'lykanshield'); ?></th>
            <td><code><?php echo esc_html($multisiteContext['multisite'] ? $multisiteContext['registrable_domain'] : 'single-site'); ?></code></td>
        </tr>
        <tr>
            <th scope="row"><?php echo esc_html__('Expires at', 'lykanshield'); ?></th>
            <td><code><?php echo esc_html($expiresAt > 0 ? gmdate('Y-m-d H:i:s', $expiresAt) . ' UTC' : '-'); ?></code></td>
        </tr>
        <tr>
            <th scope="row"><?php echo esc_html__('Grace ends at', 'lykanshield'); ?></th>
            <td><code><?php echo esc_html($graceUntil > 0 ? gmdate('Y-m-d H:i:s', $graceUntil) . ' UTC' : '-'); ?></code></td>
        </tr>
    </table>

    <?php foreach (array_merge($domainContext['warnings'], $multisiteContext['warnings'], $licenseStatus['warnings']) as $warning) : ?>
        <div class="notice notice-warning inline">
            <p><?php echo esc_html($warning); ?></p>
        </div>
    <?php endforeach; ?>

    <?php if ($multisiteContext['domain_changed']) : ?>
        <div class="notice notice-error inline">
            <p><?php echo esc_html__('This site domain changed since the last Premium activation. Reactivate Premium for the current canonical domain.', 'lykanshield'); ?></p>
        </div>
    <?php endif; ?>

    <h2><?php echo esc_html__('Multisite and domain mapping', 'lykanshield'); ?></h2>
    <p><?php echo esc_html__('Premium is scoped to one registrable main domain. Subdirectory sites and subdomains of the same main domain share that license; different main domains need their own Premium activation or remain on Free.', 'lykanshield'); ?></p>
    <table class="form-table" role="presentation">
        <tr>
            <th scope="row"><?php echo esc_html__('Installation mode', 'lykanshield'); ?></th>
            <td><code><?php echo esc_html($multisiteContext['multisite'] ? 'multisite' : 'single site'); ?></code></td>
        </tr>
        <tr>
            <th scope="row"><?php echo esc_html__('Site ID', 'lykanshield'); ?></th>
            <td><code><?php echo esc_html((string) $multisiteContext['site_id']); ?></code></td>
        </tr>
        <tr>
            <th scope="row"><?php echo esc_html__('License token source', 'lykanshield'); ?></th>
            <td><code><?php echo esc_html($multisiteContext['token_source']); ?></code></td>
        </tr>
        <tr>
            <th scope="row"><?php echo esc_html__('Network configuration', 'lykanshield'); ?></th>
            <td><code><?php echo esc_html($multisiteContext['network_config_allowed'] ? 'super-admin allowed' : 'site scoped'); ?></code></td>
        </tr>
    </table>
    <table class="widefat striped">
        <thead>
            <tr>
                <th><?php echo esc_html__('Site ID', 'lykanshield'); ?></th>
                <th><?php echo esc_html__('Canonical host', 'lykanshield'); ?></th>
                <th><?php echo esc_html__('Main domain', 'lykanshield'); ?></th>
                <th><?php echo esc_html__('License scope', 'lykanshield'); ?></th>
                <th><?php echo esc_html__('Domain changed', 'lykanshield'); ?></th>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($multisiteRows as $row) : ?>
                <tr>
                    <td><code><?php echo esc_html((string) $row['site_id']); ?></code></td>
                    <td><code><?php echo esc_html($row['canonical_domain']); ?></code></td>
                    <td><code><?php echo esc_html($row['registrable_domain']); ?></code></td>
                    <td><code><?php echo esc_html($row['license_scope']); ?></code></td>
                    <td><?php echo esc_html($row['domain_changed'] ? 'yes' : 'no'); ?></td>
                </tr>
            <?php endforeach; ?>
        </tbody>
    </table>

    <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
        <?php wp_nonce_field('lykanshield_license_action'); ?>
        <input type="hidden" name="action" value="lykanshield_license_action">
        <p>
            <label for="lykanshield-license-key"><?php echo esc_html__('Premium license key', 'lykanshield'); ?></label><br>
            <input class="regular-text" id="lykanshield-license-key" name="license_key" type="password" autocomplete="off" value="">
        </p>
        <p>
            <button class="button button-primary" name="license_action" value="activate" type="submit"><?php echo esc_html__('Activate Premium', 'lykanshield'); ?></button>
            <button class="button" name="license_action" value="renew" type="submit"><?php echo esc_html__('Renew token', 'lykanshield'); ?></button>
            <button class="button" name="license_action" value="check" type="submit"><?php echo esc_html__('Check status', 'lykanshield'); ?></button>
            <button class="button" name="license_action" value="deactivate" type="submit"><?php echo esc_html__('Deactivate Premium', 'lykanshield'); ?></button>
        </p>
    </form>

    <h2><?php echo esc_html__('Protection settings', 'lykanshield'); ?></h2>
    <form method="post" action="<?php echo esc_url(admin_url('options.php')); ?>">
        <?php settings_fields('lykanshield_settings'); ?>
        <table class="form-table" role="presentation">
            <?php foreach (LykanShield_Settings::default_filters() as $key => $enabled) : ?>
                <tr>
                    <th scope="row"><?php echo esc_html(ucwords(str_replace('_', ' ', $key))); ?></th>
                    <td>
                        <label>
                            <input type="checkbox" name="<?php echo esc_attr(LykanShield_Settings::OPTION_FILTERS); ?>[<?php echo esc_attr($key); ?>]" value="1" <?php checked(!empty($filters[$key])); ?>>
                            <?php echo esc_html__('Enabled', 'lykanshield'); ?>
                        </label>
                    </td>
                </tr>
            <?php endforeach; ?>
            <tr>
                <th scope="row"><label for="lykanshield-trusted-proxies"><?php echo esc_html__('Trusted proxies', 'lykanshield'); ?></label></th>
                <td>
                    <textarea class="large-text code" id="lykanshield-trusted-proxies" name="<?php echo esc_attr(LykanShield_Settings::OPTION_TRUSTED_PROXIES); ?>" rows="5"><?php echo esc_textarea($trustedProxies); ?></textarea>
                    <p class="description"><?php echo esc_html__('One IP address or CIDR range per line. Invalid entries are discarded on save.', 'lykanshield'); ?></p>
                </td>
            </tr>
            <tr>
                <th scope="row"><label for="lykanshield-api-key"><?php echo esc_html__('Core API key', 'lykanshield'); ?></label></th>
                <td>
                    <input class="regular-text" id="lykanshield-api-key" name="<?php echo esc_attr(LykanShield_Settings::OPTION_CORE_CONFIG); ?>[api_key]" type="password" autocomplete="off" value="" placeholder="<?php echo esc_attr((string) LykanShield_License_Client::redact_license_key((string) $coreConfig['api_key'])); ?>">
                    <p class="description"><?php echo esc_html__('Optional central LykanShield API key. Leave empty to keep the stored value. This is not the Premium license key.', 'lykanshield'); ?></p>
                </td>
            </tr>
            <tr>
                <th scope="row"><label for="lykanshield-notification-email"><?php echo esc_html__('Notification email', 'lykanshield'); ?></label></th>
                <td>
                    <input class="regular-text" id="lykanshield-notification-email" name="<?php echo esc_attr(LykanShield_Settings::OPTION_CORE_CONFIG); ?>[notification_email]" type="email" value="<?php echo esc_attr((string) $coreConfig['notification_email']); ?>">
                </td>
            </tr>
            <tr>
                <th scope="row"><label for="lykanshield-rules-unavailable-action"><?php echo esc_html__('Missing rules policy', 'lykanshield'); ?></label></th>
                <td>
                    <select id="lykanshield-rules-unavailable-action" name="<?php echo esc_attr(LykanShield_Settings::OPTION_CORE_CONFIG); ?>[rules_unavailable_action]">
                        <option value="monitor" <?php selected($coreConfig['rules_unavailable_action'], 'monitor'); ?>><?php echo esc_html__('Monitor only', 'lykanshield'); ?></option>
                        <option value="block" <?php selected($coreConfig['rules_unavailable_action'], 'block'); ?>><?php echo esc_html__('Block when rules are unavailable', 'lykanshield'); ?></option>
                    </select>
                    <p class="description"><?php echo esc_html__('Monitor is safer during installation and license-server outages because protection remains active without failing closed on missing remote rules.', 'lykanshield'); ?></p>
                </td>
            </tr>
            <?php foreach ([
                'sql_injection_block_score' => ['SQL block score', 2, 10],
                'log_lines_count' => ['Displayed log lines', 20, 1000],
                'local_bad_ip_lifetime_hours' => ['Local bad-IP lifetime in hours', 1, 9500],
                'local_bad_ip_max_entries' => ['Local bad-IP maximum entries', 100, 100000],
                'report_queue_max_entries' => ['Report queue maximum entries', 100, 50000],
                'request_inspection_max_bytes' => ['Request inspection maximum bytes', 1024, 65536],
            ] as $coreKey => $coreField) : ?>
                <tr>
                    <th scope="row"><label for="lykanshield-<?php echo esc_attr($coreKey); ?>"><?php echo esc_html($coreField[0]); ?></label></th>
                    <td>
                        <input id="lykanshield-<?php echo esc_attr($coreKey); ?>" name="<?php echo esc_attr(LykanShield_Settings::OPTION_CORE_CONFIG); ?>[<?php echo esc_attr($coreKey); ?>]" type="number" min="<?php echo esc_attr((string) $coreField[1]); ?>" max="<?php echo esc_attr((string) $coreField[2]); ?>" value="<?php echo esc_attr((string) $coreConfig[$coreKey]); ?>">
                    </td>
                </tr>
            <?php endforeach; ?>
            <tr>
                <th scope="row"><label for="lykanshield-webhook-url"><?php echo esc_html__('Premium webhook URL', 'lykanshield'); ?></label></th>
                <td>
                    <input class="regular-text" id="lykanshield-webhook-url" name="<?php echo esc_attr(LykanShield_Settings::OPTION_AUTOMATION); ?>[webhook_url]" type="url" value="<?php echo esc_attr($automation['webhook_url']); ?>" placeholder="https://">
                    <p class="description"><?php echo esc_html__('Premium only. The URL must use HTTPS; Free ignores this setting.', 'lykanshield'); ?></p>
                </td>
            </tr>
            <tr>
                <th scope="row"><label for="lykanshield-report-frequency"><?php echo esc_html__('Premium report frequency', 'lykanshield'); ?></label></th>
                <td>
                    <select id="lykanshield-report-frequency" name="<?php echo esc_attr(LykanShield_Settings::OPTION_AUTOMATION); ?>[report_frequency]">
                        <option value="none" <?php selected($automation['report_frequency'], 'none'); ?>><?php echo esc_html__('Disabled', 'lykanshield'); ?></option>
                        <option value="daily" <?php selected($automation['report_frequency'], 'daily'); ?>><?php echo esc_html__('Daily', 'lykanshield'); ?></option>
                        <option value="weekly" <?php selected($automation['report_frequency'], 'weekly'); ?>><?php echo esc_html__('Weekly', 'lykanshield'); ?></option>
                        <option value="monthly" <?php selected($automation['report_frequency'], 'monthly'); ?>><?php echo esc_html__('Monthly', 'lykanshield'); ?></option>
                    </select>
                </td>
            </tr>
            <tr>
                <th scope="row"><label for="lykanshield-report-email"><?php echo esc_html__('Premium report email', 'lykanshield'); ?></label></th>
                <td>
                    <input class="regular-text" id="lykanshield-report-email" name="<?php echo esc_attr(LykanShield_Settings::OPTION_AUTOMATION); ?>[report_email]" type="email" value="<?php echo esc_attr($automation['report_email']); ?>">
                    <p class="description"><?php echo esc_html__('Premium only. Empty uses the WordPress admin email.', 'lykanshield'); ?></p>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php echo esc_html__('MU loader removal', 'lykanshield'); ?></th>
                <td>
                    <label>
                        <input type="checkbox" name="<?php echo esc_attr(LykanShield_Settings::OPTION_REMOVE_LOADER_ON_DEACTIVATION); ?>" value="1" <?php checked($removeLoader); ?>>
                        <?php echo esc_html__('Remove the managed MU loader on normal plugin deactivation.', 'lykanshield'); ?>
                    </label>
                </td>
            </tr>
            <tr>
                <th scope="row"><?php echo esc_html__('Uninstall data removal', 'lykanshield'); ?></th>
                <td>
                    <label>
                        <input type="checkbox" name="<?php echo esc_attr(LykanShield_Settings::OPTION_DELETE_DATA_ON_UNINSTALL); ?>" value="1" <?php checked($deleteDataOnUninstall); ?>>
                        <?php echo esc_html__('Delete settings, license data and local LykanShield logs during uninstall.', 'lykanshield'); ?>
                    </label>
                    <p class="description"><?php echo esc_html__('Leave disabled to keep configuration and logs for reinstall or audit retention.', 'lykanshield'); ?></p>
                </td>
            </tr>
        </table>
        <?php submit_button(__('Save settings', 'lykanshield')); ?>
    </form>

    <h2><?php echo esc_html__('System status', 'lykanshield'); ?></h2>
    <?php if (LykanShield_Cron::wp_cron_warning() !== '') : ?>
        <div class="notice notice-warning inline">
            <p><?php echo esc_html(LykanShield_Cron::wp_cron_warning()); ?></p>
            <p><code><?php echo esc_html(LykanShield_Cron::system_cron_hint()); ?></code></p>
        </div>
    <?php endif; ?>
    <table class="widefat striped">
        <thead>
            <tr>
                <th><?php echo esc_html__('Check', 'lykanshield'); ?></th>
                <th><?php echo esc_html__('Value', 'lykanshield'); ?></th>
                <th><?php echo esc_html__('Status', 'lykanshield'); ?></th>
            </tr>
        </thead>
        <tbody>
            <tr>
                <td><?php echo esc_html__('Early MU loader', 'lykanshield'); ?></td>
                <td><code><?php echo esc_html($loaderStatus['path']); ?></code></td>
                <td><?php echo esc_html($loaderStatus['message']); ?></td>
            </tr>
            <?php foreach ($healthChecks as $check) : ?>
                <tr>
                    <td><?php echo esc_html($check['label']); ?></td>
                    <td><code><?php echo esc_html($check['value']); ?></code></td>
                    <td><?php echo esc_html($check['message']); ?></td>
                </tr>
            <?php endforeach; ?>
        </tbody>
    </table>

    <?php if (!$loaderStatus['installed'] || !$loaderStatus['managed']) : ?>
        <p><?php echo esc_html(LykanShield_Loader_Installer::manual_installation_text()); ?></p>
    <?php endif; ?>

    <h2><?php echo esc_html__('Security overview', 'lykanshield'); ?></h2>
    <p><?php echo esc_html__('Request buckets are approximate and never show raw payloads, cookies, passwords or tokens.', 'lykanshield'); ?></p>
    <table class="widefat striped">
        <tbody>
            <tr>
                <td><?php echo esc_html__('Estimated requests', 'lykanshield'); ?></td>
                <td><code><?php echo esc_html((string) $securityContext['stats']['request_count_estimate']); ?></code></td>
            </tr>
            <tr>
                <td><?php echo esc_html__('Request buckets', 'lykanshield'); ?></td>
                <td><code><?php echo esc_html((string) $securityContext['stats']['request_bucket_count']); ?></code></td>
            </tr>
            <tr>
                <td><?php echo esc_html__('Central history window', 'lykanshield'); ?></td>
                <td><code><?php echo esc_html((string) $securityContext['history_days']); ?> <?php echo esc_html__('days', 'lykanshield'); ?></code></td>
            </tr>
            <tr>
                <td><?php echo esc_html__('Local retention', 'lykanshield'); ?></td>
                <td><code><?php echo esc_html((string) $securityContext['local_retention_days']); ?> <?php echo esc_html__('days', 'lykanshield'); ?></code></td>
            </tr>
            <tr>
                <td><?php echo esc_html__('Attacker leaderboard limit', 'lykanshield'); ?></td>
                <td><code><?php echo esc_html((string) $securityContext['attacker_limit']); ?></code></td>
            </tr>
            <tr>
                <td><?php echo esc_html__('Custom rules, webhooks and reports', 'lykanshield'); ?></td>
                <td><code><?php echo esc_html($securityContext['premium'] ? 'premium enabled' : 'premium only'); ?></code></td>
            </tr>
        </tbody>
    </table>

    <h3><?php echo esc_html__('Country and attack type summary', 'lykanshield'); ?></h3>
    <table class="widefat striped">
        <thead>
            <tr>
                <th><?php echo esc_html__('Country bucket', 'lykanshield'); ?></th>
                <th><?php echo esc_html__('Events', 'lykanshield'); ?></th>
                <th><?php echo esc_html__('Attack type', 'lykanshield'); ?></th>
                <th><?php echo esc_html__('Events', 'lykanshield'); ?></th>
            </tr>
        </thead>
        <tbody>
            <?php
            $countryRows = array_map(static fn ($key, $value): array => [$key, $value], array_keys($securityContext['countries']), $securityContext['countries']);
            $typeRows = array_map(static fn ($key, $value): array => [$key, $value], array_keys($securityContext['attack_types']), $securityContext['attack_types']);
            $summaryRows = max(count($countryRows), count($typeRows), 1);
            ?>
            <?php for ($rowIndex = 0; $rowIndex < $summaryRows; $rowIndex++) : ?>
                <tr>
                    <td><?php echo esc_html((string) ($countryRows[$rowIndex][0] ?? '-')); ?></td>
                    <td><code><?php echo esc_html((string) ($countryRows[$rowIndex][1] ?? '0')); ?></code></td>
                    <td><?php echo esc_html((string) ($typeRows[$rowIndex][0] ?? '-')); ?></td>
                    <td><code><?php echo esc_html((string) ($typeRows[$rowIndex][1] ?? '0')); ?></code></td>
                </tr>
            <?php endfor; ?>
        </tbody>
    </table>

    <h3><?php echo esc_html__('Local IP blocks', 'lykanshield'); ?></h3>
    <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
        <?php wp_nonce_field('lykanshield_security_action'); ?>
        <input type="hidden" name="action" value="lykanshield_security_action">
        <input type="hidden" name="security_action" value="add_block">
        <p>
            <label for="lykanshield-block-entry"><?php echo esc_html__('IP address or CIDR range', 'lykanshield'); ?></label><br>
            <input class="regular-text" id="lykanshield-block-entry" name="block_entry" type="text" value="">
            <button class="button" type="submit"><?php echo esc_html__('Add block', 'lykanshield'); ?></button>
        </p>
    </form>
    <table class="widefat striped">
        <thead>
            <tr>
                <th><?php echo esc_html__('Entry', 'lykanshield'); ?></th>
                <th><?php echo esc_html__('Created', 'lykanshield'); ?></th>
                <th><?php echo esc_html__('Expires', 'lykanshield'); ?></th>
                <th><?php echo esc_html__('Action', 'lykanshield'); ?></th>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($securityContext['local_blocks'] as $block) : ?>
                <tr>
                    <td><code><?php echo esc_html($block['entry']); ?></code></td>
                    <td><?php echo esc_html($block['created_at']); ?></td>
                    <td><?php echo esc_html($block['expires_label']); ?></td>
                    <td>
                        <form method="post" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                            <?php wp_nonce_field('lykanshield_security_action'); ?>
                            <input type="hidden" name="action" value="lykanshield_security_action">
                            <input type="hidden" name="security_action" value="remove_block">
                            <input type="hidden" name="block_entry" value="<?php echo esc_attr($block['entry']); ?>">
                            <button class="button" type="submit"><?php echo esc_html__('Remove', 'lykanshield'); ?></button>
                        </form>
                    </td>
                </tr>
            <?php endforeach; ?>
            <?php if ($securityContext['local_blocks'] === []) : ?>
                <tr>
                    <td colspan="4"><?php echo esc_html__('No local IP blocks found.', 'lykanshield'); ?></td>
                </tr>
            <?php endif; ?>
        </tbody>
    </table>

    <h3><?php echo esc_html__('Recent security events', 'lykanshield'); ?></h3>
    <p><?php echo esc_html(sprintf(__('Showing up to %d sanitized events.', 'lykanshield'), $securityContext['event_limit'])); ?></p>
    <table class="widefat striped">
        <thead>
            <tr>
                <th><?php echo esc_html__('Time', 'lykanshield'); ?></th>
                <th><?php echo esc_html__('Type', 'lykanshield'); ?></th>
                <th><?php echo esc_html__('IP', 'lykanshield'); ?></th>
                <th><?php echo esc_html__('User agent sample', 'lykanshield'); ?></th>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($securityContext['events'] as $event) : ?>
                <tr>
                    <td><?php echo esc_html($event['time']); ?></td>
                    <td><?php echo esc_html($event['type']); ?></td>
                    <td><code><?php echo esc_html($event['ip']); ?></code></td>
                    <td><?php echo esc_html($event['user_agent']); ?></td>
                </tr>
            <?php endforeach; ?>
            <?php if ($securityContext['events'] === []) : ?>
                <tr>
                    <td colspan="4"><?php echo esc_html__('No security events found.', 'lykanshield'); ?></td>
                </tr>
            <?php endif; ?>
        </tbody>
    </table>

    <p>
        <?php if ($securityContext['exports_enabled']) : ?>
            <a class="button" href="<?php echo esc_url(wp_nonce_url(admin_url('admin-post.php?action=lykanshield_security_export&format=json'), 'lykanshield_security_export')); ?>"><?php echo esc_html__('Export JSON', 'lykanshield'); ?></a>
            <a class="button" href="<?php echo esc_url(wp_nonce_url(admin_url('admin-post.php?action=lykanshield_security_export&format=csv'), 'lykanshield_security_export')); ?>"><?php echo esc_html__('Export CSV', 'lykanshield'); ?></a>
        <?php else : ?>
            <button class="button" type="button" disabled><?php echo esc_html__('Export requires Premium', 'lykanshield'); ?></button>
        <?php endif; ?>
    </p>

    <h2><?php echo esc_html__('Free and Premium', 'lykanshield'); ?></h2>
    <table class="widefat striped">
        <thead>
            <tr>
                <th><?php echo esc_html__('Feature', 'lykanshield'); ?></th>
                <th><?php echo esc_html__('Free', 'lykanshield'); ?></th>
                <th><?php echo esc_html__('Premium', 'lykanshield'); ?></th>
            </tr>
        </thead>
        <tbody>
            <?php foreach ($featureRows as $row) : ?>
                <tr>
                    <td><?php echo esc_html($row[0]); ?></td>
                    <td><?php echo esc_html($row[1]); ?></td>
                    <td><?php echo esc_html($row[2]); ?></td>
                </tr>
            <?php endforeach; ?>
        </tbody>
    </table>
</div>
