<?php
// Removes the plugin's settings and its cached rules, switches and events.
// Orders keep their _analytics_session_id and _analytics_sent notes.
if (!defined('WP_UNINSTALL_PLUGIN')) {
    exit;
}

delete_option('site_analytics_platform');
delete_option('analytics_firewall');
delete_option('site_analytics_files_state');
delete_option('site_analytics_files_trusted');
delete_option('site_analytics_proxy');
delete_option('site_analytics_db_dropin_tried');
delete_option('site_analytics_tracker_release');
wp_clear_scheduled_hook('site_analytics_files_check');
wp_clear_scheduled_hook('site_analytics_inventory_check');
wp_clear_scheduled_hook('site_analytics_posture_check');
wp_clear_scheduled_hook('site_analytics_proxy_repair');
wp_clear_scheduled_hook('site_analytics_tracker_release_check');

// The first-party proxy's rewrite, in case the plugin was deleted without
// being deactivated first: it points at a file that is about to be gone. It is
// written at the site's home (get_home_path(), as site-analytics.php does),
// which is not ABSPATH when WordPress lives in a subfolder; ABSPATH too, where
// versions before 2.4.3 looked.
if (!function_exists('get_home_path')) {
    require_once ABSPATH . 'wp-admin/includes/file.php';
}
foreach (array_unique(array(get_home_path() . '.htaccess', ABSPATH . '.htaccess')) as $site_analytics_htaccess) {
    if (!is_file($site_analytics_htaccess) || !is_writable($site_analytics_htaccess)) {
        continue;
    }
    $site_analytics_rules = (string) @file_get_contents($site_analytics_htaccess);
    $site_analytics_clean = (string) preg_replace('/# BEGIN Site Analytics.*?# END Site Analytics\s*/s', '', $site_analytics_rules);
    if ($site_analytics_clean !== $site_analytics_rules) {
        @file_put_contents($site_analytics_htaccess, $site_analytics_clean, LOCK_EX);
    }
}
// The query-timing drop-in, when it is ours (deactivating removes it; this is
// for a plugin folder deleted by hand first).
$site_analytics_dropin = WP_CONTENT_DIR . '/db.php';
if (is_file($site_analytics_dropin) && strpos((string) @file_get_contents($site_analytics_dropin, false, null, 0, 1000), 'Site Analytics query timing') !== false) {
    @unlink($site_analytics_dropin);
}

// px.php's configs: px/ here goes with the plugin folder, the storage copy
// with the cache folder below.
@unlink(__DIR__ . '/px-config.php');

foreach (array(WP_CONTENT_DIR . '/cache/site-analytics', WP_CONTENT_DIR . '/cache/analytics-firewall') as $site_analytics_dir) {
    if (!is_dir($site_analytics_dir)) {
        continue;
    }
    $items = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($site_analytics_dir, FilesystemIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );
    foreach ($items as $item) {
        $item->isDir() ? @rmdir($item->getPathname()) : @unlink($item->getPathname());
    }
    @rmdir($site_analytics_dir);
}
