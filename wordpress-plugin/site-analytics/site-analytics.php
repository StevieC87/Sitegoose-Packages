<?php
/**
 * Plugin Name: Site Analytics
 * Description: Your analytics in WordPress: the tracker served from your own domain so ad blockers don't hide visitors, WooCommerce orders sent from your server, a firewall, error monitoring, server speed, file monitoring and a check of your plugins for known security holes. Settings → Site Analytics.
 * Version: 2.5.0
 * Requires at least: 5.6
 * Requires PHP: 7.4
 * License: MIT
 */

// The PHP package (lib/, a copy of sdk/platform-php/src made by ../build.sh)
// connected to WordPress. Same folder name as the tracker-only plugin the
// install page generates, so uploading this one replaces it.
// - Tracker: the loader in <head>, plus a first-party cookie with the visit's
//   ID so orders and logins link to the visit.
// - WooCommerce: each paid order as a "purchase" from the server (order
//   number as transaction_id, so a browser-sent copy counts once), refunds.
// - Firewall, errors, logins (identify): through the Platform.
// - File monitoring: the site's files against the accepted version, hourly from WP-Cron.
// - Software inventory: core, plugin, theme and PHP versions, daily from WP-Cron.
// - Set-up checks: the settings that leave the site open, who has administrator
//   rights, and the scheduled jobs a hack hides in, daily from WP-Cron.
// Every module can be switched off in the dashboard (Security → Server package).

if (!defined('ABSPATH')) {
    exit;
}

const SITE_ANALYTICS_OPTION = 'site_analytics_platform';
const SITE_ANALYTICS_TRACKER_MAJOR = '1';
// The tracker version it loads, pinned by its hash, and the signed file that
// moves it on (release.php).
require_once __DIR__ . '/release.php';

// The product name, shown wherever the admin says it. Internal identifiers are
// deliberately NOT derived from this and must not follow a rename: the plugin
// folder (uploading a new build replaces the old one by folder name), the
// option keys below, the .htaccess BEGIN/END markers (a renamed marker leaves
// the old block behind forever) and the cache directory. The "Plugin Name:"
// header at the top of this file is read from the comment by WordPress before
// any code runs, so it cannot read this constant and has to be edited to match.
if (!defined('SITE_ANALYTICS_NAME')) {
    define('SITE_ANALYTICS_NAME', 'Site Analytics');
}
// Square logo for the settings header; initials are drawn when it is empty.
if (!defined('SITE_ANALYTICS_LOGO')) {
    define('SITE_ANALYTICS_LOGO', '');
}
// Where "Open dashboard" goes. Empty hides the button, because a wrong guess
// is worse than no link. Set it in wp-config.php.
if (!defined('SITE_ANALYTICS_DASHBOARD')) {
    define('SITE_ANALYTICS_DASHBOARD', '');
}

// Up to two letters for the logo square, from the first words of the name.
function site_analytics_initials($name)
{
    $words = preg_split('/\s+/', trim((string) $name), -1, PREG_SPLIT_NO_EMPTY);
    if (!$words) {
        return '?';
    }
    $out = strtoupper(substr($words[0], 0, 1));
    if (isset($words[1])) {
        $out .= strtoupper(substr($words[1], 0, 1));
    }
    return $out;
}

function site_analytics_platform_settings()
{
    $saved = get_option(SITE_ANALYTICS_OPTION, null);
    // Settings from the firewall-only plugin, if that's what was installed.
    if (!is_array($saved)) {
        $old = get_option('analytics_firewall', array());
        $saved = is_array($old) ? $old : array();
    }
    return wp_parse_args($saved, array(
        'site_id' => '',
        'secret' => '',
        'endpoint' => '',
        'trust_proxy' => '0',
        'tracker' => '1',
        'identify' => '1',
        // Serve the tracker from this site's domain, past ad blockers.
        'proxy' => '1',
    ));
}

function site_analytics_platform_storage()
{
    return WP_CONTENT_DIR . '/cache/site-analytics';
}

// A platform with these settings; site_analytics_platform() is the one for this request.
function site_analytics_platform_make(array $settings)
{
    foreach (array('Core', 'RequestRules', 'Challenge', 'Firewall', 'Errors', 'Analytics', 'Performance', 'Queries', 'Queues', 'Resources', 'Crawlers', 'Forms', 'Audit', 'Flags', 'Files', 'Inventory', 'Posture', 'Proxy', 'Platform') as $class) {
        if (!class_exists('AnalyticsPlatform\\' . $class)) {
            require_once __DIR__ . '/lib/' . $class . '.php';
        }
    }
    $counter = null;
    // Without APCu, a persistent object cache (Redis, Memcached) can count.
    if (!(function_exists('apcu_enabled') && apcu_enabled()) && wp_using_ext_object_cache()) {
        $counter = function ($key, $ttl) {
            wp_cache_add($key, 0, 'site_analytics', $ttl);
            return (int) wp_cache_incr($key, 1, 'site_analytics');
        };
    }
    return new AnalyticsPlatform\Platform(array(
        'site_id' => $settings['site_id'],
        'secret' => $settings['secret'],
        'endpoint' => $settings['endpoint'],
        'storage' => site_analytics_platform_storage(),
        'platform' => 'wordpress',
        // Checked on the front end only (below), so wp-admin and logins keep working.
        'maintenance_manual' => true,
        'firewall' => array(
            'trust_proxy' => $settings['trust_proxy'] === 'cloudflare' ? 'cloudflare' : (int) $settings['trust_proxy'],
            'counter' => $counter,
        ),
        // define('SITE_ANALYTICS_QUERIES', false) in wp-config.php: Server speed without query timings.
        'queries' => !(defined('SITE_ANALYTICS_QUERIES') && !SITE_ANALYTICS_QUERIES),
        // define('SITE_ANALYTICS_CALLS', false): Server speed without the time spent calling other sites.
        'calls' => !(defined('SITE_ANALYTICS_CALLS') && !SITE_ANALYTICS_CALLS),
        // WordPress has no job queue of its own to read (WP-Cron's runs are timed as jobs).
        'queues' => false,
        'files' => site_analytics_files_options(),
        'inventory' => site_analytics_inventory_options(),
        'posture' => site_analytics_posture_options(),
    ));
}

function site_analytics_platform()
{
    static $platform = null;
    if ($platform === null) {
        $platform = site_analytics_platform_make(site_analytics_platform_settings());
    }
    return $platform;
}

// Every request but WP-CLI and WordPress's own cron calls.
// The browser check (flood protection) is part of it, and runs before
// WordPress knows who is logged in: telling that needs pluggable.php, not
// loaded yet, and the mere presence of a login cookie would let any bot past.
// So logged-in users aren't exempt; their browser passes with one reload a
// day. Login and form posts, ajax, REST and cron aren't page loads (a POST,
// or no text/html in Accept), so they are never checked.
if (!(defined('WP_CLI') && WP_CLI) && !wp_doing_cron()) {
    site_analytics_platform()->protect();
    // A static-looking request (firewall.md, `rate`: "/x.css") that reaches
    // WordPress at all is one the web server had no file for: when
    // WordPress's own router took it to a page (its main query ran, the
    // `wp` action), it counts toward the rate and the page limits after the
    // response, so WooCommerce's /my-account/lost-password/x.css isn't a way
    // past a page limit. Left alone: what WordPress and plugins serve as
    // files through PHP (/wp-content/ and /wp-includes/ behind a rewrite,
    // its /favicon.ico), and an answer with a file's Content-Type. An error
    // (a made-up file's 404) counts whatever the route.
    add_action('wp', 'site_analytics_static_routed', 0);
}

function site_analytics_static_routed()
{
    try {
        $firewall = site_analytics_platform()->firewall();
        if (!$firewall || is_admin() || (function_exists('is_favicon') && is_favicon())) {
            return;
        }
        $path = strtolower((string) parse_url(isset($_SERVER['REQUEST_URI']) ? (string) $_SERVER['REQUEST_URI'] : '/', PHP_URL_PATH));
        // The folders at the start of the path only: anywhere in it,
        // "/search/a/wp-content/b.css" (a search for "a/wp-content/b.css")
        // and "/search/a/favicon.ico" would be pages let past the limits.
        $dirs = array('/wp-content/', '/wp-includes/');
        foreach (array(content_url('/'), includes_url()) as $url) {
            $dir = strtolower((string) parse_url((string) $url, PHP_URL_PATH));
            if ($dir !== '' && $dir !== '/') {
                $dirs[] = rtrim($dir, '/') . '/';
            }
        }
        $favicon = rtrim(strtolower((string) parse_url(home_url('/'), PHP_URL_PATH)), '/') . '/favicon.ico';
        if (site_analytics_serves_files($path, $dirs, $favicon)) {
            return;
        }
        $firewall->markRouted(true);
    } catch (\Throwable $e) {
        // never break the site
    }
}

// Whether $path (lower case) is one WordPress or a plugin serves as a file
// through PHP: under one of $dirs ("/wp-content/", from its start), or the
// site's favicon.
function site_analytics_serves_files($path, array $dirs, $favicon)
{
    if ($path === '/favicon.ico' || $path === $favicon) {
        return true;
    }
    foreach ($dirs as $dir) {
        if (strpos($path, $dir) === 0) {
            return true;
        }
    }
    return false;
}
// Cron runs automatic updates: what it records (the audit log) is sent when it ends.
if (wp_doing_cron()) {
    register_shutdown_function(function () {
        site_analytics_platform()->afterResponse();
    });
}

// What WordPress asked other sites for: steps in the trail shown before a PHP
// error, with the status they answered (0: no answer), and each call's time
// for Health → Server speed → Calls, by the host it called: from
// pre_http_request (last of its filters, its value handed back unchanged, so
// a call another filter answers itself isn't timed) to http_api_debug.
// WordPress reads the whole answer before that, so the time includes the
// body. A call that doesn't wait for its answer has none to show.
function site_analytics_calls_started($set = null)
{
    static $started = array();
    if ($set !== null) {
        $started = $set;
    }
    return $started;
}

add_filter('pre_http_request', function ($preempt, $args, $url) {
    try {
        if ($preempt === false && is_array($args) && (!isset($args['blocking']) || $args['blocking']) && empty($args['site_analytics_own'])) {
            $started = site_analytics_calls_started();
            // Calls nest only through another filter; a start never answered
            // (a filter after this one answered it) doesn't pile up.
            if (count($started) >= 20) {
                array_shift($started);
            }
            $started[] = array((string) $url, microtime(true));
            site_analytics_calls_started($started);
        }
    } catch (\Throwable $e) {
        // untimed
    }
    return $preempt;
}, PHP_INT_MAX, 3);

add_action('http_api_debug', function ($response, $context, $class, $args, $url) {
    try {
        if ($context !== 'response' || !is_array($args) || empty($args['blocking'])) {
            return;
        }
        // The plugin's own checks are steps of the trail, not the site's calls:
        // they were never started above.
        $method = isset($args['method']) ? (string) $args['method'] : 'GET';
        $status = is_wp_error($response) ? 0 : (int) wp_remote_retrieve_response_code($response);
        site_analytics_platform()->addRequestBreadcrumb($method, $url, $status);
        $started = site_analytics_calls_started();
        for ($i = count($started) - 1; $i >= 0; $i--) {
            if ($started[$i][0] === (string) $url) {
                site_analytics_platform()->recordCall($method, $url, (microtime(true) - $started[$i][1]) * 1000, $status);
                array_splice($started, $i, 1);
                site_analytics_calls_started($started);
                break;
            }
        }
    } catch (\Throwable $e) {
        // the call's answer is WordPress's, untouched
    }
}, 10, 5);

// ---- First-party proxy: counting visitors who use ad blockers -----------------
// Ad blockers stop analytics by recognising the address a script comes from
// and what it is called. The dashboard's answer is to serve both from the
// site's own domain, which so far meant Nginx, Apache or Cloudflare rules
// nobody on shared hosting can add. WordPress is already a server on that
// domain, so the plugin does it itself: px.php forwards /<prefix>/js/ and
// /<prefix>/api/ to the collector, and the tracker is loaded from there.
//
// Two ways to reach px.php, best first:
//   'pretty' — a rewrite in the site's .htaccess keeps a clean address
//              (/<prefix>/js/v1/s.js). Apache and LiteSpeed.
//   'file'   — px.php is asked for directly, with the prefix and the rest of
//              the address as PATH_INFO (px.php/<prefix>/js/v1/s.js). No
//              rewrite needed, so nginx works too.
// Whichever answers is stored; if neither does, the tracker loads from the
// collector as before. The loader also falls back by itself at run time, so a
// proxy that breaks after a host change can never cost the site its analytics.

const SITE_ANALYTICS_PROXY_OPTION = 'site_analytics_proxy';
// Raised when what the stored state points at changes shape, so an update sets
// the proxy up again instead of handing out an address the new px.php won't
// answer. 2: one config per site, named by its prefix, kept outside the plugin
// folder; the prefix is in every address px.php is asked for. 3: the config
// holds the proxy key. 4: and the site id, so px.php can apply the firewall's
// address rules (deny, bans) before it forwards anything.
const SITE_ANALYTICS_PROXY_FORMAT = 4;
const SITE_ANALYTICS_PROXY_REPAIR_HOOK = 'site_analytics_proxy_repair';

// The path on the site, from the secret: not guessable from the page, and the
// same every time, so caches and the .htaccess rule stay valid. Worked out by
// the shared class, so the plugin and px.php can never disagree about it.
function site_analytics_proxy_prefix(array $settings)
{
    if ($settings['secret'] === '') {
        return '';
    }
    site_analytics_platform();
    return AnalyticsPlatform\Proxy::prefixFor($settings['secret']);
}

function site_analytics_proxy_state()
{
    $empty = array('mode' => '', 'prefix' => '', 'base' => '', 'config' => '', 'format' => 0);
    $state = get_option(SITE_ANALYTICS_PROXY_OPTION, array());
    return is_array($state) ? $state + $empty : $empty;
}

// Whether the stored state can be used as it is: written by this version, and
// its config still on disk. WordPress replaces the plugin folder whole on every
// update, and caches get cleared; a state that outlived its config would have
// every page view ask px.php first, get a 404 and only then fall back.
function site_analytics_proxy_intact(array $state)
{
    return (int) $state['format'] === SITE_ANALYTICS_PROXY_FORMAT && $state['config'] !== '' && is_file($state['config']);
}

// The address the tracker is loaded from, or '' when the proxy isn't working.
// A proxy that was working but no longer is intact loads the tracker from the
// collector until the next cron run has set it up again.
function site_analytics_proxy_base()
{
    $state = site_analytics_proxy_state();
    if ($state['mode'] === '') {
        return '';
    }
    if (!site_analytics_proxy_intact($state)) {
        if (!wp_next_scheduled(SITE_ANALYTICS_PROXY_REPAIR_HOOK)) {
            wp_schedule_single_event(time(), SITE_ANALYTICS_PROXY_REPAIR_HOOK);
        }
        return '';
    }
    return $state['base'];
}

add_action(SITE_ANALYTICS_PROXY_REPAIR_HOOK, function () {
    site_analytics_proxy_refresh(site_analytics_platform_settings());
});

// An empty index file, so a server that lists folders doesn't show what is in
// them: the storage folder's subfolder is named with a hash of the secret
// precisely so it can't be found (Core.php), and a listing would name it.
function site_analytics_storage_guard($dir)
{
    if (wp_mkdir_p($dir) && !file_exists($dir . '/index.html')) {
        @file_put_contents($dir . '/index.html', '');
    }
}

// Where px.php looks for its config, best first; px.php works out the same two
// for itself. The cache folder outlives plugin updates, but is used only when it
// is the folder px.php will look in (wp-content and the plugins folder where
// WordPress puts them). One file per site, named by its prefix: a network's
// sites share this plugin folder, and an old secret's file is never picked.
function site_analytics_proxy_config_dirs()
{
    $dirs = array();
    $cache = dirname(__DIR__, 2) . '/cache/site-analytics';
    if (wp_normalize_path($cache) === wp_normalize_path(site_analytics_platform_storage())) {
        $dirs[] = $cache . '/px';
    }
    $dirs[] = __DIR__ . '/px';
    return $dirs;
}

// px.php reads this; it must not need WordPress. Returns the file's path, or ''
// when no folder could be written.
function site_analytics_proxy_write_config(array $settings, $platform = null)
{
    $platform = $platform ?: site_analytics_platform();
    $prefix = site_analytics_proxy_prefix($settings);
    $config = "<?php\n// Written by the Site Analytics plugin for px.php. Do not edit.\nreturn " . var_export(array(
        'endpoint' => untrailingslashit($settings['endpoint']),
        'trust_proxy' => (string) $settings['trust_proxy'],
        'dir' => $platform->core()->dir(),
        // The secret itself never goes in a file the web server can serve,
        // so the path and the proxy key worked out from it are written here
        // instead. The key only proves to the collector that this site's
        // proxy passes on its visitors' addresses.
        'prefix' => $prefix,
        'key' => AnalyticsPlatform\Proxy::keyFor($settings['secret']),
        // Not secret (every page carries it): it names this site's bans.
        'site_id' => (string) $settings['site_id'],
    ), true) . ";\n";
    foreach (site_analytics_proxy_config_dirs() as $dir) {
        site_analytics_storage_guard($dir);
        $path = $dir . '/' . $prefix . '.php';
        $tmp = $path . '.' . getmypid() . '.' . bin2hex(random_bytes(4));
        if (@file_put_contents($tmp, $config) !== false && @rename($tmp, $path)) {
            return $path;
        }
        @unlink($tmp);
    }
    return '';
}

// The config this site wrote ($path, from its stored state), and the single
// px-config.php of versions before 2.4.3: next to px.php, or in a storage
// subfolder, where an old secret's folder kept its copy after a rotation.
// Nothing reads those any more.
function site_analytics_proxy_delete_config($path)
{
    // Only ever a file this plugin names: the path comes from the database.
    if (preg_match('#/px/[a-f0-9]{8}\.php$#D', (string) $path)) {
        @unlink($path);
    }
    @unlink(__DIR__ . '/px-config.php');
    foreach (glob(site_analytics_platform_storage() . '/*/px-config.php') ?: array() as $old) {
        @unlink($old);
    }
}

// The rewrite, at the very top of the site's .htaccess: WordPress's own block
// ends by sending everything to index.php, so a rule after it never runs.
function site_analytics_proxy_htaccess($prefix)
{
    // One file for the whole network: a block per site would overwrite the
    // last one, so multisite uses px.php's own address instead.
    if (is_multisite()) {
        return false;
    }
    if (!function_exists('get_home_path')) {
        require_once ABSPATH . 'wp-admin/includes/file.php';
    }
    // Not ABSPATH: with WordPress in a subfolder the rules live at the
    // site's home, and the rule's pattern is relative to that folder.
    $file = get_home_path() . '.htaccess';
    $current = is_file($file) ? (string) @file_get_contents($file) : '';
    if (is_file($file) && !is_writable($file)) {
        return false;
    }
    $target = wp_parse_url(plugins_url('px.php', __FILE__), PHP_URL_PATH);
    // sa_k tells px.php which site's config to read.
    $block = "# BEGIN Site Analytics\n<IfModule mod_rewrite.c>\nRewriteEngine On\n"
        . "RewriteRule ^" . $prefix . "/(js|api)/(.*)$ " . $target . "?sa_k=" . $prefix . "&sa_t=$1&sa_p=$2 [QSA,L]\n"
        . "</IfModule>\n# END Site Analytics\n";
    $without = site_analytics_proxy_htaccess_strip($current);
    if ($prefix === '') {
        return $without === $current ? true : (bool) @file_put_contents($file, $without, LOCK_EX);
    }
    $next = $block . ($without === '' ? '' : "\n" . ltrim($without, "\n"));
    return $next === $current ? true : (bool) @file_put_contents($file, $next, LOCK_EX);
}

function site_analytics_proxy_htaccess_strip($content)
{
    return (string) preg_replace('/# BEGIN Site Analytics.*?# END Site Analytics\s*/s', '', $content);
}

// Asks the site for the tracker through each address in turn. A proxy that
// answers with the real script is the one the snippet will use.
function site_analytics_proxy_verify(array $settings)
{
    $prefix = site_analytics_proxy_prefix($settings);
    if ($settings['tracker'] !== '1' || $prefix === '' || $settings['endpoint'] === '') {
        return array('mode' => '', 'prefix' => '', 'base' => '');
    }
    // Asked for directly, px.php reads the prefix from the first part of
    // PATH_INFO, as the rewrite's addresses carry it in the first part of theirs.
    $file = untrailingslashit(plugins_url('px.php', __FILE__)) . '/' . $prefix;
    $candidates = array('pretty' => home_url('/' . $prefix), 'file' => $file);
    $reached = false;
    foreach ($candidates as $mode => $base) {
        $res = wp_remote_get($base . '/js/v' . SITE_ANALYTICS_TRACKER_MAJOR . '/s.js', array(
            'timeout' => 10,
            'redirection' => 0,
            'headers' => array('Accept' => '*/*'),
            // The plugin's own check, not a call of the site's.
            'site_analytics_own' => true,
        ));
        if (!is_wp_error($res)) {
            $reached = true;
            if ((int) wp_remote_retrieve_response_code($res) === 200 && strlen((string) wp_remote_retrieve_body($res)) > 500) {
                return array('mode' => $mode, 'prefix' => $prefix, 'base' => $base);
            }
        }
    }
    return array('mode' => '', 'prefix' => $prefix, 'base' => '', 'unreachable' => !$reached);
}

// Sets the proxy up (or takes it down) and remembers what works. Runs when
// the settings are saved, when the plugin is activated, and from cron when
// the proxy was working but is no longer intact.
function site_analytics_proxy_refresh(array $settings, $platform = null)
{
    $platform = $platform ?: site_analytics_platform();
    $previous = site_analytics_proxy_state();
    site_analytics_storage_guard(site_analytics_platform_storage());
    if ($settings['proxy'] !== '1' || !$platform->configured()) {
        site_analytics_proxy_htaccess('');
        site_analytics_proxy_delete_config($previous['config']);
        update_option(SITE_ANALYTICS_PROXY_OPTION, array('mode' => '', 'prefix' => '', 'base' => '', 'config' => '', 'format' => SITE_ANALYTICS_PROXY_FORMAT), true);
        return array('mode' => '');
    }
    $platform->core()->ensureDir();
    $config = site_analytics_proxy_write_config($settings, $platform);
    // The file of an old secret, and the old one-file config.
    site_analytics_proxy_delete_config($previous['config'] !== $config ? $previous['config'] : '');
    site_analytics_proxy_htaccess(site_analytics_proxy_prefix($settings));
    $state = site_analytics_proxy_verify($settings) + array('config' => $config, 'format' => SITE_ANALYTICS_PROXY_FORMAT);
    update_option(SITE_ANALYTICS_PROXY_OPTION, $state, true);
    // Nothing answered: leave no rewrite behind on a server that ignores it.
    if ($state['mode'] === '') {
        site_analytics_proxy_htaccess('');
    }
    return $state;
}

register_activation_hook(__FILE__, function () {
    site_analytics_proxy_refresh(site_analytics_platform_settings());
});

// Upgrading from a version without the proxy, or one whose proxy state the
// update left unusable: set it up once, rather than wait for someone to open
// the settings page and press Save. (Front-end page views do the same from
// cron; this covers sites whose WP-Cron never runs.)
add_action('admin_init', function () {
    $state = get_option(SITE_ANALYTICS_PROXY_OPTION, null);
    if (is_array($state)) {
        $state = site_analytics_proxy_state();
        if ($state['mode'] === '' || site_analytics_proxy_intact($state)) {
            return;
        }
    }
    if (get_transient('site_analytics_proxy_tried')) {
        return;
    }
    set_transient('site_analytics_proxy_tried', 1, DAY_IN_SECONDS);
    site_analytics_proxy_refresh(site_analytics_platform_settings());
});

// The rewrite must not outlive the plugin: it points at a file that is gone.
register_deactivation_hook(__FILE__, function () {
    site_analytics_proxy_htaccess('');
    site_analytics_proxy_delete_config(site_analytics_proxy_state()['config']);
    delete_option(SITE_ANALYTICS_PROXY_OPTION);
    wp_clear_scheduled_hook(SITE_ANALYTICS_PROXY_REPAIR_HOOK);
});

// ---- Tracker ------------------------------------------------------------------

const SITE_ANALYTICS_RELEASE_OPTION = 'site_analytics_tracker_release';
const SITE_ANALYTICS_RELEASE_HOOK = 'site_analytics_tracker_release_check';

// The tracker version the tag names, with its integrity hash: the last signed
// release taken, else the one this build of the plugin carries.
function site_analytics_tracker_release()
{
    $taken = get_option(SITE_ANALYTICS_RELEASE_OPTION);
    if (is_array($taken) && isset($taken['version'], $taken['integrity'], $taken['seq'])) {
        return $taken;
    }
    return array('version' => SITE_ANALYTICS_TRACKER_VERSION, 'integrity' => SITE_ANALYTICS_TRACKER_INTEGRITY, 'seq' => 0);
}

// Reads the collector's signed release file and takes the version it names,
// when it's signed by a key this plugin lists and newer than the last one
// taken. Daily from WP-Cron, and when the settings are saved. Anything else
// (unreachable, unsigned, an old file again) leaves the version as it is.
function site_analytics_tracker_release_check()
{
    $settings = site_analytics_platform_settings();
    if ($settings['endpoint'] === '' || !SITE_ANALYTICS_RELEASE_KEYS) {
        return;
    }
    $res = wp_remote_get(untrailingslashit($settings['endpoint']) . '/tracker-release.json', array(
        'timeout' => 10,
        'redirection' => 0,
        'site_analytics_own' => true,
    ));
    if (is_wp_error($res) || (int) wp_remote_retrieve_response_code($res) !== 200) {
        return;
    }
    $taken = site_analytics_tracker_release();
    $next = site_analytics_release_verify(wp_remote_retrieve_body($res), SITE_ANALYTICS_RELEASE_KEYS, SITE_ANALYTICS_TRACKER_MAJOR, $taken['seq']);
    if ($next) {
        update_option(SITE_ANALYTICS_RELEASE_OPTION, $next, true);
    }
}
add_action(SITE_ANALYTICS_RELEASE_HOOK, 'site_analytics_tracker_release_check');

add_action('init', function () {
    if (SITE_ANALYTICS_RELEASE_KEYS && !wp_next_scheduled(SITE_ANALYTICS_RELEASE_HOOK)) {
        wp_schedule_event(time() + 60, 'daily', SITE_ANALYTICS_RELEASE_HOOK);
    }
});

register_deactivation_hook(__FILE__, function () {
    wp_clear_scheduled_hook(SITE_ANALYTICS_RELEASE_HOOK);
});

// Opt out of JS delay/defer optimisers (LiteSpeed, Cloudflare Rocket Loader, WP Rocket).
function site_analytics_platform_script_attrs()
{
    return array('data-no-optimize' => '1', 'data-cfasync' => 'false', 'nowprocket' => true);
}

function site_analytics_platform_tracker()
{
    $settings = site_analytics_platform_settings();
    if ($settings['tracker'] !== '1' || $settings['site_id'] === '' || $settings['endpoint'] === '') {
        return;
    }
    // The tracker-only plugin (or a copy in the theme) already loads it.
    if (function_exists('site_analytics_script_attrs')) {
        return;
    }
    if (is_feed() || is_embed() || is_customize_preview() || !apply_filters('site_analytics_enabled', true)) {
        return;
    }
    // Through this site's own domain when the proxy works, so ad blockers
    // have neither our address nor a name they know to match on. Either way
    // the file is asked for as "s.js" and visits are sent to "e": the names
    // "track.js" and "collect" are on the blockers' lists by themselves.
    // One version, with its hash: the browser runs nothing else, from us or
    // through the proxy (release.php).
    $direct = untrailingslashit($settings['endpoint']);
    $proxy = site_analytics_proxy_base();
    $release = site_analytics_tracker_release();
    $file = '/v' . $release['version'] . '/s.js';
    $config = wp_json_encode(array(
        'src' => ($proxy !== '' ? $proxy . '/js' : $direct) . $file,
        'integrity' => $release['integrity'],
        'attrs' => array(
            'data-domain' => (string) wp_parse_url(home_url(), PHP_URL_HOST),
            'data-siteid' => $settings['site_id'],
            'data-performance' => 'true',
            'data-collect' => $proxy !== '' ? $proxy . '/api/e' : $direct . '/collectanalytics/e',
        ),
        // If the proxy stops answering (the host changed, a rule was lost),
        // the tracker is loaded from us instead rather than not at all.
        'alt' => $proxy !== '' ? $direct . $file : '',
        'altCollect' => $proxy !== '' ? $direct . '/collectanalytics/e' : '',
        // The visit's ID as a first-party cookie, for orders and logins.
        'cookie' => (bool) apply_filters('site_analytics_session_cookie', true),
    ));
    $loader = <<<'JS'
window.analytics = window.analytics || {};
window.analytics.q = window.analytics.q || [];
["track", "identify", "consent", "reset"].forEach(function (m) {
  window.analytics[m] = window.analytics[m] || function () { window.analytics.q.push([m, [].slice.call(arguments)]); };
});
(function (c) {
  function remember() {
    var id = c.cookie && window.analyticsSession && window.analyticsSession.getId && window.analyticsSession.getId();
    if (id) document.cookie = "analytics_session=" + id + "; path=/; max-age=1800; SameSite=Lax" + (location.protocol === "https:" ? "; Secure" : "");
  }
  function load(src, collect, retry) {
    var s = document.createElement("script");
    s.src = src;
    s.async = true;
    for (var k in c.attrs) s.setAttribute(k, c.attrs[k]);
    if (collect) s.setAttribute("data-collect", collect);
    s.crossOrigin = "anonymous";
    s.integrity = c.integrity;
    s.onload = remember;
    if (retry) s.onerror = function () { load(c.alt, c.altCollect, false); };
    document.body.appendChild(s);
  }
  function start() { load(c.src, c.attrs["data-collect"], !!c.alt); }
  document.addEventListener("submit", remember, true);
  if (document.readyState === "complete") start();
  else window.addEventListener("load", start);
})(CONFIG);
JS;
    $loader = str_replace('CONFIG', $config, $loader);
    if (function_exists('wp_print_inline_script_tag')) {
        wp_print_inline_script_tag($loader, site_analytics_platform_script_attrs());
        return;
    }
    // WordPress 5.6, the oldest this plugin supports: wp_print_inline_script_tag()
    // arrived in 5.7. The same tag, written out.
    echo '<script';
    foreach (site_analytics_platform_script_attrs() as $name => $value) {
        echo ' ' . esc_attr($name) . ($value === true ? '' : '="' . esc_attr($value) . '"');
    }
    echo ">\n" . $loader . "\n</script>\n";
}
add_action('wp_head', 'site_analytics_platform_tracker', 1);

// wp-login.php never runs wp_head, so without this its sign-up form would carry
// no spam protection answer, and with "Protect every form" on every real
// sign-up would be turned away as automated (Form protection, below). Only the
// sign-up page: the login form has nothing to protect.
add_action('login_head', function () {
    if (isset($_REQUEST['action']) && sanitize_key(wp_unslash($_REQUEST['action'])) === 'register') {
        site_analytics_platform_tracker();
    }
});

// ---- WooCommerce --------------------------------------------------------------

// The visit, saved with the order when it's created (classic and block checkout).
add_action('woocommerce_new_order', function ($order_id, $order = null) {
    $session = AnalyticsPlatform\Platform::sessionIdFromRequest();
    $order = $order ?: (function_exists('wc_get_order') ? wc_get_order($order_id) : null);
    if ($session !== '' && $order) {
        $order->update_meta_data('_analytics_session_id', $session);
        $order->save_meta_data();
    }
}, 10, 2);

// An order's or refund's lines as items: name, SKU, quantity and the line
// before discounts (a refund's lines are negative; what came back is positive).
function site_analytics_platform_order_items($order)
{
    $items = array();
    foreach (array_slice($order->get_items(), 0, 100) as $item) {
        $product = is_callable(array($item, 'get_product')) ? $item->get_product() : null;
        $items[] = array(
            'name' => substr((string) $item->get_name(), 0, 200),
            'sku' => $product ? substr((string) $product->get_sku(), 0, 100) : '',
            'quantity' => max(1, abs((int) $item->get_quantity())),
            'amount' => wc_format_decimal(abs((float) $item->get_subtotal()), 2),
        );
    }
    return $items;
}

// Who bought and what the total is made of, for the Shop report's Sales,
// Customers and Cohorts. A guest's email is hashed here, so the address never
// leaves the shop; a registered customer is their WordPress user ID.
function site_analytics_platform_order_fields($order)
{
    $fields = array(
        'subtotal' => wc_format_decimal($order->get_subtotal(), 2),
        'discount' => wc_format_decimal($order->get_discount_total(), 2),
        'shipping' => wc_format_decimal($order->get_shipping_total(), 2),
        'tax' => wc_format_decimal($order->get_total_tax(), 2),
        'items' => site_analytics_platform_order_items($order),
    );
    $customer = (int) $order->get_customer_id();
    $email = strtolower(trim((string) $order->get_billing_email()));
    $earlier = array(
        'status' => function_exists('wc_get_is_paid_statuses') ? wc_get_is_paid_statuses() : array('processing', 'completed'),
        'exclude' => array($order->get_id()),
        'type' => 'shop_order',
        'limit' => 1,
        'paginate' => true,
        'return' => 'ids',
    );
    if ($customer > 0) {
        $fields['customer_id'] = (string) $customer;
        $earlier['customer_id'] = $customer;
    } elseif ($email !== '') {
        $fields['customer_email'] = hash('sha256', $email);
        $earlier['billing_email'] = $email;
    } else {
        return $fields;
    }
    // Paid orders this customer placed before this one, so a regular from
    // before the plugin was installed isn't counted as a new customer.
    $created = $order->get_date_created();
    if ($created && function_exists('wc_get_orders')) {
        $earlier['date_created'] = '<' . $created->getTimestamp();
        $found = wc_get_orders($earlier);
        if (is_object($found) && isset($found->total)) {
            $fields['prior_orders'] = (int) $found->total;
        }
    }
    return $fields;
}

// A paid order, once: as a purchase with the order number as transaction_id.
function site_analytics_platform_purchase($order_id)
{
    $order = function_exists('wc_get_order') ? wc_get_order($order_id) : null;
    if (!$order || $order->get_meta('_analytics_sent') || !apply_filters('site_analytics_enabled', true)) {
        return;
    }
    $fields = array(
        'numeric_value' => wc_format_decimal($order->get_total(), 2),
        'currency' => $order->get_currency(),
        'transaction_id' => (string) $order->get_order_number(),
    );
    $coupons = $order->get_coupon_codes();
    if ($coupons) {
        $fields['coupon'] = (string) reset($coupons);
    }
    $items = $order->get_items();
    if ($items) {
        $fields['event_label'] = substr((string) reset($items)->get_name(), 0, 200);
    }
    $fields += site_analytics_platform_order_fields($order);
    if (site_analytics_platform()->track('purchase', $fields, (string) $order->get_meta('_analytics_session_id')) !== '') {
        $order->update_meta_data('_analytics_sent', '1');
        $order->save_meta_data();
    }
}
add_action('woocommerce_payment_complete', 'site_analytics_platform_purchase');
add_action('woocommerce_order_status_processing', 'site_analytics_platform_purchase');
add_action('woocommerce_order_status_completed', 'site_analytics_platform_purchase');

add_action('woocommerce_order_refunded', function ($order_id, $refund_id) {
    $order = function_exists('wc_get_order') ? wc_get_order($order_id) : null;
    $refund = $order ? wc_get_order($refund_id) : null;
    if (!$refund || !$order->get_meta('_analytics_sent')) {
        return;
    }
    site_analytics_platform()->track('refund', array(
        'numeric_value' => wc_format_decimal($refund->get_amount(), 2),
        'currency' => $order->get_currency(),
        'transaction_id' => (string) $order->get_order_number(),
        'event_uid' => 'refund-' . $refund_id,
        'items' => site_analytics_platform_order_items($refund),
    ), (string) $order->get_meta('_analytics_session_id'));
}, 10, 2);

// ---- Server speed: route names ----------------------------------------------------
// WordPress addresses are mostly unique slugs, so requests are grouped by
// the kind of page instead: "/:post", "/:page", REST routes, ajax actions.

add_action('template_redirect', function () {
    $route = is_front_page() ? '/' : (is_404() ? '' : (is_search() ? '/(search)' : (is_singular('product') ? '/:product'
        : (is_singular() ? '/:' . (is_page() ? 'page' : 'post') : (is_archive() ? '/:archive' : (is_feed() ? '/(feed)' : ''))))));
    if ($route !== '') {
        site_analytics_platform()->setRoute($route);
    }
}, 0);

add_filter('rest_dispatch_request', function ($result, $request, $route) {
    // "/wp/v2/posts/(?P<id>[\d]+)" -> "/wp-json/wp/v2/posts/{id}"
    site_analytics_platform()->setRoute('/wp-json' . preg_replace('#\(\?P<(\w+)>[^)]*\)#', '{$1}', (string) $route));
    return $result;
}, 10, 3);

add_action('admin_init', function () {
    if (wp_doing_ajax()) {
        $action = isset($_REQUEST['action']) ? sanitize_key(wp_unslash($_REQUEST['action'])) : '';
        site_analytics_platform()->setRoute('/wp-admin/admin-ajax.php' . ($action !== '' ? ' (' . $action . ')' : ''));
    } elseif (isset($GLOBALS['pagenow'])) {
        site_analytics_platform()->setRoute('/wp-admin/' . sanitize_file_name($GLOBALS['pagenow']));
    }
});

// ---- Server speed: database queries --------------------------------------------------
// Every query's time, its values taken out (sdk/protocols/queries.md), under
// the request's route above. Two ways, best first:
//   drop-in    — wp-content/db.php, written on activation: a wpdb that times
//                each query() as it runs, from the first one WordPress makes,
//                failures included. Only when there is no db.php already (a
//                cache plugin, Query Monitor, HyperDB own theirs) and
//                wp-content can be written; removed on deactivation, and only
//                when it is ours (the mark in its header).
//   SAVEQUERIES — otherwise: WordPress's own query log, read at shutdown. It
//                misses the queries before this plugin loads (the options
//                WordPress loads first, earlier plugins' set-up), can't tell
//                a failed query from one that worked (errors are 0), and keeps
//                each query with its caller until the request ends, so it
//                costs some memory on a page that runs thousands.

const SITE_ANALYTICS_DB_DROPIN_MARK = 'Site Analytics query timing';

function site_analytics_db_dropin_path()
{
    return WP_CONTENT_DIR . '/db.php';
}

function site_analytics_db_dropin_ours($path)
{
    return is_file($path) && strpos((string) @file_get_contents($path, false, null, 0, 1000), SITE_ANALYTICS_DB_DROPIN_MARK) !== false;
}

// The drop-in names this plugin's copy of Queries.php by its full path:
// WordPress loads it before it knows where plugins live. When that file is
// gone (the plugin deleted without being deactivated), WordPress's own wpdb
// is used as if there were no drop-in.
function site_analytics_db_dropin_code()
{
    $queries = var_export(__DIR__ . '/lib/Queries.php', true);
    $mark = SITE_ANALYTICS_DB_DROPIN_MARK;
    return <<<PHP
<?php
/**
 * Plugin Name: {$mark}
 * Description: Times each database query for Server speed (values taken out first). Written by the Site Analytics plugin, which removes it when deactivated.
 */
// Leave the name above in: it is how the plugin knows this file is its own.
defined('ABSPATH') || exit;
global \$wpdb;
if (!isset(\$wpdb) && class_exists('wpdb', false) && is_file({$queries})) {
    require_once {$queries};
    class Site_Analytics_Timed_wpdb extends wpdb
    {
        private \$site_analytics_db = '';

        public function query(\$query)
        {
            \$started = microtime(true);
            \$result = parent::query(\$query);
            try {
                if (\$this->site_analytics_db === '' && \$this->dbh && method_exists(\$this, 'db_server_info')) {
                    \$this->site_analytics_db = stripos((string) \$this->db_server_info(), 'mariadb') !== false ? 'mariadb' : 'mysql';
                }
                \AnalyticsPlatform\Queries::report(\$this->site_analytics_db ?: 'mysql', \$query, (microtime(true) - \$started) * 1000, \$result === false);
            } catch (\Throwable \$e) {
                // never break the site
            }
            return \$result;
        }
    }
    \$wpdb = new Site_Analytics_Timed_wpdb(
        defined('DB_USER') ? DB_USER : '',
        defined('DB_PASSWORD') ? DB_PASSWORD : '',
        defined('DB_NAME') ? DB_NAME : '',
        defined('DB_HOST') ? DB_HOST : ''
    );
}

PHP;
}

// Created, never overwritten: 'x' fails when the file appeared meanwhile.
function site_analytics_db_dropin_install()
{
    $path = site_analytics_db_dropin_path();
    if ((defined('SITE_ANALYTICS_QUERIES') && !SITE_ANALYTICS_QUERIES) || file_exists($path) || !is_writable(WP_CONTENT_DIR)) {
        return false;
    }
    $file = @fopen($path, 'x');
    if (!$file) {
        return false;
    }
    $code = site_analytics_db_dropin_code();
    $ok = @fwrite($file, $code) === strlen($code);
    fclose($file);
    if (!$ok) {
        @unlink($path);
    }
    return $ok;
}

function site_analytics_db_dropin_remove()
{
    $path = site_analytics_db_dropin_path();
    if (site_analytics_db_dropin_ours($path)) {
        @unlink($path);
    }
}

register_activation_hook(__FILE__, 'site_analytics_db_dropin_install');
register_deactivation_hook(__FILE__, 'site_analytics_db_dropin_remove');

// An update isn't an activation, so a site that updated to a version with the
// drop-in gets it on the next admin page instead, tried once per version
// (wp-content may stay unwritable). Turning query timing off with
// SITE_ANALYTICS_QUERIES takes ours away the same way.
add_action('admin_init', function () {
    if (defined('SITE_ANALYTICS_QUERIES') && !SITE_ANALYTICS_QUERIES) {
        site_analytics_db_dropin_remove();
        return;
    }
    $version = get_file_data(__FILE__, array('Version' => 'Version'))['Version'];
    if (get_option('site_analytics_db_dropin_tried') === $version) {
        return;
    }
    update_option('site_analytics_db_dropin_tried', $version, false);
    site_analytics_db_dropin_install();
});

// Without the drop-in: SAVEQUERIES, when Server speed and query timings are on.
if (!(isset($GLOBALS['wpdb']) && is_a($GLOBALS['wpdb'], 'Site_Analytics_Timed_wpdb'))
    && site_analytics_platform()->module('queries') !== null && site_analytics_platform()->core()->isOn('performance')) {
    if (!defined('SAVEQUERIES')) {
        define('SAVEQUERIES', true);
    }
    if (SAVEQUERIES) {
        // Last on shutdown, which runs before the platform's own shutdown
        // work adds the request's queries up (WordPress registers it first).
        add_action('shutdown', function () {
            global $wpdb;
            $platform = site_analytics_platform();
            $db = method_exists($wpdb, 'db_server_info') && $wpdb->dbh && stripos((string) $wpdb->db_server_info(), 'mariadb') !== false ? 'mariadb' : 'mysql';
            foreach (is_array($wpdb->queries) ? $wpdb->queries : array() as $query) {
                if (is_array($query) && isset($query[0], $query[1])) {
                    $platform->recordQuery($db, (string) $query[0], (float) $query[1] * 1000);
                }
            }
        }, PHP_INT_MAX);
    }
}

// ---- Form protection ----------------------------------------------------------------
// Comments, sign-ups, Contact Form 7 and Gravity Forms are checked before
// WordPress accepts them; spam lands in Leads → Spam in your dashboard. Turn
// on "Protect every form" in your spam protection settings so the tracker
// puts its answer in these forms (the sign-up page gets the tracker too, above).
// Logged-in users aren't checked, nor pingbacks and trackbacks: other sites'
// servers send those, with no page and no tracker, so no answer could be in them.

function site_analytics_platform_is_spam(array $fields, $email = null, $name = null, $form = null)
{
    if (is_user_logged_in() || !apply_filters('site_analytics_enabled', true)) {
        return false;
    }
    $result = site_analytics_platform()->checkForm($fields, $email, $name, $form);
    return !empty($result['spam']);
}

add_filter('pre_comment_approved', function ($approved, $comment) {
    if ($approved === 'spam' || $approved === 'trash') {
        return $approved;
    }
    $type = isset($comment['comment_type']) ? (string) $comment['comment_type'] : '';
    if ($type === 'pingback' || $type === 'trackback') {
        return $approved;
    }
    $fields = wp_unslash($_POST);
    return site_analytics_platform_is_spam(is_array($fields) ? $fields : array(), isset($comment['comment_author_email']) ? $comment['comment_author_email'] : null,
        isset($comment['comment_author']) ? $comment['comment_author'] : null, 'Comment') ? 'spam' : $approved;
}, 20, 2);

add_filter('registration_errors', function ($errors, $login, $email) {
    $fields = wp_unslash($_POST);
    if (site_analytics_platform_is_spam(is_array($fields) ? $fields : array(), $email, $login, 'Sign-up')) {
        $errors->add('site_analytics_spam', 'Your sign-up looks automated. Please try again.');
    }
    return $errors;
}, 20, 3);

add_filter('wpcf7_spam', function ($spam) {
    if ($spam) {
        return $spam;
    }
    $fields = wp_unslash($_POST);
    return site_analytics_platform_is_spam(is_array($fields) ? $fields : array(), null, null, 'Contact Form 7');
}, 20);

add_filter('gform_entry_is_spam', function ($is_spam, $form) {
    if ($is_spam) {
        return $is_spam;
    }
    $fields = wp_unslash($_POST);
    return site_analytics_platform_is_spam(is_array($fields) ? $fields : array(), null, null, is_array($form) && isset($form['title']) ? (string) $form['title'] : 'Gravity Forms');
}, 20, 2);

// ---- Maintenance mode and feature flags ------------------------------------------------
// Maintenance: the front end only; wp-admin, logins, REST and ajax keep
// working, and people who can edit posts see the site as usual.
add_action('template_redirect', function () {
    if (!current_user_can('edit_posts')) {
        site_analytics_platform()->sendMaintenancePage();
    }
}, 0);

// A feature flag from your dashboard, for themes and plugins:
// if (site_analytics_flag('new-header')) { ... } (user: the logged-in user's ID).
function site_analytics_flag($key, $default = false)
{
    $user = get_current_user_id();
    return site_analytics_platform()->isEnabled($key, $user ? (string) $user : null, $default);
}

// ---- Audit log ----------------------------------------------------------------------
// Who did what in WordPress: logins, users and roles, plugins, themes, updates,
// published and deleted content. The actor is the WordPress login name.

function site_analytics_platform_audit($action, $target = '', $details = null)
{
    $user = wp_get_current_user();
    site_analytics_platform()->audit($action, $user && $user->exists() ? $user->user_login : '', $target, $details);
}

add_action('wp_login', function ($login) {
    site_analytics_platform()->audit('user.login', (string) $login);
}, 20);
add_action('wp_logout', function ($user_id = 0) {
    $user = $user_id ? get_userdata($user_id) : null;
    site_analytics_platform()->audit('user.logout', $user ? $user->user_login : '');
});
add_action('user_register', function ($user_id) {
    $user = get_userdata($user_id);
    site_analytics_platform_audit('user.registered', $user ? 'user:' . $user->user_login : 'user:' . $user_id, $user ? array('roles' => $user->roles) : null);
});
add_action('set_user_role', function ($user_id, $role, $old_roles) {
    $user = get_userdata($user_id);
    site_analytics_platform_audit('user.role_changed', 'user:' . ($user ? $user->user_login : $user_id), array('from' => array_values((array) $old_roles), 'to' => $role));
}, 10, 3);
add_action('delete_user', function ($user_id) {
    $user = get_userdata($user_id);
    site_analytics_platform_audit('user.deleted', 'user:' . ($user ? $user->user_login : $user_id));
});
add_action('after_password_reset', function ($user) {
    site_analytics_platform()->audit('user.password_reset', $user instanceof WP_User ? $user->user_login : '');
});
add_action('activated_plugin', function ($plugin) {
    site_analytics_platform_audit('plugin.activated', 'plugin:' . $plugin);
});
add_action('deactivated_plugin', function ($plugin) {
    site_analytics_platform_audit('plugin.deactivated', 'plugin:' . $plugin);
});
add_action('deleted_plugin', function ($plugin, $deleted) {
    if ($deleted) {
        site_analytics_platform_audit('plugin.deleted', 'plugin:' . $plugin);
    }
}, 10, 2);
add_action('upgrader_process_complete', function ($upgrader, $options) {
    $type = isset($options['type']) ? (string) $options['type'] : '';
    $items = isset($options['plugins']) ? (array) $options['plugins'] : (isset($options['themes']) ? (array) $options['themes'] : array());
    $action = isset($options['action']) && $options['action'] === 'install' ? 'installed' : 'updated';
    site_analytics_platform_audit(($type ?: 'software') . '.' . $action, $items ? $type . ':' . implode(', ', array_slice($items, 0, 10)) : $type);
}, 10, 2);
add_action('switch_theme', function ($name) {
    site_analytics_platform_audit('theme.switched', 'theme:' . $name);
});
add_action('transition_post_status', function ($new, $old, $post) {
    if ($new === $old || wp_is_post_revision($post) || !in_array($new, array('publish', 'trash'), true)) {
        return;
    }
    site_analytics_platform_audit($new === 'publish' ? 'post.published' : 'post.trashed', $post->post_type . ':' . $post->ID, array('title' => get_the_title($post)));
}, 10, 3);
add_action('updated_option', function ($option) {
    // The settings people change on purpose, not the many WordPress keeps itself.
    if (in_array($option, array('siteurl', 'home', 'blogname', 'admin_email', 'users_can_register', 'default_role', 'permalink_structure', 'blog_public'), true)) {
        site_analytics_platform_audit('settings.changed', 'option:' . $option);
    }
});

// ---- Logins ---------------------------------------------------------------------

// Failed logins count for bot protection: past the site's limit the address is banned.
add_action('wp_login_failed', function () {
    site_analytics_platform()->loginFailed();
});

// Links the visit to the WordPress user (their ID, nothing else).
add_action('wp_login', function ($login, $user) {
    if (site_analytics_platform_settings()['identify'] === '1' && $user instanceof WP_User) {
        site_analytics_platform()->identify((string) $user->ID);
    }
}, 10, 2);

// ---- File monitoring ------------------------------------------------------------

// The Files module (lib/Files.php, protocol in sdk/protocols/files.md): about
// once an hour WP-Cron compares the site's files with the version accepted on
// the dashboard and reports what's different (Security → Page integrity).
// WordPress changes its own files too, so: core files matching WordPress.org's
// checksums are taken in, and plugin, theme and translation *updates* are
// trusted for two hours (installs are reported: someone with admin rights
// could install anything). Anything that looks hacked is reported regardless.
const SITE_ANALYTICS_FILES_STATE = 'site_analytics_files_state';
const SITE_ANALYTICS_FILES_TRUSTED = 'site_analytics_files_trusted';
const SITE_ANALYTICS_FILES_HOOK = 'site_analytics_files_check';

function site_analytics_files_options()
{
    $roots = array(ABSPATH);
    if (strpos(wp_normalize_path(WP_CONTENT_DIR) . '/', wp_normalize_path(ABSPATH)) !== 0) {
        $roots[] = WP_CONTENT_DIR;
    }
    return array(
        'roots' => $roots,
        'exclude' => array(WP_CONTENT_DIR . '/cache', WP_CONTENT_DIR . '/upgrade'),
        // In the database (not autoloaded), compressed: a few thousand files.
        // Serialized rather than JSON: a file name that isn't valid UTF-8 (an
        // upload named on a Latin-1 system) makes json_encode() fail outright,
        // and substituting the bytes would name a file that isn't there.
        // 'gz:' and 'js:' are the JSON of versions before 2.4.3.
        'load' => function () {
            $raw = get_option(SITE_ANALYTICS_FILES_STATE, '');
            if (!is_string($raw) || $raw === '') {
                return null;
            }
            $kind = substr($raw, 0, 3);
            $body = substr($raw, 3);
            if ($kind === 'gs:' || $kind === 'gz:') {
                $body = @gzuncompress((string) base64_decode($body));
            }
            if (!is_string($body)) {
                return null;
            }
            if ($kind === 'gs:' || $kind === 'ps:') {
                $state = @unserialize($body, array('allowed_classes' => false));
                return is_array($state) ? $state : null;
            }
            return json_decode($body, true);
        },
        'save' => function ($state) {
            $body = serialize($state);
            $raw = function_exists('gzcompress') ? 'gs:' . base64_encode(gzcompress($body, 6)) : 'ps:' . base64_encode($body);
            update_option(SITE_ANALYTICS_FILES_STATE, $raw, false);
        },
        'official' => 'site_analytics_files_official',
        'trusted' => 'site_analytics_files_trusted',
    );
}

// Core files against WordPress.org's checksums for this version: true when
// the file is the official one, false when it differs (or is an unknown PHP
// file in wp-admin or wp-includes, where attackers hide them), null otherwise.
function site_analytics_files_official($path)
{
    static $sums = null, $root = null;
    if ($sums === null) {
        global $wp_version;
        $locale = get_locale() ?: 'en_US';
        $key = 'site_analytics_core_sums_' . md5($wp_version . $locale);
        $sums = get_site_transient($key);
        if (!is_array($sums)) {
            if (!function_exists('get_core_checksums')) {
                require_once ABSPATH . 'wp-admin/includes/update.php';
            }
            $sums = get_core_checksums($wp_version, $locale);
            if (!is_array($sums) && $locale !== 'en_US') {
                $sums = get_core_checksums($wp_version, 'en_US');
            }
            $sums = is_array($sums) ? $sums : array();
            set_site_transient($key, $sums, $sums ? DAY_IN_SECONDS : HOUR_IN_SECONDS);
        }
        $root = wp_normalize_path(ABSPATH);
    }
    $path = wp_normalize_path($path);
    if (!$sums || strpos($path, $root) !== 0) {
        return null;
    }
    $relative = substr($path, strlen($root));
    if (isset($sums[$relative]) && strpos($relative, 'wp-content/') !== 0) {
        return md5_file($path) === $sums[$relative];
    }
    if (preg_match('#^wp-(admin|includes)/#', $relative) && preg_match('/\.(php[0-9]?|phtml|phar)$/Di', $relative)) {
        return false;
    }
    return null;
}

function site_analytics_files_trusted($path)
{
    static $trusted = null;
    if ($trusted === null) {
        $trusted = get_option(SITE_ANALYTICS_FILES_TRUSTED, array());
        $trusted = is_array($trusted) ? $trusted : array();
    }
    $path = wp_normalize_path($path);
    foreach ($trusted as $prefix => $until) {
        if ((int) $until >= time() && strpos($path, (string) $prefix) === 0) {
            return true;
        }
    }
    return false;
}

// What an update changed is trusted for two hours; the check runs a minute later.
add_action('upgrader_process_complete', function ($upgrader, $options) {
    if (!isset($options['action']) || $options['action'] !== 'update') {
        return;
    }
    $type = isset($options['type']) ? (string) $options['type'] : '';
    $prefixes = array();
    if ($type === 'plugin') {
        foreach (isset($options['plugins']) ? (array) $options['plugins'] : array() as $plugin) {
            $dir = dirname((string) $plugin);
            $prefixes[] = wp_normalize_path(WP_PLUGIN_DIR . '/' . ($dir === '.' ? $plugin : $dir . '/'));
        }
    } elseif ($type === 'theme') {
        foreach (isset($options['themes']) ? (array) $options['themes'] : array() as $theme) {
            $prefixes[] = wp_normalize_path(get_theme_root((string) $theme) . '/' . $theme . '/');
        }
    } elseif ($type === 'translation') {
        $prefixes[] = wp_normalize_path(WP_LANG_DIR . '/');
    }
    if (!$prefixes && $type !== 'core') {
        return;
    }
    $trusted = get_option(SITE_ANALYTICS_FILES_TRUSTED, array());
    $trusted = array_filter(is_array($trusted) ? $trusted : array(), function ($until) {
        return (int) $until >= time();
    });
    foreach ($prefixes as $prefix) {
        $trusted[$prefix] = time() + 2 * HOUR_IN_SECONDS;
    }
    update_option(SITE_ANALYTICS_FILES_TRUSTED, $trusted, false);
    wp_schedule_single_event(time() + 60, SITE_ANALYTICS_FILES_HOOK, array(true));
}, 20, 2);

add_action(SITE_ANALYTICS_FILES_HOOK, function ($force = false) {
    if (function_exists('set_time_limit')) {
        @set_time_limit(300);
    }
    site_analytics_platform()->checkFiles((bool) $force);
});

add_action('init', function () {
    if (site_analytics_platform()->configured() && !wp_next_scheduled(SITE_ANALYTICS_FILES_HOOK)) {
        wp_schedule_event(time() + 300, 'hourly', SITE_ANALYTICS_FILES_HOOK);
    }
});

register_deactivation_hook(__FILE__, function () {
    wp_clear_scheduled_hook(SITE_ANALYTICS_FILES_HOOK);
});

// wp site-analytics files: check now. wp site-analytics accept-files: after a deploy.
if (defined('WP_CLI') && WP_CLI) {
    WP_CLI::add_command('site-analytics files', function () {
        $changes = site_analytics_platform()->checkFiles(true);
        WP_CLI::log(count($changes) . ' file(s) differ from the accepted version');
        foreach (array_slice($changes, 0, 50) as $change) {
            WP_CLI::log(sprintf('  %-8s %s%s', $change['change'], $change['path'], !empty($change['signals']) ? '  [' . implode(', ', $change['signals']) . ']' : ''));
        }
    });
    WP_CLI::add_command('site-analytics accept-files', function () {
        site_analytics_platform()->checkFiles(true, true);
        WP_CLI::success('The files as they are now are the accepted version.');
    });
}

// ---- Software inventory ------------------------------------------------------------

// The Inventory module (lib/Inventory.php, protocol in sdk/protocols/inventory.md):
// once a day WP-Cron reports WordPress's, PHP's and every plugin's and theme's
// version (plus a composer.lock, if the site has one), so the dashboard's
// Security check can flag known security holes in them. Again a few minutes
// after an update or install, so fixed versions show up soon.
const SITE_ANALYTICS_INVENTORY_HOOK = 'site_analytics_inventory_check';

function site_analytics_inventory_options()
{
    global $wp_version;
    return array(
        'manual' => true,
        'runtime' => array('wordpress' => (string) $wp_version),
        'packages' => 'site_analytics_inventory_packages',
    );
}

// Plugins (must-use ones too) and themes. A plugin's slug is its folder, or
// its file's name for a single-file plugin, as on WordPress.org.
function site_analytics_inventory_packages()
{
    if (!function_exists('get_plugins')) {
        require_once ABSPATH . 'wp-admin/includes/plugin.php';
    }
    $slug = function ($file) {
        $dir = dirname((string) $file);
        return $dir === '.' ? basename((string) $file, '.php') : $dir;
    };
    $packages = array();
    foreach (get_plugins() as $file => $data) {
        $packages[] = array(
            'ecosystem' => 'wordpress-plugin', 'name' => $slug($file), 'version' => isset($data['Version']) ? (string) $data['Version'] : '',
            'active' => is_plugin_active($file) || (is_multisite() && is_plugin_active_for_network($file)),
        );
    }
    foreach (get_mu_plugins() as $file => $data) {
        $packages[] = array(
            'ecosystem' => 'wordpress-plugin', 'name' => $slug($file), 'version' => isset($data['Version']) ? (string) $data['Version'] : '', 'active' => true,
        );
    }
    $active = array(get_stylesheet(), get_template());
    foreach (wp_get_themes() as $stylesheet => $theme) {
        $packages[] = array(
            'ecosystem' => 'wordpress-theme', 'name' => (string) $stylesheet, 'version' => (string) $theme->get('Version'),
            'active' => in_array($stylesheet, $active, true),
        );
    }
    return $packages;
}

add_action(SITE_ANALYTICS_INVENTORY_HOOK, function () {
    site_analytics_platform()->checkInventory(true);
});

add_action('init', function () {
    if (site_analytics_platform()->configured() && !wp_next_scheduled(SITE_ANALYTICS_INVENTORY_HOOK)) {
        wp_schedule_event(time() + 120, 'daily', SITE_ANALYTICS_INVENTORY_HOOK);
    }
});

add_action('upgrader_process_complete', function ($upgrader, $options) {
    if (!wp_next_scheduled(SITE_ANALYTICS_INVENTORY_HOOK, array('update'))) {
        wp_schedule_single_event(time() + 180, SITE_ANALYTICS_INVENTORY_HOOK, array('update'));
    }
}, 20, 2);

register_deactivation_hook(__FILE__, function () {
    wp_clear_scheduled_hook(SITE_ANALYTICS_INVENTORY_HOOK);
});

// wp site-analytics inventory: report now.
if (defined('WP_CLI') && WP_CLI) {
    WP_CLI::add_command('site-analytics inventory', function () {
        $packages = site_analytics_platform()->checkInventory(true);
        WP_CLI::log(count($packages) . ' package(s) reported');
    });
}

// ---- How the site is set up (sdk/protocols/posture.md) ----------------------------

// Once a day WP-Cron reports the settings that leave the site open, who has
// administrator rights, WordPress's scheduled jobs, and files in the web folder
// that should never be public, so the dashboard's Security check can say what
// to change (Security → Security check). It only reads: the plugin never
// changes a setting, a permission or a file, and never sends a file's contents.
const SITE_ANALYTICS_POSTURE_HOOK = 'site_analytics_posture_check';
// Logins the plugin has seen, so "nobody has used this administrator account
// for months" can be said at all. WordPress itself doesn't record it.
const SITE_ANALYTICS_LAST_LOGIN = 'site_analytics_last_login';
// Two-factor plugins: any one of these being active is enough.
const SITE_ANALYTICS_2FA_PLUGINS = array(
    'two-factor', 'wp-2fa', 'miniorange-2-factor-authentication', 'google-authenticator',
    'duo-universal', 'wordfence', 'ithemes-security-pro', 'better-wp-security', 'all-in-one-wp-security-and-firewall',
);

function site_analytics_posture_options()
{
    return array(
        'manual' => true,
        'roots' => array(ABSPATH),
        'exclude' => array(WP_CONTENT_DIR . '/cache', WP_CONTENT_DIR . '/upgrade', site_analytics_platform_storage()),
        // The client's name and version reach us in the User-Agent (Core).
        'facts' => array('webroot' => ABSPATH),
        'checks' => 'site_analytics_posture_checks',
        'accounts' => 'site_analytics_posture_accounts',
        'persistence' => 'site_analytics_posture_persistence',
    );
}

// A constant that is defined and true.
function site_analytics_posture_on($name)
{
    return defined($name) && constant($name);
}

// pass / fail / unknown for each WordPress setting. Nothing is changed here.
function site_analytics_posture_checks()
{
    $checks = array();
    $add = function ($id, $fail, $value = '') use (&$checks) {
        $row = array('id' => $id, 'state' => $fail === null ? 'unknown' : ($fail ? 'fail' : 'pass'));
        if ($value !== '') {
            $row['value'] = $value;
        }
        $checks[] = $row;
    };

    $add('wp.file_edit', !site_analytics_posture_on('DISALLOW_FILE_EDIT'));
    $add('wp.file_mods', !site_analytics_posture_on('DISALLOW_FILE_MODS'));
    $add('wp.debug_display', site_analytics_posture_on('WP_DEBUG')
        && (!defined('WP_DEBUG_DISPLAY') || constant('WP_DEBUG_DISPLAY')));
    // A log inside the web folder; WP_DEBUG_LOG true means wp-content/debug.log.
    $log = defined('WP_DEBUG_LOG') ? constant('WP_DEBUG_LOG') : false;
    $logPath = $log === true ? WP_CONTENT_DIR . '/debug.log' : (is_string($log) ? $log : '');
    $add('wp.debug_log', $logPath !== '' && strpos(wp_normalize_path($logPath), wp_normalize_path(ABSPATH)) === 0);

    // wp-config.php can be one folder above the site, as WordPress allows.
    $config = file_exists(ABSPATH . 'wp-config.php') ? ABSPATH . 'wp-config.php'
        : (file_exists(dirname(ABSPATH) . '/wp-config.php') ? dirname(ABSPATH) . '/wp-config.php' : '');
    if ($config) {
        $mode = @fileperms($config);
        $add('wp.config_writable', $mode !== false && ($mode & 0002) !== 0);
        // The example keys: a forged login cookie is enough to be an administrator.
        $example = false;
        $text = @file_get_contents($config, false, null, 0, 65536);
        if (is_string($text) && $text !== '') {
            $example = strpos($text, 'put your unique phrase here') !== false;
        }
        $add('wp.default_salts', is_string($text) && $text !== '' ? $example : null);
    }

    $add('wp.auto_update_core', site_analytics_posture_on('AUTOMATIC_UPDATER_DISABLED')
        || (defined('WP_AUTO_UPDATE_CORE') && constant('WP_AUTO_UPDATE_CORE') === false));
    $add('wp.force_ssl_admin', strpos((string) get_option('siteurl'), 'https://') === 0 && !force_ssl_admin());
    $add('wp.db_prefix', isset($GLOBALS['wpdb']) && $GLOBALS['wpdb']->prefix === 'wp_');

    // Anyone can register *and* gets more than Subscriber.
    $role = (string) get_option('default_role');
    $add('wp.open_registration', (bool) get_option('users_can_register') && $role !== '' && $role !== 'subscriber');

    // Nothing stops PHP running in the uploads folder (Apache reads .htaccess;
    // on nginx the rule is in its config, which the plugin can't see: unknown).
    $uploads = wp_get_upload_dir();
    $guard = isset($uploads['basedir']) ? $uploads['basedir'] . '/.htaccess' : '';
    $apache = isset($_SERVER['SERVER_SOFTWARE']) && stripos((string) $_SERVER['SERVER_SOFTWARE'], 'apache') !== false;
    if ($guard && $apache) {
        $rules = @is_file($guard) ? (string) @file_get_contents($guard, false, null, 0, 8192) : '';
        $add('wp.uploads_guard', !preg_match('/php_flag\s+engine\s+off|php_admin_flag\s+engine\s+off|Deny from all|Require all denied|SetHandler\s+none|RemoveHandler/i', $rules));
    } elseif ($guard) {
        $add('wp.uploads_guard', null);
    }

    // xmlrpc.php: off when something filtered it off, on otherwise.
    $add('wp.xmlrpc', (bool) apply_filters('xmlrpc_enabled', (bool) get_option('enable_xmlrpc', true)));

    // An account called admin, and whether anything does two-factor.
    $named = get_users(array('login__in' => array('admin', 'administrator'), 'fields' => 'ID', 'number' => 1));
    $add('wp.admin_user', !empty($named));
    $active = array();
    foreach ((array) get_option('active_plugins', array()) as $file) {
        $dir = dirname((string) $file);
        $active[] = $dir === '.' ? basename((string) $file, '.php') : $dir;
    }
    if (is_multisite()) {
        foreach (array_keys((array) get_site_option('active_sitewide_plugins', array())) as $file) {
            $dir = dirname((string) $file);
            $active[] = $dir === '.' ? basename((string) $file, '.php') : $dir;
        }
    }
    $admins = count(get_users(array('role' => 'administrator', 'fields' => 'ID', 'number' => 100)));
    $add('wp.two_factor', !array_intersect($active, SITE_ANALYTICS_2FA_PLUGINS), $admins ? $admins . ' administrators' : '');
    return $checks;
}

// Who has full rights: login names only — never email addresses, never hashes.
function site_analytics_posture_accounts()
{
    $admins = array();
    foreach (get_users(array('role' => 'administrator', 'number' => AnalyticsPlatform\Posture::MAX_ADMINS, 'orderby' => 'ID')) as $user) {
        $row = array('name' => (string) $user->user_login, 'roles' => array_slice((array) $user->roles, 0, 3));
        if (!empty($user->user_registered)) {
            $row['created'] = gmdate('Y-m-d\TH:i:s\Z', (int) strtotime($user->user_registered . ' UTC'));
        }
        $last = (int) get_user_meta($user->ID, SITE_ANALYTICS_LAST_LOGIN, true);
        if ($last) {
            $row['last_login'] = gmdate('Y-m-d\TH:i:s\Z', $last);
        }
        $admins[] = $row;
    }
    // One indexed count, not count_users(): that groups over usermeta and is
    // slow on a site with many accounts.
    $total = isset($GLOBALS['wpdb']) ? (int) $GLOBALS['wpdb']->get_var('SELECT COUNT(ID) FROM ' . $GLOBALS['wpdb']->users) : count($admins);
    return array('total' => $total ? $total : count($admins), 'admins' => $admins);
}

// WordPress's scheduled jobs. `handler: false` means nothing registers it any
// more: what a badly removed plugin leaves, and what a backdoor looks like
// once its file is gone.
function site_analytics_posture_persistence()
{
    if (!function_exists('_get_cron_array')) {
        return array();
    }
    $jobs = array();
    // One row per hook: Action Scheduler, WooCommerce and backup plugins queue
    // the same hook at dozens of times, which would fill the list and push a
    // job scheduled later (the one that matters) past the end.
    $seen = array();
    foreach ((array) _get_cron_array() as $events) {
        foreach ((array) $events as $hook => $runs) {
            if (isset($seen[$hook])) {
                continue;
            }
            if (count($jobs) >= AnalyticsPlatform\Posture::MAX_CRON) {
                break 2;
            }
            $seen[$hook] = true;
            $first = is_array($runs) ? reset($runs) : array();
            $jobs[] = array(
                'kind' => 'wp-cron',
                'name' => (string) $hook,
                'schedule' => isset($first['schedule']) && $first['schedule'] ? (string) $first['schedule'] : 'once',
                'handler' => has_action($hook) ? true : false,
            );
        }
    }
    return array('cron' => $jobs);
}

// Records the login so dormant administrator accounts can be spotted.
add_action('wp_login', function ($login, $user = null) {
    if ($user instanceof WP_User) {
        update_user_meta($user->ID, SITE_ANALYTICS_LAST_LOGIN, time());
    }
}, 5, 2);

add_action(SITE_ANALYTICS_POSTURE_HOOK, function () {
    site_analytics_platform()->checkPosture(true);
});

add_action('init', function () {
    if (site_analytics_platform()->configured() && !wp_next_scheduled(SITE_ANALYTICS_POSTURE_HOOK)) {
        // Not at the same minute as the inventory report: one job at a time.
        wp_schedule_event(time() + 600, 'daily', SITE_ANALYTICS_POSTURE_HOOK);
    }
});

register_deactivation_hook(__FILE__, function () {
    wp_clear_scheduled_hook(SITE_ANALYTICS_POSTURE_HOOK);
});

// wp site-analytics posture: report now and list what failed.
if (defined('WP_CLI') && WP_CLI) {
    WP_CLI::add_command('site-analytics posture', function () {
        $failed = site_analytics_platform()->checkPosture(true);
        if (!$failed) {
            WP_CLI::success('Reported; nothing failed (or the report could not be sent).');
            return;
        }
        WP_CLI::log(count($failed) . ' check(s) failed:');
        foreach ($failed as $id) {
            WP_CLI::log('  ' . $id);
        }
    });
}

// ---- Settings page --------------------------------------------------------------

add_action('admin_menu', function () {
    add_options_page(SITE_ANALYTICS_NAME, SITE_ANALYTICS_NAME, 'manage_options', 'site-analytics', 'site_analytics_platform_page');
});

add_filter('plugin_action_links_' . plugin_basename(__FILE__), function ($links) {
    array_unshift($links, '<a href="' . esc_url(admin_url('options-general.php?page=site-analytics')) . '">Settings</a>');
    return $links;
});

function site_analytics_platform_save()
{
    $settings = site_analytics_platform_settings();
    $field = function ($name, $default = '') {
        return isset($_POST[$name]) ? trim(sanitize_text_field(wp_unslash($_POST[$name]))) : $default;
    };
    $siteId = strtolower($field('site_id'));
    if ($siteId !== '' && !preg_match('/^[a-f0-9]{24}$/D', $siteId)) {
        return array('error', 'The site ID is 24 letters and numbers (0-9, a-f).');
    }
    $settings['site_id'] = $siteId;
    $settings['endpoint'] = untrailingslashit(esc_url_raw($field('endpoint')));
    if ($field('secret') !== '') {
        $settings['secret'] = $field('secret');
    }
    $proxy = $field('trust_proxy', '0');
    $settings['trust_proxy'] = in_array($proxy, array('0', '1', '2', 'cloudflare'), true) ? $proxy : '0';
    $settings['tracker'] = isset($_POST['tracker']) ? '1' : '0';
    $settings['identify'] = isset($_POST['identify']) ? '1' : '0';
    $settings['proxy'] = isset($_POST['proxy']) ? '1' : '0';
    update_option(SITE_ANALYTICS_OPTION, $settings, true);
    site_analytics_tracker_release_check();
    $platform = site_analytics_platform_make($settings);
    if (!$platform->configured()) {
        site_analytics_proxy_refresh($settings, $platform);
        return array('warning', 'Saved. Add the site secret to turn on the firewall, WooCommerce orders and error monitoring.');
    }
    $proxy = site_analytics_proxy_refresh($settings, $platform);
    if (!($platform->firewall() && $platform->firewall()->sync(true))) {
        return array('error', 'Saved, but we could not connect. Check the site ID, secret and collector URL.');
    }
    if ($settings['proxy'] !== '1' || $settings['tracker'] !== '1') {
        return array('success', 'Saved and connected.');
    }
    if ($proxy['mode'] !== '') {
        return array('success', 'Saved and connected. The tracker is served from this site\'s own domain, so visitors with an ad blocker are counted too.');
    }
    return array('warning', !empty($proxy['unreachable'])
        ? 'Saved and connected, but we could not reach this site from itself to set up serving the tracker from your own domain, so it stays switched off. This is usually a host that blocks loopback requests.'
        : 'Saved and connected. Serving the tracker from your own domain did not work on this server, so it stays switched off: the tracker loads from us, and visitors with an ad blocker may not be counted.');
}

// One card in the status grid. $state is 'on', 'off' or 'warn' and only
// chooses the dot's colour; the words carry the meaning for anyone who
// can't see it.
function site_analytics_status_card($label, $state, $value, $note = '')
{
    ?>
    <div class="sa-card sa-<?php echo esc_attr($state); ?>">
        <p class="sa-label"><?php echo esc_html($label); ?></p>
        <p class="sa-value"><span class="sa-dot" aria-hidden="true"></span><?php echo esc_html($value); ?></p>
        <?php if ($note !== '') : ?>
            <p class="sa-note"><?php echo esc_html($note); ?></p>
        <?php endif; ?>
    </div>
    <?php
}

function site_analytics_platform_page()
{
    if (!current_user_can('manage_options')) {
        return;
    }
    $notice = null;
    if (isset($_POST['site_analytics_save'])) {
        check_admin_referer('site_analytics_save');
        $notice = site_analytics_platform_save();
    }
    $settings = site_analytics_platform_settings();
    // Read fresh: the rules may have just been fetched.
    $platform = site_analytics_platform_make($settings);
    $firewall = $platform->firewall();
    $status = $platform->configured() && $firewall ? $firewall->status() : null;
    $seen = $firewall ? $firewall->clientIp() : '';
    $direct = isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '';
    // Forwarding headers from a private or Cloudflare address: a proxy of
    // the site's. From a public address the web server may already have put
    // the visitor in REMOTE_ADDR (mod_remoteip), and what is left in the
    // header is the visitor's own writing: no hint to trust it then.
    $forwarded = (!empty($_SERVER['HTTP_X_FORWARDED_FOR']) || !empty($_SERVER['HTTP_CF_CONNECTING_IP']))
        && (filter_var($direct, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false
            || AnalyticsPlatform\Firewall::fromCloudflare($direct));
    $storage = site_analytics_platform_storage();
    $ready = $platform->configured();
    $proxy = site_analytics_proxy_state();
    $name = SITE_ANALYTICS_NAME;

    // The one line at the top: what a glance should answer.
    if (!$settings['site_id']) {
        $head = array('off', 'Not set up yet', 'Enter the site ID below.');
    } elseif (!$ready) {
        $head = array('warn', 'Site secret needed', 'The tracker works; the firewall and the rest do not.');
    } elseif ($status) {
        $head = array('on', 'Connected', 'Rules fetched ' . human_time_diff($status['fetched']) . ' ago.');
    } else {
        $head = array('warn', 'No rules fetched yet', 'Check the site ID, secret and collector URL.');
    }

    $cards = array();
    $cards[] = array(
        'Tracker',
        $settings['tracker'] === '1' && $settings['site_id'] ? 'on' : 'off',
        $settings['tracker'] === '1' && $settings['site_id'] ? 'On' : 'Off',
        'The script on every page: version ' . site_analytics_tracker_release()['version'] . ', locked to its fingerprint so nothing else can run in its place.',
    );
    if ($settings['proxy'] !== '1') {
        $cards[] = array('Ad blockers', 'off', 'Off', 'The tracker loads from the collector, which many ad blockers stop.');
    } elseif ($proxy['mode'] === 'pretty') {
        $cards[] = array('Ad blockers', 'on', 'Working', 'Served from ' . wp_parse_url($proxy['base'], PHP_URL_PATH) . '/ on your own domain.');
    } elseif ($proxy['mode'] === 'file') {
        $cards[] = array('Ad blockers', 'on', 'Working', "This server ignores the rewrite rule, so the plugin's own address is used.");
    } else {
        $cards[] = array('Ad blockers', 'warn', 'Not working yet', 'The tracker loads from the collector meanwhile. Save again to retry.');
    }
    if (!class_exists('WooCommerce')) {
        $cards[] = array('WooCommerce orders', 'off', 'Not active', "WooCommerce isn't installed on this site.");
    } else {
        $cards[] = $ready
            ? array('WooCommerce orders', 'on', 'On', 'Paid orders and refunds sent from your server.')
            : array('WooCommerce orders', 'warn', 'Needs the site secret', '');
    }
    if (!$status) {
        $cards[] = $ready
            ? array('Firewall', 'warn', 'No rules yet', 'Nothing has been fetched from your dashboard.')
            : array('Firewall', 'warn', 'Needs the site secret', '');
    } else {
        if (!$status['enabled']) {
            $state = 'off';
            $value = 'Off in your dashboard';
        } elseif ($status['mode'] === 'block') {
            $state = 'on';
            $value = 'Blocking';
        } else {
            $state = 'on';
            $value = 'Monitoring';
        }
        $cards[] = array('Firewall', $state, $value, 'Rules fetched ' . human_time_diff($status['fetched']) . ' ago.');
        $cards[] = array(
            'Addresses and ranges',
            'on',
            number_format_i18n($status['ranges']['lists']) . ' networks',
            sprintf(
                '%s blocked by you, %s allowed, %s reported by other sites.',
                number_format_i18n($status['ranges']['deny']),
                number_format_i18n($status['ranges']['allow']),
                number_format_i18n($status['ranges']['shared'])
            ),
        );
        if (!$status['rate']) {
            $cards[] = array('Rate limit', 'off', 'Off', 'Turn it on in your dashboard.');
        } elseif ($status['rate_available']) {
            $cards[] = array('Rate limit', 'on', sprintf('%s a minute', number_format_i18n($status['rate']['limit'])), 'Per address.');
        } else {
            $cards[] = array('Rate limit', 'warn', 'Not working here', 'Needs the APCu PHP extension or a persistent object cache (Redis, Memcached). Ask your host.');
        }
        $cards[] = $status['enabled'] && !empty($status['challenge'])
            ? array('Browser check', 'on', 'On', "A visitor's first page each day sets a cookie with JavaScript, which bots that flood pages don't run.")
            : array('Browser check', 'off', 'Off', 'Flood protection in your dashboard.');
    }
    $cards[] = $ready
        ? array('Form protection', 'on', 'On', 'Comments, sign-ups, Contact Form 7 and Gravity Forms, with "Protect every form" on.')
        : array('Form protection', 'warn', 'Needs the site secret', '');
    $cards[] = $ready
        ? array('Audit log', 'on', 'On', 'Logins, users and roles, plugins, themes, updates, content and settings.')
        : array('Audit log', 'warn', 'Needs the site secret', '');
    $cards[] = $ready
        ? array('Server speed', 'on', 'On', 'Response times by kind of page, REST route and ajax action.')
        : array('Server speed', 'warn', 'Needs the site secret', '');
    $cards[] = $ready
        ? array('Error monitoring', 'on', 'On', 'PHP errors sent to the collector.')
        : array('Error monitoring', 'warn', 'Needs the site secret', '');
    ?>
    <style>
    .sa-wrap{max-width:1120px}
    .sa-head{display:flex;align-items:center;gap:16px;background:#fff;border:1px solid #c3c4c7;border-left-width:4px;padding:16px 20px;margin:16px 0 4px;border-radius:4px}
    .sa-head.sa-on{border-left-color:#00a32a}
    .sa-head.sa-warn{border-left-color:#dba617}
    .sa-head.sa-off{border-left-color:#c3c4c7}
    .sa-logo{width:46px;height:46px;border-radius:9px;background:#2271b1;color:#fff;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:17px;letter-spacing:.02em;flex:0 0 auto;overflow:hidden}
    .sa-logo img{width:100%;height:100%;object-fit:cover;display:block}
    .sa-head h1{margin:0;padding:0;font-size:20px;line-height:1.3}
    .sa-head .sa-state{margin:3px 0 0;color:#50575e;display:flex;align-items:center;gap:7px;font-size:13px}
    .sa-head .sa-state strong{color:#1d2327;font-weight:600}
    .sa-head .sa-actions{margin-left:auto;flex:0 0 auto}
    .sa-intro{color:#50575e;margin:0 0 4px;max-width:760px}
    .sa-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(230px,1fr));gap:12px;margin:14px 0 8px}
    .sa-card{background:#fff;border:1px solid #c3c4c7;border-radius:4px;padding:12px 14px}
    .sa-card .sa-label{color:#646970;font-size:11px;text-transform:uppercase;letter-spacing:.05em;margin:0 0 7px;font-weight:600}
    .sa-card .sa-value{font-size:15px;font-weight:600;margin:0;display:flex;align-items:center;gap:8px;color:#1d2327}
    .sa-card .sa-note{color:#646970;font-size:12px;margin:7px 0 0;line-height:1.55}
    .sa-dot{width:9px;height:9px;border-radius:50%;flex:0 0 auto;display:inline-block}
    .sa-on .sa-dot{background:#00a32a}
    .sa-off .sa-dot{background:#c3c4c7}
    .sa-warn .sa-dot{background:#dba617}
    .sa-section{margin:26px 0 10px;font-size:12px;text-transform:uppercase;letter-spacing:.05em;color:#646970;font-weight:600}
    .sa-panel{background:#fff;border:1px solid #c3c4c7;border-radius:4px;padding:2px 18px 10px}
    .sa-panel .form-table th{width:170px}
    .sa-seen{margin:14px 0 0;color:#50575e;font-size:13px}
    @media (max-width:782px){.sa-head{flex-wrap:wrap}.sa-head .sa-actions{margin-left:0;width:100%}}
    </style>
    <div class="wrap sa-wrap">
        <div class="sa-head sa-<?php echo esc_attr($head[0]); ?>">
            <div class="sa-logo">
                <?php if (SITE_ANALYTICS_LOGO !== '') : ?>
                    <img src="<?php echo esc_url(SITE_ANALYTICS_LOGO); ?>" alt="">
                <?php else : ?>
                    <?php echo esc_html(site_analytics_initials($name)); ?>
                <?php endif; ?>
            </div>
            <div>
                <h1><?php echo esc_html($name); ?></h1>
                <p class="sa-state">
                    <span class="sa-dot" aria-hidden="true"></span>
                    <strong><?php echo esc_html($head[1]); ?></strong>
                    <span><?php echo esc_html($head[2]); ?></span>
                </p>
            </div>
            <?php if (SITE_ANALYTICS_DASHBOARD !== '') : ?>
                <div class="sa-actions">
                    <a class="button button-secondary" href="<?php echo esc_url(SITE_ANALYTICS_DASHBOARD); ?>" target="_blank" rel="noopener">Open dashboard</a>
                </div>
            <?php endif; ?>
        </div>
        <p class="sa-intro">Reports, firewall rules and module switches live in your analytics dashboard. This page only holds what WordPress itself has to know.</p>

        <?php if ($notice) : ?>
            <div class="notice notice-<?php echo esc_attr($notice[0]); ?>"><p><?php echo esc_html($notice[1]); ?></p></div>
        <?php endif; ?>
        <?php if (function_exists('site_analytics_script_attrs')) : ?>
            <div class="notice notice-warning"><p>The tracker is also added by older <?php echo esc_html($name); ?> code (another plugin or your theme). This plugin leaves the tracker to it: remove the old copy to let this plugin load it.</p></div>
        <?php endif; ?>
        <?php if (!wp_mkdir_p($storage) || !wp_is_writable($storage)) : ?>
            <div class="notice notice-error"><p><?php echo esc_html(sprintf('WordPress can\'t write to %s, so the firewall can\'t keep its rules. Make it writable.', $storage)); ?></p></div>
        <?php endif; ?>

        <div class="sa-grid">
            <?php foreach ($cards as $card) : ?>
                <?php site_analytics_status_card($card[0], $card[1], $card[2], $card[3]); ?>
            <?php endforeach; ?>
        </div>

        <form method="post">
            <?php wp_nonce_field('site_analytics_save'); ?>

            <p class="sa-section">Connection</p>
            <div class="sa-panel">
                <table class="form-table" role="presentation">
                    <tr>
                        <th scope="row"><label for="sa-site">Site ID</label></th>
                        <td><input id="sa-site" name="site_id" type="text" class="regular-text code" value="<?php echo esc_attr($settings['site_id']); ?>"></td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="sa-endpoint">Collector URL</label></th>
                        <td><input id="sa-endpoint" name="endpoint" type="url" class="regular-text code" value="<?php echo esc_attr($settings['endpoint']); ?>"></td>
                    </tr>
                    <tr>
                        <th scope="row"><label for="sa-secret">Site secret</label></th>
                        <td>
                            <input id="sa-secret" name="secret" type="password" class="regular-text code" autocomplete="off"
                                placeholder="<?php echo $settings['secret'] ? esc_attr('Saved: leave empty to keep it') : ''; ?>">
                            <p class="description">In your analytics dashboard: Site settings. Needed for WooCommerce orders, the firewall and error monitoring; the tracker works without it.</p>
                        </td>
                    </tr>
                </table>
            </div>

            <p class="sa-section">Tracking</p>
            <div class="sa-panel">
                <table class="form-table" role="presentation">
                    <tr>
                        <th scope="row">Tracker</th>
                        <td><label><input type="checkbox" name="tracker" value="1" <?php checked($settings['tracker'], '1'); ?>> Add the tracker to every page</label></td>
                    </tr>
                    <tr>
                        <th scope="row">Ad blockers</th>
                        <td>
                            <label><input type="checkbox" name="proxy" value="1" <?php checked($settings['proxy'], '1'); ?>> Serve the tracker from this site's own domain, so visitors with an ad blocker are counted too</label>
                            <p class="description">
                                <?php if ($settings['proxy'] !== '1') : ?>
                                    Off: the tracker loads from the collector, which many ad blockers recognise and stop.
                                <?php elseif ($proxy['mode'] === 'pretty') : ?>
                                    Working, through <code><?php echo esc_html(wp_parse_url($proxy['base'], PHP_URL_PATH)); ?>/</code> on your own domain.
                                <?php elseif ($proxy['mode'] === 'file') : ?>
                                    Working. This server ignores the rewrite rule (usually nginx), so the plugin's own address is used instead.
                                <?php else : ?>
                                    Not working on this server yet; the tracker loads from the collector meanwhile. Save again to retry.
                                <?php endif; ?>
                                Checked when you save.
                            </p>
                        </td>
                    </tr>
                    <tr>
                        <th scope="row">Logins</th>
                        <td><label><input type="checkbox" name="identify" value="1" <?php checked($settings['identify'], '1'); ?>> Link visits to the WordPress user who logs in (their user ID only)</label></td>
                    </tr>
                </table>
            </div>

            <p class="sa-section">Network</p>
            <div class="sa-panel">
                <table class="form-table" role="presentation">
                    <tr>
                        <th scope="row"><label for="sa-proxy">Proxy</label></th>
                        <td>
                            <select id="sa-proxy" name="trust_proxy">
                                <?php foreach (array('0' => 'None: visitors connect straight to this server', '1' => 'One proxy or load balancer', '2' => 'Two proxies (such as Cloudflare in front of a load balancer)', 'cloudflare' => 'Cloudflare (every request comes through it)') as $value => $label) : ?>
                                    <option value="<?php echo esc_attr($value); ?>" <?php selected($settings['trust_proxy'], (string) $value); ?>><?php echo esc_html($label); ?></option>
                                <?php endforeach; ?>
                            </select>
                            <p class="description">Only choose a proxy you really have: otherwise visitors can pretend to be any address.
                                Count only proxies that add to <code>X-Forwarded-For</code>. If your host already puts the visitor's address in
                                <code>REMOTE_ADDR</code> (Apache's mod_remoteip, nginx's real_ip, LiteSpeed's "Use Client IP in Header"), keep None:
                                such a server takes the proxy's entry out of the header, so counting it again would read one the visitor wrote.</p>
                            <p class="sa-seen">
                                Your address, as the firewall sees it: <code><?php echo esc_html($seen); ?></code>
                                <?php if ($settings['trust_proxy'] === '0' && $forwarded) : ?>
                                    <br><strong>Your site seems to be behind a proxy (such as Cloudflare or a load balancer).</strong> If this isn't your address, choose your setup above, or every visitor will look like the proxy.
                                <?php elseif ($seen !== $direct) : ?>
                                    <br>Read from your proxy's header (the connection came from <code><?php echo esc_html($direct); ?></code>).
                                <?php endif; ?>
                            </p>
                        </td>
                    </tr>
                </table>
            </div>

            <?php submit_button('Save', 'primary', 'site_analytics_save'); ?>
        </form>
    </div>
    <?php
}
