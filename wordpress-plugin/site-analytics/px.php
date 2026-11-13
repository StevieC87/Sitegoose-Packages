<?php
// The first-party proxy's front door on WordPress: serving the tracker from
// the site's own domain, so ad blockers don't hide visitors. What it does and
// why is in lib/Proxy.php, which holds the whole of it and is shared with the
// other packages.
//
// This file is deliberately NOT part of WordPress: it is reached directly, so
// no plugin, theme or database is loaded for a beacon. It reads px/<prefix>.php,
// written by the plugin whenever the settings are saved (site-analytics.php),
// one per site: the prefix in the address says which. Without that file it
// answers 404 and nothing happens.

require_once __DIR__ . '/lib/Proxy.php';
// The firewall's address rules (deny, bans, lists) and its address helpers:
// nothing else of the package loads.
require_once __DIR__ . '/lib/Core.php';
require_once __DIR__ . '/lib/Firewall.php';

// Which site the request is for: its prefix, from the .htaccess rule (sa_k),
// or the first part of PATH_INFO when this file is asked for directly.
function sa_px_prefix()
{
    if (isset($_GET['sa_k'])) {
        $prefix = is_string($_GET['sa_k']) ? $_GET['sa_k'] : '';
    } else {
        $info = isset($_SERVER['PATH_INFO']) ? ltrim((string) $_SERVER['PATH_INFO'], '/') : '';
        $prefix = (string) strtok($info, '/');
    }
    // It names a file below, so nothing but what Proxy::prefixFor() makes.
    return preg_match('/^[a-f0-9]{8}$/D', $prefix) ? $prefix : '';
}

function sa_px_config($prefix)
{
    if ($prefix === '') {
        return null;
    }
    // The storage folder first (it outlives plugin updates), else this
    // plugin's folder; the plugin writes to the first it can
    // (site_analytics_proxy_config_dirs()).
    foreach (array(dirname(__DIR__, 2) . '/cache/site-analytics/px', __DIR__ . '/px') as $dir) {
        $path = $dir . '/' . $prefix . '.php';
        if (is_file($path)) {
            $config = include $path;
            if (is_array($config) && !empty($config['endpoint']) && isset($config['prefix']) && $config['prefix'] === $prefix) {
                return $config;
            }
        }
    }
    return null;
}

// What the visitor's address is, per the plugin's "Proxy" setting: the
// package's own rule (Firewall::clientIpFrom()), so the two never differ.
// CF-Connecting-IP only from Cloudflare's own addresses: anyone who reaches
// the server directly can send it.
function sa_px_client_ip($trust)
{
    return \AnalyticsPlatform\Firewall::clientIpFrom($_SERVER, $trust === 'cloudflare' ? 'cloudflare' : (int) $trust);
}

// The firewall's verdict on the address alone: a denied or banned address
// gets nothing from us either, while beacons are never rate-limited, checked
// or matched against request rules. Read from the rules the plugin keeps in
// its storage folder; blocked addresses are reported from there too. Fails open.
function sa_px_blocked(array $config, $ip, $method, $path)
{
    if (empty($config['site_id']) || empty($config['dir']) || !is_dir($config['dir'])) {
        return false;
    }
    try {
        $core = new \AnalyticsPlatform\Core(array('site_id' => $config['site_id'], 'secret' => '', 'endpoint' => $config['endpoint'], 'dir' => $config['dir']));
        $firewall = new \AnalyticsPlatform\Firewall(array('site_id' => $config['site_id']), $core);
        $decision = $firewall->checkAddress($ip, $method, $path, isset($_SERVER['HTTP_USER_AGENT']) ? (string) $_SERVER['HTTP_USER_AGENT'] : '');
        return $decision['action'] === 'block';
    } catch (\Throwable $e) {
        return false;
    }
}

// The address asked for, from the prefix on.
function sa_px_path($prefix)
{
    // From the .htaccess rule, which keeps the pretty address.
    if (isset($_GET['sa_t'], $_GET['sa_p']) && is_string($_GET['sa_t']) && is_string($_GET['sa_p'])) {
        return '/' . $prefix . '/' . $_GET['sa_t'] . '/' . $_GET['sa_p'];
    }
    // Without it the tracker is loaded from this file directly, and the
    // address arrives as PATH_INFO, prefix first. Relative addresses inside
    // the tracker (snapshot.js and the other files it loads on demand) resolve
    // against it correctly, which a query string would not allow.
    return '/' . (isset($_SERVER['PATH_INFO']) ? ltrim($_SERVER['PATH_INFO'], '/') : $prefix);
}

$config = sa_px_config(sa_px_prefix());
if (!$config) {
    http_response_code(404);
    header('Content-Type: text/plain; charset=utf-8');
    echo 'Not found';
    exit;
}

$proxy = new AnalyticsPlatform\Proxy(
    $config['endpoint'],
    '',
    isset($config['dir']) ? $config['dir'] : '',
    // The plugin works the prefix out from the secret and writes it here, so
    // the secret itself never has to sit in a file the web server serves.
    isset($config['prefix']) ? $config['prefix'] : '',
    isset($config['key']) ? $config['key'] : ''
);
$found = $proxy->match(sa_px_path($proxy->prefix()));
if ($found === null) {
    $found = array('bad', '');
}
// Our own three parameters belong to the rewrite, not to the collector.
$query = isset($_SERVER['QUERY_STRING']) ? $_SERVER['QUERY_STRING'] : '';
if ($query !== '') {
    parse_str($query, $params);
    unset($params['sa_k'], $params['sa_t'], $params['sa_p']);
    $query = http_build_query($params);
}
$headers = array();
foreach ($_SERVER as $key => $value) {
    if (strncmp($key, 'HTTP_', 5) === 0) {
        $headers[strtolower(str_replace('_', '-', substr($key, 5)))] = $value;
    }
}
if (!empty($_SERVER['CONTENT_TYPE'])) {
    $headers['content-type'] = $_SERVER['CONTENT_TYPE'];
}
$method = isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : 'GET';
$ip = sa_px_client_ip(isset($config['trust_proxy']) ? $config['trust_proxy'] : '0');
if ($found[0] !== 'bad' && sa_px_blocked($config, $ip, $method, sa_px_path($proxy->prefix()))) {
    http_response_code(403);
    header('Content-Type: text/plain; charset=utf-8');
    header('Cache-Control: no-store');
    echo 'Forbidden';
    exit;
}
$proxy->respond($proxy->handle(
    $found[0],
    $found[1],
    $method,
    $query,
    $headers,
    strtoupper($method) === 'POST' ? file_get_contents('php://input', false, null, 0, AnalyticsPlatform\Proxy::MAX_BODY + 1) : null,
    $ip
));
