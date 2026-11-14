<?php
// The firewall module of the PHP package, run from the analytics dashboard
// (Security → Firewall); the protocol is sdk/protocols/firewall.md. Used
// through Platform (all modules) or on its own, and by the WordPress plugin,
// which ships a copy of src/ (sdk/wordpress-plugin/build.sh).
//
// PHP keeps nothing between requests, so everything lives in the storage
// directory:
// - rules.php: the last rules, compiled and written as PHP so OPcache keeps
//   them in memory. Each request includes it; nothing waits on the network.
// - Rules are fetched after the response is sent (shutdown), when older than
//   the rules' sync interval, by one request at a time (sync.lock).
// - events.jsonl: what was blocked, appended per request and sent in batches.
// Rate limits and page limits need a counter shared between requests: APCu,
// or the `counter` option; without either neither counts (a page limit
// counted per page, `each: "path"`, only ever uses APCu). The browser check
// (Challenge) needs nothing stored: its pass is signed with the site secret.
// Fails open: no rules, unreadable rules or an unreachable collector let
// every request through.

namespace AnalyticsPlatform;

class Firewall
{
    const PROTOCOL = 1;
    const MIN_SYNC = 30;
    const RETRY = 60;
    const FLUSH_EVERY = 5;
    const BATCH = 200;
    const SPOOL_MAX = 2000000; // bytes of events waiting; more are dropped
    const RULES = array('allow', 'deny', 'banned', 'lists', 'shared', 'goodbots');
    // Cloudflare's published ranges (cloudflare.com/ips), the same list as
    // sdk/protocols/cloudflare-ranges.json: CF-Connecting-IP is believed only
    // from these, since anyone who reaches the origin directly can send it.
    const CLOUDFLARE = array(
        '173.245.48.0/20', '103.21.244.0/22', '103.22.200.0/22', '103.31.4.0/22', '141.101.64.0/18',
        '108.162.192.0/18', '190.93.240.0/20', '188.114.96.0/20', '197.234.240.0/22', '198.41.128.0/17',
        '162.158.0.0/15', '104.16.0.0/13', '104.24.0.0/14', '172.64.0.0/13', '131.0.72.0/22',
        '2400:cb00::/32', '2606:4700::/32', '2803:f800::/32', '2405:b500::/32', '2405:8100::/32',
        '2a06:98c0::/29', '2c0f:f248::/32',
    );
    private static $cloudflare = null;
    // IPv4's place in ipKey()'s space: ::ffff:0.0.0.0 to ::ffff:255.255.255.255.
    const MAPPED_START = '00000000000000000000ffff00000000';
    const MAPPED_END = '00000000000000000000ffffffffffff';
    // Files a page load asks for by the dozen: not counted against `rate`
    // (the agent's nginx limit leaves the same extensions out). An address
    // already over the limit is still turned away, and one that answered an
    // error (a flood of made-up /x.css that reaches PHP) is counted after
    // the response, as the agent counts a static 404.
    // The extension follows a name in the last segment, not starts it:
    // "/login/.css" is no file. Matched on the lower-cased path.
    const STATIC_FILES = '~/[^/.][^/]*\\.(?:css|js|mjs|map|png|jpe?g|gif|webp|avif|svg|ico|bmp|woff2?|ttf|otf|eot|mp4|webm|ogg|mp3|wav|pdf|wasm)\\z~';
    // Frameworks' asset folders (firewall.md, `rate`).
    const STATIC_PREFIXES = array('/static/', '/_next/static/', '/assets/');

    private $options;
    private $core;
    private $dir;
    private $rules = null;
    private $loaded = false;
    private $reported = false;
    // What a static file would have added to, for countStatic():
    // array('rate' => array(name, ttl) or null, 'who' => ..., 'request' =>
    // RequestRules::prepare() of it, or null when no page limit applied).
    private $staticHit = null;
    // Whether the app's router sent this request to a page (markRouted()),
    // and the response's Content-Type (null: read from headers_list() then).
    private $routed = false;
    private $routedType = null;

    // Options: site_id, secret, endpoint (required); storage (a writable
    // directory; default the system temp directory); trust_proxy (0: the
    // connection's address; a number of proxies in X-Forwarded-For;
    // 'cloudflare': CF-Connecting-IP, believed only from Cloudflare's own
    // addresses); mode ('monitor' or 'block', overrides the dashboard);
    // counter (callable($key, $ttl): int, the hit count after
    // adding one); platform (for the dashboard, default 'php'); on_block
    // (callable($decision), send your own response; not for the browser
    // check, whose page has to be ours to set the pass). $core: shared with
    // the other modules (Platform passes it).
    public function __construct(array $options, ?Core $core = null)
    {
        $this->options = $options + array(
            'trust_proxy' => 0,
            'mode' => null,
            'counter' => null,
            'on_block' => null,
        );
        $this->core = $core ?: new Core($options);
        $this->dir = $this->core->dir();
        if (!$this->counterAvailable()) {
            $this->core->features = ' (no-rate)';
        }
    }

    private function opt($key)
    {
        return $this->core->opt($key);
    }

    public function configured()
    {
        return $this->core->configured();
    }

    // The trust_proxy option, as given.
    public function trustProxy()
    {
        return $this->options['trust_proxy'];
    }

    // Checks the current request and ends it when blocked. Rules and events
    // are synced after the response ($afterResponse false: the caller runs
    // afterResponse() itself, as Platform does).
    public function protect($afterResponse = true)
    {
        if (!$this->configured() || PHP_SAPI === 'cli') {
            return;
        }
        if ($afterResponse) {
            register_shutdown_function(array($this, 'afterResponse'));
        }
        try {
            $path = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '';
            $ip = $this->clientIp();
            $method = isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : '';
            $decision = $this->check(
                $ip,
                $method,
                $path,
                isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '',
                isset($_SERVER['HTTP_ACCEPT']) ? $_SERVER['HTTP_ACCEPT'] : '',
                // Every pass the browser sent, from the raw header: $_COOKIE keeps only the first.
                Challenge::cookieValues(isset($_SERVER['HTTP_COOKIE']) ? $_SERVER['HTTP_COOKIE'] : ''),
                isset($_SERVER['HTTP_SEC_FETCH_SITE']) ? $_SERVER['HTTP_SEC_FETCH_SITE'] : ''
            );
            $page = $decision['rule'] === 'challenge' ? $this->challengePage($ip, $method) : null;
        } catch (\Throwable $e) {
            return;
        }
        if ($decision['action'] !== 'block') {
            return;
        }
        if ($page !== null) {
            if (!headers_sent()) {
                http_response_code($page['status']);
                // Replaces any Content-Security-Policy sent before (the
                // dashboard's security headers): the site's own must not
                // block the page's script.
                foreach ($page['headers'] as $name => $value) {
                    header($name . ': ' . $value);
                }
            }
            echo $page['body'];
            exit;
        }
        if (is_callable($this->options['on_block'])) {
            call_user_func($this->options['on_block'], $decision);
            exit;
        }
        $answer = $this->blockedResponse($decision);
        if (!headers_sent()) {
            http_response_code($answer['status']);
            foreach ($answer['headers'] as $name => $value) {
                header($name . ': ' . $value);
            }
        }
        echo $answer['body'];
        exit;
    }

    // The visitor's address, per trust_proxy.
    public function clientIp()
    {
        return self::clientIpFrom($_SERVER, $this->options['trust_proxy']);
    }

    // The visitor's address from $server ($_SERVER's keys), per $trust: 0
    // the connection's address; a number of proxies in X-Forwarded-For;
    // 'cloudflare' CF-Connecting-IP, believed only from Cloudflare's own
    // addresses. A hop that isn't an address (a name, "unknown", what a
    // client wrote) gives the connection's address instead, so the request
    // is still checked; a port on a hop ("203.0.113.5:54321",
    // "[2001:db8::1]:443", as Azure's load balancers send) is dropped. Shared
    // with the WordPress plugin's px.php.
    //
    // Count only the proxies that append to X-Forwarded-For. A web server
    // that already put the visitor in REMOTE_ADDR (Apache's mod_remoteip,
    // nginx's real_ip in front of PHP-FPM, LiteSpeed's "use client IP in
    // header") wants 0: mod_remoteip also takes the entries it used out of
    // the header, so counting them again would read one the visitor wrote.
    public static function clientIpFrom(array $server, $trust)
    {
        $direct = isset($server['REMOTE_ADDR']) ? self::hop($server['REMOTE_ADDR']) : '';
        if ($trust === 'cloudflare') {
            $given = isset($server['HTTP_CF_CONNECTING_IP']) ? self::hop($server['HTTP_CF_CONNECTING_IP']) : '';
            return $given !== '' && self::ipKey($given) !== null && self::fromCloudflare($direct) ? $given : $direct;
        }
        $hops = (int) $trust;
        if ($hops > 0 && !empty($server['HTTP_X_FORWARDED_FOR'])) {
            $chain = array_values(array_filter(array_map('trim', explode(',', (string) $server['HTTP_X_FORWARDED_FOR'])), 'strlen'));
            if ($chain) {
                $chosen = self::hop($chain[max(0, count($chain) - $hops)]);
                return self::ipKey($chosen) !== null ? $chosen : $direct;
            }
        }
        return $direct;
    }

    // One hop as an address: "[v6]:port", "[v6]" and "v4:port" lose the
    // brackets and the port; anything else is returned trimmed, as it was.
    public static function hop($text)
    {
        $text = trim((string) $text);
        if ($text !== '' && $text[0] === '[') {
            $close = strpos($text, ']');
            return $close === false ? $text : substr($text, 1, $close - 1);
        }
        if (preg_match('/^(\d{1,3}(?:\.\d{1,3}){3}):\d{1,5}\z/', $text, $m)) {
            return $m[1];
        }
        return $text;
    }

    // Who the rate limit, the failed-login count and the bans here are
    // about: an IPv4 address (::ffff:a.b.c.d as a.b.c.d), or an IPv6
    // address's /64 as its network ("2001:db8:1:2::/64", compressed and
    // lower-case), which one machine usually holds whole, as the browser
    // check binds its pass. Every package builds the shared counter's key
    // the same way (firewall.md), so a site mixing languages on one Redis
    // counts a visitor once. Null when it isn't an address.
    public static function who($ip)
    {
        $bin = @inet_pton(self::hop($ip));
        if ($bin === false) {
            return null;
        }
        if (strlen($bin) === 16 && substr($bin, 0, 12) === str_repeat("\0", 10) . "\xff\xff") {
            $bin = substr($bin, 12);
        }
        if (strlen($bin) === 4) {
            return inet_ntop($bin);
        }
        return inet_ntop(substr($bin, 0, 8) . str_repeat("\0", 8)) . '/64';
    }

    // Whether a request target asks for a static file (by extension, or in
    // an asset folder), read from REQUEST_URI decoded once, as the router
    // reads it (Symfony's and Laravel's path info, WordPress), lower case,
    // "//" as "/". Only a path every router reads the same way can be a
    // file: one with a "." or ".." segment, a ";", a "\\", an encoded "/" or
    // a "%xx" left after decoding is a page, so "/static/../login",
    // "/static%2F..%2Flogin", "/login;x.css" and "/login%3Bx.css" all count;
    // so is a script with PATH_INFO after it ("/wp-login.php/x.css" runs
    // wp-login.php; .phtml and .phar run as scripts too). A browser asks for
    // its files with none of those. Nor is a path past 2,000 characters: no
    // asset has a name that long. Only GET and HEAD fetch a
    // file (no method given reads as GET): a form posts to a page, and
    // WooCommerce takes a login posted to any address.
    public static function isStatic($path, $method = 'GET')
    {
        if (!in_array((string) $method, array('', 'GET', 'HEAD'), true)) {
            return false;
        }
        $raw = preg_split('/[?#]/', (string) $path, 2)[0];
        if (strlen($raw) > RequestRules::MAX_TEXT || substr($raw, 0, 1) !== '/' || stripos($raw, '%2f') !== false) {
            return false;
        }
        $decoded = rawurldecode($raw);
        // A "%xx" still there, a ";", a "\\", an encoded "?" or "#", or a control character.
        if (preg_match('/%[0-9a-f]{2}|[;\\\\?#\x00-\x1f\x7f]/i', $decoded)) {
            return false;
        }
        $segments = explode('/', strtolower($decoded));
        $parts = array();
        $last = count($segments) - 1;
        foreach ($segments as $i => $segment) {
            if ($segment === '.' || $segment === '..' || ($i < $last && preg_match('/\.ph(?:p|tml|ar)/', $segment))) {
                return false;
            }
            if ($segment !== '') {
                $parts[] = $segment;
            }
        }
        $clean = '/' . implode('/', $parts);
        if ($parts && $segments[$last] === '') {
            $clean .= '/'; // "/app.css/" isn't a file
        }
        foreach (self::STATIC_PREFIXES as $prefix) {
            if (strncmp($clean, $prefix, strlen($prefix)) === 0) {
                return true;
            }
        }
        return (bool) preg_match(self::STATIC_FILES, $clean);
    }

    // Whether the connection came from Cloudflare.
    public static function fromCloudflare($ip)
    {
        $key = self::ipKey($ip);
        if ($key === null) {
            return false;
        }
        if (self::$cloudflare === null) {
            self::$cloudflare = self::compileList(self::CLOUDFLARE);
        }
        return self::has(self::$cloudflare, $key);
    }

    // The request target as the app routes it: an absolute-form one ("GET
    // http://host/admin", sent as if to a proxy) is routed by its path, so it
    // is cut to "/admin"; matched as written it began "http:" and missed every
    // rule on "/admin". Read as a server's URL parser reads it (firewall.md,
    // "Matching"): a scheme dropped, then the authority only after "//", and
    // a "/" in front of what is left, so "x:/admin" and "x:admin" are "/admin"
    // too, as Puma, gunicorn and Go route them. "*" and a target already
    // "/..." are kept as they are. Shared cases: `targets` in
    // sdk/protocols/request-rules-cases.json.
    public static function originForm($target)
    {
        $text = (string) $target;
        if ($text === '' || $text[0] === '/' || $text === '*') {
            return $text;
        }
        $rest = (string) preg_replace('~^[a-z][a-z0-9+.-]*:~i', '', $text, 1);
        if (strncmp($rest, '//', 2) === 0) {
            $rest = substr($rest, 2 + strcspn($rest, '/?#', 2));
        }
        return substr($rest, 0, 1) === '/' ? $rest : '/' . $rest;
    }

    // array('action' => 'allow' | 'block' | 'monitor', 'rule' => ..., 'status' => ...).
    // $accept (the Accept header) and $pass (the __sg_pass cookie, or a list
    // of up to four from Challenge::cookieValues()) are for
    // the browser check: rule 'challenge', status 503, answered with
    // challengePage(). Left out, no request is checked. $fetchSite: the
    // Sec-Fetch-Site header, see crossSite().
    public function check($ip, $method = '', $path = '', $userAgent = '', $accept = '', $pass = '', $fetchSite = '')
    {
        $path = self::originForm($path);
        $allow = array('action' => 'allow', 'rule' => '', 'status' => 200);
        // A worker serving many requests (Octane): nothing of the last one's.
        $this->staticHit = null;
        $this->routed = false;
        $this->routedType = null;
        $rules = $this->rules();
        if (!$rules || empty($rules['enabled'])) {
            return $allow;
        }
        $key = self::ipKey($ip);
        if ($key === null || self::has($rules['allow'], $key)) {
            return $allow;
        }
        $who = self::who($ip);
        $mode = in_array($this->options['mode'], array('monitor', 'block'), true) ? $this->options['mode'] : $rules['mode'];
        $goodbots = isset($rules['goodbots']) ? $rules['goodbots'] : array();
        // A page limit over its count that only watches: reported, and the
        // check goes on (firewall.md, step 6).
        $watched = null;
        $matched = null;
        $rule = $this->addressRule($rules, $key, $who);
        // Prepared once (decoded, routed) for the request rules and the page limits both.
        $requests = isset($rules['requests']) ? $rules['requests'] : array();
        $request = $rule === '' && ($requests || !empty($rules['limits']['rules']))
            ? RequestRules::prepare($method, $path, $userAgent) : null;
        if ($rule !== '') {
            // deny, ban, list or shared
        } elseif (!empty($rules['probes']) && self::isProbe($rules['probes'], $path)) {
            $rule = 'probe';
        } elseif (($matched = RequestRules::matchRequest($requests, $method, $path, $userAgent, $request))) {
            $rule = 'request:' . $matched['id'];
        } else {
            $static = self::isStatic($path, $method);
            $goodbot = self::has($goodbots, $key);
            if (!empty($rules['limits']['rules']) && !$goodbot && !self::has($rules['limits']['exempt'], $key)) {
                // A static file is only compared with the counts so far
                // (where they can be read without adding: APCu, not a shared
                // counter), and counted after the response if it answered
                // an error or the router sent it to a page (countStatic()).
                list($blocking, $watched) = $this->overLimits($rules['limits']['rules'], $who, $request, $mode, $static);
                if ($static && $who !== null) {
                    $this->staticHit = array('rate' => null, 'who' => $who, 'request' => $request);
                }
                if ($blocking) {
                    $rule = 'limit:' . $blocking['id'];
                }
            }
            if ($rule !== '') {
                // a page limit that blocks
            } elseif ($rules['rate'] && !$goodbot && $this->overRate($who, $rules['rate'], $static)) {
                $rule = 'rate';
            } elseif (!empty($rules['challenge']) && Challenge::needed($rules['challenge'], $this->opt('secret'), $ip, $method, $path,
                $accept, $pass, null, $goodbots)) {
                $rule = 'challenge';
            }
        }
        if ($rule === '' && !$watched) {
            return $allow;
        }
        $event = function ($rule, $action) use ($ip, $method, $path, $userAgent) {
            return array(
                'at' => gmdate('Y-m-d\TH:i:s\Z'),
                'ip' => (string) $ip,
                'rule' => $rule,
                'action' => $action,
                'method' => substr((string) $method, 0, 10),
                'path' => substr(explode('?', (string) $path, 2)[0], 0, 300),
                'user_agent' => substr((string) $userAgent, 0, 300),
            );
        };
        if ($watched) {
            $this->report($event('limit:' . $watched['id'], 'monitor'));
            // Nothing after it matched (and the browser check wasn't needed,
            // or it would have): the request passes with what it would have got.
            if ($rule === '') {
                return array('action' => 'monitor', 'rule' => 'limit:' . $watched['id'], 'status' => 429);
            }
        }
        // The browser check is not a mode matter: the collector sends it only
        // when the site is to be checked.
        $action = $mode === 'block' || $rule === 'challenge' ? 'block' : 'monitor';
        if ($matched) {
            $action = $action === 'block' && $matched['action'] === 'block' ? 'block' : 'monitor';
        }
        // What the report says: another site's page made the browser ask, so
        // it is refused but bans no one, here or anywhere else.
        $reported = $action;
        if ($action === 'block' && ($rule === 'probe' || $rule === 'rate' || $matched) && self::crossSite($fetchSite)) {
            $reported = 'monitor';
        }
        // A request rule the dashboard only watches passes even in block mode;
        // one that blocks also bans the address here, as a flood does.
        if ($matched && $reported === 'block' && $matched['ban']) {
            $this->banHere($who, $matched['ban']);
        }
        // Asking for a secret file: banned here (with APCu); the report bans it on the site's other servers.
        if ($rule === 'probe' && $reported === 'block') {
            $this->banHere($who, $rules['probes']['ban']);
        }
        // Over the rate limit: the same, banned here only in block mode.
        if ($rule === 'rate' && $reported === 'block') {
            $this->banHere($who, isset($rules['ban']) ? $rules['ban'] : 0);
        }
        // A match that is only watched (monitor) still gets the check: firewall.md, step 8.
        if ($action === 'monitor' && !empty($rules['challenge']) && Challenge::needed($rules['challenge'], $this->opt('secret'), $ip, $method,
            $path, $accept, $pass, null, isset($rules['goodbots']) ? $rules['goodbots'] : array())) {
            $this->report($event($rule, $action));
            $rule = 'challenge';
            $action = 'block';
        }
        $this->report($event($rule, $rule === 'challenge' ? $action : $reported));
        if ($action === 'block') {
            // Turned away: nothing of it is counted after the response.
            $this->staticHit = null;
        }
        $tooMany = $rule === 'rate' || strpos($rule, 'limit:') === 0;
        return array('action' => $action, 'rule' => $rule, 'status' => $tooMany ? 429 : ($rule === 'challenge' ? 503 : 403));
    }

    // Whether Sec-Fetch-Site says another site made the browser send the
    // request (firewall.md, "Checking a request"). Any page can make a
    // visitor's browser ask for /.env (an <img>, a no-cors fetch, a link) or
    // for a page 120 times a minute, from the visitor's own address: banning
    // it would let anyone get anyone banned. A client that forges the header
    // only gives up the ban; it is still refused.
    public static function crossSite($fetchSite)
    {
        $value = strtolower(trim((string) $fetchSite));
        return $value === 'cross-site' || $value === 'same-site';
    }

    // The answer to a request check() blocked, other than the browser check
    // (challengePage()): array('status', 'headers', 'body'). protect() and the
    // Laravel and Symfony middleware all answer with it, so a page limit's
    // Retry-After is its own window, not the site-wide rate's.
    public function blockedResponse(array $decision)
    {
        $headers = array('Content-Type' => 'text/plain; charset=utf-8', 'Cache-Control' => 'no-store');
        if ($decision['status'] !== 429) {
            return array('status' => $decision['status'], 'headers' => $headers, 'body' => 'Forbidden');
        }
        $rules = $this->rules();
        $window = 0;
        if (strpos($decision['rule'], 'limit:') === 0) {
            foreach (isset($rules['limits']['rules']) ? $rules['limits']['rules'] : array() as $limit) {
                if ('limit:' . $limit['id'] === $decision['rule']) {
                    $window = $limit['window'];
                    break;
                }
            }
            // A person behind it, most likely (a shopper refreshing checkout):
            // said plainly, and nothing is banned.
            $body = 'Too many requests to this page. Please wait a little and try again.';
        } else {
            $window = !empty($rules['rate']['window']) ? $rules['rate']['window'] : 0;
            $body = 'Too Many Requests';
        }
        if ($window) {
            $headers['Retry-After'] = (string) $window;
        }
        return array('status' => 429, 'headers' => $headers, 'body' => $body);
    }

    // The rules about the address alone (deny, bans, lists, shared): '' when none.
    private function addressRule(array $rules, $key, $who)
    {
        if (self::has($rules['deny'], $key)) {
            return 'deny';
        }
        if ((isset($rules['banned']) && self::has($rules['banned'], $key)) || $this->bannedHere($who)) {
            return 'ban';
        }
        if (self::has($rules['lists'], $key)) {
            return 'list';
        }
        return self::has($rules['shared'], $key) ? 'shared' : '';
    }

    // The address rules only, for the tracker's own addresses (the proxy): a
    // denied or banned address gets nothing from us either, but beacons are
    // never rate-limited, checked or matched against request rules. The same
    // shape as check().
    public function checkAddress($ip, $method = '', $path = '', $userAgent = '')
    {
        $path = self::originForm($path);
        $allow = array('action' => 'allow', 'rule' => '', 'status' => 200);
        $rules = $this->rules();
        if (!$rules || empty($rules['enabled'])) {
            return $allow;
        }
        $key = self::ipKey($ip);
        if ($key === null || self::has($rules['allow'], $key)) {
            return $allow;
        }
        $rule = $this->addressRule($rules, $key, self::who($ip));
        if ($rule === '') {
            return $allow;
        }
        $mode = in_array($this->options['mode'], array('monitor', 'block'), true) ? $this->options['mode'] : $rules['mode'];
        $action = $mode === 'block' ? 'block' : 'monitor';
        $this->report(array(
            'at' => gmdate('Y-m-d\TH:i:s\Z'),
            'ip' => (string) $ip,
            'rule' => $rule,
            'action' => $action,
            'method' => substr((string) $method, 0, 10),
            'path' => substr(explode('?', (string) $path, 2)[0], 0, 300),
            'user_agent' => substr((string) $userAgent, 0, 300),
        ));
        return array('action' => $action, 'rule' => $rule, 'status' => 403);
    }

    // The browser check's page for this address: array('status', 'headers',
    // 'body'), for a framework to answer with when check() says 'challenge'.
    public function challengePage($ip, $method = 'GET')
    {
        return Challenge::page($this->opt('secret'), $ip, $method);
    }

    // What the rules say now, for a status page: null before the first sync.
    public function status()
    {
        $rules = $this->rules();
        if (!$rules) {
            return null;
        }
        $counts = array();
        foreach (self::RULES as $list) {
            $counts[$list] = count($rules[$list]);
        }
        return array(
            'enabled' => $rules['enabled'],
            'mode' => $rules['mode'],
            'fetched' => $rules['fetched'],
            'rate' => $rules['rate'],
            'rate_available' => $this->counterAvailable(),
            'challenge' => !empty($rules['challenge']),
            'ranges' => $counts,
        );
    }

    // ---- Addresses --------------------------------------------------------
    // Every address as 32 hex digits of its 16-byte IPv6 form (IPv4 as
    // ::ffff:a.b.c.d), so one sorted list and string comparison cover both.

    public static function ipKey($ip)
    {
        $bin = @inet_pton(trim((string) $ip));
        if ($bin === false) {
            return null;
        }
        if (strlen($bin) === 4) {
            $bin = str_repeat("\0", 10) . "\xff\xff" . $bin;
        }
        return bin2hex($bin);
    }

    // "1.2.3.0/24" -> array(start, end) as ipKey()s; null when invalid, or
    // when an IPv6 range covers all of IPv4 (below).
    public static function range($entry)
    {
        $parts = explode('/', trim((string) $entry));
        if (count($parts) > 2) {
            return null;
        }
        $bin = @inet_pton($parts[0]);
        if ($bin === false) {
            return null;
        }
        $v4 = strlen($bin) === 4;
        if ($v4) {
            $bin = str_repeat("\0", 10) . "\xff\xff" . $bin;
        }
        $prefix = 128;
        if (isset($parts[1])) {
            if (!ctype_digit($parts[1]) || (int) $parts[1] > ($v4 ? 32 : 128)) {
                return null;
            }
            $prefix = (int) $parts[1] + ($v4 ? 96 : 0);
        }
        $start = '';
        $end = '';
        for ($i = 0; $i < 16; $i++) {
            $bits = max(0, min(8, $prefix - 8 * $i));
            $mask = $bits === 0 ? 0 : (0xff << (8 - $bits)) & 0xff;
            $byte = ord($bin[$i]) & $mask;
            $start .= chr($byte);
            $end .= chr($byte | (~$mask & 0xff));
        }
        $start = bin2hex($start);
        $end = bin2hex($end);
        // An IPv6 range wide enough to hold all of ::ffff:0:0/96 (::/64,
        // ::/0) would, with IPv4 kept as ::ffff:a.b.c.d, match every IPv4
        // visitor: a /64 is one machine in IPv6, but here it is the whole
        // IPv4 internet. Dropped, whichever list it is in.
        if (!$v4 && strcmp($start, self::MAPPED_START) <= 0 && strcmp($end, self::MAPPED_END) >= 0) {
            return null;
        }
        return array($start, $end);
    }

    // Entries -> sorted, merged ranges.
    public static function compileList($entries)
    {
        $ranges = array();
        foreach (is_array($entries) ? $entries : array() as $entry) {
            if (is_string($entry) && ($range = self::range($entry))) {
                $ranges[] = $range;
            }
        }
        usort($ranges, function ($a, $b) {
            return strcmp($a[0], $b[0]);
        });
        $merged = array();
        foreach ($ranges as $range) {
            $last = count($merged) - 1;
            if ($last >= 0 && strcmp($range[0], $merged[$last][1]) <= 0) {
                if (strcmp($range[1], $merged[$last][1]) > 0) {
                    $merged[$last][1] = $range[1];
                }
            } else {
                $merged[] = $range;
            }
        }
        return $merged;
    }

    // Whether an ipKey() is in a compileList() (used by maintenance mode's allowed addresses).
    public static function inList(array $ranges, $key)
    {
        return self::has($ranges, $key);
    }

    private static function has(array $ranges, $key)
    {
        $lo = 0;
        $hi = count($ranges) - 1;
        while ($lo <= $hi) {
            $mid = ($lo + $hi) >> 1;
            if (strcmp($ranges[$mid][0], $key) > 0) {
                $hi = $mid - 1;
            } elseif (strcmp($ranges[$mid][1], $key) < 0) {
                $lo = $mid + 1;
            } else {
                return true;
            }
        }
        return false;
    }

    // ---- Probes -----------------------------------------------------------
    // Addresses of files no visitor asks for (.env, .git/, backups): only
    // scanners looking for secrets do.

    public static function compileProbes($probes)
    {
        if (!is_array($probes)) {
            return null;
        }
        $exact = array();
        foreach (isset($probes['exact']) && is_array($probes['exact']) ? $probes['exact'] : array() as $path) {
            if (is_string($path) && $path !== '') {
                $exact[strtolower($path)] = true;
            }
        }
        $prefix = array();
        foreach (isset($probes['prefix']) && is_array($probes['prefix']) ? $probes['prefix'] : array() as $path) {
            if (is_string($path) && $path !== '') {
                $prefix[] = strtolower($path);
            }
        }
        if (!$exact && !$prefix) {
            return null;
        }
        return array('exact' => $exact, 'prefix' => $prefix, 'ban' => isset($probes['ban']) ? max(0, (int) $probes['ban']) : 0);
    }

    // The path without its query string or "#", lower-cased, with "//" as
    // "/". Also as the router would see it (RequestRules::routedPath(): no
    // ";params", "." and ".." resolved, decoded once, from the whole path),
    // so "/x;y/../.env" is the probe "/.env" too.
    public static function isProbe(array $probes, $path)
    {
        $raw = preg_split('/[?#]/', (string) $path, 2)[0];
        $plain = strtolower(preg_replace('#/{2,}#', '/', $raw));
        $routed = RequestRules::routedPath($raw);
        foreach ($plain === $routed ? array($plain) : array($plain, $routed) as $text) {
            if (isset($probes['exact'][$text])) {
                return true;
            }
            foreach ($probes['prefix'] as $prefix) {
                if (strpos($text, $prefix) === 0) {
                    return true;
                }
            }
        }
        return false;
    }

    // ---- Rules ------------------------------------------------------------

    private function rules()
    {
        if (!$this->loaded) {
            $this->loaded = true;
            $rules = $this->core->readPhp('rules.php');
            $this->rules = is_array($rules) && isset($rules['v']) && $rules['v'] === self::PROTOCOL ? $rules : null;
        }
        return $this->rules;
    }

    private function compile(array $data, $etag)
    {
        $rate = null;
        if (!empty($data['rate']['limit']) && (int) $data['rate']['limit'] > 0) {
            $rate = array('limit' => (int) $data['rate']['limit'], 'window' => max(1, (int) (isset($data['rate']['window']) ? $data['rate']['window'] : 60)));
        }
        $rules = array(
            'v' => self::PROTOCOL,
            'etag' => (string) $etag,
            'fetched' => time(),
            'enabled' => !empty($data['enabled']),
            'mode' => isset($data['mode']) && $data['mode'] === 'block' ? 'block' : 'monitor',
            'sync' => max(self::MIN_SYNC, (int) (isset($data['sync']) ? $data['sync'] : self::RETRY)),
            'rate' => $rate,
            // Bot protection: how long to ban a flood, and the failed-login limit.
            'ban' => isset($data['ban']['seconds']) ? max(0, (int) $data['ban']['seconds']) : 0,
            'login' => !empty($data['login']['limit']) ? array(
                'limit' => (int) $data['login']['limit'],
                'window' => (int) (isset($data['login']['window']) ? $data['login']['window'] : 3600),
                'ban' => (int) (isset($data['login']['ban']) ? $data['login']['ban'] : 3600),
            ) : null,
            'probes' => self::compileProbes(isset($data['probes']) ? $data['probes'] : null),
            // Virtual patching: rules that match the request, not the address.
            'requests' => RequestRules::compile(isset($data['requests']) ? $data['requests'] : null),
            // The browser check (flood protection): null unless the site is to be checked.
            'challenge' => Challenge::compile(isset($data['challenge']) ? $data['challenge'] : null),
            // Page limits: a cap per kind of request, besides the site-wide rate.
            'limits' => self::compileLimits(isset($data['limits']) ? $data['limits'] : null),
        );
        foreach (self::RULES as $list) {
            $rules[$list] = self::compileList(isset($data[$list]) ? $data[$list] : array());
        }
        return $rules;
    }

    // Null when there are none (absent, null, or none valid).
    private static function compileLimits($limits)
    {
        $rules = RequestRules::compileLimits(is_array($limits) && isset($limits['rules']) ? $limits['rules'] : null);
        if (!$rules) {
            return null;
        }
        return array('exempt' => self::compileList(isset($limits['exempt']) ? $limits['exempt'] : array()), 'rules' => $rules);
    }

    private function writeRules(array $rules)
    {
        if ($this->core->writePhp('rules.php', $rules)) {
            $this->rules = $rules;
        }
    }

    // Fetches rules when due; one request at a time, at most once per
    // MIN_SYNC seconds even when fetches fail.
    public function sync($force = false)
    {
        if (!$this->configured() || !$this->core->ensureDir()) {
            return false;
        }
        $rules = $this->rules();
        $due = $rules ? $rules['fetched'] + $rules['sync'] : 0;
        if (!$force && time() < $due) {
            return true;
        }
        $lockFile = $this->dir . '/sync.lock';
        clearstatcache(true, $lockFile);
        if (!$force && is_file($lockFile) && filemtime($lockFile) > time() - self::MIN_SYNC) {
            return true;
        }
        $lock = @fopen($lockFile, 'c');
        if (!$lock || !flock($lock, LOCK_EX | LOCK_NB)) {
            return true;
        }
        @touch($lockFile);
        $ok = false;
        // What this server runs (the package's firewall and its browser
        // check) and its name, shown per server on the dashboard.
        $headers = array('X-Firewall-Layers: app check', 'X-Server-Name: ' . $this->serverName());
        if ($rules && $rules['etag'] !== '' && !$force) {
            $headers[] = 'If-None-Match: ' . $rules['etag'];
        }
        $res = $this->core->http('GET', '/events/firewall/rules?site_id=' . rawurlencode($this->opt('site_id')), null, $headers);
        if ($res['status'] === 200) {
            $data = json_decode($res['body'], true);
            if (is_array($data) && isset($data['v']) && $data['v'] === self::PROTOCOL) {
                $this->writeRules($this->compile($data, isset($res['headers']['etag']) ? $res['headers']['etag'] : ''));
                $ok = true;
            }
        } elseif ($res['status'] === 304 && $rules) {
            $rules['fetched'] = time();
            $this->writeRules($rules);
            $ok = true;
        }
        flock($lock, LOCK_UN);
        fclose($lock);
        return $ok;
    }

    // The server_name option, else the host name, as the check-in sends it;
    // 100 characters at most, on one line.
    public function serverName()
    {
        $name = $this->opt('server_name');
        if (empty($name)) {
            $name = function_exists('gethostname') ? (string) gethostname() : '';
        }
        return substr(trim(preg_replace('/[\x00-\x1f\x7f]+/', ' ', (string) $name)), 0, 100);
    }

    // ---- Rate limit -------------------------------------------------------

    private function counterAvailable()
    {
        return is_callable($this->options['counter']) || (function_exists('apcu_enabled') && apcu_enabled());
    }

    // ---- Bot protection ----------------------------------------------------
    // Bans and failed-login counts on this server need memory shared between
    // requests (APCu). Without it, the collector bans the address and every
    // server gets it with the next rules (within a minute or so).

    private function apcu()
    {
        return function_exists('apcu_enabled') && apcu_enabled();
    }

    // $who: who() of the address (an IPv4 address or an IPv6 /64).
    private function bannedHere($who)
    {
        return $who !== null && $this->apcu() && apcu_fetch('afw:ban:' . $this->opt('site_id') . ':' . $who) !== false;
    }

    private function banHere($who, $seconds)
    {
        if ($who !== null && $seconds > 0 && $this->apcu()) {
            apcu_store('afw:ban:' . $this->opt('site_id') . ':' . $who, 1, (int) $seconds);
        }
    }

    // A failed login on the site (default: the current visitor's address).
    // Counted here (past the site's limit the address is banned straight
    // away, with APCu) and reported, so it counts on the Security page and
    // gets banned on the site's other servers too.
    public function loginFailed($ip = null)
    {
        try {
            $ip = $ip === null ? $this->clientIp() : (string) $ip;
            $key = self::ipKey($ip);
            $rules = $this->rules();
            if ($key === null || ($rules && self::has($rules['allow'], $key))) {
                return;
            }
            $login = $rules && !empty($rules['login']) ? $rules['login'] : null;
            $who = self::who($ip);
            if ($login && $this->apcu()) {
                $name = 'afw:login:' . $this->opt('site_id') . ':' . $who;
                apcu_add($name, 0, max(60, $login['window']));
                if ((int) apcu_inc($name) >= $login['limit']) {
                    apcu_delete($name);
                    $this->banHere($who, $login['ban']);
                }
            }
            $this->report(array(
                'at' => gmdate('Y-m-d\TH:i:s\Z'), 'ip' => $ip, 'rule' => 'login', 'action' => 'monitor',
                'method' => '', 'path' => '', 'user_agent' => '',
            ));
        } catch (\Throwable $e) {
            // never break the site
        }
    }

    // Whether $who is over the limit. A static file isn't counted (it is
    // only compared with the count so far, where the counter can tell it
    // without adding one); countStatic() adds it after the response when it
    // answered an error.
    private function overRate($who, array $rate, $static = false)
    {
        if ($who === null) {
            return false;
        }
        $window = (int) floor(time() / $rate['window']);
        $name = 'afw:' . $this->opt('site_id') . ':' . $who . ':' . $window;
        $ttl = $rate['window'] * 2;
        if ($static) {
            $this->staticHit = array('rate' => array($name, $ttl), 'who' => $who,
                'request' => $this->staticHit ? $this->staticHit['request'] : null);
            if (is_callable($this->options['counter'])) {
                return $this->notedHere($name);
            }
            $hits = $this->peekHere($name);
        } elseif (is_callable($this->options['counter'])) {
            $hits = (int) call_user_func($this->options['counter'], $name, $ttl);
            if ($hits > $rate['limit']) {
                $this->noteHere($name, $ttl);
            }
        } elseif ($this->apcu()) {
            apcu_add($name, 0, $ttl);
            $hits = (int) apcu_inc($name);
        } else {
            return false;
        }
        return $hits > $rate['limit'];
    }

    // Counts the request toward every page limit it matches (firewall.md,
    // step 6), then: array(the first limit now over that blocks, the first
    // over that only watches), either null. Every match is counted, even
    // after one is over, so each limit's count is the same whatever the order.
    // $request: RequestRules::prepare() of the request, as check() made it.
    // $peek: only compared with the counts so far, nothing added (a static file).
    private function overLimits(array $limits, $who, array $request, $mode, $peek = false)
    {
        $blocking = null;
        $watched = null;
        if ($who === null) {
            return array(null, null);
        }
        foreach ($limits as $limit) {
            if (!RequestRules::matches($limit, $request) || $this->countLimit($limit, $who, $request['routed'], $peek) <= $limit['limit']) {
                continue;
            }
            if ($mode === 'block' && $limit['action'] === 'block') {
                $blocking = $blocking ?: $limit;
            } else {
                $watched = $watched ?: $limit;
            }
        }
        // A limit that blocks decides; one that watches is reported only when none does.
        return array($blocking, $blocking ? null : $watched);
    }

    // The count after this request, in a fixed window like the rate's, keyed
    // the same in every package (afw:<site_id>:l:<id>:<who>:<window>). An
    // `each: "path"` count is one per page per address: kept on this server
    // (APCu), never in the shared counter, which it would fill. 0 when there
    // is nothing to count with, which is never over. $peek: the count so far,
    // nothing added; a shared counter only adds, so there it is 0.
    private function countLimit(array $limit, $who, $routed, $peek = false)
    {
        $name = 'afw:' . $this->opt('site_id') . ':l:' . $limit['id'] . ':' . $who . ':' . (int) floor(time() / $limit['window']);
        $ttl = $limit['window'] * 2;
        if ($limit['each']) {
            // Hashed: a key per page must not be as long as the page's address.
            $name .= ':' . md5($routed);
            return $peek ? $this->peekHere($name) : $this->countHere($name, $ttl);
        }
        if (is_callable($this->options['counter'])) {
            if ($peek) {
                return $this->notedHere($name) ? $limit['limit'] + 1 : 0;
            }
            $hits = (int) call_user_func($this->options['counter'], $name, $ttl);
            if ($hits > $limit['limit']) {
                $this->noteHere($name, $ttl);
            }
            return $hits;
        }
        return $peek ? $this->peekHere($name) : $this->countHere($name, $ttl);
    }

    // A shared counter only adds: a count this server saw go over is noted
    // here (APCu, under its key, window and all), so a static file asked for
    // after it is turned away without adding to it. Without APCu nothing is
    // noted, and an address over a shared count still gets its files.
    protected function noteHere($name, $ttl)
    {
        if ($this->apcu()) {
            apcu_store('afw:over:' . $name, 1, $ttl);
        }
    }

    protected function notedHere($name)
    {
        return $this->apcu() && (bool) apcu_fetch('afw:over:' . $name);
    }

    // A count on this server so far, nothing added (APCu); 0 without it.
    protected function peekHere($name)
    {
        return $this->apcu() ? (int) apcu_fetch($name) : 0;
    }

    // A count on this server only (APCu); 0 without it. Protected so the
    // tests can stand in for APCu, which the plain PHP they run on lacks.
    protected function countHere($name, $ttl)
    {
        if (!$this->apcu()) {
            return 0;
        }
        apcu_add($name, 0, $ttl);
        return (int) apcu_inc($name);
    }

    // The app's router sent this request to a page of its own: the Laravel
    // middleware (a route that isn't a file's), the WordPress plugin
    // (WordPress ran its main query for it). A static-looking request then
    // counts after the response (countStatic()). $contentType: the
    // response's (null: what PHP sends, read after the response); a file's
    // (an image, a font, a stylesheet...) is left alone.
    public function markRouted($routed = true, $contentType = null)
    {
        $this->routed = (bool) $routed;
        $this->routedType = $contentType;
    }

    // A response's Content-Type that is a file's: what a route serving files answers.
    public static function servesFile($contentType)
    {
        return (bool) preg_match('~^(?:image|font|audio|video)/|^text/css|javascript|^application/(?:wasm|pdf|octet-stream|vnd\.ms-fontobject|(?:x-)?font)~i',
            trim((string) $contentType));
    }

    // The Content-Type PHP is sending, from headers_list(); '' when none.
    public static function sentContentType()
    {
        foreach (function_exists('headers_list') ? headers_list() : array() as $line) {
            if (stripos($line, 'content-type:') === 0) {
                return trim(substr($line, 13));
            }
        }
        return '';
    }

    // After the response: a static file check() only compared with the
    // counts counts toward the rate and the page limits after all when it
    // answered an error (404, 5xx: a flood of made-up file names that each
    // boot the whole app), or the router sent it to a page (markRouted(),
    // or $routed) and it wasn't a 304. $status: the response's (default
    // http_response_code()).
    public function countStatic($status = null, $routed = null)
    {
        $hit = $this->staticHit;
        $this->staticHit = null;
        if ($routed === null) {
            $routed = $this->routed && !self::servesFile($this->routedType !== null ? $this->routedType : self::sentContentType());
        }
        $routed = (bool) $routed;
        $this->routed = false;
        $this->routedType = null;
        $status = $status === null ? (int) http_response_code() : (int) $status;
        if ($hit === null || !($status >= 400 || ($routed && $status !== 304))) {
            return;
        }
        try {
            if ($hit['rate']) {
                list($name, $ttl) = $hit['rate'];
                if (is_callable($this->options['counter'])) {
                    $limit = isset($this->rules()['rate']['limit']) ? $this->rules()['rate']['limit'] : PHP_INT_MAX;
                    if ((int) call_user_func($this->options['counter'], $name, $ttl) > $limit) {
                        $this->noteHere($name, $ttl);
                    }
                } else {
                    $this->countHere($name, $ttl);
                }
            }
            $rules = $this->rules();
            if ($hit['request'] && !empty($rules['limits']['rules'])) {
                foreach ($rules['limits']['rules'] as $limit) {
                    if (RequestRules::matches($limit, $hit['request'])) {
                        $this->countLimit($limit, $hit['who'], $hit['request']['routed']);
                    }
                }
            }
        } catch (\Throwable $e) {
            // never break the site
        }
    }

    // ---- Events -----------------------------------------------------------

    private function report(array $event)
    {
        if ($this->core->ensureDir() && $this->core->append('events', $event, self::SPOOL_MAX)) {
            $this->reported = true;
        }
    }

    // Sends waiting events, grouped like the Node client does, at most every
    // FLUSH_EVERY seconds.
    public function flush($force = false)
    {
        $this->core->drain('events', self::FLUSH_EVERY, $force, function (array $events) {
            $groups = array();
            foreach ($events as $event) {
                if (empty($event['ip'])) {
                    continue;
                }
                $key = json_encode(array($event['ip'], $event['rule'], $event['action'], $event['method'], $event['path']));
                if (isset($groups[$key])) {
                    $groups[$key]['hits']++;
                } else {
                    $groups[$key] = $event + array('hits' => 1);
                }
            }
            foreach (array_chunk(array_values($groups), self::BATCH) as $batch) {
                $this->core->post('events', '/events/firewall/events', array('site_id' => (string) $this->opt('site_id'), 'events' => $batch), 'bearer');
            }
        });
    }

    // Runs at shutdown: finishes the response first where PHP-FPM allows,
    // so the visitor never waits on the sync.
    public function afterResponse()
    {
        try {
            $this->core->within(Core::DEADLINE, function () {
                $this->syncAndFlush();
            });
        } catch (\Throwable $e) {
            // never break the site
        }
    }

    private function syncAndFlush()
    {
        try {
            $this->countStatic();
            $rules = $this->rules();
            $dueSync = !$rules || time() >= $rules['fetched'] + $rules['sync'];
            $dueFlush = $this->reported || $this->core->waiting('events');
            if (!$dueSync && !$dueFlush) {
                return;
            }
            if (function_exists('fastcgi_finish_request')) {
                @fastcgi_finish_request();
            } elseif (function_exists('litespeed_finish_request')) {
                @litespeed_finish_request();
            }
            if ($dueSync) {
                $this->sync();
            }
            if ($dueFlush) {
                $this->flush();
            }
        } catch (\Throwable $e) {
            // never break the site
        }
    }
}
