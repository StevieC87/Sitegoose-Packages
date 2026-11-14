<?php
// One package for a PHP site's server, run from the analytics dashboard:
// firewall, error monitoring, server analytics and the rest. Each module is separate:
// only the ones turned on are created, and the firewall never waits on
// reporting. A module can also be switched off in the dashboard (Site
// settings → Server). Everything that talks to the collector runs after the
// response has gone out (PHP-FPM), so visitors never wait on it.
//
//   $platform = new AnalyticsPlatform\Platform([
//       'site_id' => '...', 'secret' => getenv('ANALYTICS_SITE_SECRET'), 'endpoint' => 'https://...',
//   ]);
//   $platform->protect(); // as early as possible, before any output

namespace AnalyticsPlatform;

class Platform
{
    const SESSION_HEADER = 'HTTP_X_ANALYTICS_SESSION';
    // Set by the tracker's page script in the WordPress plugin, for requests
    // that can't send the header (form posts, checkouts).
    const SESSION_COOKIE = 'analytics_session';

    private $core;
    private $options;
    private $modules = array();
    private $protected = false;
    private $clientIp = null;
    // The jobs running, innermost last: array(route, started) each. A job
    // can run another; its errors are named after the inner one.
    private $jobs = array();

    // Options: site_id, secret, endpoint (required); storage, platform (see
    // Core); trust_proxy, mode, counter, on_block (see Firewall); and per
    // module 'firewall' / 'errors' / 'analytics' / 'performance' => true, false
    // or an array of that module's options (errors: server_name, root,
    // before_send; performance: server_name; queries: the database queries
    // timed with Server speed, on with it unless false, see Queries; calls:
    // the outgoing HTTP calls, likewise; queues: job queue backlogs, likewise,
    // see Queues; files:
    // roots and the rest, see Files; off unless given; inventory: root and the rest, see Inventory;
    // posture: roots and the callbacks, see Posture). server_name names this
    // service for every module that sends one (errors, performance, crawlers,
    // resources, queries), so its errors and timings can be told apart from others'.
    // Each of site_id, secret, endpoint and server_name left out (or empty), and
    // trust_proxy left out, is read from the environment: see withEnvironment().
    public function __construct(array $options)
    {
        $options = self::withEnvironment($options);
        $this->core = new Core($options);
        $this->options = $options;
        foreach (array('proxy', 'firewall', 'errors', 'analytics', 'performance', 'queries', 'queues', 'crawlers', 'forms', 'headers', 'audit', 'flags', 'maintenance', 'files', 'inventory', 'posture', 'resources') as $name) {
            // File monitoring needs its folders, and the set-up checks walk the
            // web folder once a day: both are off unless asked for. (The
            // WordPress plugin asks for them.)
            $setting = array_key_exists($name, $options) ? $options[$name] : !in_array($name, array('files', 'posture'), true);
            $key = $name;
            if ($name === 'queries') {
                // Queries and outgoing calls are one module, kept under
                // 'calls' when queries are off.
                $calls = array_key_exists('calls', $options) ? $options['calls'] : true;
                $queriesOn = $setting !== false && $setting !== null;
                $callsOn = $calls !== false && $calls !== null;
                if (!$queriesOn && !$callsOn) {
                    continue;
                }
                $setting = (is_array($setting) ? $setting : array()) + array('queries' => $queriesOn, 'calls' => $callsOn);
                $key = $queriesOn ? 'queries' : 'calls';
            }
            // Query and call timings and queue backlogs are a part of Server
            // speed: never without it.
            if ($setting === false || $setting === null || (in_array($name, array('queries', 'queues'), true) && !isset($this->modules['performance']))) {
                continue;
            }
            $own = is_array($setting) ? $setting : array();
            if (!empty($options['server_name']) && in_array($name, array('errors', 'performance', 'queries', 'queues', 'crawlers', 'resources'), true)) {
                $own += array('server_name' => (string) $options['server_name']);
            }
            try {
                if ($name === 'proxy') {
                    $this->modules[$name] = new Proxy(
                        $this->core->opt('endpoint'),
                        $this->core->opt('secret'),
                        // Only a folder no one else can write to: what is
                        // cached there is served as the site's own script.
                        $this->core->trustedDir(),
                        isset($own['prefix']) ? $own['prefix'] : '',
                        '',
                        (bool) $this->core->opt('public_endpoint')
                    );
                } elseif ($name === 'firewall') {
                    $this->modules[$name] = new Firewall($own + $options, $this->core);
                } elseif ($name === 'errors') {
                    $this->modules[$name] = new Errors($this->core, $own);
                } elseif ($name === 'performance') {
                    $this->modules[$name] = new Performance($this->core, $own);
                } elseif ($name === 'queries') {
                    $this->modules[$key] = new Queries($this->core, $own);
                    $this->modules['performance']->setTimings($this->modules[$key]);
                } elseif ($name === 'queues') {
                    $this->modules[$name] = new Queues($this->core, $own);
                } elseif ($name === 'resources') {
                    $this->modules[$name] = new Resources($this->core, $own);
                } elseif ($name === 'crawlers') {
                    $this->modules[$name] = new Crawlers($this->core, $own);
                } elseif ($name === 'forms') {
                    $this->modules[$name] = new Forms($this->core);
                } elseif ($name === 'files') {
                    $this->modules[$name] = new Files($this->core, $own);
                } elseif ($name === 'inventory') {
                    $this->modules[$name] = new Inventory($this->core, $own);
                } elseif ($name === 'posture') {
                    $this->modules[$name] = new Posture($this->core, $own);
                } elseif ($name === 'audit') {
                    $this->modules[$name] = new Audit($this->core);
                } elseif ($name === 'flags' || $name === 'maintenance') {
                    // From the module switches (Core); see Flags.
                    $this->modules[$name] = true;
                } elseif ($name === 'headers') {
                    // The headers come with the module switches (Core).
                    $this->modules[$name] = true;
                } else {
                    $this->modules[$name] = new Analytics($this->core);
                }
            } catch (\Throwable $e) {
                // that module stays off
            }
        }
        $this->core->setLoaded(array_keys($this->modules));
    }

    // The options, with what was left out read from the environment, as the
    // Node, Python, Ruby and Go packages do: site_id, secret, endpoint and
    // server_name when missing or empty, from ANALYTICS_SITE_ID,
    // ANALYTICS_SITE_SECRET, ANALYTICS_ENDPOINT (or ANALYTICS_FIREWALL_ENDPOINT,
    // Laravel's and Symfony's name for it) and ANALYTICS_SERVER_NAME (missing, empty or false); and
    // trust_proxy when not given at all, from ANALYTICS_TRUST_PROXY
    // ("cloudflare", or the number of proxies). Each is looked for in getenv(),
    // $_ENV and $_SERVER, then in $file (start.php's lines of .env), so the
    // server's own setting wins over the file. Never on WordPress: there, the
    // plugin's settings page is the one place the keys come from.
    public static function withEnvironment(array $options, array $file = array())
    {
        if (isset($options['platform']) && $options['platform'] === 'wordpress') {
            return $options;
        }
        $read = function ($name) use ($file) {
            $found = array(
                getenv($name),
                isset($_ENV[$name]) ? $_ENV[$name] : null,
                isset($_SERVER[$name]) ? $_SERVER[$name] : null,
                isset($file[$name]) ? $file[$name] : null,
            );
            foreach ($found as $value) {
                if (is_string($value) && trim($value) !== '') {
                    return trim($value);
                }
            }
            return null;
        };
        $names = array(
            'site_id' => array('ANALYTICS_SITE_ID'),
            'secret' => array('ANALYTICS_SITE_SECRET'),
            'endpoint' => array('ANALYTICS_ENDPOINT', 'ANALYTICS_FIREWALL_ENDPOINT'),
            'server_name' => array('ANALYTICS_SERVER_NAME'),
        );
        foreach ($names as $key => $vars) {
            // false too: what getenv() gives for a variable it can't see.
            if (isset($options[$key]) && $options[$key] !== '' && $options[$key] !== false) {
                continue;
            }
            foreach ($vars as $var) {
                $value = $read($var);
                if ($value !== null) {
                    $options[$key] = $value;
                    break;
                }
            }
        }
        if (!array_key_exists('trust_proxy', $options)) {
            $trust = $read('ANALYTICS_TRUST_PROXY');
            if ($trust !== null) {
                $lower = strtolower($trust);
                if ($lower === 'cloudflare') {
                    $options['trust_proxy'] = 'cloudflare';
                } elseif ($lower === 'true') {
                    $options['trust_proxy'] = 1;
                } elseif (ctype_digit($trust)) {
                    $options['trust_proxy'] = (int) $trust;
                }
            }
        }
        return $options;
    }

    public function configured()
    {
        return $this->core->configured();
    }

    public function modules()
    {
        return array_keys($this->modules);
    }

    // The shared Core: credentials, the storage folder and sending. The
    // WordPress plugin's first-party proxy needs the folder's name, which
    // hashes the secret and so can't be worked out anywhere else.
    public function core()
    {
        return $this->core;
    }

    public function module($name)
    {
        return isset($this->modules[$name]) ? $this->modules[$name] : null;
    }

    public function firewall()
    {
        return $this->module('firewall');
    }

    // The queries module, which times both queries and outgoing calls.
    private function timings()
    {
        return isset($this->modules['queries']) ? $this->modules['queries'] : (isset($this->modules['calls']) ? $this->modules['calls'] : null);
    }

    // The visitor's address: the framework's when it gave one (Laravel's
    // trusted proxies), else the firewall's trust_proxy rule, else the connection's.
    public function clientIp()
    {
        if ($this->clientIp !== null) {
            return $this->clientIp;
        }
        return isset($this->modules['firewall']) ? $this->modules['firewall']->clientIp() : (isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : '');
    }

    // A framework that already knows the visitor's address passes it here,
    // per request; null goes back to working it out.
    public function setClientIp($ip)
    {
        $this->clientIp = $ip === null ? null : (string) $ip;
    }

    // The browser's visit: the X-Analytics-Session header, else the cookie.
    public static function sessionIdFromRequest()
    {
        $value = !empty($_SERVER[self::SESSION_HEADER]) ? $_SERVER[self::SESSION_HEADER]
            : (!empty($_COOKIE[self::SESSION_COOKIE]) ? $_COOKIE[self::SESSION_COOKIE] : '');
        return preg_match('/^[0-9a-f-]{36}$/Di', (string) $value) ? strtolower($value) : '';
    }

    // Checks the request with the firewall (and ends it when blocked), starts
    // catching errors, and sends everything after the response.
    public function protect()
    {
        if ($this->protected || !$this->core->configured() || PHP_SAPI === 'cli') {
            return;
        }
        // The tracker's own addresses, answered before anything else and
        // without the rest of the request: a visitor's beacon is our traffic,
        // not a page of the site, so it shouldn't be timed, counted as a
        // crawler or turned away by the firewall's rate limit.
        if ($this->serveProxy()) {
            exit;
        }
        $this->protected = true;
        register_shutdown_function(array($this, 'afterResponse'));
        if (isset($this->modules['errors']) && $this->core->isOn('errors')) {
            $this->modules['errors']->install();
        }
        // Security headers, sent first: a header the site sets later replaces ours.
        if (!headers_sent()) {
            foreach ($this->securityHeaders() as $pair) {
                header($pair[0] . ': ' . $pair[1]);
            }
        }
        if (isset($this->modules['firewall'])) {
            // Its own shutdown work runs from afterResponse() below.
            $this->modules['firewall']->protect(false);
        }
        // Maintenance mode, unless the caller checks it itself (the WordPress
        // plugin does, so wp-admin and logins keep working).
        if (empty($this->options['maintenance_manual'])) {
            $this->sendMaintenancePage();
        }
    }

    // The first-party proxy, so ad blockers can't hide visitors:
    // $platform->proxy()->scriptUrl() and ->collectUrl() are the two
    // addresses the page's script tag needs, on this site's own domain.
    public function proxy()
    {
        return isset($this->modules['proxy']) && $this->core->isOn('proxy') ? $this->modules['proxy'] : null;
    }

    // True when the request was the tracker's and has been answered. Called
    // by protect(); a framework asks proxyResponse() for the answer instead.
    private function serveProxy()
    {
        $answer = $this->proxyResponse(
            isset($_SERVER['REQUEST_URI']) ? explode('?', $_SERVER['REQUEST_URI'], 2)[0] : '',
            isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : 'GET',
            isset($_SERVER['QUERY_STRING']) ? $_SERVER['QUERY_STRING'] : '',
            null,
            null
        );
        if ($answer === null) {
            return false;
        }
        $this->modules['proxy']->respond($answer);
        return true;
    }

    // The answer when the address belongs to the proxy, else null. $headers
    // and $body default to this request's; a framework passes its own.
    public function proxyResponse($path, $method = 'GET', $query = '', ?array $headers = null, $body = null, $ip = null)
    {
        $proxy = $this->proxy();
        if ($proxy === null) {
            return null;
        }
        $found = $proxy->match($path);
        if ($found === null) {
            return null;
        }
        if ($headers === null) {
            $headers = array();
            foreach ($_SERVER as $key => $value) {
                if (strncmp($key, 'HTTP_', 5) === 0) {
                    $headers[strtolower(str_replace('_', '-', substr($key, 5)))] = $value;
                }
            }
            if (!empty($_SERVER['CONTENT_TYPE'])) {
                $headers['content-type'] = $_SERVER['CONTENT_TYPE'];
            }
        }
        if ($body === null && strtoupper($method) === 'POST') {
            $body = file_get_contents('php://input', false, null, 0, Proxy::MAX_BODY + 1);
        }
        if ($ip === null) {
            $ip = $this->clientIp();
        }
        // A denied or banned address gets nothing from us either; the rate
        // limit, the browser check and the request rules stay out of it.
        $firewall = $this->firewall();
        if ($firewall && $this->core->isOn('firewall')) {
            try {
                $decision = $firewall->checkAddress($ip, $method, $path, isset($headers['user-agent']) ? (string) $headers['user-agent'] : '');
                if ($decision['action'] === 'block') {
                    return array('status' => 403, 'headers' => array('Content-Type' => 'text/plain; charset=utf-8', 'Cache-Control' => 'no-store'), 'body' => 'Forbidden');
                }
            } catch (\Throwable $e) {
                // fail open
            }
        }
        try {
            return $proxy->handle($found[0], $found[1], $method, $query, $headers, $body, $ip);
        } catch (\Throwable $e) {
            return array('status' => 502, 'headers' => array(), 'body' => '');
        }
    }

    // The request's route pattern for Server speed, e.g. "/orders/{id}".
    public function setRoute($route)
    {
        if (isset($this->modules['performance'])) {
            $this->modules['performance']->setRoute($route);
        }
        if (isset($this->modules['errors'])) {
            $this->modules['errors']->setRoute($route);
        }
    }

    // A database query your own hook timed (the packaged ones: Queries):
    // $db is postgresql, mysql, sqlite... and $ms its time; $failed when it threw.
    public function recordQuery($db, $sql, $ms, $failed = false)
    {
        if (isset($this->modules['queries'])) {
            $this->modules['queries']->record($db, $sql, $ms, $failed);
        }
    }

    // An outgoing HTTP call your own hook timed (the packaged ones: Laravel's
    // Http client, Symfony's HttpClientBreadcrumbs, guzzleMiddleware(), the
    // WordPress plugin): $ms from sending it to its answer's headers, and
    // $status the answer's, 0 when none came. Only the host is kept.
    public function recordCall($method, $url, $ms, $status)
    {
        $timings = $this->timings();
        if ($timings) {
            $timings->recordCall($method, $url, $ms, $status);
        }
    }

    // Guzzle: each call timed for Server speed → Calls and added to the
    // steps before an error, from Guzzle's own middleware interface and its
    // on_headers option (a callback of yours there still runs):
    //   $stack = GuzzleHttp\HandlerStack::create();
    //   $stack->push($platform->guzzleMiddleware());
    //   $client = new GuzzleHttp\Client(['handler' => $stack]);
    // Not for Laravel's Http client, which is timed on its own.
    public function guzzleMiddleware()
    {
        $platform = $this;
        return function (callable $handler) use ($platform) {
            return function ($request, array $options) use ($handler, $platform) {
                $started = microtime(true);
                $headers = null;
                $theirs = isset($options['on_headers']) && is_callable($options['on_headers']) ? $options['on_headers'] : null;
                // Each hop of a redirect: the last one's headers are the answer.
                $options['on_headers'] = function ($response) use (&$headers, $theirs) {
                    $headers = microtime(true);
                    if ($theirs) {
                        $theirs($response);
                    }
                };
                $method = (string) $request->getMethod();
                $url = (string) $request->getUri();
                // Never lets anything of ours replace the answer or the reason.
                $done = function ($status) use ($platform, $method, $url, $started, &$headers) {
                    try {
                        $platform->recordCall($method, $url, ((($headers !== null ? $headers : microtime(true)) - $started) * 1000), $status);
                        $platform->addRequestBreadcrumb($method, $url, $status);
                    } catch (\Throwable $e) {
                        // untimed
                    }
                };
                return $handler($request, $options)->then(function ($response) use ($done) {
                    $done(is_object($response) && method_exists($response, 'getStatusCode') ? (int) $response->getStatusCode() : 0);
                    return $response;
                }, function ($reason) use ($done) {
                    // Cancelled by the code: not a failure of the other side.
                    if (!(is_object($reason) && is_a($reason, 'GuzzleHttp\\Promise\\CancellationException'))) {
                        // An error answer (http_errors) is still an answer.
                        $response = is_object($reason) && method_exists($reason, 'getResponse') ? $reason->getResponse() : null;
                        $done(is_object($response) && method_exists($response, 'getStatusCode') ? (int) $response->getStatusCode() : 0);
                    }
                    if (class_exists('GuzzleHttp\\Promise\\Create')) {
                        return \GuzzleHttp\Promise\Create::rejectionFor($reason);
                    }
                    return \GuzzleHttp\Promise\rejection_for($reason);
                });
            };
        };
    }

    // A worker that serves many requests from one process (Octane,
    // RoadRunner, FrankenPHP) starting the next one: the queries and calls
    // left from the last are forgotten, and those outside a job belong to
    // requests.
    public function beginRequest()
    {
        $timings = $this->timings();
        if ($timings) {
            $timings->beginRequest();
        }
    }

    public function captureException($error, $request = null, $status = 0, $kind = 'handled')
    {
        if (isset($this->modules['errors'])) {
            $this->modules['errors']->captureException($error, $request, $status, $kind);
        }
    }

    // A step of your own in the trail shown before an error in this request or job.
    public function addBreadcrumb($text)
    {
        if (isset($this->modules['errors'])) {
            $this->modules['errors']->addBreadcrumb($text);
        }
    }

    // An outgoing request that has finished, for frameworks that announce them;
    // $status is 0 when no answer came.
    public function addRequestBreadcrumb($method, $url, $status)
    {
        if (isset($this->modules['errors'])) {
            $this->modules['errors']->addRequestBreadcrumb($method, $url, $status);
        }
    }

    // Between requests, in a worker that serves many (Octane).
    public function clearBreadcrumbs()
    {
        if (isset($this->modules['errors'])) {
            $this->modules['errors']->clearBreadcrumbs();
        }
    }

    // A feature flag from the dashboard ($user: for rollouts and user lists;
    // $default: until the flag is known, or with the module off).
    public function isEnabled($key, $user = null, $default = false)
    {
        if (!isset($this->modules['flags'])) {
            return $default;
        }
        $flags = $this->core->flags();
        return isset($flags[$key]) && is_array($flags[$key]) ? Flags::evaluate($flags[$key], (string) $key, $user) : $default;
    }

    // Maintenance mode's page for this request, or null to let it through.
    // $secure: whether the request came over https, from a framework that
    // knows (default: secure()).
    public function maintenancePage($secure = null)
    {
        if (!isset($this->modules['maintenance']) || PHP_SAPI === 'cli') {
            return null;
        }
        return Flags::maintenancePage($this->core->maintenance(), $this->clientIp(), $secure === null ? $this->secure() : (bool) $secure);
    }

    // Whether this request came over https: the server's word, or with
    // trust_proxy set, the proxy's X-Forwarded-Proto (Cloudflare's too). For
    // the Secure flag on the cookies we set.
    public function secure()
    {
        if ((!empty($_SERVER['HTTPS']) && strtolower((string) $_SERVER['HTTPS']) !== 'off')
            || (isset($_SERVER['REQUEST_SCHEME']) && strtolower((string) $_SERVER['REQUEST_SCHEME']) === 'https')) {
            return true;
        }
        $firewall = $this->firewall();
        $trust = $firewall ? $firewall->trustProxy() : 0;
        if ($trust === 'cloudflare' || (int) $trust > 0) {
            $proto = isset($_SERVER['HTTP_X_FORWARDED_PROTO']) ? strtolower(trim(explode(',', (string) $_SERVER['HTTP_X_FORWARDED_PROTO'])[0])) : '';
            return $proto === 'https';
        }
        return false;
    }

    // Sends maintenance mode's page and ends the request, when it applies.
    public function sendMaintenancePage()
    {
        $page = $this->maintenancePage();
        if ($page === null) {
            return;
        }
        if (!headers_sent()) {
            http_response_code(503);
            header('Retry-After: 600');
            header('Cache-Control: no-store');
            header('Content-Type: text/html; charset=utf-8');
        }
        echo $page;
        exit;
    }

    // Audit log: records who did what (sent after the response).
    public function audit($action, $actor = '', $target = '', $details = null)
    {
        if (!isset($this->modules['audit'])) {
            return;
        }
        $this->modules['audit']->record($action, $actor, $target, $details, PHP_SAPI === 'cli' ? '' : $this->clientIp());
    }

    // The dashboard's security headers, as array(name, value) pairs.
    public function securityHeaders()
    {
        return isset($this->modules['headers']) ? $this->core->securityHeaders() : array();
    }

    // Form protection: checks a form before you accept it (default: $_POST).
    // Returns array('ok', 'spam', 'reasons', 'checked'); spam goes to Leads → Spam.
    public function checkForm($fields = null, $email = null, $name = null, $form = null)
    {
        if (!isset($this->modules['forms'])) {
            return array('ok' => true, 'spam' => false, 'reasons' => array(), 'checked' => false);
        }
        try {
            return $this->modules['forms']->check(is_array($fields) ? $fields : $_POST, $this->clientIp(), $email, $name, $form);
        } catch (\Throwable $e) {
            return array('ok' => true, 'spam' => false, 'reasons' => array('unchecked'), 'checked' => false);
        }
    }

    // File monitoring: checks the files when due (or now, $force) and reports
    // what changed. From a cron job, never a visitor's request. $accept: the
    // files as they are now are the accepted version (after a deploy).
    public function checkFiles($force = false, $accept = false)
    {
        $files = $this->module('files');
        if (!$files || !$this->core->isOn('files') || (!$force && !$accept && !$files->due())) {
            return array();
        }
        try {
            return $files->run($accept);
        } catch (\Throwable $e) {
            return array();
        }
    }

    // Software inventory: reports the site's packages and runtime when due
    // (or now, $force). Platform does it after responses on its own unless
    // the module's 'manual' option is set (then from your cron job).
    public function checkInventory($force = false)
    {
        $inventory = $this->module('inventory');
        if (!$inventory || !$this->core->isOn('inventory') || (!$force && !$inventory->due())) {
            return array();
        }
        try {
            return $inventory->run();
        } catch (\Throwable $e) {
            return array();
        }
    }

    // How the site is set up (sdk/protocols/posture.md): reports when due (or
    // now, $force). It rides the inventory switch, so a site with software
    // inventory off reports no posture either. Returns the checks that failed.
    public function checkPosture($force = false)
    {
        $posture = $this->module('posture');
        if (!$posture || !$this->core->isOn('inventory') || (!$force && !$posture->due())) {
            return array();
        }
        try {
            return $posture->run();
        } catch (\Throwable $e) {
            return array();
        }
    }

    // A failed login (bot protection); default: the current visitor's address.
    public function loginFailed($ip = null)
    {
        if (isset($this->modules['firewall'])) {
            $this->modules['firewall']->loginFailed($ip);
        }
    }

    public function track($name, array $fields = array(), $sessionId = null)
    {
        return isset($this->modules['analytics']) ? $this->modules['analytics']->track($name, $fields, $sessionId) : '';
    }

    // $traits: optional user properties, name => text, number or true/false.
    public function identify($userId, $sessionId = null, $traits = array())
    {
        return isset($this->modules['analytics']) ? $this->modules['analytics']->identify($userId, $sessionId, $traits) : false;
    }

    public function lead(array $fields, $sessionId = null)
    {
        return isset($this->modules['analytics']) ? $this->modules['analytics']->lead($fields, $sessionId) : null;
    }

    // Laravel: times the request and sends what's waiting, from the
    // middleware's terminate() (Laravel doesn't call protect(), so there's no
    // shutdown run as well).
    public function recordAndSend()
    {
        $this->protected = true;
        $this->afterResponse();
        $this->protected = false;
    }

    // A background job (a queue job, a cron task): its errors are sent with
    // the job's name as their route, and each run is timed (Health → Server
    // speed → Jobs). A job that throws counts as failed; the exception is
    // sent and thrown on. A worker never reaches the end of a request, so on
    // the command line errors are sent after each job.
    //   $platform->job('send-receipts', function () { ... });
    public function job($name, callable $fn)
    {
        $this->startJob($name);
        try {
            $result = $fn();
        } catch (\Throwable $e) {
            $this->captureException($e, null, 500, 'error');
            $this->endJob(true);
            throw $e;
        }
        $this->endJob(false);
        return $result;
    }

    // The two halves of job(), for frameworks that announce jobs as events (Laravel's queue).
    public function startJob($name)
    {
        $route = '/(job) ' . substr((string) $name, 0, 180);
        $this->jobs[] = array($route, microtime(true));
        if (isset($this->modules['errors'])) {
            $this->modules['errors']->setJob($route);
        }
        $timings = $this->timings();
        if ($timings) {
            $timings->startJob();
        }
    }

    public function endJob($failed)
    {
        if (!$this->jobs) {
            return;
        }
        list($route, $started) = array_pop($this->jobs);
        if (isset($this->modules['errors'])) {
            $outer = end($this->jobs);
            $this->modules['errors']->setJob($outer ? $outer[0] : '');
        }
        $performance = isset($this->modules['performance']) ? $this->modules['performance'] : null;
        // Its queries and calls ride in the run's own line, so they are sent
        // under exactly what the run is filed as.
        $queries = $this->timings();
        $extra = $queries ? $queries->takeJob() : array();
        if ($performance) {
            $performance->recordJob($route, $failed ? 500 : 200, (microtime(true) - $started) * 1000, $extra);
        }
        if (PHP_SAPI === 'cli') {
            // A worker being stopped mustn't outlast its grace period.
            $this->core->within(Core::DEADLINE, function () use ($performance, $queries) {
                $this->sendErrors();
                if ($performance) {
                    $performance->flush();
                }
                if ($queries) {
                    $queries->flush();
                }
            });
        }
    }

    // Laravel: sends the errors waiting, and nothing else, from a shutdown
    // function. A fatal error ends the request before terminate() runs, so
    // the error Laravel reports at shutdown would otherwise never be sent.
    public function sendErrors()
    {
        $errors = isset($this->modules['errors']) ? $this->modules['errors'] : null;
        if (!$errors || !$errors->pending()) {
            return;
        }
        try {
            if (function_exists('fastcgi_finish_request')) {
                @fastcgi_finish_request();
            } elseif (function_exists('litespeed_finish_request')) {
                @litespeed_finish_request();
            }
            $this->core->within(Core::DEADLINE, function () use ($errors) {
                $errors->flush();
            });
        } catch (\Throwable $e) {
            // never break the site
        }
    }

    // Sends what's waiting and syncs rules and switches when due. Runs at
    // shutdown after protect(). Every send shares one deadline
    // (Core::DEADLINE): a collector that doesn't answer costs the worker a
    // few seconds, not one timeout per module, and what wasn't sent waits
    // in its spool for a later request.
    public function afterResponse()
    {
        try {
            $this->core->within(Core::DEADLINE, function () {
                $this->sendAll();
            });
        } catch (\Throwable $e) {
            // never break the site
        }
    }

    private function sendAll()
    {
        try {
            $errors = isset($this->modules['errors']) ? $this->modules['errors'] : null;
            $analytics = isset($this->modules['analytics']) ? $this->modules['analytics'] : null;
            $firewall = isset($this->modules['firewall']) ? $this->modules['firewall'] : null;
            $performance = isset($this->modules['performance']) ? $this->modules['performance'] : null;
            $queries = $this->timings();
            $queues = isset($this->modules['queues']) ? $this->modules['queues'] : null;
            $crawlers = isset($this->modules['crawlers']) ? $this->modules['crawlers'] : null;
            $resources = isset($this->modules['resources']) ? $this->modules['resources'] : null;
            $audit = isset($this->modules['audit']) ? $this->modules['audit'] : null;
            $inventory = isset($this->modules['inventory']) && !$this->modules['inventory']->manual() && $this->core->isOn('inventory')
                ? $this->modules['inventory'] : null;
            $posture = isset($this->modules['posture']) && !$this->modules['posture']->manual() && $this->core->isOn('inventory')
                ? $this->modules['posture'] : null;
            // Timed before anything below: what follows happens after the response.
            if ($performance && $this->protected) {
                // The request's queries and calls ride in its own line.
                $performance->recordRequest($queries ? $queries->takeRequest() : array());
            }
            // What's left of them: a run that isn't a timed request
            // (WordPress's cron) is background work.
            if ($queries) {
                $queries->endRequest();
            }
            // The jobs this request added to a queue.
            if ($queues) {
                $queues->save();
            }
            if ($crawlers && $this->protected) {
                $crawlers->recordRequest($this->clientIp());
            }
            // Fatal errors are read now, before deciding whether to send.
            if ($errors) {
                $errors->onShutdown();
            }
            $busy = ($errors && ($errors->pending() || $errors->due())) || ($analytics && ($analytics->pending() || $analytics->due())) || ($audit && ($audit->pending() || $audit->due())) || $this->core->switchesDue()
                || ($performance && $performance->due()) || ($queries && $queries->due()) || ($queues && $queues->due()) || ($crawlers && $crawlers->due()) || ($resources && $resources->due()) || ($inventory && $inventory->due()) || ($posture && $posture->due());
            // Closes the connection so everything below happens after the
            // response. LiteSpeed has its own name for it, and Apache's
            // mod_php has neither: there the visitor waits for the send,
            // which is why it is only ever done once a minute.
            if ($busy) {
                if (function_exists('fastcgi_finish_request')) {
                    @fastcgi_finish_request();
                } elseif (function_exists('litespeed_finish_request')) {
                    @litespeed_finish_request();
                }
            }
            // Errors first: they are what a short deadline must not lose.
            if ($errors) {
                $errors->flush();
            }
            $this->core->syncSwitches();
            if ($analytics) {
                $analytics->flush();
            }
            if ($audit) {
                $audit->flush();
            }
            if ($performance) {
                $performance->flush();
            }
            if ($queries) {
                $queries->flush();
            }
            if ($queues) {
                $queues->flush();
            }
            if ($crawlers) {
                $crawlers->flush();
            }
            if ($resources) {
                $resources->flush();
            }
            if ($firewall) {
                $firewall->afterResponse();
            }
            // About once a day, after everything else.
            if ($inventory && $inventory->due()) {
                $inventory->run();
            }
            if ($posture && $posture->due()) {
                $posture->run();
            }
        } catch (\Throwable $e) {
            // never break the site
        }
    }
}
