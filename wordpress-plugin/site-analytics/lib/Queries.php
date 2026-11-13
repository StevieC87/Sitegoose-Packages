<?php
// Database queries and outgoing calls (protocols in sdk/protocols/queries.md
// and calls.md): the half of Server speed that says *why* a route is slow.
// Every query the site's own code runs is timed through the database
// library's public hook, its values taken out (normalize(), the collector's
// queryText.js ported), and added to a small map for the request it ran in:
// per database and statement, how many ran, how many failed, their total and
// slowest time and a count per time bucket. Every outgoing HTTP call is
// added the same way, per call method and host (only the host: a path
// carries IDs and keys).
//
// PHP handles one request per process at a time, so the request's maps live
// here. When the request ends they are written into the request's own line
// of requests.jsonl (Performance::recordRequest), and the performance module,
// which adds those lines up once a minute, hands each line's maps back under
// the method and route it filed the request under — the very route, so a
// route Server speed folded into "(other)" past its cap has its queries and
// calls there too (#373) — to be sent to POST /events/server-queries and
// /events/server-calls. A queue job's go under the job's own row the same
// way, and those outside any request or job (a cron script, a worker between
// jobs) under JOB "(background)", through queries.jsonl.
//
// The query hooks, each recording a query once:
// - Laravel: QueryExecuted (DB::listen), in the service provider.
// - Symfony: Doctrine DBAL's middleware (Symfony\QueryMiddleware).
// - Plain PHP: new TimedPdo(...) instead of new PDO(...), and
//   TimedClickHouse for smi2/phpclickhouse.
// - MongoDB: the mongodb extension's global command subscriber, on its own
//   whenever the extension is loaded (Laravel's mongodb connections are
//   left to it, so they aren't counted twice).
// - WordPress: the plugin's wp-content/db.php drop-in, else SAVEQUERIES.
// - Redis: Laravel's CommandExecuted (the service provider turns its events
//   on), and new TimedRedis(\Redis) / new TimedPredis(Predis\Client) in
//   plain PHP. Each command is "GET user:?:cart" (redisCommand()): the
//   command and its first key's shape, never an argument or value.
// Each reports through Queries::report(), which works before any Platform
// exists (WordPress's drop-in runs before the plugins load): those queries
// wait here for the first one.
//
// The call hooks, the ones the error trail already uses: Laravel's Http
// client events, Symfony's HttpClientBreadcrumbs, the plugin's
// pre_http_request/http_api_debug, and Platform::guzzleMiddleware() for
// Guzzle. Each reports through Platform::recordCall().
//
// No values ever leave the server: literals are replaced by "?" before a
// query is counted, and bound parameters are never read. Rides on the
// performance module's switch; 'queries' => false leaves queries out and
// 'calls' => false the calls.

namespace AnalyticsPlatform;

class Queries
{
    // Keep in step with Performance::BUCKET_EDGES_MS and the collector
    // (expresscollect/Analytics/serverRequests.js). Copied, not referenced:
    // WordPress's drop-in loads this file before Performance exists.
    const BUCKET_EDGES_MS = array(5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000);
    const FLUSH_EVERY = 60;
    // A request's distinct statements (or hosts); past it new ones go under "(other)".
    const MAX_PER_REQUEST = 50;
    // Keys in a minute: past MAX_KEYS new statements (or hosts) go under
    // "(other)", past HARD_MAX_KEYS nothing new is kept.
    const MAX_KEYS = 200;
    const HARD_MAX_KEYS = 300;
    const MAX_ROWS = 500;
    const SPOOL_MAX = 5000000; // bytes waiting; more background lines aren't recorded
    // Past this the background spool is sent at once rather than at the
    // next minute.
    const SEND_BYTES = 1000000;
    const MAX_STATEMENT = 1000;
    const OTHER = '(other)';
    const BACKGROUND = '(background)';
    const DATABASES = array('postgresql', 'mysql', 'mariadb', 'sqlite', 'mssql', 'oracle', 'clickhouse', 'mongodb', 'redis', 'other');
    // Mongo's connection chatter, never a query of the site's.
    const MONGO_CHATTER = array('hello', 'isMaster', 'ismaster', 'ping', 'buildInfo', 'saslStart', 'saslContinue',
        'getMore', 'endSessions', 'killCursors', 'getLastError');
    // The two kinds, by the key their maps have in a line: q is queries
    // (db, statement), c is calls (call_method, host).
    const PATHS = array('q' => '/events/server-queries', 'c' => '/events/server-calls');

    // The module the hooks report to: the last one built.
    private static $active = null;
    // Queries timed before any module existed, as one request's map.
    private static $early = array();
    // How deep inside a timed call we are: an inner hook (a TimedPdo under
    // Doctrine) leaves the query to the outer one.
    private static $depth = 0;
    private static $mongo = false;
    private static $cache = array();
    // How deep inside untimed(): the package's own Redis commands.
    private static $untimed = 0;

    private $core;
    private $options;
    // Each holder: array('q' => map, 'c' => map).
    private $request;
    // The jobs running, innermost last: a holder each.
    private $jobs = array();
    private $background;
    private $backgroundMinute = 0;
    private $shutdown = false;
    // Whether a query outside a job belongs to a request: a web server's
    // process, or a worker serving requests once beginRequest() says so.
    private $serving;
    private $queriesOn;
    private $callsOn;
    // The collector's address as a call would be written (normalAddress()):
    // the package's own calls are never counted.
    private $own;

    // Options: server_name (default the host name); queries and calls
    // (false leaves that kind out).
    public function __construct(Core $core, array $options = array())
    {
        $this->core = $core;
        $this->options = $options + array('server_name' => function_exists('gethostname') ? gethostname() : '', 'queries' => true, 'calls' => true);
        $this->queriesOn = $this->options['queries'] !== false && $this->options['queries'] !== null;
        $this->callsOn = $this->options['calls'] !== false && $this->options['calls'] !== null;
        $this->own = self::normalAddress((string) $core->opt('endpoint'));
        $this->serving = PHP_SAPI !== 'cli' && PHP_SAPI !== 'phpdbg';
        $this->request = self::holder();
        $this->background = self::holder();
        // The query hooks report to the last module that times queries.
        if ($this->queriesOn) {
            $this->request['q'] = self::$early;
            self::$early = array();
            self::$active = $this;
            self::watchMongo();
        }
    }

    private static function holder()
    {
        return array('q' => array(), 'c' => array());
    }

    public function queriesOn()
    {
        return $this->queriesOn;
    }

    public function callsOn()
    {
        return $this->callsOn;
    }

    // ---- Recording --------------------------------------------------------------

    // What every query hook calls: a query that took $ms and threw (or
    // returned false) when $failed.
    public static function report($db, $sql, $ms, $failed = false)
    {
        if (self::$active !== null) {
            self::$active->record($db, $sql, $ms, $failed);
            return;
        }
        try {
            $db = self::databaseOf($db);
            $statement = self::statement($sql, $db);
            if ($statement !== '') {
                self::add(self::$early, $db, $statement, (float) $ms, $failed, self::MAX_PER_REQUEST);
            }
        } catch (\Throwable $e) {
            // never break the query it was told of
        }
    }

    // Runs a query and reports it, for the hooks that run it themselves
    // (TimedPdo, Doctrine's middleware): failed when it threw or returned
    // false (PDO without exceptions). Inside another timed call it only
    // runs: the outer hook reports it.
    public static function timed($db, $sql, callable $run)
    {
        $outer = self::$depth++ === 0;
        $started = microtime(true);
        $failed = true;
        try {
            $result = $run();
            $failed = $result === false;
            return $result;
        } finally {
            self::$depth = max(0, self::$depth - 1);
            if ($outer) {
                self::report($db, $sql, (microtime(true) - $started) * 1000, $failed);
            }
        }
    }

    // Runs $fn with the Redis commands it makes left out: the package's own
    // (QueueWatch's queue readings, the firewall's counter in Laravel's
    // cache), which share the app's connection.
    public static function untimed(callable $fn)
    {
        self::$untimed++;
        try {
            return $fn();
        } finally {
            self::$untimed = max(0, self::$untimed - 1);
        }
    }

    // Whether a Redis command now is the package's own.
    public static function isUntimed()
    {
        return self::$untimed > 0;
    }

    // Never throws: it runs inside the site's own query call (TimedPdo's
    // finally, Laravel's listener), where a framework's error handler would
    // turn a file warning into an exception thrown at that query.
    public function record($db, $sql, $ms, $failed = false)
    {
        try {
            if (!$this->queriesOn || !$this->core->isOn('performance')) {
                return;
            }
            $db = self::databaseOf($db);
            $statement = self::statement($sql, $db);
            if ($statement === '') {
                return;
            }
            $this->put('q', $db, $statement, max(0.0, (float) $ms), $failed);
        } catch (\Throwable $e) {
            // not counted
        }
    }

    // An outgoing HTTP call that took $ms from being sent to its answer's
    // headers; $status is the answer's, 0 when none came. No answer or a
    // 5xx is a failed call; a 4xx is the other side's answer. Only the host
    // is kept, and the package's own calls to the collector are left out.
    // Never throws, like record().
    public function recordCall($method, $url, $ms, $status)
    {
        try {
            if (!$this->callsOn || !$this->core->isOn('performance')) {
                return;
            }
            $method = strtoupper(trim((string) $method));
            if (!preg_match('/^[A-Z]{1,10}\z/', $method) || $this->isOwn((string) $url)) {
                return;
            }
            $host = self::hostOf((string) $url);
            if ($host === '') {
                return;
            }
            $status = (int) $status;
            $this->put('c', $method, $host, max(0.0, (float) $ms), !($status > 0 && $status < 500));
        } catch (\Throwable $e) {
            // not counted
        }
    }

    // Into the innermost job, else the request, else the background.
    private function put($kind, $a, $b, $ms, $failed)
    {
        if ($this->jobs) {
            self::add($this->jobs[count($this->jobs) - 1][$kind], $a, $b, $ms, $failed, self::MAX_PER_REQUEST);
        } elseif ($this->serving) {
            self::add($this->request[$kind], $a, $b, $ms, $failed, self::MAX_PER_REQUEST);
        } else {
            $this->addBackground($kind, $a, $b, $ms, $failed);
        }
    }

    // A worker that serves many requests from one process (Octane,
    // RoadRunner, FrankenPHP) starting the next one: nothing of the last is
    // kept, and queries and calls outside a job belong to requests from now on.
    public function beginRequest()
    {
        $this->request = self::holder();
        $this->serving = true;
    }

    // The request's queries and calls, taken for its line in requests.jsonl
    // (Performance::recordRequest): array('q' => rows, 'c' => rows), each
    // only when there are some.
    public function takeRequest()
    {
        $holder = $this->request;
        $this->request = self::holder();
        return $this->core->isOn('performance') ? self::lineOf($holder) : array();
    }

    // The request ended without takeRequest(): it isn't one the performance
    // module times (WordPress's cron), so what ran in it is background work.
    public function endRequest()
    {
        $holder = $this->request;
        $this->request = self::holder();
        if (!$holder['q'] && !$holder['c']) {
            return;
        }
        foreach ($holder as $kind => $map) {
            foreach ($map as $row) {
                $this->mergeBackground($kind, $row);
            }
        }
        $this->saveBackground();
    }

    public function startJob()
    {
        $this->jobs[] = self::holder();
    }

    // The innermost job's queries and calls, for its line in requests.jsonl
    // (Performance::recordJob), as takeRequest()'s.
    public function takeJob()
    {
        if (!$this->jobs) {
            return array();
        }
        $holder = array_pop($this->jobs);
        return $this->core->isOn('performance') ? self::lineOf($holder) : array();
    }

    private static function add(array &$map, $a, $b, $ms, $failed, $cap)
    {
        $key = $a . "\0" . $b;
        if (!isset($map[$key]) && count($map) >= $cap) {
            $b = self::OTHER;
            $key = $a . "\0" . $b;
        }
        if (!isset($map[$key])) {
            $map[$key] = array($a, $b, 0, 0, 0.0, 0.0, array_fill(0, count(self::BUCKET_EDGES_MS) + 1, 0));
        }
        $map[$key][2]++;
        if ($failed) {
            $map[$key][3]++;
        }
        $map[$key][4] += $ms;
        if ($ms > $map[$key][5]) {
            $map[$key][5] = $ms;
        }
        $map[$key][6][self::bucketOf($ms)]++;
    }

    // Outside a request or job: kept per minute in memory, written out when
    // the minute changes and at the end of the script.
    private function addBackground($kind, $a, $b, $ms, $failed)
    {
        $minute = (int) (floor(time() / 60) * 60);
        if (($this->background['q'] || $this->background['c']) && $minute !== $this->backgroundMinute) {
            $this->saveBackground();
        }
        $this->backgroundMinute = $minute;
        // The minute's own caps apply when the lines are added up.
        self::add($this->background[$kind], $a, $b, $ms, $failed, self::HARD_MAX_KEYS);
        if (!$this->shutdown) {
            $this->shutdown = true;
            register_shutdown_function(array($this, 'onShutdown'));
        }
    }

    // A worker between jobs keeps its background minute in memory until the
    // next query: written out once that minute is over, at its next flush.
    private function saveFinishedBackground()
    {
        if (($this->background['q'] || $this->background['c']) && $this->backgroundMinute !== (int) (floor(time() / 60) * 60)) {
            $this->saveBackground();
        }
    }

    private function mergeBackground($kind, array $row)
    {
        if (!$this->background['q'] && !$this->background['c']) {
            $this->backgroundMinute = (int) (floor(time() / 60) * 60);
        }
        $key = $row[0] . "\0" . $row[1];
        if (!isset($this->background[$kind][$key])) {
            $this->background[$kind][$key] = $row;
            return;
        }
        $into = &$this->background[$kind][$key];
        $into[2] += $row[2];
        $into[3] += $row[3];
        $into[4] += $row[4];
        $into[5] = max($into[5], $row[5]);
        foreach ($row[6] as $i => $n) {
            $into[6][$i] += $n;
        }
    }

    private function saveBackground()
    {
        $holder = $this->background;
        $this->background = self::holder();
        if ($holder['q'] || $holder['c']) {
            $this->save($this->backgroundMinute ?: time(), 'JOB', self::BACKGROUND, $holder);
        }
    }

    // The end of a script: what ran outside any request is written out, and
    // on the command line sent when due, since no request will come along.
    public function onShutdown()
    {
        try {
            $this->saveBackground();
            if (PHP_SAPI === 'cli') {
                $this->core->within(Core::DEADLINE, function () {
                    $this->flush();
                });
            }
        } catch (\Throwable $e) {
            // never break the site
        }
    }

    // A holder as a line's fields: rows of (a, b, count, errors, sum, max,
    // buckets), rounded to the microsecond.
    private static function lineOf(array $holder)
    {
        $line = array();
        foreach ($holder as $kind => $map) {
            $rows = array();
            foreach ($map as $row) {
                $rows[] = array($row[0], $row[1], $row[2], $row[3], round($row[4], 3), round($row[5], 3), $row[6]);
            }
            if ($rows) {
                $line[$kind] = $rows;
            }
        }
        return $line;
    }

    private function save($at, $method, $route, array $holder)
    {
        if (!$this->core->isOn('performance') || !$this->core->ensureDir()) {
            return;
        }
        $line = self::lineOf($holder);
        if ($line) {
            $this->core->append('queries', array('t' => (int) $at, 'm' => (string) $method, 'r' => (string) $route) + $line, self::SPOOL_MAX);
        }
    }

    private static function bucketOf($ms)
    {
        foreach (self::BUCKET_EDGES_MS as $i => $edge) {
            if ($ms <= $edge) {
                return $i;
            }
        }
        return count(self::BUCKET_EDGES_MS);
    }

    // ---- Calls: the host ----------------------------------------------------------

    // The host of a call as calls.md stores it: lower case, with its port
    // when it isn't the scheme's own; '' when the address has none, or one
    // the collector would refuse.
    public static function hostOf($url)
    {
        $parts = @parse_url(trim((string) $url));
        if (!is_array($parts) || !isset($parts['host']) || $parts['host'] === '') {
            return '';
        }
        $host = strtolower($parts['host']);
        if (preg_match('/[^\x00-\x7F]/', $host)) {
            $ascii = function_exists('idn_to_ascii') ? @idn_to_ascii($host, 0, defined('INTL_IDNA_VARIANT_UTS46') ? INTL_IDNA_VARIANT_UTS46 : 0) : false;
            if (!is_string($ascii) || $ascii === '') {
                return '';
            }
            $host = strtolower($ascii);
        }
        // An IPv6 address keeps its brackets, as a URL writes it.
        if (strpos($host, ':') !== false && $host[0] !== '[') {
            $host = '[' . $host . ']';
        }
        $scheme = isset($parts['scheme']) ? strtolower($parts['scheme']) : '';
        $defaults = array('http' => 80, 'https' => 443, 'ws' => 80, 'wss' => 443);
        if (isset($parts['port']) && !(isset($defaults[$scheme]) && $defaults[$scheme] === (int) $parts['port'])) {
            $host .= ':' . (int) $parts['port'];
        }
        return preg_match('/^[a-z0-9._\-\[\]:]{1,255}\z/', $host) ? $host : '';
    }

    // scheme://host[:port]/path, without the query, the fragment or a
    // trailing slash, so two ways of writing one address compare equal.
    private static function normalAddress($url)
    {
        $host = self::hostOf($url);
        if ($host === '') {
            return '';
        }
        $parts = @parse_url(trim((string) $url));
        $scheme = isset($parts['scheme']) ? strtolower($parts['scheme']) : '';
        $path = isset($parts['path']) ? rtrim($parts['path'], '/') : '';
        return $scheme . '://' . $host . $path;
    }

    // The package's own call to the collector: its address or below it.
    private function isOwn($url)
    {
        if ($this->own === '') {
            return false;
        }
        $address = self::normalAddress($url);
        return $address === $this->own || strpos($address, $this->own . '/') === 0;
    }

    // ---- Sending ----------------------------------------------------------------

    private function big()
    {
        return $this->core->spoolOver('queries', self::SEND_BYTES);
    }

    public function due()
    {
        return $this->core->waiting('queries') && ($this->core->sendDue('queries', self::FLUSH_EVERY) || $this->big());
    }

    // Sends the background lines (queries.jsonl), added up, once a minute.
    public function flush($force = false)
    {
        $this->saveFinishedBackground();
        $this->core->drain('queries', $this->big() ? 0 : self::FLUSH_EVERY, $force, function (array $recorded) {
            $lines = array();
            foreach ($recorded as $line) {
                if (!isset($line['t'], $line['m'], $line['r'])) {
                    continue;
                }
                $lines[] = array((int) (floor($line['t'] / 60) * 60), Performance::method($line['m']), (string) $line['r'],
                    isset($line['q']) ? $line['q'] : null, isset($line['c']) ? $line['c'] : null);
            }
            $this->send($lines);
        });
    }

    // Requests' and jobs' queries and calls, from the performance module's
    // send: each array(minute, method, route, queries, calls) exactly as it
    // filed the request, so the dashboard can join the two.
    public function sendTimed(array $lines)
    {
        try {
            $this->send($lines);
        } catch (\Throwable $e) {
            // never break the site
        }
    }

    // Adds the lines up per minute, method, route and the kind's two key
    // fields, with the minute's caps, and posts each kind to its endpoint.
    private function send(array $lines)
    {
        foreach (self::PATHS as $kind => $path) {
            if (($kind === 'q' && !$this->queriesOn) || ($kind === 'c' && !$this->callsOn)) {
                continue;
            }
            $rows = array();
            $keys = array();
            foreach ($lines as $line) {
                $items = $line[$kind === 'q' ? 3 : 4];
                if (!is_array($items)) {
                    continue;
                }
                list($minute, $method, $route) = $line;
                foreach ($items as $item) {
                    if (!is_array($item) || count($item) < 7 || !is_array($item[6])) {
                        continue;
                    }
                    if ($kind === 'q') {
                        $a = self::databaseOf($item[0]);
                    } else {
                        $a = strtoupper((string) $item[0]);
                        if (!preg_match('/^[A-Z]{1,10}\z/', $a)) {
                            continue;
                        }
                    }
                    $b = (string) $item[1];
                    $key = json_encode(array($minute, $method, $route, $a, $b));
                    $count = isset($keys[$minute]) ? $keys[$minute] : 0;
                    if (!isset($rows[$key]) && $count >= self::MAX_KEYS) {
                        $b = self::OTHER;
                        $key = json_encode(array($minute, $method, $route, $a, $b));
                    }
                    if (!isset($rows[$key]) && $count >= self::HARD_MAX_KEYS) {
                        continue;
                    }
                    if (!isset($rows[$key])) {
                        $keys[$minute] = $count + 1;
                        $rows[$key] = array('minute' => gmdate('Y-m-d\TH:i:s.000\Z', $minute), 'method' => $method, 'route' => $route)
                            + ($kind === 'q' ? array('db' => $a, 'statement' => $b) : array('host' => $b, 'call_method' => $a))
                            + array('count' => 0, 'errors' => 0, 'sum_ms' => 0.0, 'max_ms' => 0.0,
                                'buckets' => array_fill(0, count(self::BUCKET_EDGES_MS) + 1, 0));
                    }
                    $rows[$key]['count'] += (int) $item[2];
                    $rows[$key]['errors'] += (int) $item[3];
                    $rows[$key]['sum_ms'] += (float) $item[4];
                    $rows[$key]['max_ms'] = max($rows[$key]['max_ms'], (float) $item[5]);
                    foreach ($rows[$key]['buckets'] as $i => $n) {
                        $rows[$key]['buckets'][$i] = $n + (isset($item[6][$i]) ? (int) $item[6][$i] : 0);
                    }
                }
            }
            foreach ($rows as $key => $row) {
                $rows[$key]['sum_ms'] = round($row['sum_ms'], 1);
                $rows[$key]['max_ms'] = round($row['max_ms'], 1);
            }
            // Both kinds retry through the queries spool: a kept batch
            // carries its own path.
            foreach (array_chunk(array_values($rows), self::MAX_ROWS) as $batch) {
                $this->core->post('queries', $path, array(
                    'site_id' => (string) $this->core->opt('site_id'),
                    'server_name' => substr((string) $this->options['server_name'], 0, 100),
                    'runtime' => 'PHP ' . PHP_VERSION,
                    'rows' => $batch,
                ), 'bearer');
            }
        }
    }

    // ---- MongoDB ----------------------------------------------------------------

    // The mongodb extension's global command subscriber, once per process,
    // when the extension is loaded. Its public monitoring API: nothing of
    // the driver is patched.
    public static function watchMongo()
    {
        if (self::$mongo || !function_exists('MongoDB\\Driver\\Monitoring\\addSubscriber')
            || !interface_exists('MongoDB\\Driver\\Monitoring\\CommandSubscriber')) {
            return false;
        }
        self::$mongo = true;
        // Declared only here, so this file loads without the extension.
        \MongoDB\Driver\Monitoring\addSubscriber(new class implements \MongoDB\Driver\Monitoring\CommandSubscriber {
            // The commands started and not yet finished, by request id.
            private $started = array();

            public function commandStarted($event): void
            {
                try {
                    $text = Queries::mongoText($event->getCommandName(), $event->getCommand());
                } catch (\Throwable $e) {
                    return;
                }
                if ($text === '') {
                    return;
                }
                if (count($this->started) >= 1000) {
                    $this->started = array();
                }
                $this->started[(string) $event->getRequestId()] = $text;
            }

            public function commandSucceeded($event): void
            {
                $this->finish($event, false);
            }

            public function commandFailed($event): void
            {
                $this->finish($event, true);
            }

            private function finish($event, $failed)
            {
                $id = (string) $event->getRequestId();
                if (!isset($this->started[$id])) {
                    return;
                }
                $text = $this->started[$id];
                unset($this->started[$id]);
                Queries::report('mongodb', $text, $event->getDurationMicros() / 1000, $failed);
            }
        });
        return true;
    }

    // "<command> <collection> <filter as JSON>", as the protocol has the
    // package build it; '' for connection chatter.
    public static function mongoText($name, $command)
    {
        $name = (string) $name;
        if ($name === '' || in_array($name, self::MONGO_CHATTER, true)) {
            return '';
        }
        $command = is_object($command) ? $command : (object) (array) $command;
        $collection = isset($command->{$name}) && is_string($command->{$name}) ? $command->{$name} : '';
        $filter = null;
        if ($name === 'find' && isset($command->filter)) {
            $filter = $command->filter;
        } elseif ($name === 'aggregate' && isset($command->pipeline)) {
            $filter = $command->pipeline;
        } elseif (in_array($name, array('count', 'distinct', 'findAndModify'), true) && isset($command->query)) {
            $filter = $command->query;
        } elseif ($name === 'delete' || $name === 'update') {
            $field = $name . 's'; // deletes, updates
            $list = isset($command->{$field}) ? $command->{$field} : null;
            $first = is_array($list) && $list ? reset($list) : null;
            if (is_object($first) && isset($first->q)) {
                $filter = $first->q;
            } elseif (is_array($first) && isset($first['q'])) {
                $filter = $first['q'];
            }
        }
        $text = $name . ($collection !== '' ? ' ' . $collection : '');
        if ($filter !== null) {
            // BSON types write themselves as extended JSON ({"$oid": ...}),
            // and every value is "?" once normalized.
            $json = json_encode($filter, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE | JSON_PARTIAL_OUTPUT_ON_ERROR);
            if (is_string($json) && $collection !== '') {
                $text .= ' ' . $json;
            }
        }
        return $text;
    }

    // ---- Normalizing ------------------------------------------------------------
    // expresscollect/Analytics/queryText.js, ported character for character:
    // sdk/protocols/query-cases.json is run against this (test/QueriesTest.php).
    // It scans bytes, not characters: everything the rule looks for is ASCII,
    // and no byte of a multi-byte UTF-8 character is, except JavaScript's
    // whitespace (its \s and trim()), matched here by its UTF-8 bytes. So it
    // gives JavaScript's answer for any valid UTF-8 and never fails on bytes
    // that aren't.

    // JavaScript's whitespace: \t \n \v \f \r, space, and U+00A0, U+1680,
    // U+2000-200A, U+2028, U+2029, U+202F, U+205F, U+3000, U+FEFF.
    const WS = '(?:[\t\n\x0B\f\r ]|\xC2\xA0|\xE1\x9A\x80|\xE2\x80[\x80-\x8A\xA8\xA9\xAF]|\xE2\x81\x9F|\xE3\x80\x80|\xEF\xBB\xBF)';
    const PLACEHOLDER = '(?:\?|\$[0-9]+|:[A-Za-z0-9_]+|@[A-Za-z0-9_]+)';
    // Bytes the scan stops at; any other byte is copied as it is.
    const SPECIAL = "-#/'\"`\$0123456789.\t\n\x0B\f\r \xC2\xE1\xE2\xE3\xEF";

    public static function databaseOf($db)
    {
        // Lower case as JavaScript's toLowerCase gives it for these names:
        // ASCII whatever the locale, and the Kelvin sign is a k. No other
        // non-ASCII character lower-cases to a letter of a name.
        $name = strtr(str_replace("\xE2\x84\xAA", 'k', is_scalar($db) ? (string) $db : ''),
            'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz');
        return in_array($name, self::DATABASES, true) ? $name : 'other';
    }

    // A driver's own name for its database (PDO's, Laravel's, Doctrine's)
    // as the protocol names it.
    public static function databaseOfDriver($driver)
    {
        $name = strtolower((string) $driver);
        $map = array(
            'pgsql' => 'postgresql', 'pdo_pgsql' => 'postgresql', 'postgres' => 'postgresql', 'postgresql' => 'postgresql',
            'mysql' => 'mysql', 'pdo_mysql' => 'mysql', 'mysqli' => 'mysql', 'mariadb' => 'mariadb',
            'sqlite' => 'sqlite', 'pdo_sqlite' => 'sqlite', 'sqlite3' => 'sqlite',
            'sqlsrv' => 'mssql', 'pdo_sqlsrv' => 'mssql', 'dblib' => 'mssql', 'mssql' => 'mssql',
            'oci' => 'oracle', 'oci8' => 'oracle', 'pdo_oci' => 'oracle', 'oracle' => 'oracle',
            'clickhouse' => 'clickhouse', 'pdo_clickhouse' => 'clickhouse',
            'mongodb' => 'mongodb',
            'redis' => 'redis', 'phpredis' => 'redis', 'predis' => 'redis',
        );
        return isset($map[$name]) ? $map[$name] : 'other';
    }

    // The statement to store, or '' when nothing is left of it.
    public static function normalize($text, $db)
    {
        if (!is_string($text)) {
            return '';
        }
        if ($text === self::OTHER) {
            return $text;
        }
        $db = self::databaseOf($db);
        if ($db === 'mongodb') {
            $shaped = self::mongoStatement($text);
        } elseif ($db === 'redis') {
            $shaped = self::redisStatement($text);
        } elseif ($db === 'other' && strpos($text, '\\') !== false) {
            // A database we don't know may or may not take a backslash as an
            // escape, and each reading leaks what the other hides. When they
            // disagree the query keeps its timing under (other) and its text
            // is left out.
            $escaped = self::sqlShape($text, $db, false);
            $shaped = $escaped === self::sqlShape($text, $db, true) ? $escaped : self::OTHER;
        } else {
            $shaped = self::sqlShape($text, $db);
        }
        return self::cut($shaped);
    }

    // normalize(), remembered for the statements a request runs again.
    private static function statement($sql, $db)
    {
        if (!is_string($sql) || strlen($sql) > 4000) {
            return self::normalize($sql, $db);
        }
        $key = $db . "\0" . $sql;
        if (!isset(self::$cache[$key])) {
            if (count(self::$cache) >= 500) {
                self::$cache = array();
            }
            self::$cache[$key] = self::normalize($sql, $db);
        }
        return self::$cache[$key];
    }

    // The byte length of the whitespace character at $i, or 0.
    private static function spaceAt($s, $i)
    {
        $c = $s[$i];
        if ($c === ' ' || $c === "\t" || $c === "\n" || $c === "\r" || $c === "\x0B" || $c === "\f") {
            return 1;
        }
        $o = ord($c);
        if ($o !== 0xC2 && $o !== 0xE1 && $o !== 0xE2 && $o !== 0xE3 && $o !== 0xEF) {
            return 0;
        }
        return preg_match('/\G' . self::WS . '/', $s, $m, 0, $i) ? strlen($m[0]) : 0;
    }

    // [A-Za-z0-9_$@:]: a digit after one is part of a name or placeholder.
    private static function isWord($c)
    {
        return $c !== '' && (ctype_alnum($c) && ord($c) < 128 || $c === '_' || $c === '$' || $c === '@' || $c === ':');
    }

    private static function trimJs($s)
    {
        $start = 0;
        $n = strlen($s);
        while ($start < $n && ($w = self::spaceAt($s, $start)) > 0) {
            $start += $w;
        }
        $end = $n;
        while ($end > $start) {
            if (strpos("\t\n\x0B\f\r ", $s[$end - 1]) !== false) {
                $end--;
                continue;
            }
            if ($end - $start >= 2 && substr($s, $end - 2) === "\xC2\xA0") {
                $end -= 2;
                continue;
            }
            if ($end - $start >= 3 && preg_match('/' . self::WS . '\z/', substr($s, $end - 3, 3))) {
                $end -= 3;
                continue;
            }
            break;
        }
        return substr($s, $start, $end - $start);
    }

    // The end of a quoted run starting at $start (the opening quote): the
    // index after the closing quote, or the text's length. A doubled quote
    // escapes, and a backslash too unless $backslash is false.
    private static function quoteEnd($sql, $start, $quote, $backslash = true)
    {
        $n = strlen($sql);
        $i = $start + 1;
        $stops = $backslash ? $quote . '\\' : $quote;
        while ($i < $n) {
            $i += strcspn($sql, $stops, $i);
            if ($i >= $n) {
                break;
            }
            if ($backslash && $sql[$i] === '\\') {
                $i += 2;
            } elseif ($i + 1 < $n && $sql[$i + 1] === $quote) {
                $i += 2;
            } else {
                return $i + 1;
            }
        }
        return $n;
    }

    private static function sqlShape($sql, $db, $backslashLiteral = null)
    {
        $mysql = $db === 'mysql' || $db === 'mariadb';
        $postgres = $db === 'postgresql';
        // Where a backslash in a string is just a character: PostgreSQL's
        // plain strings (standard_conforming_strings, on since 9.1), SQLite,
        // SQL Server and Oracle. Read as an escape there, 'C:\' ends late and
        // lets what follows out (#376). MySQL, MariaDB, ClickHouse and
        // unknown databases escape.
        $literal = $backslashLiteral === null
            ? ($postgres || $db === 'sqlite' || $db === 'mssql' || $db === 'oracle')
            : $backslashLiteral;
        $out = '';
        $n = strlen($sql);
        $i = 0;
        while ($i < $n) {
            $run = strcspn($sql, self::SPECIAL, $i);
            if ($run > 0) {
                $out .= substr($sql, $i, $run);
                $i += $run;
                continue;
            }
            $c = $sql[$i];
            $next = $i + 1 < $n ? $sql[$i + 1] : '';
            $prev = $i > 0 ? $sql[$i - 1] : '';
            if (($c === '-' && $next === '-') || ($c === '#' && $mysql)) {
                $end = strpos($sql, "\n", $i);
                $i = $end === false ? $n : $end;
                self::space($out);
            } elseif ($c === '/' && $next === '*') {
                $end = strpos($sql, '*/', $i + 2);
                $i = $end === false ? $n : $end + 2;
                self::space($out);
            } elseif ($c === "'" || ($c === '"' && $mysql)) {
                // A string's one-letter prefix: E'..' N'..' X'..' B'..'.
                $len = strlen($out);
                $prefixed = $len > 0 && strpos('EeNnXxBb', $out[$len - 1]) !== false
                    && ($len === 1 || !(ctype_alnum($out[$len - 2]) && ord($out[$len - 2]) < 128 || $out[$len - 2] === '_'));
                // Only PostgreSQL's E'..' escapes with a backslash where it is literal.
                $escapes = !$literal || ($postgres && $prefixed && ($out[$len - 1] === 'E' || $out[$len - 1] === 'e'));
                if ($prefixed) {
                    $out = substr($out, 0, -1);
                }
                $i = self::quoteEnd($sql, $i, $c, $escapes);
                $out .= '?';
            } elseif ($c === '"' || $c === '`') {
                $end = self::quoteEnd($sql, $i, $c, !$literal);
                $out .= substr($sql, $i, $end - $i);
                $i = $end;
            } elseif ($c === '$' && !self::isWord($prev) && preg_match('/^\$(?:[A-Za-z_][A-Za-z0-9_]*)?\$/', substr($sql, $i, 64), $m)) {
                $tag = $m[0];
                $end = strpos($sql, $tag, $i + strlen($tag));
                $i = $end === false ? $n : $end + strlen($tag);
                $out .= '?';
            } elseif ((ctype_digit($c) || ($c === '.' && $next !== '' && ctype_digit($next))) && !self::isWord($prev)) {
                preg_match('/^(?:0[xX][0-9a-fA-F]+|(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]+)?)/', substr($sql, $i, 400), $m);
                $i += strlen($m[0]);
                $out .= '?';
            } elseif (($w = self::spaceAt($sql, $i)) > 0) {
                $i += $w;
                self::space($out);
            } else {
                $out .= $c;
                $i += 1;
            }
        }
        // A list of only placeholders is one (?), and so are rows of them.
        $out = preg_replace('/\(' . self::WS . '*' . self::PLACEHOLDER . '(?:' . self::WS . '*,' . self::WS . '*' . self::PLACEHOLDER . ')*' . self::WS . '*\)/', '(?)', $out);
        $out = preg_replace('/\(\?\)(?:' . self::WS . '*,' . self::WS . '*\(\?\))+/', '(?)', $out);
        return self::trimJs((string) $out);
    }

    private static function space(&$out)
    {
        if ($out !== '' && substr($out, -1) !== ' ') {
            $out .= ' ';
        }
    }

    // Where the run of non-whitespace starting at $i ends.
    private static function wordEnd($s, $i)
    {
        $n = strlen($s);
        while ($i < $n) {
            $i += strcspn($s, "\t\n\x0B\f\r \xC2\xE1\xE2\xE3\xEF", $i);
            if ($i >= $n || self::spaceAt($s, $i) > 0) {
                return $i;
            }
            $i++;
        }
        return $n;
    }

    // "find users {...}": the command, the collection, and the filter's shape.
    // The split is queryText.js's /^(\S+)(?: (\S+))?(?: ([\s\S]*))?$/, worked
    // out by hand.
    private static function mongoStatement($text)
    {
        $text = self::trimJs($text);
        $n = strlen($text);
        if ($n === 0) {
            return '';
        }
        $p = self::wordEnd($text, 0);
        $command = substr($text, 0, $p);
        $collection = '';
        $rest = '';
        if ($p < $n) {
            if ($text[$p] !== ' ') {
                return '';
            }
            $q = self::wordEnd($text, $p + 1);
            if ($q > $p + 1 && ($q === $n || $text[$q] === ' ')) {
                $collection = substr($text, $p + 1, $q - $p - 1);
                $rest = $q < $n ? substr($text, $q + 1) : '';
            } else {
                $rest = substr($text, $p + 1);
            }
        }
        // A "collection" with a brace, bracket or quote in it is the filter's start.
        if ($collection !== '' && strpbrk($collection, '{}[]"\'') !== false) {
            $rest = $rest === '' ? $collection : $collection . ' ' . $rest;
            $collection = '';
        }
        $shape = '';
        if ($rest !== '') {
            // Objects as objects, so {} and [] stay apart and keys keep their order.
            $value = json_decode($rest, false, 100000);
            if (json_last_error() === JSON_ERROR_NONE) {
                $shape = self::mongoShape($value, 0);
            }
        }
        $parts = array($command);
        if ($collection !== '') {
            $parts[] = $collection;
        }
        if ($shape !== '') {
            $parts[] = $shape;
        }
        return implode(' ', $parts);
    }

    // A filter or pipeline's shape, as JSON: keys kept, every value "?", an
    // array whose items all have the same shape kept as one, and anything
    // deeper than six levels "?". Keys come out in JavaScript's order
    // (integer keys first, ascending), and "__proto__" not at all, as
    // queryText.js's object gives them.
    private static function mongoShape($value, $depth)
    {
        if ($depth >= 6 || !(is_array($value) || $value instanceof \stdClass)) {
            return '"?"';
        }
        if (is_array($value)) {
            $items = array();
            foreach ($value as $item) {
                $items[] = self::mongoShape($item, $depth + 1);
            }
            return '[' . (count(array_unique($items)) === 1 ? $items[0] : implode(',', $items)) . ']';
        }
        $numbered = array();
        $named = array();
        foreach ($value as $key => $item) {
            $key = (string) $key;
            if ($key === '__proto__') {
                continue;
            }
            if (preg_match('/^(?:0|[1-9][0-9]{0,9})\z/', $key) && (float) $key <= 4294967294) {
                $numbered[$key] = $item;
            } else {
                $named[$key] = $item;
            }
        }
        uksort($numbered, function ($a, $b) {
            return (float) $a <=> (float) $b;
        });
        $parts = array();
        foreach (array($numbered, $named) as $group) {
            foreach ($group as $key => $item) {
                $parts[] = json_encode((string) $key, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_LINE_TERMINATORS)
                    . ':' . self::mongoShape($item, $depth + 1);
            }
        }
        return '{' . implode(',', $parts) . '}';
    }

    // ---- Redis: the command and its first key's shape ------------------------------
    // queryText.js's redisKeyShape(), redisCommand() and redisStatement(),
    // ported; the shared cases' redis rows and redis_commands are run against
    // these. ASCII only, as there: a key keeps each ":" segment that is only
    // letters and "_" (32 at most), every other segment is "?".

    const REDIS_WORD = '/^[A-Za-z][A-Za-z0-9_.|-]{0,39}\z/';
    const REDIS_SEGMENT = '/^[A-Za-z_]{1,32}\z/';
    // Commands whose second word is a subcommand (CLIENT SETNAME, XINFO STREAM).
    const REDIS_CONTAINERS = array('ACL' => 1, 'CLIENT' => 1, 'CLUSTER' => 1, 'COMMAND' => 1, 'CONFIG' => 1, 'DEBUG' => 1,
        'FUNCTION' => 1, 'LATENCY' => 1, 'MEMORY' => 1, 'MODULE' => 1, 'OBJECT' => 1, 'PUBSUB' => 1, 'SCRIPT' => 1,
        'SLOWLOG' => 1, 'XGROUP' => 1, 'XINFO' => 1);
    // Of those, the ones with a key after the subcommand.
    const REDIS_SUB_KEY = array('OBJECT' => 1, 'MEMORY' => 1, 'XGROUP' => 1, 'XINFO' => 1);
    // No key: what follows is a password, a message, a number or nothing.
    const REDIS_NO_KEY = array('PING' => 1, 'ECHO' => 1, 'INFO' => 1, 'AUTH' => 1, 'HELLO' => 1, 'SELECT' => 1, 'QUIT' => 1,
        'RESET' => 1, 'MULTI' => 1, 'EXEC' => 1, 'DISCARD' => 1, 'UNWATCH' => 1, 'DBSIZE' => 1, 'TIME' => 1, 'FLUSHDB' => 1,
        'FLUSHALL' => 1, 'SAVE' => 1, 'BGSAVE' => 1, 'BGREWRITEAOF' => 1, 'LASTSAVE' => 1, 'SCAN' => 1, 'RANDOMKEY' => 1,
        'SWAPDB' => 1, 'SHUTDOWN' => 1, 'ROLE' => 1, 'REPLICAOF' => 1, 'SLAVEOF' => 1, 'READONLY' => 1, 'READWRITE' => 1,
        'LOLWUT' => 1, 'FAILOVER' => 1, 'PSYNC' => 1, 'SYNC' => 1, 'REPLCONF' => 1, 'MIGRATE' => 1);
    // Script calls: script or name, then how many keys, then the keys.
    const REDIS_SCRIPTS = array('EVAL' => 1, 'EVALSHA' => 1, 'EVAL_RO' => 1, 'EVALSHA_RO' => 1, 'FCALL' => 1, 'FCALL_RO' => 1);
    // How many keys first, then the keys.
    const REDIS_NUMKEYS = array('ZUNION' => 1, 'ZINTER' => 1, 'ZDIFF' => 1, 'SINTERCARD' => 1, 'ZINTERCARD' => 1, 'LMPOP' => 1, 'ZMPOP' => 1);
    // Waiting, not working: a queue worker sits in these for seconds.
    const REDIS_WAITING = array('BLPOP' => 1, 'BRPOP' => 1, 'BRPOPLPUSH' => 1, 'BLMOVE' => 1, 'BLMPOP' => 1, 'BZPOPMIN' => 1,
        'BZPOPMAX' => 1, 'BZMPOP' => 1, 'WAIT' => 1, 'WAITAOF' => 1, 'SUBSCRIBE' => 1, 'PSUBSCRIBE' => 1, 'SSUBSCRIBE' => 1,
        'UNSUBSCRIBE' => 1, 'PUNSUBSCRIBE' => 1, 'SUNSUBSCRIBE' => 1, 'MONITOR' => 1);
    const REDIS_PREFIXES = array('PIPELINE' => 1, 'MULTI' => 1);

    // ASCII only, whatever the locale (strtoupper follows it before PHP 8.2).
    private static function asciiUpper($text)
    {
        return strtr($text, 'abcdefghijklmnopqrstuvwxyz', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ');
    }

    public static function redisKeyShape($key)
    {
        // An empty key is "?" too: "GET " would read back as "GET".
        if (!is_string($key) || $key === '') {
            return '?';
        }
        $parts = explode(':', $key);
        foreach ($parts as $i => $part) {
            if ($part !== '' && !preg_match(self::REDIS_SEGMENT, $part)) {
                $parts[$i] = '?';
            }
        }
        return implode(':', $parts);
    }

    // JavaScript's Number($value) > 0, for the argument that says how many
    // keys follow.
    private static function positive($value)
    {
        if (is_int($value) || is_float($value)) {
            return $value > 0;
        }
        if (is_bool($value)) {
            return $value;
        }
        if (!is_string($value)) {
            return false;
        }
        $value = self::trimJs($value);
        if (preg_match('/^[+-]?Infinity\z/', $value)) {
            return $value[0] !== '-';
        }
        if (preg_match('/^[+-]?(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]+)?\z/', $value)) {
            return (float) $value > 0;
        }
        if (preg_match('/^0(?:[xX][0-9a-fA-F]+|[oO][0-7]+|[bB][01]+)\z/', $value)) {
            return trim(substr($value, 2), '0') !== '';
        }
        return false;
    }

    // A command as the client sends it (array('GET', 'user:42')) ->
    // "GET user:?", or null for one that isn't timed (blocking, or not a
    // command).
    public static function redisCommand($args)
    {
        if (!is_array($args) || !$args) {
            return null;
        }
        $args = array_values($args);
        if (!is_string($args[0]) || !preg_match(self::REDIS_WORD, $args[0])) {
            return null;
        }
        $name = self::asciiUpper($args[0]);
        if (isset(self::REDIS_WAITING[$name])) {
            return null;
        }
        $n = count($args);
        $key = null;
        $command = $name;
        if (isset(self::REDIS_CONTAINERS[$name])) {
            if ($n > 1 && is_string($args[1]) && preg_match(self::REDIS_WORD, $args[1])) {
                $command = $name . ' ' . self::asciiUpper($args[1]);
                // Only after a subcommand: "OBJECT user" would read back as OBJECT USER.
                if (isset(self::REDIS_SUB_KEY[$name])) {
                    $key = 2;
                }
            }
        } elseif ($name === 'XREAD' || $name === 'XREADGROUP') {
            // Its options, then STREAMS and the keys. XREADGROUP's group and
            // consumer come first and may be named anything, as may a stream.
            for ($i = $name === 'XREADGROUP' ? 4 : 1; $i < $n; $i++) {
                $word = is_string($args[$i]) ? self::asciiUpper($args[$i]) : '';
                if ($word === 'BLOCK') {
                    return null;
                }
                if ($word === 'STREAMS') {
                    $key = $i + 1;
                    break;
                }
            }
        } elseif (isset(self::REDIS_SCRIPTS[$name])) {
            if ($n > 2 && self::positive($args[2])) {
                $key = 3;
            }
        } elseif (isset(self::REDIS_NUMKEYS[$name])) {
            if ($n > 1 && self::positive($args[1])) {
                $key = 2;
            }
        } elseif ($name === 'BITOP') {
            $key = 2;
        } elseif (!isset(self::REDIS_NO_KEY[$name]) && !isset(self::REDIS_PREFIXES[$name])) {
            $key = 1;
        }
        return $key !== null && $key < $n ? $command . ' ' . self::redisKeyShape($args[$key]) : $command;
    }

    // A statement a package sent: [PIPELINE|MULTI] COMMAND [SUBCOMMAND] [key].
    // Anything else (an argument a hook let through) is (other).
    private static function redisStatement($text)
    {
        $text = self::trimJs($text);
        if ($text === '') {
            return '';
        }
        $words = preg_split('/' . self::WS . '+/', $text);
        $n = count($words);
        $out = array();
        $i = 0;
        if (isset(self::REDIS_PREFIXES[self::asciiUpper($words[0])]) && $n > 1) {
            $out[] = self::asciiUpper($words[$i++]);
        }
        if (!preg_match(self::REDIS_WORD, $words[$i])) {
            return self::OTHER;
        }
        $name = self::asciiUpper($words[$i++]);
        if (isset(self::REDIS_WAITING[$name])) {
            return self::OTHER;
        }
        $out[] = $name;
        if (isset(self::REDIS_CONTAINERS[$name]) && $i < $n && preg_match(self::REDIS_WORD, $words[$i])) {
            $out[] = self::asciiUpper($words[$i++]);
        }
        if ($i < $n - 1) {
            return self::OTHER;
        }
        if ($i < $n) {
            $out[] = self::redisKeyShape($words[$i]);
        }
        return implode(' ', $out);
    }

    // At most MAX_STATEMENT code points, trimmed again when cut.
    private static function cut($text)
    {
        if (strlen($text) <= self::MAX_STATEMENT) {
            return $text;
        }
        if (function_exists('mb_strlen')) {
            if (mb_strlen($text, 'UTF-8') <= self::MAX_STATEMENT) {
                return $text;
            }
            return self::trimJs(mb_substr($text, 0, self::MAX_STATEMENT, 'UTF-8'));
        }
        // Without mbstring: a code point is a byte that doesn't continue one.
        if (preg_match_all('/[^\x80-\xBF]/', $text) <= self::MAX_STATEMENT) {
            return $text;
        }
        preg_match('/^(?:[^\x80-\xBF][\x80-\xBF]*){' . self::MAX_STATEMENT . '}/', $text, $m);
        return self::trimJs($m[0]);
    }
}
