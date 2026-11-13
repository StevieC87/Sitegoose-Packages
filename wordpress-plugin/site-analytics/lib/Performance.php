<?php
// Performance & API monitoring module: times every request (from PHP
// starting it to the end of the script) and sends one row per minute,
// method, route and status code (how many, total and slowest time, and a
// count per time bucket) to POST /events/server-requests. Nothing about
// visitors is sent.
//
// PHP keeps nothing between requests, so each request appends one line to
// requests.jsonl in the storage directory, and once a minute one request adds
// them up and sends them (after its response). The route is what
// setRoute() was given (Laravel, WordPress set it), else the path with
// numbers and IDs as ":id"; unmatched 404s are one route.
//
// A request's database queries and outgoing calls ride in its own line (q and
// c, from Queries::takeRequest()), and are handed to the queries module when
// the lines are added up, under the route this filed the request under: a
// route folded into "(other)" past the cap has its queries there too, so the
// dashboard can always join the two (#373).

namespace AnalyticsPlatform;

class Performance
{
    // Keep in step with the collector (expresscollect/Analytics/serverRequests.js).
    const BUCKET_EDGES_MS = array(5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000);
    const FLUSH_EVERY = 60;
    const MAX_KEYS = 300;
    // Past MAX_KEYS new routes fold into "(other)"; past this nothing new is
    // kept at all.
    const HARD_MAX_KEYS = 400;
    // The method is the visitor's to choose: anything else is one "OTHER".
    const METHODS = array('GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'JOB');
    const MAX_ROWS = 500;
    const SPOOL_MAX = 5000000; // bytes waiting; more requests aren't recorded
    // Lines carrying queries fill the spool far sooner: past this it is sent
    // at once rather than at the next minute.
    const SEND_BYTES = 1000000;
    const NOT_FOUND = '/(not found)';

    private $core;
    private $options;
    private $route = '';
    // The queries module, which sends the queries and calls in the lines.
    private $timings = null;

    // Options: server_name (default the host name).
    public function __construct(Core $core, array $options = array())
    {
        $this->core = $core;
        $this->options = $options + array('server_name' => function_exists('gethostname') ? gethostname() : '');
    }

    public function setTimings(Queries $timings)
    {
        $this->timings = $timings;
    }

    // The request's route pattern, e.g. "/orders/{id}".
    public function setRoute($route)
    {
        $this->route = substr((string) $route, 0, 200);
    }

    // A request's method as Server speed keeps it: one of METHODS, else "OTHER".
    public static function method($method)
    {
        $name = strtoupper(trim((string) $method));
        return in_array($name, self::METHODS, true) ? $name : 'OTHER';
    }

    public static function normalizeRoute($path)
    {
        $path = explode('?', (string) $path, 2)[0];
        $path = explode('#', $path, 2)[0];
        $parts = array();
        foreach (explode('/', $path === '' ? '/' : $path) as $segment) {
            $isId = preg_match('/^\d+$/D', $segment)
                || preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/Di', $segment)
                || preg_match('/^[0-9a-f]{16,}$/Di', $segment)
                || (strlen($segment) >= 20 && preg_match('/\d/', $segment));
            $parts[] = $isId ? ':id' : $segment;
        }
        $route = implode('/', $parts);
        return substr($route[0] === '/' ? $route : '/' . $route, 0, 200);
    }

    // Records the current request (Platform calls it at shutdown), with
    // $extra: its queries and calls (Queries::takeRequest()). Returns what it
    // was recorded under (t, m, r), or null when it wasn't.
    public function recordRequest(array $extra = array())
    {
        if (!$this->core->isOn('performance') || !$this->core->ensureDir()) {
            return null;
        }
        $started = isset($_SERVER['REQUEST_TIME_FLOAT']) ? (float) $_SERVER['REQUEST_TIME_FLOAT'] : microtime(true);
        $status = (int) http_response_code();
        $status = $status ?: 200;
        // The visitor went away mid-answer: a 500 from writing to the closed
        // connection is not the site's, and its time is not the request's.
        if ($status >= 500 && function_exists('connection_aborted') && connection_aborted()) {
            $this->route = '';
            return null;
        }
        $route = $this->route !== '' ? $this->route
            : ($status === 404 ? self::NOT_FOUND : self::normalizeRoute(isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '/'));
        $line = array(
            't' => time(),
            'm' => self::method(isset($_SERVER['REQUEST_METHOD']) ? $_SERVER['REQUEST_METHOD'] : 'GET'),
            'r' => $route,
            's' => $status,
            'd' => round((microtime(true) - $started) * 1000, 1),
        );
        $this->route = '';
        return $this->append($line, $extra);
    }

    // A background job's run (Platform::job), timed like a request, with its
    // queries and calls (Queries::takeJob()). Returns what it was recorded
    // under (t, m, r), or null when it wasn't.
    public function recordJob($route, $status, $ms, array $extra = array())
    {
        if (!$this->core->isOn('performance') || !$this->core->ensureDir()) {
            return null;
        }
        $line = array('t' => time(), 'm' => 'JOB', 'r' => substr((string) $route, 0, 200),
            's' => (int) $status, 'd' => round((float) $ms, 1));
        return $this->append($line, $extra);
    }

    // A full spool keeps the timing and leaves out the queries and calls.
    private function append(array $line, array $extra)
    {
        $extra = array_intersect_key($extra, array('q' => true, 'c' => true));
        if ($this->core->append('requests', $line + $extra, self::SPOOL_MAX)
            || ($extra && $this->core->append('requests', $line, self::SPOOL_MAX))) {
            return $line;
        }
        return null;
    }

    private function big()
    {
        return $this->core->spoolOver('requests', self::SEND_BYTES);
    }

    public function due()
    {
        return $this->core->waiting('requests') && ($this->core->sendDue('requests', self::FLUSH_EVERY) || $this->big());
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

    // Adds up the recorded requests and sends them, once a minute.
    public function flush($force = false)
    {
        $this->core->drain('requests', $this->big() ? 0 : self::FLUSH_EVERY, $force, function (array $recorded) {
            $rows = array();
            // Each line's queries and calls, under what it was filed as.
            $timed = array();
            foreach ($recorded as $r) {
                if (!isset($r['t'], $r['m'], $r['r'], $r['s'], $r['d'])) {
                    continue;
                }
                $minute = (int) (floor($r['t'] / 60) * 60);
                $route = (string) $r['r'];
                // Mapped again here: a line written by an older version.
                $method = self::method($r['m']);
                $key = json_encode(array($minute, $method, $route, $r['s']));
                if (!isset($rows[$key]) && count($rows) >= self::MAX_KEYS) {
                    $route = '(other)';
                    $key = json_encode(array($minute, $method, $route, $r['s']));
                }
                // Not kept at all: its queries and calls go with it.
                if (!isset($rows[$key]) && count($rows) >= self::HARD_MAX_KEYS) {
                    continue;
                }
                if (!isset($rows[$key])) {
                    $rows[$key] = array(
                        'minute' => gmdate('Y-m-d\TH:i:s\Z', $minute), 'method' => $method, 'route' => $route, 'status' => (int) $r['s'],
                        'count' => 0, 'sum_ms' => 0.0, 'max_ms' => 0.0, 'buckets' => array_fill(0, count(self::BUCKET_EDGES_MS) + 1, 0),
                    );
                }
                $ms = (float) $r['d'];
                $rows[$key]['count']++;
                $rows[$key]['sum_ms'] += $ms;
                $rows[$key]['max_ms'] = max($rows[$key]['max_ms'], $ms);
                $rows[$key]['buckets'][self::bucketOf($ms)]++;
                if (isset($r['q']) || isset($r['c'])) {
                    $timed[] = array($minute, $method, $route, isset($r['q']) ? $r['q'] : null, isset($r['c']) ? $r['c'] : null);
                }
            }
            foreach (array_chunk(array_values($rows), self::MAX_ROWS) as $batch) {
                $this->core->post('requests', '/events/server-requests', array(
                    'server_name' => substr((string) $this->options['server_name'], 0, 100),
                    'runtime' => 'PHP ' . PHP_VERSION,
                    'rows' => $batch,
                ));
            }
            if ($timed && $this->timings) {
                $this->timings->sendTimed($timed);
            }
        });
    }
}
