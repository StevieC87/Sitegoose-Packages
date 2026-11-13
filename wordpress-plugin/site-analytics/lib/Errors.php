<?php
// Error monitoring module: the site's PHP errors go to the collector (POST
// /events/server-errors), where they join the browser's errors in the Errors
// report. install() catches uncaught exceptions (the handler that was there
// still runs); onShutdown() reads a fatal error (Platform calls it at
// shutdown); captureException() sends errors you catch. An error is sent
// once however many of those see it. Errors wait in memory and are sent after
// the response (Platform::afterResponse); a batch the collector couldn't take
// waits on disk and is sent again by a later request. Each error carries the
// trail of its request or job: the steps you add with addBreadcrumb(), and the
// outgoing requests of frameworks that announce them (WordPress, Laravel).

namespace AnalyticsPlatform;

class Errors
{
    const BATCH = 10;
    const QUEUE_MAX = 50;
    const FATAL = 85; // E_ERROR | E_PARSE | E_CORE_ERROR | E_COMPILE_ERROR
    // Seconds between tries at the batches the collector couldn't take.
    const RESEND_EVERY = 60;
    // Steps kept in the trail of a request or job.
    const CRUMB_MAX = 15;
    // Characters of a message kept: a message can carry a whole request
    // body or SQL dump, and every error is held in memory and on disk.
    const MAX_MESSAGE = 2000;
    // What a write to a visitor who has gone away fails with: the visitor
    // closed the tab, not a fault in the site.
    const GONE = '/broken pipe|connection reset|errno=(?:32|104)\b|ECONNRESET|EPIPE/i';

    private $core;
    private $options;
    private $queue = array();
    private $previous = null;
    private $installed = false;
    private $fatalRead = false;
    // Errors captured since the last send, each with its key in the queue
    // (null when it was dropped): Laravel reporting one and then logging it
    // would otherwise send it twice. Emptied on flush(), so a long-running
    // worker (Octane, queue:work) doesn't keep every exception it ever saw.
    private $seen;
    private $route = '';
    // The background job running (Platform::job), whose name is the route.
    private $job = '';
    // The current request or job's steps, oldest first.
    private $crumbs = array();

    // Options: server_name (default the host name), root (paths are made
    // relative to it; default the document root's parent), release (which build
    // this is, for "introduced in" in the Errors report; default the
    // ANALYTICS_RELEASE environment variable), before_send
    // (callable($event, $error): change an event, or return null to drop it).
    public function __construct(Core $core, array $options = array())
    {
        $this->core = $core;
        $this->seen = new \SplObjectStorage();
        $root = isset($_SERVER['DOCUMENT_ROOT']) && $_SERVER['DOCUMENT_ROOT'] !== '' ? dirname($_SERVER['DOCUMENT_ROOT']) : getcwd();
        $this->options = $options + array(
            'server_name' => function_exists('gethostname') ? gethostname() : '',
            'root' => $root,
            'release' => getenv('ANALYTICS_RELEASE') ?: '',
            'before_send' => null,
        );
    }

    public function install()
    {
        if ($this->installed) {
            return;
        }
        $this->installed = true;
        $this->previous = set_exception_handler(array($this, 'onException'));
    }

    public function onException($error)
    {
        $this->captureException($error, $this->requestFields(), 500, 'error');
        if (is_callable($this->previous)) {
            call_user_func($this->previous, $error);
            return;
        }
        // As PHP would without a handler.
        if (!headers_sent()) {
            http_response_code(500);
        }
        error_log('PHP Fatal error:  Uncaught ' . $error);
    }

    // Fatal errors can't be caught; they're read here, after the fact.
    public function onShutdown()
    {
        $last = error_get_last();
        if ($this->fatalRead || !$last || !($last['type'] & self::FATAL) || !$this->core->isOn('errors')) {
            return;
        }
        $this->fatalRead = true;
        $this->add(array(
            'message' => self::cut((string) $last['message']),
            'error_type' => 'FatalError',
            'stack' => '  File "' . $this->relative($last['file']) . '", line ' . (int) $last['line'] . ', in (fatal error)',
            'kind' => 'error',
            'status_code' => 500,
        ) + $this->requestFields(), null);
    }

    private function relative($text)
    {
        $root = rtrim((string) $this->options['root'], '/\\');
        return $root === '' ? (string) $text : str_replace($root . '/', '', (string) $text);
    }

    // Frames as "File ..., line ..., in ..." (innermost last), which the
    // collector reads like a Python traceback to group issues.
    // A PHP trace frame holds a call site and the function called; the call
    // site is inside the next frame's function.
    private function stack($error)
    {
        $trace = $error->getTrace();
        $name = function ($frame) {
            if (!$frame || !isset($frame['function'])) {
                return '{main}';
            }
            return (isset($frame['class']) ? $frame['class'] . $frame['type'] : '') . $frame['function'];
        };
        $frames = array(array($error->getFile(), $error->getLine(), $name(isset($trace[0]) ? $trace[0] : null)));
        foreach ($trace as $i => $frame) {
            if (isset($frame['file'])) {
                $frames[] = array($frame['file'], $frame['line'], $name(isset($trace[$i + 1]) ? $trace[$i + 1] : null));
            }
        }
        $lines = array();
        foreach (array_reverse($frames) as $frame) {
            $lines[] = '  File "' . $this->relative($frame[0]) . '", line ' . (int) $frame[1] . ', in ' . $frame[2];
        }
        return "Traceback (most recent call last):\n" . implode("\n", $lines) . "\n" . get_class($error) . ': ' . self::cut($error->getMessage());
    }

    // A message cut to MAX_MESSAGE characters (bytes where mbstring is missing).
    public static function cut($text)
    {
        $text = (string) $text;
        if (strlen($text) <= self::MAX_MESSAGE) {
            return $text;
        }
        return function_exists('mb_substr') ? mb_substr($text, 0, self::MAX_MESSAGE, 'UTF-8') : substr($text, 0, self::MAX_MESSAGE);
    }

    // Whether an error is only the visitor having gone away (a write to a
    // closed connection): PHP says so with connection_aborted(), and the
    // error names a broken pipe or a reset. Not reported: it isn't the
    // site's fault, and it would show as a 500 that no one saw.
    public static function clientGone($error)
    {
        if (!(function_exists('connection_aborted') && connection_aborted())) {
            return false;
        }
        $message = $error instanceof \Throwable ? $error->getMessage() : (string) $error;
        return (bool) preg_match(self::GONE, $message);
    }

    // The request's route pattern, as Server speed names it (Platform::setRoute).
    public function setRoute($route)
    {
        $this->route = substr((string) $route, 0, 200);
    }

    public function setJob($route)
    {
        $this->job = (string) $route;
        $this->clearBreadcrumbs();
    }

    // A step of your own in the trail shown before an error.
    public function addBreadcrumb($text)
    {
        $this->crumb(array('type' => 'note', 'text' => (string) $text));
    }

    // An outgoing request that has finished; $status is 0 when no answer came.
    public function addRequestBreadcrumb($method, $url, $status)
    {
        $url = preg_split('/[?#]/', (string) $url, 2)[0];
        $this->crumb(array('type' => 'request', 'text' => strtoupper((string) $method) . ' ' . $url, 'status' => (int) $status));
    }

    private function crumb(array $crumb)
    {
        $crumb['text'] = substr($crumb['text'], 0, 200);
        $crumb['at'] = microtime(true);
        $this->crumbs[] = $crumb;
        if (count($this->crumbs) > self::CRUMB_MAX) {
            array_shift($this->crumbs);
        }
    }

    // A worker that serves many requests calls this between them, so one
    // visitor's steps never appear before another's error.
    public function clearBreadcrumbs()
    {
        $this->crumbs = array();
    }

    // The trail as the tracker sends it: how long before now each step happened.
    private function breadcrumbs()
    {
        $now = microtime(true);
        return array_map(function ($crumb) use ($now) {
            $crumb['ms'] = (int) round(max(0, $now - $crumb['at']) * 1000);
            unset($crumb['at']);
            return $crumb;
        }, $this->crumbs);
    }

    public function requestFields()
    {
        if ($this->job !== '') {
            return array('method' => 'JOB', 'path' => $this->job, 'route' => $this->job, 'session_id' => '');
        }
        $path = isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '';
        return array(
            'method' => isset($_SERVER['REQUEST_METHOD']) ? (string) $_SERVER['REQUEST_METHOD'] : '',
            'path' => explode('?', (string) $path, 2)[0],
            'route' => $this->route,
            'session_id' => Platform::sessionIdFromRequest(),
        );
    }

    // $request: method, path, route, session_id (default: the current request).
    public function captureException($error, $request = null, $status = 0, $kind = 'handled')
    {
        if (!$this->core->isOn('errors')) {
            return;
        }
        try {
            $isError = $error instanceof \Throwable;
            if (self::clientGone($error)) {
                return;
            }
            $request = $request === null ? $this->requestFields() : $request;
            if ($isError && $this->seen->contains($error)) {
                $this->upgrade($error, $request, $status, $kind);
                return;
            }
            $event = array(
                'message' => self::cut($isError ? ($error->getMessage() !== '' ? $error->getMessage() : get_class($error)) : (string) $error),
                'error_type' => $isError ? (new \ReflectionClass($error))->getShortName() : 'Error',
                'stack' => $isError ? $this->stack($error) : '',
                'kind' => $kind,
                'status_code' => (int) $status,
            );
            foreach ($request as $key => $value) {
                if (in_array($key, array('method', 'path', 'route', 'session_id'), true)) {
                    $event[$key] = (string) $value;
                }
            }
            // Named as Server speed names the request, so the two match.
            if (empty($event['route']) && !empty($event['path'])) {
                $event['route'] = Performance::normalizeRoute($event['path']);
            }
            $key = $this->add($event, $error);
            if ($isError) {
                $this->seen[$error] = $key;
            }
        } catch (\Throwable $failure) {
            // never break the site
        }
    }

    // An exception logged and then thrown on is captured first as "logged",
    // with no status; Laravel's report that follows knows the status and kind.
    private function upgrade($error, array $request, $status, $kind)
    {
        $key = $this->seen[$error];
        if ($kind === 'logged' || $key === null || !isset($this->queue[$key])) {
            return;
        }
        $event = $this->queue[$key];
        if ($event['kind'] === 'logged') {
            $event['kind'] = $kind;
        }
        if (empty($event['status_code'])) {
            $event['status_code'] = (int) $status;
        }
        foreach (array('method', 'path', 'route', 'session_id') as $field) {
            if (empty($event[$field]) && !empty($request[$field])) {
                $event[$field] = (string) $request[$field];
            }
        }
        if (is_callable($this->options['before_send'])) {
            $event = Core::plain(call_user_func($this->options['before_send'], $event, $error));
        }
        if ($event && is_array($event)) {
            $this->queue[$key] = $event;
        } else {
            unset($this->queue[$key]);
        }
    }

    // Queues an event; returns its key in the queue, or null when it was dropped.
    private function add(array $event, $error)
    {
        $event += array(
            'runtime' => 'PHP',
            'runtime_version' => PHP_VERSION,
            'os' => PHP_OS_FAMILY,
            'server_name' => substr((string) $this->options['server_name'], 0, 100),
            'release' => substr(preg_replace('/[^\w.+-]/', '', (string) $this->options['release']), 0, 64),
            // When it happened: an error resent by a later request keeps its own time.
            'at' => gmdate('Y-m-d\TH:i:s\Z'),
        );
        if ($this->crumbs) {
            $event['breadcrumbs'] = $this->breadcrumbs();
        }
        if (is_callable($this->options['before_send'])) {
            // What before_send hands back is yours: made plain now, so a
            // value JSON can't hold never fails the batch at send time.
            $event = Core::plain(call_user_func($this->options['before_send'], $event, $error));
            if (!$event || !is_array($event)) {
                return null;
            }
        }
        if (count($this->queue) >= self::QUEUE_MAX) {
            return null;
        }
        $this->queue[] = $event;
        end($this->queue);
        return key($this->queue);
    }

    public function pending()
    {
        return count($this->queue) > 0;
    }

    // Batches an earlier request couldn't send are waiting, and it's time to try them.
    public function due()
    {
        return $this->core->waiting('errors') && $this->core->sendDue('errors', self::RESEND_EVERY);
    }

    public function flush()
    {
        $waiting = array_values($this->queue);
        $this->queue = array();
        $this->seen = new \SplObjectStorage();
        foreach (array_chunk($waiting, self::BATCH) as $batch) {
            $this->core->post('errors', '/events/server-errors', array('errors' => $batch));
        }
        // The errors spool holds only those retries, so there's nothing else to drain.
        $this->core->drain('errors', self::RESEND_EVERY, false, function () {
        });
    }
}
