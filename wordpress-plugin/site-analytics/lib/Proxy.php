<?php
// First-party proxy: serving the tracker from the site's own domain, so ad
// blockers don't hide visitors.
//
// Blockers stop analytics by recognising the address a script comes from and
// what it is called ("track.js", "collect"). The answer is to serve both from
// the site's own domain, which until now meant writing Nginx, Apache or
// Cloudflare rules by hand. This app is already a server on that domain, so
// the package does it itself:
//
//   <prefix>/js/<rest>   ->  <endpoint>/<rest>                  (tracker files)
//   <prefix>/api/<rest>  ->  <endpoint>/collectanalytics/<rest> (the collector)
//
// The same two rules as the hand-written ones, so one install check covers
// both. The prefix comes from the site secret: not guessable from the page,
// and the same every time, so a browser's cache and a CDN in front stay valid.
//
// It answers before every other module: a visitor's beacon is our own
// traffic, not a page of the site, so it shouldn't be counted, timed or
// turned away by the firewall's rate limit.
//
// Deliberately free of Core, so the WordPress plugin's px.php — which is
// reached without loading WordPress at all — can use the same code.

namespace AnalyticsPlatform;

class Proxy
{
    // The tracker files, by name: anything else is refused, not forwarded.
    const FILES = array('track.js', 's.js', 'snapshot.js', 'replay.js', 'survey.js', 'banner.js',
        'leadform.js', 'notice.js', 'editor.js', 'picker.js', 'feedback.js', 'shield.js', 'widget.js', 'share.js');
    // What a collector answer may be served as from the site's own domain.
    // Its type comes from the collector, so anything but these three becomes
    // plain text, and nosniff stops a browser guessing: a server that is no
    // longer ours still can't answer <prefix>/api/... with a page that runs as
    // the customer's own site. Shared cases: sdk/protocols/proxy-answer-cases.json.
    const ANSWER_TYPES = array('application/json', 'text/plain', 'image/webp');
    // A pinned version never changes; /v<major>/ follows new releases, so it
    // is held for an hour, the same as the collector serves it with.
    const TTL_PINNED = 604800;
    const TTL_MAJOR = 3600;
    // Short, because a visitor's request (a PHP worker) waits on them: a
    // collector that has gone quiet must not hold every worker of the site.
    const CONNECT_TIMEOUT = 1;
    const TIMEOUT = 2;
    // After this many failures in a row the collector is left alone for
    // BREAKER_OPEN seconds: beacons are answered 502 straight away, and the
    // tracker comes from the copy on disk when there is one. Then one
    // request tries again; the others keep the short answer until it has.
    const BREAKER_FAILURES = 3;
    const BREAKER_OPEN = 30;
    // A tracker file that couldn't be fetched isn't asked for again for this long.
    const FILE_RETRY = 30;
    const MAX_BODY = 6291456;
    // The collector reads these; everything else, cookies above all, stays here.
    const PASS_HEADERS = array('content-type' => 'Content-Type', 'user-agent' => 'User-Agent',
        'accept-language' => 'Accept-Language', 'referer' => 'Referer', 'origin' => 'Origin',
        'sec-fetch-site' => 'Sec-Fetch-Site', 'sec-ch-ua' => 'Sec-CH-UA',
        'sec-ch-ua-mobile' => 'Sec-CH-UA-Mobile', 'sec-ch-ua-platform' => 'Sec-CH-UA-Platform');

    private $endpoint;
    private $prefix;
    private $dir;
    private $key;

    // $dir: a writable folder for the copy of each tracker file. PHP keeps
    // nothing between requests, so without one every visitor costs us a fetch.
    // $key: the proxy key, for a caller that has it but not the secret (px.php).
    public function __construct($endpoint, $secret, $dir = '', $prefix = '', $key = '')
    {
        $this->endpoint = rtrim((string) $endpoint, '/');
        $this->dir = (string) $dir;
        $this->prefix = preg_replace('/[^A-Za-z0-9_-]/', '', $prefix !== '' ? (string) $prefix : self::prefixFor($secret));
        $key = $key !== '' ? (string) $key : ((string) $secret !== '' ? self::keyFor($secret) : '');
        $this->key = preg_replace('/[^a-f0-9]/', '', $key);
    }

    public static function prefixFor($secret)
    {
        return substr(hash('sha256', 'proxy|' . (string) $secret), 0, 8);
    }

    // Sent as X-Proxy-Key, so the collector believes the visitor addresses
    // this proxy passes on: anyone can write X-Forwarded-For. Worked out from
    // the secret as the collector does (expresscollect/utils/proxyKey.js).
    public static function keyFor($secret)
    {
        return substr(hash('sha256', 'proxykey|' . (string) $secret), 0, 32);
    }

    public function prefix()
    {
        return $this->prefix;
    }

    // The tracker's address on this site, for the page's script tag.
    public function scriptUrl($version = '1')
    {
        return '/' . $this->prefix . '/js/v' . $version . '/s.js';
    }

    // Where visits are sent, for the tag's data-collect.
    public function collectUrl()
    {
        return '/' . $this->prefix . '/api/e';
    }

    // array($kind, $rest) when the address is ours, else null. $kind 'bad' is
    // ours but not allowed: answer 404 rather than handing it to the app.
    public function match($path)
    {
        if ($this->prefix === '' || $this->endpoint === '') {
            return null;
        }
        $head = '/' . $this->prefix . '/';
        if (strncmp((string) $path, $head, strlen($head)) !== 0) {
            return null;
        }
        $rest = substr((string) $path, strlen($head));
        foreach (array('js', 'api') as $kind) {
            if (strncmp($rest, $kind . '/', strlen($kind) + 1) === 0) {
                $tail = substr($rest, strlen($kind) + 1);
                $ok = $tail !== '' && strpos($tail, '..') === false && preg_match('#^[A-Za-z0-9/_.-]{1,120}$#D', $tail);
                return $ok ? array($kind, $tail) : array('bad', '');
            }
        }
        return array('bad', '');
    }

    // array('status' => int, 'headers' => array(name => value), 'body' => string).
    public function handle($kind, $rest, $method = 'GET', $query = '', array $headers = array(), $body = null, $clientIp = '')
    {
        if ($kind === 'js') {
            return $this->file($rest);
        }
        if ($kind !== 'api') {
            return self::notFound();
        }
        return $this->collector($rest, $method, $query, $headers, $body, $clientIp);
    }

    private static function notFound()
    {
        return array('status' => 404, 'headers' => array('Content-Type' => 'text/plain; charset=utf-8'), 'body' => 'Not found');
    }

    // ---- The breaker: shared between requests in APCu, else in a small file
    // in $dir; with neither, every request tries (and waits TIMEOUT at most).

    private static function apcu()
    {
        return function_exists('apcu_enabled') && apcu_enabled();
    }

    private function stateKey($name)
    {
        return 'apx:' . $this->prefix . ':' . $name;
    }

    private function breaker()
    {
        $state = null;
        if (self::apcu()) {
            $state = apcu_fetch($this->stateKey('breaker'));
        } elseif ($this->dir !== '' && is_file($this->dir . '/px-breaker.json')) {
            $state = json_decode((string) @file_get_contents($this->dir . '/px-breaker.json'), true);
        }
        return is_array($state) && isset($state['failures'], $state['open_until'])
            ? $state : array('failures' => 0, 'open_until' => 0.0);
    }

    private function saveBreaker(array $state)
    {
        if (self::apcu()) {
            apcu_store($this->stateKey('breaker'), $state, 3600);
        } elseif ($this->dir !== '' && is_dir($this->dir)) {
            $file = $this->dir . '/px-breaker.json';
            $tmp = $file . '.' . getmypid() . '.' . bin2hex(random_bytes(4)) . '.tmp';
            if (@file_put_contents($tmp, json_encode($state)) === false || !@rename($tmp, $file)) {
                @unlink($tmp);
            }
        }
    }

    // True while the collector is being left alone.
    public function resting()
    {
        $state = $this->breaker();
        if ($state['failures'] < self::BREAKER_FAILURES) {
            return false;
        }
        $now = microtime(true);
        if ($now < $state['open_until']) {
            return true;
        }
        // The pause is over: this request tries, the rest wait for it.
        $state['open_until'] = $now + self::CONNECT_TIMEOUT + self::TIMEOUT;
        $this->saveBreaker($state);
        return false;
    }

    private function worked()
    {
        if ($this->breaker()['failures'] > 0) {
            $this->saveBreaker(array('failures' => 0, 'open_until' => 0.0));
        }
    }

    private function failed()
    {
        $state = $this->breaker();
        $state['failures']++;
        if ($state['failures'] >= self::BREAKER_FAILURES) {
            $state['open_until'] = microtime(true) + self::BREAKER_OPEN;
        }
        $this->saveBreaker($state);
    }

    // Whether this tracker file failed to fetch within FILE_RETRY seconds.
    private function recentlyFailed($rest)
    {
        if (self::apcu()) {
            return apcu_fetch($this->stateKey('failed:' . $rest)) !== false;
        }
        $mark = $this->dir === '' ? '' : $this->dir . '/px-' . hash('sha256', $rest) . '.failed';
        clearstatcache(true, $mark);
        return $mark !== '' && is_file($mark) && filemtime($mark) > time() - self::FILE_RETRY;
    }

    private function rememberFailure($rest, $failed)
    {
        if (self::apcu()) {
            if ($failed) {
                apcu_store($this->stateKey('failed:' . $rest), 1, self::FILE_RETRY);
            } else {
                apcu_delete($this->stateKey('failed:' . $rest));
            }
            return;
        }
        if ($this->dir !== '' && is_dir($this->dir)) {
            $mark = $this->dir . '/px-' . hash('sha256', $rest) . '.failed';
            if ($failed) {
                @touch($mark);
            } elseif (is_file($mark)) {
                @unlink($mark);
            }
        }
    }

    private function file($rest)
    {
        if (!preg_match('#^v(\d+(?:\.\d+\.\d+)?)/([a-z]+\.js)$#D', $rest, $found) || !in_array($found[2], self::FILES, true)) {
            return self::notFound();
        }
        $pinned = strpos($found[1], '.') !== false;
        $cache = $this->dir !== '' && is_dir($this->dir) ? $this->dir . '/px-' . hash('sha256', $rest) . '.js' : '';
        $body = false;
        if ($cache !== '') {
            clearstatcache(true, $cache);
            if (is_file($cache) && filemtime($cache) > time() - ($pinned ? self::TTL_PINNED : self::TTL_MAJOR)) {
                $body = @file_get_contents($cache);
            }
        }
        if ($body === false && !$this->recentlyFailed($rest) && !$this->resting()) {
            $answer = $this->send('GET', $this->endpoint . '/' . $rest, null, array());
            // Remembered only when the collector failed, not for a version
            // it doesn't have (a 404 is quick): anyone can make up versions,
            // and the breaker keeps that to a few while it is away.
            $down = $answer['status'] === 0 || $answer['status'] >= 500;
            if ($down) {
                $this->failed();
            } else {
                $this->worked();
            }
            $this->rememberFailure($rest, $down);
            if ($answer['status'] === 200 && strlen($answer['body']) > 500) {
                $body = $answer['body'];
                if ($cache !== '') {
                    // Written beside it and moved into place, so a
                    // half-written file is never served.
                    $tmp = $cache . '.' . getmypid() . '.' . bin2hex(random_bytes(4));
                    if (@file_put_contents($tmp, $body) !== false) {
                        @rename($tmp, $cache);
                    } else {
                        @unlink($tmp);
                    }
                }
            }
        }
        if ($body === false && $cache !== '' && is_file($cache)) {
            // Upstream is unreachable: an old copy beats no tracker at all.
            $body = @file_get_contents($cache);
        }
        if ($body === false || $body === '') {
            return array('status' => 502, 'headers' => array(), 'body' => '');
        }
        return array('status' => 200, 'body' => $body, 'headers' => array(
            'Content-Type' => 'application/javascript; charset=utf-8',
            'Cache-Control' => $pinned ? 'public, max-age=31536000, immutable' : 'public, max-age=3600',
            'X-Content-Type-Options' => 'nosniff',
        ));
    }

    private function collector($rest, $method, $query, array $headers, $body, $clientIp)
    {
        $method = strtoupper((string) $method);
        if ($method === 'OPTIONS') {
            // Same origin as the page, so a preflight shouldn't happen;
            // answer it cheaply rather than passing it on.
            return array('status' => 204, 'body' => '', 'headers' => array(
                'Access-Control-Allow-Methods' => 'GET, POST, OPTIONS',
                'Access-Control-Allow-Headers' => 'Content-Type',
                'Access-Control-Max-Age' => '86400',
            ));
        }
        if ($method !== 'GET' && $method !== 'POST') {
            return self::notFound();
        }
        if ($body !== null && strlen($body) > self::MAX_BODY) {
            return array('status' => 413, 'headers' => array(), 'body' => '');
        }
        // The visitor's address: the collector needs it for the country, the
        // daily visitor ID and the per-visitor rate limit.
        $out = array('X-Forwarded-For: ' . (string) $clientIp);
        if ($this->key !== '') {
            $out[] = 'X-Proxy-Key: ' . $this->key;
        }
        foreach (self::PASS_HEADERS as $key => $name) {
            if (!empty($headers[$key])) {
                $out[] = $name . ': ' . str_replace(array("\r", "\n"), '', (string) $headers[$key]);
            }
        }
        $url = $this->endpoint . '/collectanalytics/' . $rest . ($query !== '' ? '?' . $query : '');
        // Left alone for now: answered straight away; the tracker treats a
        // failed beacon as lost and carries on.
        if ($this->resting()) {
            return array('status' => 502, 'headers' => array('Retry-After' => (string) self::BREAKER_OPEN), 'body' => '');
        }
        $answer = $this->send($method, $url, $method === 'POST' ? (string) $body : null, $out);
        if ($answer['status'] === 0 || $answer['status'] >= 500) {
            $this->failed();
        } else {
            $this->worked();
        }
        if ($answer['status'] === 0) {
            // The tracker already treats a failed beacon as lost and carries on.
            return array('status' => 502, 'headers' => array(), 'body' => '');
        }
        $pass = array(
            'Content-Type' => self::answerType(isset($answer['headers']['content-type']) ? $answer['headers']['content-type'] : null),
            'X-Content-Type-Options' => 'nosniff',
        );
        foreach (array('cache-control' => 'Cache-Control', 'retry-after' => 'Retry-After') as $key => $name) {
            if (isset($answer['headers'][$key])) {
                $pass[$name] = $answer['headers'][$key];
            }
        }
        return array('status' => $answer['status'], 'headers' => $pass, 'body' => $answer['body']);
    }

    // The type a collector answer is served with: one of ANSWER_TYPES, or plain text.
    public static function answerType($value)
    {
        $value = is_string($value) ? $value : '';
        $parts = explode(';', $value, 2);
        $kind = strtolower(trim($parts[0]));
        return in_array($kind, self::ANSWER_TYPES, true) && preg_match('/^[\x20-\x7e]*\z/', $value) ? $value : 'text/plain; charset=utf-8';
    }

    // Sends it upstream. cURL when it exists (nearly always), else streams,
    // so a host without cURL still works.
    private function send($method, $url, $body, array $headers)
    {
        $result = array('status' => 0, 'body' => '', 'headers' => array());
        if (function_exists('curl_init')) {
            $ch = curl_init($url);
            curl_setopt_array($ch, array(
                CURLOPT_CUSTOMREQUEST => $method,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT => self::TIMEOUT,
                CURLOPT_CONNECTTIMEOUT => self::CONNECT_TIMEOUT,
                CURLOPT_HTTPHEADER => $headers,
                CURLOPT_HEADERFUNCTION => function ($ch, $line) use (&$result) {
                    $pair = explode(':', $line, 2);
                    if (count($pair) === 2) {
                        $result['headers'][strtolower(trim($pair[0]))] = trim($pair[1]);
                    }
                    return strlen($line);
                },
            ));
            if ($body !== null) {
                curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
            }
            $answer = curl_exec($ch);
            $result['status'] = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
            $result['body'] = $answer === false ? '' : $answer;
            curl_close($ch);
            return $result;
        }
        $context = stream_context_create(array('http' => array(
            'method' => $method,
            'header' => implode("\r\n", $headers),
            'content' => $body === null ? '' : $body,
            'timeout' => self::TIMEOUT,
            'ignore_errors' => true,
        )));
        $answer = @file_get_contents($url, false, $context);
        $result['body'] = $answer === false ? '' : $answer;
        // PHP 8.4 added http_get_last_response_headers(); 8.5 deprecated the
        // $http_response_header variable this fell back on. The old name is
        // reached through get_defined_vars() so that naming it cannot raise
        // the deprecation on 8.5, while 7.4 still gets its headers.
        if (function_exists('http_get_last_response_headers')) {
            $lines = http_get_last_response_headers();
            $lines = $lines === null ? array() : $lines;
        } else {
            $scope = get_defined_vars();
            $lines = isset($scope['http_response_header']) ? $scope['http_response_header'] : array();
        }
        foreach ($lines as $line) {
            if (preg_match('#^HTTP/\S+\s+(\d{3})#', $line, $m)) {
                $result['status'] = (int) $m[1];
            } elseif (strpos($line, ':') !== false) {
                $pair = explode(':', $line, 2);
                $result['headers'][strtolower(trim($pair[0]))] = trim($pair[1]);
            }
        }
        return $result;
    }

    // Answers the request being served and stops. For plain PHP and the
    // WordPress plugin's px.php; a framework builds its own response instead.
    public function respond(array $answer)
    {
        http_response_code($answer['status']);
        foreach ($answer['headers'] as $name => $value) {
            header($name . ': ' . $value);
        }
        if ($answer['body'] !== '') {
            header('Content-Length: ' . strlen($answer['body']));
            echo $answer['body'];
        }
    }
}
