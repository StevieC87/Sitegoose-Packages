<?php
// What every module of the PHP package shares: the site's credentials, the
// storage directory, sending to the collector, and the dashboard's module
// switches (Security → Server package, GET /events/platform/config).
//
// PHP keeps nothing between requests, so the switches are kept in the
// storage directory as a PHP file (OPcache holds it in memory) and fetched
// after the response, about once a minute, by one request at a time. Until
// they arrive, or when they can't be fetched, every loaded module stays on.

namespace AnalyticsPlatform;

class Core
{
    const VERSION = '0.3.9';
    const TIMEOUT = 4;
    const MIN_SYNC = 30;
    const RETRY = 60;
    // Batches the collector couldn't take, kept to be sent again: at most this
    // many bytes of them, and this many resent per run.
    const RETRY_MAX = 2000000;
    const RESEND = 20;
    // Everything sent after a response shares one deadline (within()), so
    // a collector that doesn't answer can't hold a PHP worker for minutes,
    // or outlast a container's grace period: each send waits at most what's
    // left, none starts after it, and what wasn't sent waits in its spool.
    const DEADLINE = 5;
    // http()'s status when the body couldn't be written as JSON: nothing was
    // sent, and sending it again would fail the same way.
    const UNSENDABLE = -1;

    // A dashboard header is added only when it is one of the nine the
    // dashboard can produce (expresscollect/Analytics/platform.js, headersOf),
    // in any case, with a value of visible ASCII, spaces and tabs, so no line
    // break, control character or byte a server rejects gets through. A list
    // of what's allowed, not of what isn't: whoever got into our servers still
    // couldn't make this site grant another its users' data
    // (Access-Control-Allow-*), send every page elsewhere (Refresh), log
    // everyone out (Clear-Site-Data) or change what a response is. Shared
    // cases: sdk/protocols/header-cases.json.
    const SECURITY_HEADERS = array('strict-transport-security', 'x-content-type-options', 'x-frame-options',
        'referrer-policy', 'permissions-policy', 'cross-origin-opener-policy', 'content-security-policy',
        'content-security-policy-report-only', 'reporting-endpoints');

    public $options;
    // Appended to the User-Agent, e.g. " (no-rate)" when the firewall can't count.
    public $features = '';
    private $dir;
    private $base;
    // Whether the storage is the default one under the system temp folder,
    // which every local user can write to.
    private $shared = false;
    private $trusted = false;
    private $legacyDirs = array();
    private $switches = null;
    private $loaded = array();
    private $deadline = null;

    // Options: site_id, secret, endpoint (required); storage (a writable
    // directory; default a folder of this user's in the system temp
    // directory, see tempStorage()); platform (for the dashboard, default
    // 'php'); public_endpoint (true: the endpoint is only called when it is
    // https on a public address, see Proxy::publicTarget()).
    public function __construct(array $options)
    {
        $this->options = $options + array('platform' => 'php');
        if (!isset($this->options['storage']) || $this->options['storage'] === '') {
            $this->options['storage'] = self::tempStorage();
            $this->shared = true;
        }
        $id = preg_replace('/[^a-f0-9]/i', '', (string) $this->opt('site_id'));
        // The folder may not be named after the site id alone. On WordPress the
        // storage lives under wp-content, which the web server serves, and the
        // site id is a data-siteid attribute in every page of the site — so a
        // folder named after it could simply be asked for, and events.jsonl
        // (visitor addresses and what they requested), crawlers.jsonl and
        // files.json (every path on the site) handed out. The .htaccess written
        // next to them only covers Apache and LiteSpeed; nginx ignores it. The
        // secret never leaves the server, so a name derived from it can't be
        // guessed from outside.
        $base = rtrim($this->options['storage'], '/\\');
        $this->base = $base;
        // The folder itself, for a caller that has it but not the secret
        // (the WordPress plugin's px.php, which checks the firewall's rules).
        if (is_string($this->opt('dir')) && $this->opt('dir') !== '') {
            $this->dir = rtrim($this->opt('dir'), '/\\');
            $this->shared = false;
            return;
        }
        // Without the secret a name is no secret at all (anyone can work it
        // out from the site id), and with nothing to send nothing need be
        // kept: no folder until the package is configured.
        if (!$this->configured()) {
            $this->dir = '';
            return;
        }
        $this->dir = $base . '/' . $id . '-' . substr(hash('sha256', $id . '|' . (string) $this->opt('secret')), 0, 16);
        // Where it used to be: named after the site id alone, or from an
        // empty secret (older versions kept spools before one was set).
        $this->legacyDirs = array($base . '/' . $id, $base . '/' . $id . '-' . substr(hash('sha256', $id . '|'), 0, 16));
    }

    // The default storage. Rules and switches are run as PHP from it, so no
    // other local user may be able to write there, or even list it: the
    // shared temp folder's "analytics-firewall", as before, only when it is
    // already this user's own (a host's other users can't have made it first
    // to swap a site's folder for theirs); else one named after this user,
    // which ensureDir() creates 0700 and checks the same way.
    private static function tempStorage()
    {
        $tmp = rtrim(sys_get_temp_dir(), '/\\');
        if (self::ownFolder($tmp . '/analytics-firewall', false)) {
            return $tmp . '/analytics-firewall';
        }
        $uid = self::uid();
        if ($uid === null) {
            $uid = function_exists('getmyuid') ? (int) getmyuid() : 0;
        }
        return $tmp . '/analytics-firewall-' . $uid;
    }

    // The user PHP runs as, or null where it can't be told (Windows, or no posix).
    private static function uid()
    {
        return DIRECTORY_SEPARATOR !== '\\' && function_exists('posix_geteuid') ? (int) posix_geteuid() : null;
    }

    // Whether $path is a folder of this user's that no one else can write
    // to: not a link, owned by the user PHP runs as, and with no write for
    // group or others. With $close, a folder of ours that others could read
    // or write (0775, as older versions made it) is closed to 0700 first.
    // Where the owner can't be told (Windows, no posix), only the link and,
    // off Windows, the write bits.
    private static function ownFolder($path, $close = true)
    {
        clearstatcache(true, $path);
        if (@is_link($path) || !@is_dir($path)) {
            return false;
        }
        if (DIRECTORY_SEPARATOR === '\\') {
            return true;
        }
        $uid = self::uid();
        $stat = @stat($path);
        if (!$stat || ($uid !== null && $stat['uid'] !== $uid)) {
            return false;
        }
        if ($close && ($stat['mode'] & 0077) && @chmod($path, 0700)) {
            clearstatcache(true, $path);
            $stat = @stat($path);
        }
        return $stat && ($stat['mode'] & 0022) === 0;
    }

    // Whether $file may be included: a plain file, not a link, of this
    // user's, that no one else can write to.
    private static function ownFile($file)
    {
        clearstatcache(true, $file);
        if (@is_link($file) || !@is_file($file)) {
            return false;
        }
        if (DIRECTORY_SEPARATOR === '\\') {
            return true;
        }
        $uid = self::uid();
        $stat = @stat($file);
        return $stat && ($uid === null || $stat['uid'] === $uid) && ($stat['mode'] & 0022) === 0;
    }

    // This site's check-in, on the switches request: server_name (default the
    // host name, as every module sends it) and the PHP version, form-encoded
    // so any name is plain ASCII. "request": PHP runs per request, so there is
    // no process to watch, and a quiet night isn't an outage.
    public function checkIn()
    {
        // Falls back as the modules' does (Platform.php passes it only when
        // not empty()), so the check-in and the data share one name.
        $server = $this->opt('server_name');
        if (empty($server)) {
            $server = function_exists('gethostname') ? (string) gethostname() : '';
        }
        return http_build_query(array(
            'server' => substr((string) $server, 0, 100),
            'kind' => 'request',
            'runtime' => 'PHP ' . PHP_VERSION,
        ), '', '&', PHP_QUERY_RFC3986);
    }

    // Runs $fn with every send inside $seconds from now (nested: the
    // earlier end wins). Returns what $fn returns.
    public function within($seconds, callable $fn)
    {
        $before = $this->deadline;
        $ends = microtime(true) + $seconds;
        $this->deadline = $before === null ? $ends : min($before, $ends);
        try {
            return $fn();
        } finally {
            $this->deadline = $before;
        }
    }

    // Seconds left before the deadline, or null when there is none.
    public function timeLeft()
    {
        return $this->deadline === null ? null : max(0.0, $this->deadline - microtime(true));
    }

    // How long one send may wait: $normal, cut to what's left of a deadline;
    // null once it has passed (nothing more is sent).
    public function sendTimeout($normal)
    {
        $left = $this->timeLeft();
        if ($left === null) {
            return (float) $normal;
        }
        return $left < 0.05 ? null : min((float) $normal, $left);
    }

    // A value as plain arrays and scalars that json_encode() can always
    // write, worked out when it is handed to us rather than when it is sent:
    // a resource, NAN or a recursive object would otherwise fail the whole
    // batch it is in. Bad UTF-8 is replaced; what still can't be written
    // becomes null. Null for nothing at all.
    public static function plain($value)
    {
        if ($value === null || is_string($value) || is_int($value) || is_bool($value)) {
            return $value;
        }
        $json = json_encode($value, JSON_INVALID_UTF8_SUBSTITUTE | JSON_PRESERVE_ZERO_FRACTION);
        if ($json === false) {
            $json = json_encode($value, JSON_INVALID_UTF8_SUBSTITUTE | JSON_PRESERVE_ZERO_FRACTION | JSON_PARTIAL_OUTPUT_ON_ERROR);
        }
        return $json === false ? null : json_decode($json, true);
    }

    public function opt($key)
    {
        return isset($this->options[$key]) ? $this->options[$key] : null;
    }

    public function configured()
    {
        return preg_match('/^[a-f0-9]{24}$/Di', (string) $this->opt('site_id')) && $this->opt('secret') && $this->opt('endpoint');
    }

    // The folder's path ('' until the package is configured), whether or not
    // it exists yet.
    public function dir()
    {
        return $this->dir;
    }

    // The folder when it exists and is safe to read from and write to (see
    // ownFolder(); the default storage's parent too), else ''.
    public function trustedDir()
    {
        if ($this->dir === '') {
            return '';
        }
        clearstatcache(true, $this->dir);
        if ($this->trusted && @is_dir($this->dir)) {
            return $this->dir;
        }
        $this->trusted = ($this->shared ? self::ownFolder($this->base) : true) && self::ownFolder($this->dir);
        return $this->trusted ? $this->dir : '';
    }

    // Creates the folder, 0700, when it isn't there. False when there is no
    // folder to use: not configured, not writable, or one this user doesn't
    // own or others can write to, which is never used (the default storage
    // is under the shared temp folder, where another user can make it first).
    public function ensureDir()
    {
        if ($this->dir === '') {
            return false;
        }
        clearstatcache(true, $this->dir);
        if (@is_link($this->dir)) {
            return false;
        }
        // The default storage's own folder first: under the shared temp
        // folder, nothing is made inside one that isn't ours alone.
        if ($this->shared && !@is_dir($this->base) && !@is_link($this->base)) {
            @mkdir($this->base, 0700, true);
        }
        if ($this->shared && !self::ownFolder($this->base)) {
            return false;
        }
        $made = false;
        if (!@is_dir($this->dir)) {
            if (!@mkdir($this->dir, 0700, true) && !@is_dir($this->dir)) {
                return false;
            }
            $made = true;
        }
        if ($this->trustedDir() === '') {
            return false;
        }
        // Only on the one request that creates the new folder, so this costs
        // nothing afterwards.
        if ($made) {
            $this->removeLegacy();
            @file_put_contents($this->dir . '/index.html', '');
            @file_put_contents($this->dir . '/.htaccess', "<IfModule mod_authz_core.c>\nRequire all denied\n</IfModule>\n<IfModule !mod_authz_core.c>\nDeny from all\n</IfModule>\n");
        }
        return true;
    }

    // The folders from before the name was unguessable held the same events,
    // crawler hits and file list, at a web address anyone could work out, so
    // they are emptied rather than left behind. They only ever held flat
    // files. One that is a link, or another user's, is left alone: removing
    // what is in it would remove whatever it points at.
    private function removeLegacy()
    {
        $uid = self::uid();
        foreach ($this->legacyDirs as $legacy) {
            clearstatcache(true, $legacy);
            if ($legacy === $this->dir || @is_link($legacy) || !@is_dir($legacy)) {
                continue;
            }
            $stat = @stat($legacy);
            if (!$stat || ($uid !== null && $stat['uid'] !== $uid)) {
                continue;
            }
            foreach (glob($legacy . '/{,.}*', GLOB_BRACE | GLOB_NOSORT) ?: array() as $path) {
                if (!@is_link($path) && @is_file($path)) {
                    @unlink($path);
                }
            }
            @rmdir($legacy);
        }
    }

    // Writes a value as a PHP file, atomically, so OPcache can keep it.
    public function writePhp($name, $value)
    {
        if ($this->dir === '') {
            return false;
        }
        $file = $this->dir . '/' . $name;
        $tmp = $file . '.' . getmypid() . '.' . bin2hex(random_bytes(4)) . '.tmp';
        $php = "<?php\n// Written by the analytics package; rewritten on every sync.\nreturn " . var_export($value, true) . ";\n";
        // 0600: the switches hold maintenance mode's bypass code.
        $written = @file_put_contents($tmp, $php, LOCK_EX) !== false;
        if ($written) {
            @chmod($tmp, 0600);
        }
        if (!$written || !@rename($tmp, $file)) {
            @unlink($tmp);
            return false;
        }
        if (function_exists('opcache_invalidate')) {
            @opcache_invalidate($file, true);
        }
        return true;
    }

    // Included only from a folder and a file of this user's that no one else
    // can write to: anything else could be anyone's code.
    public function readPhp($name)
    {
        if ($this->trustedDir() === '') {
            return null;
        }
        $file = $this->dir . '/' . $name;
        return self::ownFile($file) ? @include $file : null;
    }

    // ---- Module switches ----------------------------------------------------

    public function setLoaded(array $names)
    {
        $this->loaded = $names;
    }

    private function switches()
    {
        if ($this->switches === null) {
            $saved = $this->readPhp('switches.php');
            $this->switches = is_array($saved) ? $saved : array('fetched' => 0, 'sync' => self::RETRY, 'etag' => '', 'modules' => array());
        }
        return $this->switches;
    }

    // False only when the dashboard turned the module off.
    public function isOn($name)
    {
        $switches = $this->switches();
        return !(isset($switches['modules'][$name]) && $switches['modules'][$name] === false);
    }

    public function flags()
    {
        $switches = $this->switches();
        return $this->isOn('flags') && isset($switches['flags']) && is_array($switches['flags']) ? $switches['flags'] : array();
    }

    public function maintenance()
    {
        $switches = $this->switches();
        return $this->isOn('maintenance') && isset($switches['maintenance']) && is_array($switches['maintenance']) ? $switches['maintenance'] : array('on' => false);
    }

    // One of SECURITY_HEADERS, with a well-formed value.
    public static function safeHeader($pair)
    {
        return is_array($pair) && count($pair) === 2 && isset($pair[0], $pair[1]) && is_string($pair[0]) && is_string($pair[1])
            && in_array(strtolower($pair[0]), self::SECURITY_HEADERS, true)
            && strlen($pair[1]) <= 4000 && preg_match('/^[\x20-\x7e\t]*\z/', $pair[1]);
    }

    // The security headers picked on the dashboard, when the module is on.
    public function securityHeaders()
    {
        $switches = $this->switches();
        return $this->isOn('headers') && isset($switches['headers']) && is_array($switches['headers']) ? $switches['headers'] : array();
    }

    public function switchesDue()
    {
        $switches = $this->switches();
        return time() >= $switches['fetched'] + $switches['sync'];
    }

    // Fetches the switches when due, one request at a time.
    public function syncSwitches($force = false)
    {
        if (!$this->configured() || !$this->ensureDir() || (!$force && !$this->switchesDue())) {
            return;
        }
        $lock = @fopen($this->dir . '/switches.lock', 'c');
        if (!$lock || !flock($lock, LOCK_EX | LOCK_NB)) {
            return;
        }
        $switches = $this->switches();
        $headers = array('X-Platform-Modules: ' . implode(',', $this->loaded), 'X-Platform-App: ' . $this->checkIn());
        if ($switches['etag'] !== '' && !$force) {
            $headers[] = 'If-None-Match: ' . $switches['etag'];
        }
        $res = $this->http('GET', '/events/platform/config?site_id=' . rawurlencode($this->opt('site_id')), null, $headers, 'bearer');
        $switches['fetched'] = time();
        // Unchanged (304): the interval the dashboard last gave still holds.
        if ($res['status'] !== 304) {
            $switches['sync'] = self::RETRY;
        }
        if ($res['status'] === 200) {
            $data = json_decode($res['body'], true);
            if (is_array($data) && isset($data['v']) && $data['v'] === 1 && isset($data['modules']) && is_array($data['modules'])) {
                $switches['modules'] = $data['modules'];
                $switches['flags'] = isset($data['flags']) && is_array($data['flags']) ? $data['flags'] : array();
                $switches['maintenance'] = isset($data['maintenance']) && is_array($data['maintenance']) ? $data['maintenance'] : array('on' => false);
                $switches['headers'] = array();
                foreach (isset($data['headers']) && is_array($data['headers']) ? $data['headers'] : array() as $pair) {
                    if (self::safeHeader($pair)) {
                        $switches['headers'][] = array($pair[0], $pair[1]);
                    }
                }
                $switches['etag'] = isset($res['headers']['etag']) ? $res['headers']['etag'] : '';
                $switches['sync'] = max(self::MIN_SYNC, (int) (isset($data['sync']) ? $data['sync'] : self::RETRY));
            }
        }
        $this->writePhp('switches.php', $switches);
        $this->switches = $switches;
        flock($lock, LOCK_UN);
        fclose($lock);
    }

    // ---- Spools ---------------------------------------------------------------
    // What a request records for the collector (blocked requests, timings,
    // crawler hits, machine samples) is appended to <name>.jsonl, one line
    // each, and sent later by one request at a time. A batch the collector
    // couldn't take, when trying again may work (unreachable, 429, 5xx), is
    // kept in <name>.retry.jsonl and sent before the next one; a 4xx is
    // dropped, because resending won't make it acceptable.

    // False when the spool is full (more than $max bytes) or can't be written.
    public function append($name, array $row, $max)
    {
        if ($this->trustedDir() === '') {
            return false;
        }
        $file = $this->dir . '/' . $name . '.jsonl';
        $line = json_encode($row, JSON_INVALID_UTF8_SUBSTITUTE | JSON_PARTIAL_OUTPUT_ON_ERROR);
        if ($line === false) {
            return false;
        }
        return $this->appendText($file, $line . "\n", $max);
    }

    // Appends whole lines under the file's lock, measuring it under the lock
    // too, so many FPM workers at once neither interleave nor push it past
    // $max (the line counts: the file never grows past it). A file take()
    // moved away while this waited for the lock is let go and the line goes
    // into the new one, so nothing is written after take() has read it; a
    // writer can lose that race more than once while sends follow each other
    // closely, hence the few tries. Opened 'a+' so the last byte can be
    // read: a writer killed mid-line left the file without its newline, and
    // this line then starts on one of its own rather than being glued to the
    // half one (empty lines are skipped). Writes still all go to the end.
    // Without file locks (some network filesystems) nothing is written:
    // drain() needs them too, so a spool written there would never be sent.
    private function appendText($file, $text, $max = null)
    {
        for ($try = 0; $try < 50; $try++) {
            $handle = @fopen($file, 'a+b');
            if (!$handle) {
                return false;
            }
            if (!@flock($handle, LOCK_EX)) {
                fclose($handle);
                return false;
            }
            $here = @fstat($handle);
            clearstatcache(true, $file);
            if (!self::sameFile($here, @stat($file))) {
                flock($handle, LOCK_UN);
                fclose($handle);
                continue;
            }
            $size = $here['size'];
            if ($size === 0) {
                @chmod($file, 0600);
            }
            $out = $size > 0 && (@fseek($handle, -1, SEEK_END) !== 0 || @fread($handle, 1) !== "\n") ? "\n" . $text : $text;
            $ok = $max === null || $size + strlen($out) <= $max;
            if ($ok) {
                $ok = @fwrite($handle, $out) === strlen($out);
                @fflush($handle);
                // A disk that filled mid-line: the half line would spoil the next.
                // ftruncate() works on an append handle; only writes are pinned to the end.
                if (!$ok) {
                    @ftruncate($handle, $size);
                }
            }
            flock($handle, LOCK_UN);
            fclose($handle);
            return $ok;
        }
        return false;
    }

    // Whether an open handle's fstat() and the path's stat() are one file.
    // On Windows they fill st_dev differently (the volume's serial number,
    // the drive letter), so only the file index is compared there.
    private static function sameFile($a, $b)
    {
        return is_array($a) && is_array($b) && $a['ino'] === $b['ino']
            && (DIRECTORY_SEPARATOR === '\\' || $a['dev'] === $b['dev']);
    }

    // Whether anything is waiting to be sent, new or to be resent.
    public function waiting($name)
    {
        if ($this->dir === '') {
            return false;
        }
        clearstatcache();
        $base = $this->dir . '/' . $name;
        return is_file($base . '.jsonl') || is_file($base . '.retry.jsonl')
            || is_file($base . '.jsonl.sending') || is_file($base . '.retry.jsonl.sending');
    }

    // Whether <name>.jsonl holds more than $bytes: sent at once then,
    // rather than at the next minute.
    public function spoolOver($name, $bytes)
    {
        $file = $this->dir . '/' . $name . '.jsonl';
        clearstatcache(true, $file);
        return is_file($file) && filesize($file) > $bytes;
    }

    // Whether the last send was at least $every seconds ago.
    public function sendDue($name, $every)
    {
        $mark = $this->dir . '/' . $name . '.lock';
        clearstatcache(true, $mark);
        return !is_file($mark) || filemtime($mark) <= time() - $every;
    }

    // Takes everything waiting in the spool and hands its rows to $send,
    // which sends them with post(). At most every $every seconds unless
    // $force, and one request at a time.
    public function drain($name, $every, $force, callable $send)
    {
        if (!$this->waiting($name) || (!$force && !$this->sendDue($name, $every))) {
            return;
        }
        $lock = @fopen($this->dir . '/' . $name . '.lock', 'c');
        if (!$lock || !flock($lock, LOCK_EX | LOCK_NB)) {
            return;
        }
        @touch($this->dir . '/' . $name . '.lock');
        try {
            $this->resend($name);
            list($lines, $sending) = $this->take($this->dir . '/' . $name . '.jsonl');
            $rows = array();
            foreach ($lines as $line) {
                $row = json_decode($line, true);
                if (is_array($row)) {
                    $rows[] = $row;
                }
            }
            try {
                if ($rows) {
                    $send($rows);
                }
            } finally {
                // Only now: a request killed while sending leaves the file to
                // be sent again (take()) rather than losing what it held.
                // A batch $send couldn't deliver is in the retry spool by now.
                if ($sending !== '') {
                    @unlink($sending);
                }
            }
        } finally {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    // POSTs one batch for the spool $name, keeping it to resend when the
    // collector couldn't take it. The credentials are added when it is sent,
    // so they are never written down with it.
    public function post($name, $path, array $body, $auth = 'body')
    {
        $res = $this->http('POST', $path, $body, array(), $auth);
        // Not configured: nothing was sent, and nothing is kept either.
        if ($this->configured() && self::retryable($res['status']) && $this->ensureDir()) {
            $this->append($name . '.retry', array('path' => $path, 'auth' => $auth, 'body' => $body), self::RETRY_MAX);
        }
        return $res;
    }

    // Whether a batch is worth sending again: no answer, or the collector
    // was busy. Not a 4xx (resending won't make it acceptable), nor one that
    // couldn't be written as JSON.
    public static function retryable($status)
    {
        return $status === 0 || $status === 429 || $status >= 500;
    }

    // Sends what earlier runs couldn't, oldest first. Once one fails the
    // collector is still away (or the deadline has passed), so the rest go
    // back unsent.
    private function resend($name)
    {
        $file = $this->dir . '/' . $name . '.retry.jsonl';
        list($lines, $sending) = $this->take($file);
        foreach ($lines as $i => $line) {
            $batch = json_decode($line, true);
            if (!is_array($batch) || !isset($batch['path'], $batch['body']) || !is_array($batch['body'])
                || strpos((string) $batch['path'], '/events/') !== 0) {
                continue;
            }
            $auth = isset($batch['auth']) && $batch['auth'] === 'bearer' ? 'bearer' : 'body';
            $res = $i < self::RESEND ? $this->http('POST', $batch['path'], $batch['body'], array(), $auth) : array('status' => 0);
            if (self::retryable($res['status'])) {
                $rest = array_slice($lines, $i);
                $this->appendText($file, implode("\n", $rest) . "\n");
                break;
            }
        }
        if ($sending !== '') {
            @unlink($sending);
        }
    }

    // The lines of a spool file, and the name it was moved to while they are
    // sent ('' when there was none): renamed first, so lines other requests
    // append meanwhile start a new file rather than being lost. The caller
    // removes the moved file once it is done with it, so a request killed
    // while sending leaves it behind; only one request drains a spool at a
    // time (drain()'s lock), so the next one to get the lock finds it and
    // sends it again, before taking anything new. Some of it may have reached
    // the collector already: a copy beats a loss.
    private function take($file)
    {
        $sending = $file . '.sending';
        clearstatcache(true, $sending);
        if (!is_file($sending)) {
            clearstatcache(true, $file);
            if (!is_file($file) || !@rename($file, $sending)) {
                return array(array(), '');
            }
        }
        // A worker still writing to it (it opened the file before the move)
        // holds its lock: waited for, and the file read while holding it, so
        // no half line is read (and on Windows, where a lock also bars
        // reading, a late writer's lock can't fail the read). One that gets
        // the lock after this sees the file was moved and writes to the new
        // one (appendText()).
        $text = '';
        $handle = @fopen($sending, 'rb');
        if ($handle) {
            $locked = @flock($handle, LOCK_EX);
            $text = (string) @stream_get_contents($handle);
            if ($locked) {
                flock($handle, LOCK_UN);
            }
            fclose($handle);
        }
        $lines = array();
        foreach (explode("\n", $text) as $line) {
            if ($line !== '') {
                $lines[] = $line;
            }
        }
        return array($lines, $sending);
    }

    // ---- HTTP ---------------------------------------------------------------

    // auth 'bearer' sends the secret as a header (firewall, switches); 'body'
    // adds site_id and sitesecret to the JSON body (the event endpoints).
    public function http($method, $path, $body = null, array $headers = array(), $auth = 'bearer')
    {
        $result = array('status' => 0, 'body' => '', 'headers' => array());
        if (!$this->configured()) {
            return $result;
        }
        // Past the deadline nothing is sent: status 0, so post() keeps it.
        $timeout = $this->sendTimeout(self::TIMEOUT);
        if ($timeout === null) {
            return $result;
        }
        if ($body !== null) {
            if ($auth === 'body') {
                $body = array('site_id' => (string) $this->opt('site_id'), 'sitesecret' => (string) $this->opt('secret')) + $body;
            }
            // A name that isn't UTF-8 (a file, a path) has its bad bytes
            // replaced rather than failing the encoding and losing the whole body.
            $body = json_encode($body, JSON_INVALID_UTF8_SUBSTITUTE | JSON_PRESERVE_ZERO_FRACTION);
            if ($body === false) {
                // Not a network failure: nothing went out, and resending
                // can't help, so it isn't kept.
                $result['status'] = self::UNSENDABLE;
                return $result;
            }
            $headers[] = 'Content-Type: application/json';
        }
        if ($auth === 'bearer') {
            $headers[] = 'Authorization: Bearer ' . $this->opt('secret');
        }
        $headers[] = 'User-Agent: analytics-platform-' . $this->options['platform'] . '/' . self::VERSION . $this->features;
        $url = rtrim($this->opt('endpoint'), '/') . $path;
        // An endpoint the server's owner may not have chosen (see the
        // option): only an https one on public addresses, and only those.
        $target = null;
        if ($this->opt('public_endpoint')) {
            $target = Proxy::publicTarget($url);
            if ($target === null) {
                return $result;
            }
        }
        if (function_exists('curl_init')) {
            $ch = curl_init($url);
            curl_setopt_array($ch, array(
                CURLOPT_CUSTOMREQUEST => $method,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_TIMEOUT_MS => (int) ceil($timeout * 1000),
                CURLOPT_CONNECTTIMEOUT_MS => (int) ceil($timeout * 1000),
                CURLOPT_NOSIGNAL => true,
                CURLOPT_HTTPHEADER => $headers,
                CURLOPT_HEADERFUNCTION => function ($ch, $line) use (&$result) {
                    $parts = explode(':', $line, 2);
                    if (count($parts) === 2) {
                        $result['headers'][strtolower(trim($parts[0]))] = trim($parts[1]);
                    }
                    return strlen($line);
                },
            ));
            if ($target !== null) {
                curl_setopt_array($ch, Proxy::curlPinned($target));
            }
            if ($body !== null) {
                curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
            }
            $response = curl_exec($ch);
            $result['status'] = $response === false ? 0 : (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $result['body'] = $response === false ? '' : $response;
            curl_close($ch);
            return $result;
        }
        $ssl = array();
        if ($target !== null) {
            list($url, $ssl) = Proxy::streamPinned($url, $target, $headers);
        }
        // A redirect isn't followed: the secret would go with it.
        $context = stream_context_create(array('http' => array(
            'method' => $method,
            'header' => implode("\r\n", $headers),
            'content' => $body === null ? '' : $body,
            'timeout' => $timeout,
            'ignore_errors' => true,
            'follow_location' => 0,
        ), 'ssl' => $ssl));
        $response = @file_get_contents($url, false, $context);
        // PHP 8.4 added http_get_last_response_headers(); 8.5 deprecated the
        // $http_response_header variable this fell back on. The old name is
        // reached through get_defined_vars() so that naming it cannot raise
        // the deprecation on 8.5, while 7.4 still gets its headers. Either way
        // the first line is the status line, which the loop below relies on.
        if (function_exists('http_get_last_response_headers')) {
            $lines = http_get_last_response_headers();
            $lines = $lines === null ? array() : $lines;
        } else {
            $scope = get_defined_vars();
            $lines = isset($scope['http_response_header']) ? $scope['http_response_header'] : array();
        }
        foreach ($lines as $i => $line) {
            if ($i === 0 && preg_match('#^HTTP/\S+\s+(\d{3})#', $line, $m)) {
                $result['status'] = (int) $m[1];
            }
            $parts = explode(':', $line, 2);
            if ($i > 0 && count($parts) === 2) {
                $result['headers'][strtolower(trim($parts[0]))] = trim($parts[1]);
            }
        }
        $result['body'] = $response === false ? '' : $response;
        return $result;
    }
}
