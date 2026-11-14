<?php
// File integrity (protocol in sdk/protocols/files.md): the site's files
// compared with the version the owner accepted (the baseline), and what's
// different reported to POST /events/files/scan: changed code, backdoors,
// defacement. Never runs in a visitor's request: call run() from a cron job
// (the WordPress plugin uses WP-Cron), about once an hour; due() says when.
//
// Options: roots (folders to watch, required), exclude (folders to skip),
// load / save (callables keeping the state somewhere else than the storage
// directory), official (callable(path): true when the file is the official
// copy, false when it differs, null when unknown; WordPress core checksums),
// trusted (callable(path): true for a change the site made itself, like a
// plugin update, taken into the baseline unless it looks hacked).

namespace AnalyticsPlatform;

class Files
{
    const EVERY = 3600;
    const RETRY = 900;
    const FULL_HASH_EVERY = 86400;
    const MAX_FILE_BYTES = 5242880;
    const MAX_FILES = 50000;
    const MAX_CHANGES = 1000;
    const SIGNAL_BYTES = 1048576;
    // How many files may be read looking for signals in one scan. Each one
    // reads up to SIGNAL_BYTES, and both the first scan of a site and a deploy
    // that changes everything would otherwise read every watched file --
    // MAX_FILES x SIGNAL_BYTES -- inside a PHP worker, after the response.
    const MAX_SIGNAL_FILES = 5000;
    const EXTENSIONS = '/\.(php[0-9]?|phtml|phar|inc|m?js|cjs|jsx|tsx?|vue|svelte|html?|shtml|ejs|erb|twig|hbs|handlebars|mustache|jinja|j2|njk|liquid|cshtml|vbhtml|py|rb|pl|cgi|sh|aspx?|jsp|svg|json|ya?ml|conf|config|ini)$/Di';
    const PHP_FILE = '/\.(php[0-9]?|phtml|phar)$/Di';

    private static $skipDirs = array('.git', 'node_modules');
    private static $signals = array(
        // PHP, Node and Python: decoded code run, and commands or code taken from the request.
        'eval_decode' => '~(eval|assert)\s*\(\s*(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13)\s*\(|(eval|new\s+Function)\s*\(\s*(Buffer\.from|atob)\s*\(|exec\s*\(\s*(base64\.b64decode|zlib\.decompress|marshal\.loads|codecs\.decode)\s*\(~i',
        'exec_input' => '~(system|shell_exec|passthru|exec|popen|proc_open|eval)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)|(exec|execSync|spawn|spawnSync|eval)\s*\(\s*req\.(query|body|params)|(os\.system|os\.popen|subprocess\.\w+|eval|exec)\s*\(\s*request\.(args|form|values|GET|POST|json)~i',
        'reverse_shell' => '~bash\s+-i\s*>&\s*/dev/tcp/|/dev/tcp/[0-9.]+/[0-9]+|\bnc(at)?\s+(-\S+\s+)*-e\s+/bin/(ba)?sh|socket\.socket\(.{0,200}subprocess|pty\.spawn\(\s*[\'\"]/bin/(ba)?sh~i',
        'webshell' => '/FilesMan|c99shell|r57shell|WSO\s?[0-9]|b374k/i',
        'obfuscated_js' => '/String\.fromCharCode\(\s*[0-9]+\s*(,\s*[0-9]+\s*){50,}\)|document\.write\(\s*unescape\(/i',
        'defaced' => '/hacked\s+by|defaced\s+by/i',
    );

    private $core;
    private $options;
    private $state = null;

    public function __construct(Core $core, array $options = array())
    {
        $this->core = $core;
        $this->options = $options + array(
            'roots' => array(), 'exclude' => array(), 'load' => null, 'save' => null, 'official' => null, 'trusted' => null,
        );
    }

    // Shared with Posture, which walks folders the same way.
    public static function clean($path)
    {
        return rtrim(str_replace('\\', '/', (string) $path), '/');
    }

    // The folders of $given that exist, resolved, without any inside another
    // one on the list: those are already covered, and every file under them
    // would be reported twice.
    public static function realRoots(array $given)
    {
        $roots = array();
        foreach ($given as $root) {
            $real = @realpath((string) $root);
            if ($real && is_dir($real)) {
                $roots[$real] = self::clean($real);
            }
        }
        $roots = array_values($roots);
        return array_values(array_filter($roots, function ($root) use ($roots) {
            foreach ($roots as $other) {
                if ($other !== $root && strpos($root . '/', $other . '/') === 0) {
                    return false;
                }
            }
            return true;
        }));
    }

    public function roots()
    {
        return self::realRoots((array) $this->options['roots']);
    }

    // JSON needs UTF-8: a name that isn't is still reported, its bad bytes replaced.
    public static function utf8($path)
    {
        return preg_match('//u', $path) ? $path : (function_exists('mb_convert_encoding') ? mb_convert_encoding($path, 'UTF-8', 'UTF-8') : rawurlencode($path));
    }

    // ---- State ----------------------------------------------------------------

    private function load()
    {
        if ($this->state !== null) {
            return $this->state;
        }
        $saved = null;
        if (is_callable($this->options['load'])) {
            $saved = call_user_func($this->options['load']);
        } elseif ($this->core->ensureDir()) {
            $raw = @file_get_contents($this->core->dir() . '/files.json');
            if (is_string($raw) && strncmp($raw, 'ps:', 3) === 0) {
                $saved = @unserialize(substr($raw, 3), array('allowed_classes' => false));
            } else {
                // As it was written before: JSON.
                $saved = $raw ? json_decode($raw, true) : null;
            }
        }
        $this->state = (is_array($saved) ? $saved : array()) + array('baseline' => null, 'last' => array(), 'full_at' => 0, 'next_at' => 0);
        return $this->state;
    }

    private function save()
    {
        if (is_callable($this->options['save'])) {
            call_user_func($this->options['save'], $this->state);
            return;
        }
        if (!$this->core->ensureDir()) {
            return;
        }
        // Serialized, not JSON: the paths are kept byte for byte, so one file
        // name that isn't UTF-8 can't make the encoding fail and wipe the
        // accepted version (JSON would refuse it, or replace its bad bytes and
        // name a file that isn't there).
        $file = $this->core->dir() . '/files.json';
        $tmp = $file . '.' . getmypid() . '.' . bin2hex(random_bytes(4)) . '.tmp';
        $written = @file_put_contents($tmp, 'ps:' . serialize($this->state), LOCK_EX) !== false;
        if ($written) {
            @chmod($tmp, 0600);
        }
        if (!$written || !@rename($tmp, $file)) {
            @unlink($tmp);
        }
    }

    public function due()
    {
        $state = $this->load();
        return count($this->roots()) > 0 && time() >= (int) $state['next_at'];
    }

    // ---- Scanning -------------------------------------------------------------

    private function watched($name)
    {
        return $name === '.htaccess' || $name === '.user.ini' || strpos($name, '.env') === 0 || preg_match(self::EXTENSIONS, $name);
    }

    // array(path => array(sha256, size, mtime)), truncated. A file whose size
    // and time are unchanged keeps its last hash unless $full. A file we
    // already knew is never dropped for being unreadable or too big: it is
    // still there, and reporting it deleted would hide what happened to it.
    private function scan(array $previous, array $known, $full)
    {
        $current = array();
        $truncated = false;
        $exclude = array();
        foreach ((array) $this->options['exclude'] as $dir) {
            $exclude[] = self::clean((string) (realpath($dir) ?: $dir)) . '/';
        }
        foreach ($this->roots() as $root) {
            $dirs = new \RecursiveCallbackFilterIterator(
                new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS | \FilesystemIterator::CURRENT_AS_FILEINFO),
                function ($item) use ($exclude) {
                    if ($item->isLink()) {
                        return false;
                    }
                    if ($item->isDir()) {
                        $path = self::clean($item->getPathname()) . '/';
                        foreach ($exclude as $skip) {
                            if (strpos($path, $skip) === 0) {
                                return false;
                            }
                        }
                        return !in_array($item->getFilename(), self::$skipDirs, true) && strpos($path, '/wp-content/cache/') === false;
                    }
                    return $item->isFile();
                }
            );
            $items = new \RecursiveIteratorIterator($dirs, \RecursiveIteratorIterator::LEAVES_ONLY, \RecursiveIteratorIterator::CATCH_GET_CHILD);
            foreach ($items as $item) {
                if (!$this->watched($item->getFilename())) {
                    continue;
                }
                $path = self::clean($item->getPathname());
                $old = isset($previous[$path]) ? $previous[$path] : (isset($known[$path]) ? $known[$path] : null);
                // A file deleted mid-walk fails its stat with an exception, not false.
                try {
                    $size = $item->getSize();
                    $mtime = (int) $item->getMTime();
                } catch (\RuntimeException $e) {
                    continue;
                }
                // New files past the limit are left out (the protocol's 5 MB);
                // one we knew that grew past it is a change, and still hashed.
                if ($size > self::MAX_FILE_BYTES && !$old) {
                    continue;
                }
                if (count($current) >= self::MAX_FILES) {
                    $truncated = true;
                    break 2;
                }
                if ($old && !$full && (int) $old[1] === (int) $size && (int) $old[2] === $mtime) {
                    $current[$path] = $old;
                    continue;
                }
                $hash = @hash_file('sha256', $item->getPathname());
                if ($hash !== false) {
                    $current[$path] = array($hash, (int) $size, $mtime);
                } elseif ($old) {
                    $current[$path] = $old;
                }
            }
        }
        return array($current, $truncated);
    }

    public static function signals($path)
    {
        $found = array();
        if (strpos($path, '/uploads/') !== false && preg_match(self::PHP_FILE, $path)) {
            $found[] = 'code_in_uploads';
        }
        $head = @file_get_contents($path, false, null, 0, self::SIGNAL_BYTES);
        if (is_string($head)) {
            foreach (self::$signals as $name => $pattern) {
                if (preg_match($pattern, $head)) {
                    $found[] = $name;
                }
            }
        }
        return $found;
    }

    private function official($path)
    {
        if (!is_callable($this->options['official'])) {
            return null;
        }
        try {
            return call_user_func($this->options['official'], $path);
        } catch (\Throwable $e) {
            return null;
        }
    }

    private function trusted($path)
    {
        try {
            return is_callable($this->options['trusted']) && call_user_func($this->options['trusted'], $path) === true;
        } catch (\Throwable $e) {
            return false;
        }
    }

    private static function iso($time)
    {
        return gmdate('Y-m-d\TH:i:s\Z', (int) $time);
    }

    // Scans, reports and takes in what the owner accepted. $accept: the files
    // as they are now become the accepted version (after a deploy). Returns
    // the changes reported.
    public function run($accept = false)
    {
        $roots = $this->roots();
        if (!$roots || !$this->core->configured()) {
            return array();
        }
        $state = $this->load();
        $now = time();
        $full = $now - (int) $state['full_at'] >= self::FULL_HASH_EVERY;
        list($current, $truncated) = $this->scan(
            is_array($state['last']) ? $state['last'] : array(),
            is_array($state['baseline']) ? $state['baseline'] : array(),
            $full
        );
        if ($full) {
            $state['full_at'] = $now;
        }
        $fresh = !is_array($state['baseline']) || $accept;
        // Sorted, so the files that get read are the same set from one scan to
        // the next rather than whatever the walk reached first.
        ksort($current);
        $read = 0;
        if ($fresh) {
            $baseline = array();
            foreach ($current as $path => $entry) {
                // Files that already look hacked stay out, so they're reported from
                // the start. Past the budget a file is taken as it is: reading the
                // whole site is worse than accepting it and catching changes later.
                $looks_hacked = $accept ? false : ($read < self::MAX_SIGNAL_FILES && (bool) self::signals($path));
                if (!$accept) {
                    $read++;
                }
                if ($accept || (!$looks_hacked && $this->official($path) !== false)) {
                    $baseline[$path] = $entry;
                }
            }
            $state['baseline'] = $baseline;
        }
        $read = 0;
        $changes = array();
        foreach ($current as $path => $entry) {
            $old = isset($state['baseline'][$path]) ? $state['baseline'][$path] : null;
            if ($old !== null && $old[0] === $entry[0]) {
                continue;
            }
            // Past the budget the change is still reported; only the look inside
            // it is skipped, so a deploy of everything can't mean reading everything.
            $signals = $read < self::MAX_SIGNAL_FILES ? self::signals($path) : array();
            $read++;
            $official = $this->official($path);
            // The official copy, or the site's own update: the new accepted version.
            if (!$signals && ($official === true || $this->trusted($path))) {
                $state['baseline'][$path] = $entry;
                continue;
            }
            $change = array(
                'path' => self::utf8($path), 'change' => $old === null ? 'added' : 'modified', 'sha256' => $entry[0],
                'size' => $entry[1], 'mtime' => self::iso($entry[2]), 'signals' => $signals,
            );
            if ($official === false) {
                $change['official'] = false;
            }
            $changes[] = $change;
        }
        // A scan cut short at MAX_FILES didn't reach every file, and which ones
        // it missed depends on the walk: those aren't gone, so nothing is
        // reported deleted from it.
        foreach ($truncated ? array() : array_keys($state['baseline']) as $path) {
            if (!isset($current[$path])) {
                if ($this->trusted($path)) {
                    unset($state['baseline'][$path]);
                    continue;
                }
                $changes[] = array('path' => self::utf8($path), 'change' => 'deleted', 'sha256' => null);
            }
        }
        usort($changes, function ($a, $b) {
            $signalled = (int) !empty($b['signals']) - (int) !empty($a['signals']);
            return $signalled !== 0 ? $signalled : strcmp($a['path'], $b['path']);
        });
        $state['last'] = $current;
        $host = function_exists('gethostname') ? (string) gethostname() : '';
        $result = $this->core->http('POST', '/events/files/scan', array(
            'site_id' => (string) $this->core->opt('site_id'),
            'host' => preg_match('/^[A-Za-z0-9._-]{1,100}$/D', $host) ? $host : 'server',
            'scan' => array(
                'at' => self::iso($now), 'roots' => $roots, 'files' => count($current),
                'baseline' => $fresh && !$accept, 'accepted' => (bool) $accept, 'truncated' => $truncated,
            ),
            'changes' => array_slice($changes, 0, self::MAX_CHANGES),
        ));
        $every = self::RETRY;
        if ($result['status'] === 200) {
            $answer = json_decode($result['body'], true);
            $answer = is_array($answer) ? $answer : array();
            $every = max(300, isset($answer['every']) ? (int) $answer['every'] : self::EVERY);
            if (!empty($answer['accept_all'])) {
                // Cut short, the files this scan missed stay accepted as they were.
                $state['baseline'] = $truncated ? $current + $state['baseline'] : $current;
            }
            foreach (isset($answer['accept']) && is_array($answer['accept']) ? $answer['accept'] : array() as $item) {
                $path = isset($item['path']) ? (string) $item['path'] : '';
                $sha = isset($item['sha256']) ? $item['sha256'] : null;
                if ($sha === null && !isset($current[$path])) {
                    unset($state['baseline'][$path]);
                } elseif (isset($current[$path]) && $current[$path][0] === $sha) {
                    $state['baseline'][$path] = $current[$path];
                }
            }
        }
        $state['next_at'] = $now + $every;
        $this->state = $state;
        $this->save();
        return $changes;
    }
}
