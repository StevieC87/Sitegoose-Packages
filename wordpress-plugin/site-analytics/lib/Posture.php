<?php
// How the site is set up (protocol in sdk/protocols/posture.md): the settings
// that leave it open, who has rights, where a hack would hide to come back,
// and files in the web folder that should never be public. Reported to
// POST /events/posture about once a day, with the software inventory.
//
// **It only reads.** Nothing here changes a setting, a permission or a file:
// the dashboard says what to change and the owner changes it. Nothing here
// sends a file's contents either — paths, sizes, times, counts and short
// values only.
//
// This file does the part that is true of any PHP site (php.ini settings, the
// walk of the web folder). What only WordPress knows — its constants, its
// accounts, its scheduled jobs — comes from the callbacks below, which the
// WordPress plugin fills in.
//
// Options: roots (the folders to walk; default the document root), checks
// (callable returning more checks, each array('id' => ..., 'state' =>
// 'pass'|'fail'|'unknown'[, 'value' => string])), accounts (callable
// returning array('total' => int, 'admins' => array(array('name' => ...,
// 'roles' => array(...), 'created' => ISO, 'last_login' => ISO)))),
// persistence (callable returning array('cron' => array(array('kind' => ...,
// 'name' => ..., 'schedule' => ..., 'handler' => bool)))), facts (more facts),
// exclude (folders to leave out of the walk), manual (true: only run() from
// your own job, as the WordPress plugin does from WP-Cron).

namespace AnalyticsPlatform;

class Posture
{
    const EVERY = 86400;
    const RETRY = 3600;
    // The first report waits this long after the module starts.
    const FIRST = 180;
    const MAX_CHECKS = 200;
    const MAX_ADMINS = 50;
    const MAX_CRON = 200;
    const MAX_EXPOSURE = 50;
    // The walk of the web folder: it never costs more than this.
    const MAX_ENTRIES = 30000;
    const MAX_DEPTH = 6;
    // Code files looked at for "writable by everyone"; the count is reported.
    const MAX_PERM_CHECKS = 3000;

    private static $skipDirs = array('.git', '.svn', '.hg', 'node_modules', 'vendor', 'cache', '.cache', '.history');
    private static $codeFile = '/\.(php[0-9]?|phtml|phar|inc|m?js|cjs|py|rb|pl|sh)$/i';

    // Files in the web folder that shouldn't be there, by name. First match wins.
    private static $exposure = array(
        array('kind' => 'database_dump', 'pattern' => '/\.sql(\.(gz|bz2|xz|zip))?$/i'),
        array('kind' => 'private_key', 'pattern' => '/^(id_rsa|id_dsa|id_ecdsa|id_ed25519)$|\.(pem|key|p12|pfx|jks)$/i'),
        array('kind' => 'env', 'pattern' => '/^\.env($|\.)|^env\.(ini|txt)$/i'),
        array('kind' => 'archive', 'pattern' => '/\.(zip|tar|tgz|tar\.gz|tar\.bz2|rar|7z)$/i'),
        array('kind' => 'backup', 'pattern' => '/\.(bak|old|orig|save|swp|copy|backup)$|~$|\.php\.(txt|_|disabled)$|\.(php|conf|config|ini|yml|yaml|json)\.(bak|old|orig|save|txt)$/i'),
        array('kind' => 'info', 'pattern' => '/^(phpinfo|info|test|adminer|phpmyadmin|pma)\.php$/i'),
        array('kind' => 'log', 'pattern' => '/^(debug|error|php_error|access)[-_.]?log$|\.log$/i'),
        array('kind' => 'vcs', 'pattern' => '~(^|/)\.(git|svn|hg|bzr)/~'),
    );

    private $core;
    private $options;
    private $state = null;

    public function __construct(Core $core, array $options = array())
    {
        $this->core = $core;
        $this->options = $options + array(
            'roots' => array(), 'exclude' => array(), 'checks' => null, 'accounts' => null,
            'persistence' => null, 'facts' => array(), 'manual' => false,
        );
    }

    public function manual()
    {
        return !empty($this->options['manual']);
    }

    // ---- State: when the next report is due (posture.php, kept by OPcache) ----

    private function state()
    {
        if ($this->state === null) {
            $saved = $this->core->readPhp('posture.php');
            $this->state = is_array($saved) ? $saved : array('next_at' => 0);
        }
        return $this->state;
    }

    private function saveState(array $state)
    {
        if ($this->core->ensureDir()) {
            $this->core->writePhp('posture.php', $state);
        }
        $this->state = $state;
    }

    public function due()
    {
        $state = $this->state();
        if (!$state['next_at'] && $this->core->ensureDir()) {
            $this->saveState(array('next_at' => time() + self::FIRST));
            return false;
        }
        return time() >= (int) $state['next_at'];
    }

    // ---- The folders to walk -------------------------------------------------

    public function roots()
    {
        $given = (array) $this->options['roots'];
        if (!$given && !empty($_SERVER['DOCUMENT_ROOT'])) {
            $given = array($_SERVER['DOCUMENT_ROOT']);
        }
        return Files::realRoots($given);
    }

    // ---- The php.ini settings any PHP site has ------------------------------

    private static function onOff($name)
    {
        $value = @ini_get($name);
        if ($value === false || $value === null) {
            return null;
        }
        $value = strtolower(trim((string) $value));
        return !($value === '' || $value === '0' || $value === 'off' || $value === 'false' || $value === 'no');
    }

    // An "on" setting is the problem for every one of these, so on => fail.
    private static function stateOf($on)
    {
        if ($on === null) {
            return 'unknown';
        }
        return $on ? 'fail' : 'pass';
    }

    // Is this path inside one of the web folders?
    private function inWebroot($path)
    {
        $path = Files::clean(@realpath($path) ? realpath($path) : $path);
        if (!$path) {
            return false;
        }
        foreach ($this->roots() as $root) {
            if (strpos($path . '/', $root . '/') === 0) {
                return true;
            }
        }
        return false;
    }

    public function phpChecks()
    {
        $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
            || (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && strtolower($_SERVER['HTTP_X_FORWARDED_PROTO']) === 'https');
        $httpOnly = self::onOff('session.cookie_httponly');
        $checks = array(
            array('id' => 'php.display_errors', 'state' => self::stateOf(self::onOff('display_errors'))),
            array('id' => 'php.expose_php', 'state' => self::stateOf(self::onOff('expose_php'))),
            array('id' => 'php.allow_url_include', 'state' => self::stateOf(self::onOff('allow_url_include'))),
            // These two fail when the setting is *off*, so the state is flipped.
            array('id' => 'php.session_httponly', 'state' => self::stateOf($httpOnly === null ? null : !$httpOnly)),
        );
        // Only worth saying on a site that has HTTPS at all.
        if ($https) {
            $secure = self::onOff('session.cookie_secure');
            $checks[] = array('id' => 'php.session_secure', 'state' => self::stateOf($secure === null ? null : !$secure));
        }
        // Running the web app as root turns any hole in it into the whole machine.
        if (function_exists('posix_getuid')) {
            $checks[] = array('id' => 'server.runs_as_root', 'state' => posix_getuid() === 0 ? 'fail' : 'pass');
        }
        $log = (string) @ini_get('error_log');
        if ($log !== '' && strtolower($log) !== 'syslog') {
            $checks[] = array('id' => 'php.error_log_webroot', 'state' => $this->inWebroot($log) ? 'fail' : 'pass');
        }
        return $checks;
    }

    // ---- One walk of the web folder: files that shouldn't be there, and
    // ---- code anyone on the server can write ---------------------------------

    private static function kindOf($relative, $name)
    {
        foreach (self::$exposure as $rule) {
            if (preg_match($rule['pattern'], $rule['kind'] === 'vcs' ? '/' . $relative : $name)) {
                return $rule['kind'];
            }
        }
        return null;
    }

    // Writable by everyone (the "other" write bit): any account on the machine
    // can rewrite the file, which is how one hacked site infects the next.
    private static function worldWritable($path)
    {
        $mode = @fileperms($path);
        return $mode !== false && ($mode & 0002) !== 0;
    }

    // array(exposure, array('writable' => int, 'examples' => array(...), 'truncated' => bool))
    public function walk()
    {
        $exposure = array();
        $writable = 0;
        $examples = array();
        $entries = 0;
        $truncated = false;
        $perms = 0;
        $exclude = array();
        foreach ((array) $this->options['exclude'] as $dir) {
            $exclude[] = Files::clean(@realpath($dir) ? realpath($dir) : $dir) . '/';
        }
        foreach ($this->roots() as $root) {
            $queue = array(array($root, 0));
            while ($queue) {
                list($dir, $depth) = array_shift($queue);
                $handle = @opendir($dir);
                if (!$handle) {
                    continue;
                }
                while (($name = readdir($handle)) !== false) {
                    if ($name === '.' || $name === '..') {
                        continue;
                    }
                    if (++$entries > self::MAX_ENTRIES) {
                        $truncated = true;
                        break;
                    }
                    $path = $dir . '/' . $name;
                    if (@is_link($path)) {
                        continue;
                    }
                    $relative = ltrim(substr(Files::clean($path), strlen($root)), '/');
                    if (@is_dir($path)) {
                        if ($depth + 1 > self::MAX_DEPTH || in_array($name, self::$skipDirs, true)) {
                            // A version control folder in the web root is itself worth reporting.
                            $kind = self::kindOf($relative . '/', $name);
                            if ($kind === 'vcs' && count($exposure) < self::MAX_EXPOSURE) {
                                $exposure[] = array('path' => $relative . '/config', 'kind' => 'vcs');
                            }
                            continue;
                        }
                        $skip = false;
                        foreach ($exclude as $out) {
                            if (strpos(Files::clean($path) . '/', $out) === 0) {
                                $skip = true;
                            }
                        }
                        if (!$skip) {
                            $queue[] = array($path, $depth + 1);
                        }
                        continue;
                    }
                    if (!@is_file($path)) {
                        continue;
                    }
                    $kind = self::kindOf($relative, $name);
                    if ($kind !== null && count($exposure) < self::MAX_EXPOSURE) {
                        $size = @filesize($path);
                        $mtime = @filemtime($path);
                        $row = array('path' => Files::utf8($relative), 'kind' => $kind);
                        if ($size !== false) {
                            $row['size'] = (int) $size;
                        }
                        if ($mtime) {
                            $row['mtime'] = gmdate('Y-m-d\TH:i:s\Z', (int) $mtime);
                        }
                        $exposure[] = $row;
                    }
                    if ($perms < self::MAX_PERM_CHECKS && preg_match(self::$codeFile, $name)) {
                        $perms++;
                        if (self::worldWritable($path)) {
                            $writable++;
                            if (count($examples) < 3) {
                                $examples[] = Files::utf8($relative);
                            }
                        }
                    }
                }
                closedir($handle);
                if ($truncated) {
                    break 2;
                }
            }
        }
        return array($exposure, array('writable' => $writable, 'examples' => $examples, 'checked' => $perms, 'truncated' => $truncated));
    }

    // ---- Putting the report together ----------------------------------------

    private function fromCallback($name, $default = array())
    {
        if (!is_callable($this->options[$name])) {
            return $default;
        }
        try {
            $value = call_user_func($this->options[$name]);
        } catch (\Throwable $e) {
            return $default;
        }
        return $value === null ? $default : $value;
    }

    private static function checkRow($check)
    {
        if (!is_array($check) || empty($check['id']) || empty($check['state'])) {
            return null;
        }
        if (!in_array($check['state'], array('pass', 'fail', 'unknown'), true)) {
            return null;
        }
        $row = array('id' => strtolower(substr((string) $check['id'], 0, 60)), 'state' => $check['state']);
        if (isset($check['value']) && is_scalar($check['value']) && (string) $check['value'] !== '') {
            $row['value'] = substr((string) $check['value'], 0, 200);
        }
        return $row;
    }

    // Everything this server has to say about how it's set up.
    public function report()
    {
        $checks = $this->phpChecks();
        list($exposure, $code) = $this->walk();
        if ($code['checked'] > 0) {
            $checks[] = array(
                'id' => 'server.code_writable',
                'state' => $code['writable'] ? 'fail' : 'pass',
                'value' => $code['writable'] ? $code['writable'] . ' files, e.g. ' . implode(', ', $code['examples']) : '',
            );
        }
        foreach ((array) $this->fromCallback('checks') as $check) {
            $row = self::checkRow($check);
            if ($row && count($checks) < self::MAX_CHECKS) {
                $checks[] = $row;
            }
        }
        $facts = array('php_ini' => (string) @php_ini_loaded_file(), 'agent' => 'php/' . Core::VERSION);
        $roots = $this->roots();
        if ($roots) {
            $facts['webroot'] = $roots[0];
        }
        if (!empty($_SERVER['SERVER_SOFTWARE'])) {
            $facts['web_server'] = (string) $_SERVER['SERVER_SOFTWARE'];
        }
        foreach ((array) $this->options['facts'] as $name => $value) {
            if (is_string($name) && is_scalar($value) && (string) $value !== '') {
                $facts[$name] = substr((string) $value, 0, 100);
            }
        }
        $accounts = $this->fromCallback('accounts', array());
        $persistence = $this->fromCallback('persistence', array());
        $report = array(
            'site_id' => (string) $this->core->opt('site_id'),
            'host' => $this->host(),
            'at' => gmdate('Y-m-d\TH:i:s\Z'),
            'checks' => array_slice($checks, 0, self::MAX_CHECKS),
            'facts' => $facts,
        );
        // Left out when there's no folder to walk: the dashboard then says this
        // wasn't checked, instead of taking an empty walk for a clean one.
        if ($roots) {
            $report['exposure'] = array_slice($exposure, 0, self::MAX_EXPOSURE);
        }
        if (is_array($accounts) && !empty($accounts['admins'])) {
            $report['accounts'] = array(
                'total' => isset($accounts['total']) ? (int) $accounts['total'] : count($accounts['admins']),
                'admins' => array_slice(array_values($accounts['admins']), 0, self::MAX_ADMINS),
                'truncated' => count($accounts['admins']) > self::MAX_ADMINS,
            );
        }
        if (is_array($persistence) && !empty($persistence['cron'])) {
            $report['persistence'] = array('cron' => array_slice(array_values($persistence['cron']), 0, self::MAX_CRON));
        }
        return $report;
    }

    private function host()
    {
        $host = function_exists('gethostname') ? (string) gethostname() : '';
        return preg_match('/^[A-Za-z0-9._-]{1,100}$/D', $host) ? $host : 'server';
    }

    // Reports now, one process at a time. Returns the checks that failed
    // (empty when it didn't run).
    public function run()
    {
        if (!$this->core->configured() || !$this->core->ensureDir()) {
            return array();
        }
        $lock = @fopen($this->core->dir() . '/posture.lock', 'c');
        if (!$lock || !flock($lock, LOCK_EX | LOCK_NB)) {
            return array();
        }
        $failed = array();
        try {
            $report = $this->report();
            $result = $this->core->http('POST', '/events/posture', $report);
            $every = self::RETRY;
            if ($result['status'] === 200) {
                $answer = json_decode($result['body'], true);
                $every = max(self::RETRY, is_array($answer) && isset($answer['every']) ? (int) $answer['every'] : self::EVERY);
                foreach ($report['checks'] as $check) {
                    if ($check['state'] === 'fail') {
                        $failed[] = $check['id'];
                    }
                }
            }
            $this->saveState(array('next_at' => time() + $every));
        } catch (\Throwable $e) {
            $this->saveState(array('next_at' => time() + self::RETRY));
        }
        flock($lock, LOCK_UN);
        fclose($lock);
        return $failed;
    }
}
