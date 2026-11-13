<?php
// Software inventory (protocol in sdk/protocols/inventory.md): the Composer
// packages and runtime versions the site runs, reported to POST
// /events/inventory about once a day so the dashboard's Security check can
// match them against known security holes. Names and versions only. Platform
// runs it after the response when due (or call run() from a cron job and set
// 'manual', as the WordPress plugin does from WP-Cron).
//
// Options: root (the folder with composer.lock; default the document root's
// parent, then the document root, then the working directory), packages
// (callable returning more packages, each array('ecosystem' => ..., 'name'
// => ..., 'version' => ...[, 'active' => bool]); the WordPress plugin lists
// its plugins and themes this way), runtime (more runtime versions, e.g.
// array('wordpress' => '6.4.3')), manual (true: only run() from your own job).

namespace AnalyticsPlatform;

class Inventory
{
    const EVERY = 86400;
    const RETRY = 3600;
    // The first report waits this long after the module starts.
    const FIRST = 120;
    const MAX_PACKAGES = 5000;

    private $core;
    private $options;
    private $state = null;

    public function __construct(Core $core, array $options = array())
    {
        $this->core = $core;
        $this->options = $options + array('root' => null, 'packages' => null, 'runtime' => array(), 'manual' => false);
    }

    public function manual()
    {
        return !empty($this->options['manual']);
    }

    // ---- State: when the next report is due (inventory.php, kept by OPcache) ----

    private function state()
    {
        if ($this->state === null) {
            $saved = $this->core->readPhp('inventory.php');
            $this->state = is_array($saved) ? $saved : array('next_at' => 0);
        }
        return $this->state;
    }

    private function saveState(array $state)
    {
        if ($this->core->ensureDir()) {
            $this->core->writePhp('inventory.php', $state);
        }
        $this->state = $state;
    }

    public function due()
    {
        $state = $this->state();
        // Never reported: the first report a little after start.
        if (!$state['next_at'] && $this->core->ensureDir()) {
            $this->saveState(array('next_at' => time() + self::FIRST));
            return false;
        }
        return time() >= (int) $state['next_at'];
    }

    // ---- What to report -------------------------------------------------------

    private function lockFile()
    {
        $roots = array();
        if ($this->options['root']) {
            $roots[] = (string) $this->options['root'];
        } else {
            if (!empty($_SERVER['DOCUMENT_ROOT'])) {
                $roots[] = dirname($_SERVER['DOCUMENT_ROOT']);
                $roots[] = $_SERVER['DOCUMENT_ROOT'];
            }
            $roots[] = getcwd();
        }
        foreach ($roots as $root) {
            $file = rtrim((string) $root, '/\\') . '/composer.lock';
            if ($root && is_file($file)) {
                return $file;
            }
        }
        return null;
    }

    private static function version($version)
    {
        return ltrim(trim((string) $version), 'vV');
    }

    // composer.json's "require" beside the lock file: the packages the site
    // asks for by name, as opposed to the ones those depend on. "php" and the
    // ext-/lib- entries are platform requirements, not packages. An empty set
    // means we could not tell, and nothing is marked.
    public function requiredNames($file)
    {
        $manifest = $file ? dirname($file) . '/composer.json' : null;
        $json = $manifest && is_file($manifest) ? json_decode((string) @file_get_contents($manifest), true) : null;
        $names = array();
        if (is_array($json) && isset($json['require']) && is_array($json['require'])) {
            foreach (array_keys($json['require']) as $name) {
                $name = strtolower(trim((string) $name));
                if ($name !== '' && $name !== 'php' && strpos($name, 'ext-') !== 0 && strpos($name, 'lib-') !== 0) {
                    $names[$name] = true;
                }
            }
        }
        return $names;
    }

    // composer.lock's packages (not packages-dev); none when there's no lock file.
    public function composerPackages()
    {
        $file = $this->lockFile();
        $lock = $file ? json_decode((string) @file_get_contents($file), true) : null;
        $direct = $this->requiredNames($file);
        $out = array();
        foreach (is_array($lock) && isset($lock['packages']) && is_array($lock['packages']) ? $lock['packages'] : array() as $package) {
            if (!empty($package['name']) && !empty($package['version'])) {
                $row = array('ecosystem' => 'Packagist', 'name' => (string) $package['name'], 'version' => self::version($package['version']));
                if (isset($direct[strtolower((string) $package['name'])])) {
                    $row['direct'] = true;
                }
                $out[] = $row;
            }
        }
        return $out;
    }

    public function packages()
    {
        $packages = $this->composerPackages();
        if (is_callable($this->options['packages'])) {
            try {
                $more = call_user_func($this->options['packages']);
            } catch (\Throwable $e) {
                $more = array();
            }
            foreach (is_array($more) ? $more : array() as $package) {
                if (is_array($package) && !empty($package['ecosystem']) && !empty($package['name']) && isset($package['version']) && $package['version'] !== '') {
                    $row = array('ecosystem' => (string) $package['ecosystem'], 'name' => (string) $package['name'], 'version' => self::version($package['version']));
                    if (isset($package['active'])) {
                        $row['active'] = (bool) $package['active'];
                    }
                    if (!empty($package['direct'])) {
                        $row['direct'] = true;
                    }
                    $packages[] = $row;
                }
            }
        }
        return $packages;
    }

    // ---- Reporting ------------------------------------------------------------

    // Reports now, one process at a time. Returns the packages reported (empty
    // when it didn't run).
    public function run()
    {
        if (!$this->core->configured() || !$this->core->ensureDir()) {
            return array();
        }
        $lock = @fopen($this->core->dir() . '/inventory.lock', 'c');
        if (!$lock || !flock($lock, LOCK_EX | LOCK_NB)) {
            return array();
        }
        $packages = $this->packages();
        $runtime = array('php' => PHP_VERSION);
        foreach ((array) $this->options['runtime'] as $name => $version) {
            if (is_string($name) && is_scalar($version) && (string) $version !== '') {
                $runtime[$name] = (string) $version;
            }
        }
        $host = function_exists('gethostname') ? (string) gethostname() : '';
        $result = $this->core->http('POST', '/events/inventory', array(
            'site_id' => (string) $this->core->opt('site_id'),
            'host' => preg_match('/^[A-Za-z0-9._-]{1,100}$/D', $host) ? $host : 'server',
            'at' => gmdate('Y-m-d\TH:i:s\Z'),
            'runtime' => $runtime,
            'packages' => array_slice($packages, 0, self::MAX_PACKAGES),
            'truncated' => count($packages) > self::MAX_PACKAGES,
        ));
        $every = self::RETRY;
        if ($result['status'] === 200) {
            $answer = json_decode($result['body'], true);
            $every = max(self::RETRY, is_array($answer) && isset($answer['every']) ? (int) $answer['every'] : self::EVERY);
        }
        $this->saveState(array('next_at' => time() + $every));
        flock($lock, LOCK_UN);
        fclose($lock);
        return $result['status'] === 200 ? $packages : array();
    }
}
