<?php
// Resources module (protocol in sdk/protocols/resources.md): how the machine
// is doing — CPU, load, memory, swap, disks — sampled about once a minute and
// sent to POST /events/resources every few minutes. The companion of the
// performance module: that says how the requests went, this says whether the
// box can still serve them, so the dashboard shows what you would otherwise
// run node_exporter, Prometheus and Grafana for.
//
// PHP has no process that lives between requests, so a sample is taken during
// a request (at shutdown, like the request timings) and the previous
// /proc/stat reading is kept in the state folder. That is what lets a PHP site
// report a real CPU average: the difference between two readings a minute
// apart. The cost is that **sampling needs traffic** — a site nobody visits
// for an hour reports nothing for that hour, and the CPU figure is left out
// after a long gap rather than attributed to a minute it didn't measure.
//
// Nothing is guessed. A reading this machine won't give us is left out of the
// row, never sent as a zero: the collector stores it as NULL and the dashboard
// shows "—", because "0% CPU" and "we couldn't measure CPU" are different
// statements and only one of them means healthy.

namespace AnalyticsPlatform;

class Resources
{
    // Keep in step with the collector (expresscollect/Analytics/resources.js),
    // the agent and the Node and Python packages.
    const SAMPLE_EVERY = 60;
    const SEND_EVERY = 300;
    const MAX_ROWS = 500;
    const MAX_DISKS = 20;
    // Nobody watches a sub-gigabyte partition fill up; this drops the EFI
    // partition without needing a list of paths.
    const MIN_DISK_MB = 1024;
    // Two readings closer together than this can't be divided: the counters
    // move in ticks, so the percentage would be quantisation noise.
    const MIN_CPU_SECONDS = 10;
    // ...and further apart than this, the average covers far more than the
    // minute the row is labelled with, so it is left out instead.
    const MAX_CPU_SECONDS = 300;
    const SPOOL_MAX = 1000000;

    // Real on-disk filesystems only: no tmpfs, devtmpfs, proc, sysfs or
    // squashfs (snaps), none of which are the customer's disk. overlay is
    // here so a containerised site still reports something sensible.
    private static $fstypes = array('ext2', 'ext3', 'ext4', 'xfs', 'btrfs', 'zfs', 'f2fs', 'jfs',
        'reiserfs', 'ufs', 'vfat', 'exfat', 'ntfs', 'ntfs3', 'overlay', 'apfs', 'hfs');

    private $core;
    private $options;

    // Options: server_name (default the host name).
    public function __construct(Core $core, array $options = array())
    {
        $this->core = $core;
        $this->options = $options + array('server_name' => function_exists('gethostname') ? gethostname() : '');
    }

    private static function readText($path, $limit = 65536)
    {
        if (!@is_readable($path)) {
            return '';
        }
        $text = @file_get_contents($path, false, null, 0, $limit);
        return is_string($text) ? $text : '';
    }

    // The jiffie counters from /proc/stat's first line, or null. In order:
    // user, nice, system, idle, iowait, irq, softirq, steal.
    public static function cpuFields($text)
    {
        foreach (explode("\n", (string) $text) as $line) {
            if (strncmp($line, 'cpu ', 4) !== 0) {
                continue;
            }
            $fields = array();
            foreach (preg_split('/\s+/', trim(substr($line, 4))) as $value) {
                if (!is_numeric($value)) {
                    return null;
                }
                $fields[] = (int) $value;
            }
            return count($fields) >= 4 ? $fields : null;
        }
        return null;
    }

    // (busy, total) from counters already in hand.
    public static function cpuTimesOf(array $fields)
    {
        $total = array_sum($fields);
        $idle = $fields[3] + (isset($fields[4]) ? $fields[4] : 0);
        return array($total - $idle, $total);
    }

    // Where the machine's time went between two readings, or an empty array
    // when the pair can't say. A column this kernel is too old to carry is
    // left out rather than sent as a zero. steal is the one worth surfacing:
    // time the hypervisor gave to another tenant, which no amount of tuning
    // this site will change.
    public static function cpuShares($before, $after)
    {
        if (!is_array($before) || !is_array($after)) {
            return array();
        }
        $total = array_sum($after) - array_sum($before);
        if ($total <= 0) {
            return array();
        }
        // user folds nice in, as top adds them together.
        $parts = array(
            'cpu_user_pct' => array(0, 1),
            'cpu_system_pct' => array(2),
            'cpu_iowait_pct' => array(4),
            'cpu_steal_pct' => array(7),
        );
        $out = array();
        foreach ($parts as $name => $columns) {
            $moved = 0;
            $known = true;
            foreach ($columns as $i) {
                if (!isset($before[$i]) || !isset($after[$i])) {
                    $known = false;
                    break;
                }
                $moved += $after[$i] - $before[$i];
            }
            if (!$known) {
                continue;
            }
            if ($moved < 0) {
                return array();
            }
            $out[$name] = round(min(100.0, 100.0 * $moved / $total), 1);
        }
        return $out;
    }

    // (bytes read, bytes written) since boot over the real disks, or null.
    // Partitions are skipped so they are not counted twice with the disk they
    // sit on, and loop/ram/device-mapper devices are not disks at all.
    public static function diskCounters($text)
    {
        $read = 0;
        $written = 0;
        $found = false;
        foreach (explode("\n", (string) $text) as $line) {
            $fields = preg_split('/\s+/', trim($line));
            if (count($fields) < 10) {
                continue;
            }
            $name = $fields[2];
            if (preg_match('/^(?:loop|ram|zram|sr|fd|dm-|md\d)/', $name)
                || preg_match('/^(?:(?:sd|vd|xvd|hd)[a-z]+\d+|(?:nvme\d+n\d+|mmcblk\d+)p\d+)$/D', $name)) {
                continue;
            }
            if (!is_numeric($fields[5]) || !is_numeric($fields[9])) {
                continue;
            }
            // Sectors here are always 512 bytes: the unit of the interface.
            $read += (int) $fields[5] * 512;
            $written += (int) $fields[9] * 512;
            $found = true;
        }
        return $found ? array($read, $written) : null;
    }

    // (bytes in, bytes out) since boot over the real interfaces, or null.
    public static function netCounters($text)
    {
        $rx = 0;
        $tx = 0;
        $found = false;
        foreach (explode("\n", (string) $text) as $line) {
            $at = strpos($line, ':');
            if ($at === false) {
                continue;
            }
            $name = trim(substr($line, 0, $at));
            // Loopback, and the virtual ends of container and VM networking.
            if ($name === '' || preg_match('/^(?:lo|veth|docker|br-|virbr|tap|tun|vnet)/', $name)) {
                continue;
            }
            $fields = preg_split('/\s+/', trim(substr($line, $at + 1)));
            if (count($fields) < 9 || !is_numeric($fields[0]) || !is_numeric($fields[8])) {
                continue;
            }
            $rx += (int) $fields[0];
            $tx += (int) $fields[8];
            $found = true;
        }
        return $found ? array($rx, $tx) : null;
    }

    // Megabytes a second between two byte counters, or null when the pair
    // can't say: no pair, a reboot that reset them, no time, or too long a
    // gap. The gap rule matters most here: this client samples only while a
    // visitor is waiting, so two readings can be an hour apart.
    public static function rateMbs($before, $after, $seconds)
    {
        if ($before === null || $after === null) {
            return null;
        }
        if ($seconds <= 0 || $seconds > self::MAX_CPU_SECONDS) {
            return null;
        }
        $moved = $after - $before;
        if ($moved < 0) {
            return null;
        }
        return round($moved / $seconds / 1048576, 1);
    }

    // (busy, total) jiffies from /proc/stat's first line, or null. idle and
    // iowait are the machine doing nothing; everything else, steal included,
    // is time it wasn't available to us.
    public static function cpuTimes($text)
    {
        $fields = self::cpuFields($text);
        return $fields === null ? null : self::cpuTimesOf($fields);
    }

    // How busy the machine was between two readings, or null when the pair
    // can't say: no previous reading, a counter reset, or no time passed.
    public static function cpuPercent($before, $after)
    {
        if (!is_array($before) || !is_array($after)) {
            return null;
        }
        $busy = $after[0] - $before[0];
        $total = $after[1] - $before[1];
        if ($total <= 0 || $busy < 0) {
            return null;
        }
        return round(min(100.0, 100.0 * $busy / $total), 1);
    }

    // MemTotal/MemAvailable/Swap from /proc/meminfo, in whole megabytes.
    // Used is total - MemAvailable, never total - MemFree: page cache is not
    // pressure, and counting it as used makes every healthy Linux box look
    // full. A field the kernel didn't give us is left out.
    public static function memoryMb($text)
    {
        $values = array();
        foreach (explode("\n", (string) $text) as $line) {
            $parts = explode(':', $line, 2);
            if (count($parts) < 2) {
                continue;
            }
            $fields = preg_split('/\s+/', trim($parts[1]));
            if (!isset($fields[0]) || !is_numeric($fields[0])) {
                continue;
            }
            $values[$parts[0]] = (int) floor((int) $fields[0] / 1024);
        }
        $out = array();
        if (isset($values['MemTotal'])) {
            $out['mem_total_mb'] = $values['MemTotal'];
            if (isset($values['MemAvailable'])) {
                $out['mem_used_mb'] = max(0, $values['MemTotal'] - $values['MemAvailable']);
            }
        }
        if (isset($values['SwapTotal'])) {
            $out['swap_total_mb'] = $values['SwapTotal'];
            if (isset($values['SwapFree'])) {
                $out['swap_used_mb'] = max(0, $values['SwapTotal'] - $values['SwapFree']);
            }
        }
        return $out;
    }

    // One mount per device, under its shortest mount point, so a bind mount
    // isn't reported as a second disk. Without /proc/mounts the only
    // filesystem we can name without guessing is the site's own folder.
    //
    // A mount point has to be a **directory**. Docker bind-mounts single
    // files, so a container's /proc/mounts lists /etc/hosts, /etc/hostname
    // and /etc/resolv.conf on the host's own device — and those paths are
    // short, so without this they win the shortest-path race against the
    // real mount and the panel names a file as one of the site's disks.
    //
    // The directory test is per-device and advisory: open_basedir makes
    // is_dir() false for paths a shared host won't show us, and reporting no
    // disks at all would be worse than reporting an odd mount point, so a
    // device whose mounts we cannot confirm keeps its shortest one.
    public static function mountPoints($mountsText, $fallback = '/', $isDir = null)
    {
        if (trim((string) $mountsText) === '') {
            return array($fallback);
        }
        $isDir = $isDir ?: 'is_dir';
        $usable = is_callable($isDir);
        $dirs = array();
        $any = array();
        foreach (explode("\n", (string) $mountsText) as $line) {
            $fields = preg_split('/\s+/', trim($line));
            if (count($fields) < 3) {
                continue;
            }
            $device = $fields[0];
            $mount = str_replace('\\040', ' ', $fields[1]);
            if (!in_array($fields[2], self::$fstypes, true) || strpos($mount, '/') !== 0) {
                continue;
            }
            if (!isset($any[$device]) || strlen($mount) < strlen($any[$device])) {
                $any[$device] = $mount;
            }
            if ($usable && @call_user_func($isDir, $mount)
                && (!isset($dirs[$device]) || strlen($mount) < strlen($dirs[$device]))) {
                $dirs[$device] = $mount;
            }
        }
        $points = array();
        foreach ($any as $device => $mount) {
            $points[] = isset($dirs[$device]) ? $dirs[$device] : $mount;
        }
        $points = array_values(array_unique($points));
        sort($points);
        return $points;
    }

    // disk_total_space/disk_free_space are what PHP has, and they are df's
    // "size" and "available" — so used is size minus available, and total is
    // the size. Unlike the agent this cannot see the blocks reserved for
    // root, so used/total can read a few points under df's Use% on a disk
    // that has a reserve.
    public static function diskRows(array $points, $total = null, $free = null)
    {
        $total = $total ?: 'disk_total_space';
        $free = $free ?: 'disk_free_space';
        // Shared hosts commonly put these two in disable_functions, where PHP
        // 8 raises an Error that @ does not suppress — so the disk figures
        // have to be skipped rather than attempted. is_callable, not
        // function_exists, because the tests pass closures.
        if (!is_callable($total) || !is_callable($free)) {
            return array();
        }
        $rows = array();
        // One filesystem can sit behind two devices the kernel calls
        // different: in a container / is the overlay and the app's folder is
        // a bind of the host disk the overlay's upperdir lives on, so both
        // report the same size and the same free space down to the byte. No
        // device- or st_dev-based rule separates them, so the sizes are what
        // gives it away — a second mount matching an earlier one exactly is
        // the same storage seen twice.
        //
        // Raw bytes, not the rounded megabytes, so two disks that merely
        // round alike stay apart. Two genuinely separate filesystems of
        // identical size and identical free bytes do exist — a pair of
        // freshly formatted volumes nothing has written to — and one of them
        // is dropped until something is written to either. Both are empty, so
        // the fullness alert this feeds loses nothing.
        $seen = array();
        foreach ($points as $mount) {
            $size = @call_user_func($total, $mount);
            $available = @call_user_func($free, $mount);
            if (!is_numeric($size) || !is_numeric($available) || $size <= 0) {
                continue;
            }
            $row = array(
                'mount' => $mount,
                'total_mb' => (int) floor($size / 1048576),
                'used_mb' => (int) floor(max(0, $size - $available) / 1048576),
            );
            if ($row['total_mb'] < self::MIN_DISK_MB) {
                continue;
            }
            // $points arrives sorted, so the shortest path wins the collision.
            $key = $size . ':' . $available;
            if (isset($seen[$key])) {
                continue;
            }
            $seen[$key] = true;
            $rows[] = $row;
            if (count($rows) >= self::MAX_DISKS) {
                break;
            }
        }
        return $rows;
    }

    public static function hostUptime($text)
    {
        $fields = preg_split('/\s+/', trim((string) $text));
        return isset($fields[0]) && is_numeric($fields[0]) ? (int) $fields[0] : null;
    }

    // ---- Limits: how close the site is to a wall ------------------------------------
    // (resources.md, "Limits"; sdk/platform-node/lib/limits.js is the
    // reference). Inside Docker or Kubernetes the machine's figures are the
    // wrong question: /proc/meminfo is the host's, so memory reads 40% while
    // the container is a few megabytes from being killed. The cgroup's files
    // are the limits the kernel enforces, PHP-FPM's status says how full the
    // worker pool is, and the kernel says how long tasks waited and how many
    // connections it refused before PHP saw them.
    //
    // The counts (out-of-memory kills, the pool at its cap, refused
    // connections) are differences between this sample and the last one, kept
    // in resources.state like the CPU counters; unlike a rate they keep their
    // whole difference after a long gap, since a kill must not vanish because
    // nobody visited for an hour. Every reader gives null for a file that
    // isn't there, which outside Linux is all of them: nothing is sent then.
    //
    // Not here, on purpose: open files and requests in progress at once.
    // Each request is a process of its own (FPM, mod_php), so this process's
    // descriptors are one request's and the most in progress at once is
    // always this one; the pool's figures (workers_busy, queue_waiting) are
    // what says how many were in progress.

    // cgroup v1 says "no limit" with the largest page-aligned 64-bit number;
    // v2 says "max". Anything this size is not a cap a machine has.
    const NO_LIMIT_BYTES = 4611686018427387904.0;

    // A number from a file holding one, or null for a missing or unreadable
    // one: '' must never become the zero this module must not invent.
    private static function num($text)
    {
        $text = trim((string) $text);
        return $text !== '' && is_numeric($text) ? (float) $text : null;
    }

    // "name value" lines (memory.stat, cpu.stat, memory.events) as numbers.
    public static function keyValues($text)
    {
        $out = array();
        foreach (explode("\n", (string) $text) as $line) {
            $parts = preg_split('/\s+/', trim($line));
            if (count($parts) >= 2 && $parts[0] !== '' && ($n = self::num($parts[1])) !== null) {
                $out[$parts[0]] = $n;
            }
        }
        return $out;
    }

    // /proc/self/cgroup: the v2 path ("0::<path>") and the v1 memory and cpu
    // controllers' paths ("4:memory:<path>", "3:cpu,cpuacct:<path>").
    public static function cgroupPaths($text)
    {
        $out = array('v2' => null, 'memory' => null, 'cpu' => null);
        foreach (explode("\n", (string) $text) as $line) {
            $parts = explode(':', $line, 3);
            if (count($parts) < 3) {
                continue;
            }
            $at = trim($parts[2]);
            if ($at === '') {
                continue;
            }
            $controllers = explode(',', $parts[1]);
            if ($parts[0] === '0' && $parts[1] === '') {
                $out['v2'] = $at;
            }
            if (in_array('memory', $controllers, true)) {
                $out['memory'] = $at;
            }
            if (in_array('cpu', $controllers, true)) {
                $out['cpu'] = $at;
            }
        }
        return $out;
    }

    // Where this process's cgroup files are, or null. Under the mount at the
    // path /proc/self/cgroup names first, then the mount itself: in a
    // container with its own cgroup namespace the path is "/" and the mount
    // is already the container's; without one the path names the host's
    // hierarchy. v2 needs the memory or cpu controller's own files, not just
    // the directory: a hybrid machine lists a v2 path with no controllers in
    // it while the limits live in v1.
    public static function findCgroup(callable $read)
    {
        $paths = self::cgroupPaths($read('/proc/self/cgroup'));
        $under = function ($base, $at, array $probes) use ($read) {
            foreach ($at !== null && $at !== '/' ? array($base . $at, $base) : array($base) as $dir) {
                foreach ($probes as $probe) {
                    if ($read($dir . '/' . $probe) !== '') {
                        return $dir;
                    }
                }
            }
            return null;
        };
        if ($paths['v2'] !== null) {
            $dir = $under('/sys/fs/cgroup', $paths['v2'], array('memory.current', 'cpu.max'));
            if ($dir !== null) {
                return array('version' => 2, 'memory' => $dir, 'cpu' => $dir);
            }
        }
        $memory = $paths['memory'] !== null ? $under('/sys/fs/cgroup/memory', $paths['memory'], array('memory.usage_in_bytes')) : null;
        $cpu = $paths['cpu'] !== null ? $under('/sys/fs/cgroup/cpu', $paths['cpu'], array('cpu.cfs_quota_us')) : null;
        return $memory !== null || $cpu !== null ? array('version' => 1, 'memory' => $memory, 'cpu' => $cpu) : null;
    }

    // One reading of the cgroup's caps and counters, in bytes and raw counts.
    public static function cgroupReading($cg, callable $read)
    {
        if (!is_array($cg)) {
            return null;
        }
        $out = array('memCap' => null, 'memUsed' => null, 'cpuCores' => null, 'periods' => null, 'throttled' => null, 'oom' => null);
        if ($cg['version'] === 2) {
            $max = trim($read($cg['memory'] . '/memory.max'));
            $out['memCap'] = $max === 'max' ? null : self::num($max);
            $current = self::num($read($cg['memory'] . '/memory.current'));
            // The working set: page cache counts against the cgroup too, so
            // memory.current sits near the cap on a healthy container that
            // reads files. Less inactive_file is what Docker and the kubelet report.
            $stat = self::keyValues($read($cg['memory'] . '/memory.stat'));
            if ($current !== null) {
                $out['memUsed'] = max(0.0, $current - (isset($stat['inactive_file']) ? $stat['inactive_file'] : 0.0));
            }
            $events = self::keyValues($read($cg['memory'] . '/memory.events'));
            $out['oom'] = isset($events['oom_kill']) ? $events['oom_kill'] : null;
            $parts = preg_split('/\s+/', trim($read($cg['cpu'] . '/cpu.max')));
            if (count($parts) >= 2 && $parts[0] !== 'max' && self::num($parts[0]) > 0 && self::num($parts[1]) > 0) {
                $out['cpuCores'] = self::num($parts[0]) / self::num($parts[1]);
            }
            $cpu = self::keyValues($read($cg['cpu'] . '/cpu.stat'));
            $out['periods'] = isset($cpu['nr_periods']) ? $cpu['nr_periods'] : null;
            $out['throttled'] = isset($cpu['nr_throttled']) ? $cpu['nr_throttled'] : null;
            return $out;
        }
        if ($cg['memory'] !== null) {
            $out['memCap'] = self::num($read($cg['memory'] . '/memory.limit_in_bytes'));
            $usage = self::num($read($cg['memory'] . '/memory.usage_in_bytes'));
            $stat = self::keyValues($read($cg['memory'] . '/memory.stat'));
            if ($usage !== null) {
                $out['memUsed'] = max(0.0, $usage - (isset($stat['total_inactive_file']) ? $stat['total_inactive_file'] : 0.0));
            }
            // Kernels from 4.13 carry the count here.
            $control = self::keyValues($read($cg['memory'] . '/memory.oom_control'));
            $out['oom'] = isset($control['oom_kill']) ? $control['oom_kill'] : null;
        }
        if ($cg['cpu'] !== null) {
            $quota = self::num($read($cg['cpu'] . '/cpu.cfs_quota_us'));
            $period = self::num($read($cg['cpu'] . '/cpu.cfs_period_us'));
            if ($quota > 0 && $period > 0) {
                $out['cpuCores'] = $quota / $period;
            }
            $cpu = self::keyValues($read($cg['cpu'] . '/cpu.stat'));
            $out['periods'] = isset($cpu['nr_periods']) ? $cpu['nr_periods'] : null;
            $out['throttled'] = isset($cpu['nr_throttled']) ? $cpu['nr_throttled'] : null;
        }
        return $out;
    }

    // How much a counter moved between two readings, or null: no pair, or it
    // went down, which is a reset and not a negative count. Never dropped
    // for the pair being far apart.
    public static function countSince($before, $after)
    {
        if (!is_numeric($before) || !is_numeric($after) || $after < $before) {
            return null;
        }
        return (int) round($after - $before);
    }

    // The row's cgroup fields from two readings. A cap at or above what the
    // machine itself has isn't one (a systemd slice with no MemoryMax, or a
    // container allowed more cores than the host), so neither half is sent.
    // The throttled share is a rate over the interval, so like the CPU
    // figures it needs a usable one ($usable).
    public static function cgroupFields($before, $after, $memTotalMb = null, $cores = null, $usable = true)
    {
        $out = array();
        if (!is_array($after)) {
            return $out;
        }
        $capMb = $after['memCap'] > 0 && $after['memCap'] < self::NO_LIMIT_BYTES ? (int) floor($after['memCap'] / 1048576) : 0;
        if ($capMb > 0 && !($memTotalMb && $capMb >= $memTotalMb) && $after['memUsed'] !== null) {
            $out['limit_mem_mb'] = $capMb;
            $out['limit_mem_used_mb'] = min($capMb, (int) floor($after['memUsed'] / 1048576));
        }
        if ($after['cpuCores'] && !($cores && $after['cpuCores'] >= $cores)) {
            $out['limit_cpu_cores'] = round($after['cpuCores'], 2);
        }
        $before = is_array($before) ? $before : array();
        // Periods only pass while a quota is set, so no cap means nothing sent.
        $periods = self::countSince(isset($before['periods']) ? $before['periods'] : null, $after['periods']);
        $throttled = self::countSince(isset($before['throttled']) ? $before['throttled'] : null, $after['throttled']);
        if ($usable && $periods > 0 && $throttled !== null) {
            $out['cpu_throttled_pct'] = round(min(100.0, 100.0 * $throttled / $periods), 1);
        }
        // Kills of other processes in this cgroup (another FPM worker): the
        // kill of the one reporting can't be reported by it.
        $oom = self::countSince(isset($before['oom']) ? $before['oom'] : null, $after['oom']);
        if ($oom !== null) {
            $out['oom_kills'] = $oom;
        }
        return $out;
    }

    // /proc/pressure/<resource>'s "some" line, avg60: the share of the last
    // minute in which at least one task was waiting. One reading is enough,
    // so a site sampled during a visit still gets an honest figure.
    public static function pressureSome($text)
    {
        return preg_match('/^some\b[^\n]*\bavg60=([0-9.]+)/m', (string) $text, $m) ? round(min(100.0, (float) $m[1]), 1) : null;
    }

    public static function pressureFields(callable $read)
    {
        $out = array();
        foreach (array('psi_cpu_pct' => 'cpu', 'psi_mem_pct' => 'memory', 'psi_io_pct' => 'io') as $name => $file) {
            $value = self::pressureSome($read('/proc/pressure/' . $file));
            if ($value !== null) {
                $out[$name] = $value;
            }
        }
        return $out;
    }

    // TcpExt ListenOverflows from /proc/net/netstat: connections refused
    // since boot because the accept queue was full. A header line and a
    // value line.
    public static function listenOverflows($text)
    {
        $lines = explode("\n", (string) $text);
        for ($i = 0; $i + 1 < count($lines); $i++) {
            if (strncmp($lines[$i], 'TcpExt:', 7) !== 0 || strncmp($lines[$i + 1], 'TcpExt:', 7) !== 0) {
                continue;
            }
            $at = array_search('ListenOverflows', preg_split('/\s+/', trim($lines[$i])), true);
            $values = preg_split('/\s+/', trim($lines[$i + 1]));
            return $at !== false && $at > 0 && isset($values[$at]) ? self::num($values[$at]) : null;
        }
        return null;
    }

    // How full the connection-tracking table is. Only where the firewall
    // loaded it, and usually unreadable inside a container.
    public static function conntrackPct(callable $read)
    {
        $count = self::num($read('/proc/sys/net/netfilter/nf_conntrack_count'));
        $max = self::num($read('/proc/sys/net/netfilter/nf_conntrack_max'));
        return $count !== null && $max > 0 ? round(min(100.0, 100.0 * $count / $max), 1) : null;
    }

    // PHP-FPM's pool, from fpm_get_status() (PHP 7.3+, FPM only): workers
    // busy (this one among them: it is still running), the most allowed only
    // under pm = static (FPM reports no pm.max_children, and every child is
    // the maximum there), connections waiting for a worker, and how many
    // times since the last sample the pool wanted another worker and was at
    // its cap. The pool is the process this row speaks for, so it names the
    // row (proc_key, kept while the pool runs) and says how long it has run:
    // an FPM restart shows as proc_uptime_s starting again. $last: what the
    // state kept; $keep gets what to keep for the next sample.
    public static function fpmFields($status, array $last, array &$keep, $now = null)
    {
        if (!is_array($status) || !isset($status['pool'])) {
            return array();
        }
        $now = $now === null ? time() : (int) $now;
        $out = array();
        if (isset($status['active-processes']) && is_numeric($status['active-processes'])) {
            $out['workers_busy'] = (int) $status['active-processes'];
        }
        if (isset($status['process-manager'], $status['total-processes']) && $status['process-manager'] === 'static'
            && (int) $status['total-processes'] > 0) {
            $out['workers_max'] = (int) $status['total-processes'];
        }
        if (isset($status['listen-queue']) && is_numeric($status['listen-queue'])) {
            $out['queue_waiting'] = (int) $status['listen-queue'];
        }
        $pool = (string) $status['pool'];
        $start = isset($status['start-time']) ? (int) $status['start-time'] : 0;
        // Kept per pool and start: two pools (or two containers' pools)
        // sampling into one state folder each carry on from their own.
        $id = $pool . '|' . $start;
        $pools = isset($last['fpm']) && is_array($last['fpm']) ? $last['fpm'] : array();
        $was = isset($pools[$id]) && is_array($pools[$id]) ? $pools[$id] : null;
        $reached = isset($status['max-children-reached']) && is_numeric($status['max-children-reached']) ? (int) $status['max-children-reached'] : null;
        if ($was !== null && $reached !== null) {
            $maxed = self::countSince(isset($was['reached']) ? $was['reached'] : null, $reached);
            if ($maxed !== null) {
                $out['pool_maxed'] = $maxed;
            }
        }
        $key = $was !== null && isset($was['key']) && preg_match('/^[a-f0-9]{16}\z/', (string) $was['key']) ? (string) $was['key'] : bin2hex(random_bytes(8));
        $keep['fpm'] = self::keepIn($pools, $id, array('reached' => $reached, 'key' => $key));
        $out['proc_key'] = $key;
        if ($start > 0 && $now >= $start) {
            $out['proc_uptime_s'] = $now - $start;
        }
        return $out;
    }

    // How many cgroups, namespaces or pools the state keeps readings of.
    const KEEP_IDS = 4;

    // Which cgroup a reading is of: its directories, and the inode of one,
    // since inside a container with its own cgroup namespace every
    // container's is /sys/fs/cgroup.
    private static function cgroupId(array $cg)
    {
        $dir = $cg['memory'] !== null ? $cg['memory'] : $cg['cpu'];
        $st = @stat($dir);
        return $cg['version'] . ':' . $cg['memory'] . ':' . $cg['cpu'] . (is_array($st) ? '#' . $st['dev'] . ':' . $st['ino'] : '');
    }

    // The reading kept for $id, or null: none, or one from another boot
    // (a difference of more than two minutes: the clock may have been set).
    private static function lastOf(array $map, $id, $boot)
    {
        if (!isset($map[$id]) || !is_array($map[$id])) {
            return null;
        }
        $was = $map[$id];
        $then = isset($was['boot']) && is_numeric($was['boot']) ? (int) $was['boot'] : null;
        return ($boot === null) === ($then === null) && ($boot === null || abs($boot - $then) <= 120) ? $was : null;
    }

    // $map with $value as $id's, the most recent first, the oldest let go.
    private static function keepIn(array $map, $id, array $value)
    {
        $map = array_filter($map, 'is_array');
        unset($map[$id]);
        return array_slice(array((string) $id => $value) + $map, 0, self::KEEP_IDS, true);
    }

    // The limits pass for one sample, and what to keep for the next one
    // (array(fields, keep)). $read reads a file ('' when it can't); $fpm is
    // fpm_get_status()'s answer, read here when not given.
    public static function limits(array $last, $usable, $memTotalMb = null, $cores = null, $read = null, $fpm = false, $now = null)
    {
        $read = $read ?: function ($path) {
            return self::readText($path);
        };
        $now = $now === null ? time() : (int) $now;
        $out = array();
        $keep = array();
        // The state file outlives a reboot, and the kernel's counters don't:
        // each reading kept says which boot it was taken in, and one from
        // another is not diffed against. And one state folder can be shared
        // by processes in several cgroups or network namespaces (the web and
        // the queue worker containers mounting one storage volume, or two
        // machines on one network share), each with counters of its own: a
        // reading is kept per cgroup and per namespace, so none is diffed
        // against another's, which would make up kills and refused
        // connections out of the difference between two containers.
        $uptime = self::hostUptime($read('/proc/uptime'));
        $boot = $uptime !== null ? $now - $uptime : null;
        $cg = self::findCgroup($read);
        $reading = self::cgroupReading($cg, $read);
        $cgs = isset($last['cg']) && is_array($last['cg']) ? $last['cg'] : array();
        if ($reading !== null) {
            $id = self::cgroupId($cg);
            $was = self::lastOf($cgs, $id, $boot);
            // The throttled share is a rate: only over an interval of this
            // cgroup's own that is usable too.
            $recent = $was !== null && isset($cgs[$id]['at']) && $now - (int) $cgs[$id]['at'] <= self::MAX_CPU_SECONDS;
            $out += self::cgroupFields($was, $reading, $memTotalMb, $cores, $usable && $recent);
            $cgs = self::keepIn($cgs, $id, array('periods' => $reading['periods'], 'throttled' => $reading['throttled'],
                'oom' => $reading['oom'], 'boot' => $boot, 'at' => $now));
        }
        if ($cgs) {
            $keep['cg'] = $cgs;
        }
        $out += self::pressureFields($read);
        $overflows = self::listenOverflows($read('/proc/net/netstat'));
        $los = isset($last['lo']) && is_array($last['lo']) ? $last['lo'] : array();
        if ($overflows !== null) {
            $ns = @readlink('/proc/self/ns/net');
            $id = is_string($ns) ? $ns : '';
            $was = self::lastOf($los, $id, $boot);
            $drops = self::countSince(isset($was['n']) ? $was['n'] : null, $overflows);
            if ($drops !== null) {
                $out['listen_drops'] = $drops;
            }
            $los = self::keepIn($los, $id, array('n' => $overflows, 'boot' => $boot));
        }
        if ($los) {
            $keep['lo'] = $los;
        }
        $conntrack = self::conntrackPct($read);
        if ($conntrack !== null) {
            $out['conntrack_pct'] = $conntrack;
        }
        if ($fpm === false && function_exists('fpm_get_status')) {
            $fpm = @fpm_get_status();
        }
        $out += self::fpmFields($fpm, $last, $keep, $now);
        // A sample taken outside FPM (a command-line cron run) keeps the
        // pool's, so the pool's key and count carry on past it.
        if (!isset($keep['fpm']) && isset($last['fpm']) && is_array($last['fpm'])) {
            $keep['fpm'] = $last['fpm'];
        }
        return array($out, $keep);
    }

    // Is a sample due? PHP only runs while a request does, so "about once a
    // minute" means "on the first request after a minute has passed".
    public function due()
    {
        $file = $this->core->dir() . '/resources.state';
        clearstatcache(true, $file);
        return !is_file($file) || filemtime($file) <= time() - self::SAMPLE_EVERY;
    }

    // Takes a sample if one is due, appends it to the spool, and sends the
    // spool when that is due too. Platform calls this at shutdown.
    public function flush($force = false)
    {
        if (!$this->core->isOn('resources') || !$this->core->ensureDir()) {
            return;
        }
        if ($force || $this->due()) {
            $row = $this->sample();
            if ($row) {
                $this->spool($row);
            }
        }
        $this->send($force);
    }

    // One sample, covering the time since the last one. The previous
    // /proc/stat reading and the time of it live in resources.state, which is
    // the only way a language with no daemon can measure CPU at all.
    public function sample($now = null)
    {
        $now = $now === null ? time() : (int) $now;
        $file = $this->core->dir() . '/resources.state';
        $state = json_decode(self::readText($file, 16384), true);
        $fields = self::cpuFields(self::readText('/proc/stat'));
        $disk = self::diskCounters(self::readText('/proc/diskstats'));
        $net = self::netCounters(self::readText('/proc/net/dev'));
        $cpu = $fields === null ? null : self::cpuTimesOf($fields);
        // A state file written before the breakdown existed holds the two
        // (busy, total) figures rather than the counters; it is not a reading
        // this code can use, so the first sample after an upgrade is skipped
        // rather than measured against the wrong numbers.
        $before = is_array($state) && isset($state['cpu']) && is_array($state['cpu']) && count($state['cpu']) >= 4
            ? array_values($state['cpu']) : null;
        $previous = $before === null ? null : self::cpuTimesOf($before);
        $lastDisk = is_array($state) && isset($state['disk']) && is_array($state['disk']) && count($state['disk']) === 2
            ? array_values($state['disk']) : null;
        $lastNet = is_array($state) && isset($state['net']) && is_array($state['net']) && count($state['net']) === 2
            ? array_values($state['net']) : null;
        $since = is_array($state) && isset($state['at']) ? (int) $state['at'] : null;
        // The minute the interval started in, not the one it ended in.
        $minute = $since !== null ? $since : $now;
        $row = array('minute' => gmdate('Y-m-d\TH:i:s\Z', (int) (floor($minute / 60) * 60)));
        $elapsed = $since === null ? null : $now - $since;
        $percent = self::cpuPercent($previous, $cpu);
        // Left out after a long gap: the average would cover far more than the
        // minute this row is labelled with, which no reader could tell.
        $usable = $elapsed !== null && $elapsed >= self::MIN_CPU_SECONDS && $elapsed <= self::MAX_CPU_SECONDS;
        if ($percent !== null && $usable) {
            $row['cpu_pct'] = $percent;
        }
        // The breakdown and the rates cover the same interval as cpu_pct, so
        // they live or die with it: an hour's average must not be labelled as
        // one minute.
        if ($usable) {
            foreach (self::cpuShares($before, $fields) as $name => $value) {
                $row[$name] = $value;
            }
            $rates = array();
            if ($lastDisk !== null && $disk !== null) {
                $rates['disk_read_mbs'] = self::rateMbs($lastDisk[0], $disk[0], $elapsed);
                $rates['disk_write_mbs'] = self::rateMbs($lastDisk[1], $disk[1], $elapsed);
            }
            if ($lastNet !== null && $net !== null) {
                $rates['net_rx_mbs'] = self::rateMbs($lastNet[0], $net[0], $elapsed);
                $rates['net_tx_mbs'] = self::rateMbs($lastNet[1], $net[1], $elapsed);
            }
            foreach ($rates as $name => $value) {
                if ($value !== null) {
                    $row[$name] = $value;
                }
            }
        }
        $cores = self::cores();
        if ($cores) {
            $row['cpu_cores'] = $cores;
        }
        if (function_exists('sys_getloadavg')) {
            $load = @sys_getloadavg();
            if (is_array($load) && count($load) === 3) {
                $row['load1'] = round((float) $load[0], 2);
                $row['load5'] = round((float) $load[1], 2);
                $row['load15'] = round((float) $load[2], 2);
            }
        }
        $row += self::memoryMb(self::readText('/proc/meminfo'));
        $disks = self::diskRows(self::mountPoints(self::readText('/proc/mounts'), self::siteRoot()));
        if ($disks) {
            $row['disks'] = $disks;
        }
        // This package runs inside the application, so unlike the agent it can
        // honestly report the application's own memory.
        if (function_exists('memory_get_peak_usage')) {
            $row['proc_rss_mb'] = max(1, (int) floor(memory_get_peak_usage(true) / 1048576));
        }
        $uptime = self::hostUptime(self::readText('/proc/uptime'));
        if ($uptime !== null) {
            $row['host_uptime_s'] = $uptime;
        }
        list($limits, $keep) = self::limits(
            is_array($state) && isset($state['lim']) && is_array($state['lim']) ? $state['lim'] : array(),
            $usable,
            isset($row['mem_total_mb']) ? $row['mem_total_mb'] : null,
            $cores ?: null,
            null,
            false,
            $now
        );
        $row += $limits;
        if ($fields !== null || $keep) {
            // Beside it and moved into place, so a request reading it never
            // sees half a sample.
            $tmp = $file . '.' . getmypid() . '.' . bin2hex(random_bytes(4)) . '.tmp';
            if (@file_put_contents($tmp, json_encode(array(
                'cpu' => $fields,
                'disk' => $disk,
                'net' => $net,
                'lim' => $keep,
                'at' => $now,
            ))) !== false) {
                @chmod($tmp, 0600);
                if (!@rename($tmp, $file)) {
                    @unlink($tmp);
                }
            }
        } else {
            @touch($file);
        }
        // Nothing but a minute label is not a sample.
        return count($row) > 1 ? $row : null;
    }

    private static function cores()
    {
        $text = self::readText('/proc/cpuinfo', 1048576);
        if ($text !== '') {
            $count = preg_match_all('/^processor\s*:/m', $text);
            if ($count) {
                return $count;
            }
        }
        return 0;
    }

    private static function siteRoot()
    {
        $root = isset($_SERVER['DOCUMENT_ROOT']) ? (string) $_SERVER['DOCUMENT_ROOT'] : '';
        return $root !== '' ? $root : '/';
    }

    private function spool(array $row)
    {
        $this->core->append('resources', $row, self::SPOOL_MAX);
    }

    // Sends the spooled samples, every SEND_EVERY seconds.
    private function send($force = false)
    {
        $this->core->drain('resources', self::SEND_EVERY, $force, function (array $samples) {
            $rows = array();
            foreach ($samples as $row) {
                if (isset($row['minute'])) {
                    $rows[$row['minute']] = $row;
                }
            }
            ksort($rows);
            $rows = array_slice(array_values($rows), -self::MAX_ROWS);
            if ($rows) {
                $this->core->post('resources', '/events/resources', array(
                    'site_id' => (string) $this->core->opt('site_id'),
                    'server_name' => substr((string) $this->options['server_name'], 0, 100),
                    'runtime' => 'PHP ' . PHP_VERSION,
                    'rows' => $rows,
                ), 'bearer');
            }
        });
    }
}
