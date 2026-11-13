package com.sitegoose.analytics;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.lang.management.ManagementFactory;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileStore;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.function.Predicate;
import java.util.regex.Pattern;

/**
 * How the machine is doing (sdk/protocols/resources.md): CPU, load, memory,
 * swap and disks, sampled every minute and sent to POST /events/resources
 * every few minutes.
 *
 * <p>Nothing is guessed. A reading this machine won't give us is left out of
 * the row, never sent as a zero. On Linux everything comes from /proc, as
 * the Python package and the agent read it; elsewhere the JVM's own
 * OperatingSystemMXBean (com.sun.management) gives CPU, load and memory, and
 * FileStore the disks. Inode counts are never sent: Java can't read them.
 *
 * <p>Each row also says how close the app is to a wall ({@link Limits}): its
 * container's caps and throttling, the machine's waiting time, refused
 * connections, open files, the JVM's heap and garbage collection, and the
 * most requests in progress at once (from the servlet filter's timing).
 */
final class Resources {
    static final double SAMPLE_EVERY = 60;
    static final double EVERY = 5 * 60;
    static final double RETRY_EVERY = 60;
    static final double OFF_EVERY = 600;
    static final int MAX_ROWS = 500;
    static final int MAX_DISKS = 20;
    static final long MIN_DISK_MB = 1024;
    static final double MIN_CPU_SECONDS = 1.0;
    static final Set<String> FSTYPES = new HashSet<>(Arrays.asList("ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs", "jfs",
            "reiserfs", "ufs", "vfat", "exfat", "ntfs", "ntfs3", "overlay", "apfs", "hfs"));
    static final long MB = 1024 * 1024;
    static final long IO_SECTOR = 512;
    static final double IO_MAX_PAIR_SECONDS = 300;
    private static final Pattern IO_NOT_A_DISK = Pattern.compile("^(?:loop|ram|zram|sr|fd|dm-|md\\d)");
    private static final Pattern IO_PARTITION = Pattern.compile("^(?:(?:sd|vd|xvd|hd)[a-z]+\\d+|(?:nvme\\d+n\\d+|mmcblk\\d+)p\\d+)$");
    private static final Pattern NET_NOT_REAL = Pattern.compile("^(?:lo|veth|docker|br-|virbr|tap|tun|vnet)");
    private static final boolean LINUX = System.getProperty("os.name", "").toLowerCase().startsWith("linux");

    static String readText(String path) {
        try (InputStream in = Files.newInputStream(Paths.get(path))) {
            return new String(in.readNBytes(65536), StandardCharsets.UTF_8);
        } catch (IOException | RuntimeException unreadable) {
            return "";
        }
    }

    /** The jiffy counters from /proc/stat's first line, or null: user, nice, system, idle, iowait, irq, softirq, steal. */
    static long[] cpuFields(String text) {
        for (String line : text.split("\n")) {
            if (!line.startsWith("cpu ")) {
                continue;
            }
            String[] parts = line.trim().split("\\s+");
            long[] fields = new long[parts.length - 1];
            try {
                for (int i = 1; i < parts.length; i++) {
                    fields[i - 1] = Long.parseLong(parts[i]);
                }
            } catch (NumberFormatException error) {
                return null;
            }
            return fields.length >= 4 ? fields : null;
        }
        return null;
    }

    /** CPUs, as /proc/stat counts them (cpu0, cpu1...): the machine's, which the percentage is of. */
    static int cpuCount(String text) {
        int count = 0;
        for (String line : text.split("\n")) {
            if (line.length() > 3 && line.startsWith("cpu") && Character.isDigit(line.charAt(3))) {
                count++;
            }
        }
        return count;
    }

    /** Every jiffy once: guest and guest_nice are already inside user and nice. */
    static long cpuTotal(long[] fields) {
        long total = 0;
        for (int i = 0; i < Math.min(8, fields.length); i++) {
            total += fields[i];
        }
        return total;
    }

    /** {busy, total} jiffies. */
    static long[] cpuTimesOf(long[] fields) {
        long total = cpuTotal(fields);
        long idle = fields[3] + (fields.length > 4 ? fields[4] : 0);
        return new long[] {total - idle, total};
    }

    static final Object[][] CPU_SHARES = {
        {"cpu_user_pct", new int[] {0, 1}},
        {"cpu_system_pct", new int[] {2}},
        {"cpu_iowait_pct", new int[] {4}},
        {"cpu_steal_pct", new int[] {7}},
    };

    static double round(double value, int places) {
        // As Python's round(): the exact value, ties to even (1.25 -> 1.2).
        if (Double.isNaN(value) || Double.isInfinite(value)) {
            return value;
        }
        return new java.math.BigDecimal(value).setScale(places, java.math.RoundingMode.HALF_EVEN).doubleValue();
    }

    /** Where the machine's time went between two /proc/stat readings. */
    static Map<String, Object> cpuShares(long[] before, long[] after) {
        Map<String, Object> out = new LinkedHashMap<>();
        if (before == null || after == null) {
            return out;
        }
        long total = cpuTotal(after) - cpuTotal(before);
        if (total <= 0) {
            return out;
        }
        for (Object[] share : CPU_SHARES) {
            int[] columns = (int[]) share[1];
            boolean missing = false;
            for (int i : columns) {
                if (i >= before.length || i >= after.length) {
                    missing = true;
                }
            }
            if (missing) {
                continue;
            }
            long moved = 0;
            for (int i : columns) {
                moved += after[i] - before[i];
            }
            if (moved < 0) {
                return new LinkedHashMap<>();
            }
            out.put((String) share[0], round(Math.min(100.0, 100.0 * moved / total), 1));
        }
        return out;
    }

    /** {bytes read, bytes written} since boot over the real disks, or null. */
    static long[] diskCounters(String text) {
        long read = 0;
        long written = 0;
        boolean found = false;
        for (String line : text.split("\n")) {
            String[] fields = line.trim().split("\\s+");
            if (fields.length < 10) {
                continue;
            }
            String name = fields[2];
            if (IO_NOT_A_DISK.matcher(name).find() || IO_PARTITION.matcher(name).matches()) {
                continue;
            }
            try {
                long r = Long.parseLong(fields[5]) * IO_SECTOR;
                long w = Long.parseLong(fields[9]) * IO_SECTOR;
                read += r;
                written += w;
            } catch (NumberFormatException error) {
                continue;
            }
            found = true;
        }
        return found ? new long[] {read, written} : null;
    }

    /** {bytes in, bytes out} since boot over the real interfaces, or null. */
    static long[] netCounters(String text) {
        long rx = 0;
        long tx = 0;
        boolean found = false;
        for (String line : text.split("\n")) {
            int colon = line.indexOf(':');
            if (colon < 0) {
                continue;
            }
            String name = line.substring(0, colon).trim();
            if (name.isEmpty() || NET_NOT_REAL.matcher(name).find()) {
                continue;
            }
            String[] fields = line.substring(colon + 1).trim().split("\\s+");
            if (fields.length < 9) {
                continue;
            }
            try {
                long r = Long.parseLong(fields[0]);
                long t = Long.parseLong(fields[8]);
                rx += r;
                tx += t;
            } catch (NumberFormatException error) {
                continue;
            }
            found = true;
        }
        return found ? new long[] {rx, tx} : null;
    }

    /** Megabytes a second between two byte counters, or null when the pair can't say. */
    static Double rateMbs(Long before, Long after, double seconds) {
        if (before == null || after == null || seconds <= 0 || seconds > IO_MAX_PAIR_SECONDS) {
            return null;
        }
        long moved = after - before;
        if (moved < 0) {
            return null;
        }
        return round(moved / seconds / MB, 1);
    }

    /** How busy the machine was between two {busy, total} readings, or null. */
    static Double cpuPercent(long[] before, long[] after) {
        if (before == null || after == null) {
            return null;
        }
        long busy = after[0] - before[0];
        long total = after[1] - before[1];
        if (total <= 0 || busy < 0) {
            return null;
        }
        return round(Math.min(100.0, 100.0 * busy / total), 1);
    }

    /** MemTotal/MemAvailable/Swap from /proc/meminfo, in whole megabytes; used is total - MemAvailable. */
    static Map<String, Object> memoryMb(String text) {
        Map<String, Long> values = new LinkedHashMap<>();
        for (String line : text.split("\n")) {
            int colon = line.indexOf(':');
            if (colon < 0) {
                continue;
            }
            String[] fields = line.substring(colon + 1).trim().split("\\s+");
            if (fields.length == 0 || fields[0].isEmpty()) {
                continue;
            }
            try {
                values.put(line.substring(0, colon), Long.parseLong(fields[0]) / 1024);
            } catch (NumberFormatException error) {
                // not a number
            }
        }
        Map<String, Object> out = new LinkedHashMap<>();
        if (values.containsKey("MemTotal")) {
            out.put("mem_total_mb", values.get("MemTotal"));
            if (values.containsKey("MemAvailable")) {
                out.put("mem_used_mb", Math.max(0, values.get("MemTotal") - values.get("MemAvailable")));
            }
        }
        if (values.containsKey("SwapTotal")) {
            out.put("swap_total_mb", values.get("SwapTotal"));
            if (values.containsKey("SwapFree")) {
                out.put("swap_used_mb", Math.max(0, values.get("SwapTotal") - values.get("SwapFree")));
            }
        }
        return out;
    }

    /**
     * The real disks behind /proc/mounts, one per device under its shortest
     * mount point, which has to be a directory (Docker bind-mounts single
     * files). Off Linux, the file systems the JVM lists.
     */
    static List<String> mountPoints(String mounts, Predicate<String> isDir) {
        if (mounts == null || mounts.isEmpty()) {
            List<String> out = new ArrayList<>();
            for (File root : File.listRoots()) {
                out.add(root.getAbsolutePath());
            }
            if (out.isEmpty()) {
                out.add(Paths.get("").toAbsolutePath().getRoot().toString());
            }
            return out;
        }
        Map<String, String> dirs = new LinkedHashMap<>();
        Map<String, String> any = new LinkedHashMap<>();
        for (String line : mounts.split("\n")) {
            String[] fields = line.trim().split("\\s+");
            if (fields.length < 3) {
                continue;
            }
            String device = fields[0];
            String mount = fields[1].replace("\\040", " ");
            String type = fields[2];
            if (!FSTYPES.contains(type) || !mount.startsWith("/")) {
                continue;
            }
            if (!any.containsKey(device) || mount.length() < any.get(device).length()) {
                any.put(device, mount);
            }
            boolean confirmed;
            try {
                confirmed = isDir.test(mount);
            } catch (RuntimeException error) {
                confirmed = false;
            }
            if (confirmed && (!dirs.containsKey(device) || mount.length() < dirs.get(device).length())) {
                dirs.put(device, mount);
            }
        }
        TreeSet<String> out = new TreeSet<>();
        for (Map.Entry<String, String> entry : any.entrySet()) {
            out.add(dirs.getOrDefault(entry.getKey(), entry.getValue()));
        }
        return new ArrayList<>(out);
    }

    /** {total, unallocated, usable} bytes of the file system holding a path, or null. */
    interface Space {
        long[] of(String mount) throws IOException;
    }

    static final Space FILE_STORES = mount -> {
        FileStore store = Files.getFileStore(Paths.get(mount));
        return new long[] {store.getTotalSpace(), store.getUnallocatedSpace(), store.getUsableSpace()};
    };

    /**
     * Both figures are df's: used is total minus free, and total is used plus
     * what's available to us, so used/total is the percentage df prints. Two
     * mounts with the same size and free bytes are one file system.
     */
    static List<Map<String, Object>> diskRows(List<String> points, Space space) {
        Set<String> seen = new HashSet<>();
        List<Map<String, Object>> rows = new ArrayList<>();
        for (String mount : points) {
            long[] st;
            try {
                st = space.of(mount);
            } catch (IOException | RuntimeException error) {
                continue;
            }
            if (st == null || st[0] <= 0) {
                continue;
            }
            long used = Math.max(0, st[0] - st[1]);
            long total = used + st[2];
            if (total / MB < MIN_DISK_MB) {
                continue;
            }
            if (!seen.add(total + "/" + used)) {
                continue;
            }
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("mount", mount);
            row.put("total_mb", total / MB);
            row.put("used_mb", used / MB);
            rows.add(row);
            if (rows.size() >= MAX_DISKS) {
                break;
            }
        }
        return rows;
    }

    static Long hostUptime(String text) {
        try {
            return (long) Double.parseDouble(text.trim().split("\\s+")[0]);
        } catch (RuntimeException error) {
            return null;
        }
    }

    static Map<String, Object> loadAverage(String text) {
        Map<String, Object> out = new LinkedHashMap<>();
        String[] fields = text.trim().split("\\s+");
        if (fields.length >= 3) {
            try {
                double one = Double.parseDouble(fields[0]);
                double five = Double.parseDouble(fields[1]);
                double fifteen = Double.parseDouble(fields[2]);
                out.put("load1", round(one, 2));
                out.put("load5", round(five, 2));
                out.put("load15", round(fifteen, 2));
                return out;
            } catch (NumberFormatException error) {
                // below
            }
        }
        double one = ManagementFactory.getOperatingSystemMXBean().getSystemLoadAverage();
        if (one >= 0) {
            out.put("load1", round(one, 2));
        }
        return out;
    }

    static Long processRssMb(String text) {
        for (String line : text.split("\n")) {
            if (line.startsWith("VmRSS:")) {
                String[] fields = line.trim().split("\\s+");
                if (fields.length >= 2) {
                    try {
                        return Math.max(1, Long.parseLong(fields[1]) / 1024);
                    } catch (NumberFormatException error) {
                        return null;
                    }
                }
            }
        }
        return null;
    }

    /** The JVM's view of the machine, off Linux: com.sun.management, when this JVM has it. */
    @SuppressWarnings("deprecation")
    static void fromMxBean(Map<String, Object> row) {
        try {
            java.lang.management.OperatingSystemMXBean os = ManagementFactory.getOperatingSystemMXBean();
            if (!(os instanceof com.sun.management.OperatingSystemMXBean)) {
                return;
            }
            com.sun.management.OperatingSystemMXBean sun = (com.sun.management.OperatingSystemMXBean) os;
            // Since the last call: one a minute makes it the minute's average.
            double load = sun.getSystemCpuLoad();
            if (load >= 0 && !Double.isNaN(load)) {
                row.put("cpu_pct", round(Math.min(100.0, load * 100), 1));
            }
            long total = sun.getTotalPhysicalMemorySize();
            if (total > 0) {
                row.put("mem_total_mb", total / MB);
                // Windows' free memory is what's available (cache included); elsewhere it isn't, so used is left out.
                if (System.getProperty("os.name", "").toLowerCase().startsWith("windows")) {
                    row.put("mem_used_mb", Math.max(0, (total - sun.getFreePhysicalMemorySize()) / MB));
                }
            }
            long swap = sun.getTotalSwapSpaceSize();
            if (swap > 0) {
                row.put("swap_total_mb", swap / MB);
                row.put("swap_used_mb", Math.max(0, (swap - sun.getFreeSwapSpaceSize()) / MB));
            }
        } catch (Throwable unavailable) {
            // not this JVM
        }
    }

    private final Core core;
    final String serverName;
    final String runtime;
    private final TreeMap<String, Map<String, Object>> rows = new TreeMap<>();
    private volatile double every = EVERY;
    private volatile boolean enabled = true;
    private long[] lastCpu;
    private long[] lastDisk;
    private long[] lastNet;
    private double lastAt;
    /** The limits pass: the cgroup is found once, its counters and the listen-queue count diffed sample to sample. */
    private final Limits.Cgroup cgroup;
    private Limits.Reading lastCgroup;
    private Double lastOverflows;
    private Long lastGcMs;
    /** This process among others of the same name (several JVMs on one server_name): a read tells siblings from resent copies. */
    final String procKey;
    /** The most requests in progress at once since the last sample, from Server speed's timing; null until it has timed one. */
    private volatile java.util.function.Supplier<Long> inflightPeak = () -> null;
    private final Periodic sampler;
    private final Periodic job;

    Resources(Core core, String serverName) {
        this.core = core;
        String name = serverName == null || serverName.isEmpty() ? Hosts.hostName() : serverName;
        this.serverName = name.length() > 100 ? name.substring(0, 100) : name;
        this.runtime = Core.runtime();
        this.lastCpu = cpuFields(readText("/proc/stat"));
        this.lastDisk = diskCounters(readText("/proc/diskstats"));
        this.lastNet = netCounters(readText("/proc/net/dev"));
        this.lastAt = System.currentTimeMillis() / 1000.0;
        this.cgroup = Limits.findCgroup(Resources::readText);
        this.lastCgroup = Limits.cgroupReading(cgroup, Resources::readText);
        this.lastOverflows = Limits.listenOverflows(readText("/proc/net/netstat"));
        this.lastGcMs = Limits.gcTotalMs();
        byte[] key = new byte[6];
        new java.security.SecureRandom().nextBytes(key);
        StringBuilder hex = new StringBuilder();
        for (byte b : key) {
            hex.append(String.format("%02x", b & 0xff));
        }
        this.procKey = hex.toString();
        if (!LINUX) {
            fromMxBean(new LinkedHashMap<>()); // the first CPU reading starts its interval
        }
        this.sampler = core.valid ? core.every(this::sampleJob, SAMPLE_EVERY) : null;
        this.job = core.valid ? core.every(this::report, EVERY) : null;
    }

    /** Takes one sample, covering the time since the last one. */
    synchronized Map<String, Object> sample() {
        double at = System.currentTimeMillis() / 1000.0;
        String stat = readText("/proc/stat");
        long[] cpu = cpuFields(stat);
        long[] disk = diskCounters(readText("/proc/diskstats"));
        long[] net = netCounters(readText("/proc/net/dev"));
        Double percent = cpuPercent(lastCpu == null ? null : cpuTimesOf(lastCpu), cpu == null ? null : cpuTimesOf(cpu));
        double elapsed = at - lastAt;
        // The minute the interval started in, not the one it ended in.
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("minute", Instant.ofEpochSecond((long) (lastAt / 60) * 60).toString());
        row.put("proc_key", procKey);
        Map<String, Object> shares = cpuShares(lastCpu, cpu);
        Map<String, Object> rates = new LinkedHashMap<>();
        if (lastDisk != null && disk != null) {
            rates.put("disk_read_mbs", rateMbs(lastDisk[0], disk[0], elapsed));
            rates.put("disk_write_mbs", rateMbs(lastDisk[1], disk[1], elapsed));
        }
        if (lastNet != null && net != null) {
            rates.put("net_rx_mbs", rateMbs(lastNet[0], net[0], elapsed));
            rates.put("net_tx_mbs", rateMbs(lastNet[1], net[1], elapsed));
        }
        lastCpu = cpu;
        lastDisk = disk;
        lastNet = net;
        lastAt = at;
        row.putAll(shares);
        rates.forEach((key, value) -> {
            if (value != null) {
                row.put(key, value);
            }
        });
        String meminfo = readText("/proc/meminfo");
        if (cpu != null || !meminfo.isEmpty()) {
            if (percent != null && elapsed >= MIN_CPU_SECONDS) {
                row.put("cpu_pct", percent);
            }
            int cores = cpuCount(stat);
            row.put("cpu_cores", cores > 0 ? cores : Runtime.getRuntime().availableProcessors());
            row.putAll(loadAverage(readText("/proc/loadavg")));
            row.putAll(memoryMb(meminfo));
        } else {
            row.put("cpu_cores", Runtime.getRuntime().availableProcessors());
            row.putAll(loadAverage(""));
            fromMxBean(row);
        }
        List<Map<String, Object>> disks = diskRows(mountPoints(readText("/proc/mounts"), mount -> Files.isDirectory(Paths.get(mount))), FILE_STORES);
        if (!disks.isEmpty()) {
            row.put("disks", disks);
        }
        Long rss = processRssMb(readText("/proc/self/status"));
        if (rss != null) {
            row.put("proc_rss_mb", rss);
        }
        Long uptime = hostUptime(readText("/proc/uptime"));
        if (uptime != null) {
            row.put("host_uptime_s", uptime);
        }
        row.putAll(limitsRow(row));
        synchronized (rows) {
            if (!enabled) {
                // Off in the dashboard: only the newest minute is kept, as the
                // one row that asks the collector now and then whether it is back on.
                rows.clear();
            }
            // Two samples starting in one minute (the timer drifted): the newer
            // row stands, carrying the older one's counts and peak, which are
            // events in its interval and would otherwise be lost.
            Map<String, Object> stored = row;
            Map<String, Object> earlier = rows.get((String) row.get("minute"));
            if (earlier != null) {
                stored = new LinkedHashMap<>(row);
                carryCounts(earlier, stored);
            }
            rows.put((String) row.get("minute"), stored);
            while (rows.size() > MAX_ROWS) {
                rows.pollFirstEntry();
            }
        }
        return row;
    }

    static final String[] COUNTS = {"oom_kills", "listen_drops", "gc_ms"};

    /** The limits pass's counts in earlier added into row, and the higher of the two peaks. */
    static void carryCounts(Map<String, Object> earlier, Map<String, Object> row) {
        for (String field : COUNTS) {
            Object before = earlier.get(field);
            if (!(before instanceof Number)) {
                continue;
            }
            Object now = row.get(field);
            if (before instanceof Double || now instanceof Double) {
                row.put(field, ((Number) before).doubleValue() + (now instanceof Number ? ((Number) now).doubleValue() : 0));
            } else {
                row.put(field, ((Number) before).longValue() + (now instanceof Number ? ((Number) now).longValue() : 0));
            }
        }
        Object peak = earlier.get("inflight_peak");
        Object now = row.get("inflight_peak");
        if (peak instanceof Number && (!(now instanceof Number) || ((Number) peak).longValue() > ((Number) now).longValue())) {
            row.put("inflight_peak", ((Number) peak).longValue());
        }
    }

    /** The performance module's peak of requests in progress (Platform wires it). */
    void useInflight(java.util.function.Supplier<Long> peak) {
        inflightPeak = peak == null ? () -> null : peak;
    }

    /** The limits pass for one sample: caps and counters diffed against the previous sample's, the rest read once. */
    private Map<String, Object> limitsRow(Map<String, Object> row) {
        Map<String, Object> out = new LinkedHashMap<>();
        Long procUptime = Limits.uptimeSeconds();
        if (procUptime != null) {
            out.put("proc_uptime_s", procUptime);
        }
        Limits.Reading reading = Limits.cgroupReading(cgroup, Resources::readText);
        Object total = row.get("mem_total_mb");
        Object cores = row.get("cpu_cores");
        out.putAll(Limits.cgroupFields(lastCgroup, reading, total instanceof Number ? ((Number) total).longValue() : null,
                cores instanceof Number ? ((Number) cores).intValue() : null));
        lastCgroup = reading;
        out.putAll(Limits.pressureFields(Resources::readText));
        Double overflows = Limits.listenOverflows(readText("/proc/net/netstat"));
        Double drops = Limits.countSince(lastOverflows, overflows);
        if (drops != null) {
            out.put("listen_drops", drops.longValue());
        }
        lastOverflows = overflows;
        Double conntrack = Limits.conntrackPct(Resources::readText);
        if (conntrack != null) {
            out.put("conntrack_pct", conntrack);
        }
        out.putAll(Limits.fileFields(Resources::readText, Limits.openFiles()));
        out.putAll(Limits.heapFields());
        Long gcMs = Limits.gcTotalMs();
        if (lastGcMs != null && gcMs != null && gcMs >= lastGcMs) {
            out.put("gc_ms", (double) (gcMs - lastGcMs));
        }
        lastGcMs = gcMs;
        try {
            Long peak = inflightPeak.get();
            if (peak != null && peak >= 0) {
                out.put("inflight_peak", peak);
            }
        } catch (RuntimeException unknown) {
            // left out
        }
        return out;
    }

    private double sampleJob() {
        sample();
        return SAMPLE_EVERY;
    }

    /** Sends what's buffered; rows are kept only when the collector couldn't take them and retrying may work. */
    boolean flush() {
        List<String> minutes;
        List<Map<String, Object>> batch;
        synchronized (rows) {
            minutes = new ArrayList<>(rows.keySet());
            batch = new ArrayList<>(rows.values());
        }
        if (batch.isEmpty()) {
            return true;
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("site_id", core.siteId);
        body.put("server_name", serverName);
        body.put("runtime", runtime);
        body.put("rows", batch);
        Core.Response res = core.postBearer("resources", "/events/resources", body);
        if (res == null) {
            return false;
        }
        if (!res.ok()) {
            if (res.status >= 500) {
                return false;
            }
            drop(minutes);
            return true;
        }
        Map<String, Object> answer = Json.map(res.json());
        if (answer != null) {
            long given = Json.whole(answer.get("every"), 0);
            if (given > 0) {
                every = Math.max(RETRY_EVERY, given);
            }
            enabled = !Boolean.FALSE.equals(answer.get("enabled"));
        }
        drop(minutes);
        return true;
    }

    private void drop(List<String> minutes) {
        synchronized (rows) {
            for (String minute : minutes) {
                rows.remove(minute);
            }
        }
    }

    double report() {
        if (!core.isOn("resources")) {
            synchronized (rows) {
                rows.clear();
            }
            return Math.max(OFF_EVERY, every);
        }
        boolean sent = flush();
        if (!enabled) {
            return Math.max(OFF_EVERY, every);
        }
        return sent ? every : RETRY_EVERY;
    }

    void close() {
        if (sampler != null) {
            sampler.stop(core.stopWait());
        }
        if (job != null) {
            job.stop(core.stopWait());
        }
        if (core.isOn("resources") && enabled) {
            flush();
        }
    }
}
