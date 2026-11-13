package com.sitegoose.analytics;

import java.io.IOException;
import java.lang.management.GarbageCollectorMXBean;
import java.lang.management.ManagementFactory;
import java.lang.management.MemoryUsage;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * How close the app is to a wall, for the resources module
 * (sdk/protocols/resources.md, "Limits"): its container's own caps, the
 * machine's waiting time, connections refused before the app saw them, and
 * the process's open files, heap and garbage collection. A port of the Node
 * package's lib/limits.js.
 *
 * <p>Inside Docker or Kubernetes /proc/meminfo is the host's, so memory reads
 * 40% while the container is a few megabytes from being killed: the cgroup's
 * files are the limits the kernel actually enforces. Same rule as the rest of
 * the module: a figure this machine won't give is left out of the row, never
 * sent as a zero. Every reader here gets "" for a file that isn't there,
 * which on anything but Linux is all of them.
 */
final class Limits {
    private Limits() {
    }

    static final long MB = 1024 * 1024;
    /** cgroup v1 says "no limit" with the largest page-aligned 64-bit number; v2 says "max". Nothing this size is a cap. */
    static final double NO_LIMIT_BYTES = Math.pow(2, 62);
    private static final Pattern SPACES = Pattern.compile("\\s+");
    private static final Pattern PSI_SOME = Pattern.compile("(?m)^some\\b[^\\n]*\\bavg60=([\\d.]+)");
    private static final Pattern FD_LIMIT = Pattern.compile("(?m)^Max open files\\s+(\\S+)");

    /** A number from a file holding one, or null for a missing or unreadable one (never an invented 0). */
    static Double num(String text) {
        String trimmed = text == null ? "" : text.trim();
        if (trimmed.isEmpty()) {
            return null;
        }
        try {
            double value = Double.parseDouble(trimmed);
            return Double.isFinite(value) ? value : null;
        } catch (NumberFormatException notOne) {
            return null;
        }
    }

    /** "name value" lines (memory.stat, cpu.stat, memory.events) as numbers. */
    static Map<String, Double> keyValues(String text) {
        Map<String, Double> out = new HashMap<>();
        for (String line : (text == null ? "" : text).split("\n")) {
            String[] parts = SPACES.split(line.trim());
            if (parts.length >= 2 && !parts[0].isEmpty()) {
                Double n = num(parts[1]);
                if (n != null) {
                    out.put(parts[0], n);
                }
            }
        }
        return out;
    }

    /** Where this process's cgroup files are. */
    static final class Cgroup {
        final int version;
        final String memory;
        final String cpu;

        Cgroup(int version, String memory, String cpu) {
            this.version = version;
            this.memory = memory;
            this.cpu = cpu;
        }
    }

    /** /proc/self/cgroup: {v2 path, v1 memory path, v1 cpu path}, each null when not listed. */
    static String[] cgroupPaths(String text) {
        String[] out = new String[3];
        for (String line : (text == null ? "" : text).split("\n")) {
            int first = line.indexOf(':');
            int second = first < 0 ? -1 : line.indexOf(':', first + 1);
            if (first < 0 || second < 0) {
                continue;
            }
            String id = line.substring(0, first);
            String controllers = line.substring(first + 1, second);
            String at = line.substring(second + 1).trim();
            if (at.isEmpty()) {
                continue;
            }
            List<String> names = Arrays.asList(controllers.split(","));
            if ("0".equals(id) && controllers.replace(",", "").isEmpty()) {
                out[0] = at;
            }
            if (names.contains("memory")) {
                out[1] = at;
            }
            if (names.contains("cpu")) {
                out[2] = at;
            }
        }
        return out;
    }

    /** The directory under base for at holding one of probes: under the path first, then the mount itself. */
    private static String under(String base, String at, String[] probes, Function<String, String> read) {
        String[] dirs = at != null && !"/".equals(at) ? new String[] {base + at, base} : new String[] {base};
        for (String dir : dirs) {
            for (String probe : probes) {
                if (!read.apply(dir + "/" + probe).isEmpty()) {
                    return dir;
                }
            }
        }
        return null;
    }

    /**
     * Where this process's cgroup files are, or null. v2 needs the memory or
     * cpu controller's own files, not just the directory: a hybrid machine
     * lists a v2 path with no controllers in it while the limits live in v1.
     */
    static Cgroup findCgroup(Function<String, String> read) {
        String[] paths = cgroupPaths(read.apply("/proc/self/cgroup"));
        if (paths[0] != null) {
            String dir = under("/sys/fs/cgroup", paths[0], new String[] {"memory.current", "cpu.max"}, read);
            if (dir != null) {
                return new Cgroup(2, dir, dir);
            }
        }
        String memory = paths[1] != null ? under("/sys/fs/cgroup/memory", paths[1], new String[] {"memory.usage_in_bytes"}, read) : null;
        String cpu = paths[2] != null ? under("/sys/fs/cgroup/cpu", paths[2], new String[] {"cpu.cfs_quota_us"}, read) : null;
        return memory != null || cpu != null ? new Cgroup(1, memory, cpu) : null;
    }

    /** One reading of the cgroup's caps and counters, in bytes and raw counts; each null when not given. */
    static final class Reading {
        Double memCap;
        Double memUsed;
        Double cpuCores;
        Double periods;
        Double throttled;
        Double oom;
    }

    static Reading cgroupReading(Cgroup cg, Function<String, String> read) {
        if (cg == null) {
            return null;
        }
        Reading out = new Reading();
        if (cg.version == 2) {
            String max = read.apply(cg.memory + "/memory.max").trim();
            out.memCap = "max".equals(max) ? null : num(max);
            Double current = num(read.apply(cg.memory + "/memory.current"));
            // The working set: page cache counts against the cgroup too, so
            // memory.current sits near the cap on a healthy container that reads
            // files. Less inactive_file is what Docker and the kubelet report.
            Map<String, Double> stat = keyValues(read.apply(cg.memory + "/memory.stat"));
            if (current != null) {
                out.memUsed = Math.max(0, current - stat.getOrDefault("inactive_file", 0.0));
            }
            out.oom = keyValues(read.apply(cg.memory + "/memory.events")).get("oom_kill");
            String[] cpuMax = SPACES.split(read.apply(cg.cpu + "/cpu.max").trim());
            if (cpuMax.length >= 2 && !"max".equals(cpuMax[0])) {
                Double quota = num(cpuMax[0]);
                Double period = num(cpuMax[1]);
                if (quota != null && period != null && quota > 0 && period > 0) {
                    out.cpuCores = quota / period;
                }
            }
            Map<String, Double> cpu = keyValues(read.apply(cg.cpu + "/cpu.stat"));
            out.periods = cpu.get("nr_periods");
            out.throttled = cpu.get("nr_throttled");
            return out;
        }
        if (cg.memory != null) {
            out.memCap = num(read.apply(cg.memory + "/memory.limit_in_bytes"));
            Double usage = num(read.apply(cg.memory + "/memory.usage_in_bytes"));
            Map<String, Double> stat = keyValues(read.apply(cg.memory + "/memory.stat"));
            if (usage != null) {
                out.memUsed = Math.max(0, usage - stat.getOrDefault("total_inactive_file", 0.0));
            }
            // Kernels from 4.13 carry the count here.
            out.oom = keyValues(read.apply(cg.memory + "/memory.oom_control")).get("oom_kill");
        }
        if (cg.cpu != null) {
            Double quota = num(read.apply(cg.cpu + "/cpu.cfs_quota_us"));
            Double period = num(read.apply(cg.cpu + "/cpu.cfs_period_us"));
            if (quota != null && period != null && quota > 0 && period > 0) {
                out.cpuCores = quota / period;
            }
            Map<String, Double> cpu = keyValues(read.apply(cg.cpu + "/cpu.stat"));
            out.periods = cpu.get("nr_periods");
            out.throttled = cpu.get("nr_throttled");
        }
        return out;
    }

    /**
     * How much a counter moved between two readings, or null: no pair, or it
     * went down, which is a reset and not a negative count. Unlike a rate a
     * count is never dropped for the pair being far apart: a kill is a kill.
     */
    static Double countSince(Double before, Double after) {
        if (before == null || after == null) {
            return null;
        }
        return after >= before ? after - before : null;
    }

    private static double round(double value, int places) {
        double scale = Math.pow(10, places);
        return Math.round(value * scale) / scale;
    }

    /** A whole count as the row carries it. */
    private static Long whole(double value) {
        return Long.valueOf((long) Math.floor(value));
    }

    /**
     * The row's cgroup fields from two readings. A cap at or above what the
     * machine itself has isn't one (a systemd slice with no MemoryMax, or a
     * container allowed more cores than the host), so neither half is sent.
     */
    static Map<String, Object> cgroupFields(Reading before, Reading after, Long memTotalMb, Integer cores) {
        Map<String, Object> out = new LinkedHashMap<>();
        if (after == null) {
            return out;
        }
        Long capMb = after.memCap != null && after.memCap > 0 && after.memCap < NO_LIMIT_BYTES ? whole(after.memCap / MB) : null;
        if (capMb != null && capMb > 0 && !(memTotalMb != null && memTotalMb > 0 && capMb >= memTotalMb) && after.memUsed != null) {
            out.put("limit_mem_mb", capMb);
            out.put("limit_mem_used_mb", Math.min(capMb, whole(after.memUsed / MB)));
        }
        if (after.cpuCores != null && after.cpuCores > 0 && !(cores != null && cores > 0 && after.cpuCores >= cores)) {
            out.put("limit_cpu_cores", round(after.cpuCores, 2));
        }
        // Periods only pass while a quota is set, so no cap means nothing sent.
        Double periods = countSince(before == null ? null : before.periods, after.periods);
        Double throttled = countSince(before == null ? null : before.throttled, after.throttled);
        if (periods != null && periods > 0 && throttled != null) {
            out.put("cpu_throttled_pct", round(Math.min(100, 100 * throttled / periods), 1));
        }
        // Kills of other processes in this cgroup: this process's own kill
        // can't be reported by it (see the protocol).
        Double oom = countSince(before == null ? null : before.oom, after.oom);
        if (oom != null) {
            out.put("oom_kills", whole(oom));
        }
        return out;
    }

    /** /proc/pressure/(resource)'s "some" line, avg60: the share of the last minute in which a task was waiting. */
    static Double pressureSome(String text) {
        Matcher match = PSI_SOME.matcher(text == null ? "" : text);
        if (!match.find()) {
            return null;
        }
        Double value = num(match.group(1));
        return value == null ? null : round(Math.min(100, value), 1);
    }

    static Map<String, Object> pressureFields(Function<String, String> read) {
        Map<String, Object> out = new LinkedHashMap<>();
        String[][] files = {{"psi_cpu_pct", "cpu"}, {"psi_mem_pct", "memory"}, {"psi_io_pct", "io"}};
        for (String[] pair : files) {
            Double value = pressureSome(read.apply("/proc/pressure/" + pair[1]));
            if (value != null) {
                out.put(pair[0], value);
            }
        }
        return out;
    }

    /** TcpExt ListenOverflows from /proc/net/netstat: connections refused since boot, the accept queue full. */
    static Double listenOverflows(String text) {
        String[] lines = (text == null ? "" : text).split("\n");
        for (int i = 0; i + 1 < lines.length; i++) {
            if (!lines[i].startsWith("TcpExt:") || !lines[i + 1].startsWith("TcpExt:")) {
                continue;
            }
            List<String> names = Arrays.asList(SPACES.split(lines[i].trim()));
            int at = names.indexOf("ListenOverflows");
            String[] values = SPACES.split(lines[i + 1].trim());
            return at > 0 && at < values.length ? num(values[at]) : null;
        }
        return null;
    }

    /** How full the connection-tracking table is; only where the firewall loaded it. */
    static Double conntrackPct(Function<String, String> read) {
        Double count = num(read.apply("/proc/sys/net/netfilter/nf_conntrack_count"));
        Double max = num(read.apply("/proc/sys/net/netfilter/nf_conntrack_max"));
        return count != null && max != null && max > 0 ? round(Math.min(100, 100 * count / max), 1) : null;
    }

    /** The soft "Max open files" from /proc/self/limits, or null when unlimited or not there. */
    static Long fdLimit(String text) {
        Matcher match = FD_LIMIT.matcher(text == null ? "" : text);
        if (!match.find()) {
            return null;
        }
        Double value = num(match.group(1));
        return value == null ? null : whole(value);
    }

    /** Open descriptors of this process, less the one listing them takes; null without /proc. */
    static Long openFiles() {
        Path fd = Paths.get("/proc/self/fd");
        if (!Files.isDirectory(fd)) {
            return null;
        }
        long count = 0;
        try (DirectoryStream<Path> entries = Files.newDirectoryStream(fd)) {
            for (Path ignored : entries) {
                count++;
            }
        } catch (IOException | RuntimeException unreadable) {
            return null;
        }
        return Math.max(0, count - 1);
    }

    static Map<String, Object> fileFields(Function<String, String> read, Long used) {
        Map<String, Object> out = new LinkedHashMap<>();
        Long max = fdLimit(read.apply("/proc/self/limits"));
        if (used != null) {
            out.put("fds_used", max != null && max > 0 ? Math.min(used, max) : used);
        }
        if (max != null && max > 0) {
            out.put("fds_max", max);
        }
        return out;
    }

    /** The JVM's heap against the most it may grow to (-Xmx, or the JVM's default), a different wall from the container's. */
    static Map<String, Object> heapFields(long used, long max) {
        Map<String, Object> out = new LinkedHashMap<>();
        // max is -1 when undefined, Long.MAX_VALUE in effect when there is none.
        if (used <= 0 || max <= 0 || max == Long.MAX_VALUE) {
            return out;
        }
        out.put("heap_used_mb", used / MB);
        out.put("heap_max_mb", max / MB);
        return out;
    }

    static Map<String, Object> heapFields() {
        try {
            MemoryUsage heap = ManagementFactory.getMemoryMXBean().getHeapMemoryUsage();
            return heapFields(heap.getUsed(), heap.getMax());
        } catch (RuntimeException | LinkageError unavailable) {
            return new LinkedHashMap<>();
        }
    }

    /**
     * Milliseconds the app was stopped for garbage collection since the JVM
     * started, every collector summed; null when none says. The concurrent
     * collectors' beans ("G1 Concurrent GC", "ZGC Cycles", "Shenandoah
     * Cycles") count work done beside the app, which would make a healthy
     * minute look like one spent collecting: only their pauses count.
     */
    static Long gcTotalMs() {
        try {
            List<String> names = new java.util.ArrayList<>();
            List<Long> times = new java.util.ArrayList<>();
            for (GarbageCollectorMXBean gc : ManagementFactory.getGarbageCollectorMXBeans()) {
                names.add(gc.getName());
                times.add(gc.getCollectionTime());
            }
            return gcPauseMs(names, times);
        } catch (RuntimeException | LinkageError unavailable) {
            return null;
        }
    }

    static Long gcPauseMs(List<String> names, List<Long> times) {
        long total = 0;
        boolean any = false;
        for (int i = 0; i < names.size(); i++) {
            String name = String.valueOf(names.get(i));
            long ms = times.get(i);
            if (ms >= 0 && !name.contains("Concurrent") && !name.contains("Cycles")) {
                total += ms;
                any = true;
            }
        }
        return any ? total : null;
    }

    /** How long this JVM has run. */
    static Long uptimeSeconds() {
        try {
            return ManagementFactory.getRuntimeMXBean().getUptime() / 1000;
        } catch (RuntimeException | LinkageError unavailable) {
            return null;
        }
    }
}
