using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace SiteGoose;

/// <summary>How the machine is doing (sdk/protocols/resources.md): CPU, load,
/// memory, swap and disks, sampled every minute and sent to POST
/// /events/resources every few minutes.
///
/// Nothing is guessed. A reading this machine won't give us is left out of the
/// row, never sent as a zero. Linux reads /proc as the Python package and the
/// agent do; Windows asks the system (GetSystemTimes, GlobalMemoryStatusEx,
/// the fixed drives, the network interfaces' counters) and has no load average,
/// swap, iowait or steal to report, so those are left out there.</summary>
internal sealed class Resources
{
    // Keep in step with the collector (expresscollect/Analytics/resources.js) and the agent.
    public const int SampleEvery = 60;
    public const int EveryDefault = 5 * 60;
    public const int RetryEvery = 60;
    public const int OffEvery = 600;
    public const int MaxRows = 500;
    public const int MaxDisks = 20;
    public const long MinDiskMb = 1024;
    public const double MinCpuSeconds = 1.0;
    public const long Mb = 1024 * 1024;
    // Sectors in /proc/diskstats are always 512 bytes.
    public const long IoSector = 512;
    // Two readings further apart than this say nothing about this minute.
    public const double IoMaxPairSeconds = 300;

    // Real on-disk filesystems only: overlay is here so a containerised app still reports something sensible.
    internal static readonly HashSet<string> FsTypes = new(StringComparer.Ordinal)
    {
        "ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs", "jfs", "reiserfs", "ufs", "vfat", "exfat", "ntfs", "ntfs3", "overlay", "apfs", "hfs",
    };

    private static readonly Regex IoNotADisk = new("^(?:loop|ram|zram|sr|fd|dm-|md[0-9])", RegexOptions.CultureInvariant);
    private static readonly Regex IoPartition = new("^(?:(?:sd|vd|xvd|hd)[a-z]+[0-9]+|(?:nvme[0-9]+n[0-9]+|mmcblk[0-9]+)p[0-9]+)$", RegexOptions.CultureInvariant);
    private static readonly Regex NetNotReal = new("^(?:lo|veth|docker|br-|virbr|tap|tun|vnet)", RegexOptions.CultureInvariant);

    private readonly Core core;
    private readonly object gate = new();
    // minute (ISO) -> row, so a minute sampled twice is kept once.
    private readonly SortedDictionary<string, Dictionary<string, object?>> rows = new(StringComparer.Ordinal);
    private long[]? lastCpu;
    private (long Read, long Written)? lastDisk;
    private (long Rx, long Tx)? lastNet;
    private double lastAt;
    // The limits pass (Limits): the cgroup is found once, its counters, the
    // listen-queue count and the GC's pauses are read every sample and diffed like CPU.
    private readonly Limits.Cgroup? cgroup;
    private Limits.CgroupReading? lastCgroup;
    private double? lastOverflows;
    private double? lastGcMs;
    private readonly DateTime processStarted;

    public Resources(Core core, string? serverName = null)
    {
        this.core = core;
        ServerName = J.Clip(serverName ?? Core.HostName(), 100);
        lastCpu = CpuFields();
        lastDisk = DiskCounters();
        lastNet = NetCounters();
        lastAt = J.UnixNow();
        // This process among others of the same name (several app instances
        // on one machine), so a read can tell siblings from resent copies.
        ProcKey = Convert.ToHexString(System.Security.Cryptography.RandomNumberGenerator.GetBytes(6)).ToLowerInvariant();
        processStarted = DateTime.UtcNow;
        try
        {
            using var self = Process.GetCurrentProcess();
            processStarted = self.StartTime.ToUniversalTime();
        }
        catch (Exception)
        {
        }
        try
        {
            cgroup = Limits.FindCgroup();
            lastCgroup = Limits.ReadCgroup(cgroup);
            lastOverflows = Limits.ListenOverflows(ReadText("/proc/net/netstat"));
            lastGcMs = Limits.GcPauseMs();
        }
        catch (Exception)
        {
        }
        if (core.Valid)
        {
            core.Every(() =>
            {
                Sample();
                return Task.FromResult((double)SampleEvery);
            }, SampleEvery);
            core.Every(ReportAsync, EveryDefault);
        }
    }

    public string ServerName { get; }
    public string Runtime => Core.Runtime;
    public string ProcKey { get; }

    /// <summary>The performance module's peak of requests in progress (Platform wires it).</summary>
    internal Func<long?>? InflightPeak { get; set; }

    public int Every { get; private set; } = EveryDefault;
    public bool Enabled { get; private set; } = true;

    internal int RowCount
    {
        get
        {
            lock (gate) return rows.Count;
        }
    }

    internal static string ReadText(string path, int limit = 65536)
    {
        try
        {
            using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            var buffer = new byte[limit];
            var total = 0;
            int read;
            while (total < limit && (read = stream.Read(buffer, total, limit - total)) > 0) total += read;
            return Encoding.UTF8.GetString(buffer, 0, total);
        }
        catch (Exception)
        {
            return "";
        }
    }

    // ---- Linux (/proc) ----

    /// <summary>The jiffie counters from /proc/stat's first line, or null.
    /// In order: user, nice, system, idle, iowait, irq, softirq, steal.</summary>
    internal static long[]? CpuFieldsOf(string text)
    {
        foreach (var line in text.Split('\n'))
        {
            if (!line.StartsWith("cpu ", StringComparison.Ordinal)) continue;
            var parts = line.Split(' ', StringSplitOptions.RemoveEmptyEntries).Skip(1).ToArray();
            var fields = new long[parts.Length];
            for (var i = 0; i < parts.Length; i++)
            {
                if (!long.TryParse(parts[i], out fields[i])) return null;
            }
            return fields.Length >= 4 ? fields : null;
        }
        return null;
    }

    /// <summary>Every jiffy in the counters once. guest and guest_nice are
    /// already inside user and nice, so they are left out, as psutil and top do.</summary>
    internal static long CpuTotal(long[] fields) => fields.Take(8).Sum();

    internal static (long Busy, long Total) CpuTimesOf(long[] fields)
    {
        var total = CpuTotal(fields);
        var idle = fields[3] + (fields.Length > 4 ? fields[4] : 0);
        return (total - idle, total);
    }

    // user folds nice in, as top adds them together.
    private static readonly (string Name, int[] Columns)[] CpuShareColumns =
    {
        ("cpu_user_pct", new[] { 0, 1 }),
        ("cpu_system_pct", new[] { 2 }),
        ("cpu_iowait_pct", new[] { 4 }),
        ("cpu_steal_pct", new[] { 7 }),
    };

    /// <summary>Where the machine's time went between two /proc/stat readings;
    /// a column the kernel is too old to carry is left out rather than sent as a zero.</summary>
    internal static Dictionary<string, object?> CpuShares(long[]? before, long[]? after)
    {
        var output = new Dictionary<string, object?>();
        if (before == null || after == null) return output;
        var total = CpuTotal(after) - CpuTotal(before);
        if (total <= 0) return output;
        foreach (var (name, columns) in CpuShareColumns)
        {
            if (columns.Any(i => i >= before.Length || i >= after.Length)) continue;
            var moved = columns.Sum(i => after[i] - before[i]);
            if (moved < 0) return new Dictionary<string, object?>();
            output[name] = Math.Round(Math.Min(100.0, 100.0 * moved / total), 1);
        }
        return output;
    }

    /// <summary>(bytes read, bytes written) since boot over the real disks, or null.</summary>
    internal static (long Read, long Written)? DiskCountersOf(string text)
    {
        long read = 0, written = 0;
        var found = false;
        foreach (var line in text.Split('\n'))
        {
            var fields = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (fields.Length < 10) continue;
            var name = fields[2];
            if (IoNotADisk.IsMatch(name) || IoPartition.IsMatch(name)) continue;
            if (!long.TryParse(fields[5], out var r) || !long.TryParse(fields[9], out var w)) continue;
            read += r * IoSector;
            written += w * IoSector;
            found = true;
        }
        return found ? (read, written) : null;
    }

    /// <summary>(bytes in, bytes out) since boot over the real interfaces, or null.</summary>
    internal static (long Rx, long Tx)? NetCountersOf(string text)
    {
        long rx = 0, tx = 0;
        var found = false;
        foreach (var line in text.Split('\n'))
        {
            var colon = line.IndexOf(':');
            if (colon < 0) continue;
            var name = line.Substring(0, colon).Trim();
            if (name.Length == 0 || NetNotReal.IsMatch(name)) continue;
            var fields = line.Substring(colon + 1).Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
            if (fields.Length < 9) continue;
            if (!long.TryParse(fields[0], out var r) || !long.TryParse(fields[8], out var t)) continue;
            rx += r;
            tx += t;
            found = true;
        }
        return found ? (rx, tx) : null;
    }

    /// <summary>Megabytes a second between two byte counters, or null when the
    /// pair can't say: no pair, a reset, no time, or too long a gap.</summary>
    internal static double? RateMbs(long? before, long? after, double seconds)
    {
        if (before == null || after == null) return null;
        if (seconds <= 0 || seconds > IoMaxPairSeconds) return null;
        var moved = after.Value - before.Value;
        if (moved < 0) return null;
        return Math.Round(moved / seconds / Mb, 1);
    }

    internal static double? CpuPercent((long Busy, long Total)? before, (long Busy, long Total)? after)
    {
        if (before == null || after == null) return null;
        var busy = after.Value.Busy - before.Value.Busy;
        var total = after.Value.Total - before.Value.Total;
        if (total <= 0 || busy < 0) return null;
        return Math.Round(Math.Min(100.0, 100.0 * busy / total), 1);
    }

    /// <summary>MemTotal/MemAvailable/Swap from /proc/meminfo, in whole megabytes.
    /// Used is total - MemAvailable, never total - MemFree: page cache is not pressure.</summary>
    internal static Dictionary<string, object?> MemoryMb(string text)
    {
        var values = new Dictionary<string, long>(StringComparer.Ordinal);
        foreach (var line in text.Split('\n'))
        {
            var colon = line.IndexOf(':');
            if (colon < 0) continue;
            var fields = line.Substring(colon + 1).Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (fields.Length == 0 || !long.TryParse(fields[0], out var kb)) continue;
            values[line.Substring(0, colon)] = kb / 1024;
        }
        var output = new Dictionary<string, object?>();
        if (values.TryGetValue("MemTotal", out var total))
        {
            output["mem_total_mb"] = total;
            if (values.TryGetValue("MemAvailable", out var available)) output["mem_used_mb"] = Math.Max(0, total - available);
        }
        if (values.TryGetValue("SwapTotal", out var swap))
        {
            output["swap_total_mb"] = swap;
            if (values.TryGetValue("SwapFree", out var free)) output["swap_used_mb"] = Math.Max(0, swap - free);
        }
        return output;
    }

    /// <summary>The real disks behind /proc/mounts, one per device under its
    /// shortest mount point, so a bind mount isn't a second disk; a mount point
    /// has to be a directory (Docker bind-mounts single files), advisory per
    /// device. Off Linux, the filesystem the app runs from.</summary>
    internal static List<string> MountPoints(string mountsText, Func<string, bool>? isDir = null)
    {
        if (string.IsNullOrEmpty(mountsText)) return new List<string> { Path.GetPathRoot(AppContext.BaseDirectory) ?? "/" };
        isDir ??= Directory.Exists;
        var dirs = new Dictionary<string, string>(StringComparer.Ordinal);
        var any = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var line in mountsText.Split('\n'))
        {
            var fields = line.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (fields.Length < 3) continue;
            var device = fields[0];
            var mount = fields[1].Replace("\\040", " ");
            var fstype = fields[2];
            if (!FsTypes.Contains(fstype) || !mount.StartsWith("/", StringComparison.Ordinal)) continue;
            if (!any.TryGetValue(device, out var shortest) || mount.Length < shortest.Length) any[device] = mount;
            bool confirmed;
            try
            {
                confirmed = isDir(mount);
            }
            catch (Exception)
            {
                confirmed = false;
            }
            if (confirmed && (!dirs.TryGetValue(device, out var best) || mount.Length < best.Length)) dirs[device] = mount;
        }
        return any.Select(p => dirs.TryGetValue(p.Key, out var d) ? d : p.Value).Distinct().OrderBy(m => m, StringComparer.Ordinal).ToList();
    }

    /// <summary>statvfs's figures for one mount: block size, blocks, free, available, files, free files.</summary>
    internal sealed class FsStats
    {
        public long Block;
        public long Blocks;
        public long Free;
        public long Available;
        public long Files;
        public long FreeFiles;
        public bool HasInodes;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct StatVfs64
    {
        public ulong f_bsize;
        public ulong f_frsize;
        public ulong f_blocks;
        public ulong f_bfree;
        public ulong f_bavail;
        public ulong f_files;
        public ulong f_ffree;
        public ulong f_favail;
        public ulong f_fsid;
        public ulong f_flag;
        public ulong f_namemax;
        public int spare0, spare1, spare2, spare3, spare4, spare5;
    }

    [DllImport("libc", EntryPoint = "statvfs", SetLastError = true)]
    private static extern int statvfs(string path, out StatVfs64 buf);

    private static bool statvfsBroken;

    /// <summary>statvfs on 64-bit Linux (glibc and musl share the layout);
    /// elsewhere DriveInfo, which has no inode counts.</summary>
    internal static FsStats? StatFs(string mount)
    {
        if (OperatingSystem.IsLinux() && IntPtr.Size == 8 && !statvfsBroken)
        {
            try
            {
                if (statvfs(mount, out var st) != 0) return null;
                var block = (long)(st.f_frsize != 0 ? st.f_frsize : st.f_bsize);
                return new FsStats
                {
                    Block = block, Blocks = (long)st.f_blocks, Free = (long)st.f_bfree, Available = (long)st.f_bavail,
                    Files = (long)st.f_files, FreeFiles = (long)st.f_ffree, HasInodes = true,
                };
            }
            catch (Exception)
            {
                statvfsBroken = true;
            }
        }
        try
        {
            var drive = new DriveInfo(mount);
            if (!drive.IsReady) return null;
            return new FsStats { Block = 1, Blocks = drive.TotalSize, Free = drive.TotalFreeSpace, Available = drive.AvailableFreeSpace };
        }
        catch (Exception)
        {
            return null;
        }
    }

    /// <summary>Both figures are df's: used is total minus free, and total is
    /// used plus what's available to us. A mount whose size and free space
    /// match an earlier one exactly is the same filesystem behind another device.</summary>
    internal static List<Dictionary<string, object?>> DiskRows(IEnumerable<string> points, Func<string, FsStats?>? stat = null)
    {
        stat ??= StatFs;
        var seen = new HashSet<(long, long)>();
        var output = new List<Dictionary<string, object?>>();
        foreach (var mount in points)
        {
            var st = stat(mount);
            if (st == null || st.Block <= 0 || st.Blocks <= 0) continue;
            var used = Math.Max(0, st.Blocks - st.Free) * st.Block;
            var total = used + st.Available * st.Block;
            var row = new Dictionary<string, object?> { ["mount"] = mount, ["total_mb"] = total / Mb, ["used_mb"] = used / Mb };
            if (total / Mb < MinDiskMb) continue;
            if (!seen.Add((total, used))) continue;
            // A filesystem can refuse a write with gigabytes free once these meet.
            if (st.HasInodes && st.Files > 0)
            {
                row["inodes_total"] = st.Files;
                row["inodes_used"] = Math.Max(0, st.Files - st.FreeFiles);
            }
            output.Add(row);
            if (output.Count >= MaxDisks) break;
        }
        // Inodes are all or nothing across the mounts.
        if (output.Any(r => !r.ContainsKey("inodes_total")))
        {
            foreach (var row in output)
            {
                row.Remove("inodes_total");
                row.Remove("inodes_used");
            }
        }
        return output;
    }

    internal static long? HostUptimeOf(string text)
    {
        var first = text.Split(new[] { ' ', '\n' }, StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
        return first != null && double.TryParse(first, System.Globalization.NumberStyles.Float, System.Globalization.CultureInfo.InvariantCulture, out var s) ? (long)s : null;
    }

    internal static Dictionary<string, object?> LoadAverageOf(string text)
    {
        var parts = text.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var output = new Dictionary<string, object?>();
        if (parts.Length < 3) return output;
        var culture = System.Globalization.CultureInfo.InvariantCulture;
        if (double.TryParse(parts[0], System.Globalization.NumberStyles.Float, culture, out var one) &&
            double.TryParse(parts[1], System.Globalization.NumberStyles.Float, culture, out var five) &&
            double.TryParse(parts[2], System.Globalization.NumberStyles.Float, culture, out var fifteen))
        {
            output["load1"] = Math.Round(one, 2);
            output["load5"] = Math.Round(five, 2);
            output["load15"] = Math.Round(fifteen, 2);
        }
        return output;
    }

    [DllImport("libc", EntryPoint = "getloadavg")]
    private static extern int getloadavg([Out] double[] loadavg, int nelem);

    private static Dictionary<string, object?> LoadAverage()
    {
        if (OperatingSystem.IsLinux()) return LoadAverageOf(ReadText("/proc/loadavg"));
        if (OperatingSystem.IsMacOS() || OperatingSystem.IsFreeBSD())
        {
            try
            {
                var values = new double[3];
                if (getloadavg(values, 3) == 3)
                {
                    return new Dictionary<string, object?> { ["load1"] = Math.Round(values[0], 2), ["load5"] = Math.Round(values[1], 2), ["load15"] = Math.Round(values[2], 2) };
                }
            }
            catch (Exception)
            {
            }
        }
        return new Dictionary<string, object?>();
    }

    // ---- Windows ----

    [StructLayout(LayoutKind.Sequential)]
    private struct FileTime
    {
        public uint Low;
        public uint High;
        public long Value => ((long)High << 32) | Low;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetSystemTimes(out FileTime idle, out FileTime kernel, out FileTime user);

    [StructLayout(LayoutKind.Sequential)]
    private struct MemoryStatusEx
    {
        public uint dwLength;
        public uint dwMemoryLoad;
        public ulong ullTotalPhys;
        public ulong ullAvailPhys;
        public ulong ullTotalPageFile;
        public ulong ullAvailPageFile;
        public ulong ullTotalVirtual;
        public ulong ullAvailVirtual;
        public ulong ullAvailExtendedVirtual;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GlobalMemoryStatusEx(ref MemoryStatusEx buffer);

    /// <summary>The CPU counters as /proc/stat orders them, so one set of maths
    /// serves both: on Windows (user, 0, kernel minus idle, idle), in 100 ns
    /// ticks. No iowait or steal column, so neither is reported there.</summary>
    internal static long[]? CpuFields()
    {
        if (OperatingSystem.IsLinux()) return CpuFieldsOf(ReadText("/proc/stat"));
        if (OperatingSystem.IsWindows())
        {
            try
            {
                if (!GetSystemTimes(out var idle, out var kernel, out var user)) return null;
                return new[] { user.Value, 0, Math.Max(0, kernel.Value - idle.Value), idle.Value };
            }
            catch (Exception)
            {
                return null;
            }
        }
        return null;
    }

    private static (long, long)? DiskCounters() => OperatingSystem.IsLinux() ? DiskCountersOf(ReadText("/proc/diskstats")) : null;

    private static (long, long)? NetCounters()
    {
        if (OperatingSystem.IsLinux()) return NetCountersOf(ReadText("/proc/net/dev"));
        if (!OperatingSystem.IsWindows()) return null;
        try
        {
            long rx = 0, tx = 0;
            var found = false;
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.NetworkInterfaceType == NetworkInterfaceType.Loopback || nic.NetworkInterfaceType == NetworkInterfaceType.Tunnel) continue;
                if (nic.OperationalStatus != OperationalStatus.Up) continue;
                // Hyper-V and container switches carry the guests' traffic, not the site's.
                if (nic.Name.StartsWith("vEthernet", StringComparison.OrdinalIgnoreCase)) continue;
                var stats = nic.GetIPStatistics();
                rx += stats.BytesReceived;
                tx += stats.BytesSent;
                found = true;
            }
            return found ? (rx, tx) : null;
        }
        catch (Exception)
        {
            return null;
        }
    }

    private static Dictionary<string, object?> Memory()
    {
        if (OperatingSystem.IsLinux()) return MemoryMb(ReadText("/proc/meminfo"));
        if (OperatingSystem.IsWindows())
        {
            try
            {
                var status = new MemoryStatusEx { dwLength = (uint)Marshal.SizeOf<MemoryStatusEx>() };
                if (GlobalMemoryStatusEx(ref status))
                {
                    var total = (long)(status.ullTotalPhys / Mb);
                    return new Dictionary<string, object?> { ["mem_total_mb"] = total, ["mem_used_mb"] = Math.Max(0, total - (long)(status.ullAvailPhys / Mb)) };
                }
            }
            catch (Exception)
            {
            }
        }
        return new Dictionary<string, object?>();
    }

    private static List<string> DiskPoints()
    {
        if (OperatingSystem.IsLinux()) return MountPoints(ReadText("/proc/mounts"));
        if (OperatingSystem.IsWindows())
        {
            try
            {
                return DriveInfo.GetDrives().Where(d => d.DriveType == DriveType.Fixed && d.IsReady).Select(d => d.RootDirectory.FullName).ToList();
            }
            catch (Exception)
            {
                return new List<string>();
            }
        }
        return new List<string> { "/" };
    }

    private static long? HostUptime()
    {
        if (OperatingSystem.IsLinux()) return HostUptimeOf(ReadText("/proc/uptime"));
        // TickCount64 counts from boot on Windows; elsewhere it isn't promised to.
        if (OperatingSystem.IsWindows()) return Environment.TickCount64 / 1000;
        return null;
    }

    private static long? ProcessRssMb()
    {
        if (OperatingSystem.IsLinux())
        {
            foreach (var line in ReadText("/proc/self/status").Split('\n'))
            {
                if (!line.StartsWith("VmRSS:", StringComparison.Ordinal)) continue;
                var fields = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                if (fields.Length >= 2 && long.TryParse(fields[1], out var kb)) return Math.Max(1, kb / 1024);
                return null;
            }
        }
        try
        {
            using var self = Process.GetCurrentProcess();
            return Math.Max(1, self.WorkingSet64 / Mb);
        }
        catch (Exception)
        {
            return null;
        }
    }

    /// <summary>Takes one sample, covering the time since the last one.</summary>
    public Dictionary<string, object?> Sample(double? at = null)
    {
        var now = at ?? J.UnixNow();
        var cpu = CpuFields();
        var disk = DiskCounters();
        var net = NetCounters();
        var percent = CpuPercent(lastCpu == null ? null : CpuTimesOf(lastCpu), cpu == null ? null : CpuTimesOf(cpu));
        var elapsed = now - lastAt;
        // The minute the interval started in, not the one it ended in.
        var row = new Dictionary<string, object?> { ["minute"] = J.IsoSeconds((long)Math.Floor(lastAt / 60) * 60) };
        var shares = CpuShares(lastCpu, cpu);
        var rates = new Dictionary<string, double?>();
        if (lastDisk != null && disk != null)
        {
            rates["disk_read_mbs"] = RateMbs(lastDisk.Value.Read, disk.Value.Item1, elapsed);
            rates["disk_write_mbs"] = RateMbs(lastDisk.Value.Written, disk.Value.Item2, elapsed);
        }
        if (lastNet != null && net != null)
        {
            rates["net_rx_mbs"] = RateMbs(lastNet.Value.Rx, net.Value.Item1, elapsed);
            rates["net_tx_mbs"] = RateMbs(lastNet.Value.Tx, net.Value.Item2, elapsed);
        }
        lastCpu = cpu;
        lastDisk = disk;
        lastNet = net;
        lastAt = now;
        foreach (var pair in shares) row[pair.Key] = pair.Value;
        foreach (var pair in rates)
        {
            if (pair.Value != null) row[pair.Key] = pair.Value;
        }
        if (percent != null && elapsed >= MinCpuSeconds) row["cpu_pct"] = percent;
        row["cpu_cores"] = Environment.ProcessorCount;
        foreach (var pair in LoadAverage()) row[pair.Key] = pair.Value;
        foreach (var pair in Memory()) row[pair.Key] = pair.Value;
        var disks = DiskRows(DiskPoints());
        if (disks.Count > 0) row["disks"] = disks;
        var rss = ProcessRssMb();
        if (rss != null) row["proc_rss_mb"] = rss;
        var uptime = HostUptime();
        if (uptime != null) row["host_uptime_s"] = uptime;
        row["proc_key"] = ProcKey;
        try
        {
            foreach (var pair in LimitsRow(row)) row[pair.Key] = pair.Value;
        }
        catch (Exception error)
        {
            core.Log("resources", "could not read the limits: " + error.Message);
        }
        lock (gate)
        {
            // Off in the dashboard: only the newest minute is kept, as the one
            // row that asks the collector, now and then, whether it is back on.
            if (!Enabled) rows.Clear();
            rows[(string)row["minute"]!] = row;
            // Oldest first out: a long outage keeps the recent minutes.
            while (rows.Count > MaxRows) rows.Remove(rows.Keys.First());
        }
        return row;
    }

    /// <summary>The limits pass for one sample: caps and counters diffed
    /// against the previous sample's, the rest read once.</summary>
    internal Dictionary<string, object?> LimitsRow(Dictionary<string, object?> row)
    {
        var output = new Dictionary<string, object?>
        {
            ["proc_uptime_s"] = (long)Math.Max(0, (DateTime.UtcNow - processStarted).TotalSeconds),
        };
        var reading = Limits.ReadCgroup(cgroup);
        var memTotal = row.TryGetValue("mem_total_mb", out var total) && total is long t ? t : (long?)null;
        var cores = OperatingSystem.IsLinux() ? Limits.HostCores(ReadText("/proc/stat")) : null;
        foreach (var pair in Limits.CgroupFields(lastCgroup, reading, memTotal, cores)) output[pair.Key] = pair.Value;
        lastCgroup = reading;
        foreach (var pair in Limits.PressureFields()) output[pair.Key] = pair.Value;
        var overflows = Limits.ListenOverflows(ReadText("/proc/net/netstat"));
        var drops = Limits.CountSince(lastOverflows, overflows);
        if (drops != null) output["listen_drops"] = (long)drops.Value;
        lastOverflows = overflows;
        var conntrack = Limits.ConntrackPct();
        if (conntrack != null) output["conntrack_pct"] = conntrack;
        foreach (var pair in Limits.FileFields()) output[pair.Key] = pair.Value;
        // Work items waiting for a thread: the pool's maximum is in the tens of
        // thousands and says nothing, so it isn't sent (the protocol says why).
        output["queue_waiting"] = ThreadPool.PendingWorkItemCount;
        var gc = GC.GetGCMemoryInfo();
        foreach (var pair in Limits.HeapFields(GC.GetTotalMemory(false), gc.TotalAvailableMemoryBytes)) output[pair.Key] = pair.Value;
        var gcMs = Limits.GcPauseMs();
        var paused = Limits.CountSince(lastGcMs, gcMs);
        if (paused != null) output["gc_ms"] = Math.Round(paused.Value, 1);
        lastGcMs = gcMs;
        var peak = InflightPeak?.Invoke();
        if (peak is >= 0) output["inflight_peak"] = peak;
        return output;
    }

    /// <summary>Sends what's buffered. Rows are kept only when the collector
    /// couldn't take them and retrying may work.</summary>
    public async Task<bool> FlushAsync()
    {
        List<string> minutes;
        List<Dictionary<string, object?>> batch;
        lock (gate)
        {
            minutes = rows.Keys.ToList();
            batch = rows.Values.ToList();
        }
        if (batch.Count == 0) return true;
        var res = await core.SendAsync("resources", "/events/resources", "POST", new Dictionary<string, object?>
        {
            ["site_id"] = core.SiteId,
            ["server_name"] = ServerName,
            ["runtime"] = Runtime,
            ["rows"] = batch,
        }, "bearer").ConfigureAwait(false);
        if (res == null) return false;
        if (!res.Ok)
        {
            // Unreachable or storage down: these rows are still good. A 4xx
            // means resending won't make them acceptable.
            if (res.Status >= 500) return false;
            Drop(minutes);
            return true;
        }
        var answer = res.Json();
        if (J.Int(J.Prop(answer, "every")) > 0) Every = (int)Math.Max(RetryEvery, J.Int(J.Prop(answer, "every")));
        if (J.IsObject(answer)) Enabled = J.Prop(answer, "enabled") is not { ValueKind: System.Text.Json.JsonValueKind.False };
        Drop(minutes);
        return true;
    }

    private void Drop(List<string> minutes)
    {
        lock (gate)
        {
            foreach (var minute in minutes) rows.Remove(minute);
        }
    }

    internal async Task<double> ReportAsync()
    {
        if (!core.IsOn("resources"))
        {
            // Switched off: keep nothing, and ask again later.
            lock (gate) rows.Clear();
            return Math.Max(OffEvery, Every);
        }
        var sent = await FlushAsync().ConfigureAwait(false);
        if (!Enabled) return Math.Max(OffEvery, Every);
        return sent ? Every : RetryEvery;
    }

    public async Task CloseAsync()
    {
        // What's buffered goes out, as with every other module.
        if (core.IsOn("resources") && Enabled) await FlushAsync().ConfigureAwait(false);
    }
}

/// <summary>How close the app is to a wall (sdk/protocols/resources.md,
/// "Limits"): its container's own caps, the machine's waiting time,
/// connections refused before the app saw them, the process's open files,
/// the thread pool's backlog, and the GC's heap and pauses. A port of the Node
/// package's lib/limits.js.
///
/// Inside Docker or Kubernetes /proc/meminfo is the host's, so memory reads
/// 40% while the container is a few megabytes from being killed: the cgroup's
/// files are the limits the kernel actually enforces. Same rule as the rest of
/// the module: a figure this machine won't give us is left out, never sent as
/// a zero. Every reader returns null for a file that isn't there, which off
/// Linux is all of them.</summary>
internal static class Limits
{
    // cgroup v1 says "no limit" with the largest page-aligned 64-bit number; v2
    // says "max". Anything this size is not a cap a machine has.
    public const double NoLimitBytes = 4611686018427387904d; // 2^62

    private static readonly System.Globalization.CultureInfo Invariant = System.Globalization.CultureInfo.InvariantCulture;
    private static readonly Regex Pressure = new(@"^some\b[^\n]*\bavg60=([\d.]+)", RegexOptions.Multiline | RegexOptions.CultureInvariant);
    private static readonly Regex MaxOpenFiles = new(@"^Max open files\s+(\S+)", RegexOptions.Multiline | RegexOptions.CultureInvariant);

    internal static string Read(string path) => Resources.ReadText(path);

    /// <summary>A number from a file holding one, or null for a missing or
    /// unreadable one ("" is not 0: that's the zero this must never invent).</summary>
    internal static double? Num(string? text)
    {
        var trimmed = (text ?? "").Trim();
        if (trimmed.Length == 0) return null;
        return double.TryParse(trimmed, System.Globalization.NumberStyles.Float, Invariant, out var value) && !double.IsNaN(value) && !double.IsInfinity(value) ? value : null;
    }

    /// <summary>"name value" lines (memory.stat, cpu.stat, memory.events) as numbers.</summary>
    internal static Dictionary<string, double> KeyValues(string text)
    {
        var output = new Dictionary<string, double>(StringComparer.Ordinal);
        foreach (var line in text.Split('\n'))
        {
            var parts = line.Trim().Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2) continue;
            var n = Num(parts[1]);
            if (n != null) output[parts[0]] = n.Value;
        }
        return output;
    }

    private static double? Get(Dictionary<string, double> values, string name) => values.TryGetValue(name, out var v) ? v : null;

    /// <summary>/proc/self/cgroup: the v2 path ("0::&lt;path&gt;") and the v1
    /// memory and cpu controllers' paths ("4:memory:&lt;path&gt;", "3:cpu,cpuacct:&lt;path&gt;").</summary>
    internal static (string? V2, string? Memory, string? Cpu) CgroupPaths(string text)
    {
        string? v2 = null, memory = null, cpu = null;
        foreach (var line in text.Split('\n'))
        {
            var first = line.IndexOf(':');
            var second = first < 0 ? -1 : line.IndexOf(':', first + 1);
            if (first < 0 || second < 0) continue;
            var id = line.Substring(0, first);
            var controllers = line.Substring(first + 1, second - first - 1).Split(',');
            var at = line.Substring(second + 1).Trim();
            if (at.Length == 0) continue;
            if (id == "0" && string.Join("", controllers) == "") v2 = at;
            if (controllers.Contains("memory")) memory = at;
            if (controllers.Contains("cpu")) cpu = at;
        }
        return (v2, memory, cpu);
    }

    internal sealed class Cgroup
    {
        public int Version;
        public string? Memory;
        public string? Cpu;
    }

    /// <summary>Where this process's cgroup files are, or null. Under the mount
    /// at the path /proc/self/cgroup names first, then the mount itself: in a
    /// container with its own cgroup namespace the path is "/" and the mount is
    /// already the container's; without one the path names the host's
    /// hierarchy. v2 needs the memory or cpu controller's own files, not just
    /// the directory: a hybrid machine lists a v2 path with no controllers in
    /// it while the limits live in v1.</summary>
    internal static Cgroup? FindCgroup(Func<string, string>? read = null)
    {
        read ??= Read;
        var paths = CgroupPaths(read("/proc/self/cgroup"));
        string? Under(string mount, string? at, string[] probes)
        {
            var dirs = at != null && at != "/" ? new[] { mount + at, mount } : new[] { mount };
            foreach (var dir in dirs)
            {
                if (probes.Any(probe => read(dir + "/" + probe).Length > 0)) return dir;
            }
            return null;
        }
        if (paths.V2 != null)
        {
            var dir = Under("/sys/fs/cgroup", paths.V2, new[] { "memory.current", "cpu.max" });
            if (dir != null) return new Cgroup { Version = 2, Memory = dir, Cpu = dir };
        }
        var memory = paths.Memory != null ? Under("/sys/fs/cgroup/memory", paths.Memory, new[] { "memory.usage_in_bytes" }) : null;
        var cpu = paths.Cpu != null ? Under("/sys/fs/cgroup/cpu", paths.Cpu, new[] { "cpu.cfs_quota_us" }) : null;
        return memory != null || cpu != null ? new Cgroup { Version = 1, Memory = memory, Cpu = cpu } : null;
    }

    /// <summary>One reading of the cgroup's caps and counters, in bytes and raw counts.</summary>
    internal sealed class CgroupReading
    {
        public double? MemCap;
        public double? MemUsed;
        public double? CpuCores;
        public double? Periods;
        public double? Throttled;
        public double? Oom;
    }

    internal static CgroupReading? ReadCgroup(Cgroup? cg, Func<string, string>? read = null)
    {
        if (cg == null) return null;
        read ??= Read;
        var output = new CgroupReading();
        if (cg.Version == 2)
        {
            var max = read(cg.Memory + "/memory.max").Trim();
            output.MemCap = max == "max" ? null : Num(max);
            var current = Num(read(cg.Memory + "/memory.current"));
            // The working set: page cache counts against the cgroup too, so
            // memory.current sits near the cap on a healthy container that
            // reads files. Less inactive_file is what Docker and the kubelet report.
            var stat = KeyValues(read(cg.Memory + "/memory.stat"));
            if (current != null) output.MemUsed = Math.Max(0, current.Value - (Get(stat, "inactive_file") ?? 0));
            output.Oom = Get(KeyValues(read(cg.Memory + "/memory.events")), "oom_kill");
            var quota = read(cg.Cpu + "/cpu.max").Trim().Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
            if (quota.Length == 2 && quota[0] != "max" && Num(quota[0]) is > 0 and var q && Num(quota[1]) is > 0 and var period) output.CpuCores = q / period;
            var cpu = KeyValues(read(cg.Cpu + "/cpu.stat"));
            output.Periods = Get(cpu, "nr_periods");
            output.Throttled = Get(cpu, "nr_throttled");
            return output;
        }
        if (cg.Memory != null)
        {
            output.MemCap = Num(read(cg.Memory + "/memory.limit_in_bytes"));
            var usage = Num(read(cg.Memory + "/memory.usage_in_bytes"));
            var stat = KeyValues(read(cg.Memory + "/memory.stat"));
            if (usage != null) output.MemUsed = Math.Max(0, usage.Value - (Get(stat, "total_inactive_file") ?? 0));
            // Kernels from 4.13 carry the count here.
            output.Oom = Get(KeyValues(read(cg.Memory + "/memory.oom_control")), "oom_kill");
        }
        if (cg.Cpu != null)
        {
            var quota = Num(read(cg.Cpu + "/cpu.cfs_quota_us"));
            var period = Num(read(cg.Cpu + "/cpu.cfs_period_us"));
            if (quota > 0 && period > 0) output.CpuCores = quota / period;
            var cpu = KeyValues(read(cg.Cpu + "/cpu.stat"));
            output.Periods = Get(cpu, "nr_periods");
            output.Throttled = Get(cpu, "nr_throttled");
        }
        return output;
    }

    /// <summary>How much a counter moved between two readings, or null: no
    /// pair, or it went down (a reset, not a negative count). Unlike a rate a
    /// count is never dropped for the pair being far apart: a kill is a kill.</summary>
    internal static double? CountSince(double? before, double? after)
    {
        if (before == null || after == null) return null;
        return after >= before ? after - before : null;
    }

    /// <summary>The row's cgroup fields from two readings. A cap at or above
    /// what the machine itself has isn't one (a systemd slice with no
    /// MemoryMax, or a container allowed more cores than the host), so neither
    /// half is sent.</summary>
    internal static Dictionary<string, object?> CgroupFields(CgroupReading? before, CgroupReading? after, long? memTotalMb, int? cores)
    {
        var output = new Dictionary<string, object?>();
        if (after == null) return output;
        long? capMb = after.MemCap > 0 && after.MemCap < NoLimitBytes ? (long)Math.Floor(after.MemCap.Value / Resources.Mb) : null;
        if (capMb > 0 && !(memTotalMb > 0 && capMb >= memTotalMb) && after.MemUsed != null)
        {
            output["limit_mem_mb"] = capMb;
            output["limit_mem_used_mb"] = Math.Min(capMb.Value, (long)Math.Floor(after.MemUsed.Value / Resources.Mb));
        }
        if (after.CpuCores > 0 && !(cores > 0 && after.CpuCores >= cores)) output["limit_cpu_cores"] = Math.Round(after.CpuCores.Value, 2);
        // Periods only pass while a quota is set, so no cap means nothing sent.
        var periods = CountSince(before?.Periods, after.Periods);
        var throttled = CountSince(before?.Throttled, after.Throttled);
        if (periods > 0 && throttled != null) output["cpu_throttled_pct"] = Math.Round(Math.Min(100, 100 * throttled.Value / periods.Value), 1);
        // Kills of other processes in this cgroup: this process's own can't be reported by it.
        var oom = CountSince(before?.Oom, after.Oom);
        if (oom != null) output["oom_kills"] = (long)oom.Value;
        return output;
    }

    /// <summary>/proc/pressure/&lt;resource&gt;'s "some" line, avg60.</summary>
    internal static double? PressureSome(string text)
    {
        var match = Pressure.Match(text);
        return match.Success && double.TryParse(match.Groups[1].Value, System.Globalization.NumberStyles.Float, Invariant, out var value)
            ? Math.Round(Math.Min(100, value), 1)
            : null;
    }

    internal static Dictionary<string, object?> PressureFields(Func<string, string>? read = null)
    {
        read ??= Read;
        var output = new Dictionary<string, object?>();
        foreach (var (name, file) in new[] { ("psi_cpu_pct", "cpu"), ("psi_mem_pct", "memory"), ("psi_io_pct", "io") })
        {
            var value = PressureSome(read("/proc/pressure/" + file));
            if (value != null) output[name] = value;
        }
        return output;
    }

    /// <summary>TcpExt ListenOverflows from /proc/net/netstat: a header line and a value line.</summary>
    internal static double? ListenOverflows(string text)
    {
        var lines = text.Split('\n');
        for (var i = 0; i + 1 < lines.Length; i++)
        {
            if (!lines[i].StartsWith("TcpExt:", StringComparison.Ordinal) || !lines[i + 1].StartsWith("TcpExt:", StringComparison.Ordinal)) continue;
            var names = lines[i].Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
            var values = lines[i + 1].Trim().Split(' ', StringSplitOptions.RemoveEmptyEntries);
            var at = Array.IndexOf(names, "ListenOverflows");
            return at > 0 && at < values.Length ? Num(values[at]) : null;
        }
        return null;
    }

    /// <summary>How full the connection-tracking table is: only where the
    /// firewall loaded it, and usually unreadable inside a container.</summary>
    internal static double? ConntrackPct(Func<string, string>? read = null)
    {
        read ??= Read;
        var count = Num(read("/proc/sys/net/netfilter/nf_conntrack_count"));
        var max = Num(read("/proc/sys/net/netfilter/nf_conntrack_max"));
        return count != null && max > 0 ? Math.Round(Math.Min(100, 100 * count.Value / max.Value), 1) : null;
    }

    /// <summary>The soft "Max open files" from /proc/self/limits, or null when unlimited.</summary>
    internal static double? FdLimit(string text)
    {
        var match = MaxOpenFiles.Match(text);
        return match.Success ? Num(match.Groups[1].Value) : null;
    }

    /// <summary>Open descriptors of this process, less the one listing them takes.</summary>
    internal static long? OpenFiles(Func<int>? list = null)
    {
        try
        {
            if (list == null && !OperatingSystem.IsLinux()) return null;
            var count = list != null ? list() : Directory.EnumerateFileSystemEntries("/proc/self/fd").Count();
            return Math.Max(0, count - 1);
        }
        catch (Exception)
        {
            return null;
        }
    }

    internal static Dictionary<string, object?> FileFields(Func<string, string>? read = null, Func<int>? list = null)
    {
        read ??= Read;
        var output = new Dictionary<string, object?>();
        var used = OpenFiles(list);
        var max = FdLimit(read("/proc/self/limits"));
        if (used != null) output["fds_used"] = max > 0 ? Math.Min(used.Value, (long)max.Value) : used.Value;
        if (max > 0) output["fds_max"] = (long)max.Value;
        return output;
    }

    /// <summary>The GC's heap against what it may use (the machine's memory, a
    /// container's cap, or GCHeapHardLimit): a different wall from the container's.</summary>
    internal static Dictionary<string, object?> HeapFields(long used, long available)
    {
        if (used <= 0 || available <= 0) return new Dictionary<string, object?>();
        return new Dictionary<string, object?> { ["heap_used_mb"] = used / Resources.Mb, ["heap_max_mb"] = available / Resources.Mb };
    }

    /// <summary>Milliseconds the GC has paused the process since it started,
    /// or null where the runtime can't say (.NET 6).</summary>
    internal static double? GcPauseMs()
    {
#if NET7_0_OR_GREATER
        return GC.GetTotalPauseDuration().TotalMilliseconds;
#else
        return null;
#endif
    }

    /// <summary>The machine's own cores, which Environment.ProcessorCount isn't
    /// in a container with a CPU cap: the "cpuN" lines of /proc/stat.</summary>
    internal static int? HostCores(string stat)
    {
        var count = 0;
        foreach (var line in stat.Split('\n'))
        {
            if (line.Length > 3 && line.StartsWith("cpu", StringComparison.Ordinal) && char.IsDigit(line[3])) count++;
        }
        return count > 0 ? count : null;
    }
}
