"""How the machine is doing (protocol in sdk/protocols/resources.md).

CPU, load, memory, swap and disks, sampled every minute and sent to
POST /events/resources every few minutes. The companion of the performance
module: that says how the requests went, this says whether the box can still
serve them, so the dashboard shows what you would otherwise run node_exporter,
Prometheus and Grafana for.

Nothing is guessed. A reading this machine won't give us is left out of the
row, never sent as a zero: the collector stores it as NULL and the dashboard
shows "-", because "0% CPU" and "we couldn't measure CPU" are different
statements and only one of them means healthy.

Each row also says how close the app is to a wall (the "Limits" pass): its
cgroup's memory and CPU caps, throttling and kills, the machine's waiting
time, refused connections, the connection-tracking table, open files, the
most requests in progress at once, and how long the process has run.

Standard library only, like the rest of the package: no psutil.
"""

import os
import re
import secrets
import socket
import threading
import time
from datetime import datetime, timezone

from .core import Periodic

# Keep in step with the collector (expresscollect/Analytics/resources.py) and
# the agent (sdk/vps-agent).
SAMPLE_EVERY = 60
EVERY = 5 * 60
RETRY_EVERY = 60
OFF_EVERY = 600
# About 8 hours of samples: enough to ride out a collector outage, bounded so
# a long one can't grow in memory.
MAX_ROWS = 500
MAX_DISKS = 20
# Nobody watches a sub-gigabyte partition fill up; this drops the EFI
# partition and other small mounts without needing a list of paths.
MIN_DISK_MB = 1024
# Below this, two CPU readings are too close together to divide: the counters
# move in ticks, so a percentage over a few milliseconds is quantisation noise
# (0% or 100%, nothing between).
MIN_CPU_SECONDS = 1.0
# Real on-disk filesystems only: no tmpfs, devtmpfs, proc, sysfs, cgroup or
# squashfs (snaps), none of which are the customer's disk. overlay is here so
# a containerised app still reports something sensible.
FSTYPES = {"ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs", "jfs",
           "reiserfs", "ufs", "vfat", "exfat", "ntfs", "ntfs3", "overlay", "apfs", "hfs"}

MB = 1024 * 1024


def read_text(path, limit=65536):
    try:
        with open(path, "rb") as handle:
            return handle.read(limit).decode("utf-8", "replace")
    except OSError:
        return ""


# Sectors in /proc/diskstats are always 512 bytes: the unit of that interface,
# not of the drive.
IO_SECTOR = 512
# Two readings further apart than this say nothing about this minute. It is the
# rule that matters most here: this client only samples while a request is
# being served, so the pair can be an hour apart on a quiet site.
IO_MAX_PAIR_SECONDS = 300
# Not disks: loop and ram devices, optical drives, device-mapper and md, each
# of which would count what is underneath it a second time.
IO_NOT_A_DISK = re.compile(r"^(?:loop|ram|zram|sr|fd|dm-|md\d)")
# Partitions, which must not be counted alongside their disk.
IO_PARTITION = re.compile(r"^(?:(?:sd|vd|xvd|hd)[a-z]+\d+|(?:nvme\d+n\d+|mmcblk\d+)p\d+)\Z")
# Loopback and the virtual ends of container and VM networking.
NET_NOT_REAL = re.compile(r"^(?:lo|veth|docker|br-|virbr|tap|tun|vnet)")


def cpu_fields(text):
    """The jiffie counters from /proc/stat's first line, or None.

    In order: user, nice, system, idle, iowait, irq, softirq, steal."""
    for line in text.splitlines():
        if not line.startswith("cpu "):
            continue
        try:
            fields = [int(value) for value in line.split()[1:]]
        except ValueError:
            return None
        return fields if len(fields) >= 4 else None
    return None


def cpu_total(fields):
    """Every jiffy in the counters once. guest and guest_nice (columns 9 and
    10) are already inside user and nice, so they are left out, as psutil and
    top do: counting them again reads a busy hypervisor as half idle."""
    return sum(fields[:8])


def cpu_times_of(fields):
    """(busy, total) jiffies from the counters, for cpu_percent."""
    total = cpu_total(fields)
    idle = fields[3] + (fields[4] if len(fields) > 4 else 0)
    return total - idle, total


def cpu_times(text):
    """(busy, total) jiffies from /proc/stat's first line, or None.

    idle and iowait are the machine doing nothing; everything else, steal
    included, is time it wasn't available to us."""
    fields = cpu_fields(text)
    return None if fields is None else cpu_times_of(fields)


# user folds nice in, as top adds them together. Each is a share of the whole
# interval, so with idle and the interrupt buckets they come to 100.
CPU_SHARES = (
    ("cpu_user_pct", (0, 1)),
    ("cpu_system_pct", (2,)),
    ("cpu_iowait_pct", (4,)),
    ("cpu_steal_pct", (7,)),
)


def cpu_shares(before, after):
    """Where the machine's time went between two /proc/stat readings.

    Empty when the pair can't say, and a column the kernel is too old to carry
    is left out rather than sent as a zero. steal is the one worth surfacing:
    time the hypervisor gave to another tenant, which no tuning of the app
    will change."""
    if not before or not after:
        return {}
    total = cpu_total(after) - cpu_total(before)
    if total <= 0:
        return {}
    out = {}
    for name, columns in CPU_SHARES:
        if any(i >= len(before) or i >= len(after) for i in columns):
            continue
        moved = sum(after[i] - before[i] for i in columns)
        if moved < 0:
            return {}
        out[name] = round(min(100.0, 100.0 * moved / total), 1)
    return out


def disk_counters(text):
    """(bytes read, bytes written) since boot over the real disks, or None."""
    read = written = 0
    found = False
    for line in text.splitlines():
        fields = line.split()
        if len(fields) < 10:
            continue
        name = fields[2]
        if IO_NOT_A_DISK.match(name) or IO_PARTITION.match(name):
            continue
        try:
            read += int(fields[5]) * IO_SECTOR
            written += int(fields[9]) * IO_SECTOR
        except ValueError:
            continue
        found = True
    return (read, written) if found else None


def net_counters(text):
    """(bytes in, bytes out) since boot over the real interfaces, or None."""
    rx = tx = 0
    found = False
    for line in text.splitlines():
        if ":" not in line:
            continue
        name, rest = line.split(":", 1)
        name = name.strip()
        if not name or NET_NOT_REAL.match(name):
            continue
        fields = rest.split()
        if len(fields) < 9:
            continue
        try:
            rx += int(fields[0])
            tx += int(fields[8])
        except ValueError:
            continue
        found = True
    return (rx, tx) if found else None


def rate_mbs(before, after, seconds):
    """Megabytes a second between two byte counters, or None when the pair
    can't say: no pair, a reboot that reset them, no time, or too long a gap
    to call it a rate for this minute."""
    if before is None or after is None:
        return None
    if seconds <= 0 or seconds > IO_MAX_PAIR_SECONDS:
        return None
    moved = after - before
    if moved < 0:
        return None
    return round(moved / seconds / MB, 1)


def cpu_percent(before, after):
    """How busy the machine was between two readings, or None when the pair
    can't say: the first sample, a counter reset, or no time passed."""
    if not before or not after:
        return None
    busy, total = after[0] - before[0], after[1] - before[1]
    if total <= 0 or busy < 0:
        return None
    return round(min(100.0, 100.0 * busy / total), 1)


def memory_mb(text):
    """MemTotal/MemAvailable/Swap from /proc/meminfo, in whole megabytes.

    Used is total - MemAvailable, never total - MemFree: page cache is not
    pressure, and counting it as used makes every healthy Linux box look full.
    A field the kernel didn't give us is left out of the result."""
    values = {}
    for line in text.splitlines():
        name, _, rest = line.partition(":")
        fields = rest.split()
        if not fields:
            continue
        try:
            values[name] = int(fields[0]) // 1024  # kB -> MB
        except ValueError:
            continue
    out = {}
    if "MemTotal" in values:
        out["mem_total_mb"] = values["MemTotal"]
        if "MemAvailable" in values:
            out["mem_used_mb"] = max(0, values["MemTotal"] - values["MemAvailable"])
    if "SwapTotal" in values:
        out["swap_total_mb"] = values["SwapTotal"]
        if "SwapFree" in values:
            out["swap_used_mb"] = max(0, values["SwapTotal"] - values["SwapFree"])
    return out


def mount_points(mounts_text, is_dir=None):
    """The real disks behind /proc/mounts, one per device under its shortest
    mount point, so a bind mount isn't reported as a second disk. Off Linux
    there is no mount table, so the one filesystem we can name without
    guessing is the one the application runs from.

    A mount point has to be a directory. Docker bind-mounts single files, so a
    container lists /etc/hosts, /etc/hostname and /etc/resolv.conf on the
    host's own device, and those paths are short enough to win the
    shortest-path race against the real mount. The test is per-device and
    advisory: a device whose mounts cannot be confirmed keeps its shortest
    one, because reporting no disks is worse than an odd mount point."""
    if not mounts_text:
        return [os.path.abspath(os.sep)]
    is_dir = is_dir or os.path.isdir
    dirs, any_mount = {}, {}
    for line in mounts_text.splitlines():
        fields = line.split()
        if len(fields) < 3:
            continue
        device, mount, fstype = fields[0], fields[1].replace("\\040", " "), fields[2]
        if fstype not in FSTYPES or not mount.startswith("/"):
            continue
        if device not in any_mount or len(mount) < len(any_mount[device]):
            any_mount[device] = mount
        try:
            confirmed = is_dir(mount)
        except OSError:
            confirmed = False
        if confirmed and (device not in dirs or len(mount) < len(dirs[device])):
            dirs[device] = mount
    return sorted({dirs.get(d, m) for d, m in any_mount.items()})


def disk_rows(points, statvfs=None):
    """Both figures are df's, so a customer can check them: used is total
    minus free, and total is used plus what's available to us. The blocks
    reserved for root are in neither, which is what makes used/total the
    percentage df prints - and that percentage is what the disk alert is
    about."""
    statvfs = statvfs or getattr(os, "statvfs", None)
    if statvfs is None:
        return []
    # One filesystem can sit behind two devices the kernel calls different: in
    # a container / is the overlay and a bind mount exposes the host disk the
    # overlay's upperdir lives on, so both report the same size and the same
    # free space down to the byte. No device-based rule separates them, so the
    # sizes are what gives it away. Raw bytes, not rounded megabytes, so disks
    # that merely round alike stay apart; two separate but identically sized
    # and identically empty filesystems do collapse into one until something
    # is written to either, and being empty they owe the fullness alert
    # nothing.
    seen = set()
    rows = []
    for mount in points:
        try:
            st = statvfs(mount)
        except OSError:
            continue
        block = st.f_frsize or st.f_bsize
        if not block or not st.f_blocks:
            continue
        used = max(0, st.f_blocks - st.f_bfree) * block
        total = used + st.f_bavail * block
        row = {"mount": mount, "total_mb": total // MB, "used_mb": used // MB}
        if row["total_mb"] < MIN_DISK_MB:
            continue
        # points arrives sorted, so the shortest path wins the collision.
        if (total, used) in seen:
            continue
        seen.add((total, used))
        # A filesystem can refuse a write with gigabytes free once these meet.
        if st.f_files:
            row["inodes_total"] = st.f_files
            row["inodes_used"] = max(0, st.f_files - st.f_ffree)
        rows.append(row)
        if len(rows) >= MAX_DISKS:
            break
    return rows


def host_uptime(text):
    """Seconds since boot from /proc/uptime, or None. A drop between two
    samples is a reboot, which is worth seeing beside a latency spike."""
    try:
        return int(float(text.split()[0]))
    except (IndexError, ValueError):
        return None


def load_average():
    try:
        one, five, fifteen = os.getloadavg()
    except (OSError, AttributeError):
        return {}
    return {"load1": round(one, 2), "load5": round(five, 2), "load15": round(fifteen, 2)}


def process_rss_mb(text):
    """This package runs inside the application, so unlike the agent it can
    honestly report the application's own memory."""
    for line in text.splitlines():
        if line.startswith("VmRSS:"):
            fields = line.split()
            if len(fields) >= 2:
                try:
                    return max(1, int(fields[1]) // 1024)
                except ValueError:
                    return None
    return None


# ---- Limits: how close the app is to a wall (resources.md, "Limits") ----
#
# The rest of this module says how busy the machine is. Inside Docker or
# Kubernetes that is the wrong question: /proc/meminfo is the host's, so
# memory reads 40% while the container is a few megabytes from being killed.
# The cgroup's files are the limits the kernel actually enforces. Same rule as
# the rest: a figure this machine won't give is left out, never sent as 0.
# No garbage-collection timing (a callback per collection costs too much in
# Python) and no heap cap (CPython has none).

# cgroup v1 says "no limit" with the largest page-aligned 64-bit number; v2
# says "max". Anything this size is not a cap a machine has.
NO_LIMIT_BYTES = 2 ** 62


def _num(text):
    """A number from a file holding one, or None for a missing or unreadable one."""
    text = str(text if text is not None else "").strip()
    if not text:
        return None
    try:
        value = float(text)
    except ValueError:
        return None
    return int(value) if value.is_integer() else value


def key_values(text):
    """"name value" lines (memory.stat, cpu.stat, memory.events) as numbers."""
    out = {}
    for line in str(text).splitlines():
        parts = line.split()
        if len(parts) >= 2:
            value = _num(parts[1])
            if value is not None:
                out[parts[0]] = value
    return out


def cgroup_paths(text):
    """/proc/self/cgroup: the v2 path ("0::<path>") and the v1 memory and cpu
    controllers' paths ("4:memory:<path>", "3:cpu,cpuacct:<path>")."""
    out = {"v2": None, "memory": None, "cpu": None}
    for line in str(text).splitlines():
        parts = line.split(":", 2)
        if len(parts) < 3:
            continue
        ident, controllers, at = parts[0], parts[1].split(","), parts[2].strip()
        if not at:
            continue
        if ident == "0" and "".join(controllers) == "":
            out["v2"] = at
        if "memory" in controllers:
            out["memory"] = at
        if "cpu" in controllers:
            out["cpu"] = at
    return out


def find_cgroup(read=read_text):
    """Where this process's cgroup files are, or None. Under the mount at the
    path /proc/self/cgroup names first, then the mount itself: in a container
    with its own cgroup namespace the path is "/" and the mount is already the
    container's; without one the path names the host's hierarchy.

    v2 needs the memory or cpu controller's own files, not just the
    directory: a hybrid machine lists a v2 path with no controllers in it
    while the limits live in v1."""
    paths = cgroup_paths(read("/proc/self/cgroup"))

    def under(base, at, probes):
        for folder in ([base + at, base] if at and at != "/" else [base]):
            if any(read("%s/%s" % (folder, probe)) for probe in probes):
                return folder
        return None

    if paths["v2"] is not None:
        folder = under("/sys/fs/cgroup", paths["v2"], ("memory.current", "cpu.max"))
        if folder:
            return {"version": 2, "memory": folder, "cpu": folder}
    memory = under("/sys/fs/cgroup/memory", paths["memory"], ("memory.usage_in_bytes",)) if paths["memory"] is not None else None
    cpu = under("/sys/fs/cgroup/cpu", paths["cpu"], ("cpu.cfs_quota_us",)) if paths["cpu"] is not None else None
    return {"version": 1, "memory": memory, "cpu": cpu} if memory or cpu else None


def cgroup_reading(cg, read=read_text):
    """One reading of the cgroup's caps and counters, in bytes and raw
    counts. The counters (periods, throttled, oom) need two readings."""
    if not cg:
        return None
    out = {"mem_cap": None, "mem_used": None, "cpu_cores": None, "periods": None, "throttled": None, "oom": None}
    if cg["version"] == 2:
        limit = read("%s/memory.max" % cg["memory"]).strip()
        out["mem_cap"] = None if limit == "max" else _num(limit)
        current = _num(read("%s/memory.current" % cg["memory"]))
        # The working set: page cache counts against the cgroup too, so
        # memory.current sits near the cap on a healthy container that reads
        # files. Less inactive_file is what Docker and the kubelet report.
        stat = key_values(read("%s/memory.stat" % cg["memory"]))
        if current is not None:
            out["mem_used"] = max(0, current - (stat.get("inactive_file") or 0))
        out["oom"] = key_values(read("%s/memory.events" % cg["memory"])).get("oom_kill")
        quota_period = read("%s/cpu.max" % cg["cpu"]).split()
        if len(quota_period) == 2 and quota_period[0] != "max":
            quota, period = _num(quota_period[0]), _num(quota_period[1])
            if quota and period and quota > 0 and period > 0:
                out["cpu_cores"] = quota / period
        cpu = key_values(read("%s/cpu.stat" % cg["cpu"]))
        out["periods"], out["throttled"] = cpu.get("nr_periods"), cpu.get("nr_throttled")
        return out
    if cg["memory"]:
        out["mem_cap"] = _num(read("%s/memory.limit_in_bytes" % cg["memory"]))
        usage = _num(read("%s/memory.usage_in_bytes" % cg["memory"]))
        stat = key_values(read("%s/memory.stat" % cg["memory"]))
        if usage is not None:
            out["mem_used"] = max(0, usage - (stat.get("total_inactive_file") or 0))
        # Kernels from 4.13 carry the count here.
        out["oom"] = key_values(read("%s/memory.oom_control" % cg["memory"])).get("oom_kill")
    if cg["cpu"]:
        quota = _num(read("%s/cpu.cfs_quota_us" % cg["cpu"]))
        period = _num(read("%s/cpu.cfs_period_us" % cg["cpu"]))
        if quota and period and quota > 0 and period > 0:
            out["cpu_cores"] = quota / period
        cpu = key_values(read("%s/cpu.stat" % cg["cpu"]))
        out["periods"], out["throttled"] = cpu.get("nr_periods"), cpu.get("nr_throttled")
    return out


def count_since(before, after):
    """How much a counter moved between two readings, or None: no pair, or
    it went down, which is a reset. Unlike a rate a count is never dropped
    for the pair being far apart: a kill is a kill."""
    if before is None or after is None:
        return None
    return after - before if after >= before else None


def cgroup_fields(before, after, mem_total_mb=None, cores=None):
    """The row's cgroup fields from two readings. A cap at or above what the
    machine itself has isn't one (a systemd slice with no MemoryMax, or a
    container allowed more cores than the host), so neither half is sent."""
    out = {}
    if not after:
        return out
    cap = after["mem_cap"]
    cap_mb = cap // MB if cap is not None and 0 < cap < NO_LIMIT_BYTES else None
    if cap_mb and not (mem_total_mb and cap_mb >= mem_total_mb) and after["mem_used"] is not None:
        out["limit_mem_mb"] = int(cap_mb)
        out["limit_mem_used_mb"] = int(min(cap_mb, after["mem_used"] // MB))
    if after["cpu_cores"] and not (cores and after["cpu_cores"] >= cores):
        out["limit_cpu_cores"] = round(after["cpu_cores"], 2)
    # Periods only pass while a quota is set, so no cap means nothing sent.
    periods = count_since((before or {}).get("periods"), after["periods"])
    throttled = count_since((before or {}).get("throttled"), after["throttled"])
    if periods and throttled is not None:
        out["cpu_throttled_pct"] = round(min(100.0, 100.0 * throttled / periods), 1)
    # Kills of other processes in this cgroup (a gunicorn or Celery worker):
    # this process's own kill can't be reported by it.
    oom = count_since((before or {}).get("oom"), after["oom"])
    if oom is not None:
        out["oom_kills"] = int(oom)
    return out


_AVG60 = re.compile(r"^some\b[^\n]*\bavg60=([\d.]+)", re.M)


def pressure_some(text):
    """/proc/pressure/<resource>'s "some" line, avg60: the share of the last
    minute in which at least one task was waiting. One reading is enough."""
    match = _AVG60.search(str(text))
    return round(min(100.0, float(match.group(1))), 1) if match else None


def pressure_fields(read=read_text):
    out = {}
    for name, resource in (("psi_cpu_pct", "cpu"), ("psi_mem_pct", "memory"), ("psi_io_pct", "io")):
        value = pressure_some(read("/proc/pressure/" + resource))
        if value is not None:
            out[name] = value
    return out


def listen_overflows(text):
    """TcpExt ListenOverflows from /proc/net/netstat: connections refused
    since boot because the accept queue was full."""
    lines = str(text).splitlines()
    for i in range(len(lines) - 1):
        if not lines[i].startswith("TcpExt:") or not lines[i + 1].startswith("TcpExt:"):
            continue
        names, values = lines[i].split(), lines[i + 1].split()
        if "ListenOverflows" not in names:
            return None
        at = names.index("ListenOverflows")
        return _num(values[at]) if at < len(values) else None
    return None


def conntrack_pct(read=read_text):
    """How full the connection-tracking table is: only where the firewall
    loaded it, and usually unreadable inside a container."""
    count = _num(read("/proc/sys/net/netfilter/nf_conntrack_count"))
    most = _num(read("/proc/sys/net/netfilter/nf_conntrack_max"))
    return round(min(100.0, 100.0 * count / most), 1) if count is not None and most else None


def fd_limit(text):
    """The soft "Max open files" from /proc/self/limits, or None when unlimited."""
    match = re.search(r"^Max open files\s+(\S+)", str(text), re.M)
    value = _num(match.group(1)) if match else None
    return value if value and value > 0 else None


def open_files(listdir=None):
    """Open descriptors of this process, less the one listing them takes."""
    try:
        return max(0, len((listdir or os.listdir)("/proc/self/fd")) - 1)
    except OSError:
        return None


def file_fields(read=read_text, listdir=None):
    out = {}
    used = open_files(listdir)
    most = fd_limit(read("/proc/self/limits"))
    if used is not None:
        out["fds_used"] = min(used, most) if most else used
    if most:
        out["fds_max"] = most
    return out


def process_uptime(read=read_text, fallback=None):
    """Seconds this process has run: /proc/self/stat's start time against
    /proc/uptime, else since fallback (time.monotonic() at start)."""
    stat = read("/proc/self/stat")
    up = host_uptime(read("/proc/uptime"))
    try:
        # The name in parentheses can hold spaces; fields count from after it.
        start_ticks = int(stat.rsplit(")", 1)[1].split()[19])
        ticks = os.sysconf("SC_CLK_TCK")
        if up is not None and ticks > 0:
            return max(0, int(up - start_ticks / ticks))
    except (IndexError, ValueError, OSError, AttributeError):
        pass
    return max(0, int(time.monotonic() - fallback)) if fallback is not None else None


class Resources:
    """Options: server_name (the server's name as the dashboard shows it)."""

    def __init__(self, core, server_name=None, **_):
        self.core = core
        self.server_name = str(server_name if server_name is not None else socket.gethostname())[:100]
        import platform as _platform
        self.runtime = "Python %s" % _platform.python_version()
        # minute (ISO) -> row, so a minute sampled twice is kept once.
        self.rows = {}
        self.lock = threading.Lock()
        self.every = EVERY
        self.enabled = True
        self.last_cpu = cpu_fields(read_text("/proc/stat"))
        self.last_disk = disk_counters(read_text("/proc/diskstats"))
        self.last_net = net_counters(read_text("/proc/net/dev"))
        self.last_at = self._now()
        # The limits pass: the cgroup is found once, its counters and the
        # listen-queue count read every sample and diffed like CPU.
        self.cgroup = find_cgroup()
        self.last_cgroup = cgroup_reading(self.cgroup)
        self.last_overflows = listen_overflows(read_text("/proc/net/netstat"))
        # Requests in progress at once, from the performance module's
        # request timing (the platform wires it); None until then.
        self.inflight_peak = None
        # This process among others of the same name (gunicorn and Celery
        # workers each send their own), so a read tells siblings from copies.
        self.proc_key = secrets.token_hex(6)
        self.started = time.monotonic()
        if hasattr(os, "register_at_fork"):
            os.register_at_fork(after_in_child=self._forked)
        self.sampler = Periodic(self._sample_job, SAMPLE_EVERY) if core.valid else None
        self.job = Periodic(self._report, EVERY) if core.valid else None

    def _forked(self):
        """A forked worker is a process of its own: its own key, and the
        parent's rows are the parent's to send."""
        self.lock = threading.Lock()
        self.rows = {}
        self.proc_key = secrets.token_hex(6)
        self.started = time.monotonic()

    def limits_row(self, row):
        """The limits pass for one sample: caps and counters diffed against
        the previous sample's, the rest read once."""
        out = {}
        uptime = process_uptime(fallback=self.started)
        if uptime is not None:
            out["proc_uptime_s"] = uptime
        reading = cgroup_reading(self.cgroup)
        out.update(cgroup_fields(self.last_cgroup, reading, row.get("mem_total_mb"), row.get("cpu_cores")))
        self.last_cgroup = reading
        out.update(pressure_fields())
        overflows = listen_overflows(read_text("/proc/net/netstat"))
        drops = count_since(self.last_overflows, overflows)
        if drops is not None:
            out["listen_drops"] = int(drops)
        self.last_overflows = overflows
        conntrack = conntrack_pct()
        if conntrack is not None:
            out["conntrack_pct"] = conntrack
        out.update(file_fields())
        if self.inflight_peak is not None:
            peak = self.inflight_peak()
            if isinstance(peak, int) and peak >= 0:
                out["inflight_peak"] = peak
        return out

    @staticmethod
    def _now():
        return datetime.now(timezone.utc).timestamp()

    def sample(self, at=None):
        """Takes one sample, covering the time since the last one."""
        at = self._now() if at is None else at
        cpu = cpu_fields(read_text("/proc/stat"))
        disk = disk_counters(read_text("/proc/diskstats"))
        net = net_counters(read_text("/proc/net/dev"))
        percent = cpu_percent(
            None if self.last_cpu is None else cpu_times_of(self.last_cpu),
            None if cpu is None else cpu_times_of(cpu),
        )
        elapsed = at - self.last_at
        # The minute the interval started in, not the one it ended in.
        minute = datetime.fromtimestamp(int(self.last_at // 60) * 60, timezone.utc)
        row = {"minute": minute.isoformat().replace("+00:00", "Z"), "proc_key": self.proc_key}
        shares = cpu_shares(self.last_cpu, cpu)
        rates = {}
        if self.last_disk and disk:
            rates["disk_read_mbs"] = rate_mbs(self.last_disk[0], disk[0], elapsed)
            rates["disk_write_mbs"] = rate_mbs(self.last_disk[1], disk[1], elapsed)
        if self.last_net and net:
            rates["net_rx_mbs"] = rate_mbs(self.last_net[0], net[0], elapsed)
            rates["net_tx_mbs"] = rate_mbs(self.last_net[1], net[1], elapsed)
        self.last_cpu, self.last_disk, self.last_net, self.last_at = cpu, disk, net, at
        row.update(shares)
        row.update({name: value for name, value in rates.items() if value is not None})
        if percent is not None and elapsed >= MIN_CPU_SECONDS:
            row["cpu_pct"] = percent
        cores = os.cpu_count()
        if cores:
            row["cpu_cores"] = cores
        row.update(load_average())
        row.update(memory_mb(read_text("/proc/meminfo")))
        disks = disk_rows(mount_points(read_text("/proc/mounts")))
        if disks:
            row["disks"] = disks
        rss = process_rss_mb(read_text("/proc/self/status"))
        if rss is not None:
            row["proc_rss_mb"] = rss
        uptime = host_uptime(read_text("/proc/uptime"))
        if uptime is not None:
            row["host_uptime_s"] = uptime
        try:
            row.update(self.limits_row(row))
        except Exception as error:
            self.core.log("resources", "could not read the limits:", error)
        with self.lock:
            if not self.enabled:
                # Off in the dashboard: only the newest minute is kept, as the
                # one row that asks the collector, now and then, whether it is
                # back on (the answer is the only place that says so).
                self.rows.clear()
            self.rows[row["minute"]] = row
            # Oldest first out: a long outage keeps the recent minutes.
            while len(self.rows) > MAX_ROWS:
                del self.rows[min(self.rows)]
        return row

    def _sample_job(self):
        self.sample()
        return SAMPLE_EVERY

    def flush(self):
        """Sends what's buffered. Rows are kept only when the collector
        couldn't take them and retrying may work."""
        with self.lock:
            minutes = sorted(self.rows)
            rows = [self.rows[minute] for minute in minutes]
        if not rows:
            return True
        body = {"site_id": self.core.site_id, "server_name": self.server_name,
                "runtime": self.runtime, "rows": rows}
        res = self.core.send("resources", "/events/resources", auth="bearer", body=body)
        if res is None:
            return False
        if not getattr(res, "ok", False):
            # Unreachable or storage down: these rows are still good. A 4xx
            # means resending won't make them acceptable.
            if getattr(res, "status", 0) >= 500:
                return False
            self._drop(minutes)
            return True
        try:
            answer = res.json()
        except Exception:
            answer = {}
        if isinstance(answer, dict):
            if int(answer.get("every") or 0) > 0:
                self.every = max(RETRY_EVERY, int(answer["every"]))
            self.enabled = answer.get("enabled") is not False
        self._drop(minutes)
        return True

    def _drop(self, minutes):
        with self.lock:
            for minute in minutes:
                self.rows.pop(minute, None)

    def _report(self):
        if not self.core.is_on("resources"):
            # Switched off: keep nothing, and ask again later.
            with self.lock:
                self.rows.clear()
            return max(OFF_EVERY, self.every)
        sent = self.flush()
        if not self.enabled:
            # The collector said the module is off: ask again later, as the agent does.
            return max(OFF_EVERY, self.every)
        return self.every if sent else RETRY_EVERY

    def close(self):
        if self.sampler:
            self.sampler.stop()
        if self.job:
            self.job.stop()
        # What's buffered goes out, as with every other module.
        if self.core.is_on("resources") and self.enabled:
            self.flush()
