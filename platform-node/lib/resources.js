// Resources module (protocol in sdk/protocols/resources.md): how the machine
// is doing — CPU, load, memory, swap, disks — sampled every minute and sent to
// POST /events/resources every few minutes. The companion of the performance
// module: that says how the requests went, this says whether the box can still
// serve them, so the dashboard shows what you would otherwise run
// node_exporter, Prometheus and Grafana for.
//
// Nothing is guessed. A reading this machine won't give us is left out of the
// row, never sent as a zero: the collector stores it as NULL and the dashboard
// shows "—", because "0% CPU" and "we couldn't measure CPU" are different
// statements and only one of them means healthy.
"use strict";

const crypto = require("node:crypto");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const v8 = require("node:v8");
const limits = require("./limits.js");

// Keep in step with the collector (expresscollect/Analytics/resources.js) and
// the agent (sdk/vps-agent).
const SAMPLE_MS = 60 * 1000;
// Below this, two CPU readings are too close together to divide: the counters
// move in ticks, so a percentage over a few milliseconds is quantisation noise
// (0% or 100%, nothing between). A sample taken that soon reports no CPU
// figure rather than a made-up one.
const MIN_CPU_MS = 1000;
const EVERY_S = 5 * 60;
const RETRY_S = 60;
// About 8 hours of samples: enough to ride out a collector outage, bounded so
// a long one can't grow in memory.
const MAX_ROWS = 500;
const MAX_DISKS = 20;
// Nobody watches a sub-gigabyte partition fill up; this drops the EFI
// partition and other small mounts without needing a list of paths.
const MIN_DISK_MB = 1024;
// Real on-disk filesystems only: no tmpfs, devtmpfs, proc, sysfs, cgroup or
// squashfs (snaps), none of which are the customer's disk. overlay is here so
// a containerised app still reports something sensible.
const FSTYPES = new Set(["ext2", "ext3", "ext4", "xfs", "btrfs", "zfs", "f2fs", "jfs",
  "reiserfs", "ufs", "vfat", "exfat", "ntfs", "ntfs3", "overlay", "apfs", "hfs"]);

const MB = 1024 * 1024;
const read = (file) => {
  try {
    return fs.readFileSync(file, "utf8");
  } catch {
    return "";
  }
};

// (busy, total) across every core. idle is the machine doing nothing;
// everything else, including time stolen by the hypervisor, is time it wasn't
// available to us. os.cpus() rather than /proc/stat, so this works everywhere.
function cpuTimes(cpus = os.cpus()) {
  let busy = 0;
  let total = 0;
  for (const cpu of cpus || []) {
    const t = cpu?.times || {};
    const idle = Number(t.idle) || 0;
    const sum = idle + (Number(t.user) || 0) + (Number(t.nice) || 0) + (Number(t.sys) || 0) + (Number(t.irq) || 0);
    busy += sum - idle;
    total += sum;
  }
  return total ? { busy, total } : null;
}

// How busy the machine was between two readings, or null when the pair can't
// say: the first sample, a counter reset, or no time passed.
function cpuPercent(before, after) {
  if (!before || !after) return null;
  const busy = after.busy - before.busy;
  const total = after.total - before.total;
  if (total <= 0 || busy < 0) return null;
  return Math.round(Math.min(100, (100 * busy) / total) * 10) / 10;
}

// MemTotal/MemAvailable/Swap from /proc/meminfo, in whole megabytes.
//
// Used is total - MemAvailable, never total - MemFree. Page cache is not
// pressure, and counting it as used makes every healthy Linux box look full —
// which is also why os.freemem() is not used here: on Linux it is MemFree.
function memoryMb(text) {
  const values = {};
  for (const line of String(text).split("\n")) {
    const [name, rest] = line.split(":");
    const kb = Number(String(rest || "").trim().split(/\s+/)[0]);
    if (name && Number.isFinite(kb)) values[name] = Math.floor(kb / 1024);
  }
  const out = {};
  if (values.MemTotal) {
    out.mem_total_mb = values.MemTotal;
    if (values.MemAvailable !== undefined) out.mem_used_mb = Math.max(0, values.MemTotal - values.MemAvailable);
  }
  if (values.SwapTotal !== undefined) {
    out.swap_total_mb = values.SwapTotal;
    if (values.SwapFree !== undefined) out.swap_used_mb = Math.max(0, values.SwapTotal - values.SwapFree);
  }
  return out;
}

// Where this machine keeps its filesystems. On Linux that's /proc/mounts; off
// it, the one filesystem the application is running from, which is the only
// one we can name without guessing.
// Whether a mount point is a directory, never throwing: a path this process
// cannot stat is simply unconfirmed, and mountPoints falls back to the
// device's shortest mount rather than dropping the disk.
function defaultIsDir(point) {
  try {
    return fs.statSync(point).isDirectory();
  } catch {
    return false;
  }
}

// A mount point has to be a directory. Docker bind-mounts single files, so a
// container lists /etc/hosts, /etc/hostname and /etc/resolv.conf on the host's
// own device, and those paths are short enough to win the shortest-path race
// against the real mount. The test is per-device and advisory: a device whose
// mounts cannot be confirmed keeps its shortest one, because reporting no
// disks is worse than reporting an odd mount point.
function mountPoints(mountsText, platform = process.platform, isDir = defaultIsDir) {
  if (platform !== "linux") return [path.parse(process.cwd()).root || "/"];
  const dirs = new Map();
  const any = new Map();
  for (const line of String(mountsText).split("\n")) {
    const [device, mount, fstype] = line.split(/\s+/);
    if (!device || !mount || !FSTYPES.has(fstype) || !mount.startsWith("/")) continue;
    const point = mount.replace(/\\040/g, " ");
    // The shortest path wins: "/" over "/var" for one device, so a bind mount
    // isn't reported as a second disk.
    if (!any.has(device) || point.length < any.get(device).length) any.set(device, point);
    if (isDir(point) && (!dirs.has(device) || point.length < dirs.get(device).length)) dirs.set(device, point);
  }
  const points = [...any].map(([device, point]) => dirs.get(device) ?? point);
  return [...new Set(points)].sort();
}

// Both figures are df's, so a customer can check them: used is total minus
// free, and total is used plus what's available to us. The blocks reserved for
// root are in neither, which is what makes used/total the percentage df prints
// — and that percentage is what the disk alert is about.
function diskRows(points, statfs = fs.statfsSync) {
  if (typeof statfs !== "function") return [];
  // One filesystem can sit behind two devices the kernel calls different: in a
  // container / is the overlay and a bind mount exposes the host disk the
  // overlay's upperdir lives on, so both report the same size and the same
  // free space down to the byte. No device-based rule separates them, so the
  // sizes are what gives it away. Raw bytes, not rounded megabytes, so disks
  // that merely round alike stay apart; two separate but identically sized and
  // identically empty filesystems do collapse into one until something is
  // written to either, and being empty they owe the fullness alert nothing.
  const seen = new Set();
  const rows = [];
  for (const mount of points) {
    let st;
    try {
      st = statfs(mount);
    } catch {
      continue;
    }
    const block = Number(st.bsize) || 0;
    const blocks = Number(st.blocks) || 0;
    if (!block || !blocks) continue;
    const used = Math.max(0, blocks - Number(st.bfree || 0)) * block;
    const total = used + Number(st.bavail || 0) * block;
    const row = { mount, total_mb: Math.floor(total / MB), used_mb: Math.floor(used / MB) };
    if (row.total_mb < MIN_DISK_MB) continue;
    // points arrives sorted, so the shortest path wins the collision.
    const key = `${total}:${used}`;
    if (seen.has(key)) continue;
    seen.add(key);
    // A filesystem can refuse a write with gigabytes free once these meet.
    const nodes = Number(st.files) || 0;
    if (nodes) {
      row.inodes_total = nodes;
      row.inodes_used = Math.max(0, nodes - (Number(st.ffree) || 0));
    }
    rows.push(row);
    if (rows.length >= MAX_DISKS) break;
  }
  return rows;
}

// Sectors in /proc/diskstats are always 512 bytes: it is the unit of that
// interface, not of the drive.
const IO_SECTOR = 512;
// Two readings further apart than this say nothing about this minute.
const IO_MAX_PAIR_MS = 300 * 1000;
// Not disks: loop and ram devices, optical drives, device-mapper and md, each
// of which would count the devices underneath it a second time.
const NOT_A_DISK = /^(?:loop|ram|zram|sr|fd|dm-|md\d)/;
// Partitions, which must not be counted alongside the disk they sit on.
const PARTITION = /^(?:(?:sd|vd|xvd|hd)[a-z]+\d+|(?:nvme\d+n\d+|mmcblk\d+)p\d+)$/;
// Loopback, and the virtual ends of container and VM networking: counting
// these would count someone else's traffic, or ours twice.
const NOT_REAL_NET = /^(?:lo|veth|docker|br-|virbr|tap|tun|vnet)/;

// The jiffie counters from /proc/stat's first line, or null. In order: user,
// nice, system, idle, iowait, irq, softirq, steal. Linux only — os.cpus()
// carries no iowait and no steal, which are the two worth having.
function cpuFields(text) {
  for (const line of String(text).split("\n")) {
    if (!line.startsWith("cpu ")) continue;
    const fields = line.trim().split(/\s+/).slice(1).map(Number);
    if (fields.length < 4 || fields.some((value) => !Number.isFinite(value))) return null;
    return fields;
  }
  return null;
}

// user folds nice in, as top adds them together. Each is a share of the whole
// interval, so with idle and the interrupt buckets they come to 100.
const CPU_SHARES = [
  ["cpu_user_pct", [0, 1]],
  ["cpu_system_pct", [2]],
  ["cpu_iowait_pct", [4]],
  ["cpu_steal_pct", [7]],
];

// Where the machine's time went between two readings. A column the kernel is
// too old to carry is left out rather than sent as a zero. steal is the one
// worth surfacing: time the hypervisor gave to another tenant, which no amount
// of tuning the app will change.
function cpuShares(before, after) {
  if (!before || !after) return {};
  const total = after.reduce((sum, v) => sum + v, 0) - before.reduce((sum, v) => sum + v, 0);
  if (total <= 0) return {};
  const out = {};
  for (const [name, columns] of CPU_SHARES) {
    if (columns.some((i) => i >= before.length || i >= after.length)) continue;
    const moved = columns.reduce((sum, i) => sum + (after[i] - before[i]), 0);
    if (moved < 0) return {};
    out[name] = Math.round(Math.min(100, (100 * moved) / total) * 10) / 10;
  }
  return out;
}

// Bytes read and written since boot over the real disks, or null.
function diskCounters(text) {
  let read_ = 0;
  let written = 0;
  let found = false;
  for (const line of String(text).split("\n")) {
    const fields = line.trim().split(/\s+/);
    if (fields.length < 10) continue;
    const name = fields[2];
    if (!name || NOT_A_DISK.test(name) || PARTITION.test(name)) continue;
    const sectorsRead = Number(fields[5]);
    const sectorsWritten = Number(fields[9]);
    if (!Number.isFinite(sectorsRead) || !Number.isFinite(sectorsWritten)) continue;
    read_ += sectorsRead * IO_SECTOR;
    written += sectorsWritten * IO_SECTOR;
    found = true;
  }
  return found ? [read_, written] : null;
}

// Bytes in and out since boot over the real interfaces, or null.
function netCounters(text) {
  let rx = 0;
  let tx = 0;
  let found = false;
  for (const line of String(text).split("\n")) {
    const at = line.indexOf(":");
    if (at < 0) continue;
    const name = line.slice(0, at).trim();
    if (!name || NOT_REAL_NET.test(name)) continue;
    const fields = line.slice(at + 1).trim().split(/\s+/).map(Number);
    if (fields.length < 9) continue;
    if (!Number.isFinite(fields[0]) || !Number.isFinite(fields[8])) continue;
    rx += fields[0];
    tx += fields[8];
    found = true;
  }
  return found ? [rx, tx] : null;
}

// Megabytes a second between two byte counters, or null when the pair can't
// say: no pair, a reboot that reset them, no time, or too long a gap.
function rateMbs(before, after, ms) {
  if (before === null || before === undefined || after === null || after === undefined) return null;
  if (!(ms > 0) || ms > IO_MAX_PAIR_MS) return null;
  const moved = after - before;
  if (moved < 0) return null;
  return Math.round((moved / (ms / 1000) / MB) * 10) / 10;
}

function createResources(core, options = {}) {
  const log = (...args) => core.log("resources", ...args);
  const serverName = String(options.serverName ?? os.hostname()).slice(0, 100);
  const runtime = `Node ${process.versions.node}`;
  // minute (ISO) -> row, so a minute sampled twice is kept once.
  const rows = new Map();
  let lastCpu = cpuTimes();
  let lastFields = cpuFields(read("/proc/stat"));
  let lastDisk = diskCounters(read("/proc/diskstats"));
  let lastNet = netCounters(read("/proc/net/dev"));
  // The limits pass (limits.js): the cgroup is found once, its counters and
  // the listen-queue count are read every sample and diffed like CPU.
  const cgroup = limits.findCgroup(read);
  let lastCgroup = limits.cgroupReading(cgroup, read);
  let lastOverflows = limits.listenOverflows(read("/proc/net/netstat"));
  const gc = limits.gcTimer();
  // Requests in progress at once, from the performance module when its
  // middleware is in use (index.js wires it); null until then.
  let inflightPeak = () => null;
  // This process among others of the same name: cluster or worker processes
  // each send their own, so a read can tell siblings from resent copies.
  const procKey = crypto.randomBytes(6).toString("hex");
  let lastAt = Date.now();
  let every = EVERY_S;
  let sampleTimer = null;
  let postTimer = null;
  let closed = false;
  let loop = null;
  // The event loop's own delay: how long the application itself was blocked,
  // which no outside measurement of the machine can see.
  try {
    const { monitorEventLoopDelay } = require("node:perf_hooks");
    if (typeof monitorEventLoopDelay === "function") {
      loop = monitorEventLoopDelay({ resolution: 20 });
      loop.enable();
    }
  } catch {
    loop = null;
  }

  // One sample, covering the time since the last one.
  function sample(at = Date.now()) {
    const cpu = cpuTimes();
    const percent = cpuPercent(lastCpu, cpu);
    const elapsed = at - lastAt;
    // Everything below needs two readings, like cpu_pct does.
    const fields = cpuFields(read("/proc/stat"));
    const disk = diskCounters(read("/proc/diskstats"));
    const net = netCounters(read("/proc/net/dev"));
    // The minute the interval started in, not the one it ended in.
    const row = { minute: new Date(Math.floor(lastAt / 60000) * 60000).toISOString(), proc_key: procKey };
    lastCpu = cpu;
    lastAt = at;
    if (percent !== null && elapsed >= MIN_CPU_MS) row.cpu_pct = percent;
    const cores = os.cpus()?.length;
    if (cores) row.cpu_cores = cores;
    const load = os.loadavg?.() || [];
    // Windows has no load average and reports zeroes; sending them would be a
    // measurement we never took.
    if (load.length === 3 && load.some((value) => value > 0)) {
      row.load1 = Math.round(load[0] * 100) / 100;
      row.load5 = Math.round(load[1] * 100) / 100;
      row.load15 = Math.round(load[2] * 100) / 100;
    }
    const memory = memoryMb(read("/proc/meminfo"));
    if (memory.mem_total_mb) {
      Object.assign(row, memory);
    } else if (os.totalmem()) {
      // Off Linux: os.freemem() is the best this platform offers.
      row.mem_total_mb = Math.floor(os.totalmem() / MB);
      row.mem_used_mb = Math.max(0, Math.floor((os.totalmem() - os.freemem()) / MB));
    }
    const disks = diskRows(mountPoints(read("/proc/mounts")));
    if (disks.length) row.disks = disks;
    Object.assign(row, cpuShares(lastFields, fields));
    const rates = {
      disk_read_mbs: lastDisk && disk ? rateMbs(lastDisk[0], disk[0], elapsed) : null,
      disk_write_mbs: lastDisk && disk ? rateMbs(lastDisk[1], disk[1], elapsed) : null,
      net_rx_mbs: lastNet && net ? rateMbs(lastNet[0], net[0], elapsed) : null,
      net_tx_mbs: lastNet && net ? rateMbs(lastNet[1], net[1], elapsed) : null,
    };
    for (const [name, value] of Object.entries(rates)) {
      if (value !== null) row[name] = value;
    }
    lastFields = fields;
    lastDisk = disk;
    lastNet = net;
    const rss = process.memoryUsage?.().rss;
    if (rss) row.proc_rss_mb = Math.max(1, Math.floor(rss / MB));
    if (loop) {
      row.loop_lag_ms = Math.round((loop.mean / 1e6) * 100) / 100;
      loop.reset();
    }
    const up = os.uptime?.();
    if (Number.isFinite(up) && up > 0) row.host_uptime_s = Math.floor(up);
    Object.assign(row, limitsRow(row));
    rows.set(row.minute, row);
    // Oldest first out: a long outage keeps the recent minutes.
    while (rows.size > MAX_ROWS) rows.delete(rows.keys().next().value);
    return row;
  }

  // The limits pass for one sample: caps and counters diffed against the
  // previous sample's, the rest read once.
  function limitsRow(row) {
    const out = { proc_uptime_s: Math.floor(process.uptime()) };
    const reading = limits.cgroupReading(cgroup, read);
    Object.assign(out, limits.cgroupFields(lastCgroup, reading, { memTotalMb: row.mem_total_mb, cores: row.cpu_cores }));
    lastCgroup = reading;
    Object.assign(out, limits.pressureFields(read));
    const overflows = limits.listenOverflows(read("/proc/net/netstat"));
    const drops = limits.countSince(lastOverflows, overflows);
    if (drops !== null) out.listen_drops = drops;
    lastOverflows = overflows;
    const conntrack = limits.conntrackPct(read);
    if (conntrack !== null) out.conntrack_pct = conntrack;
    Object.assign(out, limits.fileFields(read));
    Object.assign(out, limits.heapFields(v8.getHeapStatistics?.()));
    const gcMs = gc.take();
    if (gcMs !== null) out.gc_ms = gcMs;
    const peak = inflightPeak();
    if (Number.isInteger(peak) && peak >= 0) out.inflight_peak = peak;
    return out;
  }

  // Sends what's buffered. Rows are kept only when the collector couldn't take
  // them and retrying may work.
  async function flush() {
    if (!rows.size) return true;
    const batch = [...rows.keys()].sort();
    const body = { site_id: core.siteId, server_name: serverName, runtime, rows: batch.map((minute) => rows.get(minute)) };
    const res = await core.send("resources", "/events/resources", { auth: "bearer", body });
    if (!res) return false;
    if (res.ok) {
      const data = await res.json().catch(() => null);
      if (Number(data?.every) > 0) every = Math.max(RETRY_S, Number(data.every));
      if (data?.enabled === false) log("server resources are off in the dashboard (Security → Server package)");
      for (const minute of batch) rows.delete(minute);
      return true;
    }
    // Unreachable or storage down: these rows are still good. A 4xx means
    // resending won't make them acceptable.
    if (res.status >= 500) return false;
    log("collector answered %s to the resources report", res.status);
    for (const minute of batch) rows.delete(minute);
    return true;
  }

  async function report() {
    let wait = every;
    try {
      if (core.isOn("resources")) {
        if (!(await flush())) wait = RETRY_S;
      } else {
        // Switched off: keep nothing, and ask again later.
        rows.clear();
        wait = Math.max(600, every);
      }
    } catch (error) {
      log("could not send the resources report:", error?.message);
      wait = RETRY_S;
    }
    schedule(wait * 1000);
  }

  function schedule(ms) {
    if (closed) return;
    postTimer = setTimeout(report, ms);
    postTimer.unref?.();
  }

  if (core.valid) {
    sampleTimer = setInterval(() => {
      try {
        sample();
      } catch (error) {
        log("could not sample the machine:", error?.message);
      }
    }, SAMPLE_MS);
    sampleTimer.unref?.();
    schedule(EVERY_S * 1000);
  }

  return {
    // One sample now (for your own checks and tests).
    sample,
    // Send what's buffered now.
    flush,
    report,
    // The performance module's peak of requests in progress (index.js).
    useInflight(fn) {
      inflightPeak = typeof fn === "function" ? fn : () => null;
    },
    close() {
      closed = true;
      clearInterval(sampleTimer);
      clearTimeout(postTimer);
      loop?.disable?.();
      gc.stop();
      return flush().catch(() => false);
    },
  };
}

module.exports = {
  createResources, cpuTimes, cpuPercent, memoryMb, mountPoints, diskRows, MIN_DISK_MB,
  cpuFields, cpuShares, diskCounters, netCounters, rateMbs,
};
