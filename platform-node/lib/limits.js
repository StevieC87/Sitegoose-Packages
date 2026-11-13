// How close the app is to a wall, for the resources module (protocol in
// sdk/protocols/resources.md, "Limits"): its container's own caps, the
// machine's waiting time, connections refused before the app saw them, and
// the process's open files, heap and garbage collection.
//
// The rest of resources.js says how busy the machine is. Inside Docker or
// Kubernetes that is the wrong question: /proc/meminfo is the host's, so
// memory reads 40% while the container is a few megabytes from being killed.
// The cgroup's files are the limits the kernel actually enforces.
//
// Same rule as the rest of the module: a figure this machine won't give us is
// left out of the row, never sent as a zero. Every reader here returns null
// for a file that isn't there, which on anything but Linux is all of them.
"use strict";

const fs = require("node:fs");

const MB = 1024 * 1024;
// cgroup v1 says "no limit" with the largest page-aligned 64-bit number; v2
// says "max". Anything this size is not a cap a machine has.
const NO_LIMIT_BYTES = 2 ** 62;

const read = (file) => {
  try {
    return fs.readFileSync(file, "utf8");
  } catch {
    return "";
  }
};
const round1 = (value) => Math.round(value * 10) / 10;
const round2 = (value) => Math.round(value * 100) / 100;

// A number from a file holding one, or null for a missing or unreadable one.
// Number("") is 0, which is exactly the zero this module must never invent.
function num(text) {
  const trimmed = String(text ?? "").trim();
  if (!trimmed) return null;
  const value = Number(trimmed);
  return Number.isFinite(value) ? value : null;
}

// "name value" lines (memory.stat, cpu.stat, memory.events) as numbers.
function keyValues(text) {
  const out = {};
  for (const line of String(text).split("\n")) {
    const [name, value] = line.trim().split(/\s+/);
    const n = num(value);
    if (name && n !== null) out[name] = n;
  }
  return out;
}

// /proc/self/cgroup: the v2 path ("0::<path>") and the v1 memory and cpu
// controllers' paths ("4:memory:<path>", "3:cpu,cpuacct:<path>").
function cgroupPaths(text) {
  const out = { v2: null, memory: null, cpu: null };
  for (const line of String(text).split("\n")) {
    const first = line.indexOf(":");
    const second = line.indexOf(":", first + 1);
    if (first < 0 || second < 0) continue;
    const id = line.slice(0, first);
    const controllers = line.slice(first + 1, second).split(",");
    const at = line.slice(second + 1).trim();
    if (!at) continue;
    if (id === "0" && controllers.join("") === "") out.v2 = at;
    if (controllers.includes("memory")) out.memory = at;
    if (controllers.includes("cpu")) out.cpu = at;
  }
  return out;
}

// Where this process's cgroup files are, or null. Under the mount at the path
// /proc/self/cgroup names first, then the mount itself: in a container with
// its own cgroup namespace the path is "/" and the mount is already the
// container's; without one the path names the host's hierarchy.
//
// v2 needs the memory or cpu controller's own files, not just the directory:
// a hybrid machine lists a v2 path with no controllers in it while the limits
// live in v1, and stopping at v2 there would report no limits at all.
function findCgroup(readFn = read) {
  const paths = cgroupPaths(readFn("/proc/self/cgroup"));
  const under = (base, at, probes) => {
    for (const dir of at && at !== "/" ? [base + at, base] : [base]) {
      if (probes.some((probe) => readFn(`${dir}/${probe}`))) return dir;
    }
    return null;
  };
  if (paths.v2 !== null) {
    const dir = under("/sys/fs/cgroup", paths.v2, ["memory.current", "cpu.max"]);
    if (dir) return { version: 2, memory: dir, cpu: dir };
  }
  const memory = paths.memory !== null ? under("/sys/fs/cgroup/memory", paths.memory, ["memory.usage_in_bytes"]) : null;
  const cpu = paths.cpu !== null ? under("/sys/fs/cgroup/cpu", paths.cpu, ["cpu.cfs_quota_us"]) : null;
  return memory || cpu ? { version: 1, memory, cpu } : null;
}

// One reading of the cgroup's caps and counters, in bytes and raw counts.
// Counters (periods, throttled, oom) need two readings; cgroupFields diffs them.
function cgroupReading(cg, readFn = read) {
  if (!cg) return null;
  const out = { memCap: null, memUsed: null, cpuCores: null, periods: null, throttled: null, oom: null };
  if (cg.version === 2) {
    const max = readFn(`${cg.memory}/memory.max`).trim();
    out.memCap = max === "max" ? null : num(max);
    const current = num(readFn(`${cg.memory}/memory.current`));
    // The working set: page cache counts against the cgroup too, so
    // memory.current sits near the cap on a healthy container that reads
    // files. Less inactive_file is what Docker and the kubelet report.
    const stat = keyValues(readFn(`${cg.memory}/memory.stat`));
    if (current !== null) out.memUsed = Math.max(0, current - (stat.inactive_file || 0));
    out.oom = keyValues(readFn(`${cg.memory}/memory.events`)).oom_kill ?? null;
    const [quota, period] = readFn(`${cg.cpu}/cpu.max`).trim().split(/\s+/);
    if (quota && quota !== "max" && num(period) > 0 && num(quota) > 0) out.cpuCores = num(quota) / num(period);
    const cpu = keyValues(readFn(`${cg.cpu}/cpu.stat`));
    out.periods = cpu.nr_periods ?? null;
    out.throttled = cpu.nr_throttled ?? null;
    return out;
  }
  if (cg.memory) {
    out.memCap = num(readFn(`${cg.memory}/memory.limit_in_bytes`));
    const usage = num(readFn(`${cg.memory}/memory.usage_in_bytes`));
    const stat = keyValues(readFn(`${cg.memory}/memory.stat`));
    if (usage !== null) out.memUsed = Math.max(0, usage - (stat.total_inactive_file || 0));
    // Kernels from 4.13 carry the count here.
    out.oom = keyValues(readFn(`${cg.memory}/memory.oom_control`)).oom_kill ?? null;
  }
  if (cg.cpu) {
    const quota = num(readFn(`${cg.cpu}/cpu.cfs_quota_us`));
    const period = num(readFn(`${cg.cpu}/cpu.cfs_period_us`));
    if (quota > 0 && period > 0) out.cpuCores = quota / period;
    const cpu = keyValues(readFn(`${cg.cpu}/cpu.stat`));
    out.periods = cpu.nr_periods ?? null;
    out.throttled = cpu.nr_throttled ?? null;
  }
  return out;
}

// How much a counter moved between two readings, or null: no pair, or it went
// down, which is a reset and not a negative count. Unlike a rate a count is
// never dropped for the pair being far apart — a kill is a kill.
function countSince(before, after) {
  if (before === null || before === undefined || after === null || after === undefined) return null;
  return after >= before ? after - before : null;
}

// The row's cgroup fields from two readings. A cap at or above what the
// machine itself has isn't one (a systemd slice with no MemoryMax, or a
// container allowed more cores than the host), so neither half is sent.
function cgroupFields(before, after, { memTotalMb = null, cores = null } = {}) {
  const out = {};
  if (!after) return out;
  const capMb = after.memCap > 0 && after.memCap < NO_LIMIT_BYTES ? Math.floor(after.memCap / MB) : null;
  if (capMb && !(memTotalMb && capMb >= memTotalMb) && after.memUsed !== null) {
    out.limit_mem_mb = capMb;
    out.limit_mem_used_mb = Math.min(capMb, Math.floor(after.memUsed / MB));
  }
  if (after.cpuCores && !(cores && after.cpuCores >= cores)) out.limit_cpu_cores = round2(after.cpuCores);
  // Periods only pass while a quota is set, so no cap means nothing sent.
  const periods = countSince(before?.periods, after.periods);
  const throttled = countSince(before?.throttled, after.throttled);
  if (periods > 0 && throttled !== null) out.cpu_throttled_pct = round1(Math.min(100, (100 * throttled) / periods));
  // Kills of other processes in this cgroup. This process's own kill can't
  // be reported by it: see the protocol.
  const oom = countSince(before?.oom, after.oom);
  if (oom !== null) out.oom_kills = oom;
  return out;
}

// /proc/pressure/<resource>'s "some" line, avg60: the share of the last
// minute in which at least one task was waiting. One reading is enough.
function pressureSome(text) {
  const match = /^some\b[^\n]*\bavg60=([\d.]+)/m.exec(String(text));
  return match ? round1(Math.min(100, Number(match[1]))) : null;
}

function pressureFields(readFn = read) {
  const out = {};
  for (const [name, file] of [["psi_cpu_pct", "cpu"], ["psi_mem_pct", "memory"], ["psi_io_pct", "io"]]) {
    const value = pressureSome(readFn(`/proc/pressure/${file}`));
    if (value !== null) out[name] = value;
  }
  return out;
}

// TcpExt ListenOverflows from /proc/net/netstat: connections refused since
// boot because the accept queue was full. A header line and a value line.
function listenOverflows(text) {
  const lines = String(text).split("\n");
  for (let i = 0; i + 1 < lines.length; i += 1) {
    if (!lines[i].startsWith("TcpExt:") || !lines[i + 1].startsWith("TcpExt:")) continue;
    const at = lines[i].trim().split(/\s+/).indexOf("ListenOverflows");
    return at > 0 ? num(lines[i + 1].trim().split(/\s+/)[at]) : null;
  }
  return null;
}

// How full the connection-tracking table is. Only where the firewall loaded
// it, and usually unreadable inside a container.
function conntrackPct(readFn = read) {
  const count = num(readFn("/proc/sys/net/netfilter/nf_conntrack_count"));
  const max = num(readFn("/proc/sys/net/netfilter/nf_conntrack_max"));
  return count !== null && max > 0 ? round1(Math.min(100, (100 * count) / max)) : null;
}

// The soft "Max open files" from /proc/self/limits, or null when unlimited.
function fdLimit(text) {
  const match = /^Max open files\s+(\S+)/m.exec(String(text));
  return match ? num(match[1]) : null;
}

// Open descriptors of this process, less the one listing them takes.
function openFiles(list = () => fs.readdirSync("/proc/self/fd")) {
  try {
    return Math.max(0, list().length - 1);
  } catch {
    return null;
  }
}

function fileFields(readFn = read, list) {
  const out = {};
  const used = openFiles(list);
  const max = fdLimit(readFn("/proc/self/limits"));
  if (used !== null) out.fds_used = max > 0 ? Math.min(used, max) : used;
  if (max > 0) out.fds_max = max;
  return out;
}

// V8's heap against the limit it will die at (--max-old-space-size or its
// default), which is a different wall from the container's.
function heapFields(stats) {
  const used = Number(stats?.used_heap_size);
  const limit = Number(stats?.heap_size_limit);
  if (!(used > 0) || !(limit > 0)) return {};
  return { heap_used_mb: Math.floor(used / MB), heap_max_mb: Math.floor(limit / MB) };
}

// Time spent in garbage collection, summed from V8's gc entries. take() hands
// over what accumulated since the last call; null where perf_hooks can't
// observe gc, so a process that can't measure it never reports 0.
function gcTimer() {
  let total = 0;
  let observer = null;
  try {
    const { PerformanceObserver } = require("node:perf_hooks");
    observer = new PerformanceObserver((list) => {
      for (const entry of list.getEntries()) total += entry.duration;
    });
    observer.observe({ entryTypes: ["gc"] });
  } catch {
    observer = null;
  }
  return {
    take() {
      if (!observer) return null;
      const ms = round1(total);
      total = 0;
      return ms;
    },
    stop() {
      observer?.disconnect();
    },
  };
}

module.exports = {
  cgroupPaths, findCgroup, cgroupReading, cgroupFields, countSince, pressureSome, pressureFields,
  listenOverflows, conntrackPct, fdLimit, openFiles, fileFields, heapFields, gcTimer,
};
