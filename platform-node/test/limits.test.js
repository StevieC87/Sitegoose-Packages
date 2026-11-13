// How close the app is to a wall (lib/limits.js, protocol "Limits"): the
// container's caps, waiting time, refused connections and process limits.
// Everything is read through a fake file reader, so no cgroup is needed.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const limits = require("../lib/limits.js");
const { createPerformance } = require("../lib/performance.js");
const { EventEmitter } = require("node:events");

const MB = 1024 * 1024;
const files = (map) => (file) => map[file] ?? "";

test("a v2 container is found at the mount itself, a host service under its path", () => {
  const inContainer = files({
    "/proc/self/cgroup": "0::/\n",
    "/sys/fs/cgroup/memory.current": "1000\n",
  });
  assert.deepEqual(limits.findCgroup(inContainer), { version: 2, memory: "/sys/fs/cgroup", cpu: "/sys/fs/cgroup" });
  const service = files({
    "/proc/self/cgroup": "0::/system.slice/app.service\n",
    "/sys/fs/cgroup/system.slice/app.service/memory.current": "1000\n",
  });
  assert.equal(limits.findCgroup(service).memory, "/sys/fs/cgroup/system.slice/app.service");
});

test("a hybrid machine with no v2 controllers reads its limits from v1", () => {
  const hybrid = files({
    "/proc/self/cgroup": "12:memory:/docker/abc\n4:cpu,cpuacct:/docker/abc\n0::/docker/abc\n",
    "/sys/fs/cgroup/memory/memory.usage_in_bytes": "5\n",
    "/sys/fs/cgroup/cpu/cpu.cfs_quota_us": "-1\n",
  });
  assert.deepEqual(limits.findCgroup(hybrid), { version: 1, memory: "/sys/fs/cgroup/memory", cpu: "/sys/fs/cgroup/cpu" });
  assert.equal(limits.findCgroup(files({})), null);
});

const v2 = (over = {}) => files({
  "/c/memory.max": `${512 * MB}\n`,
  "/c/memory.current": `${400 * MB}\n`,
  "/c/memory.stat": `anon ${200 * MB}\ninactive_file ${150 * MB}\n`,
  "/c/memory.events": "low 0\nhigh 0\nmax 3\noom 1\noom_kill 1\n",
  "/c/cpu.max": "150000 100000\n",
  "/c/cpu.stat": "usage_usec 10\nnr_periods 1000\nnr_throttled 100\n",
  ...over,
});
const CG = { version: 2, memory: "/c", cpu: "/c" };

test("container memory is the working set against its cap, and CPU throttling is a share of periods", () => {
  const before = limits.cgroupReading(CG, v2());
  const after = limits.cgroupReading(CG, v2({
    "/c/memory.events": "oom_kill 3\n",
    "/c/cpu.stat": "nr_periods 1600\nnr_throttled 250\n",
  }));
  const row = limits.cgroupFields(before, after, { memTotalMb: 8000, cores: 4 });
  // 400 MB current less 150 MB of inactive cache.
  assert.equal(row.limit_mem_mb, 512);
  assert.equal(row.limit_mem_used_mb, 250);
  assert.equal(row.limit_cpu_cores, 1.5);
  assert.equal(row.cpu_throttled_pct, 25);
  assert.equal(row.oom_kills, 2);
});

test("a cap that isn't one is left out, and one reading gives no counts", () => {
  const open = limits.cgroupReading(CG, v2({ "/c/memory.max": "max\n", "/c/cpu.max": "max 100000\n" }));
  const row = limits.cgroupFields(null, open, { memTotalMb: 8000, cores: 4 });
  assert.equal(row.limit_mem_mb, undefined);
  assert.equal(row.limit_mem_used_mb, undefined);
  assert.equal(row.limit_cpu_cores, undefined);
  assert.equal(row.cpu_throttled_pct, undefined);
  assert.equal(row.oom_kills, undefined);
  // A cap bigger than the machine (or v1's "unlimited") is no cap either.
  const big = limits.cgroupReading(CG, v2({ "/c/memory.max": `${16000 * MB}\n` }));
  assert.equal(limits.cgroupFields(null, big, { memTotalMb: 8000 }).limit_mem_mb, undefined);
  const v1 = files({ "/m/memory.limit_in_bytes": "9223372036854771712\n", "/m/memory.usage_in_bytes": "100\n" });
  const reading = limits.cgroupReading({ version: 1, memory: "/m", cpu: null }, v1);
  assert.equal(limits.cgroupFields(null, reading, {}).limit_mem_mb, undefined);
});

test("a counter that went down was reset, and says nothing", () => {
  assert.equal(limits.countSince(5, 3), null);
  assert.equal(limits.countSince(null, 3), null);
  assert.equal(limits.countSince(3, 3), 0);
});

test("waiting time is the some line's avg60, and a kernel without PSI sends none", () => {
  const text = "some avg10=1.50 avg60=12.34 avg300=3.00 total=123\nfull avg10=0.00 avg60=9.00 avg300=0.00 total=1\n";
  assert.equal(limits.pressureSome(text), 12.3);
  assert.deepEqual(limits.pressureFields(files({ "/proc/pressure/io": text })), { psi_io_pct: 12.3 });
  assert.deepEqual(limits.pressureFields(files({})), {});
});

test("refused connections come from TcpExt ListenOverflows", () => {
  const netstat = "TcpExt: SyncookiesSent ListenOverflows ListenDrops\nTcpExt: 0 17 20\nIpExt: InOctets\nIpExt: 5\n";
  assert.equal(limits.listenOverflows(netstat), 17);
  assert.equal(limits.listenOverflows("IpExt: a\nIpExt: 1\n"), null);
  assert.equal(limits.conntrackPct(files({
    "/proc/sys/net/netfilter/nf_conntrack_count": "300\n", "/proc/sys/net/netfilter/nf_conntrack_max": "1200\n",
  })), 25);
  assert.equal(limits.conntrackPct(files({})), null);
});

test("open files against the soft limit, and unlimited is no limit", () => {
  const limitsText = "Limit                     Soft Limit           Hard Limit           Units\nMax open files            1024                 1048576              files\n";
  assert.equal(limits.fdLimit(limitsText), 1024);
  assert.equal(limits.fdLimit("Max open files            unlimited            unlimited            files\n"), null);
  // Eleven entries, one of them the listing's own.
  assert.deepEqual(limits.fileFields(files({ "/proc/self/limits": limitsText }), () => new Array(11)), { fds_used: 10, fds_max: 1024 });
  assert.deepEqual(limits.fileFields(files({}), () => { throw new Error("no /proc"); }), {});
});

test("the heap is reported against the limit V8 will stop at", () => {
  assert.deepEqual(limits.heapFields({ used_heap_size: 300 * MB, heap_size_limit: 2048 * MB }), { heap_used_mb: 300, heap_max_mb: 2048 });
  assert.deepEqual(limits.heapFields(null), {});
});

function fakeResponse() {
  const res = new EventEmitter();
  res.statusCode = 200;
  return res;
}

test("requests in progress peak per interval, and there is no peak until the middleware runs", () => {
  const perf = createPerformance({ valid: false, log() {} }, { timer: false });
  assert.equal(perf.takeInflightPeak(), null);
  const a = fakeResponse();
  const b = fakeResponse();
  const c = fakeResponse();
  perf.middleware({ method: "GET", url: "/a" }, a);
  perf.middleware({ method: "GET", url: "/b" }, b);
  perf.middleware({ method: "GET", url: "/c" }, c);
  a.emit("finish");
  a.emit("close");
  // A dropped request ends on close alone.
  b.emit("close");
  assert.equal(perf.takeInflightPeak(), 3);
  // The next interval starts from what is still running.
  assert.equal(perf.takeInflightPeak(), 1);
  c.emit("finish");
  c.emit("close");
  assert.equal(perf.takeInflightPeak(), 1);
  assert.equal(perf.takeInflightPeak(), 0);
});
