// The resources module: what is read from the machine, and the rule the whole
// feature rests on — a reading this machine won't give is left out of the row,
// never sent as a zero (sdk/protocols/resources.md).
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const {
  createResources, cpuTimes, cpuPercent, memoryMb, mountPoints, diskRows,
  cpuShares, diskCounters, netCounters, rateMbs,
} = require("../lib/resources.js");

const MEMINFO = [
  "MemTotal:        8143868 kB",
  "MemFree:          210000 kB",
  "MemAvailable:    5021228 kB",
  "Cached:          4000000 kB",
  "SwapTotal:       2097152 kB",
  "SwapFree:        2084864 kB",
  "",
].join("\n");

// A core that records what would be sent instead of sending it.
function fakeCore(answer = { ok: true, status: 202, body: { v: 1, enabled: true, every: 300, stored: 1 } }) {
  const sent = [];
  return {
    sent,
    siteId: "a".repeat(24),
    valid: false, // no background timers in tests; sample()/flush() are called directly
    isOn: () => true,
    log: () => {},
    send: async (module, path, options) => {
      sent.push({ module, path, auth: options.auth, body: options.body });
      return { ...answer, json: async () => answer.body };
    },
  };
}

test("CPU needs two readings, and ignores the time the machine was idle", () => {
  const cpus = (idle, user) => [{ times: { user, nice: 0, sys: 0, idle, irq: 0 } }];
  const before = cpuTimes(cpus(1000, 100));
  assert.deepEqual(before, { busy: 100, total: 1100 });
  // One reading alone can say nothing.
  assert.equal(cpuPercent(null, before), null);
  assert.equal(cpuPercent(before, before), null);
  // 100 busy out of the 200 that passed.
  assert.equal(cpuPercent(before, { busy: 200, total: 1300 }), 50);
  // A counter that went backwards (a reboot) says nothing either.
  assert.equal(cpuPercent({ busy: 200, total: 1300 }, before), null);
  // No cores at all is not zero per cent.
  assert.equal(cpuTimes([]), null);
});

test("memory used is total minus available, not total minus free", () => {
  const memory = memoryMb(MEMINFO);
  assert.equal(memory.mem_total_mb, 7952);
  // 7952 - 4903 available. MemFree would claim 7747 MB used and make a
  // healthy machine look full.
  assert.equal(memory.mem_used_mb, 3049);
  assert.equal(memory.swap_total_mb, 2048);
  assert.equal(memory.swap_used_mb, 12);
});

test("a field the kernel did not give is left out, not sent as nought", () => {
  assert.deepEqual(memoryMb("MemTotal: 8143868 kB\nMemFree: 210000 kB\n"), { mem_total_mb: 7952 });
  assert.deepEqual(memoryMb(""), {});
  assert.deepEqual(memoryMb("nonsense"), {});
});

test("only real disks are listed, once each", () => {
  const mounts = [
    "/dev/sda1 / ext4 rw,relatime 0 0",
    "proc /proc proc rw 0 0",
    "tmpfs /run tmpfs rw 0 0",
    "/dev/loop3 /snap/core20/2105 squashfs ro 0 0",
    "nas:/export /mnt/nas nfs4 rw 0 0",
    "/dev/sdb1 /data xfs rw 0 0",
    // The same device bind-mounted deeper: one disk, not two.
    "/dev/sda1 /var/www ext4 rw 0 0",
    "",
  ].join("\n");
  // An explicit directory test, so the case does not depend on which of
  // these paths happens to exist on the machine running the suite.
  assert.deepEqual(mountPoints(mounts, "linux", () => true), ["/", "/data"]);
  // Off Linux there is no mount table, so the one filesystem we can name is
  // the one the application runs from.
  assert.equal(mountPoints(mounts, "darwin").length, 1);
});

test("disk figures are the ones df prints", () => {
  // A 4 GiB disk: 1200 MB free, of which 1024 MB is ours and the rest is
  // reserved for root.
  const st = { bsize: 4096, blocks: 1024 * 1024, bfree: 300 * 1024, bavail: 256 * 1024 };
  const [disk] = diskRows(["/"], () => st);
  // used = total - free; total = used + available. The 176 MB reserved for
  // root is in neither, so used/total is df's Use%.
  assert.equal(disk.used_mb, 2896);
  assert.equal(disk.total_mb, 3920);
});

test("a partition too small to care about, or one we cannot stat, is left out", () => {
  const small = { bsize: 4096, blocks: 64 * 1024, bfree: 32 * 1024, bavail: 32 * 1024 };
  assert.deepEqual(diskRows(["/boot/efi"], () => small), []);
  assert.deepEqual(diskRows(["/locked"], () => { throw new Error("permission denied"); }), []);
  // The package supports Node 18, where fs.statfsSync may not exist (it
  // arrived in 18.15). Without it, disks are simply not reported. `null`
  // stands in for the missing function, since `undefined` would take the
  // default parameter and find the real one.
  assert.deepEqual(diskRows(["/"], null), []);
});

test("a sample carries the minute it covers and the machine's own figures", () => {
  const core = fakeCore();
  const resources = createResources(core, { serverName: "web-1" });
  const row = resources.sample();
  assert.match(row.minute, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:00\.000Z$/);
  assert.ok(row.cpu_cores >= 1);
  // This package runs inside the application, so unlike the agent it can
  // honestly report the application's own memory.
  assert.ok(row.proc_rss_mb >= 1);
  assert.ok(row.host_uptime_s > 0);
  // No CPU figure: this sample is milliseconds after the first reading, and
  // the counters move in ticks, so any percentage would be noise.
  assert.equal("cpu_pct" in row, false);
  // The limits pass: this process's own key and figures, and no in-flight
  // peak until the performance module is wired in.
  assert.match(row.proc_key, /^[0-9a-f]{12}$/);
  assert.ok(row.proc_uptime_s >= 0);
  assert.ok(row.heap_max_mb > row.heap_used_mb);
  assert.equal("inflight_peak" in row, false);
  resources.useInflight(() => 4);
  assert.equal(resources.sample().inflight_peak, 4);
  resources.close();
});

test("the report is one row per minute, under the site's own secret", async () => {
  const core = fakeCore();
  const resources = createResources(core, { serverName: "web-1" });
  resources.sample();
  assert.equal(await resources.flush(), true);
  assert.equal(core.sent.length, 1);
  const { path, auth, body, module } = core.sent[0];
  assert.equal(path, "/events/resources");
  assert.equal(module, "resources");
  // Bearer, like posture, inventory and file integrity — not the body field
  // the older server-requests endpoint takes.
  assert.equal(auth, "bearer");
  assert.equal(body.site_id, "a".repeat(24));
  assert.equal(body.server_name, "web-1");
  assert.match(body.runtime, /^Node /);
  assert.equal(body.rows.length, 1);
  // Sent rows are not sent again.
  assert.equal(core.sent.length, 1);
  assert.equal(await resources.flush(), true);
  assert.equal(core.sent.length, 1);
  resources.close();
});

test("rows are kept when the collector cannot take them, dropped when it refuses them", async () => {
  const down = fakeCore({ ok: false, status: 503, body: {} });
  const kept = createResources(down, {});
  kept.sample();
  assert.equal(await kept.flush(), false, "a retry can still deliver these");
  assert.equal(await kept.flush(), false);
  assert.equal(down.sent.length, 2, "the same rows went again");
  kept.close();

  const refused = fakeCore({ ok: false, status: 400, body: {} });
  const dropped = createResources(refused, {});
  dropped.sample();
  assert.equal(await dropped.flush(), true, "resending won't make them acceptable");
  assert.equal(await dropped.flush(), true);
  assert.equal(refused.sent.length, 1, "they were not sent again");
  dropped.close();
});

test("the module switch stops it, and nothing is buffered while it is off", async () => {
  const core = fakeCore();
  core.isOn = () => false;
  const resources = createResources(core, {});
  resources.sample();
  await resources.report();
  assert.equal(core.sent.length, 0);
  // Nothing was kept, so turning it back on doesn't send a backlog of
  // minutes the owner had switched off.
  core.isOn = () => true;
  assert.equal(await resources.flush(), true);
  assert.equal(core.sent.length, 0);
  resources.close();
});

// --- The detail pass: the CPU breakdown, throughput and inodes ---

// user nice system idle iowait irq softirq steal
const CPU_BEFORE = [1000, 100, 500, 8000, 200, 10, 20, 170];
const CPU_AFTER = [1100, 100, 550, 8600, 240, 10, 20, 180];

test("steal is reported, because nothing else the customer can see says it", () => {
  const shares = cpuShares(CPU_BEFORE, CPU_AFTER);
  // 800 jiffies passed and 10 went to another tenant on the same host.
  assert.equal(shares.cpu_steal_pct, 1.3);
  assert.equal(shares.cpu_iowait_pct, 5);
  assert.equal(shares.cpu_system_pct, 6.3);
  // user folds nice in, the way top adds them together.
  assert.equal(shares.cpu_user_pct, 12.5);
});

test("a kernel without a column leaves it out rather than sending nought", () => {
  const shares = cpuShares([1000, 100, 500, 8000], [1100, 100, 550, 8600]);
  assert.equal("cpu_steal_pct" in shares, false);
  assert.equal("cpu_iowait_pct" in shares, false);
  assert.equal(typeof shares.cpu_user_pct, "number");
});

test("one reading, or counters that went backwards, says nothing", () => {
  assert.deepEqual(cpuShares(null, CPU_AFTER), {});
  // Backwards means a reboot, not negative time.
  assert.deepEqual(cpuShares(CPU_AFTER, CPU_BEFORE), {});
});

test("a bind-mounted file is not one of the disks", () => {
  // Docker bind-mounts single files, so a container's mount table lists
  // /etc/hosts and friends on the host's own device. Those paths are short, so
  // without a directory test one of them wins the shortest-path race and the
  // panel names a file as a disk.
  const mounts = [
    "overlay / overlay rw,relatime 0 0",
    "/dev/nvme0n1p6 /var/www/html/wp-content/plugins/site-analytics ext4 rw 0 0",
    "/dev/nvme0n1p6 /etc/resolv.conf ext4 rw 0 0",
    "/dev/nvme0n1p6 /etc/hostname ext4 rw 0 0",
    "/dev/nvme0n1p6 /etc/hosts ext4 rw 0 0",
  ].join("\n");
  const isDir = (point) => !point.startsWith("/etc/");
  assert.deepEqual(mountPoints(mounts, "linux", isDir),
    ["/", "/var/www/html/wp-content/plugins/site-analytics"]);
  // With no directory test to go on, the device keeps its shortest mount
  // rather than being dropped: open_basedir and friends can refuse every
  // path, and reporting no disks would be worse than an odd mount point.
  assert.deepEqual(mountPoints(mounts, "linux", () => false), ["/", "/etc/hosts"]);
});

test("one filesystem behind two devices is reported once", () => {
  // The bug seen on a real container: / is the overlay and /sdk is a bind of
  // the host disk the overlay's upperdir lives on. The kernel calls them
  // different devices (overlay vs /dev/nvme0n1p6, two different st_dev), so
  // only the byte-identical size and free space give it away.
  const st = { bsize: 4096, blocks: 78280000, bfree: 28570000, bavail: 24500000, files: 0, ffree: 0 };
  assert.deepEqual(diskRows(["/", "/sdk"], () => st).map((r) => r.mount), ["/"]);
  // Two disks that merely round to the same megabyte stay apart: the test is
  // on raw bytes.
  const other = { ...st, bfree: st.bfree + 1, bavail: st.bavail + 1 };
  assert.deepEqual(
    diskRows(["/", "/data"], (mount) => (mount === "/" ? st : other)).map((r) => r.mount),
    ["/", "/data"],
  );
});

test("a partition is not counted twice with the disk it sits on", () => {
  const stats = [
    "   8   0 sda 100 0 2000 0 50 0 4000 0 0 0 0",
    "   8   1 sda1 90 0 1800 0 40 0 3000 0 0 0 0",
    "   7   0 loop0 10 0 100 0 0 0 0 0 0 0 0",
    " 253   0 dm-0 10 0 500 0 5 0 500 0 0 0 0",
    " 259   0 nvme0n1 20 0 1000 0 10 0 2000 0 0 0 0",
    " 259   1 nvme0n1p1 15 0 900 0 8 0 1500 0 0 0 0",
  ].join("\n");
  // Only sda and nvme0n1 count: 3000 sectors read, 6000 written, 512 bytes each.
  assert.deepEqual(diskCounters(stats), [3000 * 512, 6000 * 512]);
  // A machine showing no real disk reports nothing, not zero.
  assert.equal(diskCounters("   7   0 loop0 10 0 100 0 0 0 0 0 0 0 0"), null);
});

test("container and loopback traffic is not the site's traffic", () => {
  const dev = [
    "Inter-|   Receive                    |  Transmit",
    " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets",
    "    lo: 5000 10 0 0 0 0 0 0 5000 10 0 0 0 0 0 0",
    "  eth0: 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0",
    "docker0: 9000 10 0 0 0 0 0 0 9000 10 0 0 0 0 0 0",
    "  eth1: 500 5 0 0 0 0 0 0 250 2 0 0 0 0 0 0",
  ].join("\n");
  assert.deepEqual(netCounters(dev), [1500, 2250]);
});

test("a rate needs two readings close enough together to mean this minute", () => {
  const MB = 1024 * 1024;
  assert.equal(rateMbs(0, 60 * MB, 60000), 1);
  // A reboot reset the counter: not a negative rate.
  assert.equal(rateMbs(60 * MB, 0, 60000), null);
  // Too long a gap to call an average of.
  assert.equal(rateMbs(0, 60 * MB, 301 * 1000), null);
  assert.equal(rateMbs(0, 60 * MB, 0), null);
  assert.equal(rateMbs(null, 60 * MB, 60000), null);
});

test("inodes ride along with the mount, and are left out when unknown", () => {
  const withNodes = diskRows(["/"], () => ({ bsize: 4096, blocks: 1024 * 1024, bfree: 300 * 1024, bavail: 256 * 1024, files: 262144, ffree: 200000 }));
  assert.equal(withNodes[0].inodes_total, 262144);
  assert.equal(withNodes[0].inodes_used, 62144);
  // A filesystem that doesn't count them says nothing rather than zero.
  const without = diskRows(["/"], () => ({ bsize: 4096, blocks: 1024 * 1024, bfree: 300 * 1024, bavail: 256 * 1024, files: 0, ffree: 0 }));
  assert.equal("inodes_total" in without[0], false);
});
