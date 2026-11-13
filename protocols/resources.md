# Resources protocol (v1)

What every server client reports about **how the machine is doing**, as opposed
to how its requests went (`server_requests`, the performance module), what it
runs (`inventory.md`) or how it is set up (`posture.md`): CPU, load, memory,
swap, disks and the app process's own memory, one sample per minute per host.

This is the half of a Prometheus + Grafana install that the request timings
don't cover. What fills each disk, and what can be cleared, is the server
agent's own scan: `disk-usage.md`. The dashboard shows it in Health → Server speed
(`backend/Sections/Analytics/health/serverResources.js`) and alerts on it through the
metric watches. The collector side is `expresscollect/Analytics/resources.js`;
the table is `analytics.server_resources`
(`clickhouse_worker/migrations/20261020_server_resources.sql`).

Clients: the server agent (`sdk/vps-agent`), the Node package
(`sdk/platform-node`), the Python package (`sdk/platform-python`), the PHP
package (`sdk/platform-php`, WordPress plugin included) and the Ruby, Java,
.NET and Go packages (`sdk/platform-ruby`, `sdk/platform-java`,
`sdk/platform-dotnet`, `sdk/platform-go`).

**Nothing is guessed.** Each client reports what it can actually see and leaves
the rest out — a field that is absent is stored as NULL and the dashboard shows
"—", because 0% CPU and "we can't measure CPU here" are not the same statement.
A client never installs anything, never changes a setting and never reads a
file's contents.

## Authentication

Like posture, inventory, file integrity and the firewall: the site's ID in the
body, `Authorization: Bearer <secret>`, and a `User-Agent` naming the client
and its version.

> The older `/events/server-requests` endpoint takes the secret as a
> `sitesecret` body field instead. That is the odd one out among the server
> endpoints; new ones use Bearer.

## When

Sample every **60 seconds**, in the background, and post every `every` seconds
(**300** by default) with one row per sampled minute. An idle host therefore
costs about twelve requests an hour.

A minute with no visitor traffic still reports: that is the whole reason this is
not folded into the server-requests payload. An idle server filling its disk is
exactly when the sample matters.

Never in a visitor's request, and never more work than the file check already
does. A client that cannot sample without blocking (PHP) samples from the
scheduled tick it already has.

The module switch is its own, `resources` in
`GET /events/platform/config` — *not* the inventory one. This is performance
data, and a site that turns software inventory off still wants to know its disk
is full. With the switch off the answer says `enabled: false` and the client
stops sampling until it is turned back on.

## What each client can see

| client | CPU % | load | memory | swap | disks | process | event loop |
|---|---|---|---|---|---|---|---|
| agent (`sdk/vps-agent`) | `/proc/stat` deltas | `os.getloadavg()` | `/proc/meminfo` | `/proc/meminfo` | `/proc/mounts` + `statvfs` | **—** | — |
| Node | `os.cpus()` deltas | `os.loadavg()` | `/proc/meminfo`, else `os.totalmem/freemem` | `/proc/meminfo` | `fs.statfs` | `process.memoryUsage().rss` | `monitorEventLoopDelay` |
| Python | `/proc/stat` deltas | `os.getloadavg()` | `/proc/meminfo` | `/proc/meminfo` | `os.statvfs` | `/proc/self/status` | — |
| PHP / WordPress | `/proc/stat` deltas, across requests (see below) | `sys_getloadavg()` | `/proc/meminfo` | `/proc/meminfo` | `disk_total_space`/`disk_free_space` | `memory_get_peak_usage` | — |

The four later packages, each a long-running process like Node and Python
(each sends `runtime` as `Ruby 3.3.6`, `Java 21.0.12.1`, `.NET 8.0.11`,
`Go 1.23.4`):

- **Ruby**: Linux's `/proc` for everything but the disks; Ruby's standard
  library has no `statvfs`, so the disks (and their inodes) come from `df -kP`
  and `df -iP`, and without `df` the disks are left out.
- **Java**: on Linux it reads `/proc`, elsewhere the JVM's own figures; no
  inode counts.
- **.NET**: on Linux `/proc` as the Python package and the agent read it; on
  Windows the system's own figures (`GetSystemTimes`, `GlobalMemoryStatusEx`,
  the fixed drives, the network interfaces' counters), with no load average,
  swap, iowait or steal, which are left out there.
- **Go**: `/proc` and `statfs` on Linux, which is every reading; other systems
  send what they have.

### The detail pass

Everything above is one number per thing. These are the ones people opened
Grafana for, and all of them are optional in the same way.

| client | CPU breakdown | disk read/write | network | inodes |
|---|---|---|---|---|
| agent (`sdk/vps-agent`) | `/proc/stat` fields | `/proc/diskstats` deltas | `/proc/net/dev` deltas | `statvfs` |
| Node | `/proc/stat` fields | `/proc/diskstats` deltas | `/proc/net/dev` deltas | `fs.statfs` |
| Python | `/proc/stat` fields | `/proc/diskstats` deltas | `/proc/net/dev` deltas | `os.statvfs` |
| PHP / WordPress | `/proc/stat` fields, across requests | `/proc/diskstats` deltas, across requests | `/proc/net/dev` deltas, across requests | **—** (no `statvfs` in PHP) |

These are additive, so **the protocol version stays `1`**: an old client that
sends none of them is still correct, and a new client posting to a collector
whose table has not been migrated yet loses only the new columns (ClickHouse
skips fields it has no column for), never the row.

- **`cpu_steal_pct` is the one worth explaining to a customer.** It is time the
  hypervisor gave to another tenant: the machine was not available to them and
  no amount of tuning their app will change it. Nothing else they can see says
  so, which makes it the single most useful figure here.
- `cpu_iowait_pct` is the machine waiting for a disk rather than computing —
  the usual answer when CPU looks fine but the site is slow.
- `cpu_user_pct` + `cpu_system_pct` + `cpu_iowait_pct` + `cpu_steal_pct` never
  add up to more than 100; the rest is idle and the interrupt buckets. They do
  **not** have to add up to `cpu_pct`, which stays exactly what it was in v1
  (everything that was neither idle nor iowait) so that old rows and old
  clients keep their meaning.
- **Disk and network throughput are counters**, like CPU: two readings or
  nothing, and a pair further apart than 300 seconds is dropped rather than
  reported as an average of an unknown window. Physical devices only — a
  partition must not be counted twice with its parent, and loopback is not a
  network interface.
- `inodes_used`/`inodes_total` go **inside** each `disks` entry. A client that
  cannot read them leaves them out of every entry; it must not fill them in for
  some mounts and not others.

**Two readings are needed for a CPU figure**, because `/proc/stat` counts since
boot. One reading says nothing, so the first sample a client ever takes leaves
`cpu_pct` out rather than sending a zero. The same applies to a pair taken too
close together: the counters move in ticks, so a percentage measured over a few
milliseconds is quantisation noise (0% or 100%, nothing between). Clients drop
the figure below roughly a second.

**PHP measures CPU by keeping the previous reading on disk.** It has no process
that lives between requests, so the sample is taken during a request and the
last `/proc/stat` reading is kept in the package's state folder; the difference
between two readings a minute apart is a real average. Two consequences worth
knowing:

- **Sampling needs traffic.** A PHP site nobody visits for an hour reports
  nothing for that hour. The agent and the long-running packages don't have
  this problem.
- **After a long gap the CPU figure is dropped** rather than attributed to the
  one minute the row is labelled with. The PHP client reports it only when the
  two readings are 10 to 300 seconds apart.

PHP also can't see the blocks a filesystem reserves for root, so its
`used/total` can read a few points under `df`'s Use% on a disk that has a
reserve. The agent, Node and Python all match `df` exactly.

The agent sends no `proc_rss_mb`: it is not the site's application and has no
way to know which process is. The packages, which run inside the application,
are the only clients that can honestly answer that.

**Memory used is `total - MemAvailable`, not `total - free`.** Page cache is not
memory pressure, and reporting it as used makes every healthy Linux box look
full.

### Limits: how close it is to a wall

Everything above says how busy the machine is. This pass says how close the
app is to a limit — and on the setups customers actually run, the limit is
rarely the machine. Additive like the detail pass: the protocol stays `1`.

**Sent by every client** since 2026-11-07. Node (`analytics-platform` 0.3.8,
`lib/limits.js`) is the reference. Each sends what its runtime can say:

| client | sends | leaves out (and why) |
|---|---|---|
| Node 0.3.9 | every field except the pool's | `workers_*`, `queue_waiting`, `pool_maxed`: no pool |
| Python 0.3.5 | process, cgroup, `psi_*`, network, `fds_*`, `inflight_peak` (WSGI, ASGI, Django) | `workers_*`, `queue_waiting`, `pool_maxed`, `heap_*`, `gc_ms`: per-collection callbacks cost too much |
| PHP 0.3.5, WordPress plugin 2.4.9 | cgroup, `psi_*`, network, FPM's `workers_busy`, `workers_max` (only `pm = static`), `queue_waiting`, `pool_maxed`; `proc_key`/`proc_uptime_s` are the FPM pool's | `fds_*`, `inflight_peak`, `heap_*`, `gc_ms`: each request is a process of its own |
| Ruby 0.3.4 | process, cgroup, `psi_*`, network, `fds_*`, `inflight_peak`, `gc_ms` (`GC.stat(:time)`, 3.1+), Puma's `workers_busy`/`workers_max`/`queue_waiting` | `heap_*`: no heap cap; `pool_maxed`: Puma has no such count |
| Java 0.3.3 | process, cgroup, `psi_*`, network, `fds_*`, `inflight_peak`, heap (the JVM's max), `gc_ms` (the GC beans' pauses; a concurrent collector's own cycles left out) | the pool's fields |
| .NET 0.3.3 | process, cgroup, `psi_*`, network, `fds_*`, `inflight_peak`, heap (`GCMemoryInfo.TotalAvailableMemoryBytes`), `gc_ms` (.NET 7+), `queue_waiting` (the thread pool's pending items) | `workers_max`: in the tens of thousands, says nothing |
| Go 0.4.0 | process, cgroup, `psi_*`, network, `fds_*`, `inflight_peak`, heap against `debug.SetMemoryLimit` (none when unlimited), `gc_ms` (pause totals) | the pool's fields |
| Linux agent 0.7.5 | `oom_kills` (the whole machine's, `/proc/vmstat`), `psi_*`, `listen_drops`, `conntrack_pct` | everything per process or cgroup |
| Windows agent 0.2.0 | nothing: it sends no resources report | — |

| field | what it is | where it comes from (Linux) | scope |
|---|---|---|---|
| `proc_key` | a random key the process picks once at start, up to 32 characters | — | process |
| `proc_uptime_s` | how long the reporting process has run | the runtime's own clock | process |
| `limit_mem_mb` / `limit_mem_used_mb` | the reporter's memory cap, and what counts against it | cgroup v2 `memory.max`, `memory.current` less `memory.stat`'s `inactive_file`; v1 `memory.limit_in_bytes`, `memory.usage_in_bytes` less `total_inactive_file` | cgroup |
| `limit_cpu_cores` | the reporter's CPU cap, in cores | v2 `cpu.max` (quota / period); v1 `cpu.cfs_quota_us` / `cpu.cfs_period_us` | cgroup |
| `cpu_throttled_pct` | share of the interval's CPU periods in which the cap stopped it | `cpu.stat` `nr_throttled` / `nr_periods`, two readings | cgroup |
| `oom_kills` | processes killed for memory in the interval | v2 `memory.events` `oom_kill`; v1 `memory.oom_control` `oom_kill`; the agent `/proc/vmstat` `oom_kill` | cgroup (agent: machine) |
| `psi_cpu_pct` / `psi_mem_pct` / `psi_io_pct` | share of the last minute in which at least one task was waiting | `/proc/pressure/{cpu,memory,io}`, the `some` line's `avg60` | machine |
| `inflight_peak` | most requests in progress at once during the interval | the package's own request timing | process |
| `workers_busy` / `workers_max` | the server's worker pool, busy and allowed | PHP-FPM `fpm_get_status()`, Puma's stats | pool |
| `queue_waiting` | requests or work items waiting for a worker | FPM's `listen-queue`, Puma's backlog, .NET's pending work items | pool |
| `pool_maxed` | times in the interval the pool wanted another worker and was at its cap | FPM's `max-children-reached`, two readings | pool |
| `listen_drops` | connections refused because the app didn't accept them in time | `/proc/net/netstat` TcpExt `ListenOverflows`, two readings | network namespace |
| `conntrack_pct` | how full the kernel's connection-tracking table is | `/proc/sys/net/netfilter/nf_conntrack_count` / `_max` | network namespace |
| `fds_used` / `fds_max` | the process's open files, and its soft limit | entries in `/proc/self/fd`; `/proc/self/limits` "Max open files" | process |
| `heap_used_mb` / `heap_max_mb` | the runtime's heap, and its cap | V8's heap statistics, the JVM's max memory, the .NET GC's available memory, Go's memory limit | process |
| `gc_ms` | milliseconds of the interval spent in garbage collection | the runtime's GC counters or observer | process |

Rules, each for a reason that cost something to learn:

- **A cap that isn't one is left out.** `max`, `-1`, v1's
  9223372036854771712, and any memory cap at or above the machine's own
  MemTotal are "no limit": send neither `limit_mem_mb` nor
  `limit_mem_used_mb`. A bare machine, or a systemd service with no
  `MemoryMax`, therefore reports nothing here, and the card shows no bar.
- **Container memory is a working set, not `memory.current`.** The cgroup
  counts page cache, so `memory.current` sits near the cap on a healthy
  container that reads files. Less `inactive_file` is what Docker and the
  kubelet show, and what the kernel reclaims last before it kills.
- **Find the cgroup from `/proc/self/cgroup`.** v2 is the `0::<path>` line, v1
  the `memory` and `cpu` controllers' lines. Read under `/sys/fs/cgroup<path>`
  first and fall back to `/sys/fs/cgroup` itself: inside a container with its
  own cgroup namespace the path is `/` and the mount is already the
  container's; without one the path names the host's hierarchy, which isn't
  mounted there.
- **The app's own kill is invisible to the app.** When the cap is hit and the
  kernel kills the app, the package dies with it and nothing reports the
  kill. A package's `oom_kills` sees only other processes in its cgroup — a
  PHP-FPM or gunicorn worker. The agent's machine-wide `/proc/vmstat` count is
  the reliable one, and `proc_uptime_s` starting again is how an app's own
  death shows.
- **Waiting time is the whole machine's**, read from `/proc/pressure` even in
  a container, where it is the host's. `avg60` needs one reading, so a PHP
  site that samples during a visit still gets an honest figure. A kernel built
  without PSI, or booted with `psi=0`, has no such files: leave them out.
- **Counts keep their whole difference.** `oom_kills`, `pool_maxed`,
  `listen_drops` and `gc_ms` are differences between two readings like the
  throughput fields, but unlike a rate a count is not dropped when the pair is
  more than 300 seconds apart: a kill must not vanish because PHP had no
  visitor for an hour. A counter that went down was reset — send nothing.
- **`cpu_throttled_pct` is left out with no cap** (no periods), and when no
  period passed in the interval.
- **`inflight_peak` needs the request timing on.** A package whose middleware
  isn't installed sends nothing, never 0. The peak resets to what is still in
  progress at each sample.
- **A pool's maximum only when it is one.** FPM reports no `pm.max_children`;
  send `workers_max` only for `pm = static`, where every child is the
  maximum, and rely on `pool_maxed` for the rest. .NET's thread-pool maximum
  is in the tens of thousands and says nothing: it sends `queue_waiting` only.
- `fds_used` leaves out the descriptor used to list `/proc/self/fd` itself. An
  `unlimited` soft limit means no `fds_max`.

## POST /events/resources

```json
{
  "site_id": "<id>",
  "server_name": "web-1",
  "runtime": "Node 20.11.1",
  "rows": [
    {
      "minute": "2026-10-20T12:00:00.000Z",
      "cpu_pct": 37.5,
      "cpu_cores": 4,
      "cpu_user_pct": 22.0,
      "cpu_system_pct": 9.5,
      "cpu_iowait_pct": 4.0,
      "cpu_steal_pct": 2.0,
      "load1": 1.2,
      "load5": 0.9,
      "load15": 0.7,
      "mem_total_mb": 7954,
      "mem_used_mb": 3120,
      "swap_total_mb": 2048,
      "swap_used_mb": 12,
      "disks": [
        { "mount": "/", "total_mb": 80000, "used_mb": 61000, "inodes_total": 5242880, "inodes_used": 412003 },
        { "mount": "/var/lib/docker", "total_mb": 400000, "used_mb": 120000 }
      ],
      "disk_read_mbs": 1.8,
      "disk_write_mbs": 12.4,
      "net_rx_mbs": 0.9,
      "net_tx_mbs": 3.1,
      "proc_rss_mb": 180,
      "loop_lag_ms": 1.4,
      "host_uptime_s": 864000
    }
  ]
}
```

- `server_name`: the server's name, as for file integrity and inventory. 100 characters.
- `runtime`: what the client runs on, e.g. `Node 20.11.1`, `PHP 8.3.6`, `Java 21.0.12.1`, `agent 0.3.0`. 32 characters.
- `rows`: 1 to **500** samples. Each needs a `minute` within the last 2 days
  (and no more than 5 minutes ahead); it is floored to the minute. A row with
  no readings at all is dropped, and a request left with no valid row is `400`.
- Every metric is optional; leave out what you cannot measure rather than
  sending 0. Sizes are **whole megabytes**, `cpu_pct` is 0–100 for the whole
  machine averaged over the minute, loads are as the OS gives them.
- `cpu_cores` is the exception: it is not nullable, and 0 means "didn't say".
  It is what makes a load figure readable.
- `disks`: up to 20 mounts, each an absolute path. A mount without both sizes
  is left out. `used_mb` above `total_mb` is clamped down.
- **Disk figures are `df`'s**, so a customer can check them: `used_mb` is total
  minus free, and `total_mb` is used plus what's available to the site. The
  blocks reserved for root are in neither, which is what makes `used/total` the
  percentage `df` prints — and that percentage is what the disk alert is about.
  Report real filesystems only (no tmpfs, devtmpfs, proc, sysfs, squashfs or
  network mounts), one entry per device under its shortest mount point so a
  bind mount isn't a second disk, and leave out anything under a gigabyte: an
  EFI partition is real and nobody watches it fill.
- **One entry per device is not enough on its own**, and containers are where
  it shows. Two more rules, both of which every client applies:
  - **A mount point must be a directory.** Docker bind-mounts single *files*,
    so a container's `/proc/mounts` lists `/etc/hosts`, `/etc/hostname` and
    `/etc/resolv.conf` on the host's own device. Those paths are short, so
    without this they win the shortest-path race against the real mount and
    the panel names a file as one of the site's disks. The test is per-device
    and advisory: a device whose mounts a client cannot confirm keeps its
    shortest one, because `open_basedir` and its equivalents can refuse every
    path and reporting no disks is worse than reporting an odd mount point.
  - **Drop a mount whose size and free space match an earlier one exactly.**
    One filesystem can sit behind two devices the kernel genuinely calls
    different: in a container `/` is the overlay and the app's folder is a
    bind of the host disk the overlay's `upperdir` lives on. Measured on a
    real container: `overlay /` and `/dev/nvme0n1p6 /sdk`, different device
    names *and* different `st_dev` (82 vs 66310), both reporting 305783 MB
    total and 111595 MB free. No device-based rule separates them, so the
    sizes are what gives it away. Compare **raw bytes**, not the rounded
    megabytes, so two disks that merely round alike stay apart. The cost is
    known and accepted: two genuinely separate filesystems of identical size
    with identical free bytes — a pair of freshly formatted volumes nothing
    has written to — collapse into one until something is written to either,
    and being empty they owe the fullness alert nothing.
- `disks[].inodes_total` / `inodes_used`: whole counts, not megabytes. A
  filesystem can refuse a write with gigabytes free once these meet, and every
  byte-based check still reads healthy, so this is its own alert rather than a
  detail of the disk one.
- `disk_read_mbs` / `disk_write_mbs` / `net_rx_mbs` / `net_tx_mbs`: megabytes
  **per second**, averaged across the interval, to one decimal. Not totals for
  the minute — a rate is what a reader compares against what the hardware can do.
- `host_uptime_s`: machine uptime. A drop between two minutes is a reboot, which
  is worth seeing next to a latency spike.
- The limits fields (see "Limits" above) sit on the row beside these, each as
  optional as the rest. `proc_key` is the one string: up to 32 characters of
  letters, digits, `-` and `_`; anything else is stored as `''`.

The answer (`202`): `{ "v": 1, "enabled": true, "every": 300, "stored": 2 }`.
`200` with `{ "v": 1, "enabled": false, "every": 300 }` when the owner turned
the module off. `400` for a bad site ID or no valid rows, `401` for bad
credentials, `429` with `Retry-After` over the rate limit, `503` with
`Retry-After: 30` when storage is unavailable — retry then, and a resent sample
is harmless (see below).

## Duplicates, and what a read owes them

Delivery is at least once: a client that retries a `503` resends the same
host-minutes, and `server_resources` is a plain MergeTree with no dedup. A
`(site_id, minute, server_name)` can therefore hold more than one row.

**Collapse to one row per host-minute before aggregating anything:**

```sql
SELECT avg(cpu), max(cpu) FROM (
  SELECT minute, server_name, any(cpu_pct) AS cpu
  FROM analytics.server_resources
  WHERE site_id = {site:String} AND minute >= … AND minute < …
  GROUP BY minute, server_name
)
```

It is tempting to skip that, because averaging two copies of one sample returns
that sample. It does — but a retry resends only the minutes that failed, so the
duplication is **uneven**, and an `avg()` straight over the raw rows is pulled
toward whichever minute was resent. Measured on a four-row fixture: 0.88 where
the true average was 0.80.

`any()` is enough to pick a copy (the rows are identical); use
`argMax(cpu_pct, received_at)` if you would rather take the newest.

**Several processes can share a name.** Cluster workers, gunicorn and Puma
workers each run their own client under one `server_name`, so a host-minute can
hold rows that are *not* copies. Each process sends its own `proc_key`, and a
read collapses per `(minute, server_name, proc_key)` first (copies share a key)
and then combines the processes: the machine's and the cgroup's figures with
`any()` (every process saw the same ones), `proc_rss_mb` and `inflight_peak`
summed, the worst process for heap and open files, the longest `gc_ms` and
`loop_lag_ms`, the shortest `proc_uptime_s`. Rows without a key are `''` and
collapse as before.

The other half of the rule: these are **gauges**. Never sum them, and never add
a host's minutes together — except the three counts of the limits pass
(`oom_kills`, `pool_maxed`, `listen_drops`), which are events in the interval
and are summed over a bucket after the collapse. `gc_ms` is a count too, but is
read as an average per minute, so an hour's bucket and a minute's compare. CPU, load, memory and disk are averaged over a
bucket, with the period maximum reported beside them.
