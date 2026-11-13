# Disk usage protocol (v1)

**What is filling a server's disks, and what can be cleared.** `resources.md`
says a disk is 87% full; this says it is 31 GB of Docker images, 9 GB of
rotated logs and a 14 GB log nobody rotates, and which of those can go.

Client: the Linux server agent (`sdk/vps-agent`), from 0.9.0. The language
packages don't send it: it needs root to see `/var/log`, the journal and
Docker's folders, and a package runs as the web user.

The collector side is `expresscollect/Analytics/diskUsage.js`; rows go through
the `rows.server_disk_usage` queue to `analytics.server_disk_usage`
(`clickhouse_worker/migrations/20261109_server_disk_usage.sql`). The dashboard
reads it in `backend/Sections/Analytics/health/diskUsage.js` (Health → Server
speed, "What's filling the disks") and names the biggest places in the disk
alert (`backend/Sections/CustomerDash/monitoring/serverResources.js`).

## What the client may do

**Only look.** Folder listings and `lstat` sizes, never what is in a file. The
exceptions are three settings files, read for what they say about cleanup:
`/etc/logrotate.conf` and `/etc/logrotate.d/*` (which paths a rule names),
`/etc/systemd/journald.conf` and `journald.conf.d/*` (`SystemMaxUse`), and
`/etc/docker/daemon.json` (`data-root`, `log-opts`). Plus `docker system df`
for what Docker itself calls reclaimable, and `/proc/<pid>/fd` links for
deleted files still held open.

**Never delete, truncate or change anything.** The dashboard shows commands;
a person runs them.

**Nothing from the dashboard decides what is scanned.** The places are fixed
(below) plus `disk_scan_paths` in the agent's own config file. The only thing
the dashboard can send is "scan now" (below), which runs the same scan sooner.

**Bounded.** The scan runs as a child process at the lowest CPU and disk
priority (`nice 19`, `ionice -c3` when present) with a memory cap, and is
killed past its time limit (default 300 s). It stops counting after about a
million entries; a scan that stopped early says `partial: true` and every
figure in it is "at least". It never follows a symlink, never crosses into
another filesystem, and counts a hard-linked file once (remembering at most
200,000 of them; past that the scan is partial).

## When

Every `disk_scan_every` seconds (default 10,800: three hours), the first about
five minutes after the agent starts. Only while the `resources` module is on:
the disk-usage answer says `enabled: false` otherwise, as `resources.md` does.

**Scan now.** The dashboard can set `user_sites.disk_scan_request`
`{ id, at }` (an opaque 24-hex id), at most once every 10 minutes. The
collector's answer to `POST /events/resources` then carries
`"disk_scan": "<id>"`. The agent scans once each time the id changes, no sooner
than 10 minutes after its last scan. On start it takes the current id as seen,
so a restart doesn't rescan for an old click. No clocks are compared.

## Request

`POST /events/disk-usage`, once per scan to every site on the server.
Authentication like `resources.md`: the site's ID in the body,
`Authorization: Bearer <secret>`.

```json
{
  "v": 1,
  "site_id": "65a1b2c3d4e5f60718293a4b",
  "server_name": "web-1",
  "client": "vps-agent/0.9.0",
  "scanned_at": "2026-11-09T14:05:00Z",
  "took_s": 41.2,
  "partial": false,
  "places": [
    {"mount": "/", "place": "logs", "path": "/var/log", "bytes": 10737418240, "files": 412},
    {"mount": "/", "place": "docker_images", "path": "/var/lib/docker", "bytes": 33285996544, "files": 803112}
  ],
  "notes": [
    {"mount": "/", "code": "rotated_logs", "bytes": 9663676416, "files": 380},
    {"mount": "/", "code": "big_log", "path": "/var/log/myapp/debug.log", "bytes": 15032385536, "flag": false},
    {"mount": "/", "code": "docker_unused_images", "bytes": 21474836480}
  ],
  "files": [
    {"mount": "/", "place": "logs", "path": "/var/log/myapp/debug.log", "bytes": 15032385536, "age_days": 0}
  ],
  "deleted": [
    {"mount": "/", "path": "/var/log/nginx/access.log.1", "bytes": 4509715660,
     "process": "nginx", "pid": 812, "fd": 5, "unit": "nginx.service", "container_id": ""}
  ]
}
```

| Field | Meaning |
| --- | --- |
| `scanned_at` | When the scan started. Required; at most 2 days old and not in the future. |
| `took_s` | How long it took. |
| `partial` | The scan stopped early: every figure is a floor. |
| `places` | Required, may be empty. One per place found (below). At most 60. |
| `notes` | What can be cleared and what is worth knowing (below). At most 100. |
| `files` | The biggest files across the places: path, size, how many days since it changed. At most 20. **Main site only** (below). |
| `deleted` | Deleted files still held open by a process. At most 20, biggest first. **Main site only.** |

Every entry names the `mount` it lives on, one of the mounts the same client
reports in `resources.md`'s `disks`. A place on a mount not reported there (one
under 1 GB, a network filesystem) is left out.

**File names go to one site.** The agent posts the same machine to every site
configured on it; on an agency's server those are different customers'. So
`files` and `deleted`, which name files, go only to the agent's main site (its
config's `site_id`), and to none when `disk_scan_files` is `false`. Every site
gets `places` and `notes` (totals by kind, as it already gets disk %), except
that a note's `path` is likewise sent to the main site only.

## Places

A file counts toward the **deepest** place that holds it: the journal inside
`/var/log` is the journal's, a backup folder inside `/var/www` is backups'.

| `place` | Where |
| --- | --- |
| `logs` | `/var/log` |
| `journal` | `/var/log/journal`, `/run/log/journal` |
| `docker_images` | Docker's `data-root` (default `/var/lib/docker`), less the three below |
| `docker_volumes` | `<data-root>/volumes` |
| `docker_logs` | `<data-root>/containers` (each container's `*-json.log`) |
| `docker_build` | `<data-root>/buildkit` |
| `containers` | `/var/lib/containerd`, `/var/lib/containers` (Podman) |
| `packages` | `/var/cache/apt`, `/var/cache/dnf`, `/var/cache/yum`, `/var/cache/pacman`, `/var/cache/zypp`, `/var/cache/apk` |
| `caches` | `~/.npm`, `~/.cache`, `~/.composer/cache`, `~/.cache/composer`, `~/.yarn/cache` for `/root` and every `/home/*` |
| `temp` | `/tmp`, `/var/tmp` |
| `backups` | `/var/backups`, `/backup`, `/backups`, `/root/backups`, `/home/*/backups`, `/var/www/*/backups` |
| `crash` | `/var/crash`, `/var/lib/systemd/coredump` |
| `snaps` | `/var/lib/snapd/snaps` |
| `databases` | `/var/lib/mysql`, `/var/lib/postgresql`, `/var/lib/pgsql`, `/var/lib/mongodb`, `/var/lib/clickhouse`, `/var/lib/redis` |
| `websites` | `/var/www`, `/srv` |
| `custom` | each of `disk_scan_paths` in the agent's config |

`bytes` is space used on disk (`st_blocks × 512`), not apparent size, so a
sparse file counts what it takes. `files` is how many files were counted.

## Notes

What a person can do about it. The client measures; the dashboard decides what
is "safe to clear" and what is "worth a look", and writes the words and the
commands (`backend/Sections/Analytics/health/diskAdvice.js`). Fields not listed
for a code are left out.

| `code` | Fields | Means |
| --- | --- | --- |
| `rotated_logs` | `bytes`, `files` | Rotated copies under `/var/log`: names ending `.gz`, `.xz`, `.bz2`, `.zst`, `.old` or `.<digits>`, or `-YYYYMMDD`. |
| `big_log` | `path`, `bytes`, `flag` | The biggest log still being written (at most 3, each over 1 GB). `flag`: a logrotate rule names it. |
| `journal_archived` | `bytes` | Archived journal files (`*@*.journal`, `*.journal~`) beyond the newest 500 MB of them: what `journalctl --vacuum-size=500M` removes. |
| `journal_no_limit` | — | `journald.conf` sets no `SystemMaxUse`. |
| `docker_build_cache` | `bytes` | Docker's build cache, reclaimable. |
| `docker_unused_images` | `bytes` | Images no container uses, reclaimable (`docker system df`). |
| `docker_stopped_containers` | `bytes` | Stopped containers' layers, reclaimable. |
| `docker_no_log_limit` | — | `daemon.json` sets no `log-opts` `max-size`, so container logs grow without end. |
| `docker_big_log` | `value` (container name or 12-char id), `bytes` | A container log over 1 GB (at most 3). |
| `package_cache` | `value` (`apt`, `dnf`, `yum`, `pacman`, `zypper`, `apk`), `bytes` | The package manager's download cache. |
| `user_cache` | `value` (`npm`, `pip`, `composer`, `yarn`), `user`, `bytes` | A developer tool's cache in a user's home. Over 100 MB only. |
| `old_temp` | `bytes`, `files` | Files in `/tmp` and `/var/tmp` unchanged for over 10 days. |
| `old_backups` | `bytes`, `files` | Files in the backup places unchanged for over 30 days. |
| `crash_dumps` | `bytes`, `files`, `value` (up to 3 program names, comma-separated) | Crash dumps. |
| `snap_old` | `value` (snap name), `revision`, `bytes` | A disabled snap revision. |
| `mysql_binlogs` | `bytes`, `files` | MySQL/MariaDB binary logs in its data folder. |
| `pg_wal` | `bytes` | PostgreSQL's `pg_wal` over 2 GB. |
| `open_deleted` | `bytes`, `files` | The total of `deleted` on this mount, sent to every site. |

`value`, `user` and `revision` are at most 100, 32 and 20 printable characters.

## Deleted files still open

A file deleted while a process holds it open keeps its space until the
process closes it: `df` counts it and no folder listing can find it. The agent
reads every `/proc/<pid>/fd` link ending ` (deleted)` that points at a regular
file on a reported mount, counts each file once however many processes hold
it, and names the first holder: its `process` name (`/proc/<pid>/comm`), and
from its cgroup the systemd `unit` or Docker `container_id` (12 characters).
`pid` and `fd` are as of the scan.

## Answer

`202 {"v": 1, "enabled": true, "stored": 41}`; `{"v": 1, "enabled": false}`
when the `resources` module is off. `400` for a body it can't read, `401` for a
wrong secret, `429` over the rate limit (30 a minute per address, 30 per site),
`503` with `Retry-After` when storage is down; the agent tries the same report
again in 5 minutes, up to an hour.

## Stored

One row per entry: `kind` is `scan` (one per report, so a scan that found
nothing still says when it ran), `place`, `note`, `file` or `deleted`. Delivery
is at least once, so a read collapses per `(timestamp, server_name, kind,
mount, place, code, path, value, user)` with `any()` first.
