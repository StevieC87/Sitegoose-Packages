# Services protocol (v1)

Whether each **service on a server** runs: its database, cache, queue, web
server, workers, containers. Health → All systems gives each a light of its
own (`backend/Sections/CustomerDash/monitoring/serviceChecks.js`), green while
it runs and red when it stops. The collector side is
`expresscollect/Analytics/services.js`; it is stored in Mongo
`platform_services`, one document per site and server.

The companion of `checkin.md`: there a package's own process says it is alive;
here the server agent says whether the *other* services on the machine are,
the ones no package runs inside (Redis, PostgreSQL, nginx...).

Client: the server agent (`sdk/vps-agent`), from 0.6.0; the Windows agent
(`sdk/windows-agent`), from 0.2.0.

## What is checked

Set on the server alone, in the agent's config (`"services"`), plus what the
agent finds by itself unless `"services_detect": false`. **Never from the
dashboard**: a target set there would let anyone with dashboard access make the
customer's server probe their private network. So the collector only takes
results; nothing in the answer names a check.

| `type` | Up when |
| --- | --- |
| `tcp` | A TCP connection to `host:port` opens (5 s). |
| `http` | One `GET`, no redirect followed, answers 2xx or 3xx (5 s); with `expect_ok`, the body is JSON with `"ok": true`. |
| `unit` | The systemd unit's `ActiveState` is `active` or `reloading`. |
| `process` | A process of that name runs (`/proc/*/comm` or its program's file name). |
| `container` | Docker says `running` and not `(unhealthy)`; Podman: its cgroup exists (its health check isn't read); Kubernetes: `crictl` says `CONTAINER_RUNNING`. Found only, never listed. |

Found by the agent (`auto: true`): systemd `.service` units of databases,
caches, queues, web servers, PHP-FPM, Docker and pm2, and every Docker,
Podman (0.7.5 on) and Kubernetes (0.7.5 on) container. One is reported while it runs or is enabled at boot, and while it is
still there and ran in the last 7 days, so a service that stops is red rather
than missing; one removed altogether goes at once. A read of systemd, Docker,
Podman or `crictl` that fails repeats the last results rather than reporting everything gone.

## Request

`POST /events/services`, about once a minute, to every site on the server (the
machine is the same for all of them, as in `resources.md`). Authentication like
the other server modules: the site's ID in the body, `Authorization: Bearer
<secret>`.

```json
{
  "v": 1,
  "site_id": "65a1b2c3d4e5f60718293a4b",
  "server_name": "web-1",
  "client": "vps-agent/0.6.0",
  "checks": [
    {"name": "redis-server", "type": "unit", "target": "redis-server.service", "ok": true,
     "detail": "", "ms": null, "auto": true, "for_s": 86400},
    {"name": "api", "type": "http", "target": "http://127.0.0.1:3000/health", "ok": false,
     "detail": "Answered 503", "ms": 12, "auto": false, "for_s": 120}
  ]
}
```

| Field | Meaning |
| --- | --- |
| `server_name` | Required. The machine, as the other modules name it (the host name). At most 100 characters. Compared lower-cased. |
| `checks` | Required, may be empty. At most 50 are kept; the first of each `name` (compared lower-cased). |
| `name` | Required. At most 80 characters; control characters are dropped. |
| `type` | Required: `tcp`, `http`, `unit`, `process` or `container`. |
| `ok` | Required boolean: whether it runs. A check without it is not kept. |
| `target` | What is checked, as shown. An `http` address loses any user, password, query and fragment (the agent sends it so, and the collector strips it again). At most 200 printable characters. |
| `detail` | Why it isn't up (`Connection refused`, `Answered 503`, `failed`, `Exited (1) 1 minute ago`). Dropped when `ok`. At most 200. |
| `ms` | How long a `tcp` or `http` check took. Null otherwise. |
| `auto` | Found by the agent rather than listed in its config. |
| `for_s` | Seconds it has been as it is now, as far as the agent knows (it starts again from 0 when the agent restarts). Stored as `since`. |

A number that is missing, negative, not whole or out of range is stored as null.

## Usage

A running `unit` or `container` check also carries what it uses, read from its
own cgroup. Sent by the Linux server agent (0.7.3 on; Podman and Kubernetes
from 0.7.5) and the Windows agent (0.2.0 on: a `unit` is a Windows service,
`mem_mb` its process's working set, `cpu_pct` as below; services sharing one
svchost count it once, for the first by name; never `mem_limit_mb` or
`oom_kills`). Every field is optional, and one the agent couldn't read is left
out, never sent as 0.

```json
{"name": "clickhouse", "type": "container", "target": "clickhouse", "ok": true,
 "container_id": "0123456789ab", "mem_mb": 471, "mem_limit_mb": 2048, "cpu_pct": 3.4, "oom_kills": 0}
```

| Field | Meaning |
| --- | --- |
| `mem_mb` | The working set: `memory.current` less `inactive_file` (v1: `memory.usage_in_bytes` less `total_inactive_file`), as Docker and the kubelet report it. It still includes file cache in active use, so a machine's services can add up to more than its own "used", which counts all cache as available. |
| `mem_limit_mb` | `memory.max` (v1 `memory.limit_in_bytes`). Left out when there is none, or it is at or above the machine's memory. |
| `cpu_pct` | A share of the **whole machine**, 0–100 across every core, as the machine's own CPU figure in `resources.md` is — not `docker stats`' per-core figure. From two readings of `cpu.stat` `usage_usec` (v1 `cpuacct.usage`) between 1 and 300 seconds apart, so the first report after the agent starts has none. |
| `oom_kills` | Processes in it killed for memory since the last report: the change in `memory.events` `oom_kill` (v1 `memory.oom_control`). A counter that went down was reset and sends nothing. |
| `container_id` | The first 12 characters of the container's ID (the collector keeps no more): an app inside the container has that as its default host name, which is how its own report (`resources.md`, "Limits") and this one are told to be about the same container. |

Where the cgroup is: v2 is one tree, a unit at `system.slice/<unit>`, a
container at `system.slice/docker-<id>.scope` (Docker's systemd driver) or
`docker/<id>` (its cgroupfs driver); Podman at `machine.slice/libpod-<id>.scope`
(rootless under `user.slice/user-<uid>.slice/user@<uid>.service/…`, cgroupfs
`libpod_parent/libpod-<id>`); Kubernetes at `kubepods.slice/…/<runtime>-<id>.scope`
or `kubepods/<qos>/pod<uid>/<id>`, found by a bounded walk. Podman containers are
named `<name>` (rootless `<user>/<name>`), Kubernetes ones
`<namespace>/<pod>/<container>`. v1 has a tree per controller: `memory/`,
and `cpu,cpuacct`, `cpuacct` or `cpu`. The unit name and the 64-character
container ID are checked first, so neither can climb out of the tree.

The collector stores each reading as a row of `server_service_usage` (through
the `rows.server_service_usage` queue), beside the document below. On the
dashboard: Health → Server speed's machine view shows "What's using this
machine" (only where the resources module is on, since that is where the
machine card is), All systems shows each running service's memory, CPU and
last hour, and a container near its own memory limit, or with a process killed
for memory, raises the server-resources alert — unless an app inside it already
reports that container, when only a kill the app didn't report is added.

## Answer

`202 {"v": 1, "every": 60, "stored": 2}`. `every` is how many seconds to wait
before the next report (never below 30). `400` for a body it can't read, `401`
for a wrong secret, `429` over the rate limit (30 a minute per address, 120 per
site), `503` with `Retry-After` when storage is down.

## Stored

Each report **replaces** the server's document (`_id` `<site>/<server
lower-cased>`): `siteid`, `server`, `at`, `client`, `checks`. A check taken out
of the config leaves with the next report; an empty list deletes the document.
A server unheard from for 30 days expires (TTL on `at`).

## What the dashboard makes of it

- `ok`: up. Not `ok`: red, "Not answering" for `tcp` and `http`, "Stopped"
  otherwise, with `detail` and how long.
- The light is whether the service runs, nothing else: no error count or
  security finding changes it.
- No report for 3 minutes: "Late" (yellow), since that is the agent, not the
  service. None for a day: grey and not held against the site.

## Must

- Never block the agent: every check has a time limit and runs on a thread of
  its own.
- Run no configured string through a shell, and check a unit name before it
  reaches `systemctl`.
- Send no secret: no site secret to a checked address, no credentials in a
  `target`.
