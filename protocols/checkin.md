# Check-in protocol (v1)

How each **service** says it is running, so Health → All systems
(`backend/Sections/CustomerDash/monitoring/statusBoard.js`) can give it a light
and say when it was last heard from, even when it serves no requests and sends
no other data. The collector side is `noteApp` in
`expresscollect/Analytics/platform.js` (parsing in `Analytics/checkIn.js`); it
is stored in Mongo `platform_apps`, one document per site and service.

The other services on a machine (its database, cache, web server, containers),
which no package runs inside, are checked by the server agent instead:
`services.md`.

Clients: the Node package (`sdk/platform-node`), the Python package
(`sdk/platform-python`) and the PHP package (`sdk/platform-php`, WordPress
plugin included), from 0.3.3 / plugin 2.4.7; the Ruby, Java, .NET and Go
packages (`sdk/platform-ruby`, `sdk/platform-java`, `sdk/platform-dotnet`,
`sdk/platform-go`) from their first release.

## When

No request of its own: it rides on the module switches request every client
already makes, `GET /events/platform/config`, about once a minute (the `sync`
the collector answers with). Same authentication (`Authorization: Bearer
<secret>`), same rate limit. A client too old to send it simply has no
check-in; its server still shows from its other data.

## X-Platform-App

Form-encoded (`application/x-www-form-urlencoded` rules), so any name is plain
ASCII in a header:

```
X-Platform-App: server=worker&kind=process&pid=4121&up_s=86400&rss_mb=142&runtime=Node%2026.13.0
```

| Field | Meaning |
| --- | --- |
| `server` | Required. The service's name: the package's `serverName` / `server_name`, else the machine's host name, as every module sends it. At most 100 characters; control characters are dropped. Compared lower-cased. |
| `kind` | `process` (Node, Python, Ruby, Java, .NET, Go: a long-running process) or `request` (PHP, which runs per request). Anything else reads as `process`. |
| `pid` | The process ID. `process` only. |
| `up_s` | Seconds the process has run. Stored as `started_at`. `process` only. |
| `rss_mb` | The process's resident memory, MB. Left out where it can't be read. |
| `runtime` | e.g. `Node 26.13.0`, `Python 3.12.3`, `PHP 8.3.35`, `Ruby 3.3.6`, `Java 21.0.12.1`, `.NET 8.0.11`, `Go 1.23.4`. At most 40 printable characters. |

A number that is missing, negative or not a whole number is stored as null,
never as 0. The whole header may be up to 2000 characters, room for a
100-character name in any script once percent-encoded.

Node: the name falls back to the host name through
`process.getBuiltinModule("node:os")` (Node 20.16 and later), so the core needs
no Node built-in and the edge entry (`lib/next.js`, which sends no check-in)
still builds. On an older Node, a service without `serverName` sends none.

## What the dashboard makes of it

- **process**: up when heard from in the last 3 minutes, "Late" up to 10, then
  "Stopped" (red). A deploy that restarts it changes `pid` and `started_at`,
  not the light.
- **request**: PHP checks in only while it serves, so silence is never an
  outage.
- Either, silent for a day: grey ("retired, or quiet") and not held against
  the site. Unheard from for 30 days, the document expires (TTL on `at`).
- A service retired on purpose can be removed from Health → All systems
  (`POST /customer/status-board/forget`): its document is kept with
  `forgotten_at`, and the row stays grey until it checks in again.

The collector writes each service at most once every 50 seconds per collector
process, so a client that syncs more often costs nothing extra.

## Must

- Never block or fail the switches request over it: a header that can't be
  built is left out.
- Send the same `server` name the other modules send, or the service's
  check-in and its data show as two rows.
