# Posture protocol (v1)

What every server client reports about the way the site is *set up*, as
opposed to what it runs (`inventory.md`) or what its files are (`files.md`):
settings that leave the site open, who has admin rights, the places a hacker
hides to come back, and files in the web folder that should never be public.
The dashboard's Security check turns these into findings
(`backend/Sections/CustomerDash/security/securityPosture.js`), grades them with the
rest, and alerts between checks when something changes
(`attention.js`, check `server_posture`). Clients: the WordPress plugin
(`sdk/wordpress-plugin`, built on `sdk/platform-php`'s `Posture.php`), the PHP
package itself (Laravel included, opt-in), the Node package
(`sdk/platform-node`, `lib/posture.js`), the Python package
(`sdk/platform-python`, `analytics_platform/posture.py`, with Django's
settings when it's a Django site), the Ruby package (`sdk/platform-ruby`,
Rails' settings when it's a Rails app), the Java package
(`sdk/platform-java`, Spring Boot's settings), the .NET package
(`sdk/platform-dotnet`, ASP.NET Core's), the Go package (`sdk/platform-go`)
and the server agent (`sdk/vps-agent`).
The collector side is `expresscollect/Analytics/posture.js`.

Each client reports what it can actually see, and leaves the rest out: the
agent is the only one that reads sshd, cron files and SSH keys; the WordPress
plugin is the only one that knows about accounts and WP-Cron; the Node,
Python, Ruby, Java, .NET and Go packages read their own framework's settings.
Nothing is guessed.

**Reads only.** A client never changes a setting, a permission or a file to fix
what it finds: the dashboard says what to change and the owner changes it.

## Authentication

Like the firewall, file integrity and inventory: the site's ID and its secret,
`Authorization: Bearer <secret>`, and a `User-Agent` naming the client and its
version.

## When

Once soon after start (a couple of minutes, in the background), then every
`every` seconds from the last answer (a day by default). Never in a visitor's
request, and never more work than the file check already does: the lists below
are capped, and a client that can't answer something leaves the check out or
sends it as `unknown` rather than guessing.

The module switch is the inventory one (`inventory` in
`GET /events/platform/config`): a site with software inventory off reports no
posture either, and the answer says `enabled: false`.

## POST /events/posture

```json
{
  "site_id": "<id>",
  "host": "web-1",
  "at": "2026-10-18T12:00:00.000Z",
  "checks": [
    { "id": "wp.file_edit", "state": "fail" },
    { "id": "wp.code_writable", "state": "fail", "value": "3 files" },
    { "id": "php.display_errors", "state": "pass" }
  ],
  "facts": { "os": "ubuntu 24.04", "web_server": "nginx", "php_ini": "/etc/php/8.3/fpm/php.ini" },
  "accounts": {
    "total": 14,
    "admins": [
      { "name": "alice", "created": "2024-02-03", "last_login": "2026-10-17", "roles": ["administrator"] }
    ],
    "truncated": false
  },
  "persistence": {
    "cron": [ { "kind": "wp-cron", "name": "wp_version_check", "schedule": "twicedaily", "handler": true } ],
    "keys": [ { "user": "root", "path": "/root/.ssh/authorized_keys", "fingerprints": ["SHA256:3Xr…"], "mtime": "2026-09-01T10:00:00.000Z" } ],
    "files": [ { "path": "/etc/cron.d/backup", "sha256": "9f2…", "mtime": "2026-08-14T04:00:00.000Z", "entries": 2 } ]
  },
  "exposure": [
    { "path": "db-dump.sql", "kind": "database_dump", "size": 41231234, "mtime": "2026-10-11T02:00:00.000Z" }
  ]
}
```

- `host`: the server's name, as for file integrity and inventory.
- `checks`: at most 200. `id` is from the list below (`[a-z][a-z0-9_.]*`, 60
  characters at most); unknown ids are kept but say nothing on the dashboard,
  so a newer client can report more than the backend knows yet. `state` is
  `pass`, `fail` or `unknown` — the client decides *what is true*, the backend
  decides *how bad it is* and what to write about it, so wording and severity
  change without a new client release. `value` is an optional short string
  (200 characters) shown as evidence ("3 files", "yes", "22, 3306").
- `facts`: short strings the backend judges itself (the operating system's
  support dates, for instance). `os`, `os_name`, `os_version`, `kernel`,
  `web_server`, `php_ini`, `webroot`, `agent`: 100 characters each. A
  package's `agent` is its runtime and version: `python/3.12.3`,
  `ruby/3.3.6`, `java/21.0.5`, `dotnet/8.0.11`, `go/1.23.4`.
- `accounts`: the site's own accounts with rights, **names only, never email
  addresses or password hashes**. At most 50 admins (`truncated: true` past
  that); `created` and `last_login` are ISO dates or left out when the client
  can't know (a plugin only knows logins from its own install onwards).
- `persistence.cron`: scheduled jobs, at most 200. `handler: false` means
  nothing is registered to run it any more — a classic leftover of a hack.
- `persistence.keys`: SSH keys that can log in, at most 50 files. Key
  **fingerprints** (`ssh-keygen -lf` form), never the keys themselves.
- `persistence.files`: cron and startup files, at most 100: path, hash, time
  and how many entries. **Not the commands in them** — a change is reported,
  the content stays on the server.
- `exposure`: files in the web folder that should never be downloadable, at
  most 50. Path **relative to the web root** (no leading `/`), with its size
  and time; never the contents. A client that serves a folder under a prefix
  (Django's `STATIC_URL`, an Express `app.use("/assets", ...)`) reports the
  path **as the web serves it** (`static/dump.sql`), not as the disk has it,
  because the backend asks the site for exactly that address. `kind` is one of `database_dump`, `archive`,
  `env`, `backup`, `private_key`, `log`, `vcs`, `info`, `other`. `env` is any
  file of settings and secrets: `.env` and its variants, and on .NET
  `appsettings*.json`, `secrets.json` and a `web.config.bak`/`.old` copy (the
  backend confirms JSON and XML ones by their connection strings and
  secret-named keys). The backend
  then asks the site for each one over HTTP and only reports the ones that
  really answer, so a file behind a deny rule stays quiet.

The answer (`200`): `{ "v": 1, "enabled": true, "every": 86400 }`.
`enabled: false`: software inventory is off on the dashboard (or not in the
site's plan); ask again after `every` seconds.

## The checks

The client reports the state; the dashboard owns the wording, the severity and
the fix. Leave out what doesn't apply to the client's platform. An `app.*` id
several frameworks share means the same thing in each; the dashboard words the
fix for the framework the client names in its `User-Agent`
(`securityPosture.js`, `by` on the check), and in general terms when the
servers that failed it run different ones.

| id | `fail` means |
|---|---|
| `wp.file_edit` | the plugin and theme editor can edit code from wp-admin (`DISALLOW_FILE_EDIT` not set) |
| `wp.file_mods` | plugins and themes can be installed from wp-admin (`DISALLOW_FILE_MODS` not set) |
| `wp.debug_display` | `WP_DEBUG` is on with errors shown to visitors |
| `wp.debug_log` | debug logging writes a file under the web root |
| `wp.admin_user` | an account is called `admin` (or `administrator`) |
| `wp.open_registration` | anyone can register, and the default role isn't Subscriber |
| `wp.default_salts` | a key or salt in `wp-config.php` is still the example value |
| `wp.auto_update_core` | WordPress's own security updates are switched off |
| `wp.config_writable` | `wp-config.php` is writable by everyone |
| `wp.code_writable` | code files are writable by everyone (`value`: how many) |
| `wp.uploads_guard` | nothing stops PHP in `wp-content/uploads` from running |
| `wp.force_ssl_admin` | the site is HTTPS but wp-admin doesn't require it |
| `wp.xmlrpc` | `xmlrpc.php` answers (password guessing and pingback floods) |
| `wp.rest_users` | the REST API lists accounts to anyone |
| `wp.two_factor` | no two-factor plugin is active (`value`: how many admins) |
| `wp.db_prefix` | the database prefix is the default `wp_` |
| `php.display_errors` | PHP shows errors (and file paths) to visitors |
| `php.expose_php` | PHP announces its version in headers |
| `php.allow_url_include` | PHP can include code from a URL |
| `php.session_httponly` | session cookies are readable by JavaScript |
| `php.session_secure` | session cookies are sent over plain HTTP too |
| `php.error_log_webroot` | PHP's error log is inside the web folder |
| `server.runs_as_root` | the site's own code runs as root (uid 0) |
| `app.node_env` | `NODE_ENV` isn't `production` |
| `app.django_debug` | Django runs with `DEBUG` on |
| `app.rails_env` | Rails doesn't run in `production` (`value`: the environment it runs in) |
| `app.rails_debug` | Rails shows full error pages to every visitor (`consider_all_requests_local` on) |
| `app.aspnetcore_env` | ASP.NET Core runs in the `Development` environment, where the developer exception page shows visitors stacks and source (`value`: the environment) |
| `app.error_details` | Spring Boot's error pages include stack traces or exception details (`server.error.include-stacktrace`, `include-exception`; `value`: which) |
| `app.actuator_exposed` | Spring Boot Actuator endpoints that hand out secrets or control (`env`, `heapdump`, `configprops`, `shutdown` and the like) are exposed over HTTP on the site's own port (`value`: which) |
| `app.h2_console` | the H2 database console is on (`spring.h2.console.enabled`) |
| `app.go_pprof` | `net/http/pprof`'s handlers are on `http.DefaultServeMux` (`value`: `/debug/pprof/ on http.DefaultServeMux`) |
| `app.secret_key` | the key that signs sessions is missing, short or a placeholder: Django's `SECRET_KEY`, Rails' `secret_key_base` |
| `app.allowed_hosts` | any Host header is accepted: Django's `ALLOWED_HOSTS` contains `*`, Rails' `config.hosts` is empty or has `*`, ASP.NET Core's `AllowedHosts` contains `*` (the template's default, so most .NET apps fail it until it's set) |
| `app.session_cookie_httponly` | session cookies are readable by JavaScript (Django and Rails sessions, ASP.NET Core's cookie-auth schemes, Spring Boot's servlet session) |
| `app.session_cookie_secure` | session cookies are sent over plain HTTP too (the same cookies; only sent once the site is known to be on HTTPS) |
| `app.csrf_cookie_secure` | the CSRF cookie is sent over plain HTTP too (Django's CSRF cookie, ASP.NET Core's antiforgery cookie, whose default `SecurePolicy` is `None`) |
| `app.https_redirect` | the app doesn't send plain HTTP to HTTPS itself (Django's `SECURE_SSL_REDIRECT`, Rails' `force_ssl`) |
| `server.ssh_root_login` | sshd lets root log in |
| `server.ssh_password_auth` | sshd accepts passwords (keys only is safer) |
| `server.auto_updates` | unattended security updates aren't set up |
| `server.security_updates` | updates that close a security hole are waiting to be installed (`value`: how many, and how many updates in all). `unknown` on a machine whose package manager the client doesn't know |
| `server.reboot_required` | an update needs a restart to take effect |
| `server.listening_ports` | ports besides the web and SSH ones listen on every address (`value`: which) |
| `server.docker_socket` | an account other than root can write to the Docker socket (root on the host, in effect); the group bit alone doesn't count, `value` names the accounts |
| `server.tcp_syncookies` | SYN cookies are off (`net.ipv4.tcp_syncookies` is 0), so a flood of half-open connections fills the queue and real visitors can't connect; `value` is `off`. Left out when the client can't read the setting |
| `server.code_writable` | code files under the web root are writable by everyone (`value`: how many) |

## Leaving a section out says something

The dashboard shows the owner **what was checked and what nothing checked**
(backend `securityPosture.js` `coverageOf`), because "nothing found" and
"nobody looked" read the same on a grade otherwise. It can only do that
because a section that is **present but empty** means *looked, found nothing*,
and a section that is **missing** means *this client can't see that*.

So: send a section only when you looked. A client with no web folder to walk
leaves `exposure` out rather than sending `[]`; a client that can't see
accounts leaves `accounts` out. A section left out keeps what this client last
reported for it. What a section first reports counts as already there, not new,
so the alerts start from the next report (`exposure` alerts from the first).

Clients are told apart by their `User-Agent` (`analytics-platform-<name>/<version>`),
because the agent and a package on one machine report under one `host`. Each
kind has its own record and history, so neither overwrites the other, and one
that stops reporting is flagged while the other carries on.

Each area and what covers it:

| area | from | reported by |
|---|---|---|
| settings that leave the site open | `wp.*`, `php.*`, `app.*` checks | each package, for its own platform |
| how the site's own code runs | `server.runs_as_root`, `server.code_writable` | every client |
| files in the web folder | `exposure` | the clients that serve a web folder |
| who has admin rights | `accounts` | the WordPress plugin |
| scheduled jobs | `persistence.cron` | the WordPress plugin |
| SSH keys that can log in | `persistence.keys` | the agent |
| scheduled job files | `persistence.files` | the agent |
| the server itself | `server.ssh_*`, `server.auto_updates`, `server.security_updates`, `server.reboot_required`, `server.listening_ports`, `server.docker_socket`, `server.tcp_syncookies` | the agent only |

The last area counts as checked **only** for those ids: a package that reports
`server.runs_as_root` has not looked at sshd, the updates or the open ports,
and the dashboard must not say it has.

## Must

- **Read only**: never write, move, chmod or delete anything on the site.
- **Never the contents**: paths, hashes, sizes, times, fingerprints, account
  names, version strings and short values only.
- **Fail quiet**: a check that errors is `unknown` or left out — it is never
  reported as `fail`, and one check failing never stops the report.
- **Bounded**: the caps above, and the file walk stops at the same limits as
  `files.md` (50,000 files); past that send what there is.
- A failed request is retried later (an hour), never in a loop.
