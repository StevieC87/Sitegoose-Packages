# Windows server agent (IIS)

The site firewall and flood protection for Windows Server with IIS: the same
rules as the Linux agent (`sdk/vps-agent`, protocol in
[`sdk/protocols/firewall.md`](../protocols/firewall.md)), put in place with
Windows Firewall and IIS. One PowerShell file, Windows PowerShell 5.1, no
modules to install, run as SYSTEM by a scheduled task.

**Not yet run on a real Windows Server or IIS.** Everything below is tested
on PowerShell 7 under Linux with the Windows and IIS calls mocked; see
"What is and isn't verified".

## Install

In an elevated PowerShell on the server:

```powershell
[Net.ServicePointManager]::SecurityProtocol = 'Tls12'
Invoke-WebRequest https://COLLECTOR/downloads/agent/windows/install.ps1 -UseBasicParsing -OutFile $env:TEMP\agent-install.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File $env:TEMP\agent-install.ps1 -Endpoint https://COLLECTOR -SiteId SITE_ID
```

The first line is for Windows Server 2016 and older, whose PowerShell
doesn't offer TLS 1.2 by itself. It asks for the site secret (or reads `ANALYTICS_SITE_SECRET`). `-Sha256`
(or `ANALYTICS_AGENT_SHA256`) pins the agent's checksum. The endpoint must be
https (`ANALYTICS_INSECURE=1` allows http for a local collector).

The installer:

- puts the agent in `%ProgramFiles%\AnalyticsAgent\analytics-agent.ps1`;
- writes `%ProgramData%\AnalyticsAgent\config.json`, which only SYSTEM and
  Administrators can read. The folder is given to Administrators as owner,
  its permissions are reset to SYSTEM and Administrators only, and a junction
  or link in its place is refused. The agent itself refuses a config whose
  folder or file is owned by anyone but SYSTEM, Administrators or
  TrustedInstaller, a `state_dir` or `page_dir` outside the config's folder,
  and a junction or link for any of them;
- runs the agent once (that run must reach the collector);
- registers the scheduled task `AnalyticsAgent`. The task runs as SYSTEM at
  startup and is started again within 5 minutes if it stops. Inside the task,
  the agent fetches the rules every `sync` seconds (30 at least) and reads
  IIS's logs every 5 seconds.

`install.ps1 -Uninstall` stops the task and takes every rule away (`clear`).
Only if that succeeds does it remove the task and the folders. It keeps
`%ProgramData%\AnalyticsAgent\state\iis-backups`, and says so. If `clear`
fails, everything stays, so it can be run again.

`clear` exits 1 when anything is left: a firewall rule, an IIS change, or IIS
configuration it couldn't read. Then it keeps the check page and its state,
which knows what to restore, for the next try. Without a readable config it
clears with the default folders and `check_substatus` (from a damaged file if
it can be read). `once` and `clear` refuse to run, exiting 1, while the
scheduled task runs; `run` exits 0, since one is already running.

Commands: `analytics-agent.ps1 run | once | status | clear | version`. The log
is `%ProgramData%\AnalyticsAgent\agent.log`.

Optional features the agent uses when present (`status` says what's missing):

- **IP and Domain Restrictions**, for the request limits:
  `Install-WindowsFeature Web-IP-Security`.
- **URL Rewrite 2.1**, for the browser check: from iis.net.

## Layers

`X-Firewall-Layers` names only what is really in place:

| Layer | What it does |
| --- | --- |
| `windows-firewall` | Blocks `deny`, `lists`, `shared` and `banned`, plus local bans, with inbound block rules on the web ports only (`ports`, default 80 and 443). The rules are named `AnalyticsAgent-<Lists\|Bans\|Origin>-<TCP\|UDP>-NNN` and sit in the group `AnalyticsAgent`. They are split into chunks of 500 addresses (`firewall_chunk`, 1000 at most) and changed in place. `allow` is subtracted, because a block rule beats an allow rule. Monitor mode writes no rules; the lists are then watched in the logs and reported as `monitor`. |
| `origin` | With `origin.only`, blocks everything except `only`, `allow`, private and loopback ranges, the server's own addresses and Azure's platform address `168.63.129.16`, on the web ports, for both IPv4 and IPv6. An `origin` with no valid range is ignored. In monitor mode, visitors from outside are reported (rule `origin`) and not blocked. The lock stays off, with a note in `status`, while anything that isn't a website answers on the web ports: Remote Desktop Gateway, Windows Admin Center, an SSTP VPN, or WinRM (a listener or its compatibility listener on those ports, or a `/wsman` URL). Those are looked at every 10 minutes. |
| `iis` | IIS Dynamic IP Restrictions at server level, from `flood`, in block mode only, and off while the origin lock is on (only the CDN would reach IIS, so it would count the CDN). It counts every request, images and scripts included, so `maxRequests` is 20 requests a page: the larger of 500 and (`req_rate`×10+`req_burst`)×20, over 10 s. `maxConcurrentRequests` is the larger of 100 and `conn_max`. Denied requests get 403. The exempt ranges and the server's own addresses are added first as `ipSecurity` allow entries. The layer stays off, named in `status`, where a site, application, folder or `<location>` clears or removes `ipSecurity` entries, since the allow entries wouldn't reach it. What IIS turns away (403.501 and 403.502) is reported once per address as `flood` in `monitor`, and not banned or shared: those limits are the server's own, not the rules'. Bans in force (IPv4, at most 500, those that last longest) are also added as `ipSecurity` deny entries, after the owner's, so IIS refuses them too. The agent adds and removes only its own entries. |
| `logs` | Reads the W3C logs (by the `#Fields:` line of IIS's own header block, the one with `#Software: Microsoft Internet Information Services`; a line whose date, time or method isn't what IIS writes is dropped; `c-ip` only, pages only, not static files) through a token bucket per address (IPv6 per /64), with `req_rate` and a capacity of `req_burst` + 1. An address over the limit is banned in Windows Firewall for `flood.ban` seconds and reported as `rate`. In monitor mode nothing is banned, and each address is reported once per ban period. |
| `iis-check` | The browser check, while the rules carry `challenge` (details below). |

No IIS change is made unless all of these hold:

- the config file is backed up first (`state\iis-backups`). The copy from
  before the agent's first change, `applicationHost-before-agent.config`, is
  kept for good, and the last 10 others;
- every write is one commit;
- the config can be read back after the commit, or the backup goes back;
- each started site on the web ports (10 at most) is asked for `/` from the
  server itself before and after the commit, and the backup goes back if one
  that answered now answers 500 or a configuration error (500.19, 500.5x).
  Ban entries skip this, since they can't break a site;
- the owner's values are saved before the agent's first write and restored
  when the layer turns off.

The agent never touches a firewall rule outside its own group and prefix. No
rule of its own ever names port 22, 135, 139, 445, 3389, 5985 or 5986, and
none can block every port or every address. A block-list range wider than /8
(IPv6 /32) is dropped, as is any IPv6 range covering the IPv4-mapped block
`::ffff:0:0/96`, which would hit every IPv4 visitor.

## The browser check in IIS

A URL Rewrite global rule, first in the list, gives a 503 with a private
sub-status (`check_substatus`, default 71). It applies to a GET or HEAD request
that:

- asks for `text/html`;
- comes from IPv4;
- falls outside the skip prefixes (percent-decoded first) and the exempt
  ranges, and doesn't come from the server's own addresses;
- carries no `__sg_passn` cookie with today's or yesterday's server-level pass
  (`who = *`).

A server-level `httpErrors` entry shows `%ProgramData%\AnalyticsAgent\www\check.html`
for 503.71 only, so real 503s keep their own page. When `check_substatus`
changes, the old entry is taken out. The rule also sets the
server variable `SG_CHECK`, which outbound rules match on. They add
`Cache-Control: no-store`, `X-Robots-Tag: noindex` and a Content-Security-Policy
to the check page's responses only. That policy allows the page's single script
and style by hash, since a static page can't carry a nonce.

- **Rewriting the rule:** the agent rewrites it once a day, and only after the
  rule accepts the new pass does the page hand it out.
- **Which sites are checked:** only those with an http or https binding on the
  web ports, and only where the page is shown for sure. The site's error pages
  must include ours, it must not show detailed errors, it must not pass error
  responses through, and any CSP header of its own must allow our script. A site
  with an application, virtual folder or folder holding its own `web.config`
  is skipped, since that can change any of these below it. The rest are skipped
  and named in `status`.
- **The page's permissions:** checked on every round. If IIS (IIS_IUSRS and
  IUSR) can't read the page, the agent grants them read; if that doesn't take,
  the rule is taken out and `status` says why.
- **Visitors never checked:** IPv6 visitors, because IIS writes IPv6 addresses in
  more than one form and an exempt one might be missed.

## Its services

Every minute (from 0.2.0) the agent also reports whether the server's Windows
services run, for Health -> All systems (`POST /events/services`,
`sdk/protocols/services.md`): the ones listed under `services` in the config,
and, unless `services_detect` is `false`, the common ones it finds (IIS's
W3SVC and WAS, SQL Server and its agent, MySQL, MariaDB, PostgreSQL, Redis,
Memurai, MongoDB, RabbitMQ, memcached, Elasticsearch, nginx, Apache, Tomcat,
ClickHouse, Docker). A found one is shown while it runs or starts with
Windows, and for a week after it last ran, even across a restart of the agent
(`state\services.json`), so a service that stopped is red rather than
missing. One uninstalled goes at once. Each is sent as type `unit`.

A running one carries what it uses ("Usage"): its process's working set
(`mem_mb`) and its CPU as a share of the whole machine (`cpu_pct`, from two
readings a minute apart, so the first report has none), by the service's
`ProcessId`. Services that share one svchost process can't be told apart:
the process is counted once, for the first of them in the report (the listed
ones first, then the found ones by name), and the others carry no figures. A service's child processes aren't counted (IIS's w3wp
workers belong to WAS, not W3SVC), and a process Windows protects from
reading sends nothing. Windows sets no memory cap or kill count on a service,
so `mem_limit_mb` and `oom_kills` are never sent.

`analytics-agent.ps1 services` checks them now, prints them and reports them.

## Backups

Every night (or weekly, or when you ask), the databases and folders you list into your own storage, with
[restic](https://restic.net): encrypted here, with a password made here that
only you have. No copy ever reaches us; Health → Backups shows what ran, a
missed or failed backup is an alert, and a part or a whole run can be downloaded or put back.

```json
"backups": {
  "repository": "s3:https://nbg1.your-objectstorage.com/my-bucket/web-1",
  "env": { "AWS_ACCESS_KEY_ID": "…", "AWS_SECRET_ACCESS_KEY": "…" },
  "databases": [{ "sqlserver": "local" }, { "mysql": "mysql://backup:…@127.0.0.1/shop" }],
  "folders": ["C:\\inetpub\\wwwroot", "C:\\sites\\shop"]
}
```

then, as an administrator, `analytics-agent.ps1 backup-setup`: it installs
restic to `%ProgramData%\AnalyticsAgent` (a pinned version, checked against
its SHA-256), makes the password (in `backup-password.txt` beside the config)
and shows it once, and makes the repository. **Keep the password in your
password manager**: without it no backup can be read, and we can't recover it.
Then restart the agent (`Stop-ScheduledTask AnalyticsAgent; Start-ScheduledTask AnalyticsAgent`),
which reads the config when it starts.

- **SQL Server** with `BACKUP DATABASE … WITH COPY_ONLY`, so your own backup
  plan's chain is left as it is. This machine's SQL Server only. The agent runs
  as SYSTEM, which SQL Server doesn't make a sysadmin: grant it once
  (`sqlcmd -S . -E -Q "ALTER SERVER ROLE sysadmin ADD MEMBER [NT AUTHORITY\SYSTEM]"`)
  or put a SQL login in a `sqlserver://user:pass@localhost` URL.
- **MySQL/MariaDB, PostgreSQL, MongoDB** by a connection string, with their
  own `.exe` tools (on `PATH` or where their installers put them).
- **Folders** through a shadow copy (VSS), so files IIS or SQL Server hold open
  are read whole.

Runs at 03:00 every night; `"schedule": "weekly"` (with `"weekday"`) or
`"off"` changes when, what's set on the dashboard wins, and "Back up now"
there runs one at once. No storage of your own? A folder (`"repository":
"D:\\Backups\\sitegoose"`) keeps them on this machine, and downloads come from
us instead: kept a day, encrypted here for the one browser that asked (Basic
and Pro, or a $3 add-on on Free), made in `"temp_dir"` first.

The backups run in a process of their own (`backup-worker`), which the agent
starts, so a long one never holds up the firewall. A restore from the dashboard
only with `"allow_restore": true`; it backs up what it replaces first and
undoes itself if anything fails.

    analytics-agent.ps1 backup              back up now
    analytics-agent.ps1 backups             list them
    analytics-agent.ps1 restore RUN [PART...] [-Into FOLDER] [-Yes]
    analytics-agent.ps1 export RUN PART FILE

Every key, and how a restore goes: [`sdk/protocols/backups.md`](../protocols/backups.md).

## Config

`%ProgramData%\AnalyticsAgent\config.json`:

- `site_id`, `secret` and `endpoint`;
- `ports` (default `[80, 443]`);
- `windows_firewall`, `iis_limits`, `iis_check` and `logs`: each one switches a
  layer off when set to `false`;
- `iis_log_dirs`: where the logs are. The default is each site's own log
  folder, else `%SystemDrive%\inetpub\logs\LogFiles\W3SVC*`;
- `services`: Windows services to check besides the ones found, by name
  (`"MyApp"`) or as `{"service": "MyApp", "name": "shop api"}`;
  `services_detect` (default `true`) finds the common ones;
- `firewall_chunk`, `check_substatus` and `flush_log_buffer`. With
  `flush_log_buffer`, the agent runs `netsh http flush logbuffer` every 5
  seconds, so the logs are current.

## Tests

The tests use Pester 5 on PowerShell 7 and need no Windows. From `sdk/`:

```sh
docker run --rm -v "$PWD:/sdk:ro" -v /path/with/Pester:/mods:ro -e PSModulePath=/mods \
  mcr.microsoft.com/powershell pwsh -NoProfile -File /sdk/windows-agent/tests/run.ps1
```

`tests/run.ps1 -Filter Iis.Tests.ps1` runs one file. `Compat.Tests.ps1` parses
both scripts and rejects syntax, parameters and .NET APIs that Windows
PowerShell 5.1 lacks, as well as any non-ASCII byte.

`./build.sh` copies the agent and installer to
`expresscollect/public/downloads/agent/windows/`.

## What is and isn't verified

**Tested** (mocked where it touches Windows):

- address math, the origin complement and the CIDR-to-regex conversion,
  against brute-force checks;
- the shared challenge cases, and the rewrite rule against those cases in a
  URL Rewrite simulation;
- firewall diffs, IIS change sets, log tailing, the token bucket and event
  grouping;
- clear and uninstall leaving nothing half done, the rollback after a probe,
  the backups, the IIS ban entries, the origin lock's exceptions, the config
  folder rules and the timeouts (`Hardening.Tests.ps1`).

**Not verified:**

- how Windows Firewall writes back RemoteAddress;
- whether Dynamic IP Restrictions honours the `ipSecurity` allow entries.
  Microsoft documents an allow list, but the agent has never been tried against
  a real server;
- whether URL Rewrite's `CustomResponse` lets the `httpErrors` page through;
- whether the outbound rules apply to that error response;
- whether `{INSTANCE_ID}` is set for global rules. If it isn't, the check
  never fires, so it fails safe;
- the scheduled task;
- whether URL Rewrite's `{URL}` is percent-decoded, as the skip prefixes
  assume;
- the probe after a commit, the `netsh` and `winrm` output the origin lock's
  exceptions are read from, and how Microsoft.Web.Administration reports
  applications and virtual folders;
- the services report against a real Windows: `Win32_Service` through CIM and
  the process readings are mocked in `Services.Tests.ps1`.
- backups on a real Windows: VSS, `robocopy`, SQL Server's `BACKUP` and
  `RESTORE` through `sqlcmd` as SYSTEM, the `.exe` tools, and a real S3 bucket.
  `Backups.Tests.ps1` runs a real restic (backup, report, restore, undo,
  export) on folders under PowerShell 7 on Linux, and checks the S3 signing
  against AWS's own examples.

**Not covered:**

- other platforms' health probes. Only Azure's `168.63.129.16` is exempt from
  the origin lock. A Google Cloud load balancer probes from `35.191.0.0/16` and
  `130.211.0.0/22`, and AWS from the load balancer's own private addresses
  (already allowed). Add those to `allow` when the server sits behind one.

**Can't be done on Windows:**

- `conn_rate`, which has no Windows equivalent;
- counters for the Windows Firewall blocks. Block mode reports bans, IIS
  denials and checks, but not drops from the lists or the origin lock;
- the browser check for IPv6 visitors.
