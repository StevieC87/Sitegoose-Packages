# Server agent

The analytics firewall for any Linux server, whatever runs on it: Rails,
Django, .NET, Go, Java, PHP, static sites behind nginx. One small Python 3
script (standard library only) run by systemd. The protocol it follows is
`sdk/protocols/firewall.md`.

```bash
curl -fsSL https://YOUR_COLLECTOR_URL/downloads/agent/install.sh -o /tmp/agent-install.sh
sudo ANALYTICS_ENDPOINT=https://YOUR_COLLECTOR_URL ANALYTICS_SITE_ID=YOUR_SITE_ID sh /tmp/agent-install.sh
```

It asks for the site secret, writes `/etc/analytics-agent.json` (root only),
fetches the rules once and starts the `analytics-agent` service. The backend:
`ANALYTICS_BACKEND` when given, else the one an earlier install wrote, else
nftables when `nft` is there, else iptables when `iptables` and `ipset` both
are, else nginx when it is installed, else none.

## Backends

- **nftables** (when `nft` is installed): its own table, `inet analytics_firewall`,
  drops listed addresses on the web ports (80 and 443; `"ports"` in the config)
  before anything else sees them, Docker's published ports included. Other
  ports, SSH included, are never touched, and nor is traffic only routed
  through the server (to a VM, a VPN client or a container on its own public
  IPv6 address): only what is addressed to the server itself, as the visitor
  asked for it (before Docker's NAT). Every listed address and range has a
  packet counter, so blocked (or, in monitor mode, matched) traffic shows on the
  Firewall tab, counted in packets.
- **iptables** (`ANALYTICS_BACKEND=iptables`, or `"backend": "iptables"`): the
  same as nftables, every layer included (`kernel`, `flood`, `origin`), for
  servers without nftables. Details below.
- **auto** (`"backend": "auto"`): nftables when `nft` works on this server, else
  iptables when both `iptables` and `ipset` are installed, else none. Opt-in:
  an existing config keeps the backend it names.
- **nginx** (`ANALYTICS_BACKEND=nginx`): allow/deny lines in
  `/etc/nginx/analytics-firewall.conf`; add `include /etc/nginx/analytics-firewall.conf;`
  to the `http { }` block. The agent runs `nginx -t` before every reload and puts
  the old file back if it fails. Nothing is reported, and monitor mode blocks nothing
  (and writes no lines, so `nginx-lists` is reported only in block mode, once
  `nginx -T` shows the file included). A reload that fails is tried again next round.
  The kernel's flood limits and origin lock need nftables or iptables; nginx's request limits
  and browser check (below) work with either backend. Switching away from
  nftables removes the agent's two tables (the origin lock included) rather than
  leaving them in place unmaintained (and switching away from iptables, its
  chains and ipsets); switching away from nginx empties the allow/deny file.

### iptables + ipset

**When to choose it**: the server has no nftables — CentOS 7, Ubuntu 18.04,
Debian 9/10, many minimal and container images — or its firewall is
iptables-legacy (Docker's rules there, an iptables-based firewall script) and you
won't add `nft`. Where `nft` is installed and works, use nftables: it is the
better fit, and the agent says so in its log when it finds iptables running
on nftables underneath (iptables-nft) with `nft` there. It still works as asked.

**What it needs**: `iptables` (1.4.21 or later, legacy or nft) and the
**`ipset` package**, which most servers don't have:

```bash
apt-get install ipset      # Debian, Ubuntu
yum install ipset          # CentOS 7; dnf install ipset on RHEL, Rocky, Alma 8+
```

**Owner steps**: install `ipset`, then either install with
`ANALYTICS_BACKEND=iptables` (the install command above, with that variable),
or on an installed agent set `"backend": "iptables"` (or `"auto"`) in
`/etc/analytics-agent.json` and `systemctl restart analytics-agent`. The agent
removes the nftables tables an earlier run left. `analytics-agent status` shows
`iptables: legacy 1.8.9` (or `nft`), and the layers that run.

What it puts in place, all its own (nothing of yours is flushed or moved):

- Chains `ANALYTICS-FW` (the address lists) and `ANALYTICS-FLOOD` (the
  limits and the origin lock) in the **mangle** table, jumped to from the top
  of `PREROUTING` for the web ports only (`"ports"`, TCP and UDP), by rules
  tagged `-m comment --comment analytics-agent`, and for packets addressed to
  the server only (`-m addrtype --dst-type LOCAL`, as Docker's own rule): what
  is routed through it to a VM or a VPN client is left alone. PREROUTING rather
  than INPUT, as with nftables: Docker's published ports never pass INPUT, and
  there the address is still the one the visitor asked for. The jumps go in
  once and stay where they are. Every rule of ours ends in RETURN or DROP,
  never ACCEPT, so your own mangle rules still see every packet we let through.
- ipsets `analytics-list-*` (allow, deny, ban, list, shared; IPv4 and IPv6 as
  `…4`/`…6`), each filled under another name and swapped in, so a change is
  atomic; and `analytics-flood-*` (the bans, the origin lock's counts, the
  exempt, origin and private ranges). Sized for 65,536 entries or more. A list
  of everyone (`0.0.0.0/0`, `::/0`), which ipset can't hold, is held as its two halves.
- IPv4 through `iptables`, IPv6 through `ip6tables` (where the kernel has IPv6,
  and ip6tables can use its mangle table: where it can't, the agent says so once
  and covers IPv4 only).
  Which iptables: the system's; with both iptables-legacy and iptables-nft
  installed, the one that holds the server's rules.
- Connection limits: `hashlimit` (new connections a second per address, bursts
  of twice that; at most 10,000 a second, which the agent logs when it lowers
  `conn_rate`) and `connlimit` (open at once), an IPv6 address by its /64. Over
  either, the rule itself puts the address in the ban set for `ban` seconds.
  The ban sets are never rebuilt on a rules change, so bans outlive it; after
  a reboot the agent puts back the ones still running. Only a set of ours that
  an older or newer agent made differently is started over (losing its bans);
  any other refusal leaves everything in place and is tried again. On a kernel
  whose ipset target can't give a ban its time (very old ones), the agent ends
  each ban itself, and says so.
- `hashlimit` fails closed: when its table of addresses is full it drops a new
  address's packet, whatever the rule. So the agent sizes it at twice the
  kernel's connection table (`nf_conntrack_max`, within 262,144 and 4,194,304
  addresses): a new address needs an entry there first, and when that table is
  full the kernel drops new connections anyway. Past that, under a flood from
  more distinct addresses than that within a minute, new visitors' first
  packets can be dropped by the meter; the `conn_max` limit and nftables don't
  have this edge. For the same reason **monitor mode has no `conn_rate`
  limit on iptables**: only `conn_max` is counted there (nftables counts both).
- Monitor mode drops nothing: matches are only counted (ipset's per-entry
  counters), and reported as with nftables.
- After a reboot or an `iptables -F`, the next round (within a minute) puts
  everything back: that is the agent's job, not `iptables-save`.

Two things to know:

- **Don't save the agent's rules with your own** (`iptables-save >
  /etc/iptables/rules.v4`, `netfilter-persistent save`, `service iptables
  save`) while the agent runs. The saved file then names ipsets that don't exist
  at boot, and iptables refuses the whole file, your own rules with it. Save
  after `analytics-agent clear`, or filter out the lines with `analytics`.
- A firewall that rewrites the whole mangle table (`iptables-restore` without
  `--noflush`, firewalld reloads on some versions) removes our chains too; the
  agent puts them back within a minute.

## Flood protection

On paid plans the rules carry three more keys (`flood`, `origin`, `challenge`;
`sdk/protocols/firewall.md`, "Flood protection"). The agent puts each where
this server can enforce it, and tells the dashboard which of them really run
(the `X-Firewall-Layers` header on every rules fetch, with the server's name):
`kernel` (the address lists above), `flood`, `origin`, `nginx`, `nginx-limits` (page limits, below),
`nginx-check`, `logs`, `apache-check`, `litespeed-check`, `caddy-check`, `haproxy-check`.
A layer this server can't run is left out rather than claimed.

**In the kernel** (nftables backend; the iptables backend does the same with its
`ANALYTICS-FLOOD` chain and `analytics-flood-*` ipsets), a second table, `inet analytics_flood`:

- On the web ports, TCP and UDP: at most `conn_rate` new connections a second
  per address (bursts of twice that) and `conn_max` connections open at once.
  Over either, the address is banned for `ban` seconds: in block mode every
  packet from it is dropped, in monitor mode it is only counted.
- An IPv6 address is counted and banned by its **/64**: one machine usually has
  the whole /64, so a per-address limit would never trip.
- Never counted or banned: `allow`, the good bots, `flood.exempt` (Cloudflare's
  ranges, the search engines') and the private, loopback and shared ranges
  (`10/8`, `172.16/12`, `192.168/16`, `127/8`, `100.64/10`, `169.254/16`,
  `::1`, `fc00::/7`, `fe80::/10`). That is what keeps a site behind Cloudflare
  or a load balancer online: all its visitors arrive from a few addresses.
  Nor are the server's own public addresses (read from `/proc` every five
  minutes) by nginx's limit or `logs`: its requests to its own public address
  (a cron job, WordPress's loopback) carry them.
  Nor is anything arriving over `lo`: the server's own requests, to its public
  address too (Linux sends those over loopback), never meet the limits or the lock.
- **Origin lock** (`origin`, sent once the site's domain is shown to resolve to
  Cloudflare): the web ports take traffic only from Cloudflare's ranges and
  `allow` (and the private and loopback ranges), so someone who found the
  server's own address can't go around Cloudflare. Block mode drops the rest,
  monitor mode counts it; both report it per source. Each of IPv4 and IPv6 is
  locked only when the origin's ranges include some of that family, so a list of
  IPv4 ranges alone leaves IPv6 visitors alone rather than shutting them all out.
- **Bans survive a rules change.** The address table is rewritten whole on
  every change; this one is changed in place, so a banned address isn't let
  back in each time `banned` or `shared` changes. Each ban is reported once
  (rule `flood`, with the packets it caught by then as hits). After a reboot or
  an nftables restart the bans still running are put back for the time they
  have left. At most 50,000 bans are watched at once (the set holds 65,535).
- `analytics-agent clear` removes it with the address table, whatever the backend
  (and the iptables chains and ipsets, if any).

**In nginx**, whatever the backend, when nginx is installed. The agent writes
two files and you include them; it never edits your own configuration.

1. `/etc/nginx/analytics-flood.conf`, **once, inside `http { }`** (in
   `/etc/nginx/nginx.conf`):

   ```nginx
   http {
       include /etc/nginx/analytics-flood.conf;
       ...
   }
   ```

   At most `req_rate` requests a second per address (an IPv6 /64 counts as
   one), bursts of `req_burst`; over that nginx answers `429`. In monitor mode
   nginx limits nothing and nothing is reported as `rate` (the kernel limits
   still count): nginx's `limit_req_dry_run` can't be set for one zone, so it
   would turn your own `limit_req` lines into log-only too. Static files (by
   extension: css, js, images, fonts, media, pdf) and exempt addresses don't
   count. The agent reads nginx's error log (found with `nginx -T`, else
   `/var/log/nginx/error.log`), bans each limited address in the kernel for
   `ban` seconds when the kernel's ban set is there (nftables or iptables), and reports it once as rule
   `rate`.

2. `/etc/nginx/analytics-check.conf`, **inside each `server { }` that serves
   pages**, near the top (before any `return` or `rewrite` of your own):

   ```nginx
   server {
       server_name example.com;
       include /etc/nginx/analytics-check.conf;
       ...
   }
   ```

   The browser check (`challenge`): a `GET` or `HEAD` asking for `text/html`,
   on a path not in `skip`, from an address not exempt and without a pass gets
   a small `503` page that sets the `__sg_passn` cookie with JavaScript and
   reloads. Never a `POST`, an API call, a feed reader or curl. The pass is
   written into the file per day (today's and yesterday's count), so the agent
   rewrites it when the day changes. Checked requests are logged to
   `/var/log/nginx/analytics-check.log` and reported per address. With the
   check off the file does nothing, so the include can stay.

**Your own `limit_req` lines count too.** With flood protection on, in either
mode and with or without the two files above, the agent reads nginx's error
logs for what *your* limits refused (any zone that isn't the agent's) and
reports it every 15 seconds as rule `nginx`: the busiest 500 addresses one row
each, the rest as one row per family (`0.0.0.0/0`, `::/0`), so a flood from
thousands of addresses is counted whole. Nobody is banned for it; your limit
already answered `429`. That is what lets the flood watch tell you about a
flood nginx is holding back on its own. The lines have to reach the error log:
`limit_req_log_level error` (nginx's default), not `notice` or `info`.

Every change runs `nginx -t` first and puts the old files back if it fails;
only then is nginx reloaded. Until a file is included nginx does nothing with
it, and the agent says so in its log (`journalctl -u analytics-agent`) and
leaves `nginx` / `nginx-check` out of what it reports. Removing the agent: take
the two `include` lines out before deleting the files, or nginx won't start.

**Page limits** (`limits` in the rules, every plan; `sdk/protocols/firewall.md`,
"Page limits") go in the same `http { }` file, so the one `include` is all they
need, with flood protection on or off. Only the limits whose action is `block`
reach the agent, and only in block mode does it write them (the reason above).
Each is a `limit_req` zone of its own (`sg_pl_` and ten hex digits of the SHA-1 of
its id, so reordering the limits renames nothing) keyed by address
(an IPv6 /64 as one) when the method, the path as nginx routes it (`$uri`:
decoded, `//` as `/`, dot segments resolved) and the raw query (each character
as it is or percent-encoded) match; `limit` at once, then `limit`/`window` at
nginx's rate, which is whole requests a second or a minute (rounded up; 1 a
minute at least, so 5 an hour lets 5 through, then 1 a minute). Over it nginx
answers `429` (without `Retry-After`: nginx's own answer has none), the agent
reports each limited request from the error log as rule `limit:<id>` with its
method and path, and bans nobody. Never counted: the limits' `exempt`, `allow`,
the good bots, `flood.exempt` when flood is on, the private ranges, this
server's own addresses and static files. Left out: limits with `each: "path"`
(a count per page would let an address fill nginx's zone with made-up pages,
and a full zone refuses everyone), and any path or query entry holding
characters that can't be carried in nginx's configuration as they are (quotes,
braces, `;`, `$`, `\`, spaces, `%` in a path, non-ASCII): a limit left with
nothing in a section it names is left out whole. Should
`nginx -t` refuse them anyway, the file goes in without them (flood and the
browser check unchanged) until the rules change. `nginx-limits` is reported
only while they run.

nginx gives a `server { }` or `location` that has a `limit_req` line of its own
none of the `http { }` ones, so neither the request limit nor the page limits
count anything there. The agent looks for such lines in what `nginx -T` prints
(a snippet included inside a `server { }` counts as being in it), and while one
is there it leaves `nginx` / `nginx-limits` out of what it reports and says in
its log which file and line, and the agent's `limit_req zone=...` lines to add
there next to the site's own (or take the site's own out).

### Any other web server

**The request limit from access logs (`logs`)**, for whatever serves the site:
Apache, LiteSpeed, OpenLiteSpeed, Caddy, Traefik, HAProxy (and nginx's own logs
while nginx's limit isn't in place). Needs a kernel backend (nftables or iptables). The agent
reads the access logs every few seconds and counts page requests per address
(an IPv6 /64 as one) as nginx's limit would: `req_burst` + 1 at once, then
`req_rate` a second (a log in whole seconds gets one second's worth more, so it
is never stricter than nginx). The exempt addresses don't count, as above, nor
do static files (`/x.css`, `/a.png`...) that were served: one answered `404` or
`5xx` does, so a flood of made-up `.css` paths is limited too. (nginx's own
limit can't tell, since it counts before the answer: see below.) A line too
long or odd to read whole still counts once its address and time are read. Over the limit the address is banned in the kernel for `ban`
seconds and reported once as `rate`; in monitor mode it is only reported (once
a ban period). Each log counts on its own, so a proxy and the server behind it
logging the same request don't double it.

- Formats, told apart line by line: combined and common (Apache, nginx,
  LiteSpeed, OpenLiteSpeed, Traefik's default), Apache's vhost_combined,
  Caddy's JSON, Traefik's JSON, HAProxy's `option httplog` (raw or through
  syslog). The address is read only from where the server writes it, never
  from a path, Referer, User-Agent or user name.
- Found by itself in `/var/log/apache2`, `/var/log/httpd`, `/var/log/nginx` (and
  the `access_log` lines `nginx -T` shows), `/usr/local/lsws/logs` and each
  LiteSpeed vhost's `logs/`, `/var/log/caddy`, `/var/log/traefik` and
  `/var/log/haproxy*.log`; rotated and compressed copies are skipped. Elsewhere,
  name them in `/etc/analytics-agent.json`: `"access_logs": ["/srv/logs/*.log"]`
  (`[]` turns the layer off). The agent logs it when it has none to read.
- **Caddy** logs to its own output unless a site says otherwise: add
  `log { output file /var/log/caddy/access.log }` to each site (JSON, the default).
  **Traefik**: `accessLog: { filePath: /var/log/traefik/access.log }` (either
  format). **HAProxy**: `option httplog` with the log written to a file
  (Debian's rsyslog writes `/var/log/haproxy.log`).
- The log must hold the visitor's address. Behind Cloudflare or a load balancer
  on a private address that means restoring it (Apache `mod_remoteip`, Caddy
  `trusted_proxies`, Traefik `forwardedHeaders.trustedIPs`, LiteSpeed "Use
  Client IP in Header"); until then every request carries the proxy's address,
  which is exempt, and nothing is limited. A proxy on a **public** address that
  isn't Cloudflare's goes in `allow`, or it is what gets banned.
- Trust only the proxy itself. Traefik with `forwardedHeaders.insecure: true`, or
  `trustedIPs` wider than the proxy's own addresses (`0.0.0.0/0`, a whole
  provider's range), logs whatever `X-Forwarded-For` a visitor sends: anyone
  can then name an exempt address (escaping the limit) or someone else's
  (getting them banned). The same goes for `trusted_proxies` in Caddy,
  `RemoteIPTrustedProxy` in Apache and LiteSpeed's header setting.
- It acts once the line is written, a few seconds after the burst, rather than
  answering 429 itself: the requests over the limit before then reached the site.

**The browser check** (`challenge`) in each server below: the same page, pass
(`__sg_passn`, today's and yesterday's) and rules as nginx's (`GET`/`HEAD`
asking for `text/html`, not a `skip` path, not exempt: `allow`, good bots,
`challenge.exempt`, the private ranges and the server's own public
addresses), answered `503` with
`Cache-Control: no-store`, `X-Robots-Tag: noindex` and a policy allowing only the
page's own script and style (by hash; `frame-ancestors 'none'`). The agent
writes only files of its own, tests the configuration before every reload
(where the server can), puts the old files back when the test fails, tries a
failed reload again, and doesn't try files the server refused again until they
change (a new day's pass included) or an hour has passed.

It reports the layer only once the server is shown to use it, both ways:
**every** site or virtual host includes the file (one left out is named in the
log, and the layer isn't reported until it's added), and the server, asked for
`/` over `127.0.0.1` (by each site's name, on the `ports`, `https` on 443),
answers with the check page and a policy its script runs under, and without it
once the request carries today's pass. The probe sends `X-Analytics-Probe: 1`,
which gets the check even from an exempt address; anyone else sending it only
gets the check themselves. A site whose `/` is in `skip` can't be asked, so
its layer isn't reported.

A site's own `Content-Security-Policy` can replace the page's (LiteSpeed,
HAProxy's `http-after-response`, Caddy's `header ... defer`): the page also
loads its script as `/__sg_check.js`, which the server answers itself
(Caddy, HAProxy, both LiteSpeeds), so a policy allowing `'self'` scripts still
runs it. One that allows neither `'self'` nor inline scripts blocks the check,
and the probe says so in the log (Caddy names the sites setting it deferred).

A visitor whose browser already held today's pass and still gets the page is
told the site can't be reached right now, not sent round again (it's a `503` of
the site's own, which LiteSpeed shows this page for). Where storage is blocked
the page counts its reloads in a one-minute `__sg_tries` cookie: three a
minute at most.

With the check off the files stay in place doing nothing. Its paths can be
moved with keys in the config (`apache_check_file`, `apache_check_log`,
`apache_ctl`, `apache_reload`, `caddy_config`, `caddy_check_file`,
`caddy_reload`, `caddy_bin`, `haproxy_config`, `haproxy_dir`, `haproxy_reload`,
`haproxy_bin`, `litespeed_dir`, `litespeed_check_file`, `litespeed_check_page`,
`litespeed_check_script`); `"web_checks": []` turns them all off.

- **Apache 2.4.19+** (`apache-check`): nothing to add to your sites. The agent
  writes one file Apache reads at server level, which reaches every virtual
  host (proxies included) and wins over a site's own `ErrorDocument`, headers
  and `.htaccess`: `/etc/apache2/conf-available/analytics-check.conf` (the agent
  runs `a2enconf` itself) on Debian and Ubuntu, `/etc/httpd/conf.d/analytics-check.conf`
  on RHEL, Rocky and Alma. It needs `mod_headers`, `mod_alias` and
  `mod_log_config`; Debian ships without `mod_headers`: `a2enmod headers`. Until
  then the agent says so and writes nothing (it looks again every few minutes,
  so enabling it needs no agent restart). If `apachectl -M` itself fails (a
  site's config using a module that isn't loaded), Apache is left as it is.
  `skip` is matched on the request line the visitor sent, whatever a rewrite
  of the site's has made of the path. Checks are logged to
  `/var/log/apache2/analytics-check.log` (`/var/log/httpd/` on RHEL) and reported.
- **LiteSpeed Enterprise** (`litespeed-check`): it reads Apache's configuration
  but ignores `<If>` and doesn't hand server-level rewrite rules down, so add,
  at the top of each `<VirtualHost>` (before your own rewrite rules):
  `Include /usr/local/lsws/conf/analytics-check-apache.conf`. Exempt addresses
  skip only the check's rules (`[S=1]`), so your own still run. LiteSpeed applies
  an `ErrorDocument` to the whole virtual host, so a `503` of the site's own
  shows the check page too (saying the site can't be reached), and a virtual
  host with an `ErrorDocument 503` of its own isn't counted (its page would win
  over the check's): remove it. Only virtual hosts in Apache's configuration
  are covered, not ones defined in LiteSpeed's own XML. The script is served
  from `/usr/local/lsws/analytics-check/check.js` (LiteSpeed won't serve
  anything from `conf/`).
- **OpenLiteSpeed** (`litespeed-check`): add `include /usr/local/lsws/conf/analytics-check.conf`
  to each virtual host's `vhconf.conf` (or, for a template's members, inside
  the template's `virtualHostConfig { }`), at the top level. The agent finds
  the virtual hosts from `httpd_config.conf`. OpenLiteSpeed reads only the first
  `rewrite { }` block of a virtual host, so the file's block turns rewriting
  on and loads `.htaccess` (`autoLoadHtaccess 1`) itself, the check off or on.
  A virtual host's own block may stay below the include if it holds only those
  settings (`enable`, `autoLoadHtaccess`, `logLevel`); one with rules of its own
  can't take the check: move them to `.htaccess`. One with an `errorPage 503`
  of its own isn't counted either. The agent names each of these in its log.
- Neither LiteSpeed has a configuration test: the agent restarts it
  (`lswsctrl restart`, graceful), asks whether it still runs (for 15 seconds at
  most), and puts the old files back and restarts again when it doesn't. Neither logs checks apart, so
  LiteSpeed's checks aren't reported (the request limit still counts them).
- **Caddy 2** (`caddy-check`): once at the top of the Caddyfile, outside any
  site, `import /etc/caddy/analytics-check.caddy`, then `import analytics_check`
  as the **first** line of each site block. Caddy sorts `handle` blocks: one of
  the site's own with a path matcher (`handle /app/*`) runs before the check's,
  so put `import analytics_check` first inside each of those too. `skip` is
  matched on the path the visitor asked for (`orig_uri`), whatever `try_files`
  or a `rewrite` made of it. Checked with `caddy validate`, reloaded with
  `caddy reload`; every site in `caddy adapt`'s output must use it. A site with a file `log` has its checks reported. Behind a
  proxy, Caddy 2.7+ needs `trusted_proxies` to see the visitor. A Caddy run
  from a JSON config or the admin API, without a Caddyfile, isn't covered.
- **HAProxy 2.2+** (`haproxy-check`): it can't include configuration, so once
  the agent has written `/etc/haproxy/analytics/` (it holds the lists, the page
  and its policy, kept up to date), paste `/etc/haproxy/analytics/block.cfg`
  into each `frontend` (or `listen`) in `mode http` that serves pages, before
  your own `http-request` rules. Checked with `haproxy -c`, reloaded with
  `systemctl reload haproxy`. The block captures `sg_check` into the log line
  (`{sg_check}`), so only the check's own `503`s are reported from HAProxy's
  log file, not the site's. HAProxy logs local time; the agent finds each log's
  offset itself. **Agents before this version wrote a different block:
  paste the new `block.cfg` over it** (until then the layer isn't reported).
- **Traefik**: the request limit (`logs`) only. Traefik has no middleware that
  answers a request with a page of its own (`errors` needs a service to serve
  it, `circuitBreaker` only returns a status), and putting an agent-run service
  or `forwardAuth` in front would take the site down whenever the agent stops.

**What it can't do** (the dashboard should say so too):

- Per-address limits stop one machine, or a few. A botnet of thousands of
  addresses, each under the limits, gets through; that takes a network in
  front of the server (Cloudflare and the like).
- Nothing on the server survives a flood that fills its uplink: the packets
  are dropped here, but only after they have used the line. Only a provider
  upstream can stop that.
- The browser check stops scripts that don't run JavaScript, not a real
  (headless) browser. A request that gets the check page isn't counted by
  nginx's request limit (nginx answers it first); the kernel limits still apply.
- Behind Cloudflare, nginx sees Cloudflare's addresses, which are exempt,
  unless the real visitor's address is restored (`set_real_ip_from` +
  `real_ip_header CF-Connecting-IP`); then the limits are per visitor.
- A `limit_req` of your own in a `server` or `location` replaces the agent's
  there (nginx doesn't add them up). In block mode `limit_req_status 429` and
  `limit_req_log_level error` apply to your own `limit_req` lines too, unless
  they set their own; in monitor mode the file sets neither (no `limit_req_dry_run`
  either, which would make your own limits log-only).
- A request for a static file isn't counted by nginx, so a flood of `/x.css`
  requests is left to the kernel limits (nginx counts before it knows the
  answer, so it can't count only the `404`s as `logs` does).
- Keep `net.ipv4.tcp_syncookies` on (the Linux default): the set-up checks
  report it when it's off.

## File monitoring

About once an hour, in the background, the agent compares the site's files
(`"files_roots"` in `/etc/analytics-agent.json`; the installer sets the web
folder it finds, or `ANALYTICS_WEBROOT`) with the version you accepted:
added, changed and deleted code and pages, plus signs of a hack inside them
(backdoors, PHP in an uploads folder, "hacked by" pages). They show in
Security → Page integrity and are alerted. The protocol is `sdk/protocols/files.md`.

- The first check is the accepted version, except files that already look hacked: those are reported straight away.
- **After every deploy** run `analytics-agent accept` (from your pipeline over SSH, or call
  `POST /events/files/accept` with the site secret), or accept the changes on the dashboard.
- Only paths, hashes and sizes are sent, never the files themselves.
- The record is kept in `/var/lib/analytics-agent` (root only), where the site can't change it.
- `ANALYTICS_BACKEND=none` (or neither nftables nor nginx installed): file monitoring only, no firewall.
  On a server with neither, install `ipset` and use `ANALYTICS_BACKEND=iptables` instead.
- **Several sites on one server**: install once (for the main site), then for each other site
  `sudo analytics-agent add-site SITE_ID /var/www/other-site` (asks for that site's secret) and
  `sudo systemctl restart analytics-agent`. Each site's files are reported to its own dashboard, one
  site's check at a time; the firewall follows the main site. `analytics-agent remove-site SITE_ID` stops it.
- **After a deploy from CI**: `curl -X POST COLLECTOR/events/deploy -H "Authorization: Bearer $DEPLOY_KEY" -H "Content-Type: application/json" -d '{"site_id":"SITE_ID"}'`
  records a deploy marker on the charts, even with nothing but the site ID. Give a CI pipeline the
  **deploy key** (Site settings → Integrations → Deploys): it can only add a marker. The same call
  with the site secret also accepts the files on every server and the dashboard's page checks
  (`sdk/protocols/deploys.md`).

## Set-up checks

Once a day, also in the background, the agent reports **how the server is set
up** so the dashboard's Security check can say what to change
(Security → Security check). It only reads: it never changes a setting, a
permission or a file, and it sends no file's contents. The protocol is
`sdk/protocols/posture.md`.

- **Settings**: sshd (root login, passwords), automatic security updates, a
  restart waiting after an update, ports listening on every address, the Docker
  socket, SYN cookies switched off (`net.ipv4.tcp_syncookies`), and code under
  the web folder that any account on the machine can write.
- **Where a hack comes back from**: the scheduled job files (`/etc/crontab`,
  `/etc/cron.d`, the users' crontabs) by path, hash and time — never their
  contents — and the SSH keys that can log in, by **fingerprint**. A new key or
  a changed job file is alerted within minutes, without waiting for the weekly
  check.
- **Files in the web folder that shouldn't be public**: a database dump, a
  `.env`, a backup copy, a private key, a `.git` folder. The agent reports the
  path and size; the dashboard then asks your site for each one over HTTP and
  tells you whether it really can be downloaded.
- `analytics-agent posture` lists what it would report (and reports it).
- The operating system's name and version go with it, so an unsupported release
  is flagged.
- It follows the software inventory switch (Security → Server package): with that
  off, nothing is reported.

## How the machine is doing

Every minute, on a thread of its own, the agent reads how the server is
holding up and reports it every five minutes: **CPU, load average, memory,
swap and disk space per mount**, plus how long since the last boot. It shows
in Health → Server speed beside the request timings, and the disk, memory and
load alerts hang off it. The protocol is `sdk/protocols/resources.md`.

This is what you would otherwise install node_exporter, Prometheus and Grafana
for. The request timings say how the requests went; this says whether the box
can still serve them.

- **Nothing is guessed.** A reading this machine won't give is left out, and
  the dashboard shows "—" rather than a zero that reads as healthy.
- Memory used is total minus *available*, not minus free: page cache is not
  pressure, and counting it would make every healthy Linux box look full.
- Only real disks are listed — no tmpfs, no snaps, no network mounts, nothing
  under a gigabyte — and a disk mounted twice is one disk. The figures are the
  ones `df` prints, so you can check them against it.
- It never reports its own memory use: the agent isn't your application, and it
  has no way to know which process is. The language packages, which run inside
  the application, report that.
- **How close it is to a wall** (`resources.md`, "Limits"), from 0.7.5:
  processes killed for memory anywhere on the machine (`/proc/vmstat`), the
  share of the last minute tasks waited for CPU, memory and disk
  (`/proc/pressure`), connections the kernel refused because an app didn't
  accept them in time (`ListenOverflows`) and how full the connection-tracking
  table is. A kernel without one of these files sends nothing for it. The
  container caps and the process's own figures come from the language
  packages, which run inside the app.
- It samples on its own thread, so a sample never waits behind the hourly file
  check.
- `analytics-agent resources` takes a sample now, prints it and reports it.
- It follows its own switch (Security → Server package → Server resources), not
  the software-inventory one: a site with inventory off still wants to know its
  disk is filling.

## What fills the disks

The disk alert says a disk is 87% full; this says why. Every three hours (the
first about five minutes after the agent starts), the agent measures a fixed
list of places and reports it: **logs, the journal, Docker's images, volumes,
container logs and build cache, Podman and containerd, package caches,
developer caches in each home (`~/.npm`, `~/.cache`, Composer, Yarn), `/tmp`,
backups, crash dumps, snaps, database folders and `/var/www`, `/srv`**, each
on the disk it lives on. With it come what can be cleared (rotated logs,
journal archives, what Docker calls reclaimable, old temp files and backups,
disabled snap revisions, MySQL binary logs, a big `pg_wal`), the 20 biggest
files, and deleted files a process still holds open, which `df` counts and no
folder listing finds. It shows in Health → Server speed, and the disk alert
names the biggest places. The protocol is `sdk/protocols/disk-usage.md`.

- **It only looks.** Folder listings and sizes (`lstat`), never what's in a
  file, except three settings files read for what they say about cleanup:
  logrotate's rules, journald's `SystemMaxUse` and Docker's `daemon.json`. Plus
  `docker system df` and the `/proc/<pid>/fd` links. **It deletes, truncates
  and changes nothing**: the dashboard shows the commands, and you run them.
- **Nothing from the dashboard decides what's scanned.** The places are fixed,
  plus `"disk_scan_paths"` here. "Scan now" in the dashboard only runs the same
  scan sooner (once per click, at most every 10 minutes).
- **Bounded.** The scan is a child process at `nice 19`, `ionice -c3` where
  there is ionice, with a 768 MB memory cap, killed after `"disk_scan_timeout"`.
  It never follows a symlink or crosses into another filesystem, counts a
  hard-linked file once, and stops after about a million entries; a scan that
  stopped early says so, and every figure in it is "at least". A failed scan is
  logged and the next one is at the usual time.
- Sizes are space used on disk, not apparent size, so a sparse file counts what
  it takes. A file counts toward the deepest place that holds it: the journal
  isn't counted again under `/var/log`.
- **File names go to the main site only** (the config's own `site_id`): the
  biggest files, the deleted ones and a big log's path. Every other site on the
  server gets the totals. `"disk_scan_files": false` sends no names at all.
- It follows the Server resources switch: with resources off, nothing is scanned.
- `analytics-agent disk` scans now, prints it and reports it.

| Key | Default | |
|---|---|---|
| `disk_scan_every` | `10800` | seconds between scans; 600 at least |
| `disk_scan_timeout` | `300` | seconds before a scan is stopped |
| `disk_scan_paths` | `[]` | more folders to measure, as full paths (`"custom"`) |
| `disk_scan_files` | `true` | `false`: no file names leave the server |

## What's deployed

Every five minutes, on a thread of its own, the agent reads which commit each
**git work tree** is on — the site's folders (`"files_roots"`) and up to two
levels below them, the folders the running services were started in, plus any
folder listed in `"apps"` (top level, or per entry of `"sites"`) — and, for the
main site, which image each running **Docker container** came from. A changed HEAD or image shows as a **deploy marker** on
the charts, so a jump in errors or load time can be read against what went
live. Once an hour per folder, a `git ls-remote` says whether the server is
**behind its branch**, and by how many commits. The protocol is
`sdk/protocols/deploys.md` (`POST /events/apps`).

- **It only reads.** `rev-parse`, `log -1`, `ls-remote` and comparisons of
  commits already on the server: it never fetches or pulls, so nothing is
  written into your repository.
- git runs **as the folder's owner**, with their home folder, so it uses their
  SSH keys and credentials. It **never prompts** (no password, no host-key
  question) and every call has a time limit; a check that can't finish says
  "unknown" instead of holding the agent up.
- Sent: folder paths, commit hashes, branch names, commit subjects and the
  repository as `owner/name`. A remote's URL is never sent, since it can carry
  a token.
- **Running services are found on their own.** Whatever PM2, systemd,
  supervisor or `nohup` runs, the agent reads each process's working folder
  and reports it when it, or a folder up to two above it, is a git work tree:
  a Node app in `/home/deploy/app` needs no config. An app copied there
  without git (rsync, scp, a pipeline) is reported too, as kind `folder`,
  when an app runtime (node, python, php, ruby, java, dotnet, bun, deno…)
  runs in it and it holds an app's files (`package.json`, `composer.json`, a
  `.jar`…); its version is a fingerprint of its top-level files, so a deploy
  shows and a restart doesn't. Processes on a terminal (a shell, what someone
  runs by hand) and inside containers are left out. Each app goes to the site
  whose folders it's in, the main site taking the rest. `"running_apps":
  false` turns this off.
- Containers are reported only when this server has one site, or with
  `"docker_apps": true` (`false` turns them off).
- With each container goes the registry digest its image was pulled as
  (`docker image inspect`), so Health → Updates can tell a newer build of
  the same tag, such as `latest`.
- Reported when something changes and at least hourly. `analytics-agent apps`
  lists what it sees now and reports it.

## Whether its services run

Every minute, on a thread of its own, the agent checks that the services on
the machine are running, and each gets a light in **Health → All systems**:
green while it runs, red when it stops. The protocol is
`sdk/protocols/services.md` (`POST /events/services`).

It finds the common ones by itself: the **systemd units** of databases, caches,
queues, web servers, PHP-FPM, Docker and pm2 (Redis, PostgreSQL, MySQL/MariaDB,
MongoDB, RabbitMQ, ClickHouse, nginx, Apache, Caddy...) and every **Docker
container**. A found one is shown while it runs or is set to start at boot,
and stays red for a week after it stops, even across a restart of the agent.
One removed altogether (uninstalled, or the container taken down) was removed
on purpose and goes at once. A container that reports itself unhealthy is red.

**Podman** and **Kubernetes** containers are found too (0.7.5). Podman's, root's
and each user's rootless ones (named `<user>/<name>`), from Podman's own
`containers.json`, without running `podman`: one runs while its cgroup is
there, a stopped one is red ("Not running"), and its health check isn't read.
A user's are looked for once one of their containers has been seen running,
and only in files that user owns. Buildah's working containers and CRI-O's
(which share that storage) aren't Podman's and are left out.
Kubernetes' from `crictl ps -a -o json` on a node with a `kubepods` cgroup,
named `<namespace>/<pod>/<container>`, the latest attempt of each: one waiting
to restart is red, while a stopped one in a pod that is over (a finished Job)
is left out (`crictl pods`). A container Docker already lists is Docker's.
Each running unit and container also carries the memory and CPU it uses
(`services.md`, "Usage"), from its own cgroup wherever the runtime put it. At
most 50 are reported: your list first, then units, Docker, Podman and
Kubernetes containers, in that order.

Anything else, list it in `/etc/analytics-agent.json`:

```json
"services": [
  {"name": "redis",  "tcp": "127.0.0.1:6379"},
  {"name": "api",    "http": "http://127.0.0.1:3000/health", "expect_ok": true},
  {"name": "worker", "unit": "worker.service"},
  {"name": "queue",  "process": "celery"}
]
```

- `tcp`: the port answers (a bare port means `127.0.0.1`).
- `http`: one `GET` answers 2xx or 3xx. A redirect isn't followed. With
  `"expect_ok": true` the answer must also be JSON with `"ok": true`, as a
  `/health` that checks its own database says.
- `unit`: the systemd unit is active (`.service` is added when left out).
- `process`: a process of that name runs (its name or its program's file name).
- `"services_detect": false` turns the finding off, leaving only your list.

The list lives in this file, never in the dashboard, on purpose: an address
set from there would let anyone with dashboard access make your server knock
on your private network. Every check only reads, nothing runs through a
shell, and an address is sent without its user, password or query string.
`analytics-agent services` checks them now, prints them and reports them.

## Its databases and queues

Every minute, on a thread of its own, the agent reads each database you list
as the database sees itself, for Health → Server speed → Database: the
statements that cost it the most time, with the rows each read for every row
it sent back (thousands to one is a missing index), the tables read end to
end, connections against the limit, lock waits and the longest query running.
The server packages time the queries your code runs; this is the database's
side, including what other programs and cron jobs run on it. Protocol in
`sdk/protocols/databases.md` (`POST /events/server-databases`).

```json
"databases": [
  {"postgresql": "local"},
  {"mysql": "local"},
  {"clickhouse": "http://agent:secret@127.0.0.1:8123"},
  {"mongodb": "mongodb://agent:secret@127.0.0.1:27017"},
  {"redis": "local"}
],
"queues": [{"rabbitmq": "http://user:pass@127.0.0.1:15672"}]
```

- **PostgreSQL** `"local"` runs `psql` as the `postgres` account over its
  socket, as its own tools are run; a connection string works too
  (`postgresql://user:pass@host:5432/db`). Statements need the
  `pg_stat_statements` extension (`shared_preload_libraries` and
  `CREATE EXTENSION pg_stat_statements` in the `postgres` database); without
  it the page says so and shows health and tables only.
- **MySQL and MariaDB** `"local"` runs `mysql` as root over its socket (root's
  `~/.my.cnf` applies); a connection string's password goes in a file only
  root can read for each run, never on the command line. Statements and
  tables need `performance_schema` on (MySQL's default; MariaDB:
  `performance_schema=ON`). MySQL counts rows read with no index per table,
  not how many scans, so its scans show as "—".
- **ClickHouse** 23.3 or later: its HTTP address with a user that may read
  `system.*` (`GRANT SELECT ON system.* TO agent`; a read-only user is fine).
  It reads `system.query_log` from where the last reading stopped.
- **MongoDB**: through `mongosh`, the address in its environment. Statements
  come from the profiler of each database where it's on
  (`db.setProfilingLevel(1, { slowms: 100 })`); the agent never turns it on.
- **Redis** (0.8.0; Valkey and KeyDB too): `"local"` is its socket
  (`/run/redis/redis-server.sock` or `/var/run/redis/redis.sock`), else
  `127.0.0.1:6379`; or `redis://[user:pass@]host:port`, `rediss://` for TLS
  (`?ssl_cert_reqs=none` for a certificate of its own), `unix:///path`. The
  agent speaks to it itself, no client needed, and sends only `AUTH`, `INFO`
  and `SLOWLOG GET`: each command's calls, time and failures, memory against
  `maxmemory`, keys evicted, the hit rate of lookups and the slowest command
  in the slow log. Of a slow log entry only its duration is read, never its
  arguments or client. A user limited by ACL needs `+info +slowlog`; without
  `slowlog` the slowest command is "—".
- **RabbitMQ**: the management API's address. Each queue's messages ready and
  unacknowledged, the oldest one's age when publishers stamp a timestamp, and
  published and acknowledged since the last reading, to Server speed → Jobs
  (`POST /events/server-queues`). BullMQ and Bull queues are read by the Node
  package instead (`watchQueue`).

It only reads statistics the database already keeps: nothing is changed,
installed or turned on. Every statement loses its values before it's sent,
by the same rule as the packages' queries, and again at the collector. A
figure a database doesn't keep is sent as nothing, so the page says "not
counted" rather than 0. The first reading sends health only: counters need a
reading before them. `analytics-agent databases` reads twice, ten seconds
apart, prints what it found and reports it. With Server speed off in the
dashboard it reads every ten minutes, only to hear when it's back on.

## Backups

Every night (or weekly, or when you ask), this server's databases and folders into your own storage, with
[restic](https://restic.net): encrypted here, with a password made here that
only you have. No copy ever reaches us; Health → Backups shows what ran, a
missed or failed backup is an alert, and a part or a whole run can be downloaded or put back.

```json
"backups": {
  "repository": "s3:https://nbg1.your-objectstorage.com/my-bucket/web-1",
  "env": { "AWS_ACCESS_KEY_ID": "…", "AWS_SECRET_ACCESS_KEY": "…" }
}
```

then `sudo analytics-agent backup-setup`: it installs restic (a pinned
version, checked against its SHA-256), makes the password and shows it once,
and makes the repository. **Keep the password in your password manager**:
without it no backup can be read, and we can't recover it.

Left out, `databases` are the ones under `"databases"` it can dump (PostgreSQL,
MySQL/MariaDB, MongoDB, SQLite; on the server or `docker:NAME`), and `folders`
the watched site folders and the apps it finds. Runs at 03:00, keeps 14 daily,
8 weekly and 12 monthly. `"schedule": "weekly"` (with `"weekday"`) or `"off"`
changes when; what's set on the dashboard wins, and "Back up now" there runs
one at once.

No storage of your own? `"repository": "/var/backups/sitegoose"` keeps them
on this server (lost with it, as the page warns), and a part or a whole run
can be downloaded from us instead: kept a day, encrypted here for the one
browser that asked, so we can't open it (Basic and Pro, or a $3 add-on on
Free). It is made in `"temp_dir"` (default the state folder), which needs
room for it. A restore from the dashboard only with
`"allow_restore": true`; it backs up what it replaces first and undoes itself
if anything fails. Every key, and how a restore goes:
[`sdk/protocols/backups.md`](../protocols/backups.md).

## Good to know

- **The `rate` limit isn't enforced as such**: the kernel sees packets and
  connections, not requests. Requests are limited with `flood` instead, by
  nginx once `analytics-flood.conf` is included, or from the access logs of any
  web server (`logs`; see Flood protection); until one runs the dashboard says
  the rate limit isn't working.
- **Rules stay in place when the agent stops** (or can't reach us), so a
  restart doesn't open the gates. `analytics-agent clear` removes them.
- Every address is checked before it's written anywhere: rules come from the
  network, and only valid addresses and ranges reach nftables, iptables or nginx.
- Python 3.6 is enough (CentOS 7, Ubuntu 18.04).

## Commands

| | |
|---|---|
| `analytics-agent status` | what's in place, the layers that run and the bans now |
| `analytics-agent once` | fetch and apply now |
| `analytics-agent clear` | remove everything it put in place |
| `analytics-agent files [SITE_ID]` | check the files now and list what changed |
| `analytics-agent posture [SITE_ID]` | check how the server is set up now, list it and report it |
| `analytics-agent resources` | sample CPU, load, memory and disks now, print it and report it |
| `analytics-agent disk` | measure what fills the disks now, print it and report it |
| `analytics-agent apps [SITE_ID]` | list the apps deployed here (git folders, containers) and report them |
| `analytics-agent services` | check the services now (listed and found), print them and report them |
| `analytics-agent databases` | read the listed databases and queues now, print it and report it |
| `analytics-agent accept [SITE_ID]` | the files as they are now are the accepted version (after a deploy) |
| `analytics-agent add-site SITE_ID FOLDER` | watch another site's files on this server |
| `analytics-agent remove-site SITE_ID` | stop watching it |
| `analytics-agent backup-setup` | install restic, make the backups' password and repository |
| `analytics-agent backup` / `backups` | back up now / list the backups |
| `analytics-agent restore RUN [PART...] [--into FOLDER] [--yes]` | put a backup back, or copy it out |
| `analytics-agent export RUN PART FILE` | write one part of a backup to a file |
| `journalctl -u analytics-agent` | its log |

Uninstall: `systemctl disable --now analytics-agent && analytics-agent clear`,
then delete `/usr/local/bin/analytics-agent`, `/etc/analytics-agent.json`,
`/etc/systemd/system/analytics-agent.service` and `/var/lib/analytics-agent`.
If you included the nginx files, take the `include` lines out, reload nginx, then
delete `/etc/nginx/analytics-flood.conf` and `/etc/nginx/analytics-check.conf`.
Likewise for the other servers (`clear` leaves their files in place, turned off):
Apache, `a2disconf analytics-check` on Debian, then delete the file and reload;
LiteSpeed and Caddy, take the `Include`/`include`/`import` lines out first;
HAProxy, take the pasted block out, reload, then delete `/etc/haproxy/analytics/`.

After editing these files, run `./build.sh` to copy them where the collector
serves them (`/downloads/agent/`).
