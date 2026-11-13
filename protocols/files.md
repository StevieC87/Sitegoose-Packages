# File integrity protocol (v1)

What every file-watching client implements: it keeps a record of the site's
files, compares them with the version the owner accepted, and reports what's
different, so a hacked or defaced site shows up on the Security page
(Page integrity → Server files) and in the alerts. Clients: the server agent
(`sdk/vps-agent`) and the PHP package (`sdk/platform-php`, `Files.php`), which
the WordPress plugin runs from WP-Cron. The collector side is
`expresscollect/Analytics/files.js`.

## Authentication

Like the firewall: the site's ID and its secret, `Authorization: Bearer <secret>`,
and a `User-Agent` naming the client and its version.

## Scanning

- **Roots**: the site's folders (the web root; for WordPress, `ABSPATH`).
- **Files**: code, templates and config, by extension: `php phtml phar php3-8 inc js mjs cjs jsx ts tsx
  vue svelte html htm shtml ejs erb twig hbs handlebars mustache jinja j2 njk liquid cshtml vbhtml py rb pl
  cgi sh asp aspx jsp svg json yml yaml conf config ini`, plus files named `.htaccess`, `.user.ini` and `.env*`. At most 5 MB each,
  at most 50,000 files (report `truncated: true` past that).
- **Skipped folders**: `.git`, `node_modules`, and caches (`wp-content/cache`). Never skip
  `wp-content/uploads`: code in an uploads folder is a classic backdoor.
- **Hash**: SHA-256 of the contents. A file whose size and modification time
  haven't changed may keep its last hash, but every file is hashed again at
  least once a day (attackers reset modification times).
- **Every hour** by default; the collector's answer can change it (`every`).

## The baseline

The client keeps two records: the **baseline** (what the owner accepted) and
the last scan. The first scan becomes the baseline, except files with
**signals** (below) or that differ from an official copy (WordPress core
checksums from api.wordpress.org): those stay out of it, so they are reported
from the start and an already-hacked site is caught on day one.

A change is a path that is `added` (not in the baseline), `modified` (another
hash) or `deleted` (in the baseline, gone now). Each scan reports **all** of
them against the baseline, not only what's new since the last scan: a file put
back as it was stops being reported.

## Signals

Checked in each added or modified file (first 1 MB):

| signal | pattern |
|---|---|
| `eval_decode` | PHP `eval`/`assert` of `base64_decode`, `gzinflate`, `gzuncompress`, `gzdecode`, `str_rot13`; JS `eval`/`new Function` of `Buffer.from`/`atob`; Python `exec` of `base64.b64decode`, `zlib.decompress`, `marshal.loads`, `codecs.decode` |
| `exec_input` | PHP `system`, `shell_exec`, `passthru`, `exec`, `popen`, `proc_open` or `eval` of `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`; Node `exec`/`execSync`/`spawn`/`eval` of `req.query`/`body`/`params`; Python `os.system`, `os.popen`, `subprocess.*`, `eval`, `exec` of `request.args`/`form`/`values`/`GET`/`POST`/`json` |
| `reverse_shell` | `bash -i >& /dev/tcp/`, `/dev/tcp/<ip>/<port>`, `nc -e /bin/sh`, a Python socket with subprocess, `pty.spawn("/bin/sh")` |
| `webshell` | `FilesMan`, `c99shell`, `r57shell`, `WSO `+version, `b374k` |
| `obfuscated_js` | `String.fromCharCode(` with 50+ numbers, or `document.write(unescape(` |
| `defaced` | `hacked by`, `defaced by` |
| `code_in_uploads` | a PHP file (`php phtml phar php3-8`) under an `uploads` folder (by path) |

## POST /events/files/scan

```json
{
  "site_id": "<id>",
  "host": "web-1",
  "scan": { "at": "2026-10-17T12:00:00.000Z", "roots": ["/var/www/html"], "files": 3120,
            "baseline": false, "truncated": false },
  "changes": [
    { "path": "/var/www/html/index.php", "change": "modified", "sha256": "…", "size": 1520,
      "mtime": "2026-10-17T11:58:02.000Z", "signals": ["defaced"] },
    { "path": "/var/www/html/wp-includes/version.php", "change": "modified", "sha256": "…",
      "size": 960, "mtime": "…", "signals": [], "official": false },
    { "path": "/var/www/html/old.php", "change": "deleted", "sha256": null }
  ]
}
```

- `host`: the server's name, so several servers of one site are kept apart.
- `scan.baseline`: true when this scan made a new baseline (first run, or the
  client lost its record). The collector then keeps the changes it already had
  for this host, so losing the record can't hide them.
- `scan.accepted`: true when the owner accepted the files on the server itself
  (after a deploy); the collector drops what it had and keeps this report only.
- `changes`: at most 1,000; signals first, then the rest.
- `official: false`: differs from the official copy (WordPress core).

The answer (`200`):

```json
{ "v": 1, "enabled": true, "every": 3600,
  "accept": [{ "path": "/var/www/html/index.php", "sha256": "…" }], "accept_all": false }
```

- `enabled: false`: the owner turned the module off (Security → Server package);
  scan again later (every 6 hours) to see if it's back on.
- `accept`: changes the owner accepted on the dashboard. For each, when the
  file's current hash is `sha256` (or it's gone and `sha256` is null), the
  baseline takes the file as it is now.
- `accept_all: true`: the baseline becomes the last scan (a deploy, see below).

## POST /events/files/accept (also POST /events/deploy)

`{ "site_id": "<id>" }` from a deploy pipeline: every change on every server
of the site is accepted, as the next scan finds them, and so are the pages
the dashboard checks (watched and payment pages): their next load, within a
few minutes, becomes the accepted version. Clients also have a local command
for the files (`analytics-agent accept`, `wp site-analytics accept-files`).

## Must

- **Never slow the site**: scan in the background (the agent's loop, WP-Cron),
  never in a visitor's request.
- **Keep the baseline where the site can't change it** when possible (the agent:
  `/var/lib/analytics-agent`, root only).
- Never send file contents: paths, hashes, sizes and times only.
