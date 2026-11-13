# Backups protocol (v1)

Backups of a customer's own servers, made by the server agent (Linux:
`sdk/vps-agent/analytics-agent`; Windows: `sdk/windows-agent/analytics-agent.ps1`).
Every night (or weekly, or only when asked) each database is dumped with its
own tool and each folder read, into [restic](https://restic.net), which
encrypts it on the server and keeps it in the owner's own storage: an S3
bucket (Hetzner, AWS, Backblaze, Wasabi, R2, MinIO), SFTP, a REST server, a
disk or a folder. The password is made on the server and shown once.
**Nobody but the owner holds it, and no backup ever reaches us.**

What reaches the collector is the bookkeeping: what was backed up, when, how
big, ok or not, and the dashboard's requests (back up now, a download, a
restore) and how they went. The one file that can reach our storage is a
download the owner asked to get from us, encrypted on the server for the one
browser that asked (see "A download kept for a day"). The design and the
dashboard's side: `backend/docs/SERVER_BACKUPS.md`.

WordPress is left out on purpose: its hosts and its backup plugins already
cover it, and the agent backs up the server underneath it like any other.

## Authentication

`Authorization: Bearer <site secret>` and the site's ID, as for every report a
server sends. Rate limits: `BACKUPS_IP_RATE_LIMIT` (120 a minute per address)
and `BACKUPS_SITE_RATE_LIMIT` (300 a minute per site). At most as many servers
per site as the other server reports allow (`429` past it).

## The config

A `"backups"` section in the agent's config. Without a `"repository"` backups
are off.

```json
"backups": {
  "repository": "s3:https://nbg1.your-objectstorage.com/my-bucket/web-1",
  "env": { "AWS_ACCESS_KEY_ID": "…", "AWS_SECRET_ACCESS_KEY": "…" },
  "databases": [
    { "postgresql": "local" },
    { "mysql": "docker:shop-db", "only": ["shop"] },
    { "sqlserver": "local" },
    { "mongodb": "mongodb://backup:…@127.0.0.1:27017/admin" },
    { "sqlite": "/srv/app/data.db" }
  ],
  "folders": ["/var/www/shop", "/etc/nginx"],
  "schedule": "nightly",
  "at": "03:00",
  "keep": { "daily": 14, "weekly": 8, "monthly": 12 },
  "allow_restore": false
}
```

| Key | Means |
| --- | --- |
| `repository` | restic's own repository string (`s3:`, `sftp:`, `rest:`, `b2:`, `azure:`, `gs:`, or a folder). A folder on the server itself is lost with it: the report says so (`local`) and the page warns. |
| `password_file` | Linux `/etc/analytics-backup-password`; Windows `backup-password.txt` beside the config. `backup-setup` makes it. |
| `env` | The storage's keys: only `AWS_*`, `B2_*`, `AZURE_*`, `GOOGLE_*`, `RESTIC_REST_*` are passed on. |
| `region` | The S3 region for download links, when the host name doesn't say it. |
| `databases` | Linux: the ones under `"databases"` it can dump, when left out. Windows: none unless listed. |
| `folders` | Linux: the watched site folders and found apps, when left out. Windows: none unless listed (`C:\…` paths). |
| `exclude` | restic patterns. Default `node_modules`, `.cache`, `__pycache__`, `*.tmp`, `*.swp` (Windows: `node_modules`, `*.tmp`, `App_Data\Logs`). |
| `schedule` | `nightly` (the default), `weekly` (on `weekday`) or `off` (only when asked, from the dashboard or `backup`). A schedule set on the dashboard wins over this one. |
| `weekday` | For `weekly`: `mon` … `sun` (or the day's name). Default `sun`. |
| `at` | When a scheduled run starts, the server's own time. |
| `keep` | How many daily, weekly and monthly runs `restic forget` keeps. Pruned once a week (6½ days apart, whatever the schedule), with `check --read-data-subset=5%`. |
| `temp_dir` | Where a download is made before it's uploaded (Linux: `state_dir`; Windows: `backup-temp` beside the state). A download is refused, before any work, when the disk there hasn't room for the parts plus 512 MB. |
| `allow_restore` | `true` lets the dashboard ask for a restore. Off by default; the command line always can. |

Databases, each by its own tool, and never a password on a command line
(MySQL's goes in an option file, PostgreSQL's and SQL Server's in the
environment, MongoDB's connection string in a `--config` file):

| Key | Linux | Windows |
| --- | --- | --- |
| `postgresql` | `pg_dump -Fc` per database, plus `pg_dumpall --globals-only` (the accounts and their rights) for a local or Docker one; `"local"` as the `postgres` user, a URL, or `docker:NAME` | a URL only; `pg_dump.exe` |
| `mysql` / `mariadb` | `mysqldump --single-transaction` per database; `"local"` (root over the socket), a URL, `docker:NAME` | a URL only; `mysqldump.exe` |
| `mongodb` | `mongodump --archive --gzip`; `"local"`, a URL, `docker:NAME` | a URL only; `mongodump.exe` |
| `sqlite` | the backup API, a full path | — |
| `sqlserver` | — | `BACKUP DATABASE … WITH COPY_ONLY` (the owner's own backup chain is left alone); `"local"`, an instance (`.\SQLEXPRESS`), or `sqlserver://user:pass@localhost`. This server's SQL Server only: it writes the file on its own disk. |

`only` limits it to those database names. Docker containers use the
official images' variables (`POSTGRES_USER`, `MYSQL_ROOT_PASSWORD`,
`MONGO_INITDB_ROOT_*`), read inside the container.

On Windows the agent runs as SYSTEM, which SQL Server doesn't make a
sysadmin. Either give it the rights once:

```powershell
sqlcmd -S . -E -Q "ALTER SERVER ROLE sysadmin ADD MEMBER [NT AUTHORITY\SYSTEM]"
```

or give it a SQL login in the URL (`db_backupoperator` on each database is
enough for backups; a restore needs `dbcreator`).

## A run

One run is several restic snapshots, one per database dump and one per
folder, sharing the tags `sitegoose`, `run:YYYYMMDDTHHMMSSZ` (UTC, when it
started), `trigger:nightly|manual|before-restore` and `kind:database|folder`.
A database dump is named `<kind>/<where>/<database><ending>`, for example
`mysql/local/shop.sql`, `postgresql/db.internal/app.pgdump`,
`sqlserver/local/Shop.bak`, `mongodb/127.0.0.1/all.archive.gz`. A folder is
its own path. These names are what the report, a download and a restore use.

A part that fails doesn't stop the others: the run is `ok` (every part),
`partial` (some) or `failed` (none, or it couldn't start). A folder with files
it couldn't read (restic exit 3) counts as backed up, with the reason.

## POST /events/backups

Hourly, after every run and after every request. The whole picture, replacing
the last one.

```json
{
  "v": 1, "site_id": "…", "host": "web-1", "client": "vps-agent/0.8.0", "restic": "0.19.1",
  "setup": null, "setup_detail": "",
  "settings": {
    "repository": "s3:https://nbg1.your-objectstorage.com/my-bucket/web-1", "at": "03:00", "timezone": "+0100",
    "schedule": "nightly", "weekday": "sun", "schedule_from": "config", "local": false,
    "keep": { "daily": 14, "weekly": 8, "monthly": 12 }, "allow_restore": false, "can_download": true,
    "folders": ["/var/www/shop"], "databases": ["mysql local"], "skipped": ["redis"]
  },
  "last": {
    "run": "20261107T020000Z", "trigger": "nightly", "state": "partial",
    "started_at": "2026-11-07T02:00:00.000Z", "finished_at": "2026-11-07T02:04:10.000Z", "error": "", "forget": "",
    "items": [
      { "kind": "database", "name": "mysql/local/shop.sql", "ok": true, "seconds": 41, "bytes": 81234567, "added": 1203344, "error": "" },
      { "kind": "folder", "name": "/var/www/shop", "ok": false, "missing": true, "error": "the folder doesn't exist" }
    ]
  },
  "check": { "at": "2026-11-01T02:30:00.000Z", "ok": true, "error": "" },
  "runs": [
    { "run": "20261107T020000Z", "at": "2026-11-07T02:00:02Z", "trigger": "nightly",
      "items": [{ "kind": "database", "name": "mysql/local/shop.sql", "snapshot": "4f2a9c1e", "bytes": 81234567 }] }
  ],
  "repo_bytes": 5123456789
}
```

- `repository` never carries a password (`user:pass@` is taken out).
- `setup`: why backups can't run at all, else `null`: `restic_missing`,
  `restic_old` (before 0.17), `no_password`, `wrong_password`, `repository`
  (the storage can't be reached or refused). `setup_detail` says it in words.
- `can_download`: the repository is an S3 bucket, so a link to it can be made.
- `schedule`, `weekday`, `at`: what the server runs to, and `schedule_from`
  whether that is the dashboard's (`dashboard`) or its config's (`config`).
- `local`: the repository is a folder (`/…`, `C:\…`, `local:`).
- `skipped` (Linux): databases under `"databases"` it can't dump (Redis,
  ClickHouse), by kind.
- `runs`: what restic holds now, newest first, at most 60.
- `last_ok_at` is kept by the collector: the last time a whole run finished.

`202 { "v": 1, "stored": true }`.

## GET /events/backups/requests?site_id=…&host=…

Once a minute. What the dashboard asked this server to do, each handed over
once (marked `sent` as it goes, so a second poll never starts the same restore
twice). At most five; requests waiting more than six hours are left.

```json
{ "v": 1, "schedule": { "schedule": "weekly", "weekday": "mon", "at": "04:00" }, "requests": [
  { "id": "…", "kind": "download", "run": "20261107T020000Z", "item": "/var/www/shop", "items": [], "download": false, "hosted": null },
  { "id": "…", "kind": "backup", "run": null, "item": null, "items": [], "download": true,
    "hosted": { "public_key": { "kty": "RSA", "n": "…", "e": "AQAB" }, "max_bytes": 5368709120 } },
  { "id": "…", "kind": "restore", "run": "20261107T020000Z", "item": null, "items": ["mysql/local/shop.sql"], "download": false, "hosted": null }
] }
```

- `schedule`: the one set on the dashboard, kept by the agent and winning
  over its config; `null` hands it back to the config's. Left out when the
  collector doesn't know the server yet. `at` or `weekday` `null`: the config's.
- `backup`: back up now (`trigger:manual`); with `download`, then download the
  whole of that run.
- `download`: `item` one part; `items` several; neither the whole run. Several
  come as one zip.
- `hosted`: the download is kept by us, encrypted for the browser whose public
  key this is, at most `max_bytes` (see "A download kept for a day"). `null`:
  to the owner's bucket.

`items: []` on a restore means the whole run.

## POST /events/backups/requests

How one went: `running` when started, then `done` or `failed`.

```json
{ "site_id": "…", "host": "web-1", "id": "…", "state": "done",
  "url": "https://…", "expires_at": "2026-11-07T10:30:00.000Z", "bytes": 1234567, "filename": "shop-20261107.zip" }
```

```json
{ "site_id": "…", "host": "web-1", "id": "…", "state": "done",
  "steps": ["alerts paused", "copied how things are now, as backup 20261107T093000Z", "put back /var/www/shop", "services running as before"],
  "aside": ["/var/www/.sitegoose-before-ab12cd34ef56-shop"], "safety_run": "20261107T093000Z" }
```

```json
{ "site_id": "…", "host": "web-1", "id": "…", "state": "done", "run": "20261107T093000Z", "steps": ["backed up: ok"],
  "hosted": true, "wrapped_key": "…", "bytes": 1234567, "filename": "web-1-20261107.zip" }
```

```json
{ "site_id": "…", "host": "web-1", "id": "…", "state": "failed", "error": "…" }
```

`run` is the run a `backup` made. `wrapped_key` is the download's secret
wrapped for the browser (RSA-OAEP, standard base64). A `failed` download kept
by us gives its room on the month back and drops what was uploaded.

Only `http(s)` links are kept. `404` when the request isn't one handed to this
server, or is already finished.

## A download

Made on the server, after a check that the temp folder has room. One part is
read out of restic as its own file: a database as its tool's file, gzipped; a
folder as a tar, gzipped, on Linux, and as a zip on Windows. Several parts,
or a whole run, come as one zip written as it goes: a folder inside it as
`<path with _ for />.tar` (Linux) or `.zip` (Windows), a database by its own
name. Names: `shop-20261107.tar.gz`, `shop-20261107.sql.gz`, `web-1-20261107.zip`.

Then either:

- **To the owner's bucket** (`hosted: null`): uploaded in 64 MB parts to
  `sitegoose-downloads/<repository prefix>/` at the root of the same bucket,
  beside the repository and never inside it, and a presigned link (SigV4, one
  hour) sent back. The file there is **not** encrypted beyond what the
  bucket does: it is the owner's bucket and the link is theirs. Deleted from
  the bucket after a day.
- **Kept a day by us** (`hosted`): below.

The dashboard asks for the password (or the authenticator code) for every
download, and shows the link only to the person who asked, never in an email.

Not an S3 bucket and no downloads from us: `export RUN PART FILE` on the
server writes one part to a file.

## A download kept for a day

For a server whose backups aren't in a bucket of the owner's, or an owner who
would rather. The file goes to a private bucket of ours, but **we can't open
it**: it is encrypted on the server for the one browser that asked.

1. The browser makes an RSA-OAEP key pair (3072 bits, SHA-256). The private
   key can't be read out of the browser (it is not extractable) and stays in
   its IndexedDB; the public key goes with the request.
2. The server makes a random 32-byte secret, wraps it with that public key
   (RSA-OAEP, SHA-256, no label) before any other work, so a key that won't
   do is said at once, and encrypts the download in one pass as restic reads
   it out: only ciphertext ever touches its disk.
3. `POST /events/backups/upload { site_id, host, id, bytes }`: the collector
   checks the request is this server's, running and kept by us, and that
   `bytes` is within `max_bytes`; takes that much room on the owner's month
   (atomically, once per request); and answers
   `200 { "part_size": 67108864, "parts": [{ "n": 1, "url": "…" }, …] }`,
   a presigned `PUT` link per part, good for 13 hours. `409 { error }` when
   it can't (no room left, already uploading), which the agent passes on.
4. The server `PUT`s each part (three tries) and sends
   `POST /events/backups/upload/done { site_id, host, id, parts: [{ n, etag }] }`.
   The collector completes the upload and checks the stored size is the size
   that took the room, or deletes it.
5. The result carries `wrapped_key`. The page gives it, and a link valid an
   hour, to the person who asked; their browser unwraps the secret and its
   service worker decrypts the file as it downloads.

The file is deleted a day after it was uploaded (the scheduled-reports
process), and the bucket's own rule deletes anything older than two days.

The file's format (v1), the same from both agents
(`sdk/protocols/download-cases.json` pins it: every agent's tests and the
dashboard's read the same cases):

```
"SGDL0001"  chunk size (u32, big-endian; 4 MiB)
then per chunk:  ciphertext (chunk size, the last one shorter)  tag (32 bytes)

enc key = HMAC-SHA256(secret, "sitegoose-download-v1 enc")
mac key = HMAC-SHA256(secret, "sitegoose-download-v1 mac")
ciphertext = AES-256-CTR(enc key), the counter a 128-bit big-endian number
             from 0, running on across chunks
tag = HMAC-SHA256(mac key, header ‖ chunk number (u64, big-endian) ‖ last (1 byte: 1 or 0) ‖ ciphertext)
```

A file changed, reordered or cut short fails its tags: the last chunk is the
one that says it is. An empty download is one empty last chunk. AES-CTR with
an HMAC rather than AES-GCM because neither `openssl enc` nor .NET Framework
does GCM; Linux uses the system's libcrypto, Windows .NET's AES.

The monthly room and the largest file come from the site owner's plan:
Basic 20 GB a month, 5 GB a file; Pro 200 GB, 20 GB; Free with the $3
"Backup downloads" add-on as Basic. A download over `max_bytes` stops part
way ("download its parts one at a time").

## A restore

Only when `allow_restore` is `true` on that server for a request from the
dashboard; the command line (`restore RUN [PART…]`) asks you to type
`restore` instead, or takes `--yes` (`-Yes` on Windows).

1. Alerts are paused for 120 minutes (`POST /events/maintenance`), so a site
   going down mid-restore emails nobody, and ended afterwards.
2. What is about to be replaced is backed up first, as a run of its own
   (`trigger:before-restore`). If that fails, nothing is changed.
3. Each part is put back:
   - a folder is restored beside itself (`.sitegoose-restore-<id>-<name>`),
     then swapped in by renaming. The folder as it was is kept a week at
     `.sitegoose-before-<id>-<name>`, then deleted. System folders and drives
     are refused, and on Linux mount points: `--into FOLDER` copies them out
     instead. On
     Windows, when a file in it is held open and the rename fails, it is
     mirrored over with `robocopy /MIR`.
   - a database by its own tool: `pg_restore --clean --single-transaction`
     (`--create` when it was dropped), the MySQL dump (it drops and makes the
     database), `mongorestore --drop`, SQLite through the backup API,
     `RESTORE DATABASE … WITH REPLACE` with the database in single-user mode.
4. The services that were running before must be running a minute later.
5. If a part fails or a service stops, everything is put back: swapped folders
   swapped back, the rest restored from the run of step 2.

## Commands

| Linux | Windows | |
| --- | --- | --- |
| `analytics-agent backup-setup` | `analytics-agent.ps1 backup-setup` | install restic (pinned version, checked against its SHA-256), make the password (shown once), make the repository |
| `analytics-agent backup` | `analytics-agent.ps1 backup` | back up now, whatever the schedule |
| `analytics-agent backups` | `analytics-agent.ps1 backups` | list the runs and their parts |
| `analytics-agent restore RUN [PART…] [--into FOLDER] [--yes]` | `analytics-agent.ps1 restore RUN [PART…] [-Into FOLDER] [-Yes]` | put back (or copy out) |
| `analytics-agent export RUN PART FILE` | `analytics-agent.ps1 export RUN PART FILE` | one part to a file |

Without the agent, restic itself reads every backup: `restic -r REPOSITORY snapshots --tag sitegoose`.
