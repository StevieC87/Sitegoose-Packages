# analytics-platform (Python)

One package for your Python server, run from your analytics dashboard: a
**firewall**, **error monitoring** and **server analytics** (payments,
sign-ups, leads). Django, Flask, FastAPI and any WSGI or ASGI app. No
dependencies; Python 3.8 or later.

```bash
pip install analytics-platform
```

Put your keys in `.env` (site settings has all three, ready to copy), or in
your host's environment:

```bash
ANALYTICS_SITE_ID=YOUR_SITE_ID
ANALYTICS_SITE_SECRET=YOUR_SITE_SECRET
ANALYTICS_ENDPOINT=https://YOUR_COLLECTOR_URL
```

The package reads only the `ANALYTICS_*` lines of the `.env` in the folder the
server starts in (Django: beside `manage.py`), and never writes them into
`os.environ`, so your own `.env` loading is unaffected. Behind Cloudflare, add
`ANALYTICS_TRUST_PROXY=cloudflare`; behind Nginx or a load balancer,
`ANALYTICS_TRUST_PROXY=1`. Several services on one site? Give each
`ANALYTICS_SERVER_NAME=api` (or `worker`, and so on).

## Flask and FastAPI: one line

```python
from analytics_platform.start import platform
```

Put it near the top of the module that makes your app. On the app's first
request, the package puts itself in front of it: Flask through
`init_flask(app)`, and FastAPI or any Starlette app through its middleware, as
the outermost of yours. It works whether the import is above or below
`app = Flask(...)`. An app that already has the platform by hand gets nothing
added a second time, and a FastAPI app mounted inside another isn't counted
twice.

Use the same import wherever you call `platform.track()` and the rest: it's
one platform for the whole process. It's made on first use, not on import, so
under Gunicorn or uWSGI with `--preload` its background threads start in each
worker, not in the master.

## Django: one line in settings

```python
# settings.py
MIDDLEWARE = [
    "analytics_platform.django.PlatformMiddleware",  # first
    # ...
]
```

That's all with the keys in `.env` or the environment. Options in code go in
`ANALYTICS_PLATFORM`, and win over the environment:

```python
ANALYTICS_PLATFORM = {"trust_proxy": 1, "errors": {"capture_logging": True}}
```

In your code: `from analytics_platform.django import get_platform`. The
package tells the collector it is a Django site (`analytics-platform-django/…`),
so attack patterns written for Django reach it.

## Setting it up in code instead

For options in code with Flask, FastAPI or another app (use this or the line
above, not both). Any key left out is read from `ANALYTICS_*`:

```python
from analytics_platform import create_platform, PlatformMiddleware

platform = create_platform(errors={"capture_logging": True})

app.add_middleware(PlatformMiddleware, platform=platform)   # FastAPI / Starlette
platform.init_flask(app)                                    # Flask
```

Other WSGI apps: `app = platform.wsgi(app)`; other ASGI apps: `app = platform.asgi(app)`.

## Celery, RQ and Dramatiq

```python
platform.init_celery(app)          # Celery: where the app is made
platform.init_dramatiq(broker)     # Dramatiq: after dramatiq.set_broker(broker)
PlatformWorker = platform.rq_worker()   # RQ: rq worker -w jobs.PlatformWorker
```

Every task, message or job then runs as a [job](#error-monitoring) named
after the task, actor or function: its errors carry the route
`/(job) shop.tasks.charge`, one that raises is sent once (status 500), and
each run is timed (Server speed → Jobs). Prefork, solo, threads, gevent and
eventlet pools all work (Dramatiq's `dramatiq-gevent` too), and so does
Celery's `task_always_eager`.

- A failure that will be retried is timed as failed but not sent: the error
  is sent when the last attempt fails. Celery's `Ignore` counts as done,
  `Reject` as failed.
- A run cut short (`SystemExit`, a hard time limit, the worker stopping
  mid-task) is timed as failed. Time limits are sent as errors; `SystemExit`
  isn't.
- A Celery or Dramatiq process killed outright (`SIGKILL`, out of memory)
  can't be timed: nothing of the run is left to say how long it took. RQ's
  worker outlives the process it runs a job in, so it sends and times that
  job itself (`WorkHorseKilled`).
- What's waiting is sent as each worker process ends. RQ runs each job in a
  process of its own, so it sends after every job; only the worker checks
  in (Health → All systems), not a process per job.
- Don't also wrap a task in `platform.job()`: it would be timed twice.
- Each queue's backlog: [`platform.watch_queue(...)`](#job-queues).

## Modules

| Module | What it does | Default |
|---|---|---|
| `firewall` | Blocks addresses, known criminal networks, shared blocks and floods (Security → Firewall) | on |
| `firewall`'s attack patterns | Rules that match the *request* (its path, query string and user agent), not just the address, so an attack is turned away before your code runs — a package with a known hole stays safe until you update it. They come with the firewall's rules and are managed on the Security page (Firewall → Attack patterns); a pattern a real visitor might trip only watches until you promote it. Nothing to configure (protocol: `sdk/protocols/firewall.md`) | with the firewall |
| `proxy` | Serves the tracker and takes visits under your own domain, so ad blockers can't hide those visitors | on |
| `errors` | Sends your server's errors to the Errors report | on |
| `analytics` | `track()`, `identify()` and `lead()` from your server | on |
| `audit` | `platform.audit("user.role_changed", actor=..., target=..., request=...)`; Django logins and logouts on their own | on |
| `flags` | `platform.is_enabled("new-checkout", user=user.id)`: features on or off from the dashboard | on |
| `maintenance` | A "back soon" page while maintenance mode is on in the dashboard | on |
| `headers` | Adds the security headers you pick on the Security page; your own headers win | on |
| `forms` | Checks forms before you accept them: `platform.check_form(request)` | on |
| `performance` | Response times and errors of every route (Health → Server speed): Django, Flask and FastAPI route patterns, the database queries each one ran, the other services it waited on, and your job queues' backlog (below) | on |
| `crawlers` | Which search engines and AI bots fetch your pages (Off-site → Crawlers). Django counts them for you; elsewhere call `platform.record_crawler(...)` | on |
| `inventory` | The installed packages and Python version, once a day, so the Security check can flag known security holes (`{"host": ...}`: the server's name) | on |
| `posture` | How the server is set up, once a day, for the Security check: Django's `DEBUG`, `SECRET_KEY`, `ALLOWED_HOSTS` and cookie settings (when it's a Django site), whether the app runs as root, code anyone on the machine can write, and files in the folders you serve to the web that shouldn't be public (a dump, a `.env`, a `.bak`). The dashboard then asks your site for each of those files and tells you whether it really is downloadable. Reads only, and sends no file's contents. `{"roots": ["public", {"dir": "uploads", "prefix": "files"}]}` (default: Django's `STATIC_ROOT` and `MEDIA_ROOT`, reported at their `STATIC_URL` / `MEDIA_URL`), `{"checks": fn}` for checks of your own (protocol: `sdk/protocols/posture.md`) | on |

Each takes `True`, `False` or its options as a dict:

```python
create_platform(site_id=..., secret=..., endpoint=...,
                firewall={"mode": "monitor", "cache_file": "/tmp/firewall-rules.json"},
                errors={"capture_uncaught": False},
                analytics=False)
```

**Switch modules off in the dashboard** (Security → Server package) without a
deploy: the package checks about once a minute. Modules are independent: one
failing to start, or the collector being down, never stops the others, and
never slows your requests. Background work runs in daemon threads, which start
again in each worker after a fork (gunicorn, uWSGI).

## Firewall

Rules, monitor or block mode and reports are in the dashboard (Security →
Firewall). New sites start in monitor mode.

Options: `mode` (`"monitor"` or `"block"`, overrides the dashboard),
`cache_file` (keep rules between restarts), `trust_proxy`, `counter`.

**The visitor's address:** behind a proxy, every request comes from the proxy
unless you set `trust_proxy`: `1` for one proxy or load balancer, `2` for
Cloudflare in front of a load balancer, `"cloudflare"` when every request comes
through Cloudflare (`CF-Connecting-IP` is believed only from Cloudflare's own
addresses: anyone who reaches your server directly can send it).
`X-Forwarded-For` is read from the right, as each proxy appends what it saw;
a port on an entry (`203.0.113.5:54321`, `[2001:db8::1]:443`, as Azure sends
them) is dropped, and an entry that isn't an address (`unknown`, a name)
means the connection's own address is used rather than no check at all.

When something in front of the package already works out the address, count
each proxy once:

- **gunicorn** never changes `REMOTE_ADDR` (`--forwarded-allow-ips` is about
  `X-Forwarded-Proto` only): set `trust_proxy`.
- **Uvicorn** (`--proxy-headers`, on by default, trusting the addresses in
  `--forwarded-allow-ips`) puts the visitor's address in place itself, and
  leaves the header as it was. Leave `trust_proxy` unset when
  `--forwarded-allow-ips` lists your proxies' addresses. With
  `--forwarded-allow-ips='*'` (`FORWARDED_ALLOW_IPS=*`, common in Docker images)
  Uvicorn takes the **leftmost** entry, which the visitor writes: there, set
  `trust_proxy` to your number of proxies, and the package reads the header
  itself from the right.
- **werkzeug's `ProxyFix`**: wrapped inside the package's middleware
  (`app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1)` before `init_flask`), the
  package uses its `x_for` when `trust_proxy` is unset; wrapped outside, it has
  already set `REMOTE_ADDR` and unset `trust_proxy` uses that.
- **Apache's `mod_remoteip`** (`mod_wsgi`) sets `REMOTE_ADDR` to the visitor
  and *removes the entries it used* from `X-Forwarded-For`, leaving only what
  the visitor wrote. Leave `trust_proxy` unset there: counting the same proxy
  again would believe the visitor's own entry.
- **Django** reads no forwarding header of its own: as gunicorn or Uvicorn
  above, whichever runs it.

**What the rate limit counts:** requests per IPv4 address, or per IPv6
**/64** (one machine usually holds a whole /64, so counting addresses would let
it start afresh on every request); `::ffff:a.b.c.d` counts as `a.b.c.d`. The
same goes for bans and failed logins. Static files (`.css`, `.js`, images,
fonts, video, `.pdf`, `.wasm`, and anything under `/static/`) aren't counted,
so a page with 40 assets is one hit, not 41. A full table of counts (100,000)
drops its oldest entries, never everyone's.

**Rate limit with several workers:** each worker counts on its own, so the
limit is per worker. For one count, pass a shared counter:

```python
def counter(key, ttl):
    hits = redis.incr(key)
    if hits == 1:
        redis.expire(key, ttl)
    return hits

create_platform(..., firewall={"counter": counter})
```

**Bot protection:** Django's failed logins are counted on their own; elsewhere
call `platform.login_failed(request)` when a login fails. Past the site's limit
the address is banned here straight away and on your other servers within a
minute or two. Floods (over the rate limit) are banned the same way.


**Probes.** Requests for files no visitor ever asks for (`/.env`, `/.git/…`,
backups: the list comes with the rules) are rule `probe`; in block mode the
address is also banned on this server, and the collector bans it on the
site's other servers.

**Browser check** (paid plans, switched on in the dashboard). A visitor's
first page of the day is a short "checking your browser" page that sets a
cookie with JavaScript and reloads; after that the site answers as usual for
about a day. Only a `GET` or `HEAD` that asks for a web page is checked: forms,
webhooks, payment callbacks, API calls (`Accept: application/json`), the paths
you exclude (`/api/`, …), your allowed addresses, search engines and the AI
crawlers that bring visits never see it. It stops cheap floods — scripts that
don't run JavaScript — and nothing more: a real browser, or a bot driving one,
gets through. It's a speed bump against scripts that don't run JavaScript: a
bot written for this product can read the pass from the page, which is why
the pass is bound to the visitor's address and the day. The cookie, `__sg_pass`, holds a signed day and nothing about the
visitor; it exists only to keep the site reachable, so it is strictly necessary
and needs no consent. Checked requests show on the Security page as rule
`challenge`.

## Error monitoring

Uncaught exceptions are sent on their own; request errors through the
middleware (Django, Flask, FastAPI). Errors you catch:

```python
try:
    charge_card(order)
except PaymentError as error:
    platform.capture_exception(error, status=502)
    raise
```

Exceptions your code only logs: `errors={"capture_logging": True}` sends an
exception logged at ERROR or above (`logger.exception(...)`, or
`exc_info=True`); it is still logged. An exception is sent once however many
of these see it, and one logged inside a Django, Flask or ASGI request keeps
that request's route. A batch the collector couldn't take is tried once more
a few seconds later. A visitor who hangs up mid-request (`BrokenPipeError`,
`ConnectionResetError`, Starlette's `ClientDisconnect`, Django's
`UnreadablePostError`) isn't sent as a server error. Messages are cut at
2,000 characters; the traceback keeps the detail.

What still can't be sent waits in a file in the temp folder and is sent when
it can be, after a restart too; each error keeps the time it happened.

An error in a request or job also shows the steps before it. Add them with
`platform.add_breadcrumb("Order saved")`; a step added outside a request or job
is dropped. Outgoing calls aren't recorded on their own, since Python has no
public way to see them.

Background jobs, as a decorator or a `with` block (sync or async):

```python
@platform.job("send-receipts")
def send_receipts(): ...
```

Their errors carry the job's name as the route, a job that raises is sent
(status 500) and raised on, and each run is timed (Server speed → Jobs).
Several services on one site: `Platform(..., server_name="worker")`.

**Several apps on one site** (microservices, a worker, a Node service next to
this one): install the package in each, with the same `site_id`, `secret` and
`endpoint`, and a `server_name` of its own. Errors, Server speed, Crawlers and
Health → Updates then tell the apps apart, and Health → All systems lists
each with a light: the package checks in about once a minute, so an app that
stops reads "Stopped" within ten minutes (`sdk/protocols/checkin.md`).
Without one, each app is named
after its machine: two apps on one machine are reported as one, and only the
last package list sent is kept. A service only your other apps call takes
`firewall=False, proxy=False, maintenance=False` (its requests all come from
your own apps, so the rate limit would see one visitor).

**Several apps on one machine**: leave `resources` on in all of them. The
machine's CPU, memory and disks are shown once, and each app (each gunicorn
or Celery worker process too) adds what is its own: its container's memory
and CPU caps and how close it is to them, how often the cap throttled it,
processes the kernel killed for memory, open files against the limit, the
most requests in progress at once, and how long it has run. On Linux the
machine's waiting time (`/proc/pressure`), connections refused before the
app accepted them and the connection-tracking table come with them. Python
sends no heap or garbage-collection figures. A figure the machine won't give
(no cap, no PSI, not Linux) is left out, never sent as 0 (protocol:
`sdk/protocols/resources.md`, "Limits").

Options: `server_name`, `root` (traceback paths relative to it),
`capture_uncaught`, `capture_logging`, `spool_dir` (where unsent errors wait;
`False` for none), `before_send(event, error)` (change an error, or return
`None` to drop it).

## Database queries

Server speed also shows which queries a route spends its time on (Health →
Server speed → Queries): per route and query, how many ran, how many failed and
how long they took. Every value is taken out of a query on your server before
it is counted (`WHERE email = ?`, `IN (?)`), and bound parameters are never
read, so no data leaves it.

| Library | Setup |
|---|---|
| Django | nothing: every connection, under the request or job that ran the query |
| SQLAlchemy | nothing: every engine (Flask-SQLAlchemy too) |
| pymongo | nothing, but **create the platform before your `MongoClient`**: pymongo only reports to clients made after the package is listening |
| Any other DB-API driver (psycopg, psycopg2, mysqlclient, PyMySQL, sqlite3...) | `conn = platform.watch_database(psycopg.connect(...))`, and use `conn` as before |
| ClickHouse: clickhouse-connect, clickhouse-driver | `client = platform.watch_database(clickhouse_connect.get_client(...))` (or a `clickhouse_driver.Client`), and use `client` as before |
| Redis: redis-py (`Redis`, `RedisCluster`, sync or `redis.asyncio`) | `platform.watch_database(r)`: the client is watched in place, so keep using `r` |
| Django's cache on Redis (Django's own `RedisCache`, or django-redis) | `platform.watch_database(caches["default"])`, once at start-up (in `AppConfig.ready()`) |

A query outside any request or job is counted as `JOB (background)`. Each
query is counted once: when SQLAlchemy or Django runs it over a watched
connection, they count it and the connection doesn't. It is on with
`performance`, and switched off with it in the dashboard; `queries=False`
keeps Server speed and leaves queries out (protocol: `sdk/protocols/queries.md`).

ClickHouse: clickhouse-connect's `query()` (and `query_df()`, `query_np()`,
`query_arrow()`, `raw_query()`) reads the whole result before it returns, so
its time is the result's too; `command()` and the inserts are timed until
they answer. clickhouse-driver's `execute()` likewise. The streaming
queries (`query_rows_stream()`, `execute_iter()`) aren't timed. Only the
client you pass is wrapped; the library itself is left alone.

Redis: each command is counted by its name and the shape of its key (`GET
user:?:cart`); no other argument or value is read. A pipeline or transaction
is one call (`PIPELINE GET user:?`, `MULTI SET cart:?`), timed as a whole.
Commands that wait (`BLPOP`, `XREAD BLOCK`, subscribing) aren't timed, and
nor are this package's own reads of your RQ queues. An error reply counts
as failed; a nil reply doesn't.

```python
r = redis.Redis.from_url(REDIS_URL)
platform.watch_database(r)

# Django (settings: CACHES backend django.core.cache.backends.redis.RedisCache
# or django_redis.cache.RedisCache), in your AppConfig.ready():
from django.core.cache import caches
platform.watch_database(caches["default"])
```

## Outgoing calls

Health → Server speed → Calls shows how long each route waited on other
services (a payment provider, an email API, your own microservices) by the
host it called (`api.stripe.com`), with how many calls failed. One line for
each client, where you make it:

```python
session = platform.watch_http(requests.Session())     # requests
client = platform.watch_http(httpx.Client())          # httpx; AsyncClient too

# httpx, with calls that got no answer counted too:
client = httpx.Client(transport=platform.watch_http(httpx.HTTPTransport()))
```

- **Only the host is sent.** A call's path, query string, headers and body
  never leave your server: paths carry IDs and keys.
- A call is timed from being sent to its response's headers arriving. A
  call that got no answer (refused, timed out), or a 5xx, is a failed one; a
  4xx is the other side's answer, not a failure. A call your code cancels
  isn't counted.
- requests: each adapter the session has mounted is wrapped, keeping its
  retries and pool settings; mount your own adapters before watching.
- httpx: `watch_http(client)` adds event hooks, which see every answered
  call but not one that got no answer at all. A watched transport
  (`AsyncHTTPTransport` for an `AsyncClient`) sees those too; with both on
  one client a call is counted once.
- urllib3 and `urllib.request` have no public hook, so their calls aren't
  counted (and nothing of theirs is patched).
- Calls are filed as queries are: under the request, the job, or
  `JOB (background)`. The package's own calls to us are left out.
- They ride on Server speed's switch; `calls=False` leaves them out
  (protocol: `sdk/protocols/calls.md`).

## Job queues

Health → Server speed → Jobs shows each queue's backlog once a minute: jobs
waiting, running, delayed and failed, how long the oldest has waited, and
jobs added against jobs finished, so a queue falling behind shows before the
emails go out an hour late.

```python
platform.watch_queue(celery_app)                 # Celery on a Redis broker; queues=["emails", ...] to name them
platform.watch_queue(Queue("emails", connection=redis))   # RQ, in web servers and workers alike
```

- **Celery** has no backlog API, so the broker's own lists are read from
  Redis (one `LLEN` per queue and priority). Celery can't say what is
  running, delayed or failed, nor how long a message has waited, so those
  are left out; each process counts the tasks it published and, in a
  worker, the ones it finished (a retry isn't finished). With a RabbitMQ
  broker nothing is sent from here: the server agent reads RabbitMQ's own
  numbers.
- **RQ**: the queue, its started, scheduled, deferred and failed job
  registries, and when its first job was added. RQ has no hook for a job
  being added; jobs finished are counted by `platform.rq_worker()`'s
  worker, so watch the queue in the worker's code too.
- Watching one queue in several processes is fine: the dashboard takes the
  largest reading, never the sum. Its Redis is named by host, port and
  database; never a password.
- A reading that fails is a gap, not a zero. Readings run on a background
  thread, never in a request.
- They ride on Server speed's switch; `queues=False` leaves them out
  (protocol: `sdk/protocols/queues.md`).

## Server analytics

For what only your server knows for sure. Not pageviews: the tracker counts those.

```python
session = platform.session_id(request)  # the visit, from the X-Analytics-Session header

platform.track("purchase", {"numeric_value": "49.90", "currency": "EUR", "event_uid": f"order-{order.id}"}, session_id=session)
platform.identify(user.id, session_id=session, traits={"plan": "pro", "seats": 5, "trial": False})  # traits are optional
platform.lead({"email": "ana@example.com", "name": "Ana", "status": "qualified"})
```

`track()` sends in the background; `identify()` and `lead()` wait for the
answer (up to 5 seconds). What you pass is taken as JSON when you pass it
(also `audit()`'s `details`): a date becomes ISO text, a `Decimal` a number,
a set a list, `NaN` null and anything else its `str()`, so one odd value can't
fail the batch it is sent in.

**User traits:** `identify()` takes optional `traits`, a dict of name to
text, number or `True`/`False`. Lists, dicts and other values are left out
(and `traits` is left off when nothing is left). The collector does the rest:
names are lowercased with spaces and dashes as `_` (up to 40 letters, digits
and `_`), text is cut at 200 characters, values that look like an email
address are dropped, and at most 20 are kept.

**Link to the visit:** send the tracker's session ID with your site's requests:

```js
fetch("/api/orders", { headers: { "x-analytics-session": window.analyticsSession?.getId() || "" }, ... });
```

## Ad blockers

Many visitors use an ad blocker, and most blockers stop analytics. They
recognise **the address a script comes from** and **what it is called**, so a
tracker loaded from us is simply never counted.

This package already runs on your own domain, so it serves the tracker and
takes the visits itself. Nothing to set up: use the two addresses it gives you
in your page's template.

```python
platform = get_platform()          # Django; elsewhere your own platform
context = {
    "script_url": platform.proxy.script_url(),    # /3f9a2c1b/js/v1/s.js
    "collect_url": platform.proxy.collect_url(),  # /3f9a2c1b/api/e
}
```

```html
<script async src="{{ script_url }}" data-siteid="..." data-domain="example.com"
        data-collect="{{ collect_url }}"></script>
```

- The path comes from your secret, so it isn't in the page and isn't a name
  any blocker lists. Pick your own with `proxy={"prefix": "..."}`.
- Tracker files are fetched once and then held in memory; if we can't be
  reached, the copy already held is served rather than nothing.
- The visitor's address goes on as `X-Forwarded-For` (your collector needs it
  for the country, the daily visitor ID and the rate limit) and cookies never
  leave your server.
- Beacons are answered before the firewall, the crawler count and the timing,
  so your own analytics traffic doesn't appear as pages of your site. On ASGI
  the send runs in a thread, so the event loop keeps turning.
- Works through the Django, WSGI (Flask, Bottle, Pyramid) and ASGI (FastAPI,
  Starlette) middleware alike.
- A denied or banned address (and one in the blocklists or shared blocks)
  gets nothing from it either; beacons are never rate-limited or checked.
- It runs on your request threads, so it never waits long: 2 seconds at most,
  and after 3 failures in a row the collector is left alone for 30 seconds
  (beacons are answered `502` at once, which the tracker treats as lost, and a
  tracker file that couldn't be fetched isn't asked for again for 30 seconds).
- Switch it off with `proxy=False`, or in the dashboard (Site settings →
  Server). Then load the tracker from us as before.

## Shutting down and serverless

`platform.flush()` sends everything waiting (on Lambda, before returning).
`platform.close()` also stops the background threads.

When the process ends (and when a Celery, RQ or Dramatiq worker shuts down),
what's waiting is sent within **5 seconds** for every module together, so the
package never outlasts a container's or PM2's 30-second grace period: no retry
sleeps then, and the errors that weren't sent wait in the errors file for the
next start. `platform.flush_before_exit()` does the same from your own
shutdown hook. The errors file a resend takes is deleted only once it has
been sent, so a process killed meanwhile loses nothing (the next start takes
over a file left behind for 5 minutes).
