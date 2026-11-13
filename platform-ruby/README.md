# sitegoose (Ruby)

One package for your Ruby server, run from your analytics dashboard: a
**firewall**, **error monitoring** and **server analytics** (payments,
sign-ups, leads). Rails, Sinatra and any Rack app, with Sidekiq jobs. Only
the standard library and `rack`; Ruby 3.0 or later.

```ruby
# Gemfile
gem "sitegoose"
```

## Rails

Add the gem and put your keys in the environment (site settings has all
three, ready to copy). That's all: the gem's Railtie puts its middleware
first.

```bash
ANALYTICS_SITE_ID=YOUR_SITE_ID
ANALYTICS_SITE_SECRET=YOUR_SITE_SECRET
ANALYTICS_ENDPOINT=https://YOUR_COLLECTOR_URL
# ANALYTICS_TRUST_PROXY=1            # behind Nginx or a load balancer
# ANALYTICS_TRUST_PROXY=cloudflare   # every request through Cloudflare
# ANALYTICS_SERVER_NAME=api          # several services on one site
```

With `dotenv-rails`, `.env` works as usual: the platform is made on first
use, after it has loaded.

Options in code go in an initializer, or the credentials
(`bin/rails credentials:edit`, under `sitegoose:`), or `config.sitegoose`.
Lowest first: the environment, credentials, `config.sitegoose`, `configure`.

```ruby
# config/initializers/sitegoose.rb (optional)
SiteGoose.configure(trust_proxy: 1, errors: { capture_logging: true })
```

Then, on their own:

- Request errors, with the route pattern (`/orders/:id`), including the ones
  Rails turns into its 500 page.
- `Rails.error.handle`, `.record` and `.report`: the errors your code handles.
- Devise (Warden) failed logins count towards bot protection, and logins and
  logouts go to the audit log.
- The controller action, mail and queued job before an error are its
  breadcrumbs.

In your code: `SiteGoose.track(...)`, or `SiteGoose.platform`.

## Sinatra and other Rack apps

```ruby
use SiteGoose::Middleware   # the keys from ANALYTICS_* in the environment, as for Rails
```

Or pass them: `use SiteGoose::Middleware, site_id: "...", secret: ENV["ANALYTICS_SITE_SECRET"], endpoint: "https://..."`.

Put it first; added twice (by hand next to the Railtie, or by an engine),
the second copy passes requests straight on. Sinatra's route patterns (`/users/:id`) and its error pages are
read on their own; set `set :raise_errors, false` (production's default) or
`set :show_exceptions, false` as usual. Hanami, Roda and plain Rack work the
same way. A full example is in `examples/sinatra/`.

## Sidekiq

```ruby
# config/initializers/sidekiq.rb
require "sitegoose/sidekiq"
SiteGoose::Sidekiq.install
```

Every job then runs as a [job](#error-monitoring) named after its class (the
ActiveJob class under ActiveJob): its errors carry the route
`/(job) ChargeJob`, and each run is timed (Server speed → Jobs).

- A failure that will be retried is timed as failed but not sent: the error
  is sent when the last attempt fails, or when Sidekiq gives the job up (the
  Dead set, `:kill`).
- `Sidekiq::Shutdown` (a job stopped mid-run, to run again) is neither timed
  nor sent.
- What's waiting is sent when Sidekiq shuts down.
- Don't also wrap a job in `platform.job`: it would be timed twice.
- Each queue's backlog is shown too ([Job queues](#job-queues)), from the
  same line.

## Puma, Unicorn and Passenger

The platform is made on the first request, so a master that only forks
workers starts nothing. Its background threads start again in each worker
after a fork (Puma clustered mode, `preload_app!`, Unicorn, Passenger), a
fork waits for a send in flight, and what the parent had waiting is the
parent's to send. Nothing to configure. On Ruby 3.0, which has no fork hook,
a worker notices it was forked at its first request or job instead, and a
fork doesn't wait for a send in flight.

## Modules

| Module | What it does | Default |
|---|---|---|
| `firewall` | Blocks addresses, known criminal networks, shared blocks and floods (Security → Firewall) | on |
| `firewall`'s attack patterns | Rules that match the *request* (its path, query string and user agent), not just the address, so an attack is turned away before your code runs. They come with the firewall's rules and are managed on the Security page (Firewall → Attack patterns). Nothing to configure (protocol: `sdk/protocols/firewall.md`). Patterns need Ruby 3.2+, which can stop a match that runs long; on 3.0 and 3.1 a rule's pattern is skipped (its other parts still match) and a warning says so once | with the firewall |
| `proxy` | Serves the tracker and takes visits under your own domain, so ad blockers can't hide those visitors | on |
| `errors` | Sends your server's errors to the Errors report | on |
| `analytics` | `track`, `identify` and `lead` from your server | on |
| `audit` | `platform.audit("user.role_changed", actor: ..., target: ..., request: ...)`; Devise logins and logouts on their own | on |
| `flags` | `platform.enabled?("new-checkout", user: user.id)`: features on or off from the dashboard | on |
| `maintenance` | A "back soon" page while maintenance mode is on in the dashboard | on |
| `headers` | Adds the security headers you pick on the Security page; your own headers win | on |
| `forms` | Checks forms before you accept them: `platform.check_form(request)` | on |
| `performance` | Response times and errors of every route (Health → Server speed): Rails and Sinatra route patterns. With it, the database queries each route runs, its outgoing calls and your job queues (below) | on |
| `crawlers` | Which search engines and AI bots fetch your pages (Off-site → Crawlers), counted by the middleware | on |
| `resources` | This machine's CPU, load, memory, disks and network, once a minute (Health → Server resources), and how close the app is to a limit ([below](#server-limits)). Linux | on |
| `inventory` | The installed gems and Ruby version, once a day, so the Security check can flag known security holes (`{host: ...}`: the server's name) | on |
| `posture` | How the server is set up, once a day, for the Security check: Rails' environment, `consider_all_requests_local`, `secret_key_base`, `config.hosts`, `force_ssl` and session cookie settings (when it's a Rails app), whether the app runs as root, code anyone on the machine can write, and files in the folders you serve to the web that shouldn't be public (a dump, a `.env`, a `.bak`). Reads only, and sends no file's contents. `{roots: ["public", {dir: "uploads", prefix: "files"}]}` (default: Rails' `public/`), `{checks: -> { [...] }}` for checks of your own (protocol: `sdk/protocols/posture.md`) | on |

Each takes `true`, `false` or its options as a hash:

```ruby
SiteGoose.configure(site_id: ..., secret: ..., endpoint: ...,
                            firewall: { mode: "monitor", cache_file: "tmp/firewall-rules.json" },
                            errors: { capture_uncaught: false },
                            analytics: false)
```

`enabled: false` turns the whole package off (every request passes).

**Switch modules off in the dashboard** (Security → Server package) without a
deploy: the package checks about once a minute. Modules are independent: one
failing to start, or the collector being down, never stops the others, and
never slows your requests; a failure of the package itself passes the request
to your app.

## Database queries

Server speed → Queries: per route and per query, how many ran, how many
failed, and how long they took, so a slow route shows which query made it
slow. Every value is replaced by `?` before anything is counted
(`WHERE email = ?`), and bound parameters are never read
(protocol: `sdk/protocols/queries.md`).

- **Active Record** (Rails, or on its own): automatic, from its
  `sql.active_record` notification. Schema and cached queries are left out.
- **Sequel**: one line, after `Sequel.connect`:

  ```ruby
  DB = Sequel.connect(ENV["DATABASE_URL"])
  SiteGoose.watch_database(DB)
  ```

- **MongoDB** (the `mongo` gem, Mongoid): automatic, through the driver's
  command monitoring.
- **ClickHouse**: the `click_house` gem, one line, where you make the
  connection; only that connection is timed (`select_all`, `select_one`,
  `select_value`, `execute`, `insert`). An insert is filed as
  `INSERT INTO <table>`, and its rows are never read. The ClickHouse adapter
  for Active Record (`clickhouse-activerecord`) is automatic, like any other
  adapter.

  ```ruby
  CLICKHOUSE = ClickHouse::Connection.new(ClickHouse::Config.new(url: ENV["CLICKHOUSE_URL"]))
  SiteGoose.watch_database(CLICKHOUSE)
  ```

- **Redis**: automatic with `redis-client` (so the `redis` gem 5 and Sidekiq 7
  too), through its own `RedisClient.register` middleware. Each command is its
  command and first key's shape only (`GET user:?:cart`), never an argument or
  value; a pipeline is one `PIPELINE GET user:?` call and a `multi` one
  `MULTI INCR hits:?`. Blocking commands (`BRPOP`, Sidekiq's fetch) and the
  package's own queue readings aren't timed; Sidekiq's other commands are. An
  error reply or no answer is a failure; a nil or a `MOVED` isn't. The `redis`
  gem 4 has its own connection code, which isn't seen.

A query counts under the request (or Sidekiq or `platform.job` run) it ran
in, with the same method and route Server speed shows; one outside them,
like a console or a thread of your own, counts as `JOB (background)`. A
query is counted once: one run by Sequel on Active Record's connection is
Sequel's. It rides on `performance`: switched off there, nothing is
recorded; `queries: false` keeps Server speed without the queries:

```ruby
SiteGoose.configure(site_id: ..., secret: ..., endpoint: ..., queries: false)
```

## Outgoing calls

Server speed → Calls: how long each route waited on other services (a
payment provider, an email API, your own microservices) by the host it
called (`api.stripe.com`), with how many calls failed
(protocol: `sdk/protocols/calls.md`). Faraday, one line per connection, with
Faraday's own middleware; nothing is patched:

```ruby
require "sitegoose/faraday"

STRIPE = Faraday.new(url: "https://api.stripe.com") do |f|
  f.request :sitegoose        # first, so a retried call counts once
  # ... your other middleware and adapter
end
```

Anything else (`Net::HTTP`, a vendor's own client), around the call:

```ruby
SiteGoose.time_call("https://api.postmarkapp.com", method: "POST") { client.deliver(mail) }
```

- **Only the host is sent.** A call's path, query string, headers and body
  never leave your server: paths carry IDs and keys.
- A call that got no answer (refused, timed out, reset), or a 5xx, is a
  failed one; a 4xx is the other side's answer, also when Faraday's
  `raise_error` raises it. A `time_call` block that raises counts as failed.
- Faraday hands the response back whole, so the time includes reading its
  body.
- Calls are filed as queries are: under the request, the Sidekiq or
  `platform.job` run, or `JOB (background)`. The package's own calls to us,
  and a watched `click_house` connection's HTTP (they are its queries), are
  left out, and a Faraday call inside a `time_call` block counts once.
- They ride on Server speed's switch; `calls: false` leaves them out.

## Job queues

Server speed → Jobs shows each queue's backlog once a minute: jobs waiting,
running, delayed and failed, how long the oldest has waited, and jobs added
against jobs finished, so a queue falling behind shows before the emails go
out an hour late (protocol: `sdk/protocols/queues.md`). Sidekiq, from the
same line as above:

```ruby
# config/initializers/sidekiq.rb
require "sitegoose/sidekiq"
SiteGoose::Sidekiq.install
```

- The Sidekiq process reads them through Sidekiq's API: waiting is each
  queue's size, the oldest wait its latency, running the jobs in progress,
  delayed the scheduled jobs and those waiting to retry, failed the Dead
  set. One Sidekiq process reads a minute; the others only count.
- Added and finished are counted where they happen: every process that runs
  the initializer (your web servers too) counts the jobs it pushes, and the
  Sidekiq process the jobs that left for good: done, failed on the last
  attempt, or given up. A job is counted once: the client middleware marks
  the job it counted (a `sitegoose_added` field, stored with the job), so
  the scheduler or a retry pushing it back isn't a new one; a retried
  failure isn't finished.
- Redis is named by host, port and database; never a password.
- With several queues, a scheduled, retry or Dead set over 1,000 jobs isn't
  counted per queue: that figure is left out rather than read job by job
  every minute. With one queue the set's size is used, and nothing is read.
- A reading that fails is a gap, not a zero.
- They ride on Server speed's switch; `queues: false` leaves them out.

## Server limits

With `resources` on, each sample also says how close the app is to a wall,
which on a container or a busy Puma is rarely the machine (protocol:
`sdk/protocols/resources.md`, "Limits"). Nothing to set up:

- The container's memory cap and what counts against it (its working set),
  its CPU cap, how often the cap throttled it, and processes in it killed
  for memory. A cap at or above the machine's own isn't one, so a bare
  machine reports none.
- Waiting time for CPU, memory and disk (Linux's pressure figures),
  connections refused because the app didn't accept them in time, and how
  full the connection-tracking table is.
- Open files against the process's limit, and milliseconds in garbage
  collection (Ruby 3.1+).
- Puma's thread pool: busy threads against `max_threads`, and requests
  waiting for one.
- The most requests in progress at once, from the middleware's own timing
  (nothing until it has seen a request).

Puma's workers each report as themselves, so their figures aren't mixed up.
Ruby has no heap cap, so no heap figures are sent. Anything this machine
won't say is left out, never sent as 0.

## Firewall

Rules, monitor or block mode and reports are in the dashboard (Security →
Firewall). New sites start in monitor mode.

Options: `mode` (`"monitor"` or `"block"`, overrides the dashboard),
`cache_file` (keep rules between restarts), `trust_proxy`, `counter`.

**The visitor's address:** behind a proxy, every request comes from the proxy
unless you set `trust_proxy`: `1` for one proxy or load balancer, `2` for
Cloudflare in front of a load balancer, `"cloudflare"` when every request
comes through Cloudflare (`CF-Connecting-IP` is believed only from
Cloudflare's own addresses: anyone who reaches your server directly can send
it). The package reads the connection's address itself, not Rails'
`request.remote_ip`, so set it here even if Rails already trusts the proxy.

**Who is counted:** an IPv4 address, or an IPv6 address's /64 (one machine
usually holds the whole /64); `::ffff:a.b.c.d` is the IPv4 address. Files a
page load asks for by the dozen (`/assets/`, `/packs/`, `.css`, `.js`, images,
fonts) don't count against the rate limit. A forwarded address that isn't one
(`unknown`, a name) means the connection's address is checked instead, and a
port on it (`1.2.3.4:5678`, `[2001:db8::1]:443`) is dropped.

**Rate limit with several workers:** each worker counts on its own, so the
limit is per worker. For one count, pass a shared counter:

```ruby
counter = lambda do |key, ttl|
  hits = REDIS.incr(key)
  REDIS.expire(key, ttl) if hits == 1
  hits
end

SiteGoose.configure(..., firewall: { counter: counter })
```

The same counter carries the page limits (a cap set in the dashboard on one
kind of request: the login form, checkout, search), except a limit counted
per page, which stays in each worker. Over a blocking page limit the visitor
gets a 429 with `Retry-After` set to that limit's window; nothing is banned.

**Bot protection:** Devise's failed logins are counted on their own;
elsewhere call `platform.login_failed(request)` when a login fails. Past the
site's limit the address is banned here straight away and on your other
servers within a minute or two. Floods (over the rate limit) are banned the
same way.

**Probes.** Requests for files no visitor ever asks for (`/.env`, `/.git/…`,
backups: the list comes with the rules) are rule `probe`; in block mode the
address is also banned on this server, and the collector bans it on the
site's other servers.

**Browser check** (paid plans, switched on in the dashboard). A visitor's
first page of the day is a short "checking your browser" page that sets a
cookie with JavaScript and reloads; after that the site answers as usual for
about a day. Only a `GET` or `HEAD` that asks for a web page is checked:
forms, webhooks, payment callbacks, API calls (`Accept: application/json`),
the paths you exclude, your allowed addresses, search engines and the AI
crawlers that bring visits never see it. It stops cheap floods (scripts that
don't run JavaScript) and nothing more: the pass is bound to the visitor's
address and the day. The cookie, `__sg_pass`, holds a signed day and nothing
about the visitor; it is strictly necessary and needs no consent. Checked
requests show on the Security page as rule `challenge`.

## Error monitoring

Request errors are sent by the middleware, and the exception that ends the
program (a crash in a script or rake task) at exit. Errors you catch:

```ruby
begin
  charge_card(order)
rescue PaymentError => e
  SiteGoose.capture_exception(e, status: 502)
  raise
end
```

In Rails, `Rails.error.handle { ... }` and `Rails.error.report(e)` do the
same. Exceptions your code only logs: `errors: { capture_logging: true }`
sends an exception logged at ERROR or above (`logger.error(e)`); it is still
logged. Rails' logger is hooked on its own; elsewhere
`platform.capture_logger(logger)`. An exception is sent once however many of
these see it, and one sent inside a request keeps that request's route. A
batch the collector couldn't take is tried once more a few seconds later.

What still can't be sent waits in a file in the temp folder and is sent when
it can be, after a restart too; each error keeps the time it happened.

An error in a request or job also shows the steps before it. Add them with
`SiteGoose.add_breadcrumb("Order saved")`; a step added outside a
request or job is dropped. Outgoing HTTP calls aren't steps of their own
(`Net::HTTP` has no public hook); in Rails the controller, mailer and job
notifications are.

Background jobs other than Sidekiq's:

```ruby
SiteGoose.job("send-receipts") { send_receipts }
```

Their errors carry the job's name as the route, a job that raises is sent
(status 500) and raised on, and each run is timed (Server speed → Jobs).

**Several apps on one site** (a Rails app, a Sidekiq process, a Node service
next to it): install the package in each, with the same `site_id`, `secret`
and `endpoint`, and a `server_name` of its own. Errors, Server speed,
Crawlers and Health → Updates then tell the apps apart, and Health → All
systems lists each with a light: the package checks in about once a minute
(`sdk/protocols/checkin.md`). A service only your other apps call takes
`firewall: false, proxy: false, maintenance: false`; on a machine shared by
several apps, keep `resources` on in only one of them.

Options: `server_name`, `root` (backtrace paths relative to it; default
`Rails.root` or the working directory), `release` (default
`ANALYTICS_RELEASE`), `capture_uncaught`, `capture_logging`, `spool_dir`
(where unsent errors wait; `false` for none), `before_send` (a lambda taking
the event and the error: return the event, changed or not, as a Hash, or
`nil` to drop it; anything else, or a raise, drops it with a warning).
Messages are cut at 2,000 characters, and the file of unsent errors stops at
1 MB.

## Server analytics

For what only your server knows for sure. Not pageviews: the tracker counts those.

```ruby
platform = SiteGoose.platform
session = platform.session_id(request)  # the visit, from the X-Analytics-Session header

platform.track("purchase", { "numeric_value" => "49.90", "currency" => "EUR", "event_uid" => "order-#{order.id}" }, session_id: session)
platform.identify(user.id, session_id: session, traits: { plan: "pro", seats: 5, trial: false })  # traits are optional
platform.lead({ "email" => "ana@example.com", "name" => "Ana", "status" => "qualified" })
```

`track` sends in the background; `identify` and `lead` wait for the answer
(up to 5 seconds).

**User traits:** `identify` takes optional `traits:`, a hash of name to text,
number or `true`/`false` (a symbol value is sent as its name). Arrays, hashes
and other values are left out (and `traits` is left off when nothing is left).
The collector does the rest: names are lowercased with spaces and dashes as
`_` (up to 40 letters, digits and `_`), text is cut at 200 characters, values
that look like an email address are dropped, and at most 20 are kept.

**Link to the visit:** send the tracker's session ID with your site's requests:

```js
fetch("/api/orders", { headers: { "x-analytics-session": window.analyticsSession?.getId() || "" }, ... });
```

## Ad blockers

This package already runs on your own domain, so it serves the tracker and
takes the visits itself. Use the two addresses it gives you in your layout:

```erb
<% proxy = SiteGoose.platform&.proxy %>
<script async src="<%= proxy&.script_url %>" data-siteid="..." data-domain="example.com"
        data-collect="<%= proxy&.collect_url %>"></script>
```

- The path comes from your secret, so it isn't in the page and isn't a name
  any blocker lists. Pick your own with `proxy: { prefix: "..." }`.
- Tracker files are fetched once and then held in memory; if we can't be
  reached, the copy already held is served rather than nothing, and a file
  that couldn't be fetched isn't asked for again for 30 seconds.
- These run on your app's request threads, so they wait at most 1 second to
  connect and 2 to answer, and after three failures in a row the collector
  is left alone for 30 seconds (beacons get a 502 straight away; the
  tracker counts them as lost). A collector that stops answering can't use
  up Puma's threads.
- The visitor's address goes on as `X-Forwarded-For` and cookies never leave
  your server.
- Beacons are answered before the rate limit, the browser check, the
  crawler count and the timing, so your own analytics traffic doesn't
  appear as pages of your site. A denied or banned address gets a 403 here
  too.
- Switch it off with `proxy: false`, or in the dashboard (Site settings →
  Server). Then load the tracker from us as before.

## Shutting down

What's waiting is sent at exit on its own, within 5 seconds in all (a
container's or PM2's grace period is longer): no send starts after that,
none is retried, and errors that weren't sent wait in their file for the
next start. Sidekiq's shutdown flush has the same deadline.
`SiteGoose.flush` sends it
now (a short-lived script, a serverless function before returning);
`platform.close` also stops the background threads.

## Tests

```bash
bundle install
ruby -Ilib -Itest -e 'Dir["test/*_test.rb"].each { |f| require_relative f }'
```
