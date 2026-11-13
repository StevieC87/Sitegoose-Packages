# SiteGoose (.NET)

Firewall, error monitoring and server analytics for your ASP.NET Core server,
run from your analytics dashboard. ASP.NET Core 8 (and 6), minimal APIs, MVC
and Razor Pages. No dependencies beyond the ASP.NET Core shared framework.

```sh
dotnet add package SiteGoose
```

## Set up

One line in `Program.cs`:

```csharp
using SiteGoose;

var builder = WebApplication.CreateBuilder(args);
builder.Services.AddSiteGoose();
var app = builder.Build();
// app.UseExceptionHandler("/Error"); app.UseStaticFiles(); app.MapControllers(); ...
app.Run();
```

and the three keys in the environment (site settings has them, ready to copy):

```sh
ANALYTICS_SITE_ID=your 24-character site ID
ANALYTICS_SITE_SECRET=your site secret
ANALYTICS_ENDPOINT=https://collect.example.com
# ANALYTICS_TRUST_PROXY=1   # behind nginx, IIS with ARR or a load balancer (below)
```

`AddSiteGoose()` puts its middleware first in the pipeline by itself, in
front of everything the host and your code add (`UseExceptionHandler`
included), so it sees every request and every error. `app.UseSiteGoose()` is
optional: in an app that already has it, it adds nothing, and no request is
ever handled twice. Two cases still need `app.UseSiteGoose()`: a `Platform`
you register yourself, without `AddSiteGoose()` (first), and `TrustProxy`
`"aspnetcore"` (right after your `app.UseForwardedHeaders()`, since it reads
the address that leaves).

Or set them in `appsettings.json` (or the environment as `SiteGoose__Secret=...`).
These win over the `ANALYTICS_*` variables, which only fill what is still empty:

```json
{
  "SiteGoose": {
    "SiteId": "your 24-character site ID",
    "Secret": "your site secret",
    "Endpoint": "https://collect.example.com",
    "TrustProxy": "1"
  }
}
```

Keep the secret out of source control: user secrets in development, the
environment or a key vault in production.

`TrustProxy` says how to find the visitor's address:

- left out: the connection's address, when visitors connect to the app directly;
- `"1"` behind one proxy or load balancer (nginx, IIS with ARR, Azure App
  Service, Application Gateway, a cloud load balancer), `"2"` for two, and so on:
  that many addresses from the right of `X-Forwarded-For`, a port a proxy added
  (`1.2.3.4:56789`, `[2001:db8::1]:443`) dropped;
- `"cloudflare"` when every request comes through Cloudflare (`CF-Connecting-IP`,
  believed only from Cloudflare's own addresses);
- `"aspnetcore"` to use the address ASP.NET Core's own forwarded-headers
  handling settled on (`UseForwardedHeaders` with your `KnownProxies`). Then
  call `app.UseSiteGoose()` right after `app.UseForwardedHeaders()`: the
  middleware isn't put first on its own in this mode.

`ClientIp` (code) wins over all of them. The numbers are counted on
`X-Forwarded-For` and the connection **as the request arrived**: IIS
out-of-process hosting, `ASPNETCORE_FORWARDEDHEADERS_ENABLED=true` (Azure App
Service on Linux sets it) and an early `UseForwardedHeaders()` take the entries
they believe off that header, and counting what they leave would believe the
visitor's own. Whatever the setting, a value that isn't an address gives the
connection's.

`AddSiteGoose(o => ...)` changes options in code after the
configuration, for the ones that take code:

```csharp
builder.Services.AddSiteGoose(o =>
{
    o.Firewall.Skip = c => c.Request.Path.StartsWithSegments("/health");
    o.Firewall.Counter = (key, ttl) =>                                // shared rate counts
    {
        var db = redis.GetDatabase();
        var hits = db.StringIncrement(key);
        if (hits == 1) db.KeyExpire(key, TimeSpan.FromSeconds(ttl));  // or the keys never go
        return hits;
    };
    o.Errors.BeforeSend = (evt, error) => evt;                        // or null to drop
    o.Performance.Route = c => null;                                  // your own route names
});
```

`Counter` is called on the request, synchronously: keep it to one fast round
trip (a local Redis), since every request that's checked waits for it.

Background work runs in a hosted service, so it starts with the app and, at
shutdown, sends what's waiting within the host's shutdown time
(`HostOptions.ShutdownTimeout`): errors first, with one try each; what can't
be sent in time waits in the errors file for the next start.

## Modules

Every module is on by default; `"Enabled": false` under its name turns it off
(`"Errors": { "Enabled": false }`). A module that's on can still be switched off
in the dashboard (Site settings -> Server).

| Module | What it does | Options |
| --- | --- | --- |
| `Firewall` | Allow/deny lists, blocklists, shared bans, probes for secret files, request rules (virtual patching), page limits, rate limit, the browser check | `Mode`, `CacheFile`, `Counter`, `Skip` |
| `Errors` | Unhandled exceptions, request errors (also those `UseExceptionHandler` and MVC filters turn into a page), your own, with their request, trail and release | `Root`, `Release`, `CaptureUncaught`, `CaptureLogging`, `SpoolDir`, `BeforeSend`, `ServerName` |
| `Performance` | Server speed: each minute's requests per route and status (not WebSockets or event streams, which last as long as the visitor stays), the database queries and outgoing calls each route makes, and Hangfire's queues | `Route`, `Queries`, `Calls`, `Queues`, `ServerName` |
| `Crawlers` | Search engine and AI crawlers (they run no JavaScript) | `ServerName` |
| `Analytics` | `Track`, `IdentifyAsync`, `LeadAsync` | |
| `Forms` | `CheckFormAsync`: spam check before you accept a form | |
| `Headers` | The dashboard's security headers, where a response has none | |
| `Audit` | `Audit(...)`, and cookie sign-ins and sign-outs (with Identity, only its `Identity.Application` cookie: one login is one entry) | `SignIns` |
| `Flags` | `IsEnabled("key", userId)` | |
| `Maintenance` | The "back soon" page, with allowed addresses and a preview link | `Skip` |
| `Inventory` | The app's NuGet packages (its deps.json), for Security -> Updates | `Host`, `DepsFile` |
| `Posture` | The Development environment, `AllowedHosts`, cookie flags, running as root or elevated, code anyone can change, files the web root shouldn't serve | `Roots`, `Host`, `Checks` |
| `Resources` | This machine's CPU, memory, disks, network (Linux and Windows), and how close the app is to a limit | `ServerName` |
| `Proxy` | The tracker on your own domain, past ad blockers | `Prefix` |

`ServerName` at the top names this service for all of them (default: the
machine's name).

## Firewall

Rules come from the dashboard about every minute; until the first fetch (or
with the collector away) every request passes. Monitor mode only reports;
block mode answers 403, and 429 with `Retry-After` past the rate limit.
The rate limit, bans made here and failed logins count an IPv6 visitor by
its /64; images, styles, scripts and fonts the app serves itself don't count
toward the rate. Request rules' patterns run with a 50 ms limit, and in
linear time on .NET 7 and later where the pattern allows it.

Page limits (set in the dashboard) cap one kind of request on its own, say
ten login posts a minute per address. Over a limit that blocks, the visitor
gets a 429 with `Retry-After` and a one-line note; nothing is banned, and the
cap lifts when the window ends. `Counter` counts them too, except a limit that
counts every page apart, which stays in this process.

Failed logins count toward bot protection:

```csharp
var result = await signInManager.PasswordSignInAsync(name, password, remember, lockoutOnFailure: true);
if (!result.Succeeded) platform.LoginFailed(HttpContext);
```

The browser check, when the dashboard turns it on, answers a visitor's first
page with a short page (503) that sets a pass cookie and reloads; JSON, POST,
paths under the check's skip list, allowed addresses and good bots never see
it.

## Errors

Inject `Platform` where you catch something yourself:

```csharp
try { await payments.ChargeAsync(order); }
catch (PaymentException error) { platform.CaptureException(error, context: HttpContext); }
platform.AddBreadcrumb("charged the card");
```

Outgoing `HttpClient` requests are steps of the trail by themselves.
`CaptureLogging: true` also sends exceptions logged at Error or above. Set
`ANALYTICS_RELEASE` (or `Errors:Release`) to the build, for "introduced in".
Errors the collector can't take wait in a file (the temp folder, or
`SpoolDir`) and are sent once they can be, after a restart too.

Background jobs (a hosted service's loop, a queue consumer, Hangfire or
Quartz):

```csharp
await platform.RunJobAsync("send-invoices", async () => await invoices.SendAsync());
```

Its errors are named "/(job) send-invoices" and each run is timed (Health ->
Server speed -> Jobs).

## Database queries

Server speed -> Queries shows how many queries each route runs and how long
they take, per query, with every value taken out first (`WHERE id = ?`);
bound parameters are never read. It comes with the performance module, and
`"Performance": { "Queries": false }` leaves it out. Caught by the libraries'
own events, with nothing to set up:

- SQL Server: `Microsoft.Data.SqlClient` and `System.Data.SqlClient`;
- PostgreSQL: `Npgsql`; MySQL and MariaDB: `MySqlConnector` (and Pomelo's EF Core provider on top of it);
- ClickHouse: `ClickHouse.Client` and `ClickHouse.Driver`. A query is timed
  until its answer starts arriving, as the client itself times it; the
  version query a connection runs when it opens isn't counted, and its HTTP
  requests are its queries, not outgoing calls;
- EF Core on SQLite (`Microsoft.Data.Sqlite` publishes nothing itself). Other
  EF Core providers are counted at their driver, so no query counts twice.

MongoDB takes one line, before the client is made:

```csharp
var settings = MongoClientSettings.FromConnectionString(connectionString);
var client = new MongoClient(platform.WatchMongo(settings));
```

Redis (StackExchange.Redis) takes one line, with the multiplexer the app uses:

```csharp
var redis = platform.WatchRedis(ConnectionMultiplexer.Connect(configuration));
```

StackExchange.Redis's profiler gives each command's name and time, no key
and no outcome: a Redis command is counted by its name only (`GET`, never
`GET user:?`), and an error reply or a timeout isn't counted as failed.
Blocking commands (`BLPOP` and the like) aren't timed. It holds one profiler
per multiplexer, so this replaces one you registered yourself. Batches
(`CreateBatch`) reach the profiler only in StackExchange.Redis versions newer
than 2.8.16; there, each command in one is counted on its own.

A query is counted under the request it ran in (or the `RunJobAsync` job);
outside both it is a background query, and so is one a WebSocket, a SignalR
connection or an event stream runs, since Server speed doesn't time those.

## Outgoing calls

Nothing to set up: Server speed -> Calls shows how long each route waited on
other services (a payment provider, an email API, your own microservices) by
the host it called (`api.stripe.com`), with how many calls failed. Read from
`HttpClient`'s own diagnostic events, so every `HttpClient`, the ones
`IHttpClientFactory` makes and the SDKs built on them are all seen, and none
of them is changed.

- **Only the host is sent.** A call's path, query string, headers and body
  never leave your server: paths carry IDs and keys.
- A call is timed from being sent to its response's headers arriving. A call
  that got no answer, or a 5xx, is a failed one; a 4xx is the other side's
  answer, not a failure. A call your code cancels isn't counted, and neither
  is one `HttpClient.Timeout` or `ConnectTimeout` ends: `HttpClient` reports
  both to its hook exactly as a cancellation.
- Calls are filed as queries are: under the request, the `RunJobAsync` job,
  or as background calls. The package's own calls to us are left out.
- `"Performance": { "Calls": false }` keeps Server speed and leaves calls out.

## Job queues

Server speed -> Jobs shows Hangfire's backlog once a minute: jobs waiting in
each queue and how long the oldest has waited, and for the whole storage the
jobs processing, scheduled and failed, and the jobs finished. One line, after
Hangfire's storage is set up:

```csharp
builder.Services.AddHangfire(c => c.UseSqlServerStorage(connectionString));
// ...
var app = builder.Build();
app.Services.GetRequiredService<Platform>().WatchHangfire(JobStorage.Current);
```

- It reads Hangfire's own monitoring API, the same figures its dashboard
  shows, and takes the storage as an object: the package has no Hangfire
  reference, so it adds nothing to an app without it.
- Processing, scheduled and failed jobs are kept for the whole storage, not
  per queue, so they go on one more line, "(all queues)". Finished is the
  storage's own count (succeeded, deleted, and failed for good, not a retry),
  the same in every process that watches it. Hangfire keeps no count of jobs
  added.
- The storage is named as it names itself, with any user or password taken
  out (SQL Server's `db1@Hangfire` shows as `db1/Hangfire`);
  `WatchHangfire(storage, "jobs-db")` names it yourself.
- A reading that fails, or takes over 5 seconds, is a gap, not a zero.
- Time each job too with `platform.RunJobAsync("send-email", ...)` inside it.
- `"Performance": { "Queues": false }` keeps Server speed and leaves queues out.

## Limits

The resources module also says how close the app is to a wall, which on
the setups people run is rarely the machine. On Linux: the container's or
service's memory and CPU caps (cgroup v1 and v2) and what counts against
them, how often the CPU cap throttled it, processes killed for memory beside
it, the machine's waiting time (`/proc/pressure`), connections refused before
the app accepted them, how full the connection-tracking table is, and open
files against the limit. Everywhere: the thread pool's waiting work items,
the GC heap against what it may use, time spent in GC (.NET 7 and later), how
long the process has run, and the most requests in progress at once (with
its middleware in place, as `AddSiteGoose()` puts it). A cap that isn't one (no `MemoryMax`, a cap above
the machine's own) is left out, and so is anything this machine won't say.

## Server analytics

```csharp
platform.Track("purchase", new { numeric_value = 49.90m, currency = "EUR", transaction_id = order.Id }, Platform.SessionId(HttpContext));
await platform.IdentifyAsync(user.Id, Platform.SessionId(HttpContext));
await platform.IdentifyAsync(user.Id, Platform.SessionId(HttpContext), new { plan = "pro", seats = 5, trial = false }); // with traits
```

`Platform.SessionId` reads the `X-Analytics-Session` header the tracker sends
with your own requests, which ties the event to the visit.

`IdentifyAsync`'s optional traits (an object or an `IDictionary<string, object?>`)
are name to text, a number or a bool; other values are left out (and so is
`traits` when nothing is left). The collector does the rest: names are
lowercased with spaces and dashes as `_` (up to 40 letters, digits and `_`),
text is cut at 200 characters, values that look like an email address are
dropped, and at most 20 are kept.

## Ad blockers

With the proxy on, put the tracker on your own domain:

```cshtml
@inject SiteGoose.Platform Platform
<script async src="@Platform.Proxy?.ScriptUrl()" data-siteid="your site ID" data-domain="example.com"
        data-collect="@Platform.Proxy?.CollectUrl()"></script>
```

Beacons are answered before the firewall's page rules, but an address the
site denied or banned is refused here too. The collector gets 2 seconds; when
it doesn't answer, the proxy leaves it alone for 30 seconds and answers at
once (the tracker treats a lost beacon as lost), and a tracker file it
doesn't have isn't asked for again for a minute.

## Tests

```sh
docker run --rm -v "$PWD/..:/src:ro" mcr.microsoft.com/dotnet/sdk:8.0 \
  sh -c "cp -r /src /work && cd /work/platform-dotnet && dotnet test test/SiteGoose.Tests -f net8.0"
```

The tests target net6.0 too, for the code only .NET 6 runs: leave out
`-f net8.0` where the ASP.NET Core 6 runtime is installed
(`dotnet-install.sh --runtime aspnetcore --channel 6.0`).

Run from `sdk/platform-dotnet`: the tests read the shared cases in `sdk/protocols`.
