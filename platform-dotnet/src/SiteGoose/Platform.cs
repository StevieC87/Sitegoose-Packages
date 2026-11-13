using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;

namespace SiteGoose;

/// <summary>One package for a site's ASP.NET Core server, run from the
/// analytics dashboard: firewall, error monitoring and server analytics. Each
/// module is separate: only the ones turned on are loaded, and one failing
/// never stops the others; the firewall in particular never waits on
/// reporting. A loaded module can also be switched off in the dashboard (Site
/// settings -> Server).
///
///     builder.Services.AddSiteGoose();   // the middleware goes first by itself
///
/// Options from "SiteGoose" in appsettings.json, else ANALYTICS_SITE_ID,
/// ANALYTICS_SITE_SECRET and ANALYTICS_ENDPOINT in the environment.
///
/// Inject Platform wherever you track, identify or check a form.</summary>
public sealed class Platform
{
    public static readonly string[] ModuleNames =
    {
        "proxy", "firewall", "errors", "analytics", "performance", "crawlers", "forms", "headers", "audit", "flags", "maintenance", "inventory", "posture", "resources",
    };

    private readonly Dictionary<string, object> modules = new(StringComparer.Ordinal);
    private readonly Queries? queries;
    private readonly Queries? calls;
    private readonly Queues? queues;
    private bool started;

    public Platform(PlatformOptions options) : this(options, null, null, null)
    {
    }

    internal Platform(PlatformOptions options, IEnumerable<PostureRoot>? webRoots, Func<IEnumerable<PostureCheck>>? frameworkChecks, PlatformHolder? holder)
    {
        Options = options ?? new PlatformOptions();
        Options.FillFromEnvironment();
        Core = new Core(Options.SiteId, Options.Secret, Options.Endpoint, Options.Debug, Options.ServerName, Options.Handler);
        if (!Core.Valid) Console.WriteLine("[analytics-platform] SiteId, Secret and Endpoint are required; nothing is sent and every request passes");
        var serverName = string.IsNullOrEmpty(Options.ServerName) ? null : Options.ServerName;
        foreach (var name in ModuleNames)
        {
            try
            {
                object? module = name switch
                {
                    "proxy" when Options.Proxy.Enabled => new Proxy(Core, Options.Proxy.Prefix),
                    "firewall" when Options.Firewall.Enabled => new Firewall(Core, Options.TrustProxy, Options.ClientIp, Options.Firewall.Mode, Options.Firewall.Counter, Options.Firewall.CacheFile),
                    "errors" when Options.Errors.Enabled => new Errors(Core, Options.Errors.ServerName ?? serverName, Options.Errors.Root, Options.Errors.Release,
                        Options.Errors.CaptureUncaught, Options.Errors.BeforeSend, Options.Errors.CaptureLogging, Options.Errors.SpoolDir),
                    "analytics" when Options.Analytics.Enabled => new Analytics(Core),
                    "performance" when Options.Performance.Enabled => new Performance(Core, Options.Performance.ServerName ?? serverName),
                    "crawlers" when Options.Crawlers.Enabled => new Crawlers(Core, Options.Crawlers.ServerName ?? serverName),
                    "forms" when Options.Forms.Enabled => new Forms(Core),
                    "headers" when Options.Headers.Enabled => new object(),
                    "audit" when Options.Audit.Enabled => new Audit(Core),
                    "flags" when Options.Flags.Enabled => new Flags(Core),
                    "maintenance" when Options.Maintenance.Enabled => new Maintenance(Core, Options.Maintenance.Skip),
                    // Inventory and posture call it host, and are stored one per site
                    // and host: without it two services on one machine overwrite each other's.
                    "inventory" when Options.Inventory.Enabled => new Inventory(Core, Options.Inventory.Host ?? serverName, Options.Inventory.DepsFile),
                    "posture" when Options.Posture.Enabled => new Posture(Core, Options.Posture.Roots, Options.Posture.Host ?? serverName, Options.Posture.Checks, frameworkChecks, webRoots),
                    "resources" when Options.Resources.Enabled => new Resources(Core, Options.Resources.ServerName ?? serverName),
                    _ => null,
                };
                if (module != null) modules[name] = module;
            }
            catch (Exception error)
            {
                Console.WriteLine("[analytics-platform] the " + name + " module could not start and is off: " + error.Message);
            }
        }
        // Database queries ride on Server speed: its switch, its routes.
        if (PerformanceModule is { } performance && Options.Performance.Queries)
        {
            try
            {
                queries = new Queries(Core, performance);
            }
            catch (Exception error)
            {
                Console.WriteLine("[analytics-platform] database queries could not be timed: " + error.Message);
            }
        }
        // Outgoing calls and job queues too.
        if (PerformanceModule is { } timed && Options.Performance.Calls)
        {
            try
            {
                calls = new Queries(Core, timed, Queries.CallKind);
            }
            catch (Exception error)
            {
                Console.WriteLine("[analytics-platform] outgoing calls could not be timed: " + error.Message);
            }
        }
        if (PerformanceModule is { } read && Options.Performance.Queues)
        {
            try
            {
                queues = new Queues(Core, read);
            }
            catch (Exception error)
            {
                Console.WriteLine("[analytics-platform] job queues could not be read: " + error.Message);
            }
        }
        // Requests in progress at once, from Server speed's own timing.
        if (ResourcesModule is { } resources && PerformanceModule is { } inflight) resources.InflightPeak = inflight.TakeInflightPeak;
        if (holder != null) holder.Errors = ErrorsModule;
    }

    /// <summary>A platform with its background work started.</summary>
    public static Platform Create(PlatformOptions options)
    {
        var platform = new Platform(options);
        platform.Start();
        return platform;
    }

    internal PlatformOptions Options { get; }
    internal Core Core { get; }

    /// <summary>The modules that are on.</summary>
    public IReadOnlyList<string> Modules => modules.Keys.ToList();

    internal Firewall? FirewallModule => modules.TryGetValue("firewall", out var m) ? (Firewall)m : null;
    internal Errors? ErrorsModule => modules.TryGetValue("errors", out var m) ? (Errors)m : null;
    internal Analytics? AnalyticsModule => modules.TryGetValue("analytics", out var m) ? (Analytics)m : null;
    internal Performance? PerformanceModule => modules.TryGetValue("performance", out var m) ? (Performance)m : null;
    internal Crawlers? CrawlersModule => modules.TryGetValue("crawlers", out var m) ? (Crawlers)m : null;
    internal Forms? FormsModule => modules.TryGetValue("forms", out var m) ? (Forms)m : null;
    internal Audit? AuditModule => modules.TryGetValue("audit", out var m) ? (Audit)m : null;
    internal Flags? FlagsModule => modules.TryGetValue("flags", out var m) ? (Flags)m : null;
    internal Maintenance? MaintenanceModule => modules.TryGetValue("maintenance", out var m) ? (Maintenance)m : null;
    internal Inventory? InventoryModule => modules.TryGetValue("inventory", out var m) ? (Inventory)m : null;
    internal Posture? PostureModule => modules.TryGetValue("posture", out var m) ? (Posture)m : null;
    internal Resources? ResourcesModule => modules.TryGetValue("resources", out var m) ? (Resources)m : null;
    internal Queries? QueriesModule => queries;
    internal Queries? CallsModule => calls;
    internal Queues? QueuesModule => queues;

    /// <summary>The first-party proxy: Proxy.ScriptUrl() and Proxy.CollectUrl()
    /// are the two addresses the page's script tag needs, on this site's own
    /// domain, so ad blockers have nothing of ours to recognise.</summary>
    public Proxy? Proxy => modules.TryGetValue("proxy", out var m) ? (Proxy)m : null;

    /// <summary>Whether a request reached this app over HTTPS (for the posture's cookie checks).</summary>
    internal volatile bool SawHttps;
    internal volatile bool SawHttpsDirect;

    /// <summary>Starts the background work (the hosted service does it for you).</summary>
    public void Start()
    {
        if (started) return;
        started = true;
        Core.Start(modules.Keys);
    }

    // ---- Errors ----

    /// <summary>An error you caught. context: the request it came from (default:
    /// the one being handled); status: the HTTP status it ended in, if any.</summary>
    public void CaptureException(Exception error, int status = 0, HttpContext? context = null)
    {
        ErrorsModule?.CaptureException(error, context == null ? null : FieldsOf(context), status, "handled");
    }

    internal void CaptureException(Exception error, RequestFields? request, int status, string kind)
    {
        ErrorsModule?.CaptureException(error, request, status, kind);
    }

    /// <summary>A step of your own in the trail shown before an error in this request or job.</summary>
    public void AddBreadcrumb(string text)
    {
        if (ErrorsModule != null) Errors.AddBreadcrumb(text);
    }

    internal static RequestFields FieldsOf(HttpContext context, string route = "") => new()
    {
        Method = context.Request.Method,
        Path = context.Request.PathBase.Add(context.Request.Path).Value ?? "",
        Route = route,
        SessionId = SessionId(context),
    };

    // ---- Jobs ----

    /// <summary>A background job (a queue consumer, a hosted service's loop, a
    /// Hangfire or Quartz job): its errors are sent with "/(job) name" as their
    /// route, and each run is timed (Health -> Server speed -> Jobs); a run that
    /// throws counts as failed, and the exception is thrown on. A cancelled run
    /// isn't timed or sent.</summary>
    public async Task RunJobAsync(string name, Func<Task> work)
    {
        var run = new JobRun(this, name);
        using (run.Enter())
        {
            try
            {
                await work().ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception error)
            {
                run.Failed(error);
                throw;
            }
            run.Done();
        }
    }

    public async Task<T> RunJobAsync<T>(string name, Func<Task<T>> work)
    {
        var result = default(T)!;
        await RunJobAsync(name, async () => result = await work().ConfigureAwait(false)).ConfigureAwait(false);
        return result;
    }

    public void RunJob(string name, Action work)
    {
        var run = new JobRun(this, name);
        using (run.Enter())
        {
            try
            {
                work();
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception error)
            {
                run.Failed(error);
                throw;
            }
            run.Done();
        }
    }

    private sealed class JobRun
    {
        private readonly Platform platform;
        private readonly string route;
        private readonly long started = Stopwatch.GetTimestamp();

        public JobRun(Platform platform, string name)
        {
            this.platform = platform;
            route = "/(job) " + J.Clip(string.IsNullOrEmpty(name) ? "job" : name, 180);
        }

        private RequestFields Fields() => new() { Method = "JOB", Path = route, Route = route };

        public IDisposable Enter() => Scope.Enter(new Scope(Fields));

        /// <summary>Sent (still inside the run, so the error keeps its trail) and timed as failed.</summary>
        public void Failed(Exception error)
        {
            platform.CaptureException(error, Fields(), 500, "error");
            platform.TimeRequest("JOB", route, 500, started, route);
        }

        public void Done() => platform.TimeRequest("JOB", route, 200, started, route);
    }

    // ---- Firewall ----

    /// <summary>A failed login (bot protection): the visitor's address, as TrustProxy says.</summary>
    public void LoginFailed(HttpContext context) => LoginFailed(RequestIp(context));

    public void LoginFailed(string ip)
    {
        if (!string.IsNullOrEmpty(ip)) FirewallModule?.LoginFailed(ip);
    }

    /// <summary>The visitor's address for a request.</summary>
    public string RequestIp(HttpContext context) => ClientIp(RemoteOf(context), HeaderReader(context));

    /// <summary>The connection's address. As the request arrived, before a
    /// ForwardedHeadersMiddleware rewrote it, unless TrustProxy is
    /// "aspnetcore" (then as that middleware left it).</summary>
    /// <summary>TrustProxy "aspnetcore": the address ForwardedHeadersMiddleware
    /// settled on, so the middleware has to run after it (UseSiteGoose).</summary>
    internal bool TrustsAspNetCore => string.Equals((Options.TrustProxy ?? "").Trim(), "aspnetcore", StringComparison.OrdinalIgnoreCase);

    internal string RemoteOf(HttpContext context)
    {
        if (!TrustsAspNetCore &&
            context.Items.TryGetValue(Arrival.Item, out var seen) && seen is Arrival arrival)
        {
            return arrival.Remote;
        }
        return Ip.Display(context.Connection.RemoteIpAddress);
    }

    internal static Func<string, string> HeaderReader(HttpContext context)
    {
        var arrival = context.Items.TryGetValue(Arrival.Item, out var seen) ? seen as Arrival : null;
        return name =>
        {
            // X-Forwarded-For as it arrived: ForwardedHeadersMiddleware takes
            // the entries it believes off the end, which would leave only the
            // ones the visitor wrote.
            if (arrival != null && string.Equals(name, "x-forwarded-for", StringComparison.OrdinalIgnoreCase)) return arrival.ForwardedFor;
            var values = context.Request.Headers[name];
            // HTTP/2 may split cookies over several fields (RFC 9113 8.2.3).
            return string.Equals(name, "cookie", StringComparison.OrdinalIgnoreCase) ? string.Join("; ", values.ToArray()) : values.ToString();
        };
    }

    internal string ClientIp(string remote, Func<string, string> header)
    {
        var firewall = FirewallModule;
        return firewall != null ? firewall.ClientIp(remote, header) : Firewall.ResolveClientIp(remote, header, Options.TrustProxy, Options.ClientIp);
    }

    /// <summary>The answer when the firewall turns the request away, else null.
    /// target: the request target as sent, query string and all, not yet decoded.</summary>
    internal Answer? Blocked(string remote, Func<string, string> header, string method, string target) => Blocked(remote, header, method, target, out _);

    /// <summary>late: a static-looking request let through, for
    /// Firewall.CountStatic after the response (firewall.md, `rate`).</summary>
    internal Answer? Blocked(string remote, Func<string, string> header, string method, string target, out LateHit? late)
    {
        late = null;
        var firewall = FirewallModule;
        if (firewall == null) return null;
        FirewallDecision decision;
        try
        {
            var ip = firewall.ClientIp(remote, header);
            decision = firewall.Check(ip, method, target, header("user-agent"), header("accept"), header("cookie"));
            if (decision.Action == "block" && decision.Rule == "challenge") return firewall.ChallengePage(ip, method);
            if (decision.Action != "block") late = decision.Late;
        }
        catch (Exception error)
        {
            Core.Log("firewall", "check failed, request passed: " + error.Message);
            return null;
        }
        if (decision.Action != "block") return null;
        var headers = new List<KeyValuePair<string, string>> { new("Content-Type", "text/plain; charset=utf-8"), new("Cache-Control", "no-store") };
        if (decision.Status == 429)
        {
            headers.Add(new KeyValuePair<string, string>("Retry-After", firewall.RetryAfter(decision)));
            // A page limit is someone at one page too often, often a person (a
            // shopper refreshing checkout): the body tells them what to do.
            var text = decision.Rule.StartsWith("limit:", StringComparison.Ordinal) ? Firewall.LimitBody : "Too Many Requests";
            return new Answer(429, headers, System.Text.Encoding.UTF8.GetBytes(text));
        }
        return new Answer(403, headers, System.Text.Encoding.UTF8.GetBytes("Forbidden"));
    }

    // ---- Maintenance, flags, headers ----

    /// <summary>A feature flag from the dashboard (user: for rollouts and user
    /// lists; fallback: until the flag is known, or with the module off).</summary>
    public bool IsEnabled(string key, string? user = null, bool fallback = false) => FlagsModule?.IsEnabled(key, user, fallback) ?? fallback;

    internal MaintenanceDecision? MaintenanceResponse(string remote, Func<string, string> header, string path, string? query)
    {
        var maintenance = MaintenanceModule;
        if (maintenance == null) return null;
        try
        {
            return maintenance.Decide(ClientIp(remote, header), path, query, header("cookie"));
        }
        catch (Exception error)
        {
            Core.Log("maintenance", "check failed, request passed: " + error.Message);
            return null;
        }
    }

    /// <summary>The dashboard's security headers the response doesn't set itself.</summary>
    public List<KeyValuePair<string, string>> SecurityHeaders(IEnumerable<string>? present = null)
    {
        if (!modules.ContainsKey("headers")) return new List<KeyValuePair<string, string>>();
        var have = new HashSet<string>((present ?? Array.Empty<string>()).Select(n => n.ToLowerInvariant()));
        return Core.SecurityHeaders().Where(p => !have.Contains(p.Key.ToLowerInvariant())).ToList();
    }

    // ---- Audit and forms ----

    /// <summary>Records who did what (Security -> Audit log). action: e.g.
    /// "user.role_changed"; context adds the actor's address and visit.</summary>
    public void Audit(string action, string? actor = "", string? target = "", object? details = null, HttpContext? context = null)
    {
        var audit = AuditModule;
        if (audit == null) return;
        try
        {
            audit.Record(action, actor, target, details, context == null ? "" : RequestIp(context), context == null ? "" : SessionId(context));
        }
        catch (Exception error)
        {
            Core.Log("audit", "could not record: " + error.Message);
        }
    }

    /// <summary>Form protection: checks a form before you accept it. The form is
    /// the request's (context), or pass fields. Spam goes to Leads -> Spam.</summary>
    public async Task<FormCheck> CheckFormAsync(HttpContext? context = null, IDictionary<string, string>? fields = null, string? email = null, string? name = null, string? form = null)
    {
        var forms = FormsModule;
        if (forms == null) return new FormCheck();
        try
        {
            IEnumerable<KeyValuePair<string, string[]>> all;
            if (fields != null)
            {
                all = fields.Select(p => new KeyValuePair<string, string[]>(p.Key, new[] { p.Value }));
            }
            else if (context != null && context.Request.HasFormContentType)
            {
                var read = await context.Request.ReadFormAsync().ConfigureAwait(false);
                all = read.Select(p => new KeyValuePair<string, string[]>(p.Key, p.Value.Where(v => v != null).Select(v => v!).ToArray())).ToList();
            }
            else
            {
                all = Array.Empty<KeyValuePair<string, string[]>>();
            }
            return await forms.CheckAsync(all, context == null ? "" : RequestIp(context), email, name, form).ConfigureAwait(false);
        }
        catch (Exception error)
        {
            Core.Log("forms", "could not check a form: " + error.Message);
            return new FormCheck { Reasons = new List<string> { "unchecked" } };
        }
    }

    // ---- Analytics ----

    /// <summary>A server event (a payment, a sign-up), sent in the background.
    /// Returns its event_uid, or "" when not queued.</summary>
    public string Track(string name, IDictionary<string, object?>? fields = null, string? sessionId = "") =>
        AnalyticsModule?.Track(name, fields, sessionId) ?? "";

    /// <summary>The same, with the fields as an object: new { numeric_value = "49.90", currency = "EUR" }.</summary>
    public string Track(string name, object fields, string? sessionId = "") => Track(name, ToDictionary(fields), sessionId);

    public Task<bool> IdentifyAsync(string userId, string? sessionId) => AnalyticsModule?.IdentifyAsync(userId, sessionId) ?? Task.FromResult(false);

    /// <summary>The same, with what you know about the user: traits, name to
    /// text, number or bool. Other values are left out.</summary>
    public Task<bool> IdentifyAsync(string userId, string? sessionId, IDictionary<string, object?>? traits) =>
        AnalyticsModule?.IdentifyAsync(userId, sessionId, traits) ?? Task.FromResult(false);

    /// <summary>The same, with the traits as an object: new { plan = "pro", seats = 5 },
    /// or any dictionary (a Dictionary&lt;string, string&gt; too).</summary>
    public Task<bool> IdentifyAsync(string userId, string? sessionId, object traits)
    {
        if (traits is System.Collections.IDictionary other && traits is not IDictionary<string, object?>)
        {
            var given = new Dictionary<string, object?>();
            foreach (System.Collections.DictionaryEntry pair in other) given[Convert.ToString(pair.Key, CultureInfo.InvariantCulture) ?? ""] = pair.Value;
            return IdentifyAsync(userId, sessionId, given);
        }
        return IdentifyAsync(userId, sessionId, ToDictionary(traits));
    }

    public Task<LeadResult?> LeadAsync(IDictionary<string, object?> fields, string? sessionId = "") =>
        AnalyticsModule?.LeadAsync(fields, sessionId) ?? Task.FromResult<LeadResult?>(null);

    public Task<LeadResult?> LeadAsync(object fields, string? sessionId = "") => LeadAsync(ToDictionary(fields), sessionId);

    internal static Dictionary<string, object?> ToDictionary(object? fields)
    {
        var output = new Dictionary<string, object?>();
        if (fields == null) return output;
        if (fields is IDictionary<string, object?> given)
        {
            foreach (var pair in given) output[pair.Key] = pair.Value;
            return output;
        }
        foreach (var property in fields.GetType().GetProperties(BindingFlags.Public | BindingFlags.Instance))
        {
            if (property.GetIndexParameters().Length == 0) output[property.Name] = property.GetValue(fields);
        }
        return output;
    }

    /// <summary>The browser's visit, from the X-Analytics-Session header the page sends.</summary>
    public static string SessionId(HttpContext? context) => context?.Request.Headers[Core.SessionHeader].ToString() ?? "";

    // ---- Server speed and crawlers ----

    /// <summary>Records a finished request for Server speed (started: Stopwatch.GetTimestamp()).</summary>
    public void TimeRequest(string method, string? route, int status, long started, string? path = "")
    {
        var performance = PerformanceModule;
        if (performance == null) return;
        try
        {
            var recorded = performance.Record(method, route, status, ElapsedMs(started), path);
            // The request's (or job's) queries, under the route it was just counted as.
            if (recorded is { } r)
            {
                queries?.Finish(Scope.Current, r.Method, r.Route);
                calls?.Finish(Scope.Current, r.Method, r.Route);
            }
        }
        catch (Exception error)
        {
            Core.Log("performance", "could not time a request: " + error.Message);
        }
    }

    /// <summary>A request Server speed doesn't time (a WebSocket, an event
    /// stream, a SignalR connection): no route row ever comes for it, so its
    /// queries and calls are background ones, from now on and what it already ran.</summary>
    internal void Untimed(Scope? scope)
    {
        try
        {
            queries?.Finish(scope, "JOB", Queries.Background);
            calls?.Finish(scope, "JOB", Queries.Background);
        }
        catch (Exception error)
        {
            Core.Log("performance", "could not file an untimed request's queries: " + error.Message);
        }
    }

    /// <summary>Records a finished request when it came from a crawler or AI bot (Health -> Crawlers).</summary>
    public void RecordCrawler(string? userAgent, string? path, int status, long? started = null, long size = 0, string? ip = "")
    {
        var crawlers = CrawlersModule;
        if (crawlers == null) return;
        try
        {
            crawlers.Middleware(userAgent, path, status, started == null ? 0 : ElapsedMs(started.Value), size, ip);
        }
        catch (Exception error)
        {
            Core.Log("crawlers", "could not count a crawler request: " + error.Message);
        }
    }

    /// <summary>MongoDB's queries for Server speed -> Queries: call it on the
    /// settings before the client is made (new MongoClient(platform.WatchMongo(settings))).
    /// Takes a MongoClientSettings, so the package needs no MongoDB reference;
    /// gives it back.</summary>
    public T WatchMongo<T>(T settings) where T : class
    {
        if (queries == null || settings == null) return settings!;
        try
        {
            var problem = MongoHook.Watch(settings);
            if (problem != null) Console.WriteLine("[analytics-platform] WatchMongo: " + problem);
        }
        catch (Exception error)
        {
            Console.WriteLine("[analytics-platform] WatchMongo: " + error.Message);
        }
        return settings;
    }

    /// <summary>Redis commands for Server speed -> Queries: once, with the
    /// multiplexer the app uses (platform.WatchRedis(ConnectionMultiplexer.Connect(...))).
    /// Takes a StackExchange.Redis IConnectionMultiplexer, so the package needs
    /// no StackExchange.Redis reference; gives it back. Each command is counted
    /// by its name only (StackExchange.Redis's profiler shows no key), never
    /// as failed (it shows no outcome), and it replaces a profiler the app
    /// registered on that multiplexer itself.</summary>
    public T WatchRedis<T>(T multiplexer) where T : class
    {
        if (queries == null || multiplexer == null) return multiplexer!;
        try
        {
            var problem = RedisHook.Watch(multiplexer);
            if (problem != null) Console.WriteLine("[analytics-platform] WatchRedis: " + problem);
        }
        catch (Exception error)
        {
            Console.WriteLine("[analytics-platform] WatchRedis: " + error.Message);
        }
        return multiplexer;
    }

    /// <summary>Hangfire's queues for Server speed -> Jobs, read once a minute:
    /// platform.WatchHangfire(JobStorage.Current), after UseXxxStorage. Takes
    /// the JobStorage as an object, so the package needs no Hangfire
    /// reference; gives it back. broker: where the jobs live, when the
    /// storage's own name for it (its ToString(), user and password taken out)
    /// isn't what you want shown.</summary>
    public T WatchHangfire<T>(T storage, string? broker = null) where T : class
    {
        if (queues == null || storage == null) return storage!;
        try
        {
            var problem = queues.Watch(storage, broker);
            if (problem != null) Console.WriteLine("[analytics-platform] WatchHangfire: " + problem);
        }
        catch (Exception error)
        {
            Console.WriteLine("[analytics-platform] WatchHangfire: " + error.Message);
        }
        return storage;
    }

    internal static double ElapsedMs(long started) => (Stopwatch.GetTimestamp() - started) * 1000.0 / Stopwatch.Frequency;

    // ---- Lifetime ----

    /// <summary>Sends everything waiting.</summary>
    public async Task FlushAsync()
    {
        foreach (var module in modules.Values.ToList())
        {
            try
            {
                switch (module)
                {
                    case Firewall m: await m.FlushAsync().ConfigureAwait(false); break;
                    case Errors m: await m.FlushAsync().ConfigureAwait(false); break;
                    case Analytics m: await m.FlushAsync().ConfigureAwait(false); break;
                    case Performance m: await m.FlushAsync().ConfigureAwait(false); break;
                    case Crawlers m: await m.FlushAsync().ConfigureAwait(false); break;
                    case Audit m: await m.FlushAsync().ConfigureAwait(false); break;
                    case Resources m: await m.FlushAsync().ConfigureAwait(false); break;
                }
            }
            catch (Exception error)
            {
                Core.Log("core", "flush failed: " + error.Message);
            }
        }
        foreach (var timed in new[] { queries, calls })
        {
            try
            {
                if (timed != null) await timed.FlushAsync().ConfigureAwait(false);
            }
            catch (Exception error)
            {
                Core.Log("core", "flush failed: " + error.Message);
            }
        }
    }

    /// <summary>Stops background work and sends what's waiting. Errors go
    /// first, with one try each (what can't be sent waits in the file); the
    /// rest gets what's left of the time cancel allows.</summary>
    public async Task CloseAsync(CancellationToken cancel = default)
    {
        var errors = ErrorsModule;
        if (errors != null)
        {
            try
            {
                await errors.CloseAsync(cancel).ConfigureAwait(false);
            }
            catch (Exception error)
            {
                Core.Log("errors", "close failed: " + error.Message);
            }
        }
        await Core.StopJobsAsync(TimeSpan.FromSeconds(cancel.CanBeCanceled ? 0.5 : 2)).ConfigureAwait(false);
        var closing = new List<Task>();
        foreach (var module in modules.Values.ToList())
        {
            try
            {
                switch (module)
                {
                    case Firewall m: closing.Add(Task.Run(m.CloseAsync)); break;
                    case Analytics m: closing.Add(Task.Run(m.CloseAsync)); break;
                    case Performance m: closing.Add(Task.Run(m.CloseAsync)); break;
                    case Crawlers m: closing.Add(Task.Run(m.CloseAsync)); break;
                    case Audit m: closing.Add(Task.Run(m.CloseAsync)); break;
                    case Resources m: closing.Add(Task.Run(m.CloseAsync)); break;
                }
            }
            catch (Exception error)
            {
                Core.Log("core", "close failed: " + error.Message);
            }
        }
        if (queries != null) closing.Add(Task.Run(queries.CloseAsync));
        if (calls != null) closing.Add(Task.Run(calls.CloseAsync));
        // Side by side, each on its own, so one slow module doesn't use up the others' time.
        var all = Task.WhenAll(closing);
        try
        {
            await Task.WhenAny(all, Task.Delay(Timeout.Infinite, cancel)).ConfigureAwait(false);
        }
        catch (Exception)
        {
        }
        if (!all.IsCompleted) Core.Log("core", "shutdown time ran out before everything was sent");
    }
}
