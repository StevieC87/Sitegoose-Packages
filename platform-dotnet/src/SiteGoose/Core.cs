using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace SiteGoose;

/// <summary>What the collector answered.</summary>
internal sealed class CollectorResponse
{
    public CollectorResponse(int status, Dictionary<string, string> headers, byte[] body)
    {
        Status = status;
        Headers = headers;
        Body = body;
    }

    public int Status { get; }
    public Dictionary<string, string> Headers { get; }
    public byte[] Body { get; }
    public bool Ok => Status >= 200 && Status < 300;
    public JsonElement? Json() => J.Parse(Body);
    public string Text(int max = 300) => J.Clip(Encoding.UTF8.GetString(Body), max);
}

/// <summary>A feature flag from the dashboard.</summary>
internal sealed class Flag
{
    public bool On;
    public List<string> Users = new();
    public long? Rollout = 100;
}

/// <summary>Maintenance mode, as the switches carry it.</summary>
internal sealed class MaintenanceState
{
    public static readonly MaintenanceState Off = new();
    public bool On;
    public List<string>? Allow;
    public string Bypass = "";
    public string? Message;
}

/// <summary>Runs a job on the thread pool; the job returns the seconds until
/// its next run. A job that throws runs again a minute later: it never dies.</summary>
internal sealed class Periodic
{
    private readonly Func<Task<double>> job;
    private readonly double first;
    private readonly CancellationTokenSource stop = new();
    private readonly SemaphoreSlim wake = new(0, 1);
    private Task? loop;

    public Periodic(Func<Task<double>> job, double first)
    {
        this.job = job;
        this.first = first;
    }

    public bool Started => loop != null;

    internal Task? Loop => loop;

    public void Start()
    {
        if (loop != null || stop.IsCancellationRequested) return;
        loop = Task.Run(RunAsync);
    }

    private async Task RunAsync()
    {
        var wait = first;
        while (!stop.IsCancellationRequested)
        {
            try
            {
                // WaitAsync takes at most int.MaxValue milliseconds (about 24 days).
                var ms = double.IsNaN(wait) ? Core.Retry * 1000.0 : Math.Max(0, Math.Min(wait * 1000.0, int.MaxValue));
                var span = TimeSpan.FromMilliseconds(ms);
                await wake.WaitAsync(span, stop.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                return;
            }
            if (stop.IsCancellationRequested) return;
            try
            {
                wait = await job().ConfigureAwait(false);
            }
            catch (Exception)
            {
                wait = Core.Retry;
            }
        }
    }

    public void RunNow()
    {
        try
        {
            if (wake.CurrentCount == 0) wake.Release();
        }
        catch (SemaphoreFullException)
        {
        }
        catch (ObjectDisposedException)
        {
        }
    }

    /// <summary>Stops the job and waits (up to wait) for a run in progress.</summary>
    public async Task StopAsync(TimeSpan wait)
    {
        if (!stop.IsCancellationRequested) stop.Cancel();
        var running = loop;
        if (running != null) await Task.WhenAny(running, Task.Delay(wait)).ConfigureAwait(false);
    }
}

/// <summary>What every module shares: the site's credentials, sending to the
/// collector, logging, background jobs, and the dashboard's module switches
/// (Site settings -> Server, GET /events/platform/config about once a minute).
/// A module the dashboard turns off stays loaded but does nothing; until the
/// switches arrive, or when they can't be fetched, every loaded module stays
/// on. Sending never throws into the app.</summary>
internal sealed class Core
{
    public const string Version = "0.3.6";
    /// <summary>SendAsync's status for a body that couldn't be turned into JSON: dropped, never retried.</summary>
    public const int Unsendable = -1;
    public const int TimeoutSeconds = 5;
    public const int MinSync = 30;
    public const int Retry = 60;
    public const string SessionHeader = "x-analytics-session";

    private static readonly Regex SiteIdPattern = new("^[a-fA-F0-9]{24}\\z", RegexOptions.CultureInvariant);
    /// <summary>The nine headers the dashboard can produce (expresscollect/Analytics/platform.js,
    /// headersOf), in any case. A list of what's allowed, not of what isn't: whoever got into our
    /// servers still couldn't make this app grant another site its users' data
    /// (Access-Control-Allow-*), send every page elsewhere (Refresh), log everyone out
    /// (Clear-Site-Data) or change what a response is. Shared cases: sdk/protocols/header-cases.json.</summary>
    internal static readonly HashSet<string> SecurityHeaderNames = new(StringComparer.OrdinalIgnoreCase)
    {
        "Strict-Transport-Security", "X-Content-Type-Options", "X-Frame-Options", "Referrer-Policy", "Permissions-Policy",
        "Cross-Origin-Opener-Policy", "Content-Security-Policy", "Content-Security-Policy-Report-Only", "Reporting-Endpoints",
    };
    private static HttpClient? shared;
    private static HttpClient? sharedFollow;

    private readonly DateTime started = DateTime.UtcNow;
    private readonly List<Periodic> jobs = new();
    private bool jobsStarted;
    private Dictionary<string, bool> switches = new();
    private List<KeyValuePair<string, string>> headers = new();
    private Dictionary<string, Flag> flags = new();
    private MaintenanceState maintenance = MaintenanceState.Off;
    private string etag = "";
    private List<string> loaded = new();

    public Core(string? siteId, string? secret, string? endpoint, bool debug = false, string? serverName = null, HttpMessageHandler? handler = null)
    {
        SiteId = siteId ?? "";
        Secret = secret ?? "";
        Endpoint = (endpoint ?? "").TrimEnd('/');
        Debug = debug;
        // The name this service checks in under (X-Platform-App): ServerName,
        // as every module sends it, else the machine's.
        ServerName = J.Clip(string.IsNullOrEmpty(serverName) ? HostName() : serverName, 100);
        Valid = SiteIdPattern.IsMatch(SiteId) && Secret.Length > 0 && Endpoint.Length > 0;
        UserAgent = "analytics-platform-dotnet/" + Version;
        if (handler != null)
        {
            Http = new HttpClient(handler, false) { Timeout = TimeSpan.FromSeconds(TimeoutSeconds) };
            HttpFollow = Http;
        }
        else
        {
            Http = shared ??= MakeClient(false);
            HttpFollow = sharedFollow ??= MakeClient(true);
        }
    }

    public string SiteId { get; }
    public string Secret { get; }
    public string Endpoint { get; }
    public string ServerName { get; }
    public string UserAgent { get; }
    public bool Valid { get; }
    public bool Debug { get; }

    /// <summary>For the collector's own answers: no redirects, no cookies.</summary>
    public HttpClient Http { get; }

    /// <summary>For tracker files, which may be redirected: still no cookies.</summary>
    public HttpClient HttpFollow { get; }

    /// <summary>The runtime as the dashboard shows it: ".NET 8.0.11".</summary>
    public static string Runtime => ".NET " + RuntimeVersion;

    public static string RuntimeVersion => Environment.Version.ToString();

    private static HttpClient MakeClient(bool follow)
    {
        var handler = new SocketsHttpHandler
        {
            UseCookies = false,
            AllowAutoRedirect = follow,
            MaxAutomaticRedirections = 3,
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
            ConnectTimeout = TimeSpan.FromSeconds(TimeoutSeconds),
            AutomaticDecompression = DecompressionMethods.None,
            UseProxy = true,
        };
        return new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(TimeoutSeconds) };
    }

    public static string HostName()
    {
        try
        {
            var name = Dns.GetHostName();
            if (!string.IsNullOrEmpty(name)) return name;
        }
        catch (Exception)
        {
        }
        return Environment.MachineName ?? "";
    }

    public void Log(string module, string message)
    {
        if (Debug) Console.WriteLine("[analytics-platform:" + module + "] " + message);
    }

    /// <summary>JSON to the collector. auth "body" puts site_id and sitesecret in
    /// the body (the event endpoints), "bearer" sends the secret as a header
    /// (firewall, switches, inventory, posture, resources). Null when it couldn't be sent.</summary>
    public async Task<CollectorResponse?> SendAsync(string module, string path, string method = "POST",
        Dictionary<string, object?>? body = null, string auth = "body", IDictionary<string, string>? extra = null,
        CancellationToken cancel = default)
    {
        if (!Valid) return null;
        string? json = null;
        if (body != null)
        {
            if (auth == "body")
            {
                body = new Dictionary<string, object?>(body) { ["site_id"] = SiteId, ["sitesecret"] = Secret };
            }
            try
            {
                json = J.Serialize(body);
            }
            catch (Exception error)
            {
                // Not the collector's fault: sending it again can't help.
                Log(module, "could not be sent, not JSON (" + path + "): " + error.Message);
                return new CollectorResponse(Unsendable, new Dictionary<string, string>(), Array.Empty<byte>());
            }
        }
        try
        {
            using var request = new HttpRequestMessage(new HttpMethod(method), Endpoint + path);
            request.Headers.TryAddWithoutValidation("User-Agent", UserAgent);
            if (json != null) request.Content = new StringContent(json, Encoding.UTF8, "application/json");
            if (auth == "bearer") request.Headers.TryAddWithoutValidation("Authorization", "Bearer " + Secret);
            if (extra != null)
            {
                foreach (var pair in extra) request.Headers.TryAddWithoutValidation(pair.Key, pair.Value);
            }
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancel);
            timeout.CancelAfter(TimeSpan.FromSeconds(TimeoutSeconds));
            using var res = await Http.SendAsync(request, HttpCompletionOption.ResponseContentRead, timeout.Token).ConfigureAwait(false);
            var bytes = await res.Content.ReadAsByteArrayAsync(timeout.Token).ConfigureAwait(false);
            var status = (int)res.StatusCode;
            if ((status < 200 || status >= 300) && status != 304) Log(module, "collector answered " + status + " to " + path);
            return new CollectorResponse(status, HeadersOf(res), bytes);
        }
        catch (Exception error)
        {
            Log(module, "could not reach the collector (" + path + "): " + error.Message);
            return null;
        }
    }

    public static Dictionary<string, string> HeadersOf(HttpResponseMessage res)
    {
        var all = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var pair in res.Headers) all[pair.Key] = string.Join(", ", pair.Value);
        foreach (var pair in res.Content.Headers) all[pair.Key] = string.Join(", ", pair.Value);
        return all;
    }

    // ---- Background jobs ----

    /// <summary>A job of a module: started with the others when the platform starts.</summary>
    public Periodic Every(Func<Task<double>> job, double first = 0)
    {
        var periodic = new Periodic(job, first);
        lock (jobs)
        {
            jobs.Add(periodic);
            if (jobsStarted) periodic.Start();
        }
        return periodic;
    }

    public async Task StopJobsAsync(TimeSpan wait)
    {
        Periodic[] all;
        lock (jobs) all = jobs.ToArray();
        await Task.WhenAll(all.Select(job => job.StopAsync(wait))).ConfigureAwait(false);
    }

    // ---- Module switches ----

    /// <summary>False only when the dashboard turned the module off.</summary>
    public bool IsOn(string name) => !switches.TryGetValue(name, out var on) || on;

    public Dictionary<string, Flag> Flags => flags;

    public MaintenanceState Maintenance => maintenance;

    /// <summary>The security headers picked on the dashboard, when the module is on.</summary>
    public List<KeyValuePair<string, string>> SecurityHeaders() => IsOn("headers") ? headers : new List<KeyValuePair<string, string>>();

    /// <summary>This service's check-in, form-encoded so any name is plain ASCII:
    /// Health -> All systems shows it running and when it was last heard from.
    /// Null when it can't be built: the switches still sync, without it.</summary>
    public string? CheckIn()
    {
        try
        {
            if (string.IsNullOrEmpty(ServerName)) return null;
            var fields = new List<KeyValuePair<string, string>>
            {
                new("server", ServerName),
                new("kind", "process"),
                new("pid", Environment.ProcessId.ToString()),
                new("up_s", ((long)(DateTime.UtcNow - started).TotalSeconds).ToString()),
                new("runtime", Runtime),
            };
            var rss = RssMb();
            if (rss != null) fields.Insert(4, new KeyValuePair<string, string>("rss_mb", rss.Value.ToString()));
            return string.Join("&", fields.Select(p => Uri.EscapeDataString(p.Key) + "=" + Uri.EscapeDataString(p.Value)));
        }
        catch (Exception)
        {
            return null;
        }
    }

    public static long? RssMb()
    {
        try
        {
            using var self = Process.GetCurrentProcess();
            return (long)Math.Round(self.WorkingSet64 / 1048576.0);
        }
        catch (Exception)
        {
            return null;
        }
    }

    internal async Task<double> SyncSwitchesAsync()
    {
        var extra = new Dictionary<string, string> { ["X-Platform-Modules"] = string.Join(",", loaded) };
        var app = CheckIn();
        if (app != null) extra["X-Platform-App"] = app;
        if (etag.Length > 0) extra["If-None-Match"] = etag;
        var res = await SendAsync("core", "/events/platform/config?site_id=" + SiteId, "GET", null, "bearer", extra).ConfigureAwait(false);
        if (res != null && res.Status == 200)
        {
            var data = res.Json();
            if (J.Int(J.Prop(data, "v")) == 1 && J.Prop(data, "modules") is { ValueKind: JsonValueKind.Object } modules)
            {
                var next = new Dictionary<string, bool>();
                foreach (var module in modules.EnumerateObject()) next[module.Name] = module.Value.ValueKind != JsonValueKind.False;
                flags = ParseFlags(J.Prop(data, "flags"));
                maintenance = ParseMaintenance(J.Prop(data, "maintenance"));
                headers = ParseHeaders(J.Prop(data, "headers"));
                switches = next;
                etag = res.Headers.TryGetValue("etag", out var tag) ? tag : "";
            }
            return Math.Max(MinSync, J.Int(J.Prop(data, "sync"), Retry));
        }
        return Retry;
    }

    internal static Dictionary<string, Flag> ParseFlags(JsonElement? data)
    {
        var flags = new Dictionary<string, Flag>();
        if (data is not { ValueKind: JsonValueKind.Object } all) return flags;
        foreach (var entry in all.EnumerateObject())
        {
            if (entry.Value.ValueKind != JsonValueKind.Object) continue;
            var flag = new Flag { On = J.Truthy(J.Prop(entry.Value, "on")) };
            if (J.Prop(entry.Value, "users") is { ValueKind: JsonValueKind.Array } users)
            {
                foreach (var user in users.EnumerateArray())
                {
                    flag.Users.Add(user.ValueKind == JsonValueKind.String ? user.GetString() ?? "" : user.GetRawText());
                }
            }
            var rollout = J.Prop(entry.Value, "rollout");
            if (rollout is { ValueKind: JsonValueKind.Null }) flag.Rollout = null;
            else if (rollout != null) flag.Rollout = J.IsNumber(rollout) || rollout.Value.ValueKind == JsonValueKind.String ? J.Int(rollout, 0) : null;
            flags[entry.Name] = flag;
        }
        return flags;
    }

    internal static MaintenanceState ParseMaintenance(JsonElement? data)
    {
        if (data is not { ValueKind: JsonValueKind.Object }) return MaintenanceState.Off;
        return new MaintenanceState
        {
            On = J.Truthy(J.Prop(data, "on")),
            Allow = J.IsArray(J.Prop(data, "allow")) ? J.Strings(J.Prop(data, "allow")) : null,
            Bypass = J.Str(J.Prop(data, "bypass")) ?? "",
            Message = J.Str(J.Prop(data, "message")),
        };
    }

    /// <summary>Only well-formed headers (no line breaks can get through).</summary>
    internal static List<KeyValuePair<string, string>> ParseHeaders(JsonElement? data)
    {
        var list = new List<KeyValuePair<string, string>>();
        if (data is not { ValueKind: JsonValueKind.Array } all) return list;
        foreach (var pair in all.EnumerateArray())
        {
            if (pair.ValueKind != JsonValueKind.Array || pair.GetArrayLength() != 2) continue;
            var name = pair[0];
            var value = pair[1];
            if (name.ValueKind != JsonValueKind.String || value.ValueKind != JsonValueKind.String) continue;
            var n = name.GetString() ?? "";
            var v = value.GetString() ?? "";
            if (!SafeHeader(n, v)) continue;
            list.Add(new KeyValuePair<string, string>(n, v));
        }
        return list;
    }

    /// <summary>One of SecurityHeaderNames, with a value of visible ASCII, spaces and tabs, at most
    /// 4,000 characters: a control character or one outside ASCII is refused by the server, and
    /// would cost the response its headers.</summary>
    internal static bool SafeHeader(string name, string value) =>
        SecurityHeaderNames.Contains(name) && value.Length <= 4000 && value.All(c => c == '\t' || (c >= 0x20 && c <= 0x7e));

    /// <summary>Starts fetching the switches and every module's jobs; names are the modules the code loaded.</summary>
    public void Start(IEnumerable<string> names)
    {
        lock (jobs)
        {
            if (jobsStarted) return;
            loaded = names.ToList();
            if (Valid) Every(SyncSwitchesAsync);
            jobsStarted = true;
            foreach (var job in jobs) job.Start();
        }
    }

    // ---- Request targets ----

    /// <summary>The request target as the visitor sent it, query string and
    /// all, which is what the request rules match (sdk/protocols/firewall.md).
    /// raw: the server's own copy of it (Kestrel's and IIS's RawTarget).
    /// Otherwise the path the framework has already decoded is encoded again,
    /// so the rules' one decoding pass is the only one.</summary>
    public static string RequestTarget(string? path, string? query = null, string? raw = null)
    {
        string target;
        if (!string.IsNullOrEmpty(raw))
        {
            target = OriginForm(raw!);
        }
        else
        {
            target = EncodePath(path ?? "");
        }
        if (!string.IsNullOrEmpty(query))
        {
            var q = query!.StartsWith("?", StringComparison.Ordinal) ? query.Substring(1) : query;
            if (q.Length > 0 && !target.Contains('?')) target += "?" + q;
        }
        return target;
    }

    private static readonly Regex Scheme = new("^[a-zA-Z][a-zA-Z0-9+.-]*:", RegexOptions.CultureInvariant);

    /// <summary>A request line's target in origin form, as a server's URL
    /// parser reads it (firewall.md, 'Matching'): an absolute-form target
    /// (a request through a forward proxy, or anything else a server takes)
    /// loses its scheme and, after a "//", its authority, so "http://h/admin"
    /// and "x:/admin" are both "/admin". "*" (OPTIONS *) stays as it is.</summary>
    internal static string OriginForm(string target)
    {
        if (target.Length == 0 || target[0] == '/' || target == "*") return target;
        var scheme = Scheme.Match(target);
        var rest = scheme.Success ? target.Substring(scheme.Length) : target;
        if (rest.StartsWith("//", StringComparison.Ordinal))
        {
            var end = rest.IndexOfAny(new[] { '/', '?', '#' }, 2);
            rest = end < 0 ? "" : rest.Substring(end);
        }
        return rest.StartsWith("/", StringComparison.Ordinal) ? rest : "/" + rest;
    }

    // The characters a path may carry unencoded (RFC 3986), which Python's quote() leaves alone.
    private const string PathSafe = "/:@!$&'()*+,;=-._~";

    public static string EncodePath(string path)
    {
        var builder = new StringBuilder(path.Length + 8);
        foreach (var b in Encoding.UTF8.GetBytes(path))
        {
            var c = (char)b;
            if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || (b < 128 && PathSafe.IndexOf(c) >= 0))
            {
                builder.Append(c);
            }
            else
            {
                builder.Append('%').Append(b.ToString("X2"));
            }
        }
        return builder.ToString();
    }

    public static string OsName()
    {
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) return "windows";
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux)) return "linux";
        if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX)) return "darwin";
        if (RuntimeInformation.IsOSPlatform(OSPlatform.FreeBSD)) return "freebsd";
        return "unknown";
    }
}
