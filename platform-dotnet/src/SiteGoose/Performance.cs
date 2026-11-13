using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace SiteGoose;

/// <summary>Performance &amp; API monitoring module: times every request (from
/// arriving to the response being ready) and sends one row per minute, method,
/// route and status code (how many, total and slowest time, and a count per
/// time bucket) to POST /events/server-requests. Nothing about visitors is sent.
///
/// The route is the endpoint's route pattern when routing matched one
/// ("/api/orders/{id:int}", "/Home/Index/{id?}" for conventional MVC routes);
/// otherwise numbers and IDs in the path become ":id", and unmatched 404s are
/// one route.</summary>
internal sealed class Performance
{
    // Keep in step with the collector (expresscollect/Analytics/serverRequests.js).
    public static readonly int[] BucketEdgesMs = { 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000 };
    public const int FlushEvery = 60;
    public const int MaxKeys = 300;
    public const int MaxRows = 500;
    public const string NotFound = "/(not found)";
    public const int HardMaxKeys = 2000;

    // The method is the visitor's to choose: anything else is one row, "OTHER".
    private static readonly HashSet<string> Methods = new(StringComparer.Ordinal) { "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "JOB" };

    internal static string MethodOf(string? method)
    {
        var m = (string.IsNullOrEmpty(method) ? "GET" : method!).ToUpperInvariant();
        return Methods.Contains(m) ? m : "OTHER";
    }

    private static readonly Regex Id = new("^([0-9]+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{16,})$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
    private static readonly Regex Digit = new("[0-9]", RegexOptions.CultureInvariant);

    private sealed class Row
    {
        public long Count;
        public double SumMs;
        public double MaxMs;
        public readonly long[] Buckets = new long[BucketEdgesMs.Length + 1];
    }

    private readonly Core core;
    private readonly object gate = new();
    private Dictionary<(long Minute, string Method, string Route, int Status), Row> rows = new();

    public Performance(Core core, string? serverName = null)
    {
        this.core = core;
        ServerName = J.Clip(string.IsNullOrEmpty(serverName) ? Core.HostName() : serverName, 100);
        if (core.Valid)
        {
            core.Every(async () =>
            {
                await FlushAsync(false).ConfigureAwait(false);
                return FlushEvery;
            }, FlushEvery);
        }
    }

    public string ServerName { get; }
    public string Runtime => Core.Runtime;

    // Requests in progress now, and the most at once since the resources
    // module last asked. timed stays false until the middleware first runs,
    // so an app that never installed it reports no peak rather than 0.
    private readonly object inflightGate = new();
    private long inflight;
    private long peak;
    private bool timed;

    /// <summary>A request arriving at the middleware.</summary>
    internal void RequestStarted()
    {
        lock (inflightGate)
        {
            timed = true;
            inflight += 1;
            if (inflight > peak) peak = inflight;
        }
    }

    /// <summary>The same request done, answered or dropped.</summary>
    internal void RequestEnded()
    {
        lock (inflightGate)
        {
            if (inflight > 0) inflight -= 1;
        }
    }

    /// <summary>The most requests in progress at once since the last call,
    /// or null with the request timing off or never run. The peak starts
    /// again from what is still in progress.</summary>
    internal long? TakeInflightPeak()
    {
        if (!core.IsOn("performance")) return null;
        lock (inflightGate)
        {
            if (!timed) return null;
            var most = peak;
            peak = inflight;
            return most;
        }
    }

    /// <summary>"/orders/123/items/9f8e..." -> "/orders/:id/items/:id"</summary>
    public static string NormalizeRoute(string? path)
    {
        var p = path ?? "/";
        var cut = p.IndexOfAny(new[] { '?', '#' });
        if (cut >= 0) p = p.Substring(0, cut);
        if (p.Length == 0) p = "/";
        var parts = p.Split('/').Select(s => Id.IsMatch(s) || (s.Length >= 20 && Digit.IsMatch(s)) ? ":id" : s);
        var route = string.Join("/", parts);
        return J.Clip(route.StartsWith("/", StringComparison.Ordinal) ? route : "/" + route, 200);
    }

    /// <summary>The current minute's start, in Unix seconds.</summary>
    internal static long MinuteNow() => (long)Math.Floor(J.UnixNow() / 60) * 60;

    public static int BucketOf(double ms)
    {
        for (var i = 0; i < BucketEdgesMs.Length; i++)
        {
            if (ms <= BucketEdgesMs[i]) return i;
        }
        return BucketEdgesMs.Length;
    }

    /// <summary>One finished request. route: the endpoint's pattern, or "" to work it out from path.
    /// The method and route it was counted under (its queries go there too), or null when it wasn't.</summary>
    public (string Method, string Route)? Record(string? method, string? route, int status, double ms, string? path = "")
    {
        if (!core.IsOn("performance")) return null;
        var r = string.IsNullOrEmpty(route) ? (status == 404 ? NotFound : NormalizeRoute(path)) : route!;
        var m = MethodOf(method);
        var minute = MinuteNow();
        lock (gate)
        {
            var key = (minute, m, J.Clip(r, 200), status);
            if (!rows.ContainsKey(key) && rows.Count >= MaxKeys) key = (minute, m, "(other)", status);
            // Past the cap even for "(other)" rows (many minutes the collector
            // didn't take, every status): this request isn't counted.
            if (!rows.ContainsKey(key) && rows.Count >= HardMaxKeys) return null;
            if (!rows.TryGetValue(key, out var row)) rows[key] = row = new Row();
            row.Count += 1;
            row.SumMs += ms;
            row.MaxMs = Math.Max(row.MaxMs, ms);
            row.Buckets[BucketOf(ms)] += 1;
            return (key.Item2, key.Item3);
        }
    }

    internal int RowCount
    {
        get
        {
            lock (gate) return rows.Count;
        }
    }

    internal List<Dictionary<string, object?>> Take(bool everything)
    {
        var current = MinuteNow();
        List<KeyValuePair<(long Minute, string Method, string Route, int Status), Row>> ready;
        lock (gate)
        {
            ready = rows.Where(p => everything || p.Key.Minute < current).ToList();
            foreach (var pair in ready) rows.Remove(pair.Key);
        }
        return ready.Select(p => new Dictionary<string, object?>
        {
            ["minute"] = J.IsoSeconds(p.Key.Minute),
            ["method"] = p.Key.Method,
            ["route"] = p.Key.Route,
            ["status"] = p.Key.Status,
            ["count"] = p.Value.Count,
            ["sum_ms"] = Math.Round(p.Value.SumMs, 1),
            ["max_ms"] = Math.Round(p.Value.MaxMs, 1),
            ["buckets"] = p.Value.Buckets.ToArray(),
        }).ToList();
    }

    public async Task FlushAsync(bool everything = true)
    {
        var ready = Take(everything);
        for (var i = 0; i < ready.Count; i += MaxRows)
        {
            await core.SendAsync("performance", "/events/server-requests", "POST", new Dictionary<string, object?>
            {
                ["server_name"] = ServerName,
                ["runtime"] = Runtime,
                ["rows"] = ready.Skip(i).Take(MaxRows).ToList(),
            }).ConfigureAwait(false);
        }
    }

    public Task CloseAsync() => FlushAsync(true);
}
