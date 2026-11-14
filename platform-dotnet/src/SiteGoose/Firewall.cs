using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace SiteGoose;

/// <summary>What the firewall decided about a request.</summary>
public sealed class FirewallDecision
{
    public FirewallDecision(string action, string rule, int status)
    {
        Action = action;
        Rule = rule;
        Status = status;
    }

    internal FirewallDecision(string action, string rule, int status, long window) : this(action, rule, status)
    {
        Window = window;
    }

    /// <summary>"allow", "block" or "monitor".</summary>
    public string Action { get; }

    /// <summary>"", "deny", "ban", "list", "shared", "probe", "rate", "challenge", "request:&lt;id&gt;" or "limit:&lt;id&gt;".</summary>
    public string Rule { get; }

    /// <summary>403, 429 for the rate limit and a page limit, 503 for the browser check.</summary>
    public int Status { get; }

    /// <summary>A page limit's window in seconds, for its Retry-After; 0 for any other rule.</summary>
    internal long Window { get; }

    /// <summary>A static file let through, for Firewall.CountStatic after the response.</summary>
    internal LateHit? Late { get; set; }

    public static readonly FirewallDecision Allow = new("allow", "", 200);
}

/// <summary>A static-looking request Check only compared with the counts
/// (firewall.md, `rate`): what CountStatic adds after the response when the
/// router sent it to a page or it answered an error.</summary>
internal sealed class LateHit
{
    public string Counter = "";
    public bool Rate;
    public bool Limits;
    public string? Method;
    public string? Path;
    public string? UserAgent;
}

internal sealed class Probes
{
    public HashSet<string> Exact = new(StringComparer.Ordinal);
    public string[] Prefix = Array.Empty<string>();
    public long Ban;
}

internal sealed class ChallengeRules
{
    public string[] Skip = Array.Empty<string>();
    public IpSet Exempt = IpSet.Empty;
}

/// <summary>A page limit: at most Limit requests per Window seconds, per
/// address, to what Match matches.</summary>
internal sealed class PageLimit
{
    public RequestRule Match = new();
    public long Limit;
    public long Window;
    /// <summary>A count for every page (the routed path) rather than one for all of them.</summary>
    public bool EachPath;
}

internal sealed class Rules
{
    public bool Enabled;
    public string Mode = "monitor";
    public long Sync = Core.Retry;
    public IpSet Allow = IpSet.Empty;
    public IpSet GoodBots = IpSet.Empty;
    public IpSet Deny = IpSet.Empty;
    public IpSet List = IpSet.Empty;
    public IpSet Shared = IpSet.Empty;
    public IpSet Banned = IpSet.Empty;
    public (long Limit, long Window)? Rate;
    public long Ban;
    public (long Limit, long Window, long Ban)? Login;
    public Probes? Probes;
    public List<RequestRule> Requests = new();
    public List<PageLimit> Limits = new();
    public IpSet LimitsExempt = IpSet.Empty;
    public ChallengeRules? Challenge;
}

/// <summary>Firewall module: rules from the collector (GET /events/firewall/rules,
/// protocol in sdk/protocols/firewall.md) every minute or so; every request is
/// checked against them in memory, so the app never waits on the collector.
/// What was blocked (or, in monitor mode, would have been) goes back in batches.
///
/// Fails open: until rules arrive, and whenever the collector can't be reached,
/// requests pass (with the last rules that arrived, if any). The rate limit
/// counts in this process: with several instances, pass Counter (e.g. Redis)
/// for one count across them.</summary>
internal sealed class Firewall
{
    public const int Protocol = 1;
    public const int FlushEvery = 5;
    public const int Batch = 200;
    public const int QueueMax = 2000;
    public const int CounterMax = 100000;
    public const int MaxLimits = 50;
    /// <summary>The body of a page limit's 429: a person reads it, so it says what to do.</summary>
    public const string LimitBody = "Too many requests to this page. Please wait a little and try again.";
    private static readonly Regex LimitId = new("^[a-z][a-z0-9_.-]{1,39}$", RegexOptions.CultureInvariant);
    // The layers this server runs (X-Firewall-Layers): the address firewall and the browser check.
    public const string Layers = "app check";

    // Cloudflare's published ranges (cloudflare.com/ips), the same list as
    // sdk/protocols/cloudflare-ranges.json (the tests compare them):
    // CF-Connecting-IP is believed only from these, since anyone who reaches the
    // origin directly can send it.
    public static readonly string[] Cloudflare =
    {
        "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
        "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
        "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
        "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
        "2a06:98c0::/29", "2c0f:f248::/32",
    };

    private static readonly Lazy<IpSet> CloudflareSet = new(() => new IpSet(Cloudflare));
    private static readonly Regex Slashes = new("/{2,}", RegexOptions.CultureInvariant);
    private static readonly Regex NotAscii = new("[^\\x21-\\x7e]", RegexOptions.CultureInvariant);

    private readonly Core core;
    // One lock per table, so a request counting its rate never waits on one
    // banning or reporting.
    private readonly object queueGate = new();
    private readonly object countsGate = new();
    private readonly object bansGate = new();
    private readonly object loginsGate = new();
    // Keyed by Ip.CounterKey: an IPv4 address, or an IPv6 /64.
    private readonly Dictionary<string, (long Window, long Hits)> counts = new();
    // Page limits: "<id>|<counter>" -> its count. Limits with each "path"
    // ("<id>|<counter>|<path>") count in a table of their own: one entry per
    // address and page fills a table fast, and it mustn't crowd out the
    // login limit's counts.
    internal readonly LimitTable limitCounts = new(), pathCounts = new();
    // With a shared counter: the counts this process saw go over (their key,
    // window and all), so a static file asked for after them can be turned
    // away without adding to them (a counter can only add).
    private readonly Dictionary<string, bool> overNoted = new();
    private Dictionary<string, Dictionary<string, object?>> queue = new();
    // Bot protection here: address -> when its ban ends; address -> (window start, failed logins).
    private readonly Dictionary<string, double> bans = new();
    private readonly Dictionary<string, (double Start, long Count)> logins = new();
    private readonly string? cacheFile;

    public Firewall(Core core, string? trustProxy = null, Func<Func<string, string>, string?>? clientIp = null, string? mode = null,
        Func<string, int, long>? counter = null, string? cacheFile = null)
    {
        this.core = core;
        TrustProxy = trustProxy;
        ClientIpFunc = clientIp;
        Mode = mode == "monitor" || mode == "block" ? mode : null;
        Counter = counter;
        this.cacheFile = string.IsNullOrEmpty(cacheFile) ? null : cacheFile;
        // The browser check's passes are signed with the site secret, so any
        // of the site's servers accepts one another handed out.
        PassKey = Challenge.PassKey(core.Secret);
        if (this.cacheFile != null)
        {
            try
            {
                var cached = J.Parse(File.ReadAllText(this.cacheFile));
                RulesNow = Compile(J.Prop(cached, "rules"));
                Etag = J.Str(J.Prop(cached, "etag")) ?? "";
            }
            catch (Exception)
            {
                // No cache yet, or one we can't read: the next fetch writes it.
            }
        }
        if (core.Valid)
        {
            core.Every(SyncAsync);
            core.Every(async () =>
            {
                await FlushAsync().ConfigureAwait(false);
                return FlushEvery;
            }, FlushEvery);
        }
    }

    public string? TrustProxy { get; }
    public Func<Func<string, string>, string?>? ClientIpFunc { get; }
    public string? Mode { get; }
    public Func<string, int, long>? Counter { get; }
    public byte[] PassKey { get; }
    internal Rules? RulesNow { get; set; }
    internal string Etag { get; set; } = "";

    internal int QueueCount
    {
        get
        {
            lock (queueGate) return queue.Count;
        }
    }

    internal List<Dictionary<string, object?>> Queued()
    {
        lock (queueGate) return queue.Values.ToList();
    }

    internal static Probes? CompileProbes(JsonElement? probes)
    {
        if (!J.IsObject(probes)) return null;
        var exact = J.Strings(J.Prop(probes, "exact")).Where(p => p.Length > 0).Select(p => p.ToLowerInvariant()).ToList();
        var prefix = J.Strings(J.Prop(probes, "prefix")).Where(p => p.Length > 0).Select(p => p.ToLowerInvariant()).ToArray();
        if (exact.Count == 0 && prefix.Length == 0) return null;
        return new Probes { Exact = new HashSet<string>(exact, StringComparer.Ordinal), Prefix = prefix, Ban = Math.Max(0, J.Int(J.Prop(probes, "ban"))) };
    }

    /// <summary>True when the path (no query, lower-cased, "//" as "/") is a
    /// probe, as sent or as the router reads it (";params" dropped, "." and
    /// ".." resolved, decoded once: "/x/..;/.env" is "/.env").</summary>
    internal static bool IsProbe(string? path, Probes? probes)
    {
        if (probes == null) return false;
        var p = path ?? "";
        var cut = p.IndexOfAny(new[] { '?', '#' });
        if (cut >= 0) p = p.Substring(0, cut);
        var clean = Slashes.Replace(p.ToLowerInvariant(), "/");
        foreach (var text in new[] { clean, RequestRules.NormalizeTarget(path) })
        {
            if (probes.Exact.Contains(text)) return true;
            foreach (var prefix in probes.Prefix)
            {
                if (text.StartsWith(prefix, StringComparison.Ordinal)) return true;
            }
        }
        return false;
    }

    private static bool WholeIn(JsonElement? value, long min, long max)
    {
        if (value is not { ValueKind: JsonValueKind.Number } number || !number.TryGetDouble(out var d)) return false;
        return d == Math.Floor(d) && d >= min && d <= max;
    }

    /// <summary>The page limits as they will be counted. One that can't be used
    /// (a bad id, limit or window, or nothing left to match once regex is left
    /// out) is dropped; the others stay.</summary>
    internal static List<PageLimit> CompileLimits(JsonElement? data)
    {
        var limits = new List<PageLimit>();
        if (J.Prop(data, "rules") is not { ValueKind: JsonValueKind.Array } given) return limits;
        var seen = 0;
        foreach (var limit in given.EnumerateArray())
        {
            if (seen++ >= MaxLimits) break;
            if (limit.ValueKind != JsonValueKind.Object) continue;
            var id = J.Str(J.Prop(limit, "id"));
            if (id == null || !LimitId.IsMatch(id) || !WholeIn(J.Prop(limit, "limit"), 1, 100000) || !WholeIn(J.Prop(limit, "window"), 1, 3600)) continue;
            var match = new RequestRule
            {
                Id = id,
                Action = J.Str(J.Prop(limit, "action")) == "block" ? "block" : "monitor",
                Methods = J.Strings(J.Prop(limit, "methods")).Select(m => m.ToUpperInvariant()).ToArray(),
                Path = RequestRules.Section(J.Prop(limit, "path"), regex: false),
                Query = RequestRules.Section(J.Prop(limit, "query"), regex: false),
            };
            // With neither a path nor a query it would count every request.
            if (match.Path == null && match.Query == null) continue;
            limits.Add(new PageLimit
            {
                Match = match,
                Limit = J.Int(J.Prop(limit, "limit")),
                Window = J.Int(J.Prop(limit, "window")),
                EachPath = J.Str(J.Prop(limit, "each")) == "path",
            });
        }
        return limits;
    }

    internal static Rules Compile(JsonElement? data)
    {
        if (!J.IsObject(data) || !J.IsNumber(J.Prop(data, "v")) || J.Int(J.Prop(data, "v")) != Protocol) throw new FormatException("unknown rules version");
        var rules = new Rules
        {
            Enabled = J.Prop(data, "enabled") is { ValueKind: JsonValueKind.True },
            Mode = J.Str(J.Prop(data, "mode")) == "block" ? "block" : "monitor",
            Sync = Math.Max(Core.MinSync, J.Int(J.Prop(data, "sync"), Core.Retry)),
            Allow = new IpSet(J.Strings(J.Prop(data, "allow"))),
            // Crawlers the rate limit must not catch (absent in older rules).
            GoodBots = new IpSet(J.Strings(J.Prop(data, "goodbots"))),
            Deny = new IpSet(J.Strings(J.Prop(data, "deny"))),
            List = new IpSet(J.Strings(J.Prop(data, "lists"))),
            Shared = new IpSet(J.Strings(J.Prop(data, "shared"))),
            Banned = new IpSet(J.Strings(J.Prop(data, "banned"))),
            Ban = J.Int(J.Prop(J.Prop(data, "ban"), "seconds")),
            Probes = CompileProbes(J.Prop(data, "probes")),
            // Virtual patching: rules that match the request, not the address.
            Requests = RequestRules.Compile(J.Prop(data, "requests")),
            // Page limits: one kind of request capped on its own (absent in older rules).
            Limits = CompileLimits(J.Prop(data, "limits")),
            LimitsExempt = new IpSet(J.Strings(J.Prop(J.Prop(data, "limits"), "exempt"))),
        };
        var rate = J.Prop(data, "rate");
        if (J.Truthy(rate) && J.Int(J.Prop(rate, "limit")) > 0)
        {
            rules.Rate = (J.Int(J.Prop(rate, "limit")), Math.Max(1, J.Int(J.Prop(rate, "window"), 60)));
        }
        var login = J.Prop(data, "login");
        if (J.IsObject(login) && J.Int(J.Prop(login, "limit")) > 0)
        {
            rules.Login = (J.Int(J.Prop(login, "limit")), J.Int(J.Prop(login, "window"), 3600), J.Int(J.Prop(login, "ban"), 3600));
        }
        // The browser check: present only when the site is to be checked.
        var check = J.Prop(data, "challenge");
        if (J.IsObject(check))
        {
            rules.Challenge = new ChallengeRules
            {
                Skip = Challenge.CompileSkip(J.Strings(J.Prop(check, "skip"))),
                Exempt = new IpSet(J.Strings(J.Prop(check, "exempt"))),
            };
        }
        return rules;
    }

    /// <summary>This machine's host name for X-Server-Name: plain ASCII, 100 characters at most.</summary>
    internal static string ServerNameHeader() => J.Clip(NotAscii.Replace(Core.HostName(), ""), 100);

    internal async Task<double> SyncAsync()
    {
        var extra = new Dictionary<string, string> { ["X-Firewall-Layers"] = Layers };
        var name = ServerNameHeader();
        if (name.Length > 0) extra["X-Server-Name"] = name;
        if (Etag.Length > 0) extra["If-None-Match"] = Etag;
        var res = await core.SendAsync("firewall", "/events/firewall/rules?site_id=" + core.SiteId, "GET", null, "bearer", extra).ConfigureAwait(false);
        if (res != null && res.Status == 200)
        {
            var data = res.Json();
            try
            {
                RulesNow = Compile(data);
                Etag = res.Headers.TryGetValue("etag", out var tag) ? tag : "";
                if (cacheFile != null)
                {
                    var text = "{\"etag\":" + JsonSerializer.Serialize(Etag) + ",\"rules\":" + Encoding.UTF8.GetString(res.Body) + "}";
                    File.WriteAllText(cacheFile, text);
                }
            }
            catch (Exception error)
            {
                core.Log("firewall", "rules not used: " + error.Message);
            }
        }
        return RulesNow?.Sync ?? Core.Retry;
    }

    /// <summary>peek: only compared with the count so far, nothing added (a static file).</summary>
    private bool OverRate(string counter, (long Limit, long Window) rate, double now, bool peek = false)
    {
        var window = (long)Math.Floor(now / rate.Window);
        if (Counter != null)
        {
            var name = "afw:" + core.SiteId + ":" + counter + ":" + window;
            return peek ? Noted(name) : NoteOver(name, Counter(name, (int)(rate.Window * 2)) > rate.Limit);
        }
        lock (countsGate)
        {
            if (peek) return counts.TryGetValue(counter, out var seen) && seen.Window == window && seen.Hits > rate.Limit;
            if (!counts.TryGetValue(counter, out var entry) || entry.Window != window)
            {
                if (!counts.ContainsKey(counter) && counts.Count >= CounterMax)
                {
                    // Full: the windows already over go; if that frees nothing, a
                    // new address isn't counted (it passes) rather than everyone
                    // starting again from zero.
                    foreach (var stale in counts.Where(p => p.Value.Window < window).Select(p => p.Key).ToList()) counts.Remove(stale);
                    if (counts.Count >= CounterMax) return false;
                }
                entry = (window, 0);
            }
            entry.Hits += 1;
            counts[counter] = entry;
            return entry.Hits > rate.Limit;
        }
    }

    /// <summary>Step 6: counts the request toward every page limit it matches,
    /// each in its own fixed window. Returns the first limit now over its count
    /// that blocks and the first one over it that only watches; either may be
    /// null. Nothing is banned: the cap lifts when the window ends.</summary>
    /// <summary>peek: as OverRate's.</summary>
    private (PageLimit? Blocking, PageLimit? Watched) OverLimits(List<PageLimit> limits, string counter, string? method, string? path, string? userAgent, bool blockMode, double now, bool peek = false)
    {
        PageLimit? blocking = null, watched = null;
        var request = new RequestRules.Prepared(method, path, userAgent);
        foreach (var limit in limits)
        {
            if (!RequestRules.Matches(limit.Match, request)) continue;
            var window = (long)Math.Floor(now / limit.Window);
            long hits;
            // A count per page stays on this server: in a shared counter it
            // would be one key per page per address.
            if (Counter != null && !limit.EachPath)
            {
                var shared = "afw:" + core.SiteId + ":l:" + limit.Match.Id + ":" + counter + ":" + window;
                if (peek) hits = Noted(shared) ? limit.Limit + 1 : 0;
                else
                {
                    hits = Counter(shared, (int)(limit.Window * 2));
                    NoteOver(shared, hits > limit.Limit);
                }
            }
            else
            {
                // Pages past 2,000 characters share a count: a key per long
                // path would let one address fill the table with 8 KB keys.
                var name = limit.Match.Id + "|" + counter + (limit.EachPath ? "|" + J.Clip(request.RoutedPath, RequestRules.MaxText) : "");
                var table = limit.EachPath ? pathCounts : limitCounts;
                var counted = peek ? table.Peek(name, window) : table.Hit(name, window, limit.Window, now);
                if (counted == null) continue; // full of live counts: this one isn't counted here
                hits = counted.Value;
            }
            if (hits <= limit.Limit) continue;
            if (blockMode && limit.Match.Action == "block") blocking ??= limit;
            else watched ??= limit;
        }
        return (blocking, watched);
    }

    /// <summary>One table of page-limit counts, with its own lock: name ->
    /// (window, its length, hits).</summary>
    internal sealed class LimitTable
    {
        private readonly Dictionary<string, (long Window, long Length, long Hits)> entries = new();
        private double swept = double.NegativeInfinity;

        public int Count { get { lock (entries) return entries.Count; } }

        /// <summary>Adds one to a count and returns it, or null when the table
        /// is full of live counts. Full, the windows that ended go, but at most
        /// once a second: a flood of new addresses mustn't make every request
        /// walk the whole table. What is still live is never dropped, so a new
        /// count isn't kept (the request passes) rather than everyone starting
        /// again from zero.</summary>
        /// <summary>The count so far in this window, nothing added (a static file).</summary>
        public long Peek(string name, long window)
        {
            lock (entries)
            {
                return entries.TryGetValue(name, out var entry) && entry.Window == window ? entry.Hits : 0;
            }
        }

        public long? Hit(string name, long window, long length, double now)
        {
            lock (entries)
            {
                if (!entries.TryGetValue(name, out var entry) || entry.Window != window)
                {
                    if (!entries.ContainsKey(name) && entries.Count >= CounterMax)
                    {
                        if (now - swept < 1) return null;
                        swept = now;
                        // Removing while enumerating is allowed for a Dictionary
                        // since .NET Core 3.0, so the sweep allocates nothing.
                        foreach (var pair in entries)
                        {
                            if ((pair.Value.Window + 1) * pair.Value.Length <= now) entries.Remove(pair.Key);
                        }
                        if (entries.Count >= CounterMax) return null;
                    }
                    entry = (window, length, 0);
                }
                entry.Hits += 1;
                entries[name] = entry;
                return entry.Hits;
            }
        }
    }

    private bool Noted(string name)
    {
        lock (overNoted) return overNoted.ContainsKey(name);
    }

    /// <summary>A shared count seen over, remembered under its key (window and
    /// all, so an old one never matches again) for a static file's peek.</summary>
    private bool NoteOver(string name, bool over)
    {
        if (!over) return false;
        lock (overNoted)
        {
            if (!overNoted.ContainsKey(name) && overNoted.Count >= CounterMax) overNoted.Remove(overNoted.Keys.First());
            overNoted[name] = true;
        }
        return true;
    }

    /// <summary>After the response to a static file Check let through (its
    /// decision's Late): counted toward the rate and the page limits it
    /// skipped when it answered 400 or more (a flood of made-up file names)
    /// or the router sent it to an endpoint that isn't a file's (routed),
    /// unless it answered 304 (a browser checking a file it keeps).</summary>
    internal void CountStatic(LateHit? late, int status, bool routed, double? now = null)
    {
        var rules = RulesNow;
        if (late == null || rules == null || !(status >= 400 || (routed && status != 304))) return;
        var at = now ?? J.UnixNow();
        if (late.Rate && rules.Rate is { } rate) OverRate(late.Counter, rate, at);
        if (late.Limits && rules.Limits.Count > 0) OverLimits(rules.Limits, late.Counter, late.Method, late.Path, late.UserAgent, false, at);
    }

    // A response's Content-Type that is a file's (an image, a font, a script,
    // a stylesheet, a video, a PDF, a download).
    private static readonly Regex FileTypes = new(@"^(?:image|font|audio|video)/|^text/css|javascript|^application/(?:wasm|pdf|octet-stream|vnd\.ms-fontobject|(?:x-)?font)",
        RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    /// <summary>Whether the router sent a static-looking request to a route
    /// of its own that isn't a file's. pattern: the endpoint's route pattern
    /// ("Home/Search/{q}", "/search/{q}"), null when no endpoint matched (the
    /// static files middleware). A pattern that is itself a file's by the
    /// static rule ("/avatars/{id}.png", "/static/{**path}") is left alone,
    /// and so is an answer with a file's Content-Type.</summary>
    internal static bool RoutedToPage(string? pattern, string? contentType)
    {
        if (pattern == null || FileTypes.IsMatch((contentType ?? "").Trim())) return false;
        return !IsStaticAsset(pattern.StartsWith("/", StringComparison.Ordinal) ? pattern : "/" + pattern);
    }

    private bool BannedHere(string counter)
    {
        lock (bansGate)
        {
            if (!bans.TryGetValue(counter, out var until)) return false;
            if (until > J.UnixNow()) return true;
            bans.Remove(counter);
            return false;
        }
    }

    private void BanHere(string counter, long seconds)
    {
        if (seconds <= 0) return;
        var now = J.UnixNow();
        var until = now + seconds;
        lock (bansGate)
        {
            if (!bans.ContainsKey(counter) && bans.Count >= CounterMax)
            {
                // Full: bans that are over go first, then the one ending soonest.
                foreach (var over in bans.Where(p => p.Value <= now).Select(p => p.Key).ToList()) bans.Remove(over);
                if (bans.Count >= CounterMax) bans.Remove(bans.OrderBy(p => p.Value).First().Key);
            }
            bans[counter] = bans.TryGetValue(counter, out var current) ? Math.Max(current, until) : until;
        }
    }

    /// <summary>A failed login on your site: counted here (past the site's limit
    /// the address is banned straight away) and reported, so it counts on the
    /// Security page and gets banned on the other servers too.</summary>
    public void LoginFailed(string ip)
    {
        var key = Ip.Key(ip);
        var counter = Ip.CounterKey(ip);
        var rules = RulesNow;
        if (key == null || counter == null || (rules != null && rules.Allow.Has(key.Value))) return;
        if (rules?.Login is { } login)
        {
            var now = J.UnixNow();
            var reached = false;
            lock (loginsGate)
            {
                if (!logins.TryGetValue(counter, out var entry) || now - entry.Start >= login.Window)
                {
                    if (!logins.ContainsKey(counter) && logins.Count >= CounterMax)
                    {
                        foreach (var old in logins.Where(p => now - p.Value.Start >= login.Window).Select(p => p.Key).ToList()) logins.Remove(old);
                    }
                    entry = (now, 0);
                }
                if (logins.ContainsKey(counter) || logins.Count < CounterMax)
                {
                    entry.Count += 1;
                    reached = entry.Count >= login.Limit;
                    if (reached) logins.Remove(counter);
                    else logins[counter] = entry;
                }
            }
            if (reached) BanHere(counter, login.Ban);
        }
        Report(Ip.Display(Ip.Parse(ip)), "login", "monitor", "", "", "");
    }

    private void Report(string ip, string rule, string action, string method, string path, string userAgent)
    {
        var key = ip + "|" + rule + "|" + action + "|" + method + "|" + path;
        lock (queueGate)
        {
            if (queue.TryGetValue(key, out var row))
            {
                row["hits"] = (long)row["hits"]! + 1;
            }
            else if (queue.Count < QueueMax)
            {
                queue[key] = new Dictionary<string, object?>
                {
                    ["at"] = J.Now(), ["ip"] = ip, ["rule"] = rule, ["action"] = action,
                    ["method"] = method, ["path"] = path, ["user_agent"] = userAgent, ["hits"] = 1L,
                };
            }
        }
    }

    public async Task FlushAsync()
    {
        List<Dictionary<string, object?>> rows;
        lock (queueGate)
        {
            rows = queue.Values.ToList();
            queue = new Dictionary<string, Dictionary<string, object?>>();
        }
        for (var i = 0; i < rows.Count; i += Batch)
        {
            await core.SendAsync("firewall", "/events/firewall/events", "POST", new Dictionary<string, object?>
            {
                ["site_id"] = core.SiteId,
                ["events"] = rows.Skip(i).Take(Batch).ToList(),
            }, "bearer").ConfigureAwait(false);
        }
    }

    /// <summary>Allowed addresses skip every other rule. accept and cookie (the
    /// request's headers) are for the browser check: rule "challenge", status
    /// 503, answered with ChallengePage(). fetchSite: the Sec-Fetch-Site header.</summary>
    public FirewallDecision Check(string ip, string? method = "", string? path = "", string? userAgent = "", string? accept = "", string? cookie = "", double? now = null, string? fetchSite = null)
    {
        var rules = RulesNow;
        if (rules == null || !rules.Enabled) return FirewallDecision.Allow;
        var found = Ip.Key(ip);
        if (found == null || rules.Allow.Has(found.Value)) return FirewallDecision.Allow;
        var key = found.Value;
        var counter = Ip.CounterKey(ip)!;
        // Reported as the address it is: an IPv4-mapped one as IPv4.
        ip = Ip.Display(Ip.Parse(ip));
        var at = now ?? J.UnixNow();
        var action = (Mode ?? rules.Mode) == "block" ? "block" : "monitor";
        // Another site made the browser send it (an <img src="/.env">, a
        // no-cors fetch): refused as before, but its address is the visitor's
        // own, so it bans no one here and is reported as refused, so the
        // collector bans no one elsewhere either (firewall.md, 'Checking a request').
        var fetch = (fetchSite ?? "").Trim().ToLowerInvariant();
        var otherSite = fetch == "cross-site" || fetch == "same-site";
        var rule = rules.Deny.Has(key) ? "deny"
            : rules.Banned.Has(key) || BannedHere(counter) ? "ban"
            : rules.List.Has(key) ? "list"
            : rules.Shared.Has(key) ? "shared" : "";
        if (rule.Length == 0 && IsProbe(path, rules.Probes))
        {
            rule = "probe";
            // Asking for a secret file: banned here in block mode; the report bans it on the other servers.
            if (action == "block" && !otherSite) BanHere(counter, rules.Probes!.Ban);
        }
        if (rule.Length == 0)
        {
            var matched = RequestRules.Match(rules.Requests, method, path, userAgent);
            if (matched != null)
            {
                rule = "request:" + matched.Id;
                // A rule the dashboard only watches passes even in block mode;
                // one that blocks also bans the address here, as a flood does.
                action = action == "block" && matched.Action == "block" ? "block" : "monitor";
                if (action == "block" && matched.Ban > 0 && !otherSite) BanHere(counter, matched.Ban);
            }
        }
        // Step 6, page limits. A limit only watched is reported and the check
        // goes on: watching the login page must not let a flood through it
        // untouched by the rate limit.
        // A static file isn't counted toward the page limits or the rate,
        // only compared with the counts so far: an address already over them
        // is turned away for its files too. It counts after the response when
        // the router sent it to a page after all ("Home/Search/{q}" took
        // "/Home/Search/x.css") or it answered an error (CountStatic).
        var fetchesFile = IsStaticAsset(path, method);
        bool lateRate = false, lateLimits = false;
        PageLimit? watched = null;
        long window = 0;
        if (rule.Length == 0 && rules.Limits.Count > 0 && !rules.GoodBots.Has(key) && !rules.LimitsExempt.Has(key))
        {
            lateLimits = fetchesFile;
            var over = OverLimits(rules.Limits, counter, method, path, userAgent, action == "block", at, fetchesFile);
            if (over.Blocking != null)
            {
                rule = "limit:" + over.Blocking.Match.Id;
                window = over.Blocking.Window;
            }
            else
            {
                watched = over.Watched;
            }
        }
        // A page's images, styles and scripts, when the app serves them itself
        // (UseStaticFiles after this middleware), aren't requests a visitor
        // chooses to make: they don't count toward the rate.
        if (rule.Length == 0 && rules.Rate != null && !rules.GoodBots.Has(key)) lateRate = fetchesFile;
        if (rule.Length == 0 && rules.Rate is { } rate && !rules.GoodBots.Has(key) && OverRate(counter, rate, at, fetchesFile))
        {
            rule = "rate";
            // Banned here straight away in block mode, as a probe is.
            if (action == "block" && !otherSite) BanHere(counter, rules.Ban);
        }
        var m = J.Clip(method ?? "", 10);
        var p = path ?? "";
        var q = p.IndexOfAny(new[] { '?', '#' });
        p = J.Clip(q >= 0 ? p.Substring(0, q) : p, 300);
        var ua = J.Clip(userAgent ?? "", 300);
        // Not a mode matter: the collector only sends `challenge` when the site
        // is to be checked, and a match only watched (monitor) gets it too
        // (firewall.md, step 8).
        if ((rule.Length == 0 || action != "block") && NeedsCheck(rules, key, ip, method, path, accept, cookie, at))
        {
            if (rule.Length > 0) Report(ip, rule, action, m, p, ua);
            rule = "challenge";
            action = "block";
        }
        // What CountStatic needs after the response of a static file that goes on to the app.
        var late = (lateRate || lateLimits) && (rule.Length == 0 || action != "block")
            ? new LateHit { Counter = counter, Rate = lateRate, Limits = lateLimits, Method = method, Path = path, UserAgent = userAgent }
            : null;
        if (watched != null)
        {
            Report(ip, "limit:" + watched.Match.Id, "monitor", m, p, ua);
            // What it would have answered: 429, as a limit that blocks does.
            if (rule.Length == 0) return new FirewallDecision("monitor", "limit:" + watched.Match.Id, 429, watched.Window) { Late = late };
        }
        if (rule.Length == 0) return late == null ? FirewallDecision.Allow : new FirewallDecision("allow", "", 200) { Late = late };
        var banning = rule == "probe" || rule == "rate" || rule.StartsWith("request:", StringComparison.Ordinal);
        Report(ip, rule, otherSite && banning && action == "block" ? "refused" : action, m, p, ua);
        return new FirewallDecision(action, rule, rule == "rate" || rule.StartsWith("limit:", StringComparison.Ordinal) ? 429 : rule == "challenge" ? 503 : 403, window) { Late = late };
    }

    private static readonly HashSet<string> StaticExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".css", ".js", ".mjs", ".map", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".avif", ".svg", ".ico", ".bmp",
        ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp4", ".webm", ".ogg", ".mp3", ".wav", ".pdf", ".wasm",
    };

    // Frameworks' asset folders (firewall.md, `rate`).
    private static readonly string[] StaticPrefixes = { "/static/", "/_next/static/", "/assets/" };

    // In a path decoded once: a "%xx" still there (double encoding, which a
    // router that decodes again reads differently), a ";" (a path parameter
    // to some servers and proxies, part of the name to others), a "\" (a
    // "/" to IIS), a "?" or "#" that was encoded, or a control character.
    private static readonly Regex Unsure = new(@"%[0-9a-fA-F]{2}|[;\\?#\x00-\x1f\x7f]", RegexOptions.CultureInvariant);

    /// <summary>A file a page loads with itself, by its extension or its
    /// folder (firewall.md, `rate`), read from the raw target decoded once,
    /// lower case, "//" as "/". Only a path every router reads the same way
    /// can be a file: one with a "." or ".." segment, a ";", a "\", an
    /// encoded "/" (Kestrel leaves "%2F" in Request.Path) or a "%xx" left
    /// after decoding is a page, so "/static/../login",
    /// "/static%2F..%2Flogin", "/login;x.css" and "/login%3Bx.css" all
    /// count. A browser asks for its files with none of those. Nor is a path
    /// past the rules' 2,000 characters: cut there, "/search/xxx…x.css/more"
    /// would end in .css and flood a catch-all route past the limits. Only
    /// GET and HEAD fetch a file (no method given is read as GET): a form
    /// posts to a page, and the default MVC route takes /Account/Login/x.css
    /// as Login with id "x.css".</summary>
    internal static bool IsStaticAsset(string? target, string? method = null)
    {
        if (!string.IsNullOrEmpty(method) && method != "GET" && method != "HEAD") return false;
        var raw = target ?? "";
        var cut = raw.IndexOfAny(new[] { '?', '#' });
        if (cut >= 0) raw = raw.Substring(0, cut);
        if (raw.Length > RequestRules.MaxText || !raw.StartsWith("/", StringComparison.Ordinal)
            || raw.IndexOf("%2f", StringComparison.OrdinalIgnoreCase) >= 0) return false;
        var decoded = RequestRules.DecodeOnce(raw);
        if (Unsure.IsMatch(decoded)) return false;
        // A-Z only, as every package: "İ" is "i" lower-cased by some.
        var segments = AsciiLower(decoded).Split('/');
        var parts = new List<string>(segments.Length);
        foreach (var segment in segments)
        {
            if (segment == "." || segment == "..") return false;
            if (segment.Length > 0) parts.Add(segment);
        }
        var p = "/" + string.Join("/", parts);
        if (parts.Count > 0 && segments[segments.Length - 1].Length == 0) p += "/"; // "/app.css/" isn't a file
        foreach (var prefix in StaticPrefixes)
        {
            if (p.StartsWith(prefix, StringComparison.Ordinal)) return true;
        }
        // The extension follows a name in the last segment: "/login/.css" is no file.
        var slash = p.LastIndexOf('/');
        var dot = p.LastIndexOf('.');
        return dot > slash + 1 && dot < p.Length - 1 && p[slash + 1] != '.' && StaticExtensions.Contains(p.Substring(dot));
    }

    private static string AsciiLower(string text)
    {
        var chars = text.ToCharArray();
        for (var i = 0; i < chars.Length; i++)
        {
            if (chars[i] >= 'A' && chars[i] <= 'Z') chars[i] = (char)(chars[i] + 32);
        }
        return new string(chars);
    }

    /// <summary>Only the address rules (deny, bans, blocklists, shared bans), for
    /// the first-party proxy's beacons: an address the site turned away isn't
    /// passed on to the collector either. Null when it passes.</summary>
    public FirewallDecision? AddressBlocked(string ip, string? method, string? path)
    {
        var rules = RulesNow;
        if (rules == null || !rules.Enabled) return null;
        var found = Ip.Key(ip);
        if (found == null || rules.Allow.Has(found.Value)) return null;
        var key = found.Value;
        var counter = Ip.CounterKey(ip)!;
        var rule = rules.Deny.Has(key) ? "deny"
            : rules.Banned.Has(key) || BannedHere(counter) ? "ban"
            : rules.List.Has(key) ? "list"
            : rules.Shared.Has(key) ? "shared" : "";
        if (rule.Length == 0) return null;
        var action = (Mode ?? rules.Mode) == "block" ? "block" : "monitor";
        var p = path ?? "";
        var q = p.IndexOf('?');
        Report(Ip.Display(Ip.Parse(ip)), rule, action, J.Clip(method ?? "", 10), J.Clip(q >= 0 ? p.Substring(0, q) : p, 300), "");
        return action == "block" ? new FirewallDecision(action, rule, 403) : null;
    }

    /// <summary>Step 8: the browser check is on, the request asks for a page
    /// outside skip, the address is in none of allow (already passed), goodbots
    /// and exempt, and it has no valid pass.</summary>
    private bool NeedsCheck(Rules rules, IpKey key, string ip, string? method, string? path, string? accept, string? cookie, double now)
    {
        var check = rules.Challenge;
        if (check == null || !Challenge.AsksForPage(method, path, accept, check.Skip)) return false;
        if (rules.GoodBots.Has(key) || check.Exempt.Has(key)) return false;
        return !Challenge.HasPass(PassKey, ip, cookie, now);
    }

    /// <summary>The page for a request Check() gave rule "challenge".</summary>
    public Answer ChallengePage(string ip, string? method) => Challenge.Page(PassKey, ip, method);

    public string RetryAfter() => RulesNow?.Rate is { } rate ? rate.Window.ToString() : "60";

    /// <summary>The Retry-After for a 429: a page limit's own window, else the rate limit's.</summary>
    public string RetryAfter(FirewallDecision decision) => decision.Window > 0 ? decision.Window.ToString() : RetryAfter();

    /// <summary>True when a connection's address is one of Cloudflare's.</summary>
    public static bool FromCloudflare(string? ip)
    {
        var key = Ip.Key(ip);
        return key != null && CloudflareSet.Value.Has(key.Value);
    }

    /// <summary>The visitor's address. trustProxy: null/"0" the connection's
    /// address; a number of proxies in X-Forwarded-For ("true" = 1);
    /// "cloudflare" reads CF-Connecting-IP, believed only when the connection
    /// comes from one of Cloudflare's addresses; "aspnetcore" the connection's
    /// address as ASP.NET Core's ForwardedHeadersMiddleware left it (configured
    /// by you, IIS out-of-process or ASPNETCORE_FORWARDEDHEADERS_ENABLED);
    /// clientIp gets the headers and returns it. remote and the headers are
    /// the request's as it arrived, before any middleware rewrote them. A port
    /// a proxy added ("1.2.3.4:5678", "[::1]:443") is dropped; anything that
    /// still isn't an address gives the connection's, so a header can't take
    /// a request past the firewall.</summary>
    public static string ResolveClientIp(string remote, Func<string, string> header, string? trustProxy, Func<Func<string, string>, string?>? clientIp = null)
    {
        string? found = null;
        if (clientIp != null)
        {
            found = clientIp(header);
        }
        else
        {
            var mode = (trustProxy ?? "").Trim().ToLowerInvariant();
            if (mode == "cloudflare")
            {
                if (FromCloudflare(remote)) found = header("cf-connecting-ip");
            }
            else if (mode != "aspnetcore")
            {
                var hops = mode == "true" ? 1 : int.TryParse(mode, out var n) ? n : 0;
                if (hops > 0)
                {
                    var chain = (header("x-forwarded-for") ?? "").Split(',').Select(s => s.Trim()).Where(s => s.Length > 0).ToList();
                    if (chain.Count > 0) found = chain[Math.Max(0, chain.Count - hops)];
                }
            }
        }
        var address = Ip.Parse(Ip.StripPort(found));
        return address != null ? Ip.Display(address) : remote;
    }

    public string ClientIp(string remote, Func<string, string> header) => ResolveClientIp(remote, header, TrustProxy, ClientIpFunc);

    public async Task CloseAsync() => await FlushAsync().ConfigureAwait(false);
}
