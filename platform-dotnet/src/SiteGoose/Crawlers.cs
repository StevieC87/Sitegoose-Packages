using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace SiteGoose;

/// <summary>Crawlers module: counts the search engines and AI bots that fetch
/// the site and sends one row a minute per bot, page and status to POST
/// /events/crawlers (sdk/protocols/crawlers.md). This traffic is invisible to
/// the browser tracker, because crawlers don't run JavaScript.
///
/// Only requests whose user agent names a known crawler are counted, so
/// visitors are never counted twice. Bot addresses go with the batch only so
/// the collector can check a crawler is itself, and are not stored.</summary>
internal sealed class Crawlers
{
    public const int FlushEvery = 60;
    public const int MaxKeys = 300;
    public const int MaxRows = 500;
    public const int MaxIpsPerBot = 5;
    public const int MaxPath = 400;

    // The catalogue of the protocol, most specific first: "ChatGPT-User" must be
    // tried before "GPTBot", "Claude-User" before "ClaudeBot". Keep in step with
    // the collector (expresscollect/Analytics/crawlers.js CATALOGUE).
    public static readonly (string Name, string Pattern)[] Bots =
    {
        // Fetched because a person asked an AI about the page.
        ("ChatGPT-User", "ChatGPT-User"),
        ("OAI-SearchBot", "OAI-SearchBot"),
        ("Perplexity-User", "Perplexity-User"),
        ("Claude-User", "Claude-User"),
        ("Claude-SearchBot", "Claude-SearchBot"),
        ("MistralAI-User", "MistralAI-User"),
        ("MistralAI-SearchBot", "MistralAI-SearchBot"),
        ("Meta-ExternalFetcher", "meta-externalfetcher"),
        // Bulk collection, for training or a dataset.
        ("GPTBot", "GPTBot"),
        ("ClaudeBot", "ClaudeBot|Claude-Web"),
        ("anthropic-ai", "anthropic-ai"),
        ("CCBot", "CCBot"),
        ("Bytespider", "Bytespider"),
        ("Meta-ExternalAgent", "meta-externalagent|facebookbot"),
        ("Amazonbot", "Amazonbot"),
        ("Diffbot", "Diffbot"),
        ("omgili", "omgili"),
        ("AI2Bot", "AI2Bot"),
        ("Timpibot", "Timpibot"),
        ("Webzio-Extended", "Webzio-Extended"),
        ("PerplexityBot", "PerplexityBot"),
        ("DuckAssistBot", "DuckAssistBot"),
        ("YouBot", "YouBot"),
        // Search engines. Google's tools before Googlebot itself.
        ("Google-InspectionTool", "Google-InspectionTool"),
        ("Storebot-Google", "Storebot-Google"),
        ("AdsBot-Google", "AdsBot-Google"),
        ("Googlebot", "Googlebot|Google-Site-Verification"),
        ("bingbot", "bingbot|BingPreview|adidxbot"),
        ("YandexBot", "Yandex(Bot|Mobile|Images|Webmaster)?"),
        ("Baiduspider", "Baiduspider"),
        ("DuckDuckBot", "DuckDuckBot|DuckDuckGo-Favicons"),
        ("Applebot", "Applebot"),
        ("PetalBot", "PetalBot|AspiegelBot"),
        ("SeznamBot", "SeznamBot"),
        ("Yeti", "Yeti/"),
        ("MojeekBot", "MojeekBot"),
        ("Qwantbot", "Qwantbot|Qwantify"),
        // SEO and backlink tools.
        ("AhrefsBot", "AhrefsBot|AhrefsSiteAudit"),
        ("SemrushBot", "SemrushBot|SiteAuditBot"),
        ("DotBot", "DotBot"),
        ("MJ12bot", "MJ12bot"),
        ("BLEXBot", "BLEXBot"),
        ("DataForSeoBot", "DataForSeoBot"),
        ("Barkrowler", "Barkrowler"),
        ("ScreamingFrog", "Screaming\\s?Frog"),
        ("ZoominfoBot", "ZoominfoBot"),
        // Link previews.
        ("facebookexternalhit", "facebookexternalhit"),
        ("Twitterbot", "Twitterbot"),
        ("LinkedInBot", "LinkedInBot"),
        ("Slackbot", "Slackbot|Slack-ImgProxy"),
        ("Discordbot", "Discordbot"),
        ("TelegramBot", "TelegramBot"),
        ("WhatsApp", "WhatsApp"),
        ("Pinterestbot", "Pinterest(bot)?/"),
        ("redditbot", "redditbot"),
        // Uptime and speed checks.
        ("UptimeRobot", "UptimeRobot"),
        ("Pingdom", "Pingdom"),
        ("BetterUptime", "Better\\s?Uptime|betteruptime"),
        ("Lighthouse", "Chrome-Lighthouse|Google Page Speed"),
        ("GTmetrix", "GTmetrix"),
        // Archives.
        ("ia_archiver", "ia_archiver"),
        ("archive.org_bot", "archive\\.org_bot|Wayback"),
    };

    private static readonly (string Name, Regex Pattern)[] Compiled =
        Bots.Select(b => (b.Name, new Regex(b.Pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))).ToArray();

    // Anything else that names itself a bot: counted as "Other bot", so a new
    // crawler shows up as traffic instead of disappearing.
    private static readonly Regex Generic = new(
        "bot\\b|crawler|crawling|spider|scrapy|curl/|wget/|python-requests|headlesschrome|http-client|okhttp|java/|go-http-client",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    private sealed class Row
    {
        public long Count;
        public long Bytes;
        public long SumMs;
    }

    private readonly Core core;
    private readonly object gate = new();
    private readonly Dictionary<(long Minute, string Bot, string Path, int Status), Row> rows = new();
    private Dictionary<string, List<string>> agents = new();

    public Crawlers(Core core, string? serverName = null)
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

    /// <summary>The crawler's catalogue name, or "" when the user agent isn't one.</summary>
    public static string Detect(string? userAgent)
    {
        var ua = userAgent ?? "";
        if (ua.Length == 0) return "";
        foreach (var (name, pattern) in Compiled)
        {
            if (pattern.IsMatch(ua)) return name;
        }
        return Generic.IsMatch(ua) ? "Other bot" : "";
    }

    /// <summary>One finished request from a crawler. bot: Detect(userAgent).</summary>
    public void Record(string? bot, string? path, int status, double ms = 0, long size = 0, string? ip = "")
    {
        if (string.IsNullOrEmpty(bot) || !core.IsOn("crawlers")) return;
        var p = path ?? "/";
        var cut = p.IndexOfAny(new[] { '?', '#' });
        if (cut >= 0) p = p.Substring(0, cut);
        var clean = J.Clip(p.Length == 0 ? "/" : p, MaxPath);
        var minute = (long)Math.Floor(J.UnixNow() / 60) * 60;
        lock (gate)
        {
            var key = (minute, bot!, clean, status);
            // Past MaxKeys a crawler asking for thousands of URLs becomes one row.
            if (!rows.ContainsKey(key) && rows.Count >= MaxKeys) key = (minute, bot!, "(other)", status);
            if (!rows.TryGetValue(key, out var row)) rows[key] = row = new Row();
            row.Count += 1;
            row.Bytes += Math.Max(0, size);
            row.SumMs += Math.Max(0, (long)ms);
            if (!string.IsNullOrEmpty(ip))
            {
                if (!agents.TryGetValue(bot!, out var seen)) agents[bot!] = seen = new List<string>();
                if (seen.Count < MaxIpsPerBot && !seen.Contains(ip!)) seen.Add(ip!);
            }
        }
    }

    /// <summary>Records a finished request when it came from a crawler.</summary>
    public void Middleware(string? userAgent, string? path, int status, double ms = 0, long size = 0, string? ip = "") =>
        Record(Detect(userAgent), path, status, ms, size, ip);

    internal (List<Dictionary<string, object?>> Rows, List<Dictionary<string, object?>> Agents) Take(bool everything)
    {
        var current = (long)Math.Floor(J.UnixNow() / 60) * 60;
        List<KeyValuePair<(long Minute, string Bot, string Path, int Status), Row>> ready;
        List<Dictionary<string, object?>> agentRows;
        lock (gate)
        {
            ready = rows.Where(p => everything || p.Key.Minute < current).ToList();
            foreach (var pair in ready) rows.Remove(pair.Key);
            var sent = new HashSet<string>(ready.Select(p => p.Key.Bot));
            agentRows = agents.Where(a => sent.Contains(a.Key))
                .Select(a => new Dictionary<string, object?> { ["bot"] = a.Key, ["ips"] = a.Value.ToList() }).ToList();
            if (ready.Count > 0)
            {
                // A bot with rows still waiting (this minute isn't over) keeps
                // its addresses, so the next batch can be checked as well.
                var waiting = new HashSet<string>(rows.Keys.Select(k => k.Bot));
                agents = agents.Where(a => waiting.Contains(a.Key)).ToDictionary(a => a.Key, a => a.Value);
            }
        }
        var list = ready.Select(p => new Dictionary<string, object?>
        {
            ["minute"] = J.IsoSeconds(p.Key.Minute),
            ["bot"] = p.Key.Bot,
            ["path"] = p.Key.Path,
            ["status"] = p.Key.Status,
            ["count"] = p.Value.Count,
            ["bytes"] = p.Value.Bytes,
            ["sum_ms"] = p.Value.SumMs,
        }).ToList();
        return (list, agentRows);
    }

    public async Task FlushAsync(bool everything = true)
    {
        var (ready, agentRows) = Take(everything);
        for (var i = 0; i < ready.Count; i += MaxRows)
        {
            await core.SendAsync("crawlers", "/events/crawlers", "POST", new Dictionary<string, object?>
            {
                ["server_name"] = ServerName,
                ["runtime"] = Core.Runtime,
                ["rows"] = ready.Skip(i).Take(MaxRows).ToList(),
                ["agents"] = i == 0 ? agentRows : new List<Dictionary<string, object?>>(),
            }).ConfigureAwait(false);
        }
    }

    public Task CloseAsync() => FlushAsync(true);
}
