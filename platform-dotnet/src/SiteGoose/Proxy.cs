using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace SiteGoose;

/// <summary>First-party proxy: serving the tracker from the site's own domain,
/// so ad blockers don't hide visitors.
///
///     &lt;prefix&gt;/js/&lt;rest&gt;   ->  &lt;endpoint&gt;/&lt;rest&gt;                  (tracker files)
///     &lt;prefix&gt;/api/&lt;rest&gt;  ->  &lt;endpoint&gt;/collectanalytics/&lt;rest&gt; (the collector)
///
/// The prefix comes from the site secret: not guessable from the page, and the
/// same every time, so a browser's cache and a CDN in front stay valid. It
/// answers before every other module: a visitor's beacon is our own traffic,
/// not a page of the site, so it isn't counted, timed or rate-limited.</summary>
public sealed class Proxy
{
    // The tracker files, by name: anything else is refused rather than forwarded.
    internal static readonly HashSet<string> Files = new(StringComparer.Ordinal)
    {
        "track.js", "s.js", "snapshot.js", "replay.js", "survey.js", "banner.js",
        "leadform.js", "notice.js", "editor.js", "picker.js", "feedback.js", "shield.js",
        "widget.js", "share.js",
    };

    // A pinned version never changes; /v<major>/ follows new releases, so it is
    // held for an hour, the same as the collector serves it with.
    internal const int TtlPinnedS = 7 * 24 * 60 * 60;
    internal const int TtlMajorS = 60 * 60;
    internal const int MaxBody = 6 * 1024 * 1024;
    // A visitor's page waits on these: short, and after a failure the
    // collector isn't asked again for a while, so a collector that has gone
    // quiet costs each request nothing rather than seconds.
    internal static TimeSpan Timeout = TimeSpan.FromSeconds(2);
    internal const int BreakerSeconds = 30;
    // The collector reads these; everything else, cookies above all, stays here.
    internal static readonly string[] PassHeaders =
    {
        "Content-Type", "User-Agent", "Accept-Language", "Referer", "Origin",
        "Sec-Fetch-Site", "Sec-Ch-Ua", "Sec-Ch-Ua-Mobile", "Sec-Ch-Ua-Platform",
    };

    private static readonly Regex SafePath = new("^[A-Za-z0-9/_.-]{1,120}\\z", RegexOptions.CultureInvariant);
    private static readonly Regex FilePath = new("^v([0-9]+(?:\\.[0-9]+\\.[0-9]+)?)/([a-z]+\\.js)\\z", RegexOptions.CultureInvariant);
    private static readonly Regex PrefixChars = new("[^A-Za-z0-9_-]", RegexOptions.CultureInvariant);

    private readonly Core core;
    private readonly bool enabled;
    // One copy of each tracker file, so a repeat visitor costs no upstream
    // request. A handful of small files: it never grows.
    private readonly ConcurrentDictionary<string, (byte[] Body, double At)> files = new();
    // A file the collector didn't have, not asked for again for a minute
    // (a few hundred names at most: any version can be asked for).
    private readonly ConcurrentDictionary<string, double> missing = new();
    internal const int MissingFor = 60;
    // Until when the collector is left alone after it failed (unix seconds).
    private double breakerUntil;

    internal bool Resting => Volatile.Read(ref breakerUntil) > J.UnixNow();

    private void Rest() => Volatile.Write(ref breakerUntil, J.UnixNow() + BreakerSeconds);

    internal Proxy(Core core, string? prefix = null, bool enabled = true)
    {
        this.core = core;
        this.enabled = enabled;
        Prefix = PrefixChars.Replace(string.IsNullOrEmpty(prefix) ? PrefixFor(core.Secret) : prefix!, "");
        Key = core.Secret.Length > 0 ? KeyFor(core.Secret) : "";
    }

    /// <summary>The path it answers on.</summary>
    public string Prefix { get; }

    internal string Key { get; }

    internal static string PrefixFor(string secret) => Hex(SHA256.HashData(Encoding.UTF8.GetBytes("proxy|" + secret))).Substring(0, 8);

    // Sent as X-Proxy-Key, so the collector believes the visitor addresses this
    // proxy passes on: anyone can write X-Forwarded-For. Worked out from the
    // secret as the collector does (expresscollect/utils/proxyKey.js).
    internal static string KeyFor(string secret) => Hex(SHA256.HashData(Encoding.UTF8.GetBytes("proxykey|" + secret))).Substring(0, 32);

    private static string Hex(byte[] bytes) => Convert.ToHexString(bytes).ToLowerInvariant();

    internal bool On => enabled && core.Valid && Prefix.Length > 0 && core.IsOn("proxy");

    /// <summary>The tracker's address on this site, for the page's script tag.</summary>
    public string ScriptUrl(string version = "1") => "/" + Prefix + "/js/v" + version + "/s.js";

    /// <summary>Where visits are sent, for the tag's data-collect.</summary>
    public string CollectUrl() => "/" + Prefix + "/api/e";

    /// <summary>("js" | "api", the rest) when the address is ours, ("bad", "") for
    /// one under the prefix that is neither, else null.</summary>
    internal (string Kind, string Tail)? Match(string? path)
    {
        if (!On || path == null) return null;
        var head = "/" + Prefix + "/";
        if (!path.StartsWith(head, StringComparison.Ordinal)) return null;
        var rest = path.Substring(head.Length);
        foreach (var kind in new[] { "js", "api" })
        {
            if (rest.StartsWith(kind + "/", StringComparison.Ordinal))
            {
                var tail = rest.Substring(kind.Length + 1);
                if (tail.Length > 0 && !tail.Contains("..") && SafePath.IsMatch(tail)) return (kind, tail);
                break;
            }
        }
        return ("bad", "");
    }

    /// <summary>What a collector answer may be served as from the site's own domain. Its type comes
    /// from the collector, so anything else becomes plain text, and nosniff stops a browser guessing:
    /// a server that is no longer ours still can't answer <c>&lt;prefix&gt;/api/…</c> with a page that
    /// runs as the customer's own site. Shared cases: sdk/protocols/proxy-answer-cases.json.</summary>
    internal static readonly HashSet<string> AnswerTypes = new(StringComparer.OrdinalIgnoreCase) { "application/json", "text/plain", "image/webp" };

    internal static string AnswerType(string? value)
    {
        var given = value ?? "";
        var kind = given.Split(';', 2)[0].Trim();
        return AnswerTypes.Contains(kind) && given.All(c => c >= 0x20 && c <= 0x7e) ? given : "text/plain; charset=utf-8";
    }

    internal static Answer NotFound() => new(404, new List<KeyValuePair<string, string>> { new("Content-Type", "text/plain; charset=utf-8") }, Encoding.UTF8.GetBytes("Not found"));

    private static Answer Empty(int status) => new(status, new List<KeyValuePair<string, string>>(), Array.Empty<byte>());

    internal async Task<Answer> HandleAsync(string kind, string rest, string method, string? query, Func<string, string> header, byte[]? body, string clientIp)
    {
        if (kind == "js") return await FileAsync(rest).ConfigureAwait(false);
        if (kind != "api") return NotFound();
        return await CollectorAsync(rest, method, query, header, body, clientIp).ConfigureAwait(false);
    }

    private async Task<Answer> FileAsync(string rest)
    {
        var found = FilePath.Match(rest);
        if (!found.Success || !Files.Contains(found.Groups[2].Value)) return NotFound();
        var pinned = found.Groups[1].Value.Contains('.');
        var now = J.UnixNow();
        byte[]? body = null;
        var hasHeld = files.TryGetValue(rest, out var held);
        if (hasHeld && held.At > now - (pinned ? TtlPinnedS : TtlMajorS)) body = held.Body;
        if (body == null && !Resting && !(missing.TryGetValue(rest, out var gone) && gone > now - MissingFor))
        {
            try
            {
                using var timeout = new CancellationTokenSource(Timeout);
                using var answer = await core.HttpFollow.GetAsync(core.Endpoint + "/" + rest, HttpCompletionOption.ResponseHeadersRead, timeout.Token).ConfigureAwait(false);
                if ((int)answer.StatusCode >= 500) Rest();
                else if (!answer.IsSuccessStatusCode && (missing.Count < 300 || missing.ContainsKey(rest))) missing[rest] = now;
                if (answer.IsSuccessStatusCode)
                {
                    missing.TryRemove(rest, out _);
                    var fetched = await ReadLimited(await answer.Content.ReadAsStreamAsync(timeout.Token).ConfigureAwait(false), MaxBody, timeout.Token).ConfigureAwait(false);
                    if (fetched.Length > 500)
                    {
                        body = fetched;
                        files[rest] = (body, now);
                    }
                }
            }
            catch (Exception error)
            {
                Rest();
                core.Log("proxy", "could not fetch " + rest + ": " + error.Message);
            }
        }
        // Upstream is unreachable: an old copy beats no tracker at all.
        if (body == null && hasHeld) body = held.Body;
        if (body == null) return Empty(502);
        return new Answer(200, new List<KeyValuePair<string, string>>
        {
            new("Content-Type", "application/javascript; charset=utf-8"),
            new("Cache-Control", pinned ? "public, max-age=31536000, immutable" : "public, max-age=3600"),
            new("X-Content-Type-Options", "nosniff"),
        }, body);
    }

    internal static async Task<byte[]> ReadLimited(Stream stream, int max, CancellationToken cancel)
    {
        using var buffer = new MemoryStream();
        var chunk = new byte[16384];
        int read;
        while ((read = await stream.ReadAsync(chunk.AsMemory(0, chunk.Length), cancel).ConfigureAwait(false)) > 0)
        {
            buffer.Write(chunk, 0, Math.Min(read, (int)Math.Max(0, max - buffer.Length)));
            if (buffer.Length >= max) break;
        }
        return buffer.ToArray();
    }

    private async Task<Answer> CollectorAsync(string rest, string method, string? query, Func<string, string> header, byte[]? body, string clientIp)
    {
        var m = (string.IsNullOrEmpty(method) ? "GET" : method).ToUpperInvariant();
        if (m == "OPTIONS")
        {
            // Same origin as the page, so a preflight shouldn't happen; answer
            // it cheaply rather than passing it on.
            return new Answer(204, new List<KeyValuePair<string, string>>
            {
                new("Access-Control-Allow-Methods", "GET, POST, OPTIONS"),
                new("Access-Control-Allow-Headers", "Content-Type"),
                new("Access-Control-Max-Age", "86400"),
            }, Array.Empty<byte>());
        }
        if (m != "GET" && m != "POST") return NotFound();
        if (body != null && body.Length > MaxBody) return Empty(413);
        // The tracker treats a failed beacon as lost: answered at once while the collector rests.
        if (Resting) return Empty(502);
        var q = (query ?? "").TrimStart('?');
        var url = core.Endpoint + "/collectanalytics/" + rest + (q.Length > 0 ? "?" + q : "");
        try
        {
            using var request = new HttpRequestMessage(m == "POST" ? HttpMethod.Post : HttpMethod.Get, url);
            // The visitor's address: the collector needs it for the country, the
            // daily visitor ID and the per-visitor rate limit.
            request.Headers.TryAddWithoutValidation("X-Forwarded-For", clientIp ?? "");
            if (Key.Length > 0) request.Headers.TryAddWithoutValidation("X-Proxy-Key", Key);
            if (m == "POST") request.Content = new ByteArrayContent(body ?? Array.Empty<byte>());
            foreach (var name in PassHeaders)
            {
                var value = (header(name) ?? "").Replace("\r", "").Replace("\n", "");
                if (value.Length == 0) continue;
                if (name == "Content-Type")
                {
                    if (request.Content != null) request.Content.Headers.TryAddWithoutValidation(name, value);
                }
                else
                {
                    request.Headers.TryAddWithoutValidation(name, value);
                }
            }
            using var timeout = new CancellationTokenSource(Timeout);
            using var answer = await core.Http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token).ConfigureAwait(false);
            if ((int)answer.StatusCode is 502 or 503 or 504) Rest();
            var bytes = await ReadLimited(await answer.Content.ReadAsStreamAsync(timeout.Token).ConfigureAwait(false), MaxBody, timeout.Token).ConfigureAwait(false);
            var all = Core.HeadersOf(answer);
            var headers = new List<KeyValuePair<string, string>>
            {
                new("Content-Type", AnswerType(all.TryGetValue("Content-Type", out var type) ? type : null)),
                new("X-Content-Type-Options", "nosniff"),
            };
            foreach (var name in new[] { "Cache-Control", "Retry-After" })
            {
                if (all.TryGetValue(name, out var value) && value.Length > 0) headers.Add(new KeyValuePair<string, string>(name, value));
            }
            return new Answer((int)answer.StatusCode, headers, bytes);
        }
        catch (Exception error)
        {
            // The tracker already treats a failed beacon as lost and carries on.
            Rest();
            core.Log("proxy", "could not reach the collector: " + error.Message);
            return Empty(502);
        }
    }
}
