using System;
using System.Collections.Generic;
using System.Net;
using System.Text;
using Microsoft.AspNetCore.WebUtilities;

namespace SiteGoose;

/// <summary>What maintenance mode decided: let the request through, let it
/// through and remember the preview link (a cookie), or the page.</summary>
internal sealed class MaintenanceDecision
{
    public string? RememberCookie;
    public Answer? Page;
}

/// <summary>Maintenance mode module: while it's on (Site settings -> Server),
/// visitors get a "back soon" page (503, so search engines know it's
/// temporary), except allowed addresses and whoever opened the preview link
/// (?site_preview=&lt;code&gt;, remembered for a day in a cookie).</summary>
internal sealed class Maintenance
{
    public const string Cookie = "site_preview";
    private readonly Core core;
    private List<string>? allowFor;
    private IpSet allow = IpSet.Empty;

    public Maintenance(Core core, Func<string, bool>? skip = null)
    {
        this.core = core;
        Skip = skip;
    }

    public Func<string, bool>? Skip { get; }

    public static byte[] PageBody(string? message)
    {
        var text = WebUtility.HtmlEncode(string.IsNullOrEmpty(message) ? "We're doing some maintenance. Please check back in a few minutes." : message);
        return Encoding.UTF8.GetBytes("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">" +
            "<title>Back soon</title><style>body{margin:0;min-height:100vh;display:grid;place-items:center;font:16px/1.5 system-ui,sans-serif;" +
            "background:#f8fafc;color:#0f172a}main{max-width:32rem;padding:2rem;text-align:center}h1{font-size:1.6rem;margin:0 0 .5rem}" +
            "p{color:#475569;margin:0}@media(prefers-color-scheme:dark){body{background:#0f172a;color:#e2e8f0}p{color:#94a3b8}}</style></head>" +
            "<body><main><h1>Back soon</h1><p>" + text + "</p></main></body></html>");
    }

    /// <summary>Null to let the request through, else what to do. https: the
    /// visitor is on HTTPS, so the cookie holding the code is Secure and never
    /// sent over a plain-http request someone else made the browser send.</summary>
    public MaintenanceDecision? Decide(string ip, string path, string? query, string? cookieHeader, bool https = false)
    {
        var m = core.IsOn("maintenance") ? core.Maintenance : null;
        if (m == null || !m.On || (Skip != null && Skip(path))) return null;
        if (!ReferenceEquals(allowFor, m.Allow))
        {
            allowFor = m.Allow;
            allow = new IpSet(m.Allow);
        }
        var key = Ip.Key(ip);
        if (key != null && allow.Has(key.Value)) return null;
        var code = m.Bypass;
        if (code.Length > 0)
        {
            var given = QueryHelpers.ParseQuery(query ?? "");
            if (given.TryGetValue(Cookie, out var values) && values.Count > 0 && values[0] == code)
            {
                return new MaintenanceDecision { RememberCookie = Cookie + "=" + code + "; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax" + (https ? "; Secure" : "") };
            }
            foreach (var value in Challenge.CookieValues(cookieHeader, Cookie))
            {
                if (value == code) return null;
            }
        }
        return new MaintenanceDecision
        {
            Page = new Answer(503, new List<KeyValuePair<string, string>>
            {
                new("Content-Type", "text/html; charset=utf-8"),
                new("Retry-After", "600"),
                new("Cache-Control", "no-store"),
            }, PageBody(m.Message)),
        };
    }
}
