using System;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace SiteGoose;

/// <summary>The browser check (rule `challenge`, sdk/protocols/firewall.md under
/// "Flood protection"): a GET or HEAD that asks for a page, from an address
/// with no valid pass, gets a small page instead of the site. Its script sets
/// the pass cookie and reloads, which a script that doesn't run JavaScript
/// never does.
///
/// The pass is &lt;day&gt;.&lt;first 32 hex digits of HMAC-SHA256(key, "&lt;day&gt;|&lt;who&gt;")&gt;,
/// key = HMAC-SHA256 of "sg-challenge-v1" keyed with the site secret, so any
/// of the site's servers accepts a pass another one handed out. It counts for
/// its own day and the next. sdk/protocols/challenge-cases.json holds the cases
/// every client runs.</summary>
internal static class Challenge
{
    public const string Cookie = "__sg_pass";
    public const int MaxAge = 86400;
    private static readonly byte[] Label = Encoding.ASCII.GetBytes("sg-challenge-v1");
    private static readonly Regex PassPattern = new("^([0-9]{1,10})\\.([0-9a-f]{32})\\z", RegexOptions.CultureInvariant);

    /// <summary>The key every pass is signed with, from the site secret.</summary>
    public static byte[] PassKey(string? secret) => HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret ?? ""), Label);

    /// <summary>What a pass is bound to: the IPv4 address (an IPv4-mapped IPv6
    /// address as IPv4), or an IPv6 address's /64 as four groups of four
    /// lower-case hex digits. "*" for the agent's nginx (a package never
    /// accepts it); null for anything that isn't an address.</summary>
    public static string? Who(string? ip)
    {
        var text = (ip ?? "").Trim();
        if (text == "*") return "*";
        var address = Ip.Parse(text);
        if (address == null) return null;
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        var bytes = address.GetAddressBytes();
        if (address.AddressFamily == AddressFamily.InterNetwork) return bytes[0] + "." + bytes[1] + "." + bytes[2] + "." + bytes[3];
        var groups = new string[4];
        for (var i = 0; i < 4; i++) groups[i] = ((bytes[2 * i] << 8) | bytes[2 * i + 1]).ToString("x4");
        return string.Join(":", groups);
    }

    /// <summary>Whole days since 1970-01-01 UTC.</summary>
    public static long DayOf(double? now = null) => (long)Math.Floor((now ?? J.UnixNow()) / 86400.0);

    private static string Sign(byte[] key, long day, string bound)
    {
        var mac = HMACSHA256.HashData(key, Encoding.ASCII.GetBytes(day + "|" + bound));
        return Convert.ToHexString(mac).ToLowerInvariant().Substring(0, 32);
    }

    /// <summary>Today's pass for this address, or "" when it isn't one.</summary>
    public static string MakePass(byte[] key, string? ip, double? now = null)
    {
        var bound = Who(ip);
        if (bound == null) return "";
        var day = DayOf(now);
        return day + "." + Sign(key, day, bound);
    }

    /// <summary>True when value is this address's pass for today or yesterday.</summary>
    public static bool IsValid(byte[] key, string? ip, string? value, double? now = null)
    {
        var match = PassPattern.Match(value ?? "");
        var bound = Who(ip);
        if (!match.Success || bound == null || bound == "*") return false;
        if (!long.TryParse(match.Groups[1].Value, out var day)) return false;
        var today = DayOf(now);
        if (day != today && day != today - 1) return false;
        var expected = Encoding.ASCII.GetBytes(Sign(key, day, bound));
        var given = Encoding.ASCII.GetBytes(match.Groups[2].Value);
        return CryptographicOperations.FixedTimeEquals(expected, given);
    }

    /// <summary>Every value the Cookie header carries under name (a browser can
    /// send two, from different paths); at most four, like the Node client.</summary>
    public static List<string> CookieValues(string? cookieHeader, string name = Cookie)
    {
        var found = new List<string>();
        foreach (var part in (cookieHeader ?? "").Split(';'))
        {
            var p = part.Trim();
            var eq = p.IndexOf('=');
            if (eq < 0) continue;
            if (p.Substring(0, eq).Trim() != name) continue;
            found.Add(p.Substring(eq + 1).Trim().Trim('"'));
            if (found.Count == 4) break;
        }
        return found;
    }

    public static bool HasPass(byte[] key, string? ip, string? cookieHeader, double? now = null)
    {
        foreach (var value in CookieValues(cookieHeader))
        {
            if (IsValid(key, ip, value, now)) return true;
        }
        return false;
    }

    /// <summary>The rules' skip prefixes, lower-cased.</summary>
    public static string[] CompileSkip(IEnumerable<string>? entries)
    {
        var list = new List<string>();
        if (entries != null)
        {
            foreach (var entry in entries)
            {
                if (!string.IsNullOrEmpty(entry)) list.Add(entry.ToLowerInvariant());
                if (list.Count == 200) break;
            }
        }
        return list.ToArray();
    }

    /// <summary>Conditions 1 to 3: a GET or HEAD, whose Accept asks for
    /// text/html, for a path (lower-cased, no query string) under none of skip.</summary>
    public static bool AsksForPage(string? method, string? target, string? accept, string[] skip)
    {
        var m = (method ?? "").ToUpperInvariant();
        if (m != "GET" && m != "HEAD") return false;
        if ((accept ?? "").ToLowerInvariant().IndexOf("text/html", StringComparison.Ordinal) < 0) return false;
        var path = (target ?? "");
        var q = path.IndexOf('?');
        if (q >= 0) path = path.Substring(0, q);
        var h = path.IndexOf('#');
        if (h >= 0) path = path.Substring(0, h);
        path = path.ToLowerInvariant();
        foreach (var prefix in skip)
        {
            if (path.StartsWith(prefix, StringComparison.Ordinal)) return false;
        }
        return true;
    }

    private const string PageTemplate = "<!doctype html>\n" +
        "<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n" +
        "<meta name=\"robots\" content=\"noindex\"><title>Just a moment</title>\n" +
        "<style nonce=\"{nonce}\">body{font:16px/1.5 system-ui,sans-serif;margin:0;display:flex;min-height:100vh;align-items:center;justify-content:center;color:#222;background:#fafafa}main{max-width:28rem;padding:2rem;text-align:center}</style>\n" +
        "</head><body><main><p id=\"m\">Checking your browser before you continue&hellip;</p>\n" +
        "<noscript><p>Please turn on JavaScript to continue to this site.</p></noscript></main>\n" +
        "<script nonce=\"{nonce}\">{script}</script>\n" +
        "</body></html>\n";

    /// <summary>The page's script: sets the pass and reloads, but only when
    /// reading the cookie back shows it was set (with cookies off it says so
    /// instead of reloading forever), and at most three times a minute, counted
    /// in sessionStorage, or in a __sg_tries cookie lasting a minute where
    /// storage is blocked or full. Secure only when the browser is on https: it
    /// knows, where the server behind a proxy can only be told. The same
    /// script as the Node, PHP and Python clients'.</summary>
    public static string Script(string value)
    {
        return "(function(){var n=" + JsonSerializer.Serialize(Cookie) + ",v=" + JsonSerializer.Serialize(value) + ",m=document.getElementById(\"m\")," +
               "s=location.protocol===\"https:\";" +
               "document.cookie=n+\"=\"+v+\"; Max-Age=" + MaxAge + "; Path=/; SameSite=Lax\"+(s?\"; Secure\":\"\");" +
               "if((\" \"+document.cookie+\";\").indexOf(\" \"+n+\"=\"+v+\";\")<0){m.textContent=\"Please allow cookies for this site, then reload the page.\";return;}" +
               "var k=\"__sg_tries\",r=0,t;" +
               "try{t=JSON.parse(sessionStorage.getItem(k)||\"[]\").filter(function(x){return Date.now()-x<60000;});r=t.length;if(r<3){t.push(Date.now());sessionStorage.setItem(k,JSON.stringify(t));}}" +
               "catch(e){t=/(?:^|; )__sg_tries=([0-9]+)/.exec(document.cookie);r=t?+t[1]:0;if(r<3)document.cookie=k+\"=\"+(r+1)+\"; Max-Age=60; Path=/; SameSite=Lax\"+(s?\"; Secure\":\"\");}" +
               "if(r>=3){m.textContent=\"This page couldn't be opened because your connection's address keeps changing. Please try again in a minute.\";return;}" +
               "location.reload();})();";
    }

    /// <summary>(503, headers, body) for the check page: its own
    /// Content-Security-Policy with a fresh nonce for its one script, and no
    /// body for a HEAD.</summary>
    public static Answer Page(byte[] key, string? ip, string? method, double? now = null)
    {
        var nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(18)).Replace('+', '-').Replace('/', '_').TrimEnd('=');
        var headers = new List<KeyValuePair<string, string>>
        {
            new("Content-Type", "text/html; charset=utf-8"),
            new("Cache-Control", "no-store"),
            new("X-Robots-Tag", "noindex"),
            new("Content-Security-Policy",
                "default-src 'none'; script-src 'nonce-" + nonce + "'; style-src 'nonce-" + nonce + "'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"),
        };
        if (string.Equals(method, "HEAD", StringComparison.OrdinalIgnoreCase)) return new Answer(503, headers, Array.Empty<byte>());
        var body = PageTemplate.Replace("{nonce}", nonce).Replace("{script}", Script(MakePass(key, ip, now)));
        return new Answer(503, headers, Encoding.UTF8.GetBytes(body));
    }
}

/// <summary>A response the package gives instead of the app's: status, headers, body.</summary>
public sealed class Answer
{
    public Answer(int status, List<KeyValuePair<string, string>> headers, byte[] body)
    {
        Status = status;
        Headers = headers;
        Body = body;
    }

    public int Status { get; }
    public List<KeyValuePair<string, string>> Headers { get; }
    public byte[] Body { get; }
}
