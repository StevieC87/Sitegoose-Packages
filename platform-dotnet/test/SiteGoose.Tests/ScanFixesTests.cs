using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace SiteGoose.Tests;

/// <summary>The fixes from the security scan: long targets, requests another
/// site made the browser send, the browser check's skip, the preview cookie
/// and the form filter.</summary>
public class ScanFixesTests
{
    private const string Blocking = "{\"v\":1,\"enabled\":true,\"mode\":\"block\",\"ban\":{\"seconds\":600},\"rate\":{\"limit\":1,\"window\":60},"
        + "\"probes\":{\"exact\":[\"/.env\"],\"ban\":600},"
        + "\"requests\":{\"rules\":[{\"id\":\"wp.config\",\"action\":\"block\",\"ban\":600,\"path\":{\"contains\":[\"wp-config\"]}}]}}";

    private static Firewall Wall(string rules)
    {
        var wall = new Firewall(Shared.Core());
        wall.RulesNow = Firewall.Compile(Shared.Parse(rules));
        return wall;
    }

    [Theory]
    [InlineData("/.env", "probe")]
    [InlineData("/wp-config.php", "request:wp.config")]
    [InlineData("/", "rate")]
    public void ARequestAnotherSiteMadeIsRefusedButBansNoOne(string path, string rule)
    {
        foreach (var site in new[] { "cross-site", "Same-Site" })
        {
            var wall = Wall(Blocking);
            if (rule == "rate") wall.Check("198.51.100.7", "GET", "/", fetchSite: site);
            var d = wall.Check("198.51.100.7", "GET", path, fetchSite: site);
            Assert.Equal(("block", rule), (d.Action, d.Rule));
            // Reported as only watched, so the collector bans no one elsewhere.
            Assert.Equal("monitor", wall.Queued().Single(r => (string)r["rule"]! == rule)["action"]);
            // And not banned here: an ordinary page from the same address still passes.
            Assert.NotEqual("ban", wall.Check("198.51.100.7", "GET", "/about", fetchSite: "same-origin").Rule);
        }
        foreach (var site in new string?[] { "same-origin", "none", null })
        {
            var wall = Wall(Blocking);
            if (rule == "rate") wall.Check("198.51.100.7", "GET", "/", fetchSite: site);
            Assert.Equal(rule, wall.Check("198.51.100.7", "GET", path, fetchSite: site).Rule);
            Assert.Equal("block", wall.Queued().Single(r => (string)r["rule"]! == rule)["action"]);
            Assert.Equal("ban", wall.Check("198.51.100.7", "GET", "/about").Rule);
        }
    }

    [Fact]
    public void TheMiddlewareCarriesSecFetchSiteToTheFirewall()
    {
        var platform = new Platform(Shared.Options(new FakeCollector()));
        platform.FirewallModule!.RulesNow = Firewall.Compile(Shared.Parse(Blocking));
        string Cross(string name) => name == "sec-fetch-site" ? "cross-site" : "";
        Assert.Equal(403, platform.Blocked("198.51.100.7", Cross, "GET", "/.env")!.Status);
        Assert.Null(platform.Blocked("198.51.100.8", _ => "", "GET", "/about"));
        Assert.Equal(403, platform.Blocked("198.51.100.8", _ => "", "GET", "/.env")!.Status);
        // Only the address the probe came from without the header is banned.
        Assert.Equal("ban", platform.FirewallModule.Check("198.51.100.8", "GET", "/x").Rule);
        Assert.NotEqual("ban", platform.FirewallModule.Check("198.51.100.7", "GET", "/x").Rule);
    }

    [Fact]
    public void ARegexIsSearchedInWindowsAndItsAnchorsKeepToTheEnds()
    {
        var rules = RequestRules.Compile(Shared.Parse("{\"rules\":["
            + "{\"id\":\"start\",\"action\":\"block\",\"path\":{\"regex\":\"^/admin\"}},"
            + "{\"id\":\"end\",\"action\":\"block\",\"path\":{\"regex\":\"\\\\.php$\"}},"
            + "{\"id\":\"inside\",\"action\":\"block\",\"query\":{\"regex\":\"union\\\\s+select\"}}]}"));
        // A window starting at 1,000 begins with /admin, but ^ is the path's start.
        Assert.Null(RequestRules.Match(rules, "GET", "/" + new string('a', 999) + "/admin/x", ""));
        Assert.Equal("start", RequestRules.Match(rules, "GET", "/admin/" + new string('a', 3000), "")?.Id);
        // The first window ends in .php, but $ is the path's end.
        Assert.Null(RequestRules.Match(rules, "GET", "/" + new string('a', 1995) + ".php/" + new string('b', 500), ""));
        Assert.Equal("end", RequestRules.Match(rules, "GET", "/" + new string('a', 4321) + "/x.php", "")?.Id);
        // Past the first 2,000 characters, and across a window's edge.
        Assert.Equal("inside", RequestRules.Match(rules, "GET", "/?pad=" + new string('x', 5000) + "&q=1 union select 2", "")?.Id);
        Assert.Equal("inside", RequestRules.Match(rules, "GET", "/?" + new string('x', 1990) + "union select", "")?.Id);
    }

    [Fact]
    public void TheRoutedPathIsResolvedFromTheWholePath()
    {
        var padded = "/" + string.Concat(Enumerable.Repeat("./", 1100)) + "login";
        Assert.Equal("/login", RequestRules.NormalizeTarget(padded));
        Assert.Equal("/login", new RequestRules.Prepared("POST", padded + "?x=1#y", "").RoutedPath);
        var probes = Firewall.CompileProbes(Shared.Parse("{\"exact\":[\"/.env\"]}"));
        Assert.True(Firewall.IsProbe("/" + string.Concat(Enumerable.Repeat("./", 1100)) + ".env", probes));
    }

    [Fact]
    public void TheBrowserCheckSkipsOnlyWhatTheRouterServesUnderSkip()
    {
        var skip = Challenge.CompileSkip(new[] { "/api/" });
        Assert.False(Challenge.AsksForPage("GET", "/api/orders", "text/html", skip));
        Assert.False(Challenge.AsksForPage("GET", "/API/orders?x=1", "text/html", skip));
        // Sent under /api/, served as /admin.
        Assert.True(Challenge.AsksForPage("GET", "/api/../admin", "text/html", skip));
        Assert.True(Challenge.AsksForPage("GET", "/api/%2e%2e/admin", "text/html", skip));
        Assert.True(Challenge.AsksForPage("GET", "/api/x/..;/../admin", "text/html", skip));
        Assert.True(Challenge.AsksForPage("GET", "/admin", "text/html", skip));
    }

    [Fact]
    public async Task ThePreviewCookieIsSecureOnHttps()
    {
        var collector = new FakeCollector(_ => FakeCollector.Reply(200, "{\"v\":1,\"sync\":90,\"modules\":{},\"maintenance\":{\"on\":true,\"bypass\":\"letmein\"}}"));
        var platform = new Platform(Shared.Options(collector));
        await platform.Core.SyncSwitchesAsync();
        Assert.NotNull(platform.MaintenanceResponse("203.0.113.9", _ => "", "/", "?site_preview=letmein", true)?.RememberCookie);
        var middleware = new PlatformMiddleware(_ => Task.CompletedTask, platform);
        foreach (var https in new[] { true, false })
        {
            var context = new DefaultHttpContext();
            context.Connection.RemoteIpAddress = IPAddress.Parse("203.0.113.9");
            context.Request.Method = "GET";
            context.Request.Scheme = https ? "https" : "http";
            context.Request.Path = "/";
            context.Request.QueryString = new QueryString("?site_preview=letmein");
            context.Response.Body = new MemoryStream();
            var cookie = "";
            context.Features.Set<Microsoft.AspNetCore.Http.Features.IHttpResponseFeature>(new StartingResponse(context.Response.Body, () => cookie = context.Response.Headers.SetCookie.ToString()));
            await middleware.InvokeAsync(context);
            Assert.Equal(200, context.Response.StatusCode);
            await ((StartingResponse)context.Features.Get<Microsoft.AspNetCore.Http.Features.IHttpResponseFeature>()!).StartAsync();
            Assert.StartsWith("site_preview=letmein;", cookie);
            Assert.Equal(https, cookie.EndsWith("; Secure", StringComparison.Ordinal));
        }
        await platform.CloseAsync();
    }

    /// <summary>A response feature that runs its OnStarting callbacks when asked.</summary>
    private sealed class StartingResponse : Microsoft.AspNetCore.Http.Features.HttpResponseFeature
    {
        private readonly System.Collections.Generic.List<(Func<object, Task> Call, object State)> starting = new();
        private readonly Action after;

        public StartingResponse(Stream body, Action after)
        {
            Body = body;
            this.after = after;
        }

        public override void OnStarting(Func<object, Task> callback, object state) => starting.Add((callback, state));

        public async Task StartAsync()
        {
            for (var i = starting.Count - 1; i >= 0; i--) await starting[i].Call(starting[i].State);
            after();
        }
    }

    [Fact]
    public void PrivateFormFieldsAndCardNumbersAreNeverSent()
    {
        var form = new[] { "password", "user_pwd", "passwd", "card_number", "cc_num", "cc-number", "cc-csc", "cc-exp", "api-key", "cvn", "exp_month", "expiry", "otp", "mfa_code", "2fa",
            "pin", "auth", "authorization", "api_key", "security_code", "iban", "bic", "routing_number", "account_no", "ssn", "sin", "tax_id",
            "dob", "birth_date", "licence", "license_key", "nonce", "csrf_token", "signature", "private_note", "analytics-shield" };
        var kept = new[] { "email", "name", "message", "spinner", "author", "company" };
        var fields = form.Concat(kept).Select(n => new System.Collections.Generic.KeyValuePair<string, string[]>(n, new[] { "x" }));
        Assert.Equal(kept.OrderBy(k => k), Forms.PlainFields(fields).Keys.OrderBy(k => k));
        Assert.Equal("my card [removed], thanks", Forms.WithoutCardNumbers("my card 4111 1111 1111 1111, thanks"));
        Assert.Equal("[removed]", Forms.WithoutCardNumbers("4111-1111-1111-1111"));
        // Not Luhn: an order or a phone number stays.
        Assert.Equal("order 4111111111111112", Forms.WithoutCardNumbers("order 4111111111111112"));
        Assert.Equal("call +44 20 7946 0958", Forms.WithoutCardNumbers("call +44 20 7946 0958"));
        var message = Forms.PlainFields(new[] { new System.Collections.Generic.KeyValuePair<string, string[]>("message", new[] { "pay with 5555555555554444 please" }) });
        Assert.Equal("pay with [removed] please", message["message"]);
    }
}
