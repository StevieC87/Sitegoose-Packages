using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace SiteGoose.Tests;

/// <summary>The fixes from the package's review: addresses through proxies,
/// what counts as an error, shutdown and the waiting file, and the limits.</summary>
public class ReviewFixesTests
{
    private static Func<string, string> Headers(params (string Name, string Value)[] pairs) =>
        name => pairs.Where(p => string.Equals(p.Name, name, StringComparison.OrdinalIgnoreCase)).Select(p => p.Value).FirstOrDefault() ?? "";

    private static Platform Make(FakeCollector collector, string rules, Action<PlatformOptions>? more = null)
    {
        var platform = new Platform(Shared.Options(collector, more));
        platform.FirewallModule!.RulesNow = Firewall.Compile(Shared.Parse(rules));
        return platform;
    }

    private static DefaultHttpContext Request(string ip, string method = "GET", string path = "/")
    {
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = IPAddress.Parse(ip);
        context.Request.Method = method;
        context.Request.Path = path;
        context.Request.Headers.Accept = "*/*";
        context.Response.Body = new MemoryStream();
        return context;
    }

    private static Exception Thrown()
    {
        try
        {
            throw new InvalidOperationException("x");
        }
        catch (Exception error)
        {
            return error;
        }
    }

    // ---- Addresses ----

    [Fact]
    public void PortsAProxyAddsAreDropped()
    {
        Assert.Equal("1.2.3.4", Ip.StripPort("1.2.3.4:56789"));
        Assert.Equal("2001:db8::1", Ip.StripPort("[2001:db8::1]:443"));
        Assert.Equal("2001:db8::1", Ip.StripPort("[2001:db8::1]"));
        Assert.Equal("2001:db8::1", Ip.StripPort("2001:db8::1"));
        Assert.Equal("1.2.3.4", Firewall.ResolveClientIp("10.0.0.1", Headers(("x-forwarded-for", "1.2.3.4:56789")), "1"));
        Assert.Equal("2001:db8::1", Firewall.ResolveClientIp("10.0.0.1", Headers(("x-forwarded-for", "[2001:db8::1]:443")), "1"));
        Assert.Equal("198.51.100.7", Firewall.ResolveClientIp("172.64.1.2", Headers(("cf-connecting-ip", "198.51.100.7:1234")), "cloudflare"));
    }

    [Fact]
    public void AnAddressThatIsntOneGivesTheConnections()
    {
        Assert.Equal("203.0.113.5", Firewall.ResolveClientIp("203.0.113.5", Headers(("x-forwarded-for", "not-an-ip")), "1"));
        Assert.Equal("203.0.113.5", Firewall.ResolveClientIp("203.0.113.5", _ => "", null, _ => "garbage"));
        Assert.Equal("203.0.113.5", Firewall.ResolveClientIp("203.0.113.5", Headers(("x-forwarded-for", "6.6.6.6")), "aspnetcore"));
        Assert.Equal("203.0.113.9", Firewall.ResolveClientIp("10.0.0.1", Headers(("x-forwarded-for", "::ffff:203.0.113.9")), "1"));
    }

    [Fact]
    public async Task XForwardedForIsReadAsItArrivedNotAsForwardedHeadersLeftIt()
    {
        var platform = Make(new FakeCollector(), "{\"v\":1,\"enabled\":true,\"mode\":\"block\",\"deny\":[\"198.51.100.66\"]}", o => o.TrustProxy = "1");
        var middleware = new PlatformMiddleware(_ => Task.CompletedTask, platform);
        // What ForwardedHeadersMiddleware leaves: the connection rewritten to
        // the visitor, the entry it believed taken off, only the forged one left.
        var context = Request("198.51.100.66");
        context.Request.Headers["X-Forwarded-For"] = "6.6.6.6";
        context.Request.Headers["X-Original-For"] = "10.0.0.1:5000";
        context.Items[Arrival.Item] = new Arrival { Remote = "10.0.0.1", ForwardedFor = "6.6.6.6, 198.51.100.66" };
        Assert.Equal("198.51.100.66", platform.RequestIp(context));
        await middleware.InvokeAsync(context);
        Assert.Equal(403, context.Response.StatusCode);
        // "aspnetcore": the connection as the middleware left it.
        var asp = Make(new FakeCollector(), "{\"v\":1,\"enabled\":true,\"mode\":\"block\"}", o => o.TrustProxy = "aspnetcore");
        Assert.Equal("198.51.100.66", asp.RequestIp(context));
        await platform.CloseAsync();
        await asp.CloseAsync();
    }

    [Fact]
    public void RatesAndBansCountAnIpv6Slash64AsOne()
    {
        Assert.Equal("2001:db8:1:2::/64", Ip.CounterKey("2001:db8:1:2:aaaa::1"));
        Assert.Equal("203.0.113.9", Ip.CounterKey("::ffff:203.0.113.9"));
        var wall = new Firewall(Shared.Core());
        wall.RulesNow = Firewall.Compile(Shared.Parse("{\"v\":1,\"enabled\":true,\"mode\":\"block\",\"rate\":{\"limit\":2,\"window\":60},\"ban\":{\"seconds\":600}}"));
        Assert.Equal("", wall.Check("2001:db8:1:2::1", "GET", "/").Rule);
        Assert.Equal("", wall.Check("2001:db8:1:2::2", "GET", "/").Rule);
        Assert.Equal("rate", wall.Check("2001:db8:1:2::3", "GET", "/").Rule);
        Assert.Equal("ban", wall.Check("2001:db8:1:2::ffff", "GET", "/").Rule);
        Assert.Equal("", wall.Check("2001:db8:1:3::1", "GET", "/").Rule);
        // Reported as IPv4 when it came mapped.
        wall.RulesNow = Firewall.Compile(Shared.Parse("{\"v\":1,\"enabled\":true,\"mode\":\"block\",\"deny\":[\"203.0.113.9\"]}"));
        wall.Check("::ffff:203.0.113.9", "GET", "/");
        Assert.Contains(wall.Queued(), r => (string?)r["ip"] == "203.0.113.9");
    }

    [Fact]
    public void StaticFilesDontCountTowardTheRate()
    {
        var wall = new Firewall(Shared.Core());
        wall.RulesNow = Firewall.Compile(Shared.Parse("{\"v\":1,\"enabled\":true,\"mode\":\"block\",\"rate\":{\"limit\":1,\"window\":60}}"));
        Assert.Equal("", wall.Check("203.0.113.9", "GET", "/").Rule);
        foreach (var asset in new[] { "/site.css", "/app.js?v=3", "/img/logo.PNG", "/fonts/a.woff2" }) Assert.Equal("", wall.Check("203.0.113.9", "GET", asset).Rule);
        Assert.Equal("rate", wall.Check("203.0.113.9", "GET", "/about").Rule);
    }

    // Tricks that would make a page read as a static file, so a flood of them
    // skips the rate and the page limits, and real assets: the cases every
    // package shares (sdk/protocols/static-cases.json, firewall.md, `rate`).
    private static readonly (string Path, string Method, bool Static)[] StaticCases = Shared.Load("static-cases.json").GetProperty("cases").EnumerateArray()
        .Where(c => !c.TryGetProperty("only", out var only) || only.EnumerateArray().Any(p => p.GetString() == "dotnet"))
        .Select(c => (c.GetProperty("path").GetString()!, c.TryGetProperty("method", out var m) ? m.GetString()! : "GET", c.GetProperty("static").GetBoolean())).ToArray();

    public static readonly (string Path, string Method)[] NotStatic = StaticCases.Where(c => !c.Static).Select(c => (c.Path, c.Method)).ToArray();

    // Real assets: none counts.
    public static readonly (string Path, string Method)[] Static = StaticCases.Where(c => c.Static).Select(c => (c.Path, c.Method)).ToArray();

    [Fact]
    public void StaticFileTricksCountTowardTheRateAndPageLimits()
    {
        foreach (var (target, method) in NotStatic) Assert.False(Firewall.IsStaticAsset(target, method), method + " " + target);
        foreach (var (target, method) in Static) Assert.True(Firewall.IsStaticAsset(target, method), method + " " + target);
        var rate = new Firewall(Shared.Core());
        rate.RulesNow = Firewall.Compile(Shared.Parse("{\"v\":1,\"enabled\":true,\"mode\":\"block\",\"rate\":{\"limit\":1,\"window\":60}}"));
        var limits = new Firewall(Shared.Core());
        limits.RulesNow = Firewall.Compile(Shared.Parse("{\"v\":1,\"enabled\":true,\"mode\":\"block\",\"limits\":{\"rules\":[{\"id\":\"all\",\"action\":\"block\",\"limit\":1,\"window\":60,\"path\":{\"prefix\":[\"/\"]}}]}}"));
        var all = NotStatic.Concat(Static).ToArray();
        for (var i = 0; i < all.Length; i++)
        {
            var ip = "203.0.113." + (i + 1);
            var counted = i < NotStatic.Length;
            var (target, method) = all[i];
            rate.Check(ip, method, target);
            Assert.True((counted ? "rate" : "") == rate.Check(ip, method, target).Rule, "rate, " + target);
            limits.Check(ip, method, target);
            Assert.True((counted ? "limit:all" : "") == limits.Check(ip, method, target).Rule, "page limit, " + target);
        }
    }

    [Fact]
    public async Task ADeniedAddressIsntProxiedToTheCollector()
    {
        var collector = new FakeCollector(_ => FakeCollector.Reply(204, ""));
        var platform = Make(collector, "{\"v\":1,\"enabled\":true,\"mode\":\"block\",\"deny\":[\"203.0.113.5\"]}");
        var middleware = new PlatformMiddleware(_ => Task.CompletedTask, platform);
        var context = Request("203.0.113.5", "POST", platform.Proxy!.CollectUrl());
        await middleware.InvokeAsync(context);
        Assert.Equal(403, context.Response.StatusCode);
        Assert.Empty(collector.Requests);
        var allowed = Request("198.51.100.1", "POST", platform.Proxy!.CollectUrl());
        await middleware.InvokeAsync(allowed);
        Assert.Equal(204, allowed.Response.StatusCode);
        await platform.CloseAsync();
    }

    [Fact]
    public async Task AQuietCollectorRestsTheProxy()
    {
        var collector = new FakeCollector(_ => throw new HttpRequestException("unreachable"));
        var proxy = new Proxy(Shared.Core(collector, "test-secret"));
        Assert.Equal(502, (await proxy.HandleAsync("api", "e", "POST", "", _ => "", new byte[] { 1 }, "198.51.100.4")).Status);
        Assert.True(proxy.Resting);
        Assert.Equal(502, (await proxy.HandleAsync("api", "e", "POST", "", _ => "", new byte[] { 1 }, "198.51.100.4")).Status);
        Assert.Equal(502, (await proxy.HandleAsync("js", "v1/s.js", "GET", "", _ => "", null, "198.51.100.4")).Status);
        Assert.Single(collector.Requests);
        // A file the collector doesn't have isn't asked for again straight away.
        var missing = new FakeCollector(_ => FakeCollector.Reply(404, "{}"));
        var other = new Proxy(Shared.Core(missing, "test-secret"));
        await other.HandleAsync("js", "v9.9.9/s.js", "GET", "", _ => "", null, "x");
        await other.HandleAsync("js", "v9.9.9/s.js", "GET", "", _ => "", null, "x");
        Assert.Single(missing.Requests);
    }

    // ---- What counts as an error ----

    [Fact]
    public async Task AnExceptionTheHandlerAnsweredAs404IsntAnError()
    {
        var platform = Make(new FakeCollector(), "{\"v\":1,\"enabled\":true,\"mode\":\"monitor\"}");
        var middleware = new PlatformMiddleware(c =>
        {
            c.Features.Set<IExceptionHandlerFeature>(new ExceptionHandlerFeature { Error = new KeyNotFoundException("no such order"), Path = "/orders/9" });
            c.Response.StatusCode = 404;
            return Task.CompletedTask;
        }, platform);
        await middleware.InvokeAsync(Request("198.51.100.1", path: "/orders/9"));
        Assert.Empty(platform.ErrorsModule!.Queued());
        await platform.CloseAsync();
    }

    [Fact]
    public async Task ABadRequestOrAVisitorWhoLeftIsntAnError()
    {
        var platform = Make(new FakeCollector(), "{\"v\":1,\"enabled\":true,\"mode\":\"monitor\"}");
        var tooLarge = new PlatformMiddleware(_ => throw new BadHttpRequestException("Request body too large.", 413), platform);
        await Assert.ThrowsAsync<BadHttpRequestException>(() => tooLarge.InvokeAsync(Request("198.51.100.1", "POST", "/upload")));
        using var aborted = new CancellationTokenSource();
        aborted.Cancel();
        var reset = new PlatformMiddleware(_ => throw new IOException("Connection reset by peer"), platform);
        var context = Request("198.51.100.1", path: "/stream");
        context.RequestAborted = aborted.Token;
        await Assert.ThrowsAsync<IOException>(() => reset.InvokeAsync(context));
        Assert.Empty(platform.ErrorsModule!.Queued());
        var rows = platform.PerformanceModule!.Take(true);
        Assert.Contains(rows, r => (string?)r["route"] == "/upload" && (int)r["status"]! == 413);
        Assert.Contains(rows, r => (string?)r["route"] == "/stream" && (int)r["status"]! == 499);
        await platform.CloseAsync();
    }

    [Fact]
    public async Task AnErrorAfterTheRequestEndedKeepsItsOwnRequest()
    {
        var platform = Make(new FakeCollector(), "{\"v\":1,\"enabled\":true,\"mode\":\"monitor\"}");
        Scope? kept = null;
        var middleware = new PlatformMiddleware(_ =>
        {
            kept = Scope.Current;
            return Task.CompletedTask;
        }, platform);
        var context = Request("198.51.100.1", path: "/orders/5");
        context.Request.Headers["X-Analytics-Session"] = "visit-1";
        await middleware.InvokeAsync(context);
        // The connection's next request reuses the context.
        context.Request.Path = "/admin";
        context.Request.Headers["X-Analytics-Session"] = "visit-2";
        var fields = kept!.Fields()!;
        Assert.Equal("/orders/5", fields.Path);
        Assert.Equal("visit-1", fields.SessionId);
        await platform.CloseAsync();
    }

    [Fact]
    public async Task WebSocketsAndEventStreamsArentTimed()
    {
        var platform = Make(new FakeCollector(), "{\"v\":1,\"enabled\":true,\"mode\":\"monitor\"}");
        var stream = new PlatformMiddleware(c =>
        {
            c.Response.ContentType = "text/event-stream";
            return Task.CompletedTask;
        }, platform);
        await stream.InvokeAsync(Request("198.51.100.1", path: "/events"));
        Assert.Empty(platform.PerformanceModule!.Take(true));
        var socket = Request("198.51.100.1", path: "/ws");
        socket.Request.Headers.Upgrade = "websocket";
        socket.Features.Set<Microsoft.AspNetCore.Http.Features.IHttpUpgradeFeature>(new Upgradable());
        Assert.True(PlatformMiddleware.Untimed(socket));
        await platform.CloseAsync();
    }

    private sealed class Upgradable : Microsoft.AspNetCore.Http.Features.IHttpUpgradeFeature
    {
        public bool IsUpgradableRequest => true;

        public Task<Stream> UpgradeAsync() => Task.FromResult<Stream>(new MemoryStream());
    }

    [Fact]
    public void OneSignInIsOneLogin()
    {
        var identity = new AuthenticationOptions { DefaultAuthenticateScheme = "Identity.Application", DefaultSignInScheme = "Identity.External" };
        Assert.True(CookieAudit.Audited("Identity.Application", identity));
        Assert.False(CookieAudit.Audited("Identity.External", identity));
        Assert.False(CookieAudit.Audited("Identity.TwoFactorUserId", identity));
        Assert.False(CookieAudit.Audited("Identity.TwoFactorRememberMe", identity));
        Assert.True(CookieAudit.Audited("Cookies", new AuthenticationOptions()));
        Assert.True(CookieAudit.Audited("Cookies", new AuthenticationOptions { DefaultScheme = "Cookies" }));
        Assert.False(CookieAudit.Audited("Partner", new AuthenticationOptions { DefaultScheme = "Cookies" }));
    }

    [Fact]
    public async Task BeforeSendRunsOnceWhenTheErrorIsSent()
    {
        var calls = 0;
        var collector = new FakeCollector();
        var errors = new Errors(Shared.Core(collector), "web-1", captureUncaught: false, spoolDir: "false",
            beforeSend: (evt, error) =>
            {
                calls++;
                Assert.NotNull(error);
                evt["message"] = "scrubbed";
                return evt;
            });
        try
        {
            var error = Thrown();
            errors.CaptureException(error, null, 0, "logged");
            errors.CaptureException(error, new RequestFields { Method = "GET", Path = "/a" }, 500, "error");
            Assert.Equal(0, calls);
            await errors.FlushAsync();
            Assert.Equal(1, calls);
            var sent = collector.Requests.Single().Json.GetProperty("errors")[0];
            Assert.Equal("scrubbed", sent.GetProperty("message").GetString());
            Assert.Equal("error", sent.GetProperty("kind").GetString());
            Assert.Equal(500, sent.GetProperty("status_code").GetInt32());
        }
        finally
        {
            Watchers.Unwatch(errors);
        }
    }

    [Fact]
    public async Task BreadcrumbsLeaveOutPasswordsAndQueries()
    {
        var errors = new Errors(Shared.Core(), "web-1", captureUncaught: false, spoolDir: "false");
        try
        {
            var scope = new Scope(() => new RequestFields());
            using (Scope.Enter(scope))
            {
                using var client = new HttpClient { Timeout = TimeSpan.FromSeconds(2) };
                try
                {
                    await client.GetAsync("http://user:secret@127.0.0.1:9/private?token=abc");
                }
                catch (Exception)
                {
                }
            }
            var crumb = Assert.Single(scope.Breadcrumbs());
            Assert.Equal("GET http://127.0.0.1:9/private", crumb["text"]);
        }
        finally
        {
            Watchers.Unwatch(errors);
        }
    }

    // ---- Shutdown and the waiting file ----

    [Fact]
    public async Task ClosingTriesOnceAndKeepsWhatFailedPrivately()
    {
        var dir = Shared.TempDir("pd-dotnet-close");
        var collector = new FakeCollector(_ => FakeCollector.Reply(503, "{}"));
        var errors = new Errors(Shared.Core(collector), "web-1", captureUncaught: false, spoolDir: dir);
        try
        {
            errors.CaptureException(Thrown(), null, 500, "error");
            var started = DateTime.UtcNow;
            await errors.CloseAsync(new CancellationTokenSource(TimeSpan.FromSeconds(3)).Token);
            Assert.True(DateTime.UtcNow - started < TimeSpan.FromSeconds(1.5), "no retry wait at shutdown");
            Assert.Single(collector.Requests);
            Assert.True(File.Exists(errors.SpoolFile));
            // .NET 7+ creates it so (UnixCreateMode), .NET 6 makes it so before writing.
            if (!OperatingSystem.IsWindows()) Assert.Equal("600", Shared.ModeOf(errors.SpoolFile!));
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }

    [Fact]
    public async Task AResendThatFailsHalfwayKeepsTheRest()
    {
        var dir = Shared.TempDir("pd-dotnet-resend");
        var answers = 0;
        var collector = new FakeCollector(_ => FakeCollector.Reply(Interlocked.Increment(ref answers) == 1 ? 202 : 503, "{}"));
        var errors = new Errors(Shared.Core(collector), "web-1", captureUncaught: false, spoolDir: dir);
        try
        {
            errors.Spool(Enumerable.Range(0, Errors.Batch + 3).Select(i => new Dictionary<string, object?> { ["message"] = "e" + i }).ToList());
            await errors.ResendAsync();
            Assert.Equal(2, collector.Requests.Count);
            var left = File.ReadAllLines(errors.SpoolFile!);
            Assert.Equal(3, left.Length);
            Assert.Contains("e" + Errors.Batch, left[0]);
            Assert.Empty(Directory.GetFiles(dir, "*.sending"));
        }
        finally
        {
            Watchers.Unwatch(errors);
            Directory.Delete(dir, true);
        }
    }

    [Fact]
    public async Task ErrorsAProcessThatDiedWasSendingAreSentAgain()
    {
        var dir = Shared.TempDir("pd-dotnet-orphan");
        var collector = new FakeCollector();
        var errors = new Errors(Shared.Core(collector), "web-1", captureUncaught: false, spoolDir: dir);
        try
        {
            // A taken file from a process that's gone (no such id, a start time that isn't its).
            File.WriteAllText(errors.SpoolFile + ".999999.123.abcdef.sending", "{\"message\":\"orphan\"}\n");
            await errors.ResendAsync();
            var sent = collector.Requests.Single().Json.GetProperty("errors")[0];
            Assert.Equal("orphan", sent.GetProperty("message").GetString());
            Assert.Empty(Directory.GetFiles(dir, "*.sending"));
        }
        finally
        {
            Watchers.Unwatch(errors);
            Directory.Delete(dir, true);
        }
    }

    [Fact]
    public async Task PlatformCloseRespectsTheHostsTime()
    {
        var collector = new FakeCollector(_ =>
        {
            Thread.Sleep(3000);
            return FakeCollector.Reply(202, "{}");
        });
        var platform = new Platform(Shared.Options(collector));
        platform.TimeRequest("GET", "/a", 200, System.Diagnostics.Stopwatch.GetTimestamp());
        var started = DateTime.UtcNow;
        await platform.CloseAsync(new CancellationTokenSource(TimeSpan.FromMilliseconds(800)).Token);
        Assert.True(DateTime.UtcNow - started < TimeSpan.FromSeconds(2.5));
    }

    // ---- Limits ----

    [Fact]
    public async Task AnEventThatIsntJsonIsDroppedWhenTracked()
    {
        var collector = new FakeCollector();
        var platform = new Platform(Shared.Options(collector));
        var cycle = new Dictionary<string, object?>();
        cycle["self"] = cycle;
        Assert.Equal("", platform.Track("bad", cycle));
        Assert.NotEqual("", platform.Track("good"));
        await platform.FlushAsync();
        var events = collector.Requests.Single(r => r.Url.EndsWith("/events/server-events")).Json.GetProperty("events");
        Assert.Equal("good", Assert.Single(events.EnumerateArray()).GetProperty("event_name").GetString());
        var unsendable = await Shared.Core(collector).SendAsync("t", "/x", "POST", new Dictionary<string, object?> { ["c"] = cycle });
        Assert.Equal(Core.Unsendable, unsendable!.Status);
        await platform.CloseAsync();
    }

    [Fact]
    public async Task AVeryLongWaitDoesntBreakTheJob()
    {
        var job = new Periodic(() => Task.FromResult(1e12), 1e12);
        job.Start();
        await Task.Delay(100);
        Assert.False(job.Loop!.IsFaulted);
        await job.StopAsync(TimeSpan.FromSeconds(1));
        Assert.True(job.Loop!.IsCompleted && !job.Loop.IsFaulted);
    }

    [Fact]
    public void ServerSpeedRowsDontGrowWithMadeUpMethods()
    {
        var performance = new Performance(Shared.Core(), "web-1");
        Assert.Equal("OTHER", Performance.MethodOf("BREW"));
        Assert.Equal("JOB", Performance.MethodOf("JOB"));
        for (var i = 0; i < 1000; i++) performance.Record("M" + i, "/r" + i, 200 + (i % 300), 1);
        Assert.True(performance.RowCount <= Performance.HardMaxKeys);
        Assert.All(performance.Take(true), r => Assert.Equal("OTHER", r["method"]));
    }

    [Fact]
    public void DashboardHeadersWithControlOrNonAsciiCharactersAreRefused()
    {
        // A tab is allowed, as in every other package (sdk/protocols/header-cases.json).
        var headers = Core.ParseHeaders(Shared.Parse("[[\"X-Frame-Options\",\"DENY\"],[\"Referrer-Policy\",\"a\\tb\"],[\"Permissions-Policy\",\"caf\\u00e9\"],[\"X-Content-Type-Options\",\"a\\u0000\"],[\"Access-Control-Allow-Origin\",\"*\"]]"));
        Assert.Equal(new[] { "X-Frame-Options", "Referrer-Policy" }, headers.Select(h => h.Key));
    }

    [Fact]
    public void DotnetOnlyRegexSyntaxIsRefused()
    {
        foreach (var bad in new[] { "(?<name>a)", "(?'name'a)", "(?<a-b>c)", "(a)\\k<1>", "\\k<name>", "(?(a)b|c)", "(?i)abc", "(?>abc)", "(?#note)a", "(?<=a)b" })
        {
            Assert.False(RequestRules.SafePattern(bad), bad);
        }
        foreach (var good in new[] { "(?:a|b)c", "a(?=b)", "a(?!b)", "union\\s+select", "\\.php$" }) Assert.True(RequestRules.SafePattern(good), good);
        var compiled = RequestRules.Compiled("union\\s+select");
#if NET7_0_OR_GREATER
        Assert.True((compiled.Options & System.Text.RegularExpressions.RegexOptions.NonBacktracking) != 0);
        Assert.True((RequestRules.Compiled("a(?=b)").Options & System.Text.RegularExpressions.RegexOptions.NonBacktracking) == 0);
#endif
        Assert.Matches(compiled, "1 UNION   SELECT 2");
        Assert.Equal(TimeSpan.FromMilliseconds(50), compiled.MatchTimeout);
    }

    [Fact]
    public void ProbesMatchThePathTheRouterReads()
    {
        var probes = Firewall.CompileProbes(Shared.Parse("{\"exact\":[\"/.env\"],\"prefix\":[\"/.git/\"],\"ban\":60}"));
        Assert.True(Firewall.IsProbe("/x/..;/.env", probes));
        Assert.True(Firewall.IsProbe("/./.git/config", probes));
        Assert.True(Firewall.IsProbe("/%2e%65nv", probes));
        Assert.False(Firewall.IsProbe("/x/.env.example", probes));
        Assert.Equal("/admin/users", RequestRules.NormalizeTarget("/x;y/..;/ADMIN//users?q=1"));
        Assert.Equal("/", RequestRules.NormalizeTarget("/..;/.."));
    }
    [Fact]
    public void AFullPerPageTableLeavesOtherLimitsCounting()
    {
        // The "any one page" watcher keeps a count per address and page, which
        // can fill a table; it has one of its own, so a full one leaves the
        // login limit counting new addresses and keeps the counts it has.
        var wall = new Firewall(Shared.Core());
        wall.RulesNow = Firewall.Compile(Shared.Parse("{\"v\":1,\"enabled\":true,\"mode\":\"block\",\"limits\":{\"rules\":["
            + "{\"id\":\"login\",\"action\":\"block\",\"limit\":1,\"window\":60,\"path\":{\"exact\":[\"/login\"]}},"
            + "{\"id\":\"any.page\",\"action\":\"block\",\"limit\":600,\"window\":600,\"each\":\"path\",\"path\":{\"prefix\":[\"/\"]}}]}}"));
        var now = Math.Floor(J.UnixNow() / 600) * 600 + 600;
        Assert.Equal("", wall.Check("198.51.100.7", "POST", "/login", now: now).Rule);
        for (var i = 0; wall.pathCounts.Count < Firewall.CounterMax; i++) wall.pathCounts.Hit("any.page|x|/" + i, (long)(now / 600), 600, now);
        Assert.Equal("limit:login", wall.Check("198.51.100.7", "POST", "/login", now: now).Rule);
        Assert.Equal("", wall.Check("203.0.113.9", "POST", "/login", now: now).Rule);
        Assert.Equal("limit:login", wall.Check("203.0.113.9", "POST", "/login", now: now).Rule);
        Assert.Equal(Firewall.CounterMax, wall.pathCounts.Count);
        // Full of live counts, a new page isn't counted and nothing is dropped.
        Assert.Null(wall.pathCounts.Hit("any.page|y|/new", (long)(now / 600), 600, now));
    }
}
