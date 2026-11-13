using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Xunit;

namespace SiteGoose.Tests;

public class ModulesTests
{
    private static Exception Thrown(string message)
    {
        try
        {
            throw new InvalidOperationException(message);
        }
        catch (Exception error)
        {
            return error;
        }
    }

    [Fact]
    public void AnErrorIsSentOnceWithItsRequestAndTrail()
    {
        var core = Shared.Core();
        var errors = new Errors(core, "web-1", captureUncaught: false, spoolDir: "false", release: "v1.2");
        try
        {
            var error = Thrown("boom");
            var fields = new RequestFields { Method = "GET", Path = "/orders/7", Route = "/orders/{id}", SessionId = "s1" };
            using (Scope.Enter(new Scope(() => fields)))
            {
                Errors.AddBreadcrumb("loaded the basket");
                errors.CaptureException(error, null, 0, "handled");
                errors.CaptureException(error, fields, 500, "error");
            }
            var evt = Assert.Single(errors.Queued());
            Assert.Equal("boom", evt["message"]);
            Assert.Equal("InvalidOperationException", evt["error_type"]);
            Assert.Equal(".NET", evt["runtime"]);
            Assert.Equal("v1.2", evt["release"]);
            Assert.Equal("/orders/{id}", evt["route"]);
            Assert.Equal("s1", evt["session_id"]);
            // The later capture (the middleware's) fills in what the first didn't know.
            Assert.Equal("handled", evt["kind"]);
            Assert.Equal(500, Convert.ToInt32(evt["status_code"]));
            var crumbs = (List<Dictionary<string, object?>>)evt["breadcrumbs"]!;
            Assert.Contains(crumbs, c => (string?)c["type"] == "note" && (string?)c["text"] == "loaded the basket");
            Assert.Contains("at SiteGoose.Tests.ModulesTests.Thrown(", (string)evt["stack"]!);
        }
        finally
        {
            Watchers.Unwatch(errors);
        }
    }

    [Fact]
    public async Task ErrorsTheCollectorCantTakeWaitInAFile()
    {
        var dir = Shared.TempDir("pd-dotnet-spool");
        var down = true;
        var collector = new FakeCollector(_ => FakeCollector.Reply(down ? 503 : 202, "{}"));
        var errors = new Errors(Shared.Core(collector), "web-1", captureUncaught: false, spoolDir: dir);
        var before = Errors.RetryAfterMs;
        Errors.RetryAfterMs = 1;
        try
        {
            errors.CaptureException(Thrown("kept"), null, 500, "error");
            await errors.FlushAsync();
            Assert.True(File.Exists(errors.SpoolFile));
            Assert.Equal(2, collector.Requests.Count);
            down = false;
            await errors.ResendAsync();
            Assert.False(File.Exists(errors.SpoolFile));
            var sent = collector.Requests.Last().Json.GetProperty("errors")[0];
            Assert.Equal("kept", sent.GetProperty("message").GetString());
        }
        finally
        {
            Errors.RetryAfterMs = before;
            Watchers.Unwatch(errors);
            Directory.Delete(dir, true);
        }
    }

    [Fact]
    public async Task ServerRequestsPerMinuteAndRoute()
    {
        Assert.Equal("/orders/:id/items/:id", Performance.NormalizeRoute("/orders/123/items/9f8e7d6c5b4a39281706f5e4d3c2b1a0"));
        Assert.Equal("/u/:id", Performance.NormalizeRoute("/u/550e8400-e29b-41d4-a716-446655440000?x=1"));
        Assert.Equal("/", Performance.NormalizeRoute(""));
        Assert.Equal("/a/b", Performance.NormalizeRoute("a/b"));
        var collector = new FakeCollector();
        var performance = new Performance(Shared.Core(collector), "web-1");
        performance.Record("GET", "/orders/{id}", 200, 12, "/orders/1");
        performance.Record("GET", "/orders/{id}", 200, 30, "/orders/2");
        performance.Record("GET", "", 404, 1, "/nothing/here");
        await performance.FlushAsync(true);
        var body = Assert.Single(collector.Requests).Json;
        Assert.Equal("web-1", body.GetProperty("server_name").GetString());
        Assert.StartsWith(".NET ", body.GetProperty("runtime").GetString());
        var rows = body.GetProperty("rows").EnumerateArray().ToList();
        var orders = rows.Single(r => r.GetProperty("route").GetString() == "/orders/{id}");
        Assert.Equal(2, orders.GetProperty("count").GetInt32());
        Assert.Equal(30, orders.GetProperty("max_ms").GetDouble());
        Assert.Contains(rows, r => r.GetProperty("route").GetString() == Performance.NotFound);
    }

    [Fact]
    public void CrawlersAreNamedAsPythonNamesThem()
    {
        Assert.Equal("Googlebot", Crawlers.Detect("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"));
        Assert.Equal("GPTBot", Crawlers.Detect("Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)"));
        Assert.Equal("", Crawlers.Detect("Mozilla/5.0 (Windows NT 10.0) Chrome/120"));
        Assert.Equal("Other bot", Crawlers.Detect("SomeRandomCrawler/1.0"));
        Assert.Equal("Other bot", Crawlers.Detect("curl/8.0"));
        var crawlers = new Crawlers(Shared.Core(), "web-1");
        crawlers.Middleware("Mozilla/5.0 (compatible; Googlebot/2.1)", "/a", 200, 5, 100, "66.249.66.1");
        crawlers.Middleware("Mozilla/5.0 Chrome/120", "/a", 200, 5, 100, "198.51.100.1");
        var (rows, agents) = crawlers.Take(true);
        Assert.Equal("Googlebot", Assert.Single(rows)["bot"]);
        Assert.Equal("Googlebot", Assert.Single(agents)["bot"]);
    }

    [Fact]
    public void ResourceReadingsMatchPython()
    {
        var a = Resources.CpuFieldsOf("cpu  100 10 50 1000 20 0 5 0 0 0\ncpu0 50 5 25 500 10 0 2 0 0 0\nintr 1\n")!;
        var b = Resources.CpuFieldsOf("cpu  160 10 80 1300 40 0 9 0 0 0\n")!;
        var shares = Resources.CpuShares(a, b);
        Assert.Equal(14.5, shares["cpu_user_pct"]);
        Assert.Equal(7.2, shares["cpu_system_pct"]);
        Assert.Equal(4.8, shares["cpu_iowait_pct"]);
        Assert.Equal(0.0, shares["cpu_steal_pct"]);
        Assert.Equal((165L, 1185L), Resources.CpuTimesOf(a));
        var memory = Resources.MemoryMb("MemTotal:        8143868 kB\nMemFree:          210000 kB\nMemAvailable:    5021228 kB\nCached:          4000000 kB\nSwapTotal:       2097152 kB\nSwapFree:        2084864 kB\n");
        Assert.Equal(7952L, memory["mem_total_mb"]);
        Assert.Equal(3049L, memory["mem_used_mb"]);
        Assert.Equal(2048L, memory["swap_total_mb"]);
        Assert.Equal(12L, memory["swap_used_mb"]);
        Assert.Equal((1048576L, 2097152L), Resources.DiskCountersOf("   8       0 sda 100 0 2048 0 50 0 4096 0 0 0 0\n   8       1 sda1 100 0 2048 0 50 0 4096 0 0 0 0\n   7       0 loop0 1 0 8 0 0 0 0 0 0 0 0\n"));
        Assert.Equal((5000L, 7000L), Resources.NetCountersOf("Inter-|   Receive\n face |bytes    packets errs drop fifo frame compressed multicast|bytes\n    lo: 1000 10 0 0 0 0 0 0 1000 10 0 0 0 0 0 0\n  eth0: 5000 50 0 0 0 0 0 0 7000 70 0 0 0 0 0 0\n"));
        Assert.Equal(12345L, Resources.HostUptimeOf("12345.67 54321.00\n"));
        // A reading of this machine: what it can't measure is left out, never zero.
        var row = new Resources(Shared.Core(), "web-1").Sample();
        Assert.Equal(Environment.ProcessorCount, row["cpu_cores"]);
        Assert.True(row.ContainsKey("mem_total_mb"));
        Assert.False(row.ContainsKey("cpu_pct"));
    }

    [Fact]
    public void ProxyAddressesMatchPython()
    {
        Assert.Equal("087e8910", Proxy.PrefixFor("test-secret"));
        Assert.Equal("7a196c9d2b5b031ca355a352fa26e4b4", Proxy.KeyFor("test-secret"));
        var proxy = new Proxy(Shared.Core(secret: "test-secret"));
        Assert.Equal("/087e8910/js/v1/s.js", proxy.ScriptUrl());
        Assert.Equal(("js", "v1/s.js"), proxy.Match("/087e8910/js/v1/s.js"));
        Assert.Equal(("bad", ""), proxy.Match("/087e8910/js/../x"));
        Assert.Null(proxy.Match("/pricing"));
    }

    [Fact]
    public async Task ProxyForwardsTheBeaconWithTheVisitorsAddress()
    {
        var collector = new FakeCollector(_ => FakeCollector.Reply(204, ""));
        var proxy = new Proxy(Shared.Core(collector, "test-secret"));
        var answer = await proxy.HandleAsync("api", "e", "POST", "?x=1", n => n == "Content-Type" ? "text/plain" : "", new byte[] { 1, 2 }, "198.51.100.4");
        Assert.Equal(204, answer.Status);
        var sent = Assert.Single(collector.Requests);
        Assert.Equal(Shared.Endpoint + "/collectanalytics/e?x=1", sent.Url);
        Assert.Equal("198.51.100.4", sent.Headers["X-Forwarded-For"]);
        Assert.Equal(Proxy.KeyFor("test-secret"), sent.Headers["X-Proxy-Key"]);
        Assert.Equal(413, (await proxy.HandleAsync("api", "e", "POST", "", _ => "", new byte[Proxy.MaxBody + 1], "x")).Status);
    }

    [Fact]
    public async Task SwitchesCheckInFlagsAndMaintenance()
    {
        var collector = new FakeCollector(_ => FakeCollector.Reply(200,
            "{\"v\":1,\"sync\":90,\"modules\":{\"analytics\":false},\"flags\":{\"new-checkout\":{\"on\":true,\"rollout\":30},\"beta\":{\"on\":true,\"rollout\":0,\"users\":[\"u1\"]}}," +
            "\"maintenance\":{\"on\":true,\"allow\":[\"198.51.100.1\"],\"bypass\":\"letmein\",\"message\":\"Back at <5>\"},\"headers\":[[\"X-Frame-Options\",\"DENY\"],[\"Bad\\nName\",\"x\"]]}", "\"c1\""));
        var platform = new Platform(Shared.Options(collector));
        Assert.Equal(90, await platform.Core.SyncSwitchesAsync());
        var sent = Assert.Single(collector.Requests);
        Assert.EndsWith("/events/platform/config?site_id=" + Shared.SiteId, sent.Url);
        var app = sent.Headers["X-Platform-App"];
        Assert.Contains("server=web-1", app);
        Assert.Contains("kind=process", app);
        Assert.Contains("runtime=.NET%20", app);
        // Switched off in the dashboard.
        Assert.Equal("", platform.Track("signup"));
        // Rollouts bucket users as every client does.
        Assert.Equal(26, Flags.Bucket("new-checkout", "user-42"));
        Assert.Equal(44, Flags.Bucket("a", "b"));
        Assert.Equal(67, Flags.Bucket("flag", ""));
        Assert.True(platform.IsEnabled("new-checkout", "user-42"));
        Assert.True(platform.IsEnabled("beta", "u1"));
        Assert.False(platform.IsEnabled("beta", "u2"));
        Assert.True(platform.IsEnabled("unknown", null, true));
        Assert.Equal(new[] { "X-Frame-Options" }, platform.SecurityHeaders(new[] { "content-type" }).Select(p => p.Key));
        Assert.Empty(platform.SecurityHeaders(new[] { "x-frame-options" }));

        string NoHeader(string _) => "";
        var page = platform.MaintenanceResponse("203.0.113.9", NoHeader, "/", "")!.Page!;
        Assert.Equal(503, page.Status);
        Assert.Contains("Back at &lt;5&gt;", System.Text.Encoding.UTF8.GetString(page.Body));
        Assert.Null(platform.MaintenanceResponse("198.51.100.1", NoHeader, "/", ""));
        Assert.StartsWith("site_preview=letmein;", platform.MaintenanceResponse("203.0.113.9", NoHeader, "/", "?site_preview=letmein")!.RememberCookie);
        Assert.Null(platform.MaintenanceResponse("203.0.113.9", n => n == "cookie" ? "site_preview=letmein" : "", "/", ""));
        await platform.CloseAsync();
    }

    [Fact]
    public async Task ServerEventsAreSentWithExactAmounts()
    {
        var collector = new FakeCollector();
        var platform = new Platform(Shared.Options(collector));
        var uid = platform.Track("purchase", new { numeric_value = 49.90m, currency = "EUR" }, "s1");
        Assert.NotEqual("", uid);
        await platform.FlushAsync();
        var evt = collector.Requests.Single(r => r.Url.EndsWith("/events/server-events")).Json.GetProperty("events")[0];
        Assert.Equal("purchase", evt.GetProperty("event_name").GetString());
        Assert.Equal("49.90", evt.GetProperty("numeric_value").GetString());
        Assert.Equal(uid, evt.GetProperty("event_uid").GetString());
        await platform.CloseAsync();
    }

    [Fact]
    public async Task IdentifySendsScalarTraitsAndLeavesTheRestOut()
    {
        var collector = new FakeCollector();
        var platform = new Platform(Shared.Options(collector));
        Assert.True(await platform.IdentifyAsync("u1", "s1"));
        Assert.True(await platform.IdentifyAsync("u1", "s1", new { plan = "pro", Seats = 5, ratio = 0.5, trial = false,
                                                                    tags = new[] { "a" }, gone = (string?)null, bad = double.NaN }));
        Assert.True(await platform.IdentifyAsync("u1", "s1", new Dictionary<string, object?> { ["tags"] = new[] { "a" } }));
        Assert.True(await platform.IdentifyAsync("u1", "s1", new Dictionary<string, string> { ["plan"] = "basic" }));
        var sent = collector.Requests.Where(r => r.Url.EndsWith("/events/identify")).Select(r => r.Json).ToList();
        Assert.Equal(4, sent.Count);
        Assert.Equal("{\"plan\":\"basic\"}", sent[3].GetProperty("traits").GetRawText());
        Assert.False(sent[0].TryGetProperty("traits", out _));
        var traits = sent[1].GetProperty("traits");
        Assert.Equal(new[] { "plan", "Seats", "ratio", "trial" }.OrderBy(n => n), traits.EnumerateObject().Select(p => p.Name).OrderBy(n => n));
        Assert.Equal("pro", traits.GetProperty("plan").GetString());
        Assert.Equal(5, traits.GetProperty("Seats").GetInt32());
        Assert.False(traits.GetProperty("trial").GetBoolean());
        Assert.False(sent[2].TryGetProperty("traits", out _));
        await platform.CloseAsync();
    }

    [Fact]
    public void InventoryReadsDepsJson()
    {
        const string deps = "{\"targets\":{\".NETCoreApp,Version=v8.0\":{\"Shop/1.0.0\":{\"dependencies\":{\"Newtonsoft.Json\":\"13.0.3\"}}," +
                            "\"Newtonsoft.Json/13.0.3\":{},\"Microsoft.Extensions.Primitives/8.0.0\":{}}}," +
                            "\"libraries\":{\"Shop/1.0.0\":{\"type\":\"project\"},\"Newtonsoft.Json/13.0.3\":{\"type\":\"package\"}," +
                            "\"Microsoft.Extensions.Primitives/8.0.0\":{\"type\":\"package\"},\"Lib/1.0.0\":{\"type\":\"reference\"}}}";
        var packages = Inventory.FromDeps(deps);
        Assert.Equal(new[] { "Microsoft.Extensions.Primitives", "Newtonsoft.Json" }, packages.Select(p => (string)p["name"]!));
        Assert.All(packages, p => Assert.Equal("NuGet", p["ecosystem"]));
        Assert.True(packages[1].ContainsKey("direct"));
        Assert.False(packages[0].ContainsKey("direct"));
        // This test run's own deps.json.
        var inventory = new Inventory(Shared.Core(), "web-1");
        var body = inventory.Body();
        Assert.Contains(inventory.InstalledPackages(), p => (string)p["name"]! == "xunit.core");
        Assert.True(body.ContainsKey("packages"));
    }

    [Fact]
    public void PostureNamesExposedFiles()
    {
        Assert.Equal("env", Posture.KindOf(".env"));
        Assert.Equal("env", Posture.KindOf("appsettings.Production.json"));
        Assert.Equal("database_dump", Posture.KindOf("backup.sql.gz"));
        Assert.Equal("private_key", Posture.KindOf("site.pfx"));
        Assert.Null(Posture.KindOf("site.css"));
        var dir = Shared.TempDir("pd-dotnet-web");
        try
        {
            File.WriteAllText(Path.Combine(dir, "appsettings.json"), "{}");
            File.WriteAllText(Path.Combine(dir, "index.html"), "");
            var posture = new Posture(Shared.Core(), new[] { new PostureRoot { Dir = dir, Prefix = "/" } }, "web-1",
                () => new[] { new PostureCheck { Id = "custom.check", State = "pass" } });
            var report = posture.Report();
            var text = JsonSerializer.Serialize(report);
            Assert.True(text.Contains("\"path\":\"appsettings.json\""), text);
            Assert.Contains("custom.check", text);
            Assert.Contains("server.runs_as_root", text);
        }
        finally
        {
            Directory.Delete(dir, true);
        }
    }
}
