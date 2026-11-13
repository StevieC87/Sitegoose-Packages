using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Xunit;

namespace SiteGoose.Tests;

public class FirewallTests
{
    private static Firewall Wall(string json, Core? core = null)
    {
        var wall = new Firewall(core ?? Shared.Core());
        wall.RulesNow = Firewall.Compile(Shared.Parse(json));
        return wall;
    }

    private const string Rate = "{\"v\":1,\"enabled\":true,\"mode\":\"MODE\",\"rate\":{\"limit\":2,\"window\":60},\"ban\":{\"seconds\":600}}";

    [Fact]
    public void MonitorModeBansNobody()
    {
        var wall = Wall(Rate.Replace("MODE", "monitor"));
        var rules = Enumerable.Range(0, 5).Select(_ => wall.Check("203.0.113.9", "GET", "/").Rule).ToList();
        Assert.Equal(new[] { "", "", "rate", "rate", "rate" }, rules);
    }

    [Fact]
    public void BlockModeBansHere()
    {
        var wall = Wall(Rate.Replace("MODE", "block"));
        var decisions = Enumerable.Range(0, 4).Select(_ => wall.Check("203.0.113.9", "GET", "/")).ToList();
        Assert.Equal(new[] { "", "", "rate", "ban" }, decisions.Select(d => d.Rule));
        Assert.Equal(429, decisions[2].Status);
        Assert.Equal(403, decisions[3].Status);
    }

    [Fact]
    public void ListsAndSteps()
    {
        var wall = Wall("{\"v\":1,\"enabled\":true,\"mode\":\"block\",\"allow\":[\"198.51.100.1\"],\"deny\":[\"203.0.113.0/24\"],\"lists\":[\"192.0.2.9\"]," +
                        "\"probes\":{\"exact\":[\"/.env\"],\"ban\":3600}}");
        Assert.Equal(("block", "deny", 403), Tuple(wall.Check("203.0.113.5", "GET", "/")));
        Assert.Equal("deny", wall.Check("::ffff:203.0.113.5", "GET", "/").Rule);
        Assert.Equal("list", wall.Check("192.0.2.9", "GET", "/").Rule);
        Assert.Equal("", wall.Check("198.51.100.1", "GET", "/.env").Rule);
        Assert.Equal("probe", wall.Check("192.0.2.200", "GET", "/.env").Rule);
        // Banned here after the probe, in block mode.
        Assert.Equal("ban", wall.Check("192.0.2.200", "GET", "/").Rule);
        Assert.Equal("", wall.Check("not an address", "GET", "/").Rule);
    }

    private static (string, string, int) Tuple(FirewallDecision d) => (d.Action, d.Rule, d.Status);

    [Fact]
    public void RangesCoveringIpv4AreDropped()
    {
        foreach (var wide in new[] { "::/64", "::ffff:0:0/64", "::/0", "::ffff:0:0/96", "::/8" })
        {
            Assert.Null(Ip.ParseRange(wide));
            Assert.False(new IpSet(new[] { wide }).Has("203.0.113.9"), wide);
        }
        Assert.True(new IpSet(new[] { "::ffff:203.0.113.0/120" }).Has("203.0.113.9"));
        Assert.True(new IpSet(new[] { "2001:db8:0:1::/64" }).Has("2001:db8:0:1::9"));
        Assert.True(new IpSet(new[] { "203.0.113.0/24", "::/64" }).Has("203.0.113.9"));
        var wall = Wall("{\"v\":1,\"enabled\":true,\"mode\":\"block\",\"banned\":[\"::/64\"],\"shared\":[\"::ffff:0:0/64\"]}");
        Assert.Equal("", wall.Check("203.0.113.9", "GET", "/").Rule);
    }

    [Fact]
    public void ClientAddressFromProxies()
    {
        string Header(Dictionary<string, string> h, string name) => h.TryGetValue(name, out var v) ? v : "";
        var cf = new Dictionary<string, string> { ["cf-connecting-ip"] = "198.51.100.7" };
        Assert.Equal("198.51.100.7", Firewall.ResolveClientIp("172.64.1.2", n => Header(cf, n), "cloudflare"));
        Assert.Equal("198.51.100.7", Firewall.ResolveClientIp("::ffff:162.158.0.9", n => Header(cf, n), "cloudflare"));
        Assert.Equal("198.51.100.7", Firewall.ResolveClientIp("2606:4700::1", n => Header(cf, n), "cloudflare"));
        Assert.Equal("203.0.113.50", Firewall.ResolveClientIp("203.0.113.50", n => Header(cf, n), "cloudflare"));
        var xff = new Dictionary<string, string> { ["x-forwarded-for"] = "1.1.1.1, 198.51.100.8, 10.0.0.2" };
        Assert.Equal("10.0.0.2", Firewall.ResolveClientIp("10.0.0.1", n => Header(xff, n), "1"));
        Assert.Equal("198.51.100.8", Firewall.ResolveClientIp("10.0.0.1", n => Header(xff, n), "2"));
        Assert.Equal("10.0.0.1", Firewall.ResolveClientIp("10.0.0.1", n => Header(xff, n), null));
    }

    [Fact]
    public void ReportsAreGroupedAndALoginFailureCounts()
    {
        var wall = Wall("{\"v\":1,\"enabled\":true,\"mode\":\"block\",\"deny\":[\"203.0.113.5\"],\"login\":{\"limit\":2,\"window\":600,\"ban\":900}}");
        wall.Check("203.0.113.5", "GET", "/a?x=1");
        wall.Check("203.0.113.5", "GET", "/a?x=2");
        var row = Assert.Single(wall.Queued());
        Assert.Equal(2L, row["hits"]);
        Assert.Equal("/a", row["path"]);
        wall.LoginFailed("192.0.2.4");
        Assert.Equal("", wall.Check("192.0.2.4", "GET", "/").Rule);
        wall.LoginFailed("192.0.2.4");
        Assert.Equal("ban", wall.Check("192.0.2.4", "GET", "/").Rule);
        Assert.Contains(wall.Queued(), r => (string?)r["rule"] == "login");
    }

    [Fact]
    public async Task SyncSendsTheLayersAndUsesTheEtag()
    {
        var cache = Path.Combine(Path.GetTempPath(), "pd-dotnet-rules-" + System.Guid.NewGuid().ToString("N") + ".json");
        var collector = new FakeCollector(seen => seen.Headers.ContainsKey("If-None-Match")
            ? FakeCollector.Reply(304, "")
            : FakeCollector.Reply(200, "{\"v\":1,\"enabled\":true,\"mode\":\"block\",\"sync\":45,\"deny\":[\"203.0.113.5\"]}", "\"r1\""));
        var wall = new Firewall(Shared.Core(collector), cacheFile: cache);
        Assert.Equal(45, await wall.SyncAsync());
        var first = collector.Requests[0];
        Assert.Equal("GET", first.Method);
        Assert.Equal(Shared.Endpoint + "/events/firewall/rules?site_id=" + Shared.SiteId, first.Url);
        Assert.Equal("app check", first.Headers["X-Firewall-Layers"]);
        Assert.True(first.Headers.ContainsKey("X-Server-Name"));
        Assert.StartsWith("Bearer ", first.Headers["Authorization"]);
        Assert.StartsWith("analytics-platform-dotnet/", first.Headers["User-Agent"]);
        Assert.Equal("deny", wall.Check("203.0.113.5", "GET", "/").Rule);
        await wall.SyncAsync();
        Assert.Equal("\"r1\"", collector.Requests[1].Headers["If-None-Match"]);
        Assert.Equal("deny", wall.Check("203.0.113.5", "GET", "/").Rule);
        // A restart reads the rules from the cache before the first fetch.
        var again = new Firewall(Shared.Core(new FakeCollector()), cacheFile: cache);
        Assert.Equal("deny", again.Check("203.0.113.5", "GET", "/").Rule);
        File.Delete(cache);
    }

    [Fact]
    public async Task FlushSendsTheEventsWithTheSiteId()
    {
        var collector = new FakeCollector();
        var wall = new Firewall(Shared.Core(collector));
        wall.RulesNow = Firewall.Compile(Shared.Parse("{\"v\":1,\"enabled\":true,\"mode\":\"monitor\",\"deny\":[\"203.0.113.5\"]}"));
        Assert.Equal("monitor", wall.Check("203.0.113.5", "GET", "/").Action);
        await wall.FlushAsync();
        var sent = Assert.Single(collector.Requests);
        Assert.EndsWith("/events/firewall/events", sent.Url);
        Assert.Equal(Shared.SiteId, sent.Json.GetProperty("site_id").GetString());
        Assert.Equal("deny", sent.Json.GetProperty("events")[0].GetProperty("rule").GetString());
    }

    [Fact]
    public void ChallengePageCarriesTheNonceAndAPass()
    {
        var wall = Wall("{\"v\":1,\"enabled\":true,\"mode\":\"monitor\",\"challenge\":{\"skip\":[\"/api/\"]}}");
        var page = wall.ChallengePage("203.0.113.7", "GET");
        Assert.Equal(503, page.Status);
        var csp = page.Headers.First(h => h.Key == "Content-Security-Policy").Value;
        var nonce = System.Text.RegularExpressions.Regex.Match(csp, "'nonce-([^']+)'").Groups[1].Value;
        var html = System.Text.Encoding.UTF8.GetString(page.Body);
        Assert.Contains("nonce=\"" + nonce + "\"", html);
        Assert.Contains("__sg_tries", html);
        Assert.Contains(Challenge.MakePass(wall.PassKey, "203.0.113.7"), html);
        Assert.Empty(wall.ChallengePage("203.0.113.7", "HEAD").Body);
        // JSON and POST never get the page.
        Assert.Equal("", wall.Check("203.0.113.7", "POST", "/form", "Mozilla/5.0", "text/html").Rule);
        Assert.Equal("", wall.Check("203.0.113.7", "GET", "/data", "Mozilla/5.0", "application/json").Rule);
        Assert.Equal("challenge", wall.Check("203.0.113.7", "GET", "/", "Mozilla/5.0", "text/html").Rule);
        var pass = "__sg_pass=" + Challenge.MakePass(wall.PassKey, "203.0.113.7");
        Assert.Equal("", wall.Check("203.0.113.7", "GET", "/", "Mozilla/5.0", "text/html", pass).Rule);
    }

    [Fact]
    public void RequestTargets()
    {
        Assert.Equal("/a%252e?q=1", Core.RequestTarget("/a%2e", "?q=1", "/a%252e?q=1"));
        Assert.Equal("/app/caf%C3%A9?id=1%20union", Core.RequestTarget("/app/café", "?id=1%20union"));
        Assert.Equal("/x?y=1", Core.RequestTarget("/ignored", null, "http://host.example/x?y=1"));
    }
}
