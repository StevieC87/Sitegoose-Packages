using System.Collections.Generic;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;
using Xunit;

namespace SiteGoose.Tests;

/// <summary>The cases every client runs (sdk/protocols): the browser check,
/// the request rules, Cloudflare's ranges, the dashboard's security headers and
/// the type a proxied answer is served with.</summary>
public class SharedCasesTests
{
    private static readonly JsonElement Challenges = Shared.Load("challenge-cases.json");
    private static readonly JsonElement Rules = Shared.Load("request-rules-cases.json");
    private static readonly JsonElement Limits = Shared.Load("page-limits-cases.json");
    private static readonly JsonElement Headers = Shared.Load("header-cases.json");
    private static readonly JsonElement Answers = Shared.Load("proxy-answer-cases.json");

    private static Firewall Wall(string mode = "monitor")
    {
        var secret = Challenges.GetProperty("secret").GetString()!;
        var wall = new Firewall(Shared.Core(secret: secret));
        wall.RulesNow = Firewall.Compile(Shared.Parse("{\"v\":1,\"enabled\":true,\"mode\":\"" + mode + "\",\"challenge\":" + Challenges.GetProperty("challenge").GetRawText() + "}"));
        return wall;
    }

    [Fact]
    public void ChallengeTokens()
    {
        var key = Challenge.PassKey(Challenges.GetProperty("secret").GetString());
        foreach (var c in Challenges.GetProperty("tokens").EnumerateArray())
        {
            var ip = c.GetProperty("ip").GetString();
            Assert.Equal(c.GetProperty("who").GetString(), Challenge.Who(ip));
            Assert.Equal(c.GetProperty("token").GetString(), Challenge.MakePass(key, ip, c.GetProperty("now").GetDouble()));
        }
    }

    [Fact]
    public void ChallengeChecks()
    {
        var key = Challenge.PassKey(Challenges.GetProperty("secret").GetString());
        foreach (var c in Challenges.GetProperty("checks").EnumerateArray())
        {
            var got = Challenge.IsValid(key, c.GetProperty("ip").GetString(), c.GetProperty("cookie").GetString(), c.GetProperty("now").GetDouble());
            Assert.True(got == c.GetProperty("valid").GetBoolean(), c.GetProperty("why").GetString());
        }
    }

    [Fact]
    public void ChallengeDecisions()
    {
        foreach (var c in Challenges.GetProperty("decisions").EnumerateArray())
        {
            var r = c.GetProperty("request");
            var cookie = r.GetProperty("cookie").GetString();
            var decision = Wall().Check(r.GetProperty("ip").GetString()!, r.GetProperty("method").GetString(), r.GetProperty("path").GetString(), "Mozilla/5.0",
                r.GetProperty("accept").GetString(), string.IsNullOrEmpty(cookie) ? "" : "__sg_pass=" + cookie, c.GetProperty("now").GetDouble());
            var why = c.GetProperty("why").GetString();
            var challenged = c.GetProperty("challenged").GetBoolean();
            Assert.True((decision.Rule == "challenge") == challenged, why);
            if (challenged)
            {
                Assert.Equal("block", decision.Action);
                Assert.Equal(503, decision.Status);
            }
        }
    }

    [Fact]
    public void RequestRuleCases()
    {
        var rules = RequestRules.Compile(Shared.Parse("{\"rules\":" + Rules.GetProperty("rules").GetRawText() + "}"));
        foreach (var c in Rules.GetProperty("requests").EnumerateArray())
        {
            var matched = RequestRules.Match(rules, c.GetProperty("method").GetString(), c.GetProperty("target").GetString(), c.GetProperty("ua").GetString());
            var expect = c.GetProperty("expect").ValueKind == JsonValueKind.Null ? null : c.GetProperty("expect").GetString();
            Assert.True(matched?.Id == expect, c.GetProperty("why").GetString() + ": got " + (matched?.Id ?? "null"));
        }
    }

    [Fact]
    public void RequestTargetsInOriginForm()
    {
        foreach (var c in Rules.GetProperty("targets").EnumerateArray())
        {
            var target = c.GetProperty("target").GetString()!;
            // What the middleware hands the firewall: RawTarget, else the path.
            Assert.True(c.GetProperty("origin").GetString() == Core.RequestTarget("/decoded", "", target), target + ": got " + Core.RequestTarget("/decoded", "", target));
        }
    }

    [Fact]
    public void RequestRulePatterns()
    {
        var patterns = Rules.GetProperty("patterns");
        foreach (var p in patterns.GetProperty("refused").EnumerateArray()) Assert.False(RequestRules.SafePattern(p.GetString()), "should refuse " + p.GetString());
        foreach (var p in patterns.GetProperty("allowed").EnumerateArray()) Assert.True(RequestRules.SafePattern(p.GetString()), "should allow " + p.GetString());
    }

    /// <summary>Hits waiting per rule, to tell what one request reported.</summary>
    private static Dictionary<string, long> Reported(Firewall wall)
    {
        var hits = new Dictionary<string, long>();
        foreach (var row in wall.Queued())
        {
            var rule = (string)row["rule"]!;
            hits[rule] = hits.GetValueOrDefault(rule) + (long)row["hits"]!;
        }
        return hits;
    }

    [Fact]
    public void PageLimitCases()
    {
        foreach (var scenario in Limits.GetProperty("scenarios").EnumerateArray())
        {
            // base, the scenario's rules laid over it, and its limits.
            var rules = JsonNode.Parse(Limits.GetProperty("base").GetRawText())!.AsObject();
            if (scenario.TryGetProperty("rules", out var over))
            {
                foreach (var pair in over.EnumerateObject()) rules[pair.Name] = JsonNode.Parse(pair.Value.GetRawText());
            }
            rules["limits"] = JsonNode.Parse(scenario.GetProperty("limits").GetRawText());
            var wall = new Firewall(Shared.Core());
            wall.RulesNow = Firewall.Compile(Shared.Parse(rules.ToJsonString()));
            var n = 0;
            foreach (var c in scenario.GetProperty("requests").EnumerateArray())
            {
                var label = scenario.GetProperty("name").GetString() + " #" + (++n) + ": " + c.GetProperty("target").GetString()
                    + (c.TryGetProperty("why", out var why) ? " " + why.GetString() : "");
                var before = Reported(wall);
                var d = wall.Check(c.GetProperty("ip").GetString()!, c.GetProperty("method").GetString(), c.GetProperty("target").GetString(), "Mozilla/5.0", "", "");
                var reports = Reported(wall).Where(p => p.Value > before.GetValueOrDefault(p.Key)).Select(p => p.Key).OrderBy(r => r, System.StringComparer.Ordinal).ToList();
                var expect = c.GetProperty("expect");
                var got = d.Action + " " + d.Rule + " " + d.Status;
                if (expect.ValueKind == JsonValueKind.String)
                {
                    Assert.True(d.Action == "allow", label + ": got " + got);
                    Assert.True(reports.Count == 0, label + ": reported " + string.Join(",", reports));
                }
                else
                {
                    var want = expect.GetProperty("action").GetString() + " " + expect.GetProperty("rule").GetString() + " " + expect.GetProperty("status").GetInt32();
                    Assert.True(want == got, label + ": got " + got);
                }
                if (c.TryGetProperty("reports", out var listed))
                {
                    var want = listed.EnumerateArray().Select(r => r.GetString()!).OrderBy(r => r, System.StringComparer.Ordinal).ToList();
                    Assert.True(want.SequenceEqual(reports), label + ": reported " + string.Join(",", reports));
                }
            }
        }
    }

    [Fact]
    public void APageLimitLiftsWhenItsWindowEnds()
    {
        var wall = new Firewall(Shared.Core());
        wall.RulesNow = Firewall.Compile(Shared.Parse("{\"v\":1,\"enabled\":true,\"mode\":\"block\","
            + "\"limits\":{\"rules\":[{\"id\":\"login\",\"action\":\"block\",\"limit\":2,\"window\":60,\"path\":{\"exact\":[\"/login\"]}}]}}"));
        var start = 60.0 * 1000;
        Assert.Equal("allow", wall.Check("198.51.100.7", "POST", "/login", "", "", "", start).Action);
        Assert.Equal("allow", wall.Check("198.51.100.7", "POST", "/login", "", "", "", start + 30).Action);
        var over = wall.Check("198.51.100.7", "POST", "/login", "", "", "", start + 59);
        Assert.Equal("block limit:login 429", over.Action + " " + over.Rule + " " + over.Status);
        Assert.Equal("allow", wall.Check("198.51.100.7", "POST", "/login", "", "", "", start + 60).Action); // a new window
        Assert.Equal("allow", wall.Check("198.51.100.7", "POST", "/login", "", "", "", start + 61).Action); // nothing was banned
    }

    [Fact]
    public void CloudflareRangesMatchTheSharedList()
    {
        var shared = Shared.Load("cloudflare-ranges.json").GetProperty("ranges").EnumerateArray().Select(r => r.GetString()!).ToList();
        Assert.Equal(shared, Firewall.Cloudflare.ToList());
        Assert.True(Firewall.FromCloudflare("173.245.48.1"));
        Assert.True(Firewall.FromCloudflare("::ffff:173.245.48.1"));
        Assert.False(Firewall.FromCloudflare("203.0.113.7"));
    }

    [Fact]
    public void DashboardHeaders()
    {
        foreach (var c in Headers.GetProperty("cases").EnumerateArray())
        {
            var value = c.GetProperty("value").GetString()!;
            var repeat = c.TryGetProperty("repeat", out var r) ? r.GetInt32() : 1;
            var name = c.GetProperty("name").GetString()!;
            Assert.True(Core.SafeHeader(name, string.Concat(Enumerable.Repeat(value, repeat))) == c.GetProperty("ok").GetBoolean(), name + ": " + value);
        }
    }

    [Fact]
    public void ProxyAnswerTypes()
    {
        foreach (var c in Answers.GetProperty("cases").EnumerateArray())
        {
            var type = c.GetProperty("type");
            var given = type.ValueKind == JsonValueKind.Null ? null : type.GetString();
            Assert.Equal(c.GetProperty("served").GetString(), Proxy.AnswerType(given));
        }
    }
}
