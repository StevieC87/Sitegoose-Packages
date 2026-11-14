package com.sitegoose.analytics;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;
import org.junit.jupiter.api.Test;

/**
 * The cases every client runs (sdk/protocols): the browser check, the
 * request rules, Cloudflare's ranges, the dashboard's security headers and
 * the type a proxied answer is served with, so the packages decide alike.
 */
class SharedCasesTest {
    static final Map<String, Object> CHALLENGE = Fixtures.protocol("challenge-cases.json");
    static final Map<String, Object> RULES = Fixtures.protocol("request-rules-cases.json");
    static final Map<String, Object> LIMITS = Fixtures.protocol("page-limits-cases.json");
    static final Map<String, Object> HEADERS = Fixtures.protocol("header-cases.json");
    static final Map<String, Object> ANSWERS = Fixtures.protocol("proxy-answer-cases.json");
    static final String SECRET = (String) CHALLENGE.get("secret");
    static final byte[] KEY = Challenge.passKey(SECRET);

    static double now(Map<String, Object> c) {
        return ((Number) c.get("now")).doubleValue();
    }

    @Test
    void challengeTokens() {
        for (Map<String, Object> c : Fixtures.rows(CHALLENGE.get("tokens"))) {
            String ip = (String) c.get("ip");
            assertEquals(c.get("who"), Ip.who(ip), ip);
            assertEquals(c.get("token"), Challenge.makePass(KEY, ip, now(c)), ip);
        }
    }

    @Test
    void challengeChecks() {
        for (Map<String, Object> c : Fixtures.rows(CHALLENGE.get("checks"))) {
            boolean got = Challenge.isValid(KEY, (String) c.get("ip"), (String) c.get("cookie"), now(c));
            assertEquals(c.get("valid"), got, (String) c.get("why"));
        }
    }

    @Test
    void challengeDecisions() {
        for (Map<String, Object> c : Fixtures.rows(CHALLENGE.get("decisions"))) {
            Map<String, Object> request = Json.map(c.get("request"));
            Map<String, Object> rules = new LinkedHashMap<>();
            rules.put("v", 1L);
            rules.put("enabled", true);
            rules.put("mode", "monitor");
            rules.put("challenge", CHALLENGE.get("challenge"));
            Firewall wall = Fixtures.firewall(SECRET, rules);
            String cookie = (String) request.get("cookie");
            Firewall.Decision d = wall.check((String) request.get("ip"), (String) request.get("method"), (String) request.get("path"),
                    "Mozilla/5.0", (String) request.get("accept"), cookie.isEmpty() ? "" : Challenge.COOKIE + "=" + cookie, now(c));
            String why = (String) c.get("why");
            assertEquals(c.get("challenged"), "challenge".equals(d.rule), why);
            if (Boolean.TRUE.equals(c.get("challenged"))) {
                assertEquals("block", d.action, why);
                assertEquals(503, d.status, why);
            }
        }
    }

    @Test
    void requestRuleCases() {
        Map<String, Object> wrapped = new LinkedHashMap<>();
        wrapped.put("rules", RULES.get("rules"));
        List<RequestRules.Rule> rules = RequestRules.compile(wrapped);
        for (Map<String, Object> c : Fixtures.rows(RULES.get("requests"))) {
            RequestRules.Rule matched = RequestRules.match(rules, (String) c.get("method"), (String) c.get("target"), (String) c.get("ua"));
            assertEquals(c.get("expect"), matched == null ? null : matched.id, c.get("why") + ": " + c.get("target"));
        }
    }

    @Test
    void requestTargetsInOriginForm() {
        for (Map<String, Object> c : Fixtures.rows(RULES.get("targets"))) {
            assertEquals(c.get("origin"), RequestRules.originForm((String) c.get("target")), (String) c.get("target"));
        }
    }

    @Test
    void requestRulePatterns() {
        Map<String, Object> patterns = Json.map(RULES.get("patterns"));
        for (Object p : Json.list(patterns.get("refused"))) {
            assertFalse(RequestRules.safePattern((String) p), (String) p);
        }
        for (Object p : Json.list(patterns.get("allowed"))) {
            assertTrue(RequestRules.safePattern((String) p), (String) p);
        }
    }

    @Test
    void anUnsafeRuleIsDroppedAndMatchingStaysQuick() {
        Map<String, Object> data = Json.map(Json.parse("{\"rules\":[{\"id\":\"slow\",\"action\":\"block\",\"path\":{\"regex\":\"(a+)+b\"}},"
                + "{\"id\":\"fine\",\"action\":\"block\",\"path\":{\"exact\":[\"/x\"]}}]}"));
        List<RequestRules.Rule> rules = RequestRules.compile(data);
        assertEquals(1, rules.size());
        assertEquals("fine", rules.get(0).id);
        long started = System.nanoTime();
        assertNull(RequestRules.match(rules, "GET", "/" + "a".repeat(5000), ""));
        assertTrue(System.nanoTime() - started < 1_000_000_000L);
    }

    @Test
    void aRuleWithNothingToMatchOrABadPatternIsDropped() {
        assertEquals(0, RequestRules.compile(Json.parse("{\"rules\":[{\"id\":\"empty\",\"action\":\"block\"}]}")).size());
        List<RequestRules.Rule> rules = RequestRules.compile(Json.parse(
                "{\"rules\":[{\"id\":\"bad\",\"action\":\"block\",\"path\":{\"regex\":\"([\"}},{\"id\":\"good\",\"action\":\"block\",\"path\":{\"exact\":[\"/shell.php\"]}}]}"));
        assertEquals(1, rules.size());
        assertEquals("good", RequestRules.match(rules, "GET", "/shell.php", "").id);
        assertNull(RequestRules.match(RequestRules.compile(null), "GET", "/../../etc/passwd", ""));
        assertNull(RequestRules.match(RequestRules.compile(Json.parse("{\"rules\":\"nonsense\"}")), "GET", "/x", ""));
    }

    @Test
    void atMost200Rules() {
        StringBuilder many = new StringBuilder("{\"rules\":[");
        for (int i = 0; i < 250; i++) {
            many.append(i == 0 ? "" : ",").append("{\"id\":\"r").append(i).append("\",\"action\":\"monitor\",\"path\":{\"exact\":[\"/").append(i).append("\"]}}");
        }
        assertEquals(200, RequestRules.compile(Json.parse(many.append("]}").toString())).size());
    }

    /** Hits waiting per rule, to tell what one request reported. */
    static Map<String, Long> reported(Firewall wall) {
        Map<String, Long> out = new HashMap<>();
        for (Map<String, Object> row : wall.waiting()) {
            out.merge((String) row.get("rule"), ((Number) row.get("hits")).longValue(), Long::sum);
        }
        return out;
    }

    /** base, the scenario's rules laid over it, and its limits. */
    static Firewall limitsFirewall(Map<String, Object> scenario) {
        Map<String, Object> rules = new LinkedHashMap<>(Json.map(LIMITS.get("base")));
        Map<String, Object> over = Json.map(scenario.get("rules"));
        if (over != null) {
            rules.putAll(over);
        }
        rules.put("limits", scenario.get("limits"));
        return Fixtures.firewall("s", rules);
    }

    @Test
    void pageLimitCases() {
        for (Map<String, Object> scenario : Fixtures.rows(LIMITS.get("scenarios"))) {
            Firewall wall = limitsFirewall(scenario);
            int i = 0;
            for (Map<String, Object> c : Fixtures.rows(scenario.get("requests"))) {
                String label = scenario.get("name") + " #" + (++i) + ": " + c.get("target") + " " + c.get("why");
                Map<String, Long> before = reported(wall);
                Firewall.Decision d = wall.check((String) c.get("ip"), (String) c.get("method"), (String) c.get("target"), "Mozilla/5.0", "", "");
                Map<String, Long> after = reported(wall);
                TreeSet<String> reports = new TreeSet<>();
                for (Map.Entry<String, Long> e : after.entrySet()) {
                    if (e.getValue() > before.getOrDefault(e.getKey(), 0L)) {
                        reports.add(e.getKey());
                    }
                }
                Object expect = c.get("expect");
                if ("allow".equals(expect)) {
                    assertEquals("allow", d.action, label);
                    assertEquals(Collections.emptySet(), reports, label);
                } else {
                    Map<String, Object> e = Json.map(expect);
                    assertEquals(e.get("action") + " " + e.get("rule") + " " + e.get("status"), d.toString(), label);
                }
                if (c.get("reports") != null) {
                    assertEquals(new TreeSet<>(Json.strings(c.get("reports"))), reports, label);
                }
            }
        }
    }

    @Test
    void aPageLimitLiftsWhenItsWindowEnds() {
        Firewall wall = Fixtures.firewall("s", Json.map(Json.parse("{\"v\":1,\"enabled\":true,\"mode\":\"block\","
                + "\"limits\":{\"rules\":[{\"id\":\"login\",\"action\":\"block\",\"limit\":2,\"window\":60,\"path\":{\"exact\":[\"/login\"]}}]}}")));
        double start = 60.0 * 1000;
        assertEquals("allow", wall.check("198.51.100.7", "POST", "/login", "", "", "", start).action);
        assertEquals("allow", wall.check("198.51.100.7", "POST", "/login", "", "", "", start + 30).action);
        assertEquals("block limit:login 429", wall.check("198.51.100.7", "POST", "/login", "", "", "", start + 59).toString());
        assertEquals("allow", wall.check("198.51.100.7", "POST", "/login", "", "", "", start + 60).action, "a new window");
        assertEquals("allow", wall.check("198.51.100.7", "POST", "/login", "", "", "", start + 61).action, "nothing was banned");
    }

    @Test
    void aFullPerPageTableLeavesOtherLimitsCounting() {
        // The "any one page" watcher keeps a count per address and page, which
        // can fill a table; it has one of its own, so making room there never
        // drops the login limit's counts.
        Firewall wall = Fixtures.firewall("s", Json.map(Json.parse("{\"v\":1,\"enabled\":true,\"mode\":\"block\","
                + "\"limits\":{\"rules\":[{\"id\":\"login\",\"action\":\"block\",\"limit\":2,\"window\":600,\"path\":{\"exact\":[\"/login\"]}},"
                + "{\"id\":\"any.page\",\"action\":\"block\",\"limit\":600,\"window\":600,\"each\":\"path\",\"path\":{\"prefix\":[\"/\"]}}]}}")));
        double start = 600.0 * 1000;
        assertEquals("allow", wall.check("198.51.100.7", "POST", "/login", "", "", "", start).action);
        assertEquals("allow", wall.check("198.51.100.7", "POST", "/login", "", "", "", start + 1).action);
        for (int i = 0; wall.pathCounts.size() < Firewall.COUNTER_MAX; i++) {
            wall.pathCounts.put("any.page|x|/" + i, new long[] {1000, 1});
        }
        for (int i = 0; i < 10; i++) {
            assertEquals("allow", wall.check("198.51.100.8", "GET", "/page/" + i, "", "", "", start + 2).action);
        }
        assertEquals(Firewall.COUNTER_MAX, wall.pathCounts.size());
        assertEquals("block limit:login 429", wall.check("198.51.100.7", "POST", "/login", "", "", "", start + 3).toString(), "the login count was kept");
        assertEquals("allow", wall.check("203.0.113.9", "POST", "/login", "", "", "", start + 3).action);
        assertEquals("allow", wall.check("203.0.113.9", "POST", "/login", "", "", "", start + 3).action);
        assertEquals("block limit:login 429", wall.check("203.0.113.9", "POST", "/login", "", "", "", start + 3).toString(), "a new address is counted");
    }

    @Test
    void aBlockedPageGets429WithItsWindowAndANote() {
        Platform platform = Platform.create(new PlatformOptions().siteId("a".repeat(24)).secret("s").endpoint("http://127.0.0.1:9")
                .shutdownHook(false).allOff().firewall(true));
        try {
            platform.firewall().rules = Firewall.compile(Json.parse("{\"v\":1,\"enabled\":true,\"mode\":\"block\","
                    + "\"rate\":{\"limit\":100,\"window\":60},"
                    + "\"limits\":{\"rules\":[{\"id\":\"login\",\"action\":\"block\",\"limit\":1,\"window\":300,\"path\":{\"exact\":[\"/login\"]}}]}}"));
            assertNull(platform.blocked("198.51.100.7", Collections.emptyMap(), "POST", "/login"));
            Reply reply = platform.blocked("198.51.100.7", Collections.emptyMap(), "POST", "/login");
            assertEquals(429, reply.status());
            assertEquals("300", reply.header("Retry-After"));
            assertEquals("text/plain; charset=utf-8", reply.header("Content-Type"));
            assertEquals(Firewall.LIMIT_BODY, new String(reply.body(), java.nio.charset.StandardCharsets.UTF_8));
            assertEquals("Too many requests to this page. Please wait a little and try again.", Firewall.LIMIT_BODY);
        } finally {
            platform.close(500);
        }
    }

    @Test
    void cloudflareRangesAreTheSharedFile() {
        assertEquals(Fixtures.protocol("cloudflare-ranges.json").get("ranges"), Firewall.CLOUDFLARE);
    }

    @Test
    void dashboardHeaders() {
        for (Map<String, Object> c : Fixtures.rows(HEADERS.get("cases"))) {
            String value = ((String) c.get("value")).repeat(c.containsKey("repeat") ? ((Number) c.get("repeat")).intValue() : 1);
            assertEquals(c.get("ok"), Core.safeHeader((String) c.get("name"), value), c.get("name") + ": " + c.get("value"));
        }
    }

    @Test
    void proxyAnswerTypes() {
        for (Map<String, Object> c : Fixtures.rows(ANSWERS.get("cases"))) {
            assertEquals(c.get("served"), Proxy.answerType((String) c.get("type")), String.valueOf(c.get("type")));
        }
    }
}
