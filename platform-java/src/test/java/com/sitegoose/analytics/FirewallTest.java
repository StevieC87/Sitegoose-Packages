package com.sitegoose.analytics;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class FirewallTest {
    static final String HTML = "text/html,application/xhtml+xml,*/*;q=0.8";
    static final String CHECK = "\"challenge\":{\"skip\":[\"/api/\"],\"exempt\":[]}";

    static Firewall wall(String json) {
        return Fixtures.firewall("s", Json.map(Json.parse(json)));
    }

    static List<String> rules(Firewall wall, int times) {
        List<String> out = new ArrayList<>();
        for (int i = 0; i < times; i++) {
            out.add(wall.check("203.0.113.9", "GET", "/", "", "", "").rule);
        }
        return out;
    }

    @Test
    void monitorModeBansNobody() {
        Firewall wall = wall("{\"v\":1,\"enabled\":true,\"mode\":\"monitor\",\"rate\":{\"limit\":2,\"window\":60},\"ban\":{\"seconds\":600}}");
        assertEquals(Arrays.asList("", "", "rate", "rate", "rate"), rules(wall, 5));
    }

    @Test
    void blockModeBansHere() {
        Firewall wall = wall("{\"v\":1,\"enabled\":true,\"mode\":\"block\",\"rate\":{\"limit\":2,\"window\":60},\"ban\":{\"seconds\":600}}");
        assertEquals(Arrays.asList("", "", "rate", "ban"), rules(wall, 4));
    }

    @Test
    void denyBlocksInBlockModeAndIsWatchedInMonitorMode() {
        Firewall block = wall("{\"v\":1,\"enabled\":true,\"mode\":\"block\",\"deny\":[\"203.0.113.0/24\"]}");
        Firewall.Decision d = block.check("203.0.113.9", "GET", "/", "", "", "");
        assertEquals("block deny 403", d.toString());
        Firewall watch = wall("{\"v\":1,\"enabled\":true,\"mode\":\"monitor\",\"deny\":[\"203.0.113.0/24\"]}");
        assertEquals("monitor", watch.check("203.0.113.9", "GET", "/", "", "", "").action);
        assertEquals("allow", watch.check("198.51.100.1", "GET", "/", "", "", "").action);
    }

    @Test
    void allowedAndGoodBotsAreNeverChecked() {
        Firewall wall = wall("{\"v\":1,\"enabled\":true,\"mode\":\"monitor\",\"allow\":[\"198.51.100.9\"],\"goodbots\":[\"192.0.2.0/24\"]," + CHECK + "}");
        assertEquals("", wall.check("198.51.100.9", "GET", "/", "", HTML, "").rule);
        assertEquals("", wall.check("192.0.2.5", "GET", "/", "", HTML, "").rule);
        assertEquals("challenge", wall.check("203.0.113.5", "GET", "/", "", HTML, "").rule);
        assertEquals("", wall.check("203.0.113.5", "GET", "/api/x", "", HTML, "").rule, "skipped path");
        assertEquals("", wall.check("203.0.113.5", "POST", "/", "", HTML, "").rule, "not a page load");
    }

    @Test
    void aMatchOnlyWatchedStillGetsTheCheck() {
        Firewall wall = wall("{\"v\":1,\"enabled\":true,\"mode\":\"monitor\",\"deny\":[\"203.0.113.0/24\"]," + CHECK + "}");
        assertEquals("block challenge 503", wall.check("203.0.113.5", "GET", "/", "", HTML, "").toString());
        List<String> seen = new ArrayList<>();
        for (Map<String, Object> row : wall.waiting()) {
            seen.add(row.get("rule") + " " + row.get("action"));
        }
        Collections.sort(seen);
        assertEquals(Arrays.asList("challenge block", "deny monitor"), seen);
        assertEquals("monitor", wall.check("203.0.113.5", "POST", "/", "", HTML, "").action);
    }

    @Test
    void aPassFromThisServerLetsTheNextRequestThrough() {
        Firewall wall = wall("{\"v\":1,\"enabled\":true,\"mode\":\"monitor\"," + CHECK + "}");
        String pass = Challenge.makePass(wall.passKey, "203.0.113.5", null);
        assertEquals("", wall.check("203.0.113.5", "GET", "/", "", HTML, "theme=dark; __sg_pass=" + pass).rule);
    }

    @Test
    void reportsAreGroupedIntoHits() {
        Firewall wall = wall("{\"v\":1,\"enabled\":true,\"mode\":\"monitor\"," + CHECK + "}");
        for (int i = 0; i < 2; i++) {
            wall.check("203.0.113.5", "GET", "/pricing?x=1", "Mozilla/5.0", HTML, "");
        }
        List<Map<String, Object>> rows = wall.waiting();
        assertEquals(1, rows.size());
        assertEquals("/pricing", rows.get(0).get("path"));
        assertEquals(2L, ((Number) rows.get(0).get("hits")).longValue());
    }

    @Test
    void requestRulesAndProbes() {
        Firewall wall = wall("{\"v\":1,\"enabled\":true,\"mode\":\"block\",\"requests\":{\"rules\":[{\"id\":\"traversal\",\"action\":\"block\","
                + "\"path\":{\"contains\":[\"../\"]}}]},\"probes\":{\"exact\":[\"/.env\"],\"prefix\":[\"/wp-admin\"],\"ban\":0}}");
        assertEquals("request:traversal", wall.check("203.0.113.5", "GET", "/a/..%2f..%2fetc", "", "", "").rule);
        Firewall.Decision probe = wall.check("198.51.100.5", "GET", "/.env", "", "", "");
        assertEquals("probe", probe.rule);
        assertEquals("", wall.check("198.51.100.6", "GET", "/fine", "", "", "").rule);
    }

    @Test
    void offOrWithoutRulesEverythingPasses() {
        assertEquals(Firewall.Decision.ALLOW, Fixtures.firewall("s", null).check("203.0.113.5", "GET", "/", "", HTML, ""));
        assertEquals("allow", wall("{\"v\":1,\"enabled\":false,\"mode\":\"block\",\"deny\":[\"203.0.113.0/24\"]}")
                .check("203.0.113.5", "GET", "/", "", "", "").action);
    }

    @Test
    void cloudflareHeaderOnlyFromACloudflareConnection() {
        Map<String, String> h = Collections.singletonMap("cf-connecting-ip", "198.51.100.7");
        TrustProxy cf = TrustProxy.cloudflare();
        assertEquals("198.51.100.7", cf.clientIp("172.64.1.2", h));
        assertEquals("198.51.100.7", cf.clientIp("::ffff:162.158.0.9", h));
        assertEquals("198.51.100.7", cf.clientIp("2606:4700::1", h));
        assertEquals("203.0.113.50", cf.clientIp("203.0.113.50", h));
        assertEquals("172.64.1.2", cf.clientIp("172.64.1.2", Collections.emptyMap()));
    }

    @Test
    void forwardedHops() {
        Map<String, String> h = Collections.singletonMap("x-forwarded-for", "198.51.100.1, 203.0.113.9");
        assertEquals("203.0.113.9", TrustProxy.hops(1).clientIp("10.0.0.1", h));
        assertEquals("198.51.100.1", TrustProxy.hops(2).clientIp("10.0.0.1", h));
        assertEquals("10.0.0.1", TrustProxy.none().clientIp("10.0.0.1", h));
        assertEquals("10.0.0.1", TrustProxy.parse("1").clientIp("10.0.0.1", Collections.emptyMap()));
    }

    @Test
    void rangesCoveringIpv4AreDropped() {
        for (String wide : new String[] {"::/64", "::ffff:0:0/64", "::/0", "::ffff:0:0/96", "::/8"}) {
            assertNull(Ip.range(wide), wide);
            assertFalse(new Ip.Set(Collections.singletonList(wide)).has(Ip.key("203.0.113.9")), wide);
        }
        assertTrue(new Ip.Set(Collections.singletonList("::ffff:203.0.113.0/120")).has(Ip.key("203.0.113.9")));
        assertTrue(new Ip.Set(Collections.singletonList("2001:db8:0:1::/64")).has(Ip.key("2001:db8:0:1::9")));
        assertTrue(new Ip.Set(Arrays.asList("203.0.113.0/24", "::/64")).has(Ip.key("203.0.113.9")));
        assertEquals("", wall("{\"v\":1,\"enabled\":true,\"mode\":\"block\",\"banned\":[\"::/64\"],\"shared\":[\"::ffff:0:0/64\"]}")
                .check("203.0.113.9", "GET", "/", "", "", "").rule);
    }

    @Test
    void addressesAreReadStrictly() {
        assertNotNull(Ip.key("203.0.113.9"));
        assertEquals(Ip.key("203.0.113.9"), Ip.key("::ffff:203.0.113.9"));
        assertNull(Ip.key("01.2.3.4"), "leading zeros");
        assertNull(Ip.key("١.2.3.4"), "non-ASCII digits");
        assertNull(Ip.key("1.2.3"));
        assertNull(Ip.key("2001:db8::١"));
        assertEquals(Ip.key("2001:db8::1"), Ip.key("2001:0db8:0:0:0:0:0:1"));
        assertNull(Ip.key("not an address"));
    }
}
