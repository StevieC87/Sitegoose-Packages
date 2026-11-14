package com.sitegoose.analytics;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

/** What the security scan of the Java package found, each pinned down. */
class SecurityFixesTest {
    static final String RULES = "{\"v\":1,\"enabled\":true,\"mode\":\"block\",\"rate\":{\"limit\":2,\"window\":60},\"ban\":600,"
            + "\"probes\":{\"exact\":[\"/.env\"],\"ban\":600},"
            + "\"requests\":{\"rules\":[{\"id\":\"install\",\"action\":\"block\",\"ban\":600,\"path\":{\"exact\":[\"/wp-admin/install.php\"]}}]}}";

    static String actionOf(Firewall wall, String rule) {
        for (Map<String, Object> event : wall.waiting()) {
            if (rule.equals(event.get("rule"))) {
                return (String) event.get("action");
            }
        }
        return null;
    }

    // ---- Sec-Fetch-Site: refused, never banned ----

    @Test
    void aProbeAnotherSiteMadeIsRefusedButBansNoOne() {
        Firewall wall = Fixtures.firewall("s", Json.map(Json.parse(RULES)));
        Firewall.Decision probe = wall.check("198.51.100.7", "GET", "/.env", "", "", "", "Cross-Site");
        assertEquals("block probe 403", probe.toString());
        assertEquals("refused", actionOf(wall, "probe"), "the collector bans nobody for it");
        assertEquals("", wall.check("198.51.100.7", "GET", "/", "", "", "", "cross-site").rule, "not banned here");

        Firewall own = Fixtures.firewall("s", Json.map(Json.parse(RULES)));
        assertEquals("probe", own.check("198.51.100.8", "GET", "/.env", "", "", "", "same-origin").rule);
        assertEquals("block", actionOf(own, "probe"));
        assertEquals("ban", own.check("198.51.100.8", "GET", "/", "", "", "").rule, "same-origin is as before");
    }

    @Test
    void aRequestRuleAndTheRateLimitFromAnotherSiteBanNoOne() {
        Firewall wall = Fixtures.firewall("s", Json.map(Json.parse(RULES)));
        assertEquals("block request:install 403", wall.check("198.51.100.7", "GET", "/wp-admin/install.php", "", "", "", "same-site").toString());
        assertEquals("refused", actionOf(wall, "request:install"));
        assertEquals("", wall.check("198.51.100.7", "GET", "/", "", "", "", "same-site").rule);
        assertEquals("", wall.check("198.51.100.7", "GET", "/", "", "", "", "same-site").rule);
        assertEquals("block rate 429", wall.check("198.51.100.7", "GET", "/", "", "", "", "same-site").toString());
        assertEquals("refused", actionOf(wall, "rate"));
        assertEquals("rate", wall.check("198.51.100.7", "GET", "/", "", "", "").rule, "still over the rate, but not banned");
        assertTrue(Firewall.fromAnotherSite(" CROSS-SITE "));
        assertFalse(Firewall.fromAnotherSite("none"));
        assertFalse(Firewall.fromAnotherSite(null));
    }

    // ---- Regex windows ----

    @Test
    void aRegexIsSearchedInWindowsAndItsAnchorsKeepTheirMeaning() {
        String filler = "x".repeat(3000);
        RequestRules.Windowed start = new RequestRules.Windowed("^/admin");
        assertTrue(start.find("/admin" + filler));
        assertFalse(start.find(filler + "/admin"), "^ is only the window that starts the part");
        RequestRules.Windowed end = new RequestRules.Windowed("\\.php$");
        assertTrue(end.find(filler + ".php"));
        assertFalse(end.find(".php" + filler), "$ is only the window that ends the part");
        assertTrue(new RequestRules.Windowed("\\$").find("$" + filler), "\\$ is a dollar sign, anywhere");
        assertTrue(new RequestRules.Windowed("union.{0,20}select").find(filler + "union select" + filler));
        assertFalse(new RequestRules.Windowed("^x+$").find(filler), "both anchors: only a part one window holds");
        assertTrue(new RequestRules.Windowed("^x+$").find("xxx"));
    }

    // ---- An address that doesn't parse ----

    @Test
    void anAddressThatDoesntParseStillMeetsTheRulesAboutTheRequest() {
        Firewall wall = Fixtures.firewall("s", Json.map(Json.parse(RULES)));
        assertEquals("block probe 403", wall.check("x", "GET", "/.env", "", "", "").toString());
        assertEquals("block request:install 403", wall.check("not-an-ip", "GET", "/wp-admin/install.php", "", "", "").toString());
        assertEquals("allow", wall.check("x", "GET", "/", "", "", "").action);
    }

    @Test
    void aTargetInAbsoluteFormIsCheckedInOriginForm() {
        Firewall wall = Fixtures.firewall("s", Json.map(Json.parse(RULES)));
        assertEquals("request:install", wall.check("198.51.100.7", "GET", "x:/wp-admin/install.php", "", "", "").rule);
        assertEquals("request:install", wall.check("198.51.100.9", "GET", "http://h/wp-admin/install.php?a=1", "", "", "").rule);
    }

    // ---- The proxy ----

    static Map<String, Object> started(int status, AtomicInteger asked) throws Exception {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            asked.incrementAndGet();
            exchange.sendResponseHeaders(status, -1);
            exchange.close();
        });
        server.start();
        Map<String, Object> out = new HashMap<>();
        out.put("server", server);
        out.put("proxy", new Proxy(new Core("a".repeat(24), "s", "http://127.0.0.1:" + server.getAddress().getPort(), false, "t"), null));
        return out;
    }

    @Test
    void failedTrackerVersionsAreRememberedInABoundedList() throws Exception {
        AtomicInteger asked = new AtomicInteger();
        Map<String, Object> up = started(404, asked);
        Proxy proxy = (Proxy) up.get("proxy");
        try {
            for (int i = 0; i < Proxy.MAX_FAILED + 50; i++) {
                assertEquals(502, proxy.handle("js", "v" + (1000 + i) + "/s.js", "GET", "", null, null, "198.51.100.7").status());
            }
            assertEquals(Proxy.MAX_FAILED, proxy.failing(), "the oldest made room");
            int before = asked.get();
            proxy.handle("js", "v" + (1000 + Proxy.MAX_FAILED + 49) + "/s.js", "GET", "", null, null, "198.51.100.7");
            assertEquals(before, asked.get(), "a version that failed lately isn't asked for again");
            assertFalse(proxy.breakerOpen(), "a 404 is no collector failure");
        } finally {
            proxy.close();
            ((HttpServer) up.get("server")).stop(0);
        }
    }

    @Test
    void aMalformedQueryIsAnsweredWithoutTheCollectorOrTheBreaker() throws Exception {
        AtomicInteger asked = new AtomicInteger();
        Map<String, Object> up = started(204, asked);
        Proxy proxy = (Proxy) up.get("proxy");
        try {
            for (int i = 0; i < Proxy.FAILS_TO_OPEN + 2; i++) {
                assertEquals(400, proxy.handle("api", "e", "GET", "a=%zz", Collections.emptyMap(), null, "198.51.100.7").status());
                assertEquals(400, proxy.handle("api", "e", "GET", "a=%", Collections.emptyMap(), null, "198.51.100.7").status());
            }
            assertFalse(proxy.breakerOpen());
            assertEquals(0, asked.get());
            assertEquals(204, proxy.handle("api", "e", "GET", "a=%20", Collections.emptyMap(), null, "198.51.100.7").status());
        } finally {
            proxy.close();
            ((HttpServer) up.get("server")).stop(0);
        }
    }

    // ---- Maintenance's preview cookie ----

    @Test
    void thePreviewCookieIsSecureOverHttps() {
        Core core = Fixtures.offline("s");
        core.apply(Json.map(Json.parse("{\"v\":1,\"modules\":{},\"maintenance\":{\"on\":true,\"bypass\":\"code\"}}")));
        Maintenance maintenance = new Maintenance(core, null);
        String secure = maintenance.decide("198.51.100.7", "/", "site_preview=code", "", true).headers().get(0)[1];
        assertTrue(secure.endsWith("; Secure"), secure);
        String plain = maintenance.decide("198.51.100.7", "/", "site_preview=code", "", false).headers().get(0)[1];
        assertFalse(plain.contains("Secure"), plain);
    }

    // ---- requestIp(request) ----

    static Object request(String remote, Map<String, String> headers, Map<String, Object> attributes) {
        return java.lang.reflect.Proxy.newProxyInstance(SecurityFixesTest.class.getClassLoader(),
                new Class<?>[] {jakarta.servlet.http.HttpServletRequest.class}, (self, method, args) -> {
                    switch (method.getName()) {
                        case "getRemoteAddr":
                            return remote;
                        case "getHeaderNames":
                            return Collections.enumeration(headers.keySet());
                        case "getHeaders":
                            String value = headers.get((String) args[0]);
                            return Collections.enumeration(value == null ? List.of() : List.of(value));
                        case "getHeader":
                            return headers.get((String) args[0]);
                        case "getAttribute":
                            return attributes.get((String) args[0]);
                        default:
                            return null;
                    }
                });
    }

    @Test
    void requestIpLeavesTheHeadersAloneWhenTomcatAlreadyReadThem() {
        Platform platform = Platform.create(new PlatformOptions().siteId("a".repeat(24)).secret("s").endpoint("http://127.0.0.1:9")
                .trustProxy("1").shutdownHook(false).inventory(false).posture(false).resources(false));
        try {
            Map<String, String> headers = new LinkedHashMap<>();
            headers.put("X-Forwarded-For", "203.0.113.5");
            Map<String, Object> attributes = new HashMap<>();
            assertEquals("203.0.113.5", platform.requestIp(request("198.51.100.7", headers, attributes)));
            attributes.put(Platform.TOMCAT_FORWARDED, "true");
            assertEquals("198.51.100.7", platform.requestIp(request("198.51.100.7", headers, attributes)), "what is left is the visitor's writing");
            attributes.put(Platform.IP_ATTRIBUTE, "192.0.2.1");
            assertEquals("192.0.2.1", platform.requestIp(request("198.51.100.7", headers, attributes)), "the filter's own answer");
        } finally {
            platform.close(500);
        }
    }

    // ---- Form protection ----

    @Test
    void privateFieldsAndCardNumbersNeverGoToTheCollector() {
        Map<String, Object> fields = new LinkedHashMap<>();
        for (String name : new String[] {"password", "user_pwd", "cc-number", "cc-csc", "cc-exp", "cvn", "exp_month", "otp", "mfa_code",
                "pin", "api_key", "Authorization", "iban", "routing", "account_number", "dob", "date_of_birth", "licence", "nonce", "ssn"}) {
            fields.put(name, "x");
        }
        fields.put("message", "Order 12345, card 4111 1111 1111 1111 please, call 0123 456 7890");
        fields.put("spinach", "kept");
        fields.put("amount", 25);
        Map<String, String> sent = Forms.plainFields(fields);
        assertEquals(java.util.Arrays.asList("message", "spinach", "amount"), new java.util.ArrayList<>(sent.keySet()), sent.toString());
        assertEquals("Order 12345, card [removed] please, call 0123 456 7890", sent.get("message"));
        assertEquals("25", sent.get("amount"));
    }
}
