package com.sitegoose.analytics;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Predicate;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** The whole package against a collector on localhost: what it asks for and what it sends. */
class CollectorTest {
    static final class Seen {
        final String method;
        final String path;
        final Map<String, String> headers;
        final String body;

        Seen(String method, String path, Map<String, String> headers, String body) {
            this.method = method;
            this.path = path;
            this.headers = headers;
            this.body = body;
        }

        Map<String, Object> json() {
            return Json.map(Json.parse(body));
        }
    }

    static final String RULES = "{\"v\":1,\"enabled\":true,\"mode\":\"block\",\"deny\":[\"203.0.113.0/24\"],\"sync\":300}";
    static final String CONFIG = "{\"v\":1,\"modules\":{\"firewall\":true,\"errors\":true,\"analytics\":true,\"performance\":true,"
            + "\"crawlers\":true,\"headers\":true,\"audit\":true,\"flags\":true,\"maintenance\":true},"
            + "\"headers\":[[\"X-Frame-Options\",\"SAMEORIGIN\"]],\"flags\":{\"beta\":{\"on\":true}},\"sync\":300}";

    HttpServer server;
    final List<Seen> seen = new CopyOnWriteArrayList<>();
    Platform platform;

    @BeforeEach
    void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            Map<String, String> headers = new java.util.LinkedHashMap<>();
            exchange.getRequestHeaders().forEach((k, v) -> headers.put(k.toLowerCase(Locale.ROOT), v.get(0)));
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            String path = exchange.getRequestURI().toString();
            seen.add(new Seen(exchange.getRequestMethod(), path, headers, body));
            String answer = path.startsWith("/events/firewall/rules") ? RULES
                    : path.startsWith("/events/platform/config") ? CONFIG : "{\"ok\":true}";
            int status = path.startsWith("/events/firewall/rules") || path.startsWith("/events/platform/config") ? 200 : 202;
            byte[] out = answer.getBytes(StandardCharsets.UTF_8);
            exchange.getResponseHeaders().add("Content-Type", "application/json");
            exchange.getResponseHeaders().add("ETag", "\"one\"");
            exchange.sendResponseHeaders(status, out.length);
            exchange.getResponseBody().write(out);
            exchange.close();
        });
        server.start();
        platform = Platform.create(new PlatformOptions()
                .siteId("a".repeat(24)).secret("test-secret").endpoint("http://127.0.0.1:" + server.getAddress().getPort())
                .serverName("shop-api").shutdownHook(false)
                .inventory(false).posture(false).resources(false)
                .errors(e -> e.noSpool().captureUncaught(false)));
    }

    @AfterEach
    void stop() {
        platform.close();
        server.stop(0);
    }

    Seen await(Predicate<Seen> wanted) throws InterruptedException {
        for (int i = 0; i < 100; i++) {
            for (Seen s : seen) {
                if (wanted.test(s)) {
                    return s;
                }
            }
            Thread.sleep(50);
        }
        return null;
    }

    @Test
    void rulesAndSwitchesAreFetchedAndUsed() throws Exception {
        Seen rules = await(s -> s.path.startsWith("/events/firewall/rules"));
        assertNotNull(rules);
        assertEquals("GET", rules.method);
        assertEquals("Bearer test-secret", rules.headers.get("authorization"));
        assertEquals("app check", rules.headers.get("x-firewall-layers"));
        assertEquals("analytics-platform-java/" + Version.VERSION, rules.headers.get("user-agent"));
        Seen config = await(s -> s.path.startsWith("/events/platform/config"));
        assertNotNull(config);
        String app = config.headers.get("x-platform-app");
        assertTrue(app.startsWith("server=shop-api&kind=process&pid="), app);
        assertTrue(app.contains("runtime=Java+"), app);
        assertTrue(config.headers.get("x-platform-modules").startsWith("proxy,firewall,errors,analytics,performance"), config.headers.get("x-platform-modules"));

        for (int i = 0; i < 50 && platform.firewall().rules == null; i++) {
            Thread.sleep(50);
        }
        Reply blocked = platform.blocked("203.0.113.5", Collections.emptyMap(), "GET", "/");
        assertNotNull(blocked);
        assertEquals(403, blocked.status());
        assertNull(platform.blocked("198.51.100.5", Collections.emptyMap(), "GET", "/"));

        for (int i = 0; i < 50 && platform.securityHeaders(null).isEmpty(); i++) {
            Thread.sleep(50);
        }
        assertEquals("X-Frame-Options", platform.securityHeaders(Collections.singleton("content-type")).get(0)[0]);
        assertTrue(platform.securityHeaders(Collections.singleton("x-frame-options")).isEmpty(), "the app's own header wins");
        assertTrue(platform.isEnabled("beta"));

        platform.flush();
        Seen events = await(s -> s.path.equals("/events/firewall/events"));
        assertNotNull(events);
        Map<String, Object> row = Fixtures.rows(events.json().get("events")).get(0);
        assertEquals("deny", row.get("rule"));
        assertEquals("block", row.get("action"));
    }

    @Test
    void errorsRequestsAndEventsAreSent() throws Exception {
        try (Platform.Scope ignored = platform.enterRequest("GET", "/orders/7", () -> "/orders/{id}", "visit-1", "198.51.100.5")) {
            platform.addBreadcrumb("looked up the order");
            platform.captureException(new IllegalStateException("no such order"), 500);
        }
        platform.timeRequest("GET", "/orders/{id}", 200, System.nanoTime() - 12_000_000L, "/orders/7");
        platform.recordCrawler("Mozilla/5.0 (compatible; GPTBot/1.0)", "/orders/7", 200, System.nanoTime(), 512, "198.51.100.9");
        String uid = platform.track("signup", Collections.singletonMap("plan", "pro"), "visit-1");
        assertNotNull(uid);
        platform.flush();

        Seen error = await(s -> s.path.equals("/events/server-errors"));
        assertNotNull(error);
        String body = error.body;
        assertTrue(body.contains("java.lang.IllegalStateException"), body);
        assertTrue(body.contains("no such order"), body);
        assertTrue(body.contains("/orders/{id}"), body);
        assertTrue(body.contains("looked up the order"), body);
        assertTrue(body.contains("\"sitesecret\":\"test-secret\""), body);

        Seen requests = await(s -> s.path.equals("/events/server-requests"));
        assertNotNull(requests);
        Map<String, Object> sent = requests.json();
        assertEquals("shop-api", sent.get("server_name"));
        assertTrue(String.valueOf(sent.get("runtime")).startsWith("Java "), String.valueOf(sent.get("runtime")));
        assertEquals("/orders/{id}", Fixtures.rows(sent.get("rows")).get(0).get("route"));

        Seen crawlers = await(s -> s.path.equals("/events/crawlers"));
        assertNotNull(crawlers);
        assertEquals("GPTBot", Fixtures.rows(crawlers.json().get("rows")).get(0).get("bot"));

        Seen events = await(s -> s.path.equals("/events/server-events"));
        assertNotNull(events);
        assertTrue(events.body.contains("signup") && events.body.contains(uid), events.body);
    }

    @Test
    void identifySendsScalarTraitsAndLeavesTheRestOut() throws Exception {
        assertTrue(platform.identify("u1", "visit-1"));
        Map<String, Object> traits = new java.util.LinkedHashMap<>();
        traits.put("plan", "pro");
        traits.put("Seats", 5);
        traits.put("trial", false);
        traits.put("tags", List.of("a"));
        traits.put("meta", Map.of("a", 1));
        traits.put("gone", null);
        traits.put("bad", Double.NaN);
        assertTrue(platform.identify("u2", "visit-1", traits));
        assertTrue(platform.identify("u3", "visit-1", Map.of("tags", List.of("a"))));

        List<Map<String, Object>> sent = new java.util.ArrayList<>();
        for (Seen s : seen) {
            if (s.path.equals("/events/identify")) {
                sent.add(s.json());
            }
        }
        assertEquals(3, sent.size());
        assertNull(sent.get(0).get("traits"));
        Map<String, Object> kept = Json.map(sent.get(1).get("traits"));
        assertEquals(java.util.Set.of("plan", "Seats", "trial"), kept.keySet());
        assertEquals("pro", kept.get("plan"));
        assertEquals(5, ((Number) kept.get("Seats")).intValue());
        assertEquals(false, kept.get("trial"));
        assertNull(sent.get(2).get("traits"));
    }
}
