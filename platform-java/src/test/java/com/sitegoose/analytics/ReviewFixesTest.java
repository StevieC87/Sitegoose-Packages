package com.sitegoose.analytics;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.io.ByteArrayInputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

/** What the review of the Java package found, each pinned down. */
class ReviewFixesTest {
    static final Object UNREADABLE = new Object() {
        @Override
        public String toString() {
            throw new IllegalStateException("could not initialize proxy - no Session");
        }
    };

    // ---- The visitor's address ----

    @Test
    void portsInProxyHeadersAreDropped() {
        assertEquals("203.0.113.5", Ip.withoutPort("203.0.113.5:54321"));
        assertEquals("2001:db8::1", Ip.withoutPort("[2001:db8::1]:443"));
        assertEquals("2001:db8::1", Ip.withoutPort("[2001:db8::1]"));
        assertEquals("2001:db8::1", Ip.withoutPort("2001:db8::1"));
        assertEquals("::ffff:203.0.113.5", Ip.withoutPort("::ffff:203.0.113.5"));
        Map<String, String> azure = Collections.singletonMap("x-forwarded-for", "198.51.100.1:1234, 203.0.113.5:54321");
        assertEquals("203.0.113.5", TrustProxy.hops(1).clientIp("10.0.0.1", azure));
        assertEquals("198.51.100.1", TrustProxy.hops(2).clientIp("10.0.0.1", azure));
        assertEquals("10.0.0.1", TrustProxy.hops(1).clientIp("10.0.0.1", Collections.singletonMap("x-forwarded-for", "unknown")));
        assertEquals("10.0.0.1", TrustProxy.hops(1).clientIp("10.0.0.1", Collections.singletonMap("x-forwarded-for", "_hidden")));
    }

    @Test
    void anAddressThatIsntOneNeverLetsARequestPast() {
        Firewall wall = Fixtures.firewall("s", Json.map(Json.parse("{\"v\":1,\"enabled\":true,\"mode\":\"block\",\"deny\":[\"203.0.113.0/24\"]}")));
        assertEquals("block", wall.check(wall.clientIp("203.0.113.5:443", Collections.emptyMap()), "GET", "/", "", "", "").action);
        Firewall custom = new Firewall(Fixtures.offline("s"), null, TrustProxy.custom(h -> "not-an-address"));
        assertEquals("203.0.113.5", custom.clientIp("203.0.113.5", Collections.emptyMap()));
    }

    @Test
    void ipv6IsBannedByItsSlash64AndMappedIpv4IsOneAddress() {
        Firewall wall = Fixtures.firewall("s", Json.map(Json.parse(
                "{\"v\":1,\"enabled\":true,\"mode\":\"block\",\"rate\":{\"limit\":1,\"window\":60},\"ban\":{\"seconds\":600}}")));
        assertEquals("", wall.check("2001:db8:1:2::1", "GET", "/", "", "", "").rule);
        assertEquals("rate", wall.check("2001:db8:1:2::99", "GET", "/", "", "", "").rule, "the same /64 counts as one");
        assertEquals("ban", wall.check("2001:db8:1:2:ffff::7", "GET", "/", "", "", "").rule);
        assertEquals("", wall.check("2001:db8:1:3::1", "GET", "/", "", "", "").rule, "another /64 is someone else");
        assertEquals("", wall.check("203.0.113.9", "GET", "/", "", "", "").rule);
        assertEquals("rate", wall.check("::ffff:203.0.113.9", "GET", "/", "", "", "").rule);
        assertEquals("2001:db8:1:2::/64", Ip.bucket("2001:db8:1:2::1"));
        assertEquals("2001:db8:1:2::/64", Ip.bucket("[2001:DB8:1:2:ffff::1]:443"));
        assertEquals("2001::/64", Ip.bucket("2001::1"));
        assertEquals("::/64", Ip.bucket("::1"));
        assertEquals("2001:db8:0:1::/64", Ip.bucket("2001:db8:0:1:2:3:4:5"));
        assertEquals("0:0:1::/64", Ip.bucket("0:0:1:0::9"));
        assertEquals("198.51.100.7", Ip.bucket("::ffff:198.51.100.7"));
    }

    @Test
    void aFullTableForgetsTheOldestNotEveryone() {
        Firewall wall = Fixtures.firewall("s", Json.map(Json.parse("{\"v\":1,\"enabled\":true,\"mode\":\"monitor\",\"rate\":{\"limit\":1,\"window\":3600}}")));
        assertEquals("", wall.check("10.0.0.1", "GET", "/", "", "", "").rule);
        for (int i = 0; i < Firewall.COUNTER_MAX; i++) {
            wall.check("10." + (1 + i / 65536) + "." + (i / 256 % 256) + "." + (i % 256), "GET", "/", "", "", "");
        }
        assertEquals("rate", wall.check("10.2.134.159", "GET", "/", "", "", "").rule, "the newest is still counted");
        assertEquals("", wall.check("10.0.0.1", "GET", "/", "", "", "").rule, "the oldest made room");
    }

    @Test
    void staticFilesDontCountAgainstTheRateLimit() {
        Firewall wall = Fixtures.firewall("s", Json.map(Json.parse("{\"v\":1,\"enabled\":true,\"mode\":\"block\",\"rate\":{\"limit\":2,\"window\":60}}")));
        for (int i = 0; i < 10; i++) {
            assertEquals("", wall.check("203.0.113.9", "GET", "/img/" + i + ".png?v=3", "", "", "").rule);
        }
        assertEquals(java.util.Arrays.asList("", "", "rate"), FirewallTest.rules(wall, 3));
    }

    // ---- Paths as the router sees them ----

    @Test
    void rulesSeeThePathTheRouterResolves() {
        assertEquals("/actuator/env", RequestRules.resolvePath("/actuator;x/env"));
        assertEquals("/actuator/env", RequestRules.resolvePath("/a/../actuator/env"));
        assertEquals("/actuator/env", RequestRules.resolvePath("/./actuator/./env"));
        assertEquals("/env", RequestRules.resolvePath("/../../env"));
        assertEquals("/a/", RequestRules.resolvePath("/a/b/../"));
        List<RequestRules.Rule> rules = RequestRules.compile(Json.parse(
                "{\"rules\":[{\"id\":\"actuator\",\"action\":\"block\",\"path\":{\"exact\":[\"/actuator/env\"]}}]}"));
        for (String target : new String[] {"/actuator/env", "/actuator;x/env", "/a/../actuator/env", "/a/%2e%2e/actuator/env",
            "/actuator;jsessionid=1/env;x=y", "/ACTUATOR/env"}) {
            RequestRules.Rule hit = RequestRules.match(rules, "GET", target, "");
            assertNotNull(hit, target);
        }
        assertNull(RequestRules.match(rules, "GET", "/actuator/health", ""));
        Firewall.Probes probes = Firewall.compileProbes(Json.parse("{\"exact\":[\"/.env\"],\"prefix\":[\"/.git/\"]}"));
        assertTrue(Firewall.isProbe("/x/../.env", probes));
        assertTrue(Firewall.isProbe("/.env;a", probes));
        assertTrue(Firewall.isProbe("/static/%2e%2e/.git/config", probes));
    }

    // ---- Values that can't be sent ----

    @Test
    void aValueThatCantBeReadIsRefusedInTheCallNotAtSendTime() {
        assertThrows(IllegalArgumentException.class, () -> Json.safe(Collections.singletonMap("order", UNREADABLE)));
        Map<String, Object> plain = Json.safeMap(Collections.singletonMap("when", java.time.Instant.EPOCH));
        assertEquals("1970-01-01T00:00:00Z", plain.get("when"));
        Platform platform = Platform.create(new PlatformOptions().siteId("a".repeat(24)).secret("s").endpoint("http://127.0.0.1:9")
                .shutdownHook(false).allOff().analytics(true).audit(true));
        try {
            assertEquals("", platform.track("order.paid", Collections.singletonMap("order", UNREADABLE)));
            assertFalse(platform.track("order.paid", Collections.singletonMap("value", 5)).isEmpty());
            platform.audit("user.changed", "a", "b", Collections.singletonMap("user", UNREADABLE));
            assertNull(platform.lead(Collections.singletonMap("email", UNREADABLE)));
        } finally {
            platform.close(500);
        }
        Core core = new Core("a".repeat(24), "s", "http://127.0.0.1:9", false, "t");
        Core.Response res = core.post("analytics", "/events/server-events", Collections.singletonMap("x", UNREADABLE));
        assertNotNull(res, "not a network failure");
        assertEquals(Core.UNSENDABLE, res.status);
        core.shutdown();
    }

    // ---- Server speed and headers ----

    @Test
    void madeUpMethodsAreOneRowAndTheTableHasAHardCap() {
        Performance performance = new Performance(Fixtures.offline("s"), "t");
        performance.record("FOOBAR", "/x", 200, 1, "/x");
        performance.record("get", "/x", 200, 1, "/x");
        List<String> methods = new ArrayList<>();
        for (Map<String, Object> row : performance.take(true)) {
            methods.add((String) row.get("method"));
        }
        Collections.sort(methods);
        assertEquals(java.util.Arrays.asList("GET", "OTHER"), methods);
        for (int i = 0; i < 2000; i++) {
            performance.record("GET", "/r" + i, 100 + i % 500, 1, "/r" + i);
        }
        assertTrue(performance.take(true).size() <= Performance.HARD_MAX_KEYS);
    }

    @Test
    void securityHeaderValuesAreVisibleAscii() {
        Core core = Fixtures.offline("s");
        core.apply(Json.map(Json.parse("{\"v\":1,\"modules\":{},\"headers\":[[\"X-Frame-Options\",\"SAMEORIGIN\"],"
                + "[\"X-Bad\",\"caf\\u00e9\"],[\"X-Break\",\"a\\u0000b\"],[\"Content-Security-Policy\",\"default-src 'self'\"]]}")));
        List<String> names = new ArrayList<>();
        for (String[] pair : core.securityHeaders()) {
            names.add(pair[0]);
        }
        assertEquals(java.util.Arrays.asList("X-Frame-Options", "Content-Security-Policy"), names);
    }

    // ---- Shutting down ----

    @Test
    void closeKeepsToItsBudgetWhenTheCollectorNeverAnswers() throws Exception {
        try (ServerSocket blackHole = new ServerSocket(0)) {
            List<Socket> held = Collections.synchronizedList(new ArrayList<>());
            Thread acceptor = new Thread(() -> {
                try {
                    while (true) {
                        held.add(blackHole.accept());
                    }
                } catch (Exception closed) {
                    // done
                }
            });
            acceptor.setDaemon(true);
            acceptor.start();
            Platform platform = Platform.create(new PlatformOptions().siteId("a".repeat(24)).secret("s")
                    .endpoint("http://127.0.0.1:" + blackHole.getLocalPort()).shutdownHook(false)
                    .inventory(false).posture(false).resources(false).errors(e -> e.noSpool().captureUncaught(false)));
            platform.track("signup", Collections.singletonMap("plan", "pro"));
            platform.captureException(new IllegalStateException("x"));
            platform.timeRequest("GET", "/", 200, System.nanoTime(), "/");
            platform.audit("a", "b", "c", null);
            long started = System.nanoTime();
            platform.close(1500);
            long ms = (System.nanoTime() - started) / 1_000_000;
            assertTrue(ms < 4000, "closed in " + ms + " ms");
            for (Socket socket : held) {
                socket.close();
            }
        }
    }

    @Test
    void theJvmsHandlerIsLeftAloneInASharedContainer() {
        class FakeWebappClassLoader extends ClassLoader {
            FakeWebappClassLoader() {
                super(ReviewFixesTest.class.getClassLoader());
            }
        }
        assertTrue(Errors.sharedContainer(new FakeWebappClassLoader()));
        assertFalse(Errors.sharedContainer(ClassLoader.getSystemClassLoader()));
        Thread.UncaughtExceptionHandler before = Thread.getDefaultUncaughtExceptionHandler();
        Platform platform = Platform.create(new PlatformOptions().siteId("a".repeat(24)).secret("s").endpoint("http://127.0.0.1:9")
                .shutdownHook(false).allOff().errors(e -> e.noSpool()));
        platform.close(200);
        assertEquals(before, Thread.getDefaultUncaughtExceptionHandler(), "put back at close");
    }

    @Test
    void theErrorsFileIsKeptUntilItWasSentAndAbandonedOnesArePickedUp() throws Exception {
        AtomicInteger status = new AtomicInteger(503);
        List<String> bodies = Collections.synchronizedList(new ArrayList<>());
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            bodies.add(new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            exchange.sendResponseHeaders(status.get(), -1);
            exchange.close();
        });
        server.start();
        Path dir = Files.createTempDirectory("spool");
        try {
            Core core = new Core("a".repeat(24), "s", "http://127.0.0.1:" + server.getAddress().getPort(), false, "t");
            PlatformOptions.ErrorsOptions options = new PlatformOptions.ErrorsOptions().captureUncaught(false).spoolDir(dir.toString());
            Errors errors = new Errors(core, options, "t");
            errors.close();
            Map<String, Object> first = new LinkedHashMap<>();
            first.put("message", "first");
            errors.spool(Collections.singletonList(first));
            errors.resend();
            assertTrue(Files.exists(errors.spoolFile), "the collector failed: still in the file");
            assertTrue(new String(Files.readAllBytes(errors.spoolFile), StandardCharsets.UTF_8).contains("first"));

            // A process that stopped while sending left its taken file behind.
            Path abandoned = Path.of(errors.spoolFile + ".2147483646.1.sending");
            Files.write(abandoned, "{\"message\":\"left behind\"}\n{broken".getBytes(StandardCharsets.UTF_8));
            status.set(202);
            bodies.clear();
            errors.resend();
            String sent = String.join("\n", bodies);
            assertTrue(sent.contains("first") && sent.contains("left behind"), sent);
            assertFalse(Files.exists(errors.spoolFile));
            try (java.util.stream.Stream<Path> left = Files.list(dir)) {
                assertEquals(0, left.count(), "nothing left once sent");
            }
            core.shutdown();
        } finally {
            server.stop(0);
        }
    }

    // ---- Inventory and posture ----

    @Test
    void anOversizedPomPropertiesIsNotRead() throws Exception {
        Map<String, Map<String, Object>> found = new LinkedHashMap<>();
        String big = "groupId=a\nartifactId=b\nversion=1\n#" + "x".repeat(Inventory.POM_MAX);
        Inventory.add(new ByteArrayInputStream(big.getBytes(StandardCharsets.ISO_8859_1)), found);
        assertTrue(found.isEmpty());
        Inventory.add(new ByteArrayInputStream("groupId=a\nartifactId=b\nversion=1\n".getBytes(StandardCharsets.ISO_8859_1)), found);
        assertEquals(Collections.singleton("a:b"), found.keySet());
    }

    @Test
    void webInfAndMetaInfAtTheWebrootAreNotServed() throws Exception {
        Path root = Files.createTempDirectory("webroot");
        Files.createDirectories(root.resolve("WEB-INF"));
        Files.createDirectories(root.resolve("META-INF"));
        Files.write(root.resolve("WEB-INF/.env"), "x".getBytes(StandardCharsets.UTF_8));
        Files.write(root.resolve("META-INF/backup.sql"), "x".getBytes(StandardCharsets.UTF_8));
        Files.write(root.resolve(".env"), "x".getBytes(StandardCharsets.UTF_8));
        Posture.Walk walk = Posture.walk(Collections.singletonList(Posture.Root.dir(root.toString(), "")));
        List<Object> paths = new ArrayList<>();
        for (Map<String, Object> row : walk.exposure) {
            paths.add(row.get("path"));
        }
        assertEquals(Collections.singletonList(".env"), paths);
    }
}
