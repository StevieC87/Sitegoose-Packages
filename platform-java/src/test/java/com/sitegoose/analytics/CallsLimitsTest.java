package com.sitegoose.analytics;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Function;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;

/**
 * Outgoing calls (sdk/protocols/calls.md), ClickHouse's JDBC label, the
 * firewall's static-file check, and the limits pass of the resources module
 * (resources.md "Limits"). Every file is read through a fake reader; calls go
 * to a server on this machine.
 */
class CallsLimitsTest {
    static final long MB = 1024 * 1024;

    static Platform offline(PlatformOptions options) {
        return Platform.create(options.allOff().performance(true).errors(true)
                .errors(e -> e.noSpool().captureUncaught(false).captureLogging(false)).shutdownHook(false));
    }

    /** Rows keyed "METHOD route call_method host" -> the row. */
    static Map<String, Map<String, Object>> rows(Platform platform) {
        Map<String, Map<String, Object>> out = new HashMap<>();
        for (Map<String, Object> row : platform.calls().take(true)) {
            out.put(row.get("method") + " " + row.get("route") + " " + row.get("call_method") + " " + row.get("host"), row);
        }
        return out;
    }

    /** A server answering each path with the status it names (/404, /503...). */
    static HttpServer server(List<String> seen) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            String path = exchange.getRequestURI().getPath();
            seen.add(exchange.getRequestMethod() + " " + path);
            int status = path.length() == 4 ? Integer.parseInt(path.substring(1)) : 200;
            byte[] out = "ok".getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(status, out.length);
            exchange.getResponseBody().write(out);
            exchange.close();
        });
        server.start();
        return server;
    }

    static int closedPort() throws IOException {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }

    @Test
    void onlyTheHostIsKept() {
        assertEquals("api.stripe.com", Calls.hostOf("https://API.Stripe.com/v1/customers/cus_8x?key=secret"));
        assertEquals("localhost:8080", Calls.hostOf("http://localhost:8080/x"));
        assertEquals("[::1]:3000", Calls.hostOf("http://[::1]:3000/"));
        assertEquals("a.example", Calls.hostOf("https://a.example:443/"));
        assertEquals("a.example:80", Calls.hostOf("https://a.example:80/"));
        assertEquals("my_host", Calls.hostOf("http://user:pw@my_host:80/x"));
        assertEquals("", Calls.hostOf("not a url"));
        assertEquals("", Calls.hostOf("/relative"));
        assertTrue(Calls.isOwn(Calls.address("https://collect.example.com"), "https://Collect.example.com:443/events/server-calls?x=1"));
        assertTrue(Calls.isOwn(Calls.address("https://collect.example.com/"), "https://collect.example.com"));
        assertFalse(Calls.isOwn(Calls.address("https://collect.example.com"), "https://collect.example.com.evil.test/events"));
        assertFalse(Calls.isOwn(Calls.address("https://x.example/base"), "https://x.example/basement"));
        assertFalse(Calls.isOwn(Calls.address(""), "https://x.example/"));
        // The trail's step: no query, and no user:password@.
        assertEquals("https://api.example/v1/a@b", Calls.withoutSecrets("https://user:pw@api.example/v1/a@b?key=k#x"));
        assertEquals("https://api.example", Calls.withoutSecrets("https://u@api.example"));
        assertEquals("/relative", Calls.withoutSecrets("/relative?x"));
        assertFalse(Calls.failed(404));
        assertTrue(Calls.failed(503));
        assertTrue(Calls.failed(0));
        assertEquals("", Calls.methodOf("MADE-UP"));
    }

    @Test
    void callsGoUnderTheirRequestsRoute() {
        Platform platform = offline(new PlatformOptions());
        long now = System.nanoTime();
        Platform.Scope scope = platform.enterRequest("POST", "/checkout", () -> "/checkout", "", "");
        platform.recordCall("post", "https://api.stripe.com/v1/charges?amount=5", now, 200);
        // A step in the request's error trail too, without its query string.
        assertEquals("POST https://api.stripe.com/v1/charges", scope.context().breadcrumbs().get(0).get("text"));
        platform.recordCall("POST", "https://api.stripe.com/v1/refunds", now, 502);
        platform.recordCall("GET", "https://api.stripe.com/v1/x", now, 404);
        platform.recordCall("GET", "https://api.stripe.com/v1/x", now, 0);
        for (int i = 0; i < 60; i++) {
            platform.recordCall("GET", "https://h" + i + ".example/", now, 200);
        }
        scope.close();
        platform.timeRequest("POST", "/checkout", 200, now, "/checkout", scope.context());
        // Outside any request: background.
        platform.recordCall("GET", "https://cron.example/ping", now, 200);

        Map<String, Map<String, Object>> rows = rows(platform);
        Map<String, Object> post = rows.get("POST /checkout POST api.stripe.com");
        assertNotNull(post, rows.keySet().toString());
        assertEquals(2L, post.get("count"));
        assertEquals(1L, post.get("errors"), "a 5xx failed");
        Map<String, Object> get = rows.get("POST /checkout GET api.stripe.com");
        assertEquals(2L, get.get("count"));
        assertEquals(1L, get.get("errors"), "a 4xx is an answer, no answer is an error");
        // 50 hosts a request: the rest are (other).
        assertEquals(12L, rows.get("POST /checkout GET (other)").get("count"));
        assertNotNull(rows.get("JOB (background) GET cron.example"));
        assertFalse(rows.toString().contains("amount"), "no path or query leaves the server");
        platform.close(0);
    }

    @Test
    void callsFalseKeepsServerSpeed() {
        Platform platform = offline(new PlatformOptions().calls(false));
        assertNull(platform.calls());
        assertNotNull(platform.queries());
        Platform.Scope scope = platform.enterRequest("GET", "/", () -> "/", "", "");
        platform.recordCall("GET", "https://api.example/x", System.nanoTime(), 200);
        scope.close();
        assertEquals(1, scope.context().breadcrumbs().size(), "still a step in the error trail");
        platform.close(0);
    }

    @Test
    void theCollectorsOwnCallsAreLeftOut() {
        Platform platform = Platform.create(new PlatformOptions().allOff().performance(true).siteId("c".repeat(24))
                .secret("s").endpoint("http://127.0.0.1:1").shutdownHook(false));
        platform.recordCall("POST", "http://127.0.0.1:1/events/server-calls", System.nanoTime(), 202);
        platform.recordCall("GET", "http://127.0.0.1:2/other", System.nanoTime(), 200);
        Map<String, Map<String, Object>> rows = rows(platform);
        assertEquals(1, rows.size(), rows.keySet().toString());
        assertNotNull(rows.get("JOB (background) GET 127.0.0.1:2"));
        platform.close(0);
    }

    @Test
    void httpClientCallsAreTimedToTheirHeaders() throws Exception {
        List<String> seen = new CopyOnWriteArrayList<>();
        HttpServer server = server(seen);
        Platform platform = offline(new PlatformOptions());
        HttpClient client = HttpClient.newHttpClient();
        String base = "http://127.0.0.1:" + server.getAddress().getPort();
        try (Platform.Scope scope = platform.enterRequest("GET", "/report", () -> "/report", "", "")) {
            HttpResponse<String> ok = platform.send(client, HttpRequest.newBuilder(URI.create(base + "/ok?token=x")).build(),
                    HttpResponse.BodyHandlers.ofString());
            assertEquals("ok", ok.body());
            platform.send(client, HttpRequest.newBuilder(URI.create(base + "/503")).build(), HttpResponse.BodyHandlers.discarding());
            platform.sendAsync(client, HttpRequest.newBuilder(URI.create(base + "/404")).build(), HttpResponse.BodyHandlers.discarding()).get();
            URI refused = URI.create("http://127.0.0.1:" + closedPort() + "/");
            assertThrows(IOException.class, () -> platform.send(client, HttpRequest.newBuilder(refused).build(),
                    HttpResponse.BodyHandlers.discarding()));
            platform.timeRequest("GET", "/report", 200, System.nanoTime(), "/report", scope.context());
        } finally {
            server.stop(0);
        }
        Map<String, Map<String, Object>> rows = rows(platform);
        Map<String, Object> local = rows.get("GET /report GET 127.0.0.1:" + server.getAddress().getPort());
        assertNotNull(local, rows.keySet().toString());
        assertEquals(3L, local.get("count"));
        assertEquals(1L, local.get("errors"));
        assertEquals(2, rows.size(), rows.keySet().toString());
        String refusedKey = rows.keySet().stream().filter(k -> !k.equals("GET /report GET 127.0.0.1:" + server.getAddress().getPort()))
                .findFirst().orElse("");
        assertEquals(1L, rows.get(refusedKey).get("errors"), "refused is an error");
        assertEquals(3, seen.size());
        platform.close(0);
    }

    @Test
    void okHttpCalls() throws Exception {
        List<String> seen = new CopyOnWriteArrayList<>();
        HttpServer server = server(seen);
        Platform platform = offline(new PlatformOptions());
        okhttp3.Interceptor interceptor = platform.okHttpInterceptor();
        okhttp3.OkHttpClient client = new okhttp3.OkHttpClient.Builder().addInterceptor(interceptor).build();
        String base = "http://127.0.0.1:" + server.getAddress().getPort();
        try (Platform.Scope scope = platform.enterRequest("GET", "/sync", () -> "/sync", "", "")) {
            try (okhttp3.Response r = client.newCall(new okhttp3.Request.Builder().url(base + "/500").build()).execute()) {
                assertEquals(500, r.code());
            }
            try (okhttp3.Response r = client.newCall(new okhttp3.Request.Builder().url(base + "/ok")
                    .post(okhttp3.RequestBody.create(new byte[0])).build()).execute()) {
                assertEquals(200, r.code());
            }
            platform.timeRequest("GET", "/sync", 200, System.nanoTime(), "/sync", scope.context());
        } finally {
            server.stop(0);
            client.dispatcher().executorService().shutdown();
            client.connectionPool().evictAll();
        }
        Map<String, Map<String, Object>> rows = rows(platform);
        String host = "127.0.0.1:" + server.getAddress().getPort();
        assertEquals(1L, rows.get("GET /sync GET " + host).get("errors"), rows.keySet().toString());
        assertEquals(0L, rows.get("GET /sync POST " + host).get("errors"));
        platform.close(0);
    }

    @Test
    void sentToTheCollector() throws Exception {
        List<String> bodies = new CopyOnWriteArrayList<>();
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", exchange -> {
            String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            String path = exchange.getRequestURI().getPath();
            if (path.equals("/events/server-calls")) {
                bodies.add(body);
            }
            int status = path.startsWith("/events/platform/config") ? 304 : 202;
            exchange.sendResponseHeaders(status, -1);
            exchange.close();
        });
        server.start();
        Platform platform = Platform.create(new PlatformOptions().allOff().performance(true)
                .siteId("b".repeat(24)).secret("call-secret").endpoint("http://127.0.0.1:" + server.getAddress().getPort())
                .serverName("shop-api").shutdownHook(false));
        try {
            platform.recordCall("GET", "https://api.example.com/v1/users/42?key=k", System.nanoTime() - 12_000_000L, 200);
            platform.flush();
            assertEquals(1, bodies.size());
            Map<String, Object> sent = Json.map(Json.parse(bodies.get(0)));
            assertEquals("shop-api", sent.get("server_name"));
            Map<String, Object> row = Fixtures.rows(sent.get("rows")).get(0);
            assertEquals("JOB", row.get("method"));
            assertEquals("(background)", row.get("route"));
            assertEquals("GET", row.get("call_method"));
            assertEquals("api.example.com", row.get("host"));
            assertFalse(row.containsKey("db") || row.containsKey("statement"), row.toString());
            assertTrue(((Number) row.get("sum_ms")).doubleValue() >= 12, row.toString());
            assertFalse(bodies.get(0).contains("users") || bodies.get(0).contains("key="), bodies.get(0));
        } finally {
            platform.close(0);
            server.stop(0);
        }
    }

    // ---- ClickHouse, PostgreSQL's backslashes, static files ----

    @Test
    void clickHouseIsNamed() throws Exception {
        assertEquals("clickhouse", QueryText.databaseOfProduct("ClickHouse"));
        assertEquals("clickhouse", QueryText.databaseOfUrl("jdbc:clickhouse://localhost:8123/default"));
        assertEquals("clickhouse", QueryText.databaseOfUrl("jdbc:ch:https://ch.example:8443"));
        assertEquals("postgresql", QueryText.databaseOfUrl("jdbc:postgresql://db/app"));
        assertEquals("mssql", QueryText.databaseOfUrl("jdbc:sqlserver://db"));
        assertEquals("other", QueryText.databaseOfUrl("jdbc:h2:mem:x"));
        assertEquals("clickhouse", QueryText.databaseOf("clickhouse"));
        Platform platform = Platform.create(new PlatformOptions().allOff().performance(true).shutdownHook(false));
        DataSource db = platform.wrap(new FakeJdbc.Source("ClickHouse", new ArrayList<>()));
        try (Connection c = db.getConnection()) {
            c.createStatement().execute("SELECT count() FROM events WHERE site = 'x'");
        }
        List<Map<String, Object>> rows = platform.queries().take(true);
        assertEquals("clickhouse", rows.get(0).get("db"));
        assertEquals("SELECT count() FROM events WHERE site = ?", rows.get(0).get("statement"));
        platform.close(0);
    }

    @Test
    void postgresBackslashIsLiteral() {
        // 'C:\' ends at its quote on PostgreSQL: what follows is a value of its own.
        assertEquals("SELECT ? , ?", QueryText.normalize("SELECT 'C:\\' , 'secret'", "postgresql"));
        assertEquals("SELECT ?", QueryText.normalize("SELECT E'it\\'s'", "postgresql"));
        assertEquals("SELECT ?", QueryText.normalize("SELECT 'it\\' , \\'s'", "mysql"));
    }

    /**
     * Tricks that would make a page read as a static file, so a flood of them
     * skips the rate and the page limits, and real assets: the cases every
     * package shares (sdk/protocols/static-cases.json, firewall.md, `rate`).
     */
    @Test
    void staticFilesFollowTheFirewallProtocol() {
        Firewall rate = Fixtures.firewall("s", Json.map(Json.parse("{\"v\":1,\"enabled\":true,\"mode\":\"block\",\"rate\":{\"limit\":1,\"window\":60}}")));
        Firewall limits = Fixtures.firewall("s", Json.map(Json.parse("{\"v\":1,\"enabled\":true,\"mode\":\"block\",\"limits\":{\"rules\":"
                + "[{\"id\":\"all\",\"action\":\"block\",\"limit\":1,\"window\":60,\"path\":{\"prefix\":[\"/\"]}}]}}")));
        int i = 0;
        for (Object item : Json.list(Fixtures.protocol("static-cases.json").get("cases"))) {
            Map<String, Object> c = Json.map(item);
            if (c.containsKey("only") && !Json.list(c.get("only")).contains("java")) {
                continue;
            }
            String target = (String) c.get("path");
            String method = c.containsKey("method") ? (String) c.get("method") : "GET";
            boolean expected = Boolean.TRUE.equals(c.get("static"));
            String shown = method + " " + target.substring(0, Math.min(60, target.length()));
            assertEquals(expected, Firewall.isStaticFile(target, method), shown);
            String ip = "198.51.100." + (++i);
            rate.check(ip, method, target, "", "", "");
            assertEquals(expected ? "" : "rate", rate.check(ip, method, target, "", "", "").rule, "rate, " + shown);
            limits.check(ip, method, target, "", "", "");
            assertEquals(expected ? "" : "limit:all", limits.check(ip, method, target, "", "", "").rule, "page limit, " + shown);
        }
    }

    /**
     * A static file Spring sent to a controller after all (suffix pattern
     * matching reads /search.css as /search, a variable takes /search/x.css),
     * or that answered an error, counts after its response; one that is
     * already over is turned away without adding to the count.
     */
    @Test
    void aStaticFileRoutedToAControllerCountsAfterItsResponse() throws Exception {
        Firewall wall = Fixtures.firewall("s", Json.map(Json.parse("{\"v\":1,\"enabled\":true,\"mode\":\"block\",\"rate\":{\"limit\":2,\"window\":60},"
                + "\"limits\":{\"rules\":[{\"id\":\"search\",\"action\":\"block\",\"limit\":1,\"window\":60,\"path\":{\"prefix\":[\"/search\"]}}]}}")));
        // A real file the app serves itself: never counted, however many.
        for (int i = 0; i < 5; i++) {
            Firewall.Decision file = wall.check("198.51.100.1", "GET", "/search/logo.png", "", "", "");
            assertEquals("", file.rule);
            wall.countStatic(file, 200, false);
        }
        Firewall.Decision first = wall.check("198.51.100.2", "GET", "/search.css?q=a", "", "", "");
        assertEquals("", first.rule);
        assertTrue(first.countsLater());
        wall.countStatic(first, 200, true);
        Firewall.Decision second = wall.check("198.51.100.2", "GET", "/search.css?q=b", "", "", "");
        assertEquals("", second.rule, "compared, not counted: still at 1");
        wall.countStatic(second, 200, true);
        // Over the page limit now: the next one is turned away before the app.
        assertEquals("limit:search", wall.check("198.51.100.2", "GET", "/search.css?q=c", "", "", "").rule);
        // A missing file counts toward the rate.
        for (int i = 0; i < 3; i++) {
            wall.countStatic(wall.check("198.51.100.3", "GET", "/x" + i + ".css", "", "", ""), 404, false);
        }
        assertEquals("rate", wall.check("198.51.100.3", "GET", "/y.css", "", "", "").rule);

        Object controller = new Object() {
            @SuppressWarnings("unused")
            public String search() {
                return "";
            }
        };
        Object handler = new org.springframework.web.method.HandlerMethod(controller, controller.getClass().getMethod("search"));
        assertTrue(Platform.routedToController(handler, "/search"));
        assertTrue(Platform.routedToController(handler, "/search/{q}"));
        assertFalse(Platform.routedToController(handler, "/avatars/{id}.png"), "a route for files");
        assertFalse(Platform.routedToController(new org.springframework.web.servlet.resource.ResourceHttpRequestHandler(), "/**"));
        assertFalse(Platform.routedToController(null, null));
    }

    @Test
    void gcCountsPausesNotConcurrentWork() {
        assertEquals(Long.valueOf(30), Limits.gcPauseMs(List.of("G1 Young Generation", "G1 Old Generation", "G1 Concurrent GC"),
                List.of(20L, 10L, 900L)));
        assertEquals(Long.valueOf(4), Limits.gcPauseMs(List.of("ZGC Cycles", "ZGC Pauses"), List.of(5000L, 4L)));
        assertNull(Limits.gcPauseMs(List.of("Shenandoah Cycles"), List.of(70L)));
        assertNull(Limits.gcPauseMs(List.of("Copy"), List.of(-1L)));
    }

    @Test
    void twoSamplesInOneMinuteKeepBothCounts() {
        Map<String, Object> earlier = new HashMap<>(Map.of("oom_kills", 1L, "gc_ms", 12.0, "inflight_peak", 9L));
        Map<String, Object> row = new HashMap<>(Map.of("oom_kills", 2L, "listen_drops", 3L, "inflight_peak", 4L));
        Resources.carryCounts(earlier, row);
        assertEquals(3L, row.get("oom_kills"));
        assertEquals(3L, row.get("listen_drops"));
        assertEquals(12.0, row.get("gc_ms"));
        assertEquals(9L, row.get("inflight_peak"));
    }

    // ---- Limits ----

    static Function<String, String> files(Map<String, String> map) {
        return file -> map.getOrDefault(file, "");
    }

    static Map<String, String> v2(String... over) {
        Map<String, String> m = new HashMap<>();
        m.put("/c/memory.max", (512 * MB) + "\n");
        m.put("/c/memory.current", (400 * MB) + "\n");
        m.put("/c/memory.stat", "anon " + (200 * MB) + "\ninactive_file " + (150 * MB) + "\n");
        m.put("/c/memory.events", "low 0\nhigh 0\nmax 3\noom 1\noom_kill 1\n");
        m.put("/c/cpu.max", "150000 100000\n");
        m.put("/c/cpu.stat", "usage_usec 10\nnr_periods 1000\nnr_throttled 100\n");
        for (int i = 0; i + 1 < over.length; i += 2) {
            m.put(over[i], over[i + 1]);
        }
        return m;
    }

    @Test
    void cgroupsAreFound() {
        Map<String, String> container = new HashMap<>();
        container.put("/proc/self/cgroup", "0::/\n");
        container.put("/sys/fs/cgroup/memory.current", "1000\n");
        Limits.Cgroup found = Limits.findCgroup(files(container));
        assertEquals(2, found.version);
        assertEquals("/sys/fs/cgroup", found.memory);
        Map<String, String> service = new HashMap<>();
        service.put("/proc/self/cgroup", "0::/system.slice/app.service\n");
        service.put("/sys/fs/cgroup/system.slice/app.service/memory.current", "1000\n");
        assertEquals("/sys/fs/cgroup/system.slice/app.service", Limits.findCgroup(files(service)).memory);
        Map<String, String> hybrid = new HashMap<>();
        hybrid.put("/proc/self/cgroup", "12:memory:/docker/abc\n4:cpu,cpuacct:/docker/abc\n0::/docker/abc\n");
        hybrid.put("/sys/fs/cgroup/memory/memory.usage_in_bytes", "5\n");
        hybrid.put("/sys/fs/cgroup/cpu/cpu.cfs_quota_us", "-1\n");
        Limits.Cgroup v1 = Limits.findCgroup(files(hybrid));
        assertEquals(1, v1.version);
        assertEquals("/sys/fs/cgroup/memory", v1.memory);
        assertEquals("/sys/fs/cgroup/cpu", v1.cpu);
        assertNull(Limits.findCgroup(files(new HashMap<>())));
    }

    @Test
    void containerMemoryIsTheWorkingSetAndThrottlingAShareOfPeriods() {
        Limits.Cgroup cg = new Limits.Cgroup(2, "/c", "/c");
        Limits.Reading before = Limits.cgroupReading(cg, files(v2()));
        Limits.Reading after = Limits.cgroupReading(cg, files(v2("/c/memory.events", "oom_kill 3\n",
                "/c/cpu.stat", "nr_periods 1600\nnr_throttled 250\n")));
        Map<String, Object> row = Limits.cgroupFields(before, after, 8000L, 4);
        assertEquals(512L, row.get("limit_mem_mb"));
        assertEquals(250L, row.get("limit_mem_used_mb"));
        assertEquals(1.5, row.get("limit_cpu_cores"));
        assertEquals(25.0, row.get("cpu_throttled_pct"));
        assertEquals(2L, row.get("oom_kills"));

        Limits.Reading open = Limits.cgroupReading(cg, files(v2("/c/memory.max", "max\n", "/c/cpu.max", "max 100000\n")));
        assertTrue(Limits.cgroupFields(null, open, 8000L, 4).isEmpty(), "no cap, one reading: nothing");
        Limits.Reading big = Limits.cgroupReading(cg, files(v2("/c/memory.max", (16000 * MB) + "\n")));
        assertFalse(Limits.cgroupFields(null, big, 8000L, null).containsKey("limit_mem_mb"));
        Map<String, String> v1 = new HashMap<>();
        v1.put("/m/memory.limit_in_bytes", "9223372036854771712\n");
        v1.put("/m/memory.usage_in_bytes", "100\n");
        Limits.Reading unlimited = Limits.cgroupReading(new Limits.Cgroup(1, "/m", null), files(v1));
        assertFalse(Limits.cgroupFields(null, unlimited, null, null).containsKey("limit_mem_mb"));
        assertNull(Limits.countSince(5.0, 3.0), "a counter that went down was reset");
        assertEquals(0.0, Limits.countSince(3.0, 3.0));
    }

    @Test
    void waitingRefusedAndOpenFiles() {
        String psi = "some avg10=1.50 avg60=12.34 avg300=3.00 total=123\nfull avg10=0.00 avg60=9.00 avg300=0.00 total=1\n";
        assertEquals(12.3, Limits.pressureSome(psi));
        Map<String, String> io = new HashMap<>();
        io.put("/proc/pressure/io", psi);
        assertEquals(Map.of("psi_io_pct", 12.3), Limits.pressureFields(files(io)));
        assertTrue(Limits.pressureFields(files(new HashMap<>())).isEmpty());

        String netstat = "TcpExt: SyncookiesSent ListenOverflows ListenDrops\nTcpExt: 0 17 20\nIpExt: InOctets\nIpExt: 5\n";
        assertEquals(17.0, Limits.listenOverflows(netstat));
        assertNull(Limits.listenOverflows("IpExt: a\nIpExt: 1\n"));
        Map<String, String> conntrack = new HashMap<>();
        conntrack.put("/proc/sys/net/netfilter/nf_conntrack_count", "300\n");
        conntrack.put("/proc/sys/net/netfilter/nf_conntrack_max", "1200\n");
        assertEquals(25.0, Limits.conntrackPct(files(conntrack)));
        assertNull(Limits.conntrackPct(files(new HashMap<>())));

        String limits = "Limit                     Soft Limit           Hard Limit           Units\n"
                + "Max open files            1024                 1048576              files\n";
        assertEquals(1024L, Limits.fdLimit(limits));
        assertNull(Limits.fdLimit("Max open files            unlimited            unlimited            files\n"));
        Map<String, String> l = new HashMap<>();
        l.put("/proc/self/limits", limits);
        assertEquals(Map.of("fds_used", 10L, "fds_max", 1024L), Limits.fileFields(files(l), 10L));
        assertTrue(Limits.fileFields(files(new HashMap<>()), null).isEmpty());

        assertEquals(Map.of("heap_used_mb", 300L, "heap_max_mb", 2048L), Limits.heapFields(300 * MB, 2048 * MB));
        assertTrue(Limits.heapFields(300 * MB, -1).isEmpty());
        assertTrue(Limits.heapFields(300 * MB, Long.MAX_VALUE).isEmpty());
    }

    @Test
    void requestsInProgressPeakPerSample() {
        Platform platform = Platform.create(new PlatformOptions().allOff().performance(true).resources(true).shutdownHook(false));
        Resources resources = platform.module("resources");
        Map<String, Object> first = resources.sample();
        assertFalse(first.containsKey("inflight_peak"), "no request timed yet: no peak, never 0");
        assertTrue(String.valueOf(first.get("proc_key")).matches("[0-9a-f]{12}"), first.toString());
        assertTrue(first.containsKey("proc_uptime_s"));
        assertTrue(first.containsKey("heap_used_mb") && first.containsKey("heap_max_mb"), first.toString());
        platform.requestStarted();
        platform.requestStarted();
        platform.requestStarted();
        platform.requestEnded();
        platform.requestEnded();
        Map<String, Object> second = resources.sample();
        assertEquals(3L, second.get("inflight_peak"));
        assertTrue(((Number) second.get("gc_ms")).doubleValue() >= 0, second.toString());
        // The next interval starts from what is still running.
        assertEquals(1L, resources.sample().get("inflight_peak"));
        platform.requestEnded();
        assertEquals(1L, resources.sample().get("inflight_peak"));
        assertEquals(0L, resources.sample().get("inflight_peak"));
        platform.close(0);
    }
}
