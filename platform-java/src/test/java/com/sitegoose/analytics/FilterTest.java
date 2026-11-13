package com.sitegoose.analytics;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.sitegoose.analytics.jakarta.PlatformFilter;
import jakarta.servlet.AsyncContext;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.apache.catalina.Context;
import org.apache.catalina.Wrapper;
import org.apache.catalina.startup.Tomcat;
import org.apache.catalina.valves.RemoteIpValve;
import org.apache.tomcat.util.descriptor.web.FilterDef;
import org.apache.tomcat.util.descriptor.web.FilterMap;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/** The jakarta filter in a real Tomcat: what reaches the app, what's answered for it, what's reported. */
class FilterTest {
    static final String RULES = "{\"v\":1,\"enabled\":true,\"mode\":\"block\",\"deny\":[\"203.0.113.0/24\"],"
            + "\"rate\":{\"limit\":3,\"window\":60},"
            + "\"requests\":{\"rules\":[{\"id\":\"actuator\",\"action\":\"block\",\"path\":{\"exact\":[\"/actuator/env\"]}}]}}";

    Tomcat tomcat;
    Platform platform;
    final List<Map<String, Object>> captured = Collections.synchronizedList(new ArrayList<>());
    final AtomicBoolean sseStopped = new AtomicBoolean();
    final CountDownLatch sseDone = new CountDownLatch(1);

    @AfterEach
    void stop() throws Exception {
        if (tomcat != null) {
            tomcat.stop();
            tomcat.destroy();
        }
        if (platform != null) {
            platform.close(500);
        }
    }

    /** A Tomcat with the filter first, optionally behind RemoteIpValve, and the app below. */
    int start(boolean remoteIpValve) throws Exception {
        platform = Platform.create(new PlatformOptions().siteId("a".repeat(24)).secret("s")
                // Nothing listens there: nothing is sent, and the modules work as when the collector is down.
                .endpoint("http://127.0.0.1:9").trustProxy("1").shutdownHook(false)
                .inventory(false).posture(false).resources(false)
                .errors(e -> e.noSpool().captureUncaught(false).beforeSend((event, error) -> {
                    captured.add(event);
                    return event;
                })));
        platform.firewall().rules = Firewall.compile(Json.parse(RULES));
        platform.core.apply(Json.map(Json.parse("{\"v\":1,\"modules\":{},\"headers\":[[\"X-Frame-Options\",\"SAMEORIGIN\"]]}")));
        tomcat = new Tomcat();
        tomcat.setBaseDir(Files.createTempDirectory("tomcat").toString());
        tomcat.setPort(0);
        tomcat.getConnector();
        Context ctx = tomcat.addContext("", Files.createTempDirectory("docbase").toString());
        if (remoteIpValve) {
            ctx.getPipeline().addValve(new RemoteIpValve());
        }
        FilterDef def = new FilterDef();
        def.setFilterName("analytics");
        def.setFilter(new PlatformFilter(platform));
        def.setAsyncSupported("true");
        ctx.addFilterDef(def);
        FilterMap map = new FilterMap();
        map.setFilterName("analytics");
        map.addURLPattern("/*");
        ctx.addFilterMap(map);
        Wrapper app = Tomcat.addServlet(ctx, "app", new App());
        app.setAsyncSupported(true);
        ctx.addServletMappingDecoded("/", "app");
        tomcat.start();
        return tomcat.getConnector().getLocalPort();
    }

    final class App extends HttpServlet {
        @Override
        protected void service(HttpServletRequest req, HttpServletResponse res) throws IOException {
            String path = req.getRequestURI();
            if (path.startsWith("/orders/")) {
                req.setAttribute(Platform.ROUTE_ATTRIBUTE, "/orders/{id}");
            }
            switch (path) {
                case "/boom":
                    req.setAttribute(Platform.ROUTE_ATTRIBUTE, "/boom");
                    throw new IllegalStateException("app boom");
                case "/abort":
                    throw new org.apache.catalina.connector.ClientAbortException(new IOException("Broken pipe"));
                case "/handled":
                    req.setAttribute("jakarta.servlet.error.exception", new IllegalArgumentException("handled by an error page"));
                    res.setStatus(500);
                    res.getWriter().write("sorry");
                    return;
                case "/own":
                    res.setHeader("X-Frame-Options", "DENY");
                    res.getWriter().write("own");
                    return;
                case "/sse":
                    res.setContentType("text/event-stream");
                    PrintWriter writer = res.getWriter();
                    long until = System.currentTimeMillis() + 10_000;
                    while (System.currentTimeMillis() < until) {
                        writer.write("data: tick " + "x".repeat(4000) + "\n\n");
                        writer.flush();
                        if (writer.checkError()) {
                            sseStopped.set(true);
                            break;
                        }
                        try {
                            Thread.sleep(20);
                        } catch (InterruptedException e) {
                            break;
                        }
                    }
                    sseDone.countDown();
                    return;
                case "/async":
                    AsyncContext async = req.startAsync();
                    async.start(() -> {
                        try {
                            async.getResponse().getWriter().write("later");
                        } catch (IOException ignored) {
                            // test fails on the body
                        }
                        async.complete();
                    });
                    return;
                default:
                    res.setContentType("text/html");
                    res.getWriter().write(req.getMethod() + " " + path + " from " + req.getRemoteAddr());
            }
        }
    }

    /** One request over a plain socket, as sent (no client tidies the path): status line, headers and body. */
    static String raw(int port, String request) throws IOException {
        try (Socket socket = new Socket("127.0.0.1", port)) {
            socket.setSoTimeout(10_000);
            OutputStream out = socket.getOutputStream();
            out.write(request.getBytes(StandardCharsets.ISO_8859_1));
            out.flush();
            InputStream in = socket.getInputStream();
            ByteArrayOutputStream got = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int n;
            while ((n = in.read(buffer)) > 0) {
                got.write(buffer, 0, n);
            }
            return got.toString(StandardCharsets.ISO_8859_1);
        }
    }

    /** Only the status line and headers: for an answer the server sends before the body it asked for. */
    static String head(int port, String request) throws IOException {
        try (Socket socket = new Socket("127.0.0.1", port)) {
            socket.setSoTimeout(10_000);
            socket.getOutputStream().write(request.getBytes(StandardCharsets.ISO_8859_1));
            InputStream in = socket.getInputStream();
            StringBuilder got = new StringBuilder();
            int c;
            while ((c = in.read()) >= 0) {
                got.append((char) c);
                if (got.toString().endsWith("\r\n\r\n")) {
                    break;
                }
            }
            return got.toString();
        }
    }

    static String get(int port, String target, String... headers) throws IOException {
        StringBuilder request = new StringBuilder("GET " + target + " HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n");
        for (String header : headers) {
            request.append(header).append("\r\n");
        }
        return raw(port, request.append("\r\n").toString());
    }

    static int status(String response) {
        return Integer.parseInt(response.substring(9, 12));
    }

    @Test
    void addressesWithPortsAreReadAndJunkFallsBackToTheConnection() throws Exception {
        int port = start(false);
        assertEquals(403, status(get(port, "/", "X-Forwarded-For: 203.0.113.5:54321")));
        assertEquals(403, status(get(port, "/", "X-Forwarded-For: [::ffff:203.0.113.5]:443")));
        String passed = get(port, "/", "X-Forwarded-For: unknown");
        assertEquals(200, status(passed));
    }

    @Test
    void behindRemoteIpValveTheContainersAddressIsBelieved() throws Exception {
        int port = start(true);
        // The valve took 198.51.100.7 (the last hop it doesn't trust) and left
        // "203.0.113.5", the visitor's own writing, in the header.
        String forged = get(port, "/", "X-Forwarded-For: 203.0.113.5, 198.51.100.7");
        assertEquals(200, status(forged), forged);
        assertTrue(forged.contains("from 198.51.100.7"), forged);
        assertEquals(403, status(get(port, "/", "X-Forwarded-For: 198.51.100.7, 203.0.113.5")));
    }

    @Test
    void attackPatternsSeeThePathTheRouterSees() throws Exception {
        int port = start(false);
        assertEquals(403, status(get(port, "/actuator/env")));
        assertEquals(403, status(get(port, "/actuator;x/env")));
        assertEquals(403, status(get(port, "/a/../actuator/env")));
        assertEquals(403, status(get(port, "/a/%2e%2e/actuator/env")));
        assertEquals(200, status(get(port, "/actuator/health")));
    }

    @Test
    void errorsAreReportedButAVisitorHangingUpIsNot() throws Exception {
        int port = start(false);
        assertEquals(500, status(get(port, "/boom")));
        get(port, "/abort");
        assertEquals(500, status(get(port, "/handled")));
        List<String> messages = new ArrayList<>();
        for (Map<String, Object> event : captured) {
            messages.add(event.get("message") + " " + event.get("route") + " " + event.get("status_code"));
        }
        Collections.sort(messages);
        assertEquals(java.util.Arrays.asList("app boom /boom 500", "handled by an error page /handled 500"), messages);
    }

    @Test
    void securityHeadersAreAddedAndTheAppsOwnWin() throws Exception {
        int port = start(false);
        assertTrue(get(port, "/").contains("X-Frame-Options: SAMEORIGIN"));
        String own = get(port, "/own");
        assertTrue(own.contains("X-Frame-Options: DENY") && !own.contains("SAMEORIGIN"), own);
    }

    @Test
    void anEventStreamStopsWhenTheVisitorLeavesAndIsntTimed() throws Exception {
        int port = start(false);
        try (Socket socket = new Socket("127.0.0.1", port)) {
            socket.getOutputStream().write("GET /sse HTTP/1.1\r\nHost: localhost\r\n\r\n".getBytes(StandardCharsets.ISO_8859_1));
            socket.getInputStream().read(new byte[100]);
            socket.setSoLinger(true, 0);
        }
        assertTrue(sseDone.await(10, TimeUnit.SECONDS));
        assertTrue(sseStopped.get(), "checkError() saw the closed connection");
        Performance performance = platform.module("performance");
        for (Map<String, Object> row : performance.take(true)) {
            assertFalse("/sse".equals(row.get("route")), row.toString());
        }
    }

    @Test
    void asyncServletsWorkBehindTheFilter() throws Exception {
        int port = start(false);
        String answer = get(port, "/async");
        assertEquals(200, status(answer), answer);
        assertTrue(answer.contains("later"), answer);
    }

    @Test
    void staticFilesAndMethodsAndTheRateLimit() throws Exception {
        int port = start(false);
        for (int i = 0; i < 6; i++) {
            assertEquals(200, status(get(port, "/img/" + i + ".png", "X-Forwarded-For: 198.51.100.50")));
        }
        int[] got = new int[4];
        for (int i = 0; i < 4; i++) {
            got[i] = status(get(port, "/orders/" + i, "X-Forwarded-For: 198.51.100.50"));
        }
        assertEquals("[200, 200, 200, 429]", java.util.Arrays.toString(got));
        raw(port, "FOOBAR /made-up HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nX-Forwarded-For: 198.51.100.60\r\n\r\n");
        Performance performance = platform.module("performance");
        List<String> rows = new ArrayList<>();
        for (Map<String, Object> row : performance.take(true)) {
            rows.add(row.get("method") + " " + row.get("route"));
        }
        assertTrue(rows.contains("GET /orders/{id}"), rows.toString());
        assertTrue(rows.contains("OTHER /made-up"), rows.toString());
    }

    @Test
    void theProxyRefusesBannedAddressesAndOversizedBodies() throws Exception {
        int port = start(false);
        String prefix = platform.proxy().prefix;
        String denied = raw(port, "POST /" + prefix + "/api/e HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n"
                + "X-Forwarded-For: 203.0.113.5\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\n{}");
        assertEquals(403, status(denied));
        String big = head(port, "POST /" + prefix + "/api/e HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n"
                + "Content-Type: text/plain\r\nContent-Length: " + (Platform.PROXY_MAX_BODY + 1) + "\r\n\r\n");
        assertEquals(413, status(big));
    }
}
