package com.sitegoose.analytics;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.lang.reflect.InvocationTargetException;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

class ModulesTest {
    static final String STAT = "cpu  100 10 50 1000 20 0 5 0 0 0\ncpu0 50 5 25 500 10 0 2 0 0 0\nintr 1\n";
    static final String MEMINFO = "MemTotal:        8143868 kB\nMemFree:          210000 kB\nMemAvailable:    5021228 kB\n"
            + "Cached:          4000000 kB\nSwapTotal:       2097152 kB\nSwapFree:        2084864 kB\n";

    @Test
    void jsonRoundTrip() {
        Object parsed = Json.parse("{\"a\":[1,2.5,true,null,\"\\u00e9\\n\"],\"b\":{\"c\":-3}}");
        Map<String, Object> map = Json.map(parsed);
        assertEquals(Arrays.asList(1L, 2.5, true, null, "é\n"), map.get("a"));
        assertEquals("{\"a\":[1,2.5,true,null,\"\\u00e9\\n\"],\"b\":{\"c\":-3}}", Json.write(parsed));
        assertEquals("3", Json.write(3.0));
    }

    @Test
    void cpuNeedsTwoReadingsAndIgnoresIdle() {
        long[] before = Resources.cpuTimesOf(Resources.cpuFields(STAT));
        assertArrayEquals(new long[] {165, 1185}, before);
        assertNull(Resources.cpuPercent(null, before));
        assertNull(Resources.cpuPercent(before, before));
        long[] after = {before[0] + 100, before[1] + 200};
        assertEquals(50.0, Resources.cpuPercent(before, after));
        assertNull(Resources.cpuPercent(after, before));
    }

    @Test
    void stealIsReportedAndAMissingColumnSaysNothing() {
        long[] before = {1000, 100, 500, 8000, 200, 10, 20, 170};
        long[] after = {1100, 100, 550, 8600, 240, 10, 20, 180};
        Map<String, Object> shares = Resources.cpuShares(before, after);
        assertEquals(1.2, shares.get("cpu_steal_pct"));
        assertEquals(5.0, shares.get("cpu_iowait_pct"));
        assertEquals(12.5, shares.get("cpu_user_pct"));
        Map<String, Object> old = Resources.cpuShares(new long[] {1000, 100, 500, 8000}, new long[] {1100, 100, 550, 8600});
        assertFalse(old.containsKey("cpu_steal_pct"));
        assertTrue(Resources.cpuShares(after, before).isEmpty());
    }

    @Test
    void memoryUsedIsTotalMinusAvailable() {
        Map<String, Object> memory = Resources.memoryMb(MEMINFO);
        assertEquals(7952L, ((Number) memory.get("mem_total_mb")).longValue());
        assertEquals(3049L, ((Number) memory.get("mem_used_mb")).longValue());
        assertEquals(2048L, ((Number) memory.get("swap_total_mb")).longValue());
        assertEquals(12L, ((Number) memory.get("swap_used_mb")).longValue());
        assertEquals(Collections.singleton("mem_total_mb"), Resources.memoryMb("MemTotal: 8143868 kB\nMemFree: 1 kB\n").keySet());
        assertTrue(Resources.memoryMb("").isEmpty());
        assertNull(Resources.hostUptime(""));
        assertEquals(864000L, Resources.hostUptime("864000.12 1700000.00"));
        assertNull(Resources.processRssMb("Name:\tjava\n"));
        assertEquals(64L, Resources.processRssMb("Name:\tjava\nVmRSS:\t   65536 kB\n"));
    }

    @Test
    void diskAndNetworkCounters() {
        String stats = "   8   0 sda 100 0 2000 0 50 0 4000 0 0 0 0\n   8   1 sda1 90 0 1800 0 40 0 3000 0 0 0 0\n"
                + "   7   0 loop0 10 0 100 0 0 0 0 0 0 0 0\n 259   0 nvme0n1 20 0 1000 0 10 0 2000 0 0 0 0\n"
                + " 259   1 nvme0n1p1 15 0 900 0 8 0 1500 0 0 0 0\n";
        assertArrayEquals(new long[] {3000 * 512, 6000 * 512}, Resources.diskCounters(stats));
        assertNull(Resources.diskCounters(""));
        String dev = "    lo: 5000 10 0 0 0 0 0 0 5000 10 0 0 0 0 0 0\n  eth0: 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0\n"
                + "docker0: 9000 10 0 0 0 0 0 0 9000 10 0 0 0 0 0 0\n";
        assertArrayEquals(new long[] {1000, 2000}, Resources.netCounters(dev));
        long mb = 1024 * 1024;
        assertEquals(1.0, Resources.rateMbs(0L, 60 * mb, 60));
        assertNull(Resources.rateMbs(0L, 60 * mb, 3600));
        assertNull(Resources.rateMbs(60 * mb, 0L, 60));
    }

    @Test
    void guestTimeIsNotCountedTwice() {
        long[] before = {1000, 0, 0, 8000, 0, 0, 0, 0, 0, 0};
        long[] after = {1800, 0, 0, 8200, 0, 0, 0, 0, 400, 0};
        assertEquals(80.0, Resources.cpuPercent(Resources.cpuTimesOf(before), Resources.cpuTimesOf(after)));
        assertEquals(80.0, Resources.cpuShares(before, after).get("cpu_user_pct"));
    }

    @Test
    void wrappersAreTakenOff() {
        IllegalStateException inner = new IllegalStateException("boom");
        assertSame(inner, Platform.unwrap(new jakarta.servlet.ServletException("Request processing failed", inner)));
        assertSame(inner, Platform.unwrap(new InvocationTargetException(inner)));
        RuntimeException own = new RuntimeException("own", inner);
        assertSame(own, Platform.unwrap(own), "an error of its own kind is kept");
        assertEquals("", Platform.routeOf(null, "/**"));
        assertEquals("/orders/{id}", Platform.routeOf(null, "/orders/{id}"));
        assertEquals("/mine", Platform.routeOf("/mine", "/orders/{id}"));
    }

    @Test
    void stacksAreJavasOwnCappedAndCutOnALine() {
        Exception error = new IllegalArgumentException("outer", new IllegalStateException("inner"));
        String stack = Errors.stackOf(error);
        assertTrue(stack.startsWith("java.lang.IllegalArgumentException: outer\n\tat "), stack);
        assertTrue(stack.contains("Caused by: java.lang.IllegalStateException: inner"), stack);
        assertEquals("java.lang.IllegalArgumentException", Errors.typeOf(error));
        Throwable deep = new RuntimeException("x".repeat(5000));
        assertTrue(Errors.stackOf(deep).length() <= 4000);
    }

    @Test
    void resourceUrlsBecomeFolders() {
        assertArrayEquals(new String[] {"/app.jar", "", "BOOT-INF/classes/static/"},
                Platform.folderOf("jar:nested:/app.jar/!BOOT-INF/classes/!/static/", ""));
        assertArrayEquals(new String[] {"/app.jar", "/assets", "BOOT-INF/classes/static/"},
                Platform.folderOf("jar:file:/app.jar!/BOOT-INF/classes!/static/", "/assets"));
        assertNull(Platform.folderOf("jar:nested:/app.jar/!BOOT-INF/lib/webjar.jar!/META-INF/resources/", ""));
        assertArrayEquals(new String[] {"/srv/static", ""}, Platform.folderOf("file:/srv/static/", ""));
    }

    @Test
    void checkInSaysWhichServiceAsksAndThatItRuns() {
        Core core = new Core("a".repeat(24), "s", "", false, "shop-api");
        String app = core.checkIn();
        assertTrue(app.startsWith("server=shop-api&kind=process&pid=" + ProcessHandle.current().pid() + "&up_s="), app);
        assertTrue(app.contains("&runtime=Java+" + System.getProperty("java.version")), app);
        assertEquals("analytics-platform-java/" + Version.VERSION, core.userAgent);
    }

    @Test
    void anUnconfiguredPlatformSendsNothingAndLetsEverythingPass() {
        Platform platform = Platform.create(new PlatformOptions().shutdownHook(false));
        try {
            assertFalse(platform.isConfigured());
            assertNull(platform.blocked("203.0.113.9", Collections.emptyMap(), "GET", "/"));
            platform.captureException(new RuntimeException("x"));
            platform.timeRequest("GET", "/", 200, System.nanoTime(), "/");
            assertFalse(platform.isEnabled("anything"));
        } finally {
            platform.close();
            platform.close();
        }
    }

    @Test
    void formsKeepOnlyPlainFields() {
        Map<String, Object> given = new LinkedHashMap<>();
        given.put("email", "a@example.com");
        given.put("password", "hunter2");
        given.put("csrfmiddlewaretoken", "x");
        given.put("message", "hello");
        Map<String, String> kept = Forms.plainFields(given);
        assertTrue(kept.containsKey("email"));
        assertTrue(kept.containsKey("message"));
        assertFalse(kept.containsKey("password"));
    }

    @Test
    void flagsFollowTheirRules() {
        Map<String, Object> flag = Json.map(Json.parse("{\"on\":true,\"percent\":100}"));
        assertTrue(Flags.evaluate(flag, "new-checkout", "42"));
        Map<String, Object> off = Json.map(Json.parse("{\"on\":false,\"percent\":100}"));
        assertFalse(Flags.evaluate(off, "new-checkout", "42"));
    }

    @Test
    void jarsWithoutPomPropertiesAreNamedByTheirFamily() {
        Map<String, Map<String, Object>> found = new LinkedHashMap<>();
        Inventory.fromJarName("spring-core-6.1.14.jar", null, found);
        Inventory.fromJarName("spring-boot-autoconfigure-3.3.5.jar", null, found);
        Inventory.fromJarName("tomcat-embed-core-10.1.31.jar", null, found);
        java.util.jar.Manifest ivy = new java.util.jar.Manifest();
        ivy.getMainAttributes().put(java.util.jar.Attributes.Name.MANIFEST_VERSION, "1.0");
        ivy.getMainAttributes().put(java.util.jar.Attributes.Name.IMPLEMENTATION_TITLE, "com.example#widgets;2.0.1");
        Inventory.fromJarName("widgets-2.0.1.jar", ivy, found);
        Inventory.fromJarName("mystery-lib-1.0.jar", null, found);
        Inventory.fromJarName("not-a-versioned-name.jar", null, found);
        assertEquals(Arrays.asList("org.springframework:spring-core", "org.springframework.boot:spring-boot-autoconfigure",
                "org.apache.tomcat.embed:tomcat-embed-core", "com.example:widgets"), new java.util.ArrayList<>(found.keySet()));
        assertEquals("10.1.31", found.get("org.apache.tomcat.embed:tomcat-embed-core").get("version"));
    }

    @Test
    void ipWhoIsTheAddressOrItsV6Slash64() {
        List<String> got = Arrays.asList(Ip.who("203.0.113.7"), Ip.who("::ffff:203.0.113.7"));
        assertEquals(Arrays.asList("203.0.113.7", "203.0.113.7"), got);
    }
}
