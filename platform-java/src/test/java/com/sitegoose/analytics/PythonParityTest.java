package com.sitegoose.analytics;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.junit.jupiter.api.Test;

/** The same input as the Python package, the same output (src/test/resources/python-fixtures.json). */
class PythonParityTest {
    static final Map<String, Object> PY = Fixtures.python();

    @Test
    void theCheckPagesScriptIsByteForByteThePythonOne() {
        Map<String, Object> s = Json.map(PY.get("script"));
        assertEquals(s.get("script"), Challenge.script((String) s.get("value")));
    }

    @Test
    void theCheckPageIsThePythonTemplate() {
        byte[] key = Challenge.passKey("test-secret-0123456789abcdef");
        double now = 1793750400;
        Reply page = Challenge.page(key, "203.0.113.7", "GET", now);
        assertEquals(503, page.status());
        assertEquals("text/html; charset=utf-8", page.header("Content-Type"));
        assertEquals("no-store", page.header("Cache-Control"));
        assertEquals("noindex", page.header("X-Robots-Tag"));
        Matcher nonce = Pattern.compile("script-src 'nonce-([^']+)'").matcher(page.header("Content-Security-Policy"));
        assertNotNull(nonce.find() ? nonce.group(1) : null);
        String template = ((String) PY.get("page_template")).replace("{{", "\u0001").replace("}}", "\u0002");
        String expected = template.replace("{nonce}", nonce.group(1))
                .replace("{script}", Challenge.script(Challenge.makePass(key, "203.0.113.7", now)))
                .replace("\u0001", "{").replace("\u0002", "}");
        assertEquals(expected, new String(page.body(), StandardCharsets.UTF_8));
        assertEquals(0, Challenge.page(key, "203.0.113.7", "HEAD", now).body().length, "a HEAD gets no body");
    }

    @Test
    void flagBuckets() {
        for (Map<String, Object> c : Fixtures.rows(PY.get("buckets"))) {
            assertEquals(((Number) c.get("bucket")).intValue(), Flags.bucket((String) c.get("key"), (String) c.get("user")), c.toString());
        }
    }

    @Test
    void proxyAddressAndKey() {
        for (Map<String, Object> c : Fixtures.rows(PY.get("proxy"))) {
            assertEquals(c.get("prefix"), Proxy.prefixFor((String) c.get("secret")));
            assertEquals(c.get("key"), Proxy.keyFor((String) c.get("secret")));
        }
    }

    @Test
    void routesAndTimeBuckets() {
        for (Map<String, Object> c : Fixtures.rows(PY.get("routes"))) {
            assertEquals(c.get("route"), Performance.normalizeRoute((String) c.get("path")), (String) c.get("path"));
        }
        for (Map<String, Object> c : Fixtures.rows(PY.get("buckets_ms"))) {
            assertEquals(((Number) c.get("bucket")).intValue(), Performance.bucketOf(((Number) c.get("ms")).doubleValue()), c.toString());
        }
    }

    @Test
    void crawlerNames() {
        for (Map<String, Object> c : Fixtures.rows(PY.get("crawlers"))) {
            assertEquals(c.get("bot"), Objects.toString(Crawlers.detect((String) c.get("ua")), ""), (String) c.get("ua"));
        }
    }

    @Test
    void maintenancePage() {
        assertEquals(PY.get("maintenance_page"), Maintenance.page("We <b>are</b> & back"));
        assertEquals(PY.get("maintenance_default"), Maintenance.page(null));
    }
}
