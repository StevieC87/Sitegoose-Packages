package com.sitegoose.analytics;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Performance and API monitoring module: times every request (from arriving
 * to the response being ready) and sends one row per minute, method, route
 * and status code (how many, total and slowest time, and a count per time
 * bucket) to POST /events/server-requests. Nothing about visitors is sent.
 *
 * <p>The route is the framework's own pattern when the integration knows it
 * (Spring MVC's best matching pattern); otherwise numbers and IDs in the path
 * become ":id", and unmatched 404s are one route.
 */
final class Performance {
    /** Keep in step with the collector (expresscollect/Analytics/serverRequests.js). */
    static final int[] BUCKET_EDGES_MS = {5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000};
    static final double FLUSH_EVERY = 60;
    static final int MAX_KEYS = 300;
    /** Past MAX_KEYS requests go to "(other)" rows; past this, nothing more is kept this minute. */
    static final int HARD_MAX_KEYS = 400;
    static final java.util.Set<String> METHODS = new java.util.HashSet<>(java.util.Arrays.asList(
            "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "JOB"));
    static final int MAX_ROWS = 500;
    static final String NOT_FOUND = "/(not found)";
    private static final Pattern ID = Pattern.compile(
            "^(\\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{16,})$", Pattern.CASE_INSENSITIVE);
    private static final Pattern DIGIT = Pattern.compile("\\d");

    /** "/orders/123/items/9f8e..." -> "/orders/:id/items/:id". */
    static String normalizeRoute(String path) {
        String clean = path == null || path.isEmpty() ? "/" : path;
        int cut = clean.length();
        for (char c : new char[] {'?', '#'}) {
            int at = clean.indexOf(c);
            if (at >= 0 && at < cut) {
                cut = at;
            }
        }
        clean = clean.substring(0, cut);
        if (clean.isEmpty()) {
            clean = "/";
        }
        String[] parts = clean.split("/", -1);
        StringBuilder route = new StringBuilder();
        for (int i = 0; i < parts.length; i++) {
            String s = parts[i];
            if (i > 0) {
                route.append('/');
            }
            boolean id = ID.matcher(s).matches() || (s.length() >= 20 && DIGIT.matcher(s).find());
            route.append(id ? ":id" : s);
        }
        String out = route.toString();
        if (!out.startsWith("/")) {
            out = "/" + out;
        }
        return out.length() > 200 ? out.substring(0, 200) : out;
    }

    static int bucketOf(double ms) {
        for (int i = 0; i < BUCKET_EDGES_MS.length; i++) {
            if (ms <= BUCKET_EDGES_MS[i]) {
                return i;
            }
        }
        return BUCKET_EDGES_MS.length;
    }

    private static final class Key {
        final long minute;
        final String method;
        final String route;
        final int status;

        Key(long minute, String method, String route, int status) {
            this.minute = minute;
            this.method = method;
            this.route = route;
            this.status = status;
        }

        @Override
        public boolean equals(Object o) {
            if (!(o instanceof Key)) {
                return false;
            }
            Key k = (Key) o;
            return minute == k.minute && status == k.status && method.equals(k.method) && route.equals(k.route);
        }

        @Override
        public int hashCode() {
            return Objects.hash(minute, method, route, status);
        }
    }

    private static final class Row {
        long count;
        double sumMs;
        double maxMs;
        final long[] buckets = new long[BUCKET_EDGES_MS.length + 1];
    }

    private final Core core;
    final String serverName;
    final String runtime;
    private Map<Key, Row> rows = new LinkedHashMap<>();
    private final Periodic job;
    /**
     * Requests in progress now, and the most at once since the resources
     * module last asked. timed stays false until the filter first counts one,
     * so an app that never installed it reports no peak rather than 0.
     */
    private long inflight;
    private long peak;
    private boolean timed;

    /** A request started (the servlet filters call it as it enters the app). */
    synchronized void started() {
        timed = true;
        inflight += 1;
        if (inflight > peak) {
            peak = inflight;
        }
    }

    /** A request that started() ended, answered or dropped; once per request. */
    synchronized void ended() {
        if (inflight > 0) {
            inflight -= 1;
        }
    }

    /** The most requests in progress at once since the last call, or null when none was ever counted; resets to what is still running. */
    synchronized Long takeInflightPeak() {
        if (!timed) {
            return null;
        }
        long most = peak;
        peak = inflight;
        return most;
    }

    Performance(Core core, String serverName) {
        this.core = core;
        String name = serverName == null || serverName.isEmpty() ? Hosts.hostName() : serverName;
        this.serverName = name.length() > 100 ? name.substring(0, 100) : name;
        this.runtime = Core.runtime();
        this.job = core.valid ? core.every(this::flushJob, FLUSH_EVERY) : null;
    }

    /**
     * One finished request. route: the framework's pattern, or "" to work it
     * out from path. Returns the {method, route} it was counted under (its
     * queries go under the same), or null when it wasn't.
     */
    String[] record(String method, String route, int status, double ms, String path) {
        if (!core.isOn("performance")) {
            return null;
        }
        String r = route == null || route.isEmpty() ? (status == 404 ? NOT_FOUND : normalizeRoute(path)) : route;
        if (r.length() > 200) {
            r = r.substring(0, 200);
        }
        // The method is the client's to choose: anything outside the usual few is
        // one row, so made-up methods can't fill the table.
        String given = (method == null || method.isEmpty() ? "GET" : method).toUpperCase(Locale.ROOT);
        String m = METHODS.contains(given) ? given : "OTHER";
        int code = status >= 100 && status <= 599 ? status : 0;
        long minute = System.currentTimeMillis() / 60000 * 60;
        synchronized (this) {
            Key key = new Key(minute, m, r, code);
            if (!rows.containsKey(key) && rows.size() >= MAX_KEYS) {
                key = new Key(minute, m, "(other)", code);
                if (!rows.containsKey(key) && rows.size() >= HARD_MAX_KEYS) {
                    return new String[] {m, r};
                }
            }
            Row row = rows.computeIfAbsent(key, k -> new Row());
            row.count += 1;
            row.sumMs += ms;
            row.maxMs = Math.max(row.maxMs, ms);
            row.buckets[bucketOf(ms)] += 1;
            return new String[] {key.method, key.route};
        }
    }

    static double round1(double value) {
        return Math.round(value * 10) / 10.0;
    }

    /** The rows ready to send: every minute (everything), or the minutes that are over. */
    List<Map<String, Object>> take(boolean everything) {
        long current = System.currentTimeMillis() / 60000 * 60;
        List<Map<String, Object>> out = new ArrayList<>();
        synchronized (this) {
            Map<Key, Row> keep = new LinkedHashMap<>();
            for (Map.Entry<Key, Row> entry : rows.entrySet()) {
                Key k = entry.getKey();
                if (!everything && k.minute >= current) {
                    keep.put(k, entry.getValue());
                    continue;
                }
                Row v = entry.getValue();
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("minute", Instant.ofEpochSecond(k.minute).toString());
                row.put("method", k.method);
                row.put("route", k.route);
                row.put("status", k.status);
                row.put("count", v.count);
                row.put("sum_ms", round1(v.sumMs));
                row.put("max_ms", round1(v.maxMs));
                List<Long> buckets = new ArrayList<>();
                for (long b : v.buckets) {
                    buckets.add(b);
                }
                row.put("buckets", buckets);
                out.add(row);
            }
            rows = keep;
        }
        return out;
    }

    void flush(boolean everything) {
        List<Map<String, Object>> ready = take(everything);
        for (int i = 0; i < ready.size(); i += MAX_ROWS) {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("server_name", serverName);
            body.put("runtime", runtime);
            body.put("rows", ready.subList(i, Math.min(ready.size(), i + MAX_ROWS)));
            core.post("performance", "/events/server-requests", body);
        }
    }

    private double flushJob() {
        flush(false);
        return FLUSH_EVERY;
    }

    void close() {
        if (job != null) {
            job.stop(core.stopWait());
        }
        flush(true);
    }
}
