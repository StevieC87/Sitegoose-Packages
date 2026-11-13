package com.sitegoose.analytics;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Database queries (sdk/protocols/queries.md), the half of Server speed that
 * says why a route is slow: every query the site's own code runs is timed
 * through a public hook ({@link Platform#wrap}, {@link Platform#mongoListener},
 * {@link Platform#redisListener}),
 * its values taken out ({@link QueryText}), and added to the request it ran
 * in. When the request finishes, its queries go into that minute's rows under
 * the method and route the performance module recorded it with, so the
 * dashboard can join the two. One row per minute, method, route, database and
 * query goes to POST /events/server-queries.
 *
 * <p>Rides on the performance module: with Server speed off (here or in the
 * dashboard) nothing is recorded. No values ever leave the server, and bound
 * parameters are never read.
 *
 * <p>The same class, as {@link Kind#CALLS}, files the requests' outgoing HTTP
 * calls (sdk/protocols/calls.md) by call method and host, through the same
 * per-request map, caps and minute rows, to POST /events/server-calls.
 */
final class Queries {
    static final double FLUSH_EVERY = 60;
    /** Distinct statements one request keeps; past it, new ones are "(other)". */
    static final int MAX_PER_REQUEST = 50;
    /** Keys in a minute before new statements become "(other)"; past HARD_MAX_KEYS nothing new is kept. */
    static final int MAX_KEYS = 200;
    static final int HARD_MAX_KEYS = 300;
    static final int MAX_ROWS = 500;
    /** Minutes held unsent: with no flush running (credentials missing, after close) the oldest goes. */
    static final int MAX_MINUTES = 5;
    /** Rows kept for a collector that answered 429/503 or couldn't be reached; the oldest go first. */
    static final int MAX_RETRY_ROWS = 2000;
    static final String JOB = "JOB";
    static final String BACKGROUND = "(background)";
    static final String OTHER = QueryText.OTHER_STATEMENT;
    private static final int CACHE_MAX = 2000;

    /** What is filed: where its rows go and its two key fields (the second folds into "(other)" past a cap). */
    static final class Kind {
        static final Kind QUERIES = new Kind("/events/server-queries", "db", "statement");
        static final Kind CALLS = new Kind("/events/server-calls", "call_method", "host");
        final String path;
        final String first;
        final String second;

        private Kind(String path, String first, String second) {
            this.path = path;
            this.first = first;
            this.second = second;
        }
    }
    private static final int CACHE_TEXT_MAX = 4000;

    /** count, errors, total and slowest time, and a count per bucket: one query's, a request's or a minute's. */
    static final class Stat {
        long count;
        long errors;
        double sumMs;
        double maxMs;
        final long[] buckets = new long[Performance.BUCKET_EDGES_MS.length + 1];

        void add(double ms, boolean failed) {
            count += 1;
            if (failed) {
                errors += 1;
            }
            sumMs += ms;
            maxMs = Math.max(maxMs, ms);
            buckets[Performance.bucketOf(ms)] += 1;
        }

        void add(Stat other) {
            count += other.count;
            errors += other.errors;
            sumMs += other.sumMs;
            maxMs = Math.max(maxMs, other.maxMs);
            for (int i = 0; i < buckets.length; i++) {
                buckets[i] += other.buckets[i];
            }
        }
    }

    /** One request's queries, kept in its RequestContext until it finishes: a request running 10,000 queries costs what one running ten does. */
    static final class PerRequest {
        private final Map<String, Stat> stats = new LinkedHashMap<>();
        /** Set when the request finished: queries after that (an async tail) go straight to the minute. */
        private String method;
        private String route;
    }

    private static final class Key {
        final long minute;
        final String method;
        final String route;
        final String db;
        final String statement;

        Key(long minute, String method, String route, String db, String statement) {
            this.minute = minute;
            this.method = method;
            this.route = route;
            this.db = db;
            this.statement = statement;
        }

        @Override
        public boolean equals(Object o) {
            if (!(o instanceof Key)) {
                return false;
            }
            Key k = (Key) o;
            return minute == k.minute && method.equals(k.method) && route.equals(k.route) && db.equals(k.db) && statement.equals(k.statement);
        }

        @Override
        public int hashCode() {
            return Objects.hash(minute, method, route, db, statement);
        }
    }

    private final Core core;
    final Kind kind;
    final String serverName;
    final String runtime;
    private Map<Key, Stat> rows = new LinkedHashMap<>();
    private final Map<Long, Integer> keysPerMinute = new HashMap<>();
    private final List<Map<String, Object>> retry = new ArrayList<>();
    private long retryAt;
    private final Map<String, String> normalized = new ConcurrentHashMap<>();
    private final Periodic job;

    Queries(Core core, String serverName, String runtime) {
        this(core, serverName, runtime, Kind.QUERIES);
    }

    Queries(Core core, String serverName, String runtime, Kind kind) {
        this.core = core;
        this.kind = kind;
        this.serverName = serverName;
        this.runtime = runtime;
        this.job = core.valid ? core.every(this::flushJob, FLUSH_EVERY) : null;
    }

    /** False while Server speed is off in the dashboard: nothing is recorded. */
    boolean on() {
        return core.isOn("performance");
    }

    /** The statement to store ("" to drop it); prepared statements repeat, so recent ones are remembered. */
    String normalize(String text, String db) {
        if (text == null) {
            return "";
        }
        if (text.length() > CACHE_TEXT_MAX) {
            return QueryText.normalize(text, db);
        }
        String key = db + '\u0000' + text;
        String found = normalized.get(key);
        if (found == null) {
            found = QueryText.normalize(text, db);
            if (normalized.size() >= CACHE_MAX) {
                normalized.clear();
            }
            normalized.put(key, found);
        }
        return found;
    }

    /** A query (raw text, normalized here) that ran for context (null: outside any request or job). */
    void record(String db, String text, double ms, boolean failed, RequestContext context) {
        if (!on()) {
            return;
        }
        String database = QueryText.databaseOf(db);
        String statement = normalize(text, database);
        if (!statement.isEmpty()) {
            recordNormalized(database, statement, ms, failed, context);
        }
    }

    /** One outgoing call (calls.md): its method and host as stored, "" for a host it couldn't name. */
    void recordCall(String callMethod, String host, double ms, boolean failed, RequestContext context) {
        if (!on() || host == null || host.isEmpty() || callMethod == null || callMethod.isEmpty()) {
            return;
        }
        recordNormalized(callMethod, host, ms, failed, context);
    }

    /** This kind's map in the request's context. */
    private PerRequest perRequest(RequestContext context) {
        return kind == Kind.CALLS ? context.calls() : context.queries();
    }

    /** A query whose statement is already normalized (the Mongo and Redis listeners build their own). */
    void recordNormalized(String db, String statement, double ms, boolean failed, RequestContext context) {
        double time = Double.isFinite(ms) ? Math.max(0, ms) : 0;
        if (context == null) {
            Stat one = new Stat();
            one.add(time, failed);
            add(minuteNow(), JOB, BACKGROUND, db, statement, one);
            return;
        }
        PerRequest request = perRequest(context);
        String method;
        String route;
        synchronized (request) {
            if (request.method == null) {
                String key = db + '\u0000' + statement;
                if (!request.stats.containsKey(key) && request.stats.size() >= MAX_PER_REQUEST) {
                    key = db + '\u0000' + OTHER;
                }
                request.stats.computeIfAbsent(key, k -> new Stat()).add(time, failed);
                return;
            }
            method = request.method;
            route = request.route;
        }
        Stat one = new Stat();
        one.add(time, failed);
        add(minuteNow(), method, route, db, statement, one);
    }

    /** The request finished: its queries go into this minute under the method and route Server speed recorded it with. */
    void finish(RequestContext context, String method, String route) {
        if (context == null || method == null || route == null) {
            return;
        }
        PerRequest request = kind == Kind.CALLS ? context.peekCalls() : context.peekQueries();
        if (request == null) {
            return;
        }
        Map<String, Stat> done;
        synchronized (request) {
            if (request.method != null) {
                return;
            }
            request.method = method;
            request.route = route;
            done = new LinkedHashMap<>(request.stats);
            request.stats.clear();
        }
        long minute = minuteNow();
        for (Map.Entry<String, Stat> entry : done.entrySet()) {
            String[] parts = entry.getKey().split("\u0000", 2);
            add(minute, method, route, parts[0], parts[1], entry.getValue());
        }
    }

    private static long minuteNow() {
        return System.currentTimeMillis() / 60000 * 60;
    }

    private synchronized void add(long minute, String method, String route, String db, String statement, Stat stat) {
        Key key = new Key(minute, method, route, db, statement);
        Stat row = rows.get(key);
        if (row == null) {
            if (!keysPerMinute.containsKey(minute) && keysPerMinute.size() >= MAX_MINUTES) {
                long oldest = Collections.min(keysPerMinute.keySet());
                if (oldest >= minute) {
                    return;
                }
                keysPerMinute.remove(oldest);
                rows.keySet().removeIf(k -> k.minute == oldest);
            }
            int keys = keysPerMinute.getOrDefault(minute, 0);
            if (keys >= MAX_KEYS) {
                key = new Key(minute, method, route, db, OTHER);
                row = rows.get(key);
                if (row == null && keys >= HARD_MAX_KEYS) {
                    return;
                }
            }
            if (row == null) {
                row = new Stat();
                rows.put(key, row);
                keysPerMinute.put(minute, keys + 1);
            }
        }
        row.add(stat);
    }

    /** The rows ready to send: every minute (everything), or the minutes that are over. */
    synchronized List<Map<String, Object>> take(boolean everything) {
        long current = minuteNow();
        List<Map<String, Object>> out = new ArrayList<>();
        Map<Key, Stat> keep = new LinkedHashMap<>();
        for (Map.Entry<Key, Stat> entry : rows.entrySet()) {
            Key k = entry.getKey();
            if (!everything && k.minute >= current) {
                keep.put(k, entry.getValue());
                continue;
            }
            Stat v = entry.getValue();
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("minute", Instant.ofEpochSecond(k.minute).toString());
            row.put("method", k.method);
            row.put("route", k.route);
            row.put(kind.first, k.db);
            row.put(kind.second, k.statement);
            row.put("count", v.count);
            row.put("errors", v.errors);
            row.put("sum_ms", Performance.round1(v.sumMs));
            row.put("max_ms", Performance.round1(v.maxMs));
            List<Long> buckets = new ArrayList<>();
            for (long b : v.buckets) {
                buckets.add(b);
            }
            row.put("buckets", buckets);
            out.add(row);
        }
        rows = keep;
        Iterator<Long> minutes = keysPerMinute.keySet().iterator();
        while (minutes.hasNext()) {
            long minute = minutes.next();
            if (everything || minute < current) {
                minutes.remove();
            }
        }
        return out;
    }

    void flush(boolean everything) {
        List<Map<String, Object>> ready = new ArrayList<>();
        synchronized (retry) {
            // Rows a busy collector turned away go first, once it said to try again.
            if (everything || System.currentTimeMillis() >= retryAt) {
                ready.addAll(retry);
                retry.clear();
            }
        }
        ready.addAll(take(everything));
        if (!on()) {
            // Server speed switched off in the dashboard: what's left isn't wanted.
            return;
        }
        for (int i = 0; i < ready.size(); i += MAX_ROWS) {
            List<Map<String, Object>> batch = new ArrayList<>(ready.subList(i, Math.min(ready.size(), i + MAX_ROWS)));
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("site_id", core.siteId);
            body.put("server_name", serverName);
            body.put("runtime", runtime);
            body.put("rows", batch);
            Core.Response res = core.postBearer("performance", kind.path, body);
            if (!core.isClosing() && (res == null || res.status == 429 || res.status >= 500)) {
                keepForRetry(batch, res);
            }
        }
    }

    private void keepForRetry(List<Map<String, Object>> batch, Core.Response res) {
        long wait = (long) FLUSH_EVERY;
        if (res != null) {
            try {
                wait = Math.max(1, Math.min(3600, Long.parseLong(res.headers.getOrDefault("retry-after", "").trim())));
            } catch (NumberFormatException none) {
                // no seconds given: the next flush
            }
        }
        synchronized (retry) {
            retry.addAll(batch);
            while (retry.size() > MAX_RETRY_ROWS) {
                retry.remove(0);
            }
            retryAt = Math.max(retryAt, System.currentTimeMillis() + wait * 1000);
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
