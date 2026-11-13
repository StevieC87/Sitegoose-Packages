package com.sitegoose.analytics;

import java.io.IOException;
import java.lang.management.ManagementFactory;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.ThreadFactory;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.DoubleSupplier;
import java.util.regex.Pattern;

/**
 * What every module shares: the site's credentials, sending to the
 * collector, logging, background jobs, and the dashboard's module switches
 * (Site settings -> Server, GET /events/platform/config about once a minute).
 *
 * <p>A module the dashboard turns off stays loaded but does nothing; until
 * the switches arrive, or when they can't be fetched, every loaded module
 * stays on. Sending never throws into the app. Background jobs run on a few
 * daemon threads of the package's own.
 */
final class Core {
    static final String VERSION = Version.VERSION;
    static final Duration TIMEOUT = Duration.ofSeconds(5);
    static final int MIN_SYNC = 30;
    static final double RETRY = 60;
    static final String SESSION_HEADER = "x-analytics-session";
    private static final Pattern SITE_ID = Pattern.compile("[a-fA-F0-9]{24}");
    /**
     * The nine headers the dashboard can produce (expresscollect/Analytics/platform.js,
     * headersOf), lower case. A list of what's allowed, not of what isn't: whoever got
     * into our servers still couldn't make this app grant another site its users' data
     * (Access-Control-Allow-*), send every page elsewhere (Refresh), log everyone out
     * (Clear-Site-Data) or change what a response is. Shared cases:
     * sdk/protocols/header-cases.json.
     */
    static final Set<String> SECURITY_HEADERS = Set.of("strict-transport-security", "x-content-type-options",
            "x-frame-options", "referrer-policy", "permissions-policy", "cross-origin-opener-policy",
            "content-security-policy", "content-security-policy-report-only", "reporting-endpoints");
    static final System.Logger LOG = System.getLogger("com.sitegoose.analytics");

    final String siteId;
    final String secret;
    final String endpoint;
    final String serverName;
    final boolean valid;
    final boolean debug;
    final String userAgent;
    final HttpClient http;
    final ScheduledExecutorService pool;

    private volatile Map<String, Object> switches = Collections.emptyMap();
    private volatile List<String[]> headers = Collections.emptyList();
    private volatile Map<String, Object> flags = Collections.emptyMap();
    private volatile Map<String, Object> maintenance = Collections.singletonMap("on", false);
    private volatile String etag = "";
    private List<String> loaded = new ArrayList<>();
    private Periodic job;

    Core(String siteId, String secret, String endpoint, boolean debug, String serverName) {
        this.siteId = siteId == null ? "" : siteId;
        this.secret = secret == null ? "" : secret;
        String base = endpoint == null ? "" : endpoint;
        while (base.endsWith("/")) {
            base = base.substring(0, base.length() - 1);
        }
        this.endpoint = base;
        // The name this service checks in under (X-Platform-App): serverName,
        // as every module sends it, else the machine's.
        String name = serverName == null || serverName.isEmpty() ? Hosts.hostName() : serverName;
        this.serverName = name.length() > 100 ? name.substring(0, 100) : name;
        this.valid = SITE_ID.matcher(this.siteId).matches() && !this.secret.isEmpty()
                && (this.endpoint.startsWith("http://") || this.endpoint.startsWith("https://"));
        this.debug = debug;
        this.userAgent = "analytics-platform-java/" + VERSION;
        this.http = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(TIMEOUT)
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
        ScheduledThreadPoolExecutor executor = new ScheduledThreadPoolExecutor(4, daemonThreads());
        executor.setRemoveOnCancelPolicy(true);
        this.pool = executor;
    }

    private static ThreadFactory daemonThreads() {
        AtomicInteger count = new AtomicInteger();
        return work -> {
            Thread thread = new Thread(work, "analytics-platform-" + count.incrementAndGet());
            thread.setDaemon(true);
            return thread;
        };
    }

    void log(String module, String message) {
        if (debug) {
            LOG.log(System.Logger.Level.INFO, "[analytics-platform:" + module + "] " + message);
        }
    }

    static void warn(String message) {
        LOG.log(System.Logger.Level.WARNING, "[analytics-platform] " + message);
    }

    Periodic every(DoubleSupplier job, double first) {
        return new Periodic(pool, job, first);
    }

    /** A collector answer. */
    static final class Response {
        final int status;
        final Map<String, String> headers;
        final byte[] body;

        Response(int status, Map<String, String> headers, byte[] body) {
            this.status = status;
            this.headers = headers;
            this.body = body == null ? new byte[0] : body;
        }

        boolean ok() {
            return status >= 200 && status < 300;
        }

        Object json() {
            return Json.parse(new String(body, StandardCharsets.UTF_8));
        }

        String text(int max) {
            String text = new String(body, StandardCharsets.UTF_8);
            return text.length() > max ? text.substring(0, max) : text;
        }
    }

    enum Auth { BODY, BEARER }

    /** send()'s status when the body couldn't be written: dropped, never retried. */
    static final int UNSENDABLE = 0;

    /**
     * JSON to the collector. BODY puts site_id and sitesecret in the body
     * (the event endpoints), BEARER sends the secret as a header (firewall,
     * switches). Returns the answer, or null when it couldn't be sent.
     */
    Response send(String module, String path, String method, Map<String, Object> body, Auth auth, Map<String, String> extra) {
        if (!valid) {
            return null;
        }
        Duration timeout = TIMEOUT;
        if (deadline != 0) {
            long left = remainingMs();
            if (left <= 0) {
                log(module, "closing: out of time, not sent (" + path + ")");
                return null;
            }
            timeout = Duration.ofMillis(Math.min(TIMEOUT.toMillis(), left));
        }
        try {
            HttpRequest.Builder request = HttpRequest.newBuilder(URI.create(endpoint + path))
                    .timeout(timeout)
                    .header("User-Agent", userAgent);
            if (body != null) {
                Map<String, Object> payload = body;
                if (auth == Auth.BODY) {
                    payload = new LinkedHashMap<>(body);
                    payload.put("site_id", siteId);
                    payload.put("sitesecret", secret);
                }
                String json;
                try {
                    json = Json.write(payload);
                } catch (RuntimeException | StackOverflowError unsendable) {
                    // Not the network: trying again would fail the same way, so the
                    // batch is given up (status 0) instead of queued again.
                    warn("a " + module + " batch could not be written as JSON and was dropped: " + unsendable);
                    return new Response(UNSENDABLE, Collections.emptyMap(), null);
                }
                request.header("Content-Type", "application/json");
                request.method(method, HttpRequest.BodyPublishers.ofString(json, StandardCharsets.UTF_8));
            } else {
                request.method(method, HttpRequest.BodyPublishers.noBody());
            }
            if (auth == Auth.BEARER) {
                request.header("Authorization", "Bearer " + secret);
            }
            if (extra != null) {
                for (Map.Entry<String, String> header : extra.entrySet()) {
                    request.header(header.getKey(), header.getValue());
                }
            }
            HttpResponse<byte[]> answer = http.send(request.build(), HttpResponse.BodyHandlers.ofByteArray());
            Map<String, String> answerHeaders = new LinkedHashMap<>();
            answer.headers().map().forEach((name, values) -> {
                if (!values.isEmpty()) {
                    answerHeaders.put(name.toLowerCase(Locale.ROOT), values.get(0));
                }
            });
            if (answer.statusCode() >= 400) {
                log(module, "collector answered " + answer.statusCode() + " to " + path);
            }
            return new Response(answer.statusCode(), answerHeaders, answer.body());
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            return null;
        } catch (IOException | RuntimeException error) {
            log(module, "could not reach the collector (" + path + "): " + error);
            return null;
        }
    }

    Response post(String module, String path, Map<String, Object> body) {
        return send(module, path, "POST", body, Auth.BODY, null);
    }

    Response postBearer(String module, String path, Map<String, Object> body) {
        return send(module, path, "POST", body, Auth.BEARER, null);
    }

    // ---- Module switches ----

    /** False only when the dashboard turned the module off. */
    boolean isOn(String name) {
        return !Boolean.FALSE.equals(switches.get(name));
    }

    /** This process's resident memory in MB, where /proc says; null elsewhere. */
    static Long rssMb() {
        try {
            for (String line : Files.readAllLines(Paths.get("/proc/self/status"))) {
                if (line.startsWith("VmRSS:")) {
                    String[] fields = line.trim().split("\\s+");
                    return Math.round(Long.parseLong(fields[1]) / 1024.0);
                }
            }
        } catch (Exception unreadable) {
            // not Linux
        }
        return null;
    }

    static String runtime() {
        return "Java " + System.getProperty("java.version", "");
    }

    /**
     * This service's check-in, form-encoded so any name is plain ASCII:
     * Health -> All systems shows it running and when it was last heard
     * from. Null when it can't be built: the switches still sync, without it.
     */
    String checkIn() {
        try {
            if (serverName.isEmpty()) {
                return null;
            }
            Map<String, String> fields = new LinkedHashMap<>();
            fields.put("server", serverName);
            fields.put("kind", "process");
            fields.put("pid", String.valueOf(ProcessHandle.current().pid()));
            fields.put("up_s", String.valueOf(ManagementFactory.getRuntimeMXBean().getUptime() / 1000));
            fields.put("runtime", runtime());
            Long rss = rssMb();
            if (rss != null) {
                fields.put("rss_mb", String.valueOf(rss));
            }
            StringBuilder out = new StringBuilder();
            for (Map.Entry<String, String> field : fields.entrySet()) {
                if (out.length() > 0) {
                    out.append('&');
                }
                out.append(URLEncoder.encode(field.getKey(), StandardCharsets.UTF_8)).append('=')
                        .append(URLEncoder.encode(field.getValue(), StandardCharsets.UTF_8));
            }
            return out.toString();
        } catch (Throwable error) {
            return null;
        }
    }

    double syncSwitches() {
        Map<String, String> extra = new LinkedHashMap<>();
        extra.put("X-Platform-Modules", String.join(",", loaded));
        String app = checkIn();
        if (app != null) {
            extra.put("X-Platform-App", app);
        }
        if (!etag.isEmpty()) {
            extra.put("If-None-Match", etag);
        }
        Response res = send("core", "/events/platform/config?site_id=" + siteId, "GET", null, Auth.BEARER, extra);
        if (res != null && res.status == 200) {
            Map<String, Object> data = Json.map(res.json());
            if (data == null) {
                data = Collections.emptyMap();
            }
            if (Long.valueOf(1).equals(data.get("v")) && Json.map(data.get("modules")) != null) {
                apply(data);
                etag = res.headers.getOrDefault("etag", "");
            }
            return syncSeconds(data.get("sync"));
        }
        return RETRY;
    }

    /** Seconds until the next fetch: the answer's sync (RETRY when it gives none), at least MIN_SYNC. */
    static double syncSeconds(Object sync) {
        long seconds = Json.whole(sync, 0);
        return Math.max(MIN_SYNC, seconds == 0 ? (long) RETRY : seconds);
    }

    /** The switches answer, applied (also used by tests). */
    void apply(Map<String, Object> data) {
        switches = Json.map(data.get("modules"));
        Map<String, Object> flagMap = Json.map(data.get("flags"));
        flags = flagMap == null ? Collections.emptyMap() : flagMap;
        Map<String, Object> m = Json.map(data.get("maintenance"));
        maintenance = m == null ? Collections.singletonMap("on", false) : m;
        // Only the security headers, well formed (no line breaks can get through).
        List<String[]> pairs = new ArrayList<>();
        List<Object> given = Json.list(data.get("headers"));
        if (given != null) {
            for (Object item : given) {
                List<Object> pair = Json.list(item);
                if (pair == null || pair.size() != 2 || !(pair.get(0) instanceof String) || !(pair.get(1) instanceof String)) {
                    continue;
                }
                String name = (String) pair.get(0);
                String value = (String) pair.get(1);
                if (safeHeader(name, value)) {
                    pairs.add(new String[] {name, value});
                }
            }
        }
        headers = pairs;
    }

    /** One of SECURITY_HEADERS, in any case, with a value of visible ASCII, spaces and tabs, at most 4,000 characters. */
    static boolean safeHeader(String name, String value) {
        return SECURITY_HEADERS.contains(name.toLowerCase(Locale.ROOT)) && value.length() <= 4000 && visibleAscii(value);
    }

    /** Printable ASCII, spaces and tabs: what a header value may hold everywhere (no line breaks, no bytes a container mangles). */
    static boolean visibleAscii(String value) {
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            if (!(c == '\t' || (c >= 0x20 && c <= 0x7E))) {
                return false;
            }
        }
        return true;
    }

    Map<String, Object> flags() {
        return flags;
    }

    Map<String, Object> maintenance() {
        return maintenance;
    }

    /** The security headers picked on the dashboard, when the module is on. */
    List<String[]> securityHeaders() {
        return isOn("headers") ? headers : Collections.emptyList();
    }

    /** Starts fetching the switches; names are the modules the code loaded. */
    void start(List<String> names) {
        loaded = new ArrayList<>(names);
        if (valid) {
            job = every(this::syncSwitches, 0);
        }
    }

    void stop() {
        if (job != null) {
            job.stop(stopWait());
        }
    }

    void shutdown() {
        pool.shutdownNow();
        closeClient(http);
    }

    /** HttpClient's own threads stop too (Java 21's shutdownNow(); before that they end when idle). */
    static void closeClient(HttpClient client) {
        try {
            HttpClient.class.getMethod("shutdownNow").invoke(client);
        } catch (NoSuchMethodException older) {
            // Java 11-20: nothing to call
        } catch (ReflectiveOperationException | RuntimeException ignored) {
            // already closed
        }
    }

    /** Closing: everything still to send has until then, all modules together. */
    private volatile long deadline;

    void closing(long ms) {
        deadline = System.nanoTime() + ms * 1_000_000L;
    }

    boolean isClosing() {
        return deadline != 0;
    }

    long remainingMs() {
        return deadline == 0 ? Long.MAX_VALUE : (deadline - System.nanoTime()) / 1_000_000L;
    }

    /** How long to wait for a background run in progress to end. */
    long stopWait() {
        return Math.max(0, Math.min(2000, remainingMs()));
    }

    /** A header from a map with lower-case names, trimmed ("" when absent). */
    static String header(Map<String, String> headers, String name) {
        String value = headers == null ? null : headers.get(name.toLowerCase(Locale.ROOT));
        return value == null ? "" : value.trim();
    }
}
