package com.sitegoose.analytics;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * First-party proxy: the tracker served from the site's own domain, so ad
 * blockers don't hide visitors. Blockers recognise the address a script
 * comes from and what it is called; this app is already a server on the
 * site's domain, so the package serves both:
 *
 * <pre>
 *   &lt;prefix&gt;/js/&lt;rest&gt;   -&gt;  &lt;endpoint&gt;/&lt;rest&gt;                  (tracker files)
 *   &lt;prefix&gt;/api/&lt;rest&gt;  -&gt;  &lt;endpoint&gt;/collectanalytics/&lt;rest&gt; (the collector)
 * </pre>
 *
 * The prefix comes from the site secret: not guessable from the page, and
 * the same every time. It answers before every other module: a visitor's
 * beacon is our own traffic, not a page of the site.
 */
public final class Proxy {
    /** The tracker files, by name: anything else is refused rather than forwarded. */
    static final Set<String> FILES = Collections.unmodifiableSet(new HashSet<>(Arrays.asList(
            "track.js", "s.js", "snapshot.js", "replay.js", "survey.js", "banner.js",
            "leadform.js", "notice.js", "editor.js", "picker.js", "feedback.js", "shield.js",
            "widget.js", "share.js")));
    /** A pinned version never changes; /v&lt;major&gt;/ follows new releases, so it is held for an hour. */
    static final long TTL_PINNED_S = 7 * 24 * 60 * 60;
    static final long TTL_MAJOR_S = 60 * 60;
    static final int MAX_BODY = 6 * 1024 * 1024;
    /** The collector reads these; everything else, cookies above all, stays here. */
    /**
     * What a collector answer may be served as from the site's own domain. Its type comes
     * from the collector, so anything else becomes plain text, and nosniff stops a browser
     * guessing: a server that is no longer ours still can't answer {@code <prefix>/api/...}
     * with a page that runs as the customer's own site. Shared cases:
     * sdk/protocols/proxy-answer-cases.json.
     */
    static final Set<String> ANSWER_TYPES = Set.of("application/json", "text/plain", "image/webp");

    static String answerType(String value) {
        String given = value == null ? "" : value;
        String kind = given.split(";", 2)[0].trim().toLowerCase(Locale.ROOT);
        return ANSWER_TYPES.contains(kind) && given.chars().allMatch(c -> c >= 0x20 && c <= 0x7E) ? given : "text/plain; charset=utf-8";
    }

    static final List<String> PASS_HEADERS = Arrays.asList("content-type", "user-agent", "accept-language", "referer", "origin",
            "sec-fetch-site", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform");
    private static final Pattern SAFE_PATH = Pattern.compile("^[A-Za-z0-9/_.-]{1,120}$");
    private static final Pattern FILE_PATH = Pattern.compile("^v(\\d+(?:\\.\\d+\\.\\d+)?)/([a-z]+\\.js)$");

    private final Core core;
    private final boolean enabled;
    final String prefix;
    final String key;
    // One copy of each tracker file the collector serves, so a repeat visitor costs no upstream request.
    private final Map<String, Object[]> files = new ConcurrentHashMap<>();
    /**
     * When each version that failed was last asked for. Anyone can ask for
     * v&lt;any digits&gt;, so this keeps only the latest MAX_FAILED, as the other
     * packages do: kept forever, it would grow until the heap ran out.
     */
    static final int MAX_FAILED = 200;
    static final double FILE_RETRY_S = 60;
    private final Map<String, Double> failed = new java.util.LinkedHashMap<String, Double>() {
        @Override
        protected boolean removeEldestEntry(Map.Entry<String, Double> eldest) {
            return size() > MAX_FAILED;
        }
    };
    /**
     * A visitor's beacon waits on this, so the collector gets 2 seconds, not
     * the 5 the background sends get; and after FAILS_TO_OPEN failures in a
     * row the proxy answers 502 at once for OPEN_MS rather than holding every
     * request thread on a collector that is down.
     */
    static final java.time.Duration UPSTREAM_TIMEOUT = java.time.Duration.ofSeconds(2);
    static final int FAILS_TO_OPEN = 3;
    static final long OPEN_MS = 30_000;
    private final java.net.http.HttpClient http;
    private int failures;
    private volatile long openUntil;

    Proxy(Core core, String prefix) {
        this.core = core;
        this.enabled = true;
        String given = prefix == null || prefix.isEmpty() ? prefixFor(core.secret) : prefix;
        this.prefix = given.replaceAll("[^A-Za-z0-9_-]", "");
        this.key = core.secret.isEmpty() ? "" : keyFor(core.secret);
        this.http = java.net.http.HttpClient.newBuilder()
                .version(java.net.http.HttpClient.Version.HTTP_1_1)
                .connectTimeout(UPSTREAM_TIMEOUT)
                .followRedirects(java.net.http.HttpClient.Redirect.NEVER)
                .build();
    }

    /** True while the collector failed too often lately: answer without asking it. */
    boolean breakerOpen() {
        return System.currentTimeMillis() < openUntil;
    }

    private synchronized void succeeded() {
        failures = 0;
    }

    private synchronized void failedUpstream() {
        failures += 1;
        if (failures >= FAILS_TO_OPEN) {
            openUntil = System.currentTimeMillis() + OPEN_MS;
            failures = 0;
        }
    }

    void close() {
        Core.closeClient(http);
    }

    static String prefixFor(String secret) {
        return Errors.sha256("proxy|" + secret).substring(0, 8);
    }

    /**
     * Sent as X-Proxy-Key, so the collector believes the visitor addresses
     * this proxy passes on: anyone can write X-Forwarded-For. Worked out
     * from the secret as the collector does (expresscollect/utils/proxyKey.js).
     */
    static String keyFor(String secret) {
        return Errors.sha256("proxykey|" + secret).substring(0, 32);
    }

    /** Whether it is on (it can also be switched off in the dashboard). */
    public boolean on() {
        return enabled && core.valid && !prefix.isEmpty() && core.isOn("proxy");
    }

    public String prefix() {
        return prefix;
    }

    /** The tracker's address on this site, for the page's script tag: "/3f9a2c1b/js/v1/s.js". */
    public String scriptUrl() {
        return scriptUrl("1");
    }

    public String scriptUrl(String version) {
        return "/" + prefix + "/js/v" + version + "/s.js";
    }

    /** Where visits are sent, for the tag's data-collect: "/3f9a2c1b/api/e". */
    public String collectUrl() {
        return "/" + prefix + "/api/e";
    }

    /** {"js" | "api" | "bad", the rest} when the address is ours, else null. */
    String[] match(String path) {
        if (!on() || path == null) {
            return null;
        }
        String head = "/" + prefix + "/";
        if (!path.startsWith(head)) {
            return null;
        }
        String rest = path.substring(head.length());
        for (String kind : new String[] {"js", "api"}) {
            if (rest.startsWith(kind + "/")) {
                String tail = rest.substring(kind.length() + 1);
                if (!tail.isEmpty() && !tail.contains("..") && SAFE_PATH.matcher(tail).matches()) {
                    return new String[] {kind, tail};
                }
                break;
            }
        }
        return new String[] {"bad", ""};
    }

    static Reply notFound() {
        return new Reply(404).header("Content-Type", "text/plain; charset=utf-8").body("Not found");
    }

    /** The answer for one of our addresses. Blocking: up to the collector's timeout. */
    Reply handle(String kind, String rest, String method, String query, Map<String, String> headers, byte[] body, String clientIp) {
        if ("js".equals(kind)) {
            return file(rest);
        }
        if (!"api".equals(kind)) {
            return notFound();
        }
        return collector(rest, method, query, headers == null ? Collections.emptyMap() : headers, body, clientIp);
    }

    private static byte[] readCapped(InputStream in) throws IOException {
        try (InputStream stream = in) {
            return stream.readNBytes(MAX_BODY);
        }
    }

    private Reply file(String rest) {
        Matcher found = FILE_PATH.matcher(rest);
        if (!found.matches() || !FILES.contains(found.group(2))) {
            return notFound();
        }
        boolean pinned = found.group(1).contains(".");
        Object[] held = files.get(rest);
        double now = System.currentTimeMillis() / 1000.0;
        byte[] body = null;
        if (held != null && (Double) held[1] > now - (pinned ? TTL_PINNED_S : TTL_MAJOR_S)) {
            body = (byte[]) held[0];
        }
        if (body == null && !breakerOpen() && !recentlyFailed(rest, now)) {
            try {
                HttpRequest request = HttpRequest.newBuilder(URI.create(core.endpoint + "/" + rest)).timeout(UPSTREAM_TIMEOUT).GET().build();
                HttpResponse<InputStream> answer = http.send(request, HttpResponse.BodyHandlers.ofInputStream());
                byte[] fetched = readCapped(answer.body());
                if (answer.statusCode() >= 500) {
                    failedUpstream();
                } else {
                    succeeded();
                }
                if (answer.statusCode() == 200 && fetched.length > 500) {
                    body = fetched;
                    files.put(rest, new Object[] {body, now});
                    forgetFailure(rest);
                } else {
                    rememberFailure(rest, now);
                }
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
            } catch (IOException | RuntimeException error) {
                core.log("proxy", "could not fetch " + rest + ": " + error);
                rememberFailure(rest, now);
                failedUpstream();
            }
            // Upstream is unreachable: an old copy beats no tracker at all.
            if (body == null && held != null) {
                body = (byte[]) held[0];
            }
        }
        if (body == null) {
            return new Reply(502);
        }
        return new Reply(200)
                .header("Content-Type", "application/javascript; charset=utf-8")
                .header("Cache-Control", pinned ? "public, max-age=31536000, immutable" : "public, max-age=3600")
                .header("X-Content-Type-Options", "nosniff")
                .body(body);
    }

    // A fetch that failed lately isn't tried again for a minute.
    private boolean recentlyFailed(String rest, double now) {
        synchronized (failed) {
            Double at = failed.get(rest);
            return at != null && at > now - FILE_RETRY_S;
        }
    }

    private void rememberFailure(String rest, double now) {
        synchronized (failed) {
            failed.remove(rest);
            failed.put(rest, now);
        }
    }

    private void forgetFailure(String rest) {
        synchronized (failed) {
            failed.remove(rest);
        }
    }

    /** How many failed versions are remembered (tests). */
    int failing() {
        synchronized (failed) {
            return failed.size();
        }
    }

    private static String title(String name) {
        StringBuilder out = new StringBuilder();
        boolean up = true;
        for (char c : name.toCharArray()) {
            out.append(up ? Character.toUpperCase(c) : c);
            up = !Character.isLetter(c);
        }
        return out.toString();
    }

    private Reply collector(String rest, String method, String query, Map<String, String> headers, byte[] body, String clientIp) {
        String m = (method == null || method.isEmpty() ? "GET" : method).toUpperCase(Locale.ROOT);
        if ("OPTIONS".equals(m)) {
            // Same origin as the page, so a preflight shouldn't happen; answer it cheaply.
            return new Reply(204)
                    .header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
                    .header("Access-Control-Allow-Headers", "Content-Type")
                    .header("Access-Control-Max-Age", "86400");
        }
        if (!"GET".equals(m) && !"POST".equals(m)) {
            return notFound();
        }
        if (body != null && body.length > MAX_BODY) {
            return new Reply(413);
        }
        // The request is built before the breaker is asked: a query the URI parser
        // refuses (a "%zz" anyone can send) is the visitor's mistake, not the
        // collector's, and must not count against it.
        HttpRequest upstream;
        try {
            String url = core.endpoint + "/collectanalytics/" + rest + (query == null || query.isEmpty() ? "" : "?" + query);
            HttpRequest.Builder request = HttpRequest.newBuilder(new URI(url)).timeout(UPSTREAM_TIMEOUT);
            // The visitor's address: the collector needs it for the country, the
            // daily visitor ID and the per-visitor rate limit.
            request.header("X-Forwarded-For", clientIp == null ? "" : clientIp);
            if (!key.isEmpty()) {
                request.header("X-Proxy-Key", key);
            }
            for (String name : PASS_HEADERS) {
                String value = headers.get(name);
                if (value != null && !value.isEmpty()) {
                    request.header(title(name), value.replace("\r", "").replace("\n", ""));
                }
            }
            if ("POST".equals(m)) {
                request.POST(HttpRequest.BodyPublishers.ofByteArray(body == null ? new byte[0] : body));
            } else {
                request.GET();
            }
            upstream = request.build();
        } catch (URISyntaxException | IllegalArgumentException bad) {
            return new Reply(400);
        }
        if (breakerOpen()) {
            return new Reply(502);
        }
        try {
            HttpResponse<InputStream> answer = http.send(upstream, HttpResponse.BodyHandlers.ofInputStream());
            if (answer.statusCode() >= 500) {
                failedUpstream();
            } else {
                succeeded();
            }
            Reply reply = new Reply(answer.statusCode())
                    .header("Content-Type", answerType(answer.headers().firstValue("Content-Type").orElse(null)))
                    .header("X-Content-Type-Options", "nosniff");
            for (String name : new String[] {"Cache-Control", "Retry-After"}) {
                answer.headers().firstValue(name).ifPresent(value -> reply.header(name, value));
            }
            return reply.body(readCapped(answer.body()));
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            return new Reply(502);
        } catch (IOException error) {
            // The tracker already treats a failed beacon as lost and carries on.
            core.log("proxy", "could not reach the collector: " + error);
            failedUpstream();
            return new Reply(502);
        } catch (RuntimeException error) {
            core.log("proxy", "could not ask the collector: " + error);
            return new Reply(502);
        }
    }
}
