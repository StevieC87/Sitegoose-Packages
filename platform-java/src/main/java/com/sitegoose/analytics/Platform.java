package com.sitegoose.analytics;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Callable;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Supplier;

/**
 * One package for a site's Java server, run from the analytics dashboard:
 * firewall, error monitoring and server analytics. Each module is separate:
 * only the ones turned on are loaded, and one failing never stops the others;
 * the firewall in particular never waits on reporting. A loaded module can
 * also be switched off in the dashboard (Site settings -> Server).
 *
 * <pre>{@code
 * Platform platform = Platform.create(new PlatformOptions()
 *     .siteId("...").secret(System.getenv("ANALYTICS_SITE_SECRET")).endpoint("https://..."));
 * }</pre>
 *
 * Then the servlet filter ({@code com.sitegoose.analytics.jakarta.PlatformFilter},
 * or {@code com.sitegoose.analytics.javax.PlatformFilter}) in front of the app,
 * or the Spring Boot starter, which does both. No dependencies; Java 11+.
 */
public final class Platform {
    static final List<String> MODULES = Collections.unmodifiableList(java.util.Arrays.asList(
            "proxy", "firewall", "errors", "analytics", "performance", "crawlers", "forms", "headers", "audit", "flags",
            "maintenance", "inventory", "posture", "resources"));

    final Core core;
    private final Map<String, Object> modules = new LinkedHashMap<>();
    private final AtomicBoolean closed = new AtomicBoolean();
    private final Thread hook;
    /** Database queries (Server speed -> Queries): null when performance is off or queries(false). */
    private final Queries queries;
    /** Outgoing HTTP calls (Server speed -> Calls): null when performance is off or calls(false). */
    private final Queries calls;
    /** The collector's address as Calls.address() writes one: calls under it are the package's own. */
    private final String ownAddress;

    private Platform(PlatformOptions options) {
        PlatformOptions o = options == null ? new PlatformOptions() : options;
        core = new Core(o.siteId, o.secret, o.endpoint, o.debug, o.serverName);
        ownAddress = Calls.address(core.endpoint);
        if (!core.valid) {
            Core.warn("siteId, secret and endpoint are required; nothing is sent and every request passes");
        }
        ClassLoader loader = Thread.currentThread().getContextClassLoader();
        String serverName = o.serverName == null || o.serverName.isEmpty() ? null : o.serverName;
        for (String name : MODULES) {
            try {
                Object module = load(name, o, serverName, loader);
                if (module != null) {
                    modules.put(name, module);
                }
            } catch (RuntimeException | LinkageError error) {
                Core.warn("the " + name + " module could not start and is off: " + error);
            }
        }
        Queries timed = null;
        Performance performance = module("performance");
        if (performance != null && o.queries) {
            try {
                timed = new Queries(core, performance.serverName, performance.runtime);
            } catch (RuntimeException | LinkageError error) {
                Core.warn("query timings could not start and are off: " + error);
            }
        }
        queries = timed;
        Queries called = null;
        if (performance != null && o.calls) {
            try {
                called = new Queries(core, performance.serverName, performance.runtime, Queries.Kind.CALLS);
            } catch (RuntimeException | LinkageError error) {
                Core.warn("call timings could not start and are off: " + error);
            }
        }
        calls = called;
        Resources resources = module("resources");
        if (resources != null && performance != null) {
            resources.useInflight(performance::takeInflightPeak);
        }
        core.start(new ArrayList<>(modules.keySet()));
        Thread exit = null;
        if (o.shutdownHook) {
            exit = new Thread(this::closeQuietly, "analytics-platform-exit");
            try {
                Runtime.getRuntime().addShutdownHook(exit);
            } catch (RuntimeException shuttingDown) {
                exit = null;
            }
        }
        hook = exit;
    }

    public static Platform create(PlatformOptions options) {
        return new Platform(options);
    }

    private Object load(String name, PlatformOptions o, String serverName, ClassLoader loader) {
        switch (name) {
            case "proxy":
                return o.proxy.enabled ? new Proxy(core, o.proxy.prefix) : null;
            case "firewall":
                return o.firewall.enabled ? new Firewall(core, o.firewall, o.firewall.trustProxy != null ? o.firewall.trustProxy : o.trustProxy) : null;
            case "errors":
                return o.errors.enabled ? new Errors(core, o.errors, serverName) : null;
            case "analytics":
                return o.analytics.enabled ? new Analytics(core) : null;
            case "performance":
                return o.performance.enabled ? new Performance(core, o.performance.serverName != null ? o.performance.serverName : serverName) : null;
            case "crawlers":
                return o.crawlers.enabled ? new Crawlers(core, o.crawlers.serverName != null ? o.crawlers.serverName : serverName) : null;
            case "forms":
                return o.forms.enabled ? new Forms(core) : null;
            case "headers":
                // The headers come with the module switches (core).
                return o.headers.enabled ? Boolean.TRUE : null;
            case "audit":
                return o.audit.enabled ? new Audit(core) : null;
            case "flags":
                return o.flags.enabled ? new Flags(core) : null;
            case "maintenance":
                return o.maintenance.enabled ? new Maintenance(core, o.maintenance.skip) : null;
            case "inventory":
                return o.inventory.enabled ? new Inventory(core, o.inventory, serverName, loader) : null;
            case "posture":
                return o.posture.enabled ? new Posture(core, o.posture, serverName) : null;
            case "resources":
                return o.resources.enabled ? new Resources(core, o.resources.serverName != null ? o.resources.serverName : serverName) : null;
            default:
                throw new IllegalArgumentException(name);
        }
    }

    @SuppressWarnings("unchecked")
    <T> T module(String name) {
        return (T) modules.get(name);
    }

    // ---- Modules ----

    /** The modules that are on. */
    public List<String> modules() {
        return new ArrayList<>(modules.keySet());
    }

    /** The firewall, for check() in frameworks without a filter; null when off. */
    public Firewall firewall() {
        return module("firewall");
    }

    /**
     * The first-party proxy: proxy().scriptUrl() and proxy().collectUrl() are
     * the two addresses the page's script tag needs, on this site's own
     * domain. Null when off.
     */
    public Proxy proxy() {
        return module("proxy");
    }

    /** True when the configuration is complete (site ID, secret, endpoint): only then is anything sent. */
    public boolean isConfigured() {
        return core.valid;
    }

    /** The visitor's address, as trustProxy says. headers: names lower-case. */
    public String clientIp(String remote, Map<String, String> headers) {
        Firewall firewall = firewall();
        return firewall != null ? firewall.clientIp(remote, headers) : remote == null ? "" : remote;
    }

    /** The largest body the proxy forwards: a bigger one is answered 413. */
    public static final int PROXY_MAX_BODY = Proxy.MAX_BODY;

    /** Whether path is one of the proxy's addresses (cheap: no reading of the request). */
    public boolean isProxyPath(String path) {
        Proxy proxy = proxy();
        return proxy != null && proxy.match(path) != null;
    }

    /**
     * The answer when the address belongs to the proxy, else null. Called
     * first by every integration: a visitor's beacon is our traffic, not a
     * page of the site, so it is answered before the firewall, the crawler
     * count and the timing. body: the request's body (POST), or null.
     */
    public Reply proxyResponse(String path, String method, String query, Map<String, String> headers, byte[] body, String remote) {
        Proxy proxy = proxy();
        if (proxy == null) {
            return null;
        }
        String[] found = proxy.match(path);
        if (found == null) {
            return null;
        }
        Map<String, String> h = headers == null ? Collections.emptyMap() : headers;
        try {
            String ip = clientIp(remote, h);
            // A denied or banned address gets no tracker and sends no visits; the
            // rate limit and the browser check leave the tracker's own traffic alone.
            Firewall firewall = firewall();
            if (firewall != null) {
                try {
                    if ("block".equals(firewall.addressCheck(ip, method, path, Core.header(h, "user-agent")).action)) {
                        return new Reply(403).header("Content-Type", "text/plain; charset=utf-8")
                                .header("Cache-Control", "no-store").body("Forbidden");
                    }
                } catch (RuntimeException error) {
                    core.log("firewall", "check failed, request passed: " + error);
                }
            }
            return proxy.handle(found[0], found[1], method, query, h, body, ip);
        } catch (RuntimeException error) {
            core.log("proxy", "failed: " + error);
            return new Reply(502);
        }
    }

    /**
     * The firewall's answer when it turns the request away, else null.
     * headers: names lower-case. target: the request target as sent, query
     * string and all, not decoded (getRequestURI() + "?" + getQueryString()).
     */
    public Reply blocked(String remote, Map<String, String> headers, String method, String target) {
        return blocked(remote, headers, method, target, null);
    }

    /**
     * As blocked(remote, headers, method, target); seen[0] gets the decision
     * when one was made, for countStatic() after the response.
     */
    public Reply blocked(String remote, Map<String, String> headers, String method, String target, Firewall.Decision[] seen) {
        Firewall firewall = firewall();
        if (firewall == null) {
            return null;
        }
        Firewall.Decision decision;
        String ip;
        try {
            ip = firewall.clientIp(remote, headers);
            decision = firewall.check(ip, method, target, Core.header(headers, "user-agent"), Core.header(headers, "accept"),
                    Core.header(headers, "cookie"));
            if (seen != null && seen.length > 0) {
                seen[0] = decision;
            }
            if ("block".equals(decision.action) && "challenge".equals(decision.rule)) {
                return firewall.challengePage(ip, method);
            }
        } catch (RuntimeException error) {
            core.log("firewall", "check failed, request passed: " + error);
            return null;
        }
        if (!"block".equals(decision.action)) {
            return null;
        }
        Reply reply = new Reply(decision.status == 429 ? 429 : 403)
                .header("Content-Type", "text/plain; charset=utf-8")
                .header("Cache-Control", "no-store");
        if (decision.status == 429) {
            // A page limit is someone at one page too often, often a person (a
            // shopper refreshing checkout): the body tells them what to do.
            return reply.header("Retry-After", firewall.retryAfter(decision))
                    .body(decision.rule.startsWith("limit:") ? Firewall.LIMIT_BODY : "Too Many Requests");
        }
        return reply.body("Forbidden");
    }

    /**
     * After the response: a static file blocked() let through counts toward
     * the rate and the page limits after all when it answered 400 or more or
     * the app routed it to a controller (firewall.md, `rate`). Never throws.
     */
    public void countStatic(Firewall.Decision decision, int status, boolean routed) {
        Firewall firewall = firewall();
        if (firewall == null || decision == null || decision.late == null) {
            return;
        }
        try {
            firewall.countStatic(decision, status, routed);
        } catch (RuntimeException error) {
            core.log("firewall", "could not count a static file: " + error);
        }
    }

    /**
     * Whether Spring MVC sent the request to a controller method (handler:
     * the request's HandlerMapping.bestMatchingHandler, read by class name,
     * no Spring needed) on a route that isn't itself a file's: "/login" took
     * "/login.css" (suffix pattern matching) and "/search/{q}" took
     * "/search/x.css", but "/avatars/{id}.png" asks for files. A file Spring
     * serves from its resource handlers has no controller method.
     */
    public static boolean routedToController(Object handler, Object pattern) {
        if (handler == null) {
            return false;
        }
        boolean method = false;
        for (Class<?> type = handler.getClass(); type != null && !method; type = type.getSuperclass()) {
            method = "org.springframework.web.method.HandlerMethod".equals(type.getName());
        }
        return method && !(pattern instanceof String && Firewall.isStaticFile((String) pattern));
    }

    /** Spring MVC's HandlerMapping.BEST_MATCHING_HANDLER_ATTRIBUTE, read by name. */
    public static final String SPRING_HANDLER_ATTRIBUTE = "org.springframework.web.servlet.HandlerMapping.bestMatchingHandler";

    /**
     * Maintenance mode: null to let the request through; a Reply with status
     * 0 to let it through and remember the preview link (put its headers on
     * the response); else the "back soon" page (503).
     */
    public Reply maintenanceResponse(String remote, Map<String, String> headers, String path, String query) {
        Maintenance maintenance = module("maintenance");
        if (maintenance == null) {
            return null;
        }
        try {
            return maintenance.decide(clientIp(remote, headers), path, query, Core.header(headers, "cookie"));
        } catch (RuntimeException error) {
            core.log("maintenance", "check failed, request passed: " + error);
            return null;
        }
    }

    /** The dashboard's security headers the response doesn't set itself (present: the header names it has). */
    public List<String[]> securityHeaders(Collection<String> present) {
        if (!modules.containsKey("headers")) {
            return Collections.emptyList();
        }
        Set<String> have = new HashSet<>();
        if (present != null) {
            for (String name : present) {
                have.add(name.toLowerCase(Locale.ROOT));
            }
        }
        List<String[]> out = new ArrayList<>();
        for (String[] pair : core.securityHeaders()) {
            if (!have.contains(pair[0].toLowerCase(Locale.ROOT))) {
                out.add(pair);
            }
        }
        return out;
    }

    /** Records a finished request for Server speed (startedNanos: System.nanoTime() when it arrived). */
    public void timeRequest(String method, String route, int status, long startedNanos, String path) {
        timeRequest(method, route, status, startedNanos, path, RequestContext.current());
    }

    /**
     * timeRequest() for a request whose context isn't this thread's any more
     * (the filter ends a request after leaving it, or on an async thread):
     * the database queries it ran go under the same method and route.
     */
    public void timeRequest(String method, String route, int status, long startedNanos, String path, RequestContext context) {
        Performance performance = module("performance");
        if (performance != null) {
            try {
                String[] key = performance.record(method, route, status, (System.nanoTime() - startedNanos) / 1e6, path);
                if (key != null && context != null) {
                    if (queries != null) {
                        queries.finish(context, key[0], key[1]);
                    }
                    if (calls != null) {
                        calls.finish(context, key[0], key[1]);
                    }
                }
            } catch (RuntimeException error) {
                core.log("performance", "could not time a request: " + error);
            }
        }
    }

    /**
     * A request entered the app (the servlet filters call it): Server
     * resources reports the most in progress at once. Call {@link #requestEnded()}
     * once for each, however it ends.
     */
    public void requestStarted() {
        Performance performance = module("performance");
        if (performance != null) {
            performance.started();
        }
    }

    /** A request that {@link #requestStarted()} counted was answered or dropped. */
    public void requestEnded() {
        Performance performance = module("performance");
        if (performance != null) {
            performance.ended();
        }
    }

    // ---- Outgoing calls ----

    Queries calls() {
        return calls;
    }

    /**
     * An outgoing HTTP call your code made, for a client the package has no
     * hook for (Health -> Server speed -> Calls, and a step in the error
     * trail). startedNanos: System.nanoTime() as it was sent; status: the
     * answer's, 0 when none came (refused, timed out, reset). Only the host
     * is kept. The hooks ({@link #okHttpInterceptor()}, {@link #send},
     * the Spring starter's) call this themselves.
     */
    public void recordCall(String method, String url, long startedNanos, int status) {
        recordCall(method, url, startedNanos, status, RequestContext.current());
    }

    /** recordCall() for a call answered on another thread: context is the request it was made in (null: none). */
    public void recordCall(String method, String url, long startedNanos, int status, RequestContext context) {
        if (url == null || Calls.isOwn(ownAddress, url)) {
            return;
        }
        double ms = (System.nanoTime() - startedNanos) / 1e6;
        String callMethod = Calls.methodOf(method);
        crumb(context, callMethod.isEmpty() ? "GET" : callMethod, url, status);
        Queries mine = calls;
        if (mine == null || callMethod.isEmpty()) {
            return;
        }
        try {
            mine.recordCall(callMethod, Calls.hostOf(url), ms, Calls.failed(status), context);
        } catch (RuntimeException error) {
            core.log("performance", "could not count a call: " + error);
        }
    }

    /**
     * For an HTTP client hook, around the call it times: true when it is the
     * outermost on this thread and should record it (then call
     * {@link #endCallTiming()} once it has), false when an outer hook already
     * times this call (a RestTemplate on OkHttp with the interceptor too), so
     * the call is counted once.
     */
    public static boolean beginCallTiming() {
        return Calls.begin();
    }

    /** Ends what a {@link #beginCallTiming()} that returned true began. */
    public static void endCallTiming() {
        Calls.end();
    }

    /**
     * An OkHttp interceptor timing every call the client makes, for
     * {@code new OkHttpClient.Builder().addInterceptor(platform.okHttpInterceptor())}.
     * Typed by the call so the package needs no OkHttp of its own: it is an
     * {@code okhttp3.Interceptor}. A call made with {@code execute()} goes
     * under the request it ran in; one made with {@code enqueue()} runs on
     * OkHttp's own threads and is (background).
     *
     * @throws IllegalStateException when OkHttp isn't on the classpath
     */
    @SuppressWarnings("unchecked")
    public <T> T okHttpInterceptor() {
        try {
            return (T) new OkHttpCalls(this);
        } catch (LinkageError absent) {
            throw new IllegalStateException("OkHttp (okhttp3.Interceptor) isn't on the classpath", absent);
        }
    }

    /**
     * {@code client.send(request, handler)}, timed (Health -> Server speed ->
     * Calls): from sending to the response's headers, as the handler is
     * handed them. Answers and throws exactly as client.send does.
     */
    public <T> java.net.http.HttpResponse<T> send(java.net.http.HttpClient client, java.net.http.HttpRequest request,
            java.net.http.HttpResponse.BodyHandler<T> handler) throws java.io.IOException, InterruptedException {
        return Calls.send(this, client, request, handler);
    }

    /** {@code client.sendAsync(request, handler)}, timed as {@link #send} is; the call goes under the request it was made in. */
    public <T> java.util.concurrent.CompletableFuture<java.net.http.HttpResponse<T>> sendAsync(java.net.http.HttpClient client,
            java.net.http.HttpRequest request, java.net.http.HttpResponse.BodyHandler<T> handler) {
        return Calls.sendAsync(this, client, request, handler);
    }

    // ---- Database queries ----

    Queries queries() {
        return queries;
    }

    /**
     * The data source with every query timed (Health -> Server speed ->
     * Queries): use what this returns in place of the one you made. Values
     * are taken out of each statement before it is counted; bound parameters
     * are never read. Returned unchanged when performance is off or
     * queries(false). The Spring Boot starter wraps every DataSource bean
     * itself.
     */
    public javax.sql.DataSource wrap(javax.sql.DataSource dataSource) {
        if (queries == null) {
            return dataSource;
        }
        Queries mine = queries;
        return Jdbc.wrap(dataSource, () -> mine);
    }

    /**
     * wrap() for a data source made before the platform (a framework's own
     * wiring): platform is asked for on each query until it gives one. Already
     * wrapped: returned as it is.
     */
    public static javax.sql.DataSource wrap(javax.sql.DataSource dataSource, Supplier<Platform> platform) {
        return Jdbc.wrap(dataSource, queriesOf(platform));
    }

    /** The queries of a platform asked for on each use until it gives one. */
    private static Supplier<Queries> queriesOf(Supplier<Platform> platform) {
        AtomicReference<Platform> found = new AtomicReference<>();
        return () -> {
            Platform p = found.get();
            if (p == null && platform != null) {
                try {
                    p = platform.get();
                } catch (RuntimeException notYet) {
                    p = null;
                }
                if (p != null) {
                    found.set(p);
                }
            }
            return p == null ? null : p.queries;
        };
    }

    /** True when the data source is one wrap() returned. */
    public static boolean isWrapped(javax.sql.DataSource dataSource) {
        return Jdbc.isWrapped(dataSource);
    }

    /**
     * A MongoDB command listener timing every query (Health -> Server speed ->
     * Queries), for {@code MongoClientSettings.builder().addCommandListener(platform.mongoListener())}.
     * Typed by the call so the package needs no MongoDB driver of its own: it
     * is a {@code com.mongodb.event.CommandListener}. The Spring Boot starter
     * adds it to Spring's MongoClient itself.
     *
     * @throws IllegalStateException when the MongoDB driver isn't on the classpath
     */
    @SuppressWarnings("unchecked")
    public <T> T mongoListener() {
        try {
            return (T) new MongoListener(this::queries);
        } catch (LinkageError absent) {
            throw new IllegalStateException("the MongoDB Java driver (com.mongodb.event.CommandListener) isn't on the classpath", absent);
        }
    }

    /**
     * A Lettuce command listener timing every Redis command (Health -> Server
     * speed -> Queries) as "GET user:?": the command and its first key's
     * shape, never a value. For {@code redisClient.addListener(platform.redisListener())}
     * (Lettuce 6.1+, RedisClient or RedisClusterClient), before the client
     * connects: connections made earlier aren't watched. Typed by the call so
     * the package needs no Lettuce of its own: it is an
     * {@code io.lettuce.core.event.command.CommandListener}. The Spring Boot
     * starter adds it to Spring Data Redis's Lettuce client itself.
     *
     * @throws IllegalStateException when Lettuce isn't on the classpath
     */
    @SuppressWarnings("unchecked")
    public <T> T redisListener() {
        try {
            return (T) new RedisListener(this::queries);
        } catch (LinkageError absent) {
            throw new IllegalStateException("Lettuce (io.lettuce.core.event.command.CommandListener) isn't on the classpath", absent);
        }
    }

    /** redisListener() for a client made before the platform (a framework's own wiring): platform is asked for on each command until it gives one. */
    @SuppressWarnings("unchecked")
    public static <T> T redisListener(Supplier<Platform> platform) {
        try {
            return (T) new RedisListener(queriesOf(platform));
        } catch (LinkageError absent) {
            throw new IllegalStateException("Lettuce (io.lettuce.core.event.command.CommandListener) isn't on the classpath", absent);
        }
    }

    /** Records a finished request when it came from a crawler or AI bot (Health -> Crawlers). */
    public void recordCrawler(String userAgent, String path, int status, long startedNanos, long size, String ip) {
        Crawlers crawlers = module("crawlers");
        if (crawlers != null) {
            try {
                double ms = startedNanos == 0 ? 0 : (System.nanoTime() - startedNanos) / 1e6;
                crawlers.middleware(userAgent, path, status, ms, size, ip);
            } catch (RuntimeException error) {
                core.log("crawlers", "could not count a crawler request: " + error);
            }
        }
    }

    // ---- Errors ----

    /** An error you caught. */
    public void captureException(Throwable error) {
        captureException(error, null, 0, "handled");
    }

    /** An error you caught, with the status your answer has. */
    public void captureException(Throwable error, int status) {
        captureException(error, null, status, "handled");
    }

    /**
     * request: {method, path, route, session_id}, or null for this thread's
     * request. kind: "handled", "error" (uncaught) or "logged".
     */
    public void captureException(Throwable error, Map<String, String> request, int status, String kind) {
        Errors errors = module("errors");
        if (errors != null) {
            errors.capture(error, request, status, kind == null ? "handled" : kind);
        }
    }

    /** A step of your own in the trail shown before an error in this request or job. */
    public void addBreadcrumb(String text) {
        RequestContext context = RequestContext.current();
        if (context != null && modules.containsKey("errors")) {
            context.addCrumb("note", text, null);
        }
    }

    /** An outgoing call this request or job made, as a step only; {@link #recordCall} adds the step and times the call too. */
    public void addRequestBreadcrumb(String method, String url, int status) {
        // The package's own calls aren't steps of the request.
        if (url == null || Calls.isOwn(ownAddress, url)) {
            return;
        }
        crumb(RequestContext.current(), method == null ? "GET" : method.toUpperCase(Locale.ROOT), url, status);
    }

    /** A call as a step of the trail: the address without its query, fragment or user:password@. */
    private void crumb(RequestContext context, String method, String url, int status) {
        if (context != null && modules.containsKey("errors")) {
            context.addCrumb("request", method + " " + Calls.withoutSecrets(url), status > 0 ? Integer.valueOf(status) : null);
        }
    }

    /** A request in progress, for the integrations: errors captured meanwhile know it. Close it when the request ends. */
    public final class Scope implements AutoCloseable {
        private final RequestContext previous;
        final RequestContext context;

        Scope(RequestContext context) {
            this.context = context;
            this.previous = RequestContext.enter(context);
        }

        /** The request's context, for timeRequest() once the scope is closed. */
        public RequestContext context() {
            return context;
        }

        @Override
        public void close() {
            RequestContext.restore(previous);
        }
    }

    /**
     * Starts a request on this thread (the servlet filters do it): route is
     * read when an error is, since the framework finds it on the way in.
     */
    public Scope enterRequest(String method, String path, Supplier<String> route, String sessionId, String ip) {
        return new Scope(new RequestContext(method, path, route, sessionId, ip));
    }

    /** Puts a request's context on another thread (an async continuation of the same request). */
    public Scope resume(RequestContext context) {
        return new Scope(context);
    }

    /**
     * A background job (a queue consumer, a scheduled task): its errors are
     * sent with the job's name as their route, and each run is timed (Health
     * -> Server speed -> Jobs); a run that throws counts as failed, and the
     * exception is thrown on.
     */
    public <T> T job(String name, Callable<T> work) throws Exception {
        String route = "/(job) " + cut(name == null || name.isEmpty() ? "job" : name, 180);
        long started = System.nanoTime();
        Scope scope = new Scope(new RequestContext("JOB", route, () -> route, "", ""));
        int status = 200;
        try {
            return work.call();
        } catch (Exception | Error error) {
            status = 500;
            Map<String, String> fields = new LinkedHashMap<>();
            fields.put("method", "JOB");
            fields.put("path", route);
            fields.put("route", route);
            fields.put("session_id", "");
            captureException(error, fields, 500, "error");
            throw error;
        } finally {
            timeRequest("JOB", route, status, started, route, scope.context);
            scope.close();
        }
    }

    /** job() for work that returns nothing; a checked exception it throws comes out wrapped in a RuntimeException. */
    public void job(String name, Runnable work) {
        try {
            job(name, () -> {
                work.run();
                return null;
            });
        } catch (RuntimeException error) {
            throw error;
        } catch (Exception checked) {
            throw new RuntimeException(checked);
        }
    }

    /** The work wrapped as a job, to hand to an executor or scheduler: each run is a job(name). */
    public Runnable wrapJob(String name, Runnable work) {
        return () -> job(name, work);
    }

    private static String cut(String text, int max) {
        return text.length() > max ? text.substring(0, max) : text;
    }

    // ---- Requests from your code ----

    /** The visit, from a servlet request (jakarta or javax): the X-Analytics-Session header the page sends. */
    public static String sessionId(Object request) {
        if (request == null) {
            RequestContext context = RequestContext.current();
            return context == null ? "" : context.sessionId;
        }
        return ServletRequests.header(request, Core.SESSION_HEADER);
    }

    /** The visitor's address for a servlet request (jakarta or javax), as trustProxy says. */
    public String requestIp(Object request) {
        if (request == null) {
            RequestContext context = RequestContext.current();
            return context == null ? "" : context.ip;
        }
        if (!ServletRequests.isRequest(request)) {
            return "";
        }
        return clientIp(ServletRequests.remoteAddr(request), ServletRequests.headers(request));
    }

    /** A failed login on your site (bot protection), from this thread's request. */
    public void loginFailed() {
        String ip = requestIp(null);
        if (!ip.isEmpty()) {
            loginFailedFrom(ip);
        }
    }

    /** A failed login: the address as text, or a servlet request (jakarta or javax). */
    public void loginFailed(Object requestOrIp) {
        String ip = requestOrIp instanceof String ? (String) requestOrIp : requestIp(requestOrIp);
        if (ip != null && !ip.isEmpty()) {
            loginFailedFrom(ip);
        }
    }

    private void loginFailedFrom(String ip) {
        Firewall firewall = firewall();
        if (firewall != null) {
            try {
                firewall.loginFailed(ip);
            } catch (RuntimeException error) {
                core.log("firewall", "could not count a failed login: " + error);
            }
        }
    }

    /** A feature flag from the dashboard (false until the flag is known, or with the module off). */
    public boolean isEnabled(String key) {
        return isEnabled(key, null, false);
    }

    public boolean isEnabled(String key, Object user) {
        return isEnabled(key, user, false);
    }

    /** user: for rollouts and user lists; otherwise: until the flag is known, or with the module off. */
    public boolean isEnabled(String key, Object user, boolean otherwise) {
        Flags flags = module("flags");
        return flags != null ? flags.isEnabled(key, user == null ? null : String.valueOf(user), otherwise) : otherwise;
    }

    /** Records who did what (Security -> Audit log), with this thread's request's address and visit. */
    public void audit(String action, String actor, String target, Object details) {
        audit(action, actor, target, details, null);
    }

    /** request: a servlet request (jakarta or javax) for the actor's address and visit; null for this thread's. */
    public void audit(String action, String actor, String target, Object details, Object request) {
        Audit audit = module("audit");
        if (audit == null) {
            return;
        }
        try {
            audit.record(action, actor, target, details, requestIp(request), sessionId(request));
        } catch (RuntimeException error) {
            core.log("audit", "could not record: " + error);
        }
    }

    /** Form protection: checks a form (a servlet request's parameters) before you accept it. Spam goes to Leads -> Spam. */
    public FormCheck checkForm(Object request) {
        return checkForm(request, null, null, null);
    }

    public FormCheck checkForm(Object request, String email, String name, String form) {
        Map<String, Object> fields = new LinkedHashMap<>();
        if (request != null) {
            fields.putAll(ServletRequests.parameters(request));
        }
        return checkFields(fields, requestIp(request), email, name, form);
    }

    /** Form protection with the fields in hand (a JSON body, another framework's form). */
    public FormCheck checkFields(Map<String, ?> fields, String ip, String email, String name, String form) {
        Forms forms = module("forms");
        if (forms == null) {
            return new FormCheck(true, false, Collections.emptyList(), false);
        }
        try {
            return forms.check(fields, ip == null ? requestIp(null) : ip, email, name, form);
        } catch (RuntimeException error) {
            core.log("forms", "could not check a form: " + error);
            return Forms.unchecked();
        }
    }

    // ---- Server analytics ----

    /** An event (sent in the background), linked to this thread's request's visit. Returns its event_uid ("" when not queued). */
    public String track(String name, Map<String, ?> fields) {
        return track(name, fields, null);
    }

    /** sessionId: the visit (Platform.sessionId(request)); null for this thread's request's. */
    public String track(String name, Map<String, ?> fields, String sessionId) {
        Analytics analytics = module("analytics");
        return analytics != null ? analytics.track(name, fields, sessionId == null ? sessionId(null) : sessionId) : "";
    }

    /** Links this thread's request's visit to your user ID (waits up to 5 seconds). */
    public boolean identify(String userId) {
        return identify(userId, null);
    }

    public boolean identify(String userId, String sessionId) {
        return identify(userId, sessionId, null);
    }

    /**
     * With what you know about the user: traits, name to text, number or boolean
     * (Map.of("plan", "pro", "seats", 5)); other values are left out. sessionId
     * null for this thread's request's visit.
     */
    public boolean identify(String userId, String sessionId, Map<String, ?> traits) {
        Analytics analytics = module("analytics");
        return analytics != null && analytics.identify(userId, sessionId == null ? sessionId(null) : sessionId, traits);
    }

    /** Adds or updates a lead: {status, lead_id}, or null (waits up to 5 seconds). */
    public Map<String, Object> lead(Map<String, ?> fields) {
        return lead(fields, null);
    }

    public Map<String, Object> lead(Map<String, ?> fields, String sessionId) {
        Analytics analytics = module("analytics");
        return analytics != null ? analytics.lead(fields, sessionId == null ? sessionId(null) : sessionId) : null;
    }

    // ---- For the integrations ----

    /** The folders the app serves (an integration's), for posture's exposure check when its options named none. */
    public void servedFolders(List<String[]> folders) {
        Posture posture = module("posture");
        if (posture == null || folders == null) {
            return;
        }
        List<Posture.Root> roots = new ArrayList<>();
        for (String[] folder : folders) {
            try {
                if (folder.length >= 3 && folder[2] != null) {
                    roots.add(Posture.Root.jar(java.nio.file.Paths.get(folder[0]), folder[2], folder[1]));
                } else if (folder.length >= 1 && folder[0] != null && java.nio.file.Files.isDirectory(java.nio.file.Paths.get(folder[0]))) {
                    roots.add(Posture.Root.dir(folder[0], folder.length > 1 ? folder[1] : ""));
                }
            } catch (RuntimeException unusable) {
                // left out
            }
        }
        posture.defaultRoots(roots);
    }

    /**
     * The same from resource URLs (a class loader's file:, jar:file: or
     * Spring Boot's jar:nested: URL for "static/"), each {url, prefix}.
     */
    public void servedLocations(List<String[]> locations) {
        if (locations == null || module("posture") == null) {
            return;
        }
        List<String[]> folders = new ArrayList<>();
        for (String[] location : locations) {
            String[] folder = location == null || location.length == 0 ? null : folderOf(location[0], location.length > 1 ? location[1] : "");
            if (folder != null) {
                folders.add(folder);
            }
        }
        servedFolders(folders);
    }

    /** {dir, prefix} or {jar, prefix, entryPrefix} for a resource URL, or null. */
    static String[] folderOf(String url, String prefix) {
        if (url == null) {
            return null;
        }
        String p = prefix == null ? "" : prefix;
        try {
            if (url.startsWith("file:")) {
                return new String[] {java.nio.file.Paths.get(new java.net.URI(url)).toString(), p};
            }
            if (!url.startsWith("jar:")) {
                return null;
            }
            java.nio.file.Path jar = Inventory.outerFile(url);
            if (jar == null) {
                return null;
            }
            String rest = url.substring(4);
            int cut = rest.startsWith("nested:") ? rest.indexOf("/!") : rest.indexOf("!/");
            String inside = cut < 0 ? "" : rest.substring(cut).replace("!", "").replaceAll("/+", "/");
            while (inside.startsWith("/")) {
                inside = inside.substring(1);
            }
            if (inside.contains(".jar/")) {
                // inside a library jar inside the app's jar (a webjar): not the site's own files
                return null;
            }
            return new String[] {jar.toString(), p, inside};
        } catch (Exception unusable) {
            return null;
        }
    }

    /** Checks a framework integration makes (Spring Boot's settings), reported with posture. */
    public void frameworkChecks(Supplier<List<Map<String, Object>>> checks) {
        Posture posture = module("posture");
        if (posture != null) {
            posture.frameworkChecks(checks);
        }
    }

    /** A request attribute your code (or a framework adapter) can set to name the route, e.g. "/orders/{id}". */
    public static final String ROUTE_ATTRIBUTE = "com.sitegoose.analytics.route";
    /** A request attribute holding an exception a framework handled itself (Spring's resolver sets it). */
    public static final String ERROR_ATTRIBUTE = "com.sitegoose.analytics.error";
    /** Spring MVC's HandlerMapping.BEST_MATCHING_PATTERN_ATTRIBUTE, read by name: no Spring needed. */
    public static final String SPRING_PATTERN_ATTRIBUTE = "org.springframework.web.servlet.HandlerMapping.bestMatchingPattern";
    private static final Set<String> WRAPPERS = new HashSet<>(java.util.Arrays.asList(
            "jakarta.servlet.ServletException", "javax.servlet.ServletException",
            "org.springframework.web.util.NestedServletException",
            "java.lang.reflect.UndeclaredThrowableException", "java.lang.reflect.InvocationTargetException",
            "java.util.concurrent.CompletionException", "java.util.concurrent.ExecutionException"));

    /**
     * The error inside the wrappers a container or framework puts around it
     * (ServletException "Request processing failed", InvocationTargetException...),
     * so errors group by what went wrong, not by the wrapper. Subclasses (a
     * real error of its own kind) are kept.
     */
    public static Throwable unwrap(Throwable error) {
        Throwable current = error;
        for (int i = 0; i < 10 && current != null && current.getCause() != null && WRAPPERS.contains(current.getClass().getName()); i++) {
            current = current.getCause();
        }
        return current;
    }

    /** The route for a request's attributes: ours, else Spring MVC's pattern ("/**", the catch-all resource handler, is none). */
    public static String routeOf(Object ours, Object spring) {
        Object value = ours != null ? ours : spring;
        String route = value == null ? "" : String.valueOf(value);
        return "/**".equals(route) ? "" : route;
    }

    static byte[] utf8(String text) {
        return text.getBytes(StandardCharsets.UTF_8);
    }

    // ---- Shutting down ----

    /** Sends everything waiting (serverless: before returning). */
    public void flush() {
        for (Map.Entry<String, Object> entry : modules.entrySet()) {
            try {
                Object module = entry.getValue();
                if (module instanceof Firewall) {
                    ((Firewall) module).flush();
                } else if (module instanceof Errors) {
                    ((Errors) module).flush(false);
                } else if (module instanceof Analytics) {
                    ((Analytics) module).flush();
                } else if (module instanceof Performance) {
                    ((Performance) module).flush(true);
                } else if (module instanceof Crawlers) {
                    ((Crawlers) module).flush(true);
                } else if (module instanceof Audit) {
                    ((Audit) module).flush();
                } else if (module instanceof Resources) {
                    ((Resources) module).flush();
                }
            } catch (RuntimeException error) {
                core.log(entry.getKey(), "flush failed: " + error);
            }
        }
        if (queries != null) {
            try {
                queries.flush(true);
            } catch (RuntimeException error) {
                core.log("performance", "query flush failed: " + error);
            }
        }
        if (calls != null) {
            try {
                calls.flush(true);
            } catch (RuntimeException error) {
                core.log("performance", "call flush failed: " + error);
            }
        }
    }

    /** close() sends what's waiting for at most this long, all modules together. */
    static final long CLOSE_MS = 8000;

    /** Stops background work and sends what's waiting (at most 8 seconds). Safe to call more than once. */
    public void close() {
        close(CLOSE_MS);
    }

    /** close() with another time budget (tests). */
    void close(long budgetMs) {
        if (!closed.compareAndSet(false, true)) {
            return;
        }
        if (hook != null && Thread.currentThread() != hook) {
            try {
                Runtime.getRuntime().removeShutdownHook(hook);
            } catch (RuntimeException shuttingDown) {
                // the JVM is exiting: the hook is this very close
            }
        }
        // All of it, every module together, within CLOSE_MS: a redeploy or a
        // container's stop never waits on a collector that doesn't answer.
        core.closing(budgetMs);
        core.stop();
        for (Map.Entry<String, Object> entry : modules.entrySet()) {
            try {
                Object module = entry.getValue();
                if (module instanceof Proxy) {
                    ((Proxy) module).close();
                } else if (module instanceof Firewall) {
                    ((Firewall) module).close();
                } else if (module instanceof Errors) {
                    ((Errors) module).close();
                } else if (module instanceof Analytics) {
                    ((Analytics) module).close();
                } else if (module instanceof Performance) {
                    ((Performance) module).close();
                } else if (module instanceof Crawlers) {
                    ((Crawlers) module).close();
                } else if (module instanceof Audit) {
                    ((Audit) module).close();
                } else if (module instanceof Inventory) {
                    ((Inventory) module).close();
                } else if (module instanceof Posture) {
                    ((Posture) module).close();
                } else if (module instanceof Resources) {
                    ((Resources) module).close();
                }
            } catch (RuntimeException error) {
                core.log(entry.getKey(), "close failed: " + error);
            }
        }
        if (queries != null) {
            try {
                queries.close();
            } catch (RuntimeException error) {
                core.log("performance", "query close failed: " + error);
            }
        }
        if (calls != null) {
            try {
                calls.close();
            } catch (RuntimeException error) {
                core.log("performance", "call close failed: " + error);
            }
        }
        core.shutdown();
    }

    private void closeQuietly() {
        try {
            close();
        } catch (Throwable ignored) {
            // at exit: nothing left to tell
        }
    }
}
