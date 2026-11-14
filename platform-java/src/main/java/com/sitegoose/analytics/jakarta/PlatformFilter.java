package com.sitegoose.analytics.jakarta;

import com.sitegoose.analytics.Firewall;
import com.sitegoose.analytics.Platform;
import com.sitegoose.analytics.PlatformOptions;
import com.sitegoose.analytics.Reply;
import com.sitegoose.analytics.RequestContext;
import jakarta.servlet.AsyncEvent;
import jakarta.servlet.AsyncListener;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletContext;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletRequestWrapper;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Supplier;

/**
 * The package in front of a servlet app (Jakarta Servlet 5+: Tomcat 10+,
 * Jetty 11+, Undertow 2.2+, Spring Boot 3). Put it first, before any other
 * filter, so turned-away requests cost the app nothing.
 *
 * <p>In order: the tracker's own addresses (the first-party proxy), the
 * firewall (403, 429, or the browser check's 503 page), maintenance mode;
 * then the app, with the dashboard's security headers added to its answer,
 * its uncaught errors and handled 500s reported, and the request timed
 * (Server speed) and counted when a crawler made it.
 *
 * <p>Set up either in code ({@code new PlatformFilter(platform)}), or in
 * web.xml with init-params {@code site-id}, {@code secret}, {@code endpoint},
 * {@code trust-proxy} and {@code server-name}, each defaulting to the
 * environment ({@code ANALYTICS_SITE_ID}, {@code ANALYTICS_SITE_SECRET},
 * {@code ANALYTICS_ENDPOINT}, {@code ANALYTICS_TRUST_PROXY},
 * {@code ANALYTICS_SERVER_NAME}); or with a Platform you created put in the
 * servlet context attribute {@link #CONTEXT_ATTRIBUTE}.
 *
 * <p>The javax copy (com.sitegoose.analytics.javax.PlatformFilter, Servlet
 * 3.1/4: Tomcat 8.5/9, Jetty 9/10, Spring Boot 2) is generated from this
 * file at build time.
 */
public class PlatformFilter implements Filter {
    /** A servlet context attribute holding a Platform the filter uses (and leaves open). */
    public static final String CONTEXT_ATTRIBUTE = "com.sitegoose.analytics.Platform";

    private Platform platform;
    private boolean owned;

    /** For web.xml or a container's annotation scan: the platform comes from init() */
    public PlatformFilter() {
    }

    public PlatformFilter(Platform platform) {
        this.platform = platform;
    }

    public Platform platform() {
        return platform;
    }

    @Override
    public void init(FilterConfig config) {
        if (platform != null) {
            served(config.getServletContext());
            return;
        }
        ServletContext context = config.getServletContext();
        Object given = context == null ? null : context.getAttribute(CONTEXT_ATTRIBUTE);
        if (given instanceof Platform) {
            platform = (Platform) given;
        } else {
            PlatformOptions options = new PlatformOptions()
                    .siteId(setting(config, "site-id", "ANALYTICS_SITE_ID"))
                    .secret(setting(config, "secret", "ANALYTICS_SITE_SECRET"))
                    .endpoint(setting(config, "endpoint", "ANALYTICS_ENDPOINT"));
            String trust = setting(config, "trust-proxy", "ANALYTICS_TRUST_PROXY");
            if (trust != null && !trust.isEmpty()) {
                options.trustProxy(trust);
            }
            String server = setting(config, "server-name", "ANALYTICS_SERVER_NAME");
            if (server != null && !server.isEmpty()) {
                options.serverName(server);
            }
            platform = Platform.create(options);
            owned = true;
        }
        served(context);
    }

    private static String setting(FilterConfig config, String name, String env) {
        String value = config.getInitParameter(name);
        if (value == null || value.isEmpty()) {
            value = System.getenv(env);
        }
        return value == null ? null : value.trim();
    }

    /** The web app's folder, for posture's check of what it serves (when its options named none). */
    private void served(ServletContext context) {
        if (context == null || platform == null) {
            return;
        }
        try {
            String root = context.getRealPath("/");
            String temp = System.getProperty("java.io.tmpdir", "");
            // An embedded container's empty docbase (Spring Boot's tomcat-docbase.*) is not the site's files.
            if (root != null && !(temp.length() > 1 && java.nio.file.Paths.get(root).toAbsolutePath().startsWith(java.nio.file.Paths.get(temp).toAbsolutePath()))) {
                List<String[]> folders = new ArrayList<>();
                folders.add(new String[] {root, ""});
                platform.servedFolders(folders);
            }
        } catch (RuntimeException unsupported) {
            // a packed war: nothing on disk to look at
        }
    }

    @Override
    public void destroy() {
        if (owned && platform != null) {
            platform.close();
        }
    }

    @Override
    public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException, ServletException {
        if (platform == null || !(req instanceof HttpServletRequest) || !(res instanceof HttpServletResponse)) {
            chain.doFilter(req, res);
            return;
        }
        HttpServletRequest request = (HttpServletRequest) req;
        HttpServletResponse response = (HttpServletResponse) res;
        long started = System.nanoTime();
        // What was sent, not what Spring's ForwardedHeaderFilter made of it.
        HttpServletRequest sent = beforeForwarding(request);
        String method = sent.getMethod();
        String uri = sent.getRequestURI() == null ? "/" : sent.getRequestURI();
        String path = inApp(sent, uri);
        String query = sent.getQueryString();
        String remote = sent.getRemoteAddr();
        Map<String, String> headers = headers(sent);
        // The container already took the visitor's address from the proxy
        // headers (Tomcat's RemoteIpValve / RemoteIpFilter, Spring Boot's
        // server.forward-headers-strategy=native): what's left in them is the
        // visitor's own writing, so trustProxy must not read them again.
        Map<String, String> forIp = request.getAttribute(TOMCAT_FORWARDED) != null ? withoutForwarding(headers) : headers;

        // The tracker's own addresses, before anything else: a visitor's
        // beacon is our traffic, not a page of the site.
        if (platform.isProxyPath(path)) {
            byte[] body = null;
            if ("POST".equalsIgnoreCase(method)) {
                body = request.getContentLengthLong() > Platform.PROXY_MAX_BODY ? null : read(request.getInputStream());
                if (body == null) {
                    send(response, TOO_LARGE, method);
                    return;
                }
            }
            Reply answer = platform.proxyResponse(path, method, query == null ? "" : query, forIp, body, remote);
            if (answer != null) {
                send(response, answer, method);
                return;
            }
        }
        Firewall.Decision[] firewallSaid = new Firewall.Decision[1];
        Reply blocked = platform.blocked(remote, forIp, method, query == null ? uri : uri + "?" + query, firewallSaid);
        if (blocked != null) {
            send(response, blocked, method);
            return;
        }
        Reply closed = platform.maintenanceResponse(remote, forIp, path, query == null ? "" : query, request.isSecure() || sent.isSecure());
        if (closed != null && closed.status() != 0) {
            send(response, closed, method);
            return;
        }
        List<String[]> remember = closed == null ? Collections.emptyList() : closed.headers();
        TrackedResponse tracked = new TrackedResponse(response, () -> {
            for (String[] pair : platform.securityHeaders(response.getHeaderNames())) {
                response.setHeader(pair[0], pair[1]);
            }
            for (String[] pair : remember) {
                response.addHeader(pair[0], pair[1]);
            }
        });
        Route route = new Route(request);
        String ip = platform.clientIp(remote, forIp);
        // For platform.requestIp(request): the address worked out here, not the headers read again.
        request.setAttribute(Platform.IP_ATTRIBUTE, ip);
        Platform.Scope scope = platform.enterRequest(method, path, route, Platform.sessionId(request), ip);
        Request seen = new Request(request, response, tracked, method, route, path, started, headers, ip);
        seen.context = scope.context();
        seen.firewall = firewallSaid[0];
        // In progress from here until finish(): Server resources' most at once.
        platform.requestStarted();
        boolean async = false;
        try {
            chain.doFilter(request, tracked);
            async = request.isAsyncStarted();
        } catch (IOException | ServletException | RuntimeException | Error error) {
            Throwable cause = Platform.unwrap(error);
            // The visitor went away mid-answer (a closed tab, a cancelled
            // download): nothing went wrong on the site.
            boolean gone = clientGone(error);
            int status = gone || response.isCommitted() ? response.getStatus() : 500;
            if (!gone) {
                report(cause, null, status);
            }
            finish(seen, status);
            throw error;
        } finally {
            scope.close();
        }
        if (async && listen(request, response, seen, method, path, route, headers)) {
            return;
        }
        finish(seen, response.getStatus());
    }

    /**
     * Ends the request when its async processing completes. False when the
     * container won't take a listener (it completed meanwhile): the request
     * ends now, so it never stays counted as in progress.
     */
    private boolean listen(HttpServletRequest request, HttpServletResponse response, Request seen, String method, String path,
            Route route, Map<String, String> headers) {
        AtomicBoolean done = new AtomicBoolean();
        try {
            request.getAsyncContext().addListener(new AsyncListener() {
                @Override
                public void onComplete(AsyncEvent event) {
                    if (done.compareAndSet(false, true)) {
                        finish(seen, response.getStatus());
                    }
                }

                @Override
                public void onTimeout(AsyncEvent event) {
                }

                @Override
                public void onError(AsyncEvent event) {
                    Throwable error = event.getThrowable();
                    if (error != null && !clientGone(error)) {
                        // Another thread: the request's details go with the error.
                        report(Platform.unwrap(error), context(method, path, route.get(), headers), 500);
                    }
                }

                @Override
                public void onStartAsync(AsyncEvent event) {
                    event.getAsyncContext().addListener(this);
                }
            });
            return true;
        } catch (RuntimeException completed) {
            return false;
        }
    }

    /** Tomcat's RemoteIpValve and RemoteIpFilter set this when they changed the remote address. */
    static final String TOMCAT_FORWARDED = "org.apache.tomcat.request.forwarded";
    private static final Reply TOO_LARGE = new Reply(413);
    private static final java.util.Set<String> GONE = new java.util.HashSet<>(java.util.Arrays.asList(
            "org.apache.catalina.connector.ClientAbortException",
            "org.eclipse.jetty.io.EofException",
            "org.eclipse.jetty.io.EOFException",
            "io.undertow.server.TruncatedResponseException",
            "org.springframework.web.context.request.async.AsyncRequestNotUsableException",
            "java.nio.channels.ClosedChannelException"));

    /** True when the error only says the visitor hung up (broken pipe, reset, the containers' own abort exceptions). */
    static boolean clientGone(Throwable error) {
        Throwable current = error;
        for (int i = 0; i < 10 && current != null; i++) {
            if (GONE.contains(current.getClass().getName())) {
                return true;
            }
            if (current instanceof IOException) {
                String message = String.valueOf(current.getMessage()).toLowerCase(Locale.ROOT);
                if (message.contains("broken pipe") || message.contains("connection reset")
                        || message.contains("connection was aborted") || message.contains("connection abort")) {
                    return true;
                }
            }
            current = current.getCause();
        }
        return false;
    }

    /** The wrappers Spring's ForwardedHeaderFilter puts around a request. */
    static final String SPRING_FORWARDED = "org.springframework.web.filter.ForwardedHeaderFilter$";

    /**
     * The request as the container received it, under Spring's
     * ForwardedHeaderFilter (server.forward-headers-strategy=framework). That
     * filter believes the leftmost X-Forwarded-For or Forwarded entry, which
     * the visitor writes, and hides the headers: read from under it, the
     * address is trustProxy's, from the right, and the path is the one sent
     * (X-Forwarded-Prefix is anyone's to write too).
     */
    static HttpServletRequest beforeForwarding(HttpServletRequest request) {
        HttpServletRequest found = request;
        ServletRequest current = request;
        for (int i = 0; i < 20 && current instanceof ServletRequestWrapper; i++) {
            ServletRequest inner = ((ServletRequestWrapper) current).getRequest();
            if (current.getClass().getName().startsWith(SPRING_FORWARDED) && inner instanceof HttpServletRequest) {
                found = (HttpServletRequest) inner;
            }
            current = inner;
        }
        return found;
    }

    private static Map<String, String> withoutForwarding(Map<String, String> headers) {
        Map<String, String> out = new LinkedHashMap<>(headers);
        for (String name : new String[] {"x-forwarded-for", "cf-connecting-ip", "forwarded", "x-real-ip"}) {
            out.remove(name);
        }
        return out;
    }

    /**
     * The route, read from the request while it's in progress and kept when
     * it ends: an error sent later, or from another thread, never reads a
     * request the container has recycled for someone else.
     */
    static final class Route implements Supplier<String> {
        private final HttpServletRequest request;
        private volatile boolean ended;
        private volatile String value = "";

        Route(HttpServletRequest request) {
            this.request = request;
        }

        @Override
        public String get() {
            if (ended) {
                return value;
            }
            try {
                return Platform.routeOf(request.getAttribute(Platform.ROUTE_ATTRIBUTE), request.getAttribute(Platform.SPRING_PATTERN_ATTRIBUTE));
            } catch (RuntimeException recycled) {
                return value;
            }
        }

        void end() {
            if (!ended) {
                value = get();
                ended = true;
            }
        }
    }

    /** One request's details, for the end of it. */
    private static final class Request {
        final HttpServletRequest request;
        final HttpServletResponse response;
        final TrackedResponse tracked;
        final String method;
        final Route route;
        final String path;
        final long started;
        final Map<String, String> headers;
        final String ip;
        /** The request's context: its database queries are counted when it finishes, after the scope is left. */
        RequestContext context;
        /** Set by the first finish(): the request stops being in progress once. */
        final AtomicBoolean ended = new AtomicBoolean();
        /** The firewall's decision, for a static file counted after its response (Platform.countStatic). */
        Firewall.Decision firewall;

        Request(HttpServletRequest request, HttpServletResponse response, TrackedResponse tracked, String method, Route route,
                String path, long started, Map<String, String> headers, String ip) {
            this.request = request;
            this.response = response;
            this.tracked = tracked;
            this.method = method;
            this.route = route;
            this.path = path;
            this.started = started;
            this.headers = headers;
            this.ip = ip;
        }
    }

    private void report(Throwable error, Map<String, String> request, int status) {
        try {
            platform.captureException(error, request, status, "error");
        } catch (RuntimeException ignored) {
            // fail open
        }
    }

    /** Exceptions a framework or the container handled itself and still answered 500 with. */
    private static final String[] HANDLED = {Platform.ERROR_ATTRIBUTE, "jakarta.servlet.error.exception", "javax.servlet.error.exception"};

    private void finish(Request r, int status) {
        if (r.ended.compareAndSet(false, true)) {
            platform.requestEnded();
            // A static file that answered an error, or that Spring sent to a
            // controller after all (/login.css as /login), counts after all.
            if (r.firewall != null && r.firewall.countsLater()) {
                boolean routed;
                try {
                    routed = Platform.routedToController(r.request.getAttribute(Platform.SPRING_HANDLER_ATTRIBUTE),
                            r.request.getAttribute(Platform.SPRING_PATTERN_ATTRIBUTE));
                } catch (RuntimeException recycled) {
                    routed = false;
                }
                platform.countStatic(r.firewall, status, routed);
            }
        }
        try {
            r.tracked.commit();
            String route = r.route.get();
            r.route.end();
            // Spring's error handling, or Spring Boot's ErrorPageFilter in a war,
            // answered 500 itself: report what it handled.
            if (status >= 500) {
                for (String name : HANDLED) {
                    Object handled = r.request.getAttribute(name);
                    if (handled instanceof Throwable) {
                        if (!clientGone((Throwable) handled)) {
                            platform.captureException(Platform.unwrap((Throwable) handled), context(r.method, r.path, route, r.headers), status, "error");
                        }
                        break;
                    }
                }
            }
            // An event stream is open for minutes by design: not a slow request.
            String type = r.response.getContentType();
            if (type == null || !type.toLowerCase(Locale.ROOT).startsWith("text/event-stream")) {
                platform.timeRequest(r.method, route, status, r.started, r.path, r.context);
            }
            platform.recordCrawler(r.headers.get("user-agent"), r.path, status, r.started, r.tracked.bytes(), r.ip);
        } catch (RuntimeException ignored) {
            // fail open: reporting never changes the answer
        }
    }

    private static Map<String, String> context(String method, String path, String route, Map<String, String> headers) {
        Map<String, String> out = new LinkedHashMap<>();
        out.put("method", method);
        out.put("path", path);
        out.put("route", route == null ? "" : route);
        String session = headers.get("x-analytics-session");
        out.put("session_id", session == null ? "" : session);
        return out;
    }

    /** The path inside the app (no context path), as the framework's routes see it. */
    private static String inApp(HttpServletRequest request, String uri) {
        String context = request.getContextPath();
        if (context != null && !context.isEmpty() && uri.startsWith(context)) {
            String rest = uri.substring(context.length());
            return rest.isEmpty() ? "/" : rest;
        }
        return uri;
    }

    private static Map<String, String> headers(HttpServletRequest request) {
        Map<String, String> out = new LinkedHashMap<>();
        Enumeration<String> names = request.getHeaderNames();
        if (names == null) {
            return out;
        }
        while (names.hasMoreElements()) {
            String name = names.nextElement();
            String key = name.toLowerCase(Locale.ROOT);
            Enumeration<String> values = request.getHeaders(name);
            StringBuilder joined = new StringBuilder();
            while (values != null && values.hasMoreElements()) {
                if (joined.length() > 0) {
                    // HTTP/2 may split cookies over several fields (RFC 9113 8.2.3).
                    joined.append("cookie".equals(key) ? "; " : ", ");
                }
                joined.append(values.nextElement());
            }
            out.merge(key, joined.toString(), (a, b) -> a + ("cookie".equals(key) ? "; " : ", ") + b);
        }
        return out;
    }

    /** The body, or null when it is bigger than the proxy forwards (answered 413, never cut short). */
    private static byte[] read(InputStream in) throws IOException {
        byte[] body = in.readNBytes(Platform.PROXY_MAX_BODY + 1);
        return body.length > Platform.PROXY_MAX_BODY ? null : body;
    }

    private static void send(HttpServletResponse response, Reply reply, String method) throws IOException {
        response.setStatus(reply.status());
        for (String[] pair : reply.headers()) {
            response.addHeader(pair[0], pair[1]);
        }
        byte[] body = reply.body();
        response.setContentLength(body.length);
        if (!"HEAD".equalsIgnoreCase(method) && body.length > 0) {
            OutputStream out = response.getOutputStream();
            out.write(body);
            out.flush();
        }
    }
}
