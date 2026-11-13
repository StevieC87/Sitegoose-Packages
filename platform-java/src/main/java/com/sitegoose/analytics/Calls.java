package com.sitegoose.analytics;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Locale;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.regex.Pattern;

/**
 * Outgoing HTTP calls (sdk/protocols/calls.md): what the hooks have in
 * common. Only the host is kept: a call's path, query string, headers and
 * body never leave the server. A call is timed from being sent to its
 * response's headers arriving; no answer or a 5xx is an error, a 4xx is the
 * other side's answer. The package's own calls to the collector aren't
 * counted.
 */
final class Calls {
    private Calls() {
    }

    private static final Pattern HOST = Pattern.compile("^[a-z0-9._\\-\\[\\]:]{1,255}$");
    private static final Pattern METHOD = Pattern.compile("^[A-Z]{1,10}$");

    private static int defaultPort(String scheme) {
        switch (scheme) {
            case "http":
            case "ws":
                return 80;
            case "https":
            case "wss":
                return 443;
            default:
                return -1;
        }
    }

    /** host[:port] without userinfo, lower case, from an authority ("user@Host:8080"). */
    private static String fromAuthority(String authority) {
        String a = authority;
        int at = a.lastIndexOf('@');
        if (at >= 0) {
            a = a.substring(at + 1);
        }
        return a.toLowerCase(Locale.ROOT);
    }

    /**
     * The host as calls.md stores it: lower case, with its port only when it
     * isn't the scheme's default ("localhost:8080", "[::1]:3000"); "" when it
     * isn't one.
     */
    static String hostOf(URI uri) {
        if (uri == null) {
            return "";
        }
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        String host;
        if (uri.getHost() != null) {
            host = uri.getHost().toLowerCase(Locale.ROOT);
            int port = uri.getPort();
            if (port >= 0 && port != defaultPort(scheme)) {
                host = host + ":" + port;
            }
        } else if (uri.getRawAuthority() != null) {
            // A registry-based authority (a host with "_" in it): URI won't split it.
            host = fromAuthority(uri.getRawAuthority());
            int colon = host.lastIndexOf(':');
            if (colon > host.lastIndexOf(']') && String.valueOf(defaultPort(scheme)).equals(host.substring(colon + 1))) {
                host = host.substring(0, colon);
            }
        } else {
            return "";
        }
        return HOST.matcher(host).matches() ? host : "";
    }

    static String hostOf(String url) {
        if (url == null) {
            return "";
        }
        try {
            return hostOf(URI.create(url.split("[?#]", 2)[0]));
        } catch (IllegalArgumentException notOne) {
            return "";
        }
    }

    /** scheme://host[:port]/path, lower case scheme and host, default port and trailing slashes dropped; "" when not one. */
    static String address(String url) {
        try {
            URI uri = URI.create(url.split("[?#]", 2)[0]);
            String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
            String host = hostOf(uri);
            if (scheme.isEmpty() || host.isEmpty()) {
                return "";
            }
            String path = uri.getRawPath() == null ? "" : uri.getRawPath();
            while (path.endsWith("/")) {
                path = path.substring(0, path.length() - 1);
            }
            return scheme + "://" + host + path;
        } catch (IllegalArgumentException notOne) {
            return "";
        }
    }

    /** True when url is under own (the collector's endpoint, as {@link #address} writes it): the package's own calls. */
    static boolean isOwn(String own, String url) {
        if (own == null || own.isEmpty() || url == null) {
            return false;
        }
        String given = address(url);
        return given.equals(own) || given.startsWith(own + "/");
    }

    /** The address for the error trail: no query string or fragment, and no user:password@ before the host. */
    static String withoutSecrets(String url) {
        String clean = url.split("[?#]", 2)[0];
        int scheme = clean.indexOf("://");
        int from = scheme < 0 ? 0 : scheme + 3;
        int slash = clean.indexOf('/', from);
        int at = clean.lastIndexOf('@', slash < 0 ? clean.length() : slash);
        return at >= from ? clean.substring(0, from) + clean.substring(at + 1) : clean;
    }

    /** Set while a hook on this thread times a call: one under it (OkHttp under a RestTemplate) leaves the call to it. */
    private static final ThreadLocal<Boolean> TIMING = new ThreadLocal<>();

    /** True when no hook on this thread is timing a call yet: this one does, until {@link #end()}. */
    static boolean begin() {
        if (TIMING.get() != null) {
            return false;
        }
        TIMING.set(Boolean.TRUE);
        return true;
    }

    static void end() {
        TIMING.remove();
    }

    /** The call's method as stored, or "" when it isn't one (made-up methods can't fill the table). */
    static String methodOf(String method) {
        String m = (method == null || method.isEmpty() ? "GET" : method).toUpperCase(Locale.ROOT);
        return METHOD.matcher(m).matches() ? m : "";
    }

    /** No answer (0) or a 5xx failed; a 4xx is the other side's answer. */
    static boolean failed(int status) {
        return !(status > 0 && status < 500);
    }

    // ---- java.net.http.HttpClient ----

    /**
     * A body handler that notes when the response's headers arrived (its
     * apply() is called then, before any body is read), then hands over to
     * the app's own handler. With redirects followed it sees the last answer only.
     */
    static final class Timed<T> implements HttpResponse.BodyHandler<T> {
        private final HttpResponse.BodyHandler<T> handler;
        private final Platform platform;
        private final String method;
        private final String url;
        private final long started;
        private final RequestContext context;
        private final AtomicBoolean done = new AtomicBoolean();

        Timed(Platform platform, HttpRequest request, HttpResponse.BodyHandler<T> handler) {
            this.platform = platform;
            this.handler = handler;
            this.method = request.method();
            this.url = String.valueOf(request.uri());
            this.started = System.nanoTime();
            this.context = RequestContext.current();
        }

        @Override
        public HttpResponse.BodySubscriber<T> apply(HttpResponse.ResponseInfo info) {
            answered(info.statusCode());
            return handler.apply(info);
        }

        void answered(int status) {
            if (done.compareAndSet(false, true)) {
                try {
                    platform.recordCall(method, url, started, status, context);
                } catch (RuntimeException ignored) {
                    // never in the way of the call
                }
            }
        }

        /** The call ended without headers: refused, timed out, reset. A cancel by the app isn't counted. */
        void failed(Throwable error) {
            Throwable cause = error instanceof CompletionException && error.getCause() != null ? error.getCause() : error;
            if (cause instanceof CancellationException || cause instanceof InterruptedException) {
                done.set(true);
                return;
            }
            answered(0);
        }
    }

    static <T> HttpResponse<T> send(Platform platform, HttpClient client, HttpRequest request, HttpResponse.BodyHandler<T> handler)
            throws IOException, InterruptedException {
        if (!begin()) {
            return client.send(request, handler);
        }
        Timed<T> timed = new Timed<>(platform, request, handler);
        try {
            return client.send(request, timed);
        } catch (IOException | RuntimeException | InterruptedException error) {
            timed.failed(error);
            throw error;
        } finally {
            end();
        }
    }

    static <T> CompletableFuture<HttpResponse<T>> sendAsync(Platform platform, HttpClient client, HttpRequest request,
            HttpResponse.BodyHandler<T> handler) {
        Timed<T> timed = new Timed<>(platform, request, handler);
        CompletableFuture<HttpResponse<T>> future;
        try {
            future = client.sendAsync(request, timed);
        } catch (RuntimeException error) {
            timed.failed(error);
            throw error;
        }
        future.whenComplete((response, error) -> {
            if (error != null) {
                timed.failed(error);
            }
        });
        return future;
    }
}
