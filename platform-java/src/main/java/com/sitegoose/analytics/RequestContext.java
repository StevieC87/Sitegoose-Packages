package com.sitegoose.analytics;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Supplier;

/**
 * The request or job being handled on this thread, set by the integrations
 * (the servlet filters, Platform.job): an error captured without a request
 * (logged, or caught deep in your code) still gets its route, and the trail
 * of steps before it. Outside one, steps are dropped.
 *
 * <p>A thread-local: work handed to another thread (an executor, a reactive
 * pipeline) leaves the request behind, as it does for MDC.
 */
public final class RequestContext {
    static final int CRUMB_MAX = 15;
    private static final ThreadLocal<RequestContext> CURRENT = new ThreadLocal<>();

    final String method;
    final String path;
    final String sessionId;
    final String ip;
    private final Supplier<String> route;
    private final List<Map<String, Object>> trail = new ArrayList<>();
    private Queries.PerRequest queries;
    private Queries.PerRequest calls;

    RequestContext(String method, String path, Supplier<String> route, String sessionId, String ip) {
        this.method = method == null ? "" : method;
        this.path = path == null ? "" : path;
        this.route = route;
        this.sessionId = sessionId == null ? "" : sessionId;
        this.ip = ip == null ? "" : ip;
    }

    /** The context of this thread, or null outside a request or job. */
    public static RequestContext current() {
        return CURRENT.get();
    }

    /** Sets this thread's context; returns the one it replaces, for {@link #restore}. */
    static RequestContext enter(RequestContext context) {
        RequestContext previous = CURRENT.get();
        CURRENT.set(context);
        return previous;
    }

    static void restore(RequestContext previous) {
        if (previous == null) {
            CURRENT.remove();
        } else {
            CURRENT.set(previous);
        }
    }

    String route() {
        try {
            String value = route == null ? null : route.get();
            return value == null ? "" : value;
        } catch (RuntimeException error) {
            return "";
        }
    }

    /** This request's database queries, made on its first one. */
    synchronized Queries.PerRequest queries() {
        if (queries == null) {
            queries = new Queries.PerRequest();
        }
        return queries;
    }

    /** This request's database queries, or null when it ran none. */
    synchronized Queries.PerRequest peekQueries() {
        return queries;
    }

    /** This request's outgoing calls, made on its first one. */
    synchronized Queries.PerRequest calls() {
        if (calls == null) {
            calls = new Queries.PerRequest();
        }
        return calls;
    }

    /** This request's outgoing calls, or null when it made none. */
    synchronized Queries.PerRequest peekCalls() {
        return calls;
    }

    /** {method, path, route, session_id}, as an error carries them. */
    Map<String, String> fields() {
        Map<String, String> out = new LinkedHashMap<>();
        out.put("method", method);
        out.put("path", path);
        out.put("route", route());
        out.put("session_id", sessionId);
        return out;
    }

    void addCrumb(String type, String text, Integer status) {
        Map<String, Object> crumb = new LinkedHashMap<>();
        crumb.put("type", type);
        String value = text == null ? "" : text;
        crumb.put("text", value.length() > 200 ? value.substring(0, 200) : value);
        if (status != null) {
            crumb.put("status", status);
        }
        crumb.put("at", System.currentTimeMillis());
        synchronized (trail) {
            trail.add(crumb);
            while (trail.size() > CRUMB_MAX) {
                trail.remove(0);
            }
        }
    }

    /** The trail as the tracker sends it: how long before now each step happened. */
    List<Map<String, Object>> breadcrumbs() {
        long now = System.currentTimeMillis();
        List<Map<String, Object>> out = new ArrayList<>();
        synchronized (trail) {
            for (Map<String, Object> crumb : trail) {
                Map<String, Object> copy = new LinkedHashMap<>(crumb);
                long at = (Long) copy.remove("at");
                copy.put("ms", Math.max(0, now - at));
                out.add(copy);
            }
        }
        return out;
    }

    public String method() {
        return method;
    }

    public String path() {
        return path;
    }

    /** The visit (the X-Analytics-Session header), "" when the page sent none. */
    public String sessionId() {
        return sessionId;
    }

    /** The visitor's address, as trustProxy says. */
    public String ip() {
        return ip;
    }
}
