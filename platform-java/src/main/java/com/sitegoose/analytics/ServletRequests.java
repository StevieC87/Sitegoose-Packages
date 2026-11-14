package com.sitegoose.analytics;

import java.lang.reflect.Method;
import java.util.Collections;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * A servlet request read without depending on either servlet API: the same
 * calls work for a {@code jakarta.servlet.http.HttpServletRequest} and a
 * {@code javax.servlet.http.HttpServletRequest}, so Platform's methods that
 * take a request take both. The methods are looked up on the interface, so a
 * container's own (non-public) request class is no obstacle.
 */
final class ServletRequests {
    private ServletRequests() {
    }

    private static final String[] INTERFACES = {"jakarta.servlet.http.HttpServletRequest", "javax.servlet.http.HttpServletRequest"};
    private static final Map<Class<?>, Map<String, Method>> METHODS = new ConcurrentHashMap<>();

    private static Map<String, Method> methodsOf(Object request) {
        return METHODS.computeIfAbsent(request.getClass(), type -> {
            for (String name : INTERFACES) {
                try {
                    Class<?> api = Class.forName(name, false, type.getClassLoader());
                    if (api.isAssignableFrom(type)) {
                        Map<String, Method> out = new ConcurrentHashMap<>();
                        out.put("getHeader", api.getMethod("getHeader", String.class));
                        out.put("getHeaders", api.getMethod("getHeaders", String.class));
                        out.put("getHeaderNames", api.getMethod("getHeaderNames"));
                        out.put("getRemoteAddr", api.getMethod("getRemoteAddr"));
                        out.put("getParameterMap", api.getMethod("getParameterMap"));
                        out.put("getMethod", api.getMethod("getMethod"));
                        out.put("getRequestURI", api.getMethod("getRequestURI"));
                        out.put("getAttribute", api.getMethod("getAttribute", String.class));
                        return out;
                    }
                } catch (ClassNotFoundException | NoSuchMethodException | LinkageError absent) {
                    // try the other API
                }
            }
            return Collections.emptyMap();
        });
    }

    static boolean isRequest(Object request) {
        return request != null && !methodsOf(request).isEmpty();
    }

    private static Object call(Object request, String method, Object... args) {
        Method found = request == null ? null : methodsOf(request).get(method);
        if (found == null) {
            return null;
        }
        try {
            return found.invoke(request, args);
        } catch (ReflectiveOperationException | RuntimeException error) {
            return null;
        }
    }

    static String header(Object request, String name) {
        Object value = call(request, "getHeader", name);
        return value instanceof String ? (String) value : "";
    }

    static Object attribute(Object request, String name) {
        return call(request, "getAttribute", name);
    }

    private static final String[] WRAPPERS = {"jakarta.servlet.ServletRequestWrapper", "javax.servlet.ServletRequestWrapper"};
    private static final String SPRING_FORWARDED = "org.springframework.web.filter.ForwardedHeaderFilter$";

    /** The request a wrapper wraps, or null when it is none. */
    private static Object unwrap(Object request) {
        for (String name : WRAPPERS) {
            try {
                Class<?> wrapper = Class.forName(name, false, request.getClass().getClassLoader());
                if (wrapper.isInstance(request)) {
                    return wrapper.getMethod("getRequest").invoke(request);
                }
            } catch (ReflectiveOperationException | LinkageError | RuntimeException absent) {
                // try the other API
            }
        }
        return null;
    }

    /**
     * The request from under Spring's ForwardedHeaderFilter, which believes
     * the leftmost (visitor-written) X-Forwarded-For entry and hides the
     * headers; the request itself when it isn't wrapped by it. As the
     * filter's PlatformFilter.beforeForwarding does.
     */
    static Object beforeForwarding(Object request) {
        Object found = request;
        Object current = request;
        for (int i = 0; i < 20 && current != null; i++) {
            Object inner = unwrap(current);
            if (inner != null && current.getClass().getName().startsWith(SPRING_FORWARDED) && isRequest(inner)) {
                found = inner;
            }
            current = inner;
        }
        return found;
    }

    static String remoteAddr(Object request) {
        Object value = call(request, "getRemoteAddr");
        return value instanceof String ? (String) value : "";
    }

    /** Every header, names lower-case; repeated Cookie fields joined with "; " (HTTP/2 may split them), others with ", ". */
    static Map<String, String> headers(Object request) {
        Map<String, String> out = new LinkedHashMap<>();
        Object names = call(request, "getHeaderNames");
        if (!(names instanceof Enumeration)) {
            return out;
        }
        Enumeration<?> each = (Enumeration<?>) names;
        while (each.hasMoreElements()) {
            Object name = each.nextElement();
            if (!(name instanceof String)) {
                continue;
            }
            String lower = ((String) name).toLowerCase(Locale.ROOT);
            Object values = call(request, "getHeaders", name);
            StringBuilder joined = new StringBuilder(out.getOrDefault(lower, ""));
            if (values instanceof Enumeration) {
                Enumeration<?> list = (Enumeration<?>) values;
                while (list.hasMoreElements()) {
                    Object value = list.nextElement();
                    if (joined.length() > 0) {
                        joined.append("cookie".equals(lower) ? "; " : ", ");
                    }
                    joined.append(value);
                }
            }
            out.put(lower, joined.toString());
        }
        return out;
    }

    @SuppressWarnings("unchecked")
    static Map<String, String[]> parameters(Object request) {
        Object value = call(request, "getParameterMap");
        return value instanceof Map ? (Map<String, String[]>) value : Collections.emptyMap();
    }
}
