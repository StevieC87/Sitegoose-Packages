package com.sitegoose.analytics;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

/**
 * Maintenance mode module: while it's on (Site settings -> Server), visitors
 * get a "back soon" page (503, so search engines know it's temporary), except
 * allowed addresses and whoever opened the preview link
 * (?site_preview=&lt;code&gt;, remembered for a day in a cookie).
 */
final class Maintenance {
    static final String COOKIE = "site_preview";

    private final Core core;
    private final Predicate<String> skip;
    private Object allowFor;
    private Ip.Set allow = new Ip.Set(Collections.emptyList());

    Maintenance(Core core, Predicate<String> skip) {
        this.core = core;
        this.skip = skip;
    }

    static String escape(String text) {
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&#x27;");
    }

    static String page(String message) {
        String text = escape(message == null || message.isEmpty() ? "We're doing some maintenance. Please check back in a few minutes." : message);
        return "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
                + "<title>Back soon</title><style>body{margin:0;min-height:100vh;display:grid;place-items:center;font:16px/1.5 system-ui,sans-serif;"
                + "background:#f8fafc;color:#0f172a}main{max-width:32rem;padding:2rem;text-align:center}h1{font-size:1.6rem;margin:0 0 .5rem}"
                + "p{color:#475569;margin:0}@media(prefers-color-scheme:dark){body{background:#0f172a;color:#e2e8f0}p{color:#94a3b8}}</style></head>"
                + "<body><main><h1>Back soon</h1><p>" + text + "</p></main></body></html>";
    }

    /** The first value of a query parameter, as parse_qs gives it ("" when absent). */
    static String queryValue(String query, String name) {
        if (query == null || query.isEmpty()) {
            return "";
        }
        for (String part : query.split("[&;]")) {
            int eq = part.indexOf('=');
            if (eq < 0) {
                continue;
            }
            try {
                if (URLDecoder.decode(part.substring(0, eq), StandardCharsets.UTF_8).equals(name)) {
                    return URLDecoder.decode(part.substring(eq + 1), StandardCharsets.UTF_8);
                }
            } catch (IllegalArgumentException malformed) {
                // not that one
            }
        }
        return "";
    }

    /**
     * Null to let the request through; a Reply with status 0 to let it through
     * and remember the preview link (its headers go on the response); else the
     * "back soon" page. secure: the request came over HTTPS, so the cookie,
     * which carries the code itself, is never sent over plain HTTP.
     */
    Reply decide(String ip, String path, String query, String cookieHeader, boolean secure) {
        Map<String, Object> m = core.isOn("maintenance") ? core.maintenance() : null;
        if (m == null || !Boolean.TRUE.equals(m.get("on")) || (skip != null && skip.test(path))) {
            return null;
        }
        Object allowed = m.get("allow");
        synchronized (this) {
            if (allowFor != allowed) {
                allowFor = allowed;
                allow = new Ip.Set(Json.strings(allowed));
            }
        }
        Ip.Key key = Ip.key(ip);
        if (key != null && allow.has(key)) {
            return null;
        }
        Object bypass = m.get("bypass");
        String code = bypass instanceof String ? (String) bypass : "";
        if (!code.isEmpty()) {
            if (code.equals(queryValue(query, COOKIE))) {
                return new Reply(0).header("Set-Cookie", COOKIE + "=" + code + "; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax"
                        + (secure ? "; Secure" : ""));
            }
            List<String> values = Challenge.cookieValues(cookieHeader, COOKIE);
            if (values.contains(code)) {
                return null;
            }
        }
        Object message = m.get("message");
        return new Reply(503)
                .header("Content-Type", "text/html; charset=utf-8")
                .header("Retry-After", "600")
                .header("Cache-Control", "no-store")
                .body(page(message instanceof String ? (String) message : ""));
    }
}
