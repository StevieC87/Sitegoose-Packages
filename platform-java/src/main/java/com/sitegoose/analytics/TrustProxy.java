package com.sitegoose.analytics;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.Function;

/**
 * How to find the visitor's address. Behind a proxy every request comes from
 * the proxy unless this says otherwise:
 *
 * <ul>
 *   <li>{@link #none()}: the connection's address (the default);</li>
 *   <li>{@link #hops(int)}: that many proxies of yours put addresses in X-Forwarded-For;</li>
 *   <li>{@link #cloudflare()}: CF-Connecting-IP, believed only when the connection comes
 *       from one of Cloudflare's own addresses (anyone who reaches the server directly can send it);</li>
 *   <li>{@link #custom(Function)}: your own, from the request's headers.</li>
 * </ul>
 */
public interface TrustProxy {
    /**
     * @param remote the connection's address
     * @param headers the request's headers, names lower-case
     */
    String clientIp(String remote, Map<String, String> headers);

    static TrustProxy none() {
        return (remote, headers) -> remote;
    }

    static TrustProxy hops(int hops) {
        if (hops <= 0) {
            return none();
        }
        return (remote, headers) -> {
            List<String> chain = new ArrayList<>();
            for (String part : Core.header(headers, "x-forwarded-for").split(",")) {
                if (!part.trim().isEmpty()) {
                    chain.add(part.trim());
                }
            }
            if (chain.isEmpty()) {
                return remote;
            }
            // A port after the address (Azure) is dropped; a hop that isn't an
            // address at all is no visitor, so the connection's address stands.
            String hop = Ip.withoutPort(chain.get(Math.max(0, chain.size() - hops)));
            return Ip.key(hop) != null ? hop : remote;
        };
    }

    static TrustProxy cloudflare() {
        return (remote, headers) -> {
            String forwarded = Ip.withoutPort(Core.header(headers, "cf-connecting-ip"));
            return Firewall.fromCloudflare(remote) && Ip.key(forwarded) != null ? forwarded : remote;
        };
    }

    static TrustProxy custom(Function<Map<String, String>, String> fromHeaders) {
        return (remote, headers) -> {
            String ip = fromHeaders.apply(headers);
            return ip == null ? "" : ip;
        };
    }

    /** From configuration text: "", "0" or "false" none; "true" one hop; a number of hops; "cloudflare". */
    static TrustProxy parse(String text) {
        String value = text == null ? "" : text.trim().toLowerCase(Locale.ROOT);
        if (value.isEmpty() || "false".equals(value) || "none".equals(value)) {
            return none();
        }
        if ("cloudflare".equals(value)) {
            return cloudflare();
        }
        if ("true".equals(value)) {
            return hops(1);
        }
        try {
            return hops(Integer.parseInt(value));
        } catch (NumberFormatException error) {
            throw new IllegalArgumentException("trustProxy: a number of proxies, true, or \"cloudflare\", not " + text);
        }
    }
}
