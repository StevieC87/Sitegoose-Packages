package com.sitegoose.analytics;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * The browser check (rule {@code challenge}, sdk/protocols/firewall.md under
 * "Flood protection"): a GET or HEAD that asks for a page, from an address
 * with no valid pass, gets a small page instead of the site. Its script sets
 * the pass cookie and reloads, which a script that doesn't run JavaScript
 * never does.
 *
 * <p>The pass is {@code <day>.<first 32 hex digits of HMAC-SHA256(key, "<day>|<who>")>},
 * key = HMAC-SHA256 of "sg-challenge-v1" keyed with the site secret, so any of
 * the site's servers accepts a pass another one handed out. It counts for its
 * own day and the next. sdk/protocols/challenge-cases.json holds the cases
 * every client runs.
 */
public final class Challenge {
    private Challenge() {
    }

    public static final String COOKIE = "__sg_pass";
    static final int MAX_AGE = 86400;
    private static final Pattern PASS = Pattern.compile("(\\d{1,10})\\.([0-9a-f]{32})");
    private static final SecureRandom RANDOM = new SecureRandom();

    static byte[] hmac(byte[] key, byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            // An empty secret is still a key (Python's hmac takes b""), which the
            // JDK refuses; HMAC pads a short key with zeros, so one zero byte is the same key.
            mac.init(new SecretKeySpec(key.length == 0 ? new byte[1] : key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (Exception error) {
            throw new IllegalStateException("HmacSHA256 unavailable", error);
        }
    }

    /** The key every pass is signed with, from the site secret. */
    public static byte[] passKey(String secret) {
        return hmac((secret == null ? "" : secret).getBytes(StandardCharsets.UTF_8),
                "sg-challenge-v1".getBytes(StandardCharsets.US_ASCII));
    }

    /** Whole days since 1970-01-01 UTC. */
    static long dayOf(double nowSeconds) {
        return (long) Math.floor(nowSeconds / 86400);
    }

    static double now() {
        return System.currentTimeMillis() / 1000.0;
    }

    static String sign(byte[] key, long day, String bound) {
        byte[] digest = hmac(key, (day + "|" + bound).getBytes(StandardCharsets.UTF_8));
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < 16; i++) {
            out.append(String.format(Locale.ROOT, "%02x", digest[i] & 0xFF));
        }
        return out.toString();
    }

    /** Today's pass for this address, or "" when it isn't one. */
    public static String makePass(byte[] key, String ip, Double nowSeconds) {
        String bound = Ip.who(ip);
        if (bound == null) {
            return "";
        }
        long day = dayOf(nowSeconds == null ? now() : nowSeconds);
        return day + "." + sign(key, day, bound);
    }

    /** True when value is this address's pass for today or yesterday. */
    public static boolean isValid(byte[] key, String ip, String value, Double nowSeconds) {
        Matcher match = PASS.matcher(value == null ? "" : value);
        String bound = Ip.who(ip);
        if (!match.matches() || bound == null || "*".equals(bound)) {
            return false;
        }
        long day = Long.parseLong(match.group(1));
        long today = dayOf(nowSeconds == null ? now() : nowSeconds);
        if (day != today && day != today - 1) {
            return false;
        }
        return MessageDigest.isEqual(match.group(2).getBytes(StandardCharsets.US_ASCII),
                sign(key, day, bound).getBytes(StandardCharsets.US_ASCII));
    }

    /**
     * Every value the Cookie header carries under name (a browser can send
     * two, from different paths); at most four, like the Node client.
     */
    static List<String> cookieValues(String header, String name) {
        List<String> found = new ArrayList<>();
        for (String part : (header == null ? "" : header).split(";", -1)) {
            String piece = part.trim();
            int eq = piece.indexOf('=');
            if (eq < 0) {
                continue;
            }
            if (piece.substring(0, eq).trim().equals(name)) {
                String value = piece.substring(eq + 1).trim();
                // strip('"'): every quote at either end goes.
                int start = 0;
                int end = value.length();
                while (start < end && value.charAt(start) == '"') {
                    start++;
                }
                while (end > start && value.charAt(end - 1) == '"') {
                    end--;
                }
                found.add(value.substring(start, end));
                if (found.size() == 4) {
                    break;
                }
            }
        }
        return found;
    }

    static boolean hasPass(byte[] key, String ip, String cookieHeader, Double nowSeconds) {
        for (String value : cookieValues(cookieHeader, COOKIE)) {
            if (isValid(key, ip, value, nowSeconds)) {
                return true;
            }
        }
        return false;
    }

    /** The rules' skip prefixes, lower-cased (200 at most). */
    static List<String> compileSkip(Object entries) {
        List<String> out = new ArrayList<>();
        for (String entry : Json.strings(entries)) {
            if (!entry.isEmpty() && out.size() < 200) {
                out.add(entry.toLowerCase(Locale.ROOT));
            }
        }
        return out;
    }

    /**
     * Conditions 1 to 3: a GET or HEAD, whose Accept asks for text/html, for
     * a path (lower-cased, no query string) under none of skip.
     */
    static boolean asksForPage(String method, String target, String accept, List<String> skip) {
        String upper = method == null ? "" : method.toUpperCase(Locale.ROOT);
        if (!"GET".equals(upper) && !"HEAD".equals(upper)) {
            return false;
        }
        if (accept == null || !accept.toLowerCase(Locale.ROOT).contains("text/html")) {
            return false;
        }
        String path = target == null ? "" : target;
        int mark = path.indexOf('?');
        if (mark >= 0) {
            path = path.substring(0, mark);
        }
        mark = path.indexOf('#');
        if (mark >= 0) {
            path = path.substring(0, mark);
        }
        path = path.toLowerCase(Locale.ROOT);
        for (String prefix : skip) {
            if (path.startsWith(prefix)) {
                return false;
            }
        }
        return true;
    }

    static final String PAGE = "<!doctype html>\n"
            + "<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\n"
            + "<meta name=\"robots\" content=\"noindex\"><title>Just a moment</title>\n"
            + "<style nonce=\"{nonce}\">body{font:16px/1.5 system-ui,sans-serif;margin:0;display:flex;min-height:100vh;align-items:center;justify-content:center;color:#222;background:#fafafa}main{max-width:28rem;padding:2rem;text-align:center}</style>\n"
            + "</head><body><main><p id=\"m\">Checking your browser before you continue&hellip;</p>\n"
            + "<noscript><p>Please turn on JavaScript to continue to this site.</p></noscript></main>\n"
            + "<script nonce=\"{nonce}\">{script}</script>\n"
            + "</body></html>\n";

    /**
     * The page's script: sets the pass and reloads, but only when reading the
     * cookie back shows it was set (with cookies off it says so instead of
     * reloading forever), and at most three times a minute, counted in
     * sessionStorage, or in a __sg_tries cookie lasting a minute where
     * storage is blocked or full. Secure only when the browser is on https.
     * The same script as the Node, PHP and Python clients'.
     */
    static String script(String value) {
        return "(function(){var n=" + Json.write(COOKIE) + ",v=" + Json.write(value) + ",m=document.getElementById(\"m\"),"
                + "s=location.protocol===\"https:\";"
                + "document.cookie=n+\"=\"+v+\"; Max-Age=" + MAX_AGE + "; Path=/; SameSite=Lax\"+(s?\"; Secure\":\"\");"
                + "if((\" \"+document.cookie+\";\").indexOf(\" \"+n+\"=\"+v+\";\")<0){m.textContent=\"Please allow cookies for this site, then reload the page.\";return;}"
                + "var k=\"__sg_tries\",r=0,t;"
                + "try{t=JSON.parse(sessionStorage.getItem(k)||\"[]\").filter(function(x){return Date.now()-x<60000;});r=t.length;if(r<3){t.push(Date.now());sessionStorage.setItem(k,JSON.stringify(t));}}"
                + "catch(e){t=/(?:^|; )__sg_tries=([0-9]+)/.exec(document.cookie);r=t?+t[1]:0;if(r<3)document.cookie=k+\"=\"+(r+1)+\"; Max-Age=60; Path=/; SameSite=Lax\"+(s?\"; Secure\":\"\");}"
                + "if(r>=3){m.textContent=\"This page couldn't be opened because your connection's address keeps changing. Please try again in a minute.\";return;}"
                + "location.reload();})();";
    }

    static String nonce() {
        byte[] bytes = new byte[18];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * The check page: 503 with its own Content-Security-Policy and a fresh
     * nonce for its one script, and no body for a HEAD.
     */
    static Reply page(byte[] key, String ip, String method, Double nowSeconds) {
        String nonce = nonce();
        Reply reply = new Reply(503)
                .header("Content-Type", "text/html; charset=utf-8")
                .header("Cache-Control", "no-store")
                .header("X-Robots-Tag", "noindex")
                .header("Content-Security-Policy", "default-src 'none'; script-src 'nonce-" + nonce + "'; style-src 'nonce-"
                        + nonce + "'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");
        if ("HEAD".equalsIgnoreCase(method == null ? "" : method)) {
            return reply;
        }
        String body = PAGE.replace("{nonce}", nonce).replace("{script}", script(makePass(key, ip, nowSeconds)));
        return reply.body(body.getBytes(StandardCharsets.UTF_8));
    }
}
