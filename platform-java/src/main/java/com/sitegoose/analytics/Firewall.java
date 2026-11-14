package com.sitegoose.analytics;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Firewall module: rules from the collector (GET /events/firewall/rules,
 * protocol in sdk/protocols/firewall.md) every minute or so; every request is
 * checked against them in memory, so the app never waits on the collector.
 * What was blocked (or, in monitor mode, would have been) goes back in batches.
 *
 * <p>Fails open: until rules arrive, and whenever the collector can't be
 * reached, requests pass (with the last rules that arrived, if any). The rate
 * limit counts in this JVM: with several instances, pass a {@link Counter}
 * (e.g. Redis) for one count across them.
 */
public final class Firewall {
    static final int PROTOCOL = 1;
    static final int MIN_SYNC = 30;
    static final double FLUSH_EVERY = 5;
    static final int BATCH = 200;
    static final int QUEUE_MAX = 2000;
    static final int COUNTER_MAX = 100000;
    static final int MAX_LIMITS = 50;
    private static final Pattern LIMIT_ID = Pattern.compile("[a-z][a-z0-9_.-]{1,39}");
    /** The body of a page limit's 429: a person reads it, so it says what to do. */
    public static final String LIMIT_BODY = "Too many requests to this page. Please wait a little and try again.";
    /** The layers this server runs (X-Firewall-Layers): the address firewall and the browser check. */
    public static final String LAYERS = "app check";
    private static final Pattern SLASHES = Pattern.compile("/{2,}");

    /**
     * Cloudflare's published ranges (cloudflare.com/ips), the same list as
     * sdk/protocols/cloudflare-ranges.json (FirewallTest compares them):
     * CF-Connecting-IP is believed only from these.
     */
    public static final List<String> CLOUDFLARE = Collections.unmodifiableList(Arrays.asList(
            "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
            "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
            "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
            "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
            "2a06:98c0::/29", "2c0f:f248::/32"));
    private static volatile Ip.Set cloudflare;

    /** True when a connection's address is one of Cloudflare's. */
    static boolean fromCloudflare(String ip) {
        Ip.Key key = Ip.key(ip);
        if (key == null) {
            return false;
        }
        Ip.Set set = cloudflare;
        if (set == null) {
            set = cloudflare = new Ip.Set(CLOUDFLARE);
        }
        return set.has(key);
    }

    /** A rate-limit count shared between instances: the hits so far for key, which expires after ttl seconds. */
    @FunctionalInterface
    public interface Counter {
        long hit(String key, int ttlSeconds);
    }

    /** What check() decided. */
    public static final class Decision {
        /** "allow", "block" or "monitor". */
        public final String action;
        /** Empty when allowed; deny, ban, list, shared, probe, rate, challenge, request:&lt;id&gt; or limit:&lt;id&gt;. */
        public final String rule;
        /** 403, 429 for the rate limit and a page limit, 503 for the browser check. */
        public final int status;
        /** A page limit's window in seconds, for its Retry-After; 0 for any other rule. */
        final long window;
        /** A static file let through: what countStatic() counts after its response; null otherwise. */
        final Late late;

        Decision(String action, String rule, int status) {
            this(action, rule, status, 0);
        }

        Decision(String action, String rule, int status, long window) {
            this(action, rule, status, window, null);
        }

        Decision(String action, String rule, int status, long window, Late late) {
            this.action = action;
            this.rule = rule;
            this.status = status;
            this.window = window;
            this.late = late;
        }

        static final Decision ALLOW = new Decision("allow", "", 200);

        /** A static file let through, to be counted after its response if it turns out to be a page (Platform.countStatic). */
        public boolean countsLater() {
            return late != null;
        }

        @Override
        public String toString() {
            return action + " " + rule + " " + status;
        }
    }

    /** A static file's request, for countStatic() after the response: which counts it skipped. */
    static final class Late {
        final String ip;
        final String method;
        final String path;
        final String userAgent;
        final boolean rate;
        final boolean limits;

        Late(String ip, String method, String path, String userAgent, boolean rate, boolean limits) {
            this.ip = ip;
            this.method = method;
            this.path = path;
            this.userAgent = userAgent;
            this.rate = rate;
            this.limits = limits;
        }
    }

    static final class Probes {
        final Set<String> exact;
        final List<String> prefix;
        final long ban;

        Probes(Set<String> exact, List<String> prefix, long ban) {
            this.exact = exact;
            this.prefix = prefix;
            this.ban = ban;
        }
    }

    static final class Check {
        final List<String> skip;
        final Ip.Set exempt;

        Check(List<String> skip, Ip.Set exempt) {
            this.skip = skip;
            this.exempt = exempt;
        }
    }

    /** A page limit: at most limit requests per window seconds, per address, to what rule matches. */
    static final class Limit {
        final RequestRules.Rule rule;
        final long limit;
        final long window;
        /** A count for every page (the routed path) rather than one for all of them. */
        final boolean eachPath;

        Limit(RequestRules.Rule rule, long limit, long window, boolean eachPath) {
            this.rule = rule;
            this.limit = limit;
            this.window = window;
            this.eachPath = eachPath;
        }
    }

    static final class Rules {
        boolean enabled;
        String mode;
        double sync;
        Ip.Set allow;
        Ip.Set goodbots;
        Ip.Set deny;
        Ip.Set list;
        Ip.Set shared;
        Ip.Set banned;
        long[] rate;
        long ban;
        Map<String, Object> login;
        Probes probes;
        List<RequestRules.Rule> requests;
        List<Limit> limits;
        Ip.Set limitsExempt;
        Check challenge;
    }

    private final Core core;
    private final TrustProxy trustProxy;
    private final String mode;
    private final Counter counter;
    private final String cacheFile;
    private final Object lock = new Object();
    private final Map<String, long[]> counts = new LinkedHashMap<>();
    // Page limits: "<id>|<who>" -> {window, hits}. Limits with each "path"
    // ("<id>|<who>|<path>") count in a table of their own: one entry per
    // address and page fills a table fast, and dropping the oldest to make
    // room there mustn't start the login limit's counts again mid-window.
    final Map<String, long[]> limitCounts = new LinkedHashMap<>();
    final Map<String, long[]> pathCounts = new LinkedHashMap<>();
    // With a shared counter: the counts this process saw go over (key,
    // window and all), so a static file asked for after them can be turned
    // away without adding to them (peek). A counter can only add.
    private final Map<String, Boolean> overNoted = new LinkedHashMap<>();
    private Map<String, Map<String, Object>> queue = new LinkedHashMap<>();
    // Bot protection here: address -> when its ban ends; address -> {window start, failed logins}.
    private final Map<String, Double> bans = new LinkedHashMap<>();
    private final Map<String, double[]> logins = new LinkedHashMap<>();
    /** The browser check's passes are signed with the site secret, so any of the site's servers accepts one. */
    final byte[] passKey;
    volatile Rules rules;
    private volatile String etag = "";
    private final List<Periodic> jobs = new ArrayList<>();

    Firewall(Core core, PlatformOptions.FirewallOptions options, TrustProxy trustProxy) {
        this.core = core;
        this.trustProxy = trustProxy == null ? TrustProxy.none() : trustProxy;
        String given = options == null ? null : options.mode;
        this.mode = "monitor".equals(given) || "block".equals(given) ? given : null;
        this.counter = options == null ? null : options.counter;
        this.cacheFile = options == null ? null : options.cacheFile;
        this.passKey = Challenge.passKey(core.secret);
        if (cacheFile != null) {
            try {
                Map<String, Object> cached = Json.map(Json.parse(new String(Files.readAllBytes(Paths.get(cacheFile)), StandardCharsets.UTF_8)));
                if (cached != null) {
                    rules = compile(cached.get("rules"));
                    Object tag = cached.get("etag");
                    etag = tag instanceof String ? (String) tag : "";
                }
            } catch (IOException | RuntimeException unusable) {
                // no cache yet, or not one we can use
            }
        }
        if (core.valid) {
            jobs.add(core.every(this::sync, 0));
            jobs.add(core.every(this::flushJob, FLUSH_EVERY));
        }
    }

    static Probes compileProbes(Object given) {
        Map<String, Object> probes = Json.map(given);
        if (probes == null) {
            return null;
        }
        Set<String> exact = new LinkedHashSet<>();
        for (String path : Json.strings(probes.get("exact"))) {
            if (!path.isEmpty()) {
                exact.add(path.toLowerCase(Locale.ROOT));
            }
        }
        List<String> prefix = new ArrayList<>();
        for (String path : Json.strings(probes.get("prefix"))) {
            if (!path.isEmpty()) {
                prefix.add(path.toLowerCase(Locale.ROOT));
            }
        }
        if (exact.isEmpty() && prefix.isEmpty()) {
            return null;
        }
        return new Probes(exact, prefix, Math.max(0, Json.whole(probes.get("ban"), 0)));
    }

    /** True when the path (no query, lower-cased, "//" as "/") is a probe. */
    static boolean isProbe(String path, Probes probes) {
        if (probes == null) {
            return false;
        }
        String clean = path == null ? "" : path;
        int cut = clean.length();
        for (char c : new char[] {'?', '#'}) {
            int at = clean.indexOf(c);
            if (at >= 0 && at < cut) {
                cut = at;
            }
        }
        clean = SLASHES.matcher(clean.substring(0, cut).toLowerCase(Locale.ROOT)).replaceAll("/");
        // /x/../.env and /.env;a are /.env to the container.
        for (String text : new String[] {clean, RequestRules.resolvePath(RequestRules.decodeOnce(clean))}) {
            if (probes.exact.contains(text)) {
                return true;
            }
            for (String prefix : probes.prefix) {
                if (text.startsWith(prefix)) {
                    return true;
                }
            }
        }
        return false;
    }

    static Check compileChallenge(Object given) {
        Map<String, Object> data = Json.map(given);
        if (data == null) {
            return null;
        }
        return new Check(Challenge.compileSkip(data.get("skip")), new Ip.Set(Json.strings(data.get("exempt"))));
    }

    private static boolean wholeIn(Object value, long min, long max) {
        if (!(value instanceof Number)) {
            return false;
        }
        double d = ((Number) value).doubleValue();
        return d == Math.floor(d) && d >= min && d <= max;
    }

    /**
     * The page limits as they will be counted. One that can't be used (a bad
     * id, limit or window, or nothing left to match once regex is left out)
     * is dropped; the others stay.
     */
    static List<Limit> compileLimits(Map<String, Object> data) {
        List<Limit> out = new ArrayList<>();
        List<Object> list = data == null ? null : Json.list(data.get("rules"));
        if (list == null) {
            return out;
        }
        for (Object item : list.subList(0, Math.min(list.size(), MAX_LIMITS))) {
            Map<String, Object> limit = Json.map(item);
            if (limit == null || !(limit.get("id") instanceof String) || !LIMIT_ID.matcher((String) limit.get("id")).matches()
                    || !wholeIn(limit.get("limit"), 1, 100000) || !wholeIn(limit.get("window"), 1, 3600)) {
                continue;
            }
            List<String> methods = new ArrayList<>();
            for (String method : Json.strings(limit.get("methods"))) {
                methods.add(method.toUpperCase(Locale.ROOT));
            }
            RequestRules.Rule rule = new RequestRules.Rule((String) limit.get("id"),
                    "block".equals(limit.get("action")) ? "block" : "monitor", 0, methods);
            for (String name : new String[] {"path", "query"}) {
                RequestRules.Section part = RequestRules.section(limit.get(name), false);
                if (part != null) {
                    rule.sections.put(name, part);
                }
            }
            // With neither a path nor a query it would count every request.
            if (rule.sections.isEmpty()) {
                continue;
            }
            out.add(new Limit(rule, Json.whole(limit.get("limit"), 0), Json.whole(limit.get("window"), 0),
                    "path".equals(limit.get("each"))));
        }
        return out;
    }

    static Rules compile(Object given) {
        Map<String, Object> data = Json.map(given);
        if (data == null || !Long.valueOf(PROTOCOL).equals(data.get("v"))) {
            throw new IllegalArgumentException("unknown rules version");
        }
        Rules r = new Rules();
        Map<String, Object> rate = Json.map(data.get("rate"));
        if (rate != null && Json.whole(rate.get("limit"), 0) > 0) {
            long window = Json.whole(rate.get("window"), 0);
            r.rate = new long[] {Json.whole(rate.get("limit"), 0), Math.max(1, window == 0 ? 60 : window)};
        }
        r.enabled = Boolean.TRUE.equals(data.get("enabled"));
        r.mode = "block".equals(data.get("mode")) ? "block" : "monitor";
        r.sync = Core.syncSeconds(data.get("sync"));
        r.allow = new Ip.Set(Json.strings(data.get("allow")));
        // Crawlers the rate limit must not catch (absent in older rules).
        r.goodbots = new Ip.Set(Json.strings(data.get("goodbots")));
        r.deny = new Ip.Set(Json.strings(data.get("deny")));
        r.list = new Ip.Set(Json.strings(data.get("lists")));
        r.shared = new Ip.Set(Json.strings(data.get("shared")));
        r.banned = new Ip.Set(Json.strings(data.get("banned")));
        Map<String, Object> ban = Json.map(data.get("ban"));
        r.ban = ban == null ? 0 : Json.whole(ban.get("seconds"), 0);
        Map<String, Object> login = Json.map(data.get("login"));
        r.login = login != null && Json.whole(login.get("limit"), 0) > 0 ? login : null;
        r.probes = compileProbes(data.get("probes"));
        // Virtual patching: rules that match the request, not the address.
        r.requests = RequestRules.compile(data.get("requests"));
        // Page limits: one kind of request capped on its own (absent in older rules).
        Map<String, Object> limits = Json.map(data.get("limits"));
        r.limits = compileLimits(limits);
        r.limitsExempt = new Ip.Set(limits == null ? Collections.emptyList() : Json.strings(limits.get("exempt")));
        // The browser check: present only when the site is to be checked.
        r.challenge = compileChallenge(data.get("challenge"));
        return r;
    }

    double sync() {
        Map<String, String> extra = new LinkedHashMap<>();
        extra.put("X-Firewall-Layers", LAYERS);
        String name = Hosts.serverHeader();
        if (!name.isEmpty()) {
            extra.put("X-Server-Name", name);
        }
        if (!etag.isEmpty()) {
            extra.put("If-None-Match", etag);
        }
        Core.Response res = core.send("firewall", "/events/firewall/rules?site_id=" + core.siteId, "GET", null, Core.Auth.BEARER, extra);
        if (res != null && res.status == 200) {
            Object data = res.json();
            try {
                rules = compile(data);
                etag = res.headers.getOrDefault("etag", "");
                if (cacheFile != null) {
                    Map<String, Object> cached = new LinkedHashMap<>();
                    cached.put("etag", etag);
                    cached.put("rules", data);
                    Path target = Paths.get(cacheFile);
                    Path temp = Paths.get(cacheFile + ".tmp");
                    Files.write(temp, Json.write(cached).getBytes(StandardCharsets.UTF_8));
                    Files.move(temp, target, StandardCopyOption.REPLACE_EXISTING);
                }
            } catch (IOException | RuntimeException error) {
                core.log("firewall", "rules not used: " + error);
            }
        }
        Rules now = rules;
        return now != null ? now.sync : Core.RETRY;
    }

    private static double now() {
        return System.currentTimeMillis() / 1000.0;
    }

    /** A shared count seen over, noted under its key (window and all, so an old one never matches again). */
    private boolean noteOver(String name, boolean over) {
        if (over) {
            synchronized (lock) {
                if (!overNoted.containsKey(name)) {
                    room(overNoted);
                    overNoted.put(name, Boolean.TRUE);
                }
            }
        }
        return over;
    }

    private boolean noted(String name) {
        synchronized (lock) {
            return overNoted.containsKey(name);
        }
    }

    /**
     * After the response to a static file check() let through (its
     * decision's late hit): counted toward the rate and the page limits it
     * skipped when it answered 400 or more, or when the app routed it to a
     * controller after all (routed). Spring MVC before 5.3 reads
     * /search.css as /search (suffix pattern matching), and a route with a
     * variable takes /search/x.css: without this, a flood of those would
     * skip both. A real file the app serves itself counts only when missing.
     */
    public void countStatic(Decision decision, int status, boolean routed) {
        Late late = decision == null ? null : decision.late;
        Rules r = rules;
        if (late == null || r == null || (status < 400 && !routed)) {
            return;
        }
        if (late.rate && r.rate != null) {
            overRate(late.ip, r.rate, false);
        }
        if (late.limits && !r.limits.isEmpty()) {
            overLimits(r.limits, late.ip, late.method, late.path, late.userAgent, false, now(), false);
        }
    }

    /** Makes room for one more entry by dropping the oldest, rather than forgetting everyone. */
    private static void room(Map<String, ?> table) {
        if (table.size() >= COUNTER_MAX) {
            java.util.Iterator<String> oldest = table.keySet().iterator();
            oldest.next();
            oldest.remove();
        }
    }

    /** peek: only compared with the count so far, nothing added (a static file). */
    private boolean overRate(String ip, long[] rate, boolean peek) {
        String who = Ip.bucket(ip);
        if (who == null) {
            return false;
        }
        long window = (long) Math.floor(now() / rate[1]);
        if (counter != null) {
            String name = "afw:" + core.siteId + ":" + who + ":" + window;
            return peek ? noted(name) : noteOver(name, counter.hit(name, (int) (rate[1] * 2)) > rate[0]);
        }
        synchronized (lock) {
            long[] entry = counts.get(who);
            if (peek) {
                return entry != null && entry[0] == window && entry[1] > rate[0];
            }
            if (entry == null || entry[0] != window) {
                if (entry == null) {
                    room(counts);
                } else {
                    counts.remove(who);
                }
                entry = new long[] {window, 0};
                counts.put(who, entry);
            }
            entry[1] += 1;
            return entry[1] > rate[0];
        }
    }

    /**
     * Step 6: counts the request toward every page limit it matches, each in
     * its own fixed window. Returns the first limit now over its count that
     * blocks ([0]) and the first one over it that only watches ([1]); either
     * may be null. Nothing is banned: the cap lifts when the window ends.
     */
    private Limit[] overLimits(List<Limit> limits, String ip, String method, String path, String userAgent, boolean blockMode, double at,
            boolean peek) {
        Limit[] over = new Limit[2];
        String who = Ip.bucket(ip);
        if (who == null || limits.isEmpty()) {
            return over;
        }
        RequestRules.Prepared request = new RequestRules.Prepared(method, path, userAgent);
        for (Limit limit : limits) {
            if (!RequestRules.matches(limit.rule, request)) {
                continue;
            }
            long window = (long) Math.floor(at / limit.window);
            long hits;
            // A count per page stays on this server: in a shared counter it
            // would be one key per page per address.
            if (counter != null && !limit.eachPath) {
                String name = "afw:" + core.siteId + ":l:" + limit.rule.id + ":" + who + ":" + window;
                if (peek) {
                    hits = noted(name) ? limit.limit + 1 : 0;
                } else {
                    hits = counter.hit(name, (int) (limit.window * 2));
                    noteOver(name, hits > limit.limit);
                }
            } else {
                String name = limit.rule.id + "|" + who + (limit.eachPath ? "|" + request.routedPath : "");
                Map<String, long[]> table = limit.eachPath ? pathCounts : limitCounts;
                synchronized (lock) {
                    long[] entry = table.get(name);
                    if (peek) {
                        hits = entry != null && entry[0] == window ? entry[1] : 0;
                    } else {
                        if (entry == null || entry[0] != window) {
                            if (entry == null) {
                                room(table);
                            } else {
                                table.remove(name);
                            }
                            entry = new long[] {window, 0};
                            table.put(name, entry);
                        }
                        entry[1] += 1;
                        hits = entry[1];
                    }
                }
            }
            if (hits > limit.limit) {
                boolean blocks = blockMode && "block".equals(limit.rule.action);
                int slot = blocks ? 0 : 1;
                if (over[slot] == null) {
                    over[slot] = limit;
                }
            }
        }
        return over;
    }

    private boolean bannedHere(String ip) {
        String who = Ip.bucket(ip);
        synchronized (lock) {
            Double until = who == null ? null : bans.get(who);
            if (until == null) {
                return false;
            }
            if (until > now()) {
                return true;
            }
            bans.remove(who);
            return false;
        }
    }

    private void banHere(String ip, long seconds) {
        String who = Ip.bucket(ip);
        if (seconds > 0 && who != null) {
            synchronized (lock) {
                if (!bans.containsKey(who)) {
                    room(bans);
                }
                bans.merge(who, now() + seconds, Math::max);
            }
        }
    }

    /**
     * A failed login on your site: counted here (past the site's limit the
     * address is banned straight away) and reported, so it counts on the
     * Security page and gets banned on the other servers too.
     */
    public void loginFailed(String ip) {
        Ip.Key key = Ip.key(ip);
        Rules r = rules;
        if (key == null || (r != null && r.allow.has(key))) {
            return;
        }
        Map<String, Object> login = r == null ? null : r.login;
        if (login != null) {
            double at = now();
            boolean reached;
            String who = Ip.bucket(ip);
            synchronized (lock) {
                double[] entry = logins.get(who);
                long window = Json.whole(login.get("window"), 0);
                if (entry == null || at - entry[0] >= (window == 0 ? 3600 : window)) {
                    if (entry == null) {
                        room(logins);
                    } else {
                        logins.remove(who);
                    }
                    entry = new double[] {at, 0};
                    logins.put(who, entry);
                }
                entry[1] += 1;
                reached = entry[1] >= Json.whole(login.get("limit"), 0);
                if (reached) {
                    logins.remove(who);
                }
            }
            if (reached) {
                long ban = Json.whole(login.get("ban"), 0);
                banHere(ip, ban == 0 ? 3600 : ban);
            }
        }
        report(event(ip, "login", "monitor", "", "", ""));
    }

    private static Map<String, Object> event(String ip, String rule, String action, String method, String path, String userAgent) {
        Map<String, Object> event = new LinkedHashMap<>();
        event.put("ip", ip);
        event.put("rule", rule);
        event.put("action", action);
        event.put("method", cut(method, 10));
        String clean = path == null ? "" : path;
        int mark = clean.indexOf('?');
        event.put("path", cut(mark >= 0 ? clean.substring(0, mark) : clean, 300));
        event.put("user_agent", cut(userAgent, 300));
        return event;
    }

    private static String cut(String text, int max) {
        String value = text == null ? "" : text;
        return value.length() > max ? value.substring(0, max) : value;
    }

    private void report(Map<String, Object> event) {
        String key = event.get("ip") + "|" + event.get("rule") + "|" + event.get("action") + "|" + event.get("method") + "|" + event.get("path");
        synchronized (lock) {
            Map<String, Object> row = queue.get(key);
            if (row != null) {
                row.put("hits", ((Number) row.get("hits")).longValue() + 1);
            } else if (queue.size() < QUEUE_MAX) {
                event.put("at", Instant.now().toString());
                event.put("hits", 1L);
                queue.put(key, event);
            }
        }
    }

    /** The reports waiting (tests). */
    List<Map<String, Object>> waiting() {
        synchronized (lock) {
            return new ArrayList<>(queue.values());
        }
    }

    public void flush() {
        List<Map<String, Object>> rows;
        synchronized (lock) {
            rows = new ArrayList<>(queue.values());
            queue = new LinkedHashMap<>();
        }
        for (int i = 0; i < rows.size(); i += BATCH) {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("site_id", core.siteId);
            body.put("events", rows.subList(i, Math.min(rows.size(), i + BATCH)));
            core.postBearer("firewall", "/events/firewall/events", body);
        }
    }

    private double flushJob() {
        flush();
        return FLUSH_EVERY;
    }

    public Decision check(String ip, String method, String path, String userAgent, String accept, String cookie) {
        return check(ip, method, path, userAgent, accept, cookie, null, null);
    }

    /** As above; secFetchSite: the request's Sec-Fetch-Site header, or null. */
    public Decision check(String ip, String method, String path, String userAgent, String accept, String cookie, String secFetchSite) {
        return check(ip, method, path, userAgent, accept, cookie, secFetchSite, null);
    }

    Decision check(String ip, String method, String path, String userAgent, String accept, String cookie, Double nowSeconds) {
        return check(ip, method, path, userAgent, accept, cookie, null, nowSeconds);
    }

    /**
     * True when another site made the browser send the request (an img, a
     * no-cors fetch, a link): it comes from the visitor's own address, so it
     * may be refused but must never get that address banned.
     */
    static boolean fromAnotherSite(String secFetchSite) {
        String value = secFetchSite == null ? "" : secFetchSite.trim();
        return "cross-site".equalsIgnoreCase(value) || "same-site".equalsIgnoreCase(value);
    }

    /**
     * Allowed addresses skip every other rule. accept and cookie (the
     * request's headers) are for the browser check: rule "challenge", status
     * 503, answered with challengePage(). path: the request target, put in
     * origin form first.
     */
    Decision check(String ip, String method, String path, String userAgent, String accept, String cookie, String secFetchSite,
            Double nowSeconds) {
        Rules r = rules;
        if (r == null || !r.enabled) {
            return Decision.ALLOW;
        }
        path = RequestRules.originForm(path);
        boolean foreign = fromAnotherSite(secFetchSite);
        String action = "block".equals(mode != null ? mode : r.mode) ? "block" : "monitor";
        Ip.Key key = Ip.key(ip);
        if (key == null) {
            return withoutAddress(r, ip, method, path, userAgent, action, foreign);
        }
        if (r.allow.has(key)) {
            return Decision.ALLOW;
        }
        // What the report says: "monitor" when nobody may be banned for it.
        boolean spared = false;
        String rule = r.deny.has(key) ? "deny"
                : r.banned.has(key) || bannedHere(ip) ? "ban"
                : r.list.has(key) ? "list"
                : r.shared.has(key) ? "shared" : "";
        if (rule.isEmpty() && isProbe(path, r.probes)) {
            rule = "probe";
            spared = foreign;
            // Asking for a secret file: banned here in block mode; the report bans it on the other servers.
            if ("block".equals(action) && !foreign) {
                banHere(ip, r.probes.ban);
            }
        }
        if (rule.isEmpty()) {
            RequestRules.Rule matched = RequestRules.match(r.requests, method, path, userAgent);
            if (matched != null) {
                rule = "request:" + matched.id;
                spared = foreign;
                // A rule the dashboard only watches passes even in block mode;
                // one that blocks also bans the address here, as a flood does.
                action = "block".equals(action) && "block".equals(matched.action) ? "block" : "monitor";
                if ("block".equals(action) && matched.ban > 0 && !foreign) {
                    banHere(ip, matched.ban);
                }
            }
        }
        // Step 6, page limits. A limit only watched is reported and the check
        // goes on: watching the login page must not let a flood through it
        // untouched by the rate limit.
        Limit watched = null;
        long window = 0;
        // The app's own images, scripts and fonts come a dozen to a page: they'd
        // put a real visitor over the limits, and a flood asks for pages.
        // They are compared with the counts so far, not added to them, so an
        // address already over is turned away for its files too; counted
        // after the response if they turn out to be a page (countStatic).
        boolean asset = rule.isEmpty() && (!r.limits.isEmpty() || r.rate != null) && isStaticFile(path, method);
        boolean lateLimits = false;
        boolean lateRate = false;
        if (rule.isEmpty() && !r.limits.isEmpty() && !r.goodbots.has(key) && !r.limitsExempt.has(key)) {
            lateLimits = asset;
            Limit[] over = overLimits(r.limits, ip, method, path, userAgent, "block".equals(action),
                    nowSeconds != null ? nowSeconds : now(), asset);
            if (over[0] != null) {
                rule = "limit:" + over[0].rule.id;
                window = over[0].window;
            } else {
                watched = over[1];
            }
        }
        if (rule.isEmpty() && r.rate != null && !r.goodbots.has(key)) {
            lateRate = asset;
        }
        Late late = lateRate || lateLimits ? new Late(ip, method, path, userAgent, lateRate, lateLimits) : null;
        if (rule.isEmpty() && r.rate != null && !r.goodbots.has(key) && overRate(ip, r.rate, asset)) {
            rule = "rate";
            spared = foreign;
            // Banned here straight away in block mode, as a probe is.
            if ("block".equals(action) && !foreign) {
                banHere(ip, r.ban);
            }
        }
        // Not a mode matter: the collector only sends `challenge` when the site
        // is to be checked, and a match only watched gets it too (step 8).
        if ((rule.isEmpty() || !"block".equals(action)) && needsCheck(r, key, ip, method, path, accept, cookie, nowSeconds)) {
            if (!rule.isEmpty()) {
                report(event(ip, rule, action, method, path, userAgent));
            }
            rule = "challenge";
            action = "block";
        }
        if (watched != null) {
            report(event(ip, "limit:" + watched.rule.id, "monitor", method, path, userAgent));
            if (rule.isEmpty()) {
                // What it would have answered: 429, as a limit that blocks does.
                return new Decision("monitor", "limit:" + watched.rule.id, 429, watched.window, late);
            }
        }
        if (rule.isEmpty()) {
            return late == null ? Decision.ALLOW : new Decision("allow", "", 200, 0, late);
        }
        report(event(ip, rule, spared && !"challenge".equals(rule) ? "monitor" : action, method, path, userAgent));
        return new Decision(action, rule, "rate".equals(rule) || rule.startsWith("limit:") ? 429 : "challenge".equals(rule) ? 503 : 403, window,
                "block".equals(action) ? null : late);
    }

    /**
     * A request whose address doesn't parse (a custom trustProxy, or a
     * wrapper's getRemoteAddr(), gave text): no list, count or ban can name
     * it, but what it asks for is still checked. Passing it would let any
     * request past every rule.
     */
    private Decision withoutAddress(Rules r, String ip, String method, String path, String userAgent, String action, boolean foreign) {
        String rule = "";
        if (isProbe(path, r.probes)) {
            rule = "probe";
        } else {
            RequestRules.Rule matched = RequestRules.match(r.requests, method, path, userAgent);
            if (matched != null) {
                rule = "request:" + matched.id;
                action = "block".equals(action) && "block".equals(matched.action) ? "block" : "monitor";
            }
        }
        if (rule.isEmpty()) {
            return Decision.ALLOW;
        }
        report(event(ip, rule, foreign ? "monitor" : action, method, path, userAgent));
        return new Decision(action, rule, 403);
    }

    /**
     * Files a page load asks for by the dozen, matched on the lower-cased
     * path. The extension follows a name in the last segment, not starts it:
     * "/login/.css" is no file. {@code \z}, not {@code $}, which would let
     * "/a.css\n" end in .css.
     */
    private static final Pattern STATIC_FILE = Pattern.compile(
            "/[^/.][^/]*\\.(?:css|js|mjs|map|png|jpe?g|gif|webp|avif|svg|ico|bmp|woff2?|ttf|otf|eot|mp4|webm|ogg|mp3|wav|pdf|wasm)\\z");
    /** Frameworks' asset folders (firewall.md, `rate`). */
    private static final String[] STATIC_PREFIXES = {"/static/", "/_next/static/", "/assets/"};
    /**
     * In a path decoded once: a "%xx" still there (double encoding, which a
     * router that decodes again reads differently), a ";" (a path parameter
     * to Tomcat and Jetty, part of the name to others), a "\" (a "/" to
     * some), a "?" or "#" that was encoded, or a control character.
     */
    private static final Pattern STATIC_UNSURE = Pattern.compile("%[0-9a-fA-F]{2}|[;\\\\?#\\x00-\\x1f\\x7f]");

    /**
     * A file a page loads with itself, by its extension or its asset folder
     * (firewall.md, `rate`), read from the target as sent decoded once, lower
     * case, "//" as "/". Only a path every router reads the same way can be a
     * file: one with a "." or ".." segment, a ";", a "\", an encoded "/" or a
     * "%xx" left after decoding is a page, so "/static/../login",
     * "/static%2F..%2Flogin", "/login;x.css" and "/login%3Bx.css" all count
     * (sdk/protocols/static-cases.json). A browser asks for its files with
     * none of those. Nor is a path past the rules' 2,000 characters: cut
     * there, "/search/xxx…x.css/more" would end in .css and flood a catch-all
     * route past the limits. Query string and fragment left off.
     */
    static boolean isStaticFile(String target) {
        return isStaticFile(target, null);
    }

    /**
     * As {@link #isStaticFile(String)}, for a request with this method: only
     * GET and HEAD fetch a file. A form posts to a page, and Spring MVC before
     * 5.3 (suffix pattern matching) reads POST /login.css as /login. No method
     * given is read as GET.
     */
    static boolean isStaticFile(String target, String method) {
        if (target == null || !(method == null || method.isEmpty() || "GET".equals(method) || "HEAD".equals(method))) {
            return false;
        }
        String raw = target;
        for (char mark : new char[] {'?', '#'}) {
            int cut = raw.indexOf(mark);
            if (cut >= 0) {
                raw = raw.substring(0, cut);
            }
        }
        if (raw.length() > RequestRules.MAX_TEXT || !raw.startsWith("/") || raw.toLowerCase(Locale.ROOT).contains("%2f")) {
            return false;
        }
        String decoded = RequestRules.decodeOnce(raw);
        if (STATIC_UNSURE.matcher(decoded).find()) {
            return false;
        }
        String[] segments = asciiLower(decoded).split("/", -1);
        StringBuilder path = new StringBuilder();
        for (String segment : segments) {
            if (segment.equals(".") || segment.equals("..")) {
                return false;
            }
            if (!segment.isEmpty()) {
                path.append('/').append(segment);
            }
        }
        if (path.length() == 0) {
            return false;
        }
        if (segments[segments.length - 1].isEmpty()) {
            path.append('/'); // "/app.css/" isn't a file
        }
        String clean = path.toString();
        for (String prefix : STATIC_PREFIXES) {
            if (clean.startsWith(prefix)) {
                return true;
            }
        }
        return STATIC_FILE.matcher(clean).find();
    }

    /** A-Z as a-z, nothing else: every package lower-cases the same way ("İ" is "i" to some). */
    private static String asciiLower(String text) {
        StringBuilder out = new StringBuilder(text.length());
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            out.append(c >= 'A' && c <= 'Z' ? (char) (c + 32) : c);
        }
        return out.toString();
    }

    /**
     * The address rules alone (deny, ban, lists, shared), for the proxy's
     * addresses: a banned address gets no tracker and sends no visits, but
     * beacons don't count against the rate limit and never see the check.
     */
    Decision addressCheck(String ip, String method, String path, String userAgent) {
        Rules r = rules;
        Ip.Key key = Ip.key(ip);
        if (r == null || !r.enabled || key == null || r.allow.has(key)) {
            return Decision.ALLOW;
        }
        String rule = r.deny.has(key) ? "deny"
                : r.banned.has(key) || bannedHere(ip) ? "ban"
                : r.list.has(key) ? "list"
                : r.shared.has(key) ? "shared" : "";
        if (rule.isEmpty()) {
            return Decision.ALLOW;
        }
        String action = "block".equals(mode != null ? mode : r.mode) ? "block" : "monitor";
        report(event(ip, rule, action, method, path, userAgent));
        return new Decision(action, rule, 403);
    }

    /**
     * Step 8: the browser check is on, the request asks for a page outside
     * skip, the address is in none of allow, goodbots and exempt, and it has
     * no valid pass.
     */
    private boolean needsCheck(Rules r, Ip.Key key, String ip, String method, String path, String accept, String cookie, Double nowSeconds) {
        Check check = r.challenge;
        if (check == null || !Challenge.asksForPage(method, path, accept, check.skip)) {
            return false;
        }
        if (r.goodbots.has(key) || check.exempt.has(key)) {
            return false;
        }
        return !Challenge.hasPass(passKey, ip, cookie, nowSeconds);
    }

    /** The page for a request check() gave rule "challenge". */
    Reply challengePage(String ip, String method) {
        return Challenge.page(passKey, ip, method, null);
    }

    /** The Retry-After for a 429: a page limit's own window, else the rate limit's. */
    String retryAfter(Decision decision) {
        if (decision != null && decision.window > 0) {
            return String.valueOf(decision.window);
        }
        return retryAfter();
    }

    String retryAfter() {
        Rules r = rules;
        return r != null && r.rate != null ? String.valueOf(r.rate[1]) : "60";
    }

    /** The visitor's address, as trustProxy says. headers: names lower-case. */
    public String clientIp(String remote, Map<String, String> headers) {
        String connection = remote == null ? "" : Ip.withoutPort(remote);
        try {
            String ip = trustProxy.clientIp(connection, headers == null ? Collections.emptyMap() : headers);
            String clean = ip == null ? "" : Ip.withoutPort(ip);
            // What a custom function or a proxy gave that isn't an address would let
            // the request past every rule: the connection's address stands instead.
            return Ip.key(clean) != null ? clean : connection;
        } catch (RuntimeException error) {
            return connection;
        }
    }

    void close() {
        for (Periodic job : jobs) {
            job.stop(core.stopWait());
        }
        flush();
    }
}
