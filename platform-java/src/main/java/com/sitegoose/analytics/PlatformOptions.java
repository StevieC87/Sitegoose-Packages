package com.sitegoose.analytics;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.function.BiFunction;
import java.util.function.Consumer;
import java.util.function.Predicate;
import java.util.function.Supplier;

/**
 * The platform's options, with the same names and defaults as the Python and
 * Node packages (camelCase). Every module is on by default; turn one off with
 * {@code options.analytics(false)}, or change its options with
 * {@code options.firewall(f -> f.mode("monitor"))}.
 *
 * <pre>{@code
 * Platform platform = Platform.create(new PlatformOptions()
 *     .siteId("YOUR_SITE_ID")
 *     .secret(System.getenv("ANALYTICS_SITE_SECRET"))
 *     .endpoint("https://YOUR_COLLECTOR_URL")
 *     .trustProxy(TrustProxy.hops(1)));
 * }</pre>
 */
public final class PlatformOptions {
    String siteId;
    String secret;
    String endpoint;
    TrustProxy trustProxy;
    String serverName;
    boolean debug;
    boolean shutdownHook = true;
    boolean queries = true;
    boolean calls = true;

    final FirewallOptions firewall = new FirewallOptions();
    final ErrorsOptions errors = new ErrorsOptions();
    final Module analytics = new Module();
    final ServerNameOptions performance = new ServerNameOptions();
    final ServerNameOptions crawlers = new ServerNameOptions();
    final Module forms = new Module();
    final Module headers = new Module();
    final Module audit = new Module();
    final Module flags = new Module();
    final MaintenanceOptions maintenance = new MaintenanceOptions();
    final InventoryOptions inventory = new InventoryOptions();
    final PostureOptions posture = new PostureOptions();
    final ServerNameOptions resources = new ServerNameOptions();
    final ProxyOptions proxy = new ProxyOptions();

    /** The site's ID (site settings). */
    public PlatformOptions siteId(String value) {
        siteId = value;
        return this;
    }

    /** The site secret (site settings). Keep it on the server. */
    public PlatformOptions secret(String value) {
        secret = value;
        return this;
    }

    /** The collector's URL. */
    public PlatformOptions endpoint(String value) {
        endpoint = value;
        return this;
    }

    /** How to find the visitor's address (default: the connection's). */
    public PlatformOptions trustProxy(TrustProxy value) {
        trustProxy = value;
        return this;
    }

    /** As configuration text: "1", "2", "true", "cloudflare". */
    public PlatformOptions trustProxy(String value) {
        trustProxy = TrustProxy.parse(value);
        return this;
    }

    /** Names this service (backend, worker...) on its errors, timings, resources, packages and setup. Default: the host name. */
    public PlatformOptions serverName(String value) {
        serverName = value;
        return this;
    }

    /** Logs send problems. */
    public PlatformOptions debug(boolean value) {
        debug = value;
        return this;
    }

    /** Flushes and stops at JVM exit (default true). Spring closes the platform itself. */
    public PlatformOptions shutdownHook(boolean value) {
        shutdownHook = value;
        return this;
    }

    /** A module's on/off switch. */
    public static class Module {
        boolean enabled = true;

        @SuppressWarnings("unchecked")
        public <T extends Module> T enabled(boolean value) {
            enabled = value;
            return (T) this;
        }

        public boolean enabled() {
            return enabled;
        }
    }

    public static final class FirewallOptions extends Module {
        String mode;
        Firewall.Counter counter;
        String cacheFile;
        TrustProxy trustProxy;

        /** "monitor" or "block": overrides the dashboard. */
        public FirewallOptions mode(String value) {
            mode = value;
            return this;
        }

        /** One rate-limit count across instances (Redis INCR + EXPIRE): hits for a key that expires after ttl seconds. */
        public FirewallOptions counter(Firewall.Counter value) {
            counter = value;
            return this;
        }

        /** Keeps the last rules on disk, so they apply straight after a restart. */
        public FirewallOptions cacheFile(String value) {
            cacheFile = value;
            return this;
        }

        /** Overrides the platform's trustProxy. */
        public FirewallOptions trustProxy(TrustProxy value) {
            trustProxy = value;
            return this;
        }
    }

    public static final class ErrorsOptions extends Module {
        String serverName;
        String release;
        boolean captureUncaught = true;
        boolean captureLogging;
        String spoolDir;
        boolean noSpool;
        BiFunction<Map<String, Object>, Throwable, Map<String, Object>> beforeSend;

        /** Default: the platform's serverName, else the host name. */
        public ErrorsOptions serverName(String value) {
            serverName = value;
            return this;
        }

        /** Which build this is (default: the ANALYTICS_RELEASE environment variable). */
        public ErrorsOptions release(String value) {
            release = value;
            return this;
        }

        /** Uncaught exceptions on any thread (default true). */
        public ErrorsOptions captureUncaught(boolean value) {
            captureUncaught = value;
            return this;
        }

        /**
         * Exceptions logged at SEVERE through java.util.logging are sent too
         * (default false). Logback: the Spring starter's analytics.errors.capture-logging,
         * or {@code com.sitegoose.analytics.logback.PlatformAppender}.
         */
        public ErrorsOptions captureLogging(boolean value) {
            captureLogging = value;
            return this;
        }

        /** Where errors that couldn't be sent wait (default: java.io.tmpdir). */
        public ErrorsOptions spoolDir(String value) {
            spoolDir = value;
            return this;
        }

        /** No file of waiting errors at all (Python's spool_dir=False). */
        public ErrorsOptions noSpool() {
            noSpool = true;
            return this;
        }

        /** Change an error before it's sent, or return null to drop it. */
        public ErrorsOptions beforeSend(BiFunction<Map<String, Object>, Throwable, Map<String, Object>> value) {
            beforeSend = value;
            return this;
        }
    }

    public static final class ServerNameOptions extends Module {
        String serverName;

        public ServerNameOptions serverName(String value) {
            serverName = value;
            return this;
        }
    }

    public static final class MaintenanceOptions extends Module {
        Predicate<String> skip;

        /** skip.test(path) true lets a request through (health checks). */
        public MaintenanceOptions skip(Predicate<String> value) {
            skip = value;
            return this;
        }
    }

    public static final class InventoryOptions extends Module {
        String host;
        String sbom;

        /** The server's name (default: serverName, else the host name). */
        public InventoryOptions host(String value) {
            host = value;
            return this;
        }

        /** A CycloneDX SBOM (JSON) to read the libraries from, instead of the classpath. */
        public InventoryOptions sbom(String path) {
            sbom = path;
            return this;
        }
    }

    public static final class PostureOptions extends Module {
        final List<Object> roots = new ArrayList<>();
        String host;
        Supplier<List<Map<String, Object>>> checks;

        /** A folder the web serves, reported at the site's root. */
        public PostureOptions root(String dir) {
            roots.add(dir);
            return this;
        }

        /** A folder the web serves under a prefix ("static"), so paths are reported as the web serves them. */
        public PostureOptions root(String dir, String prefix) {
            roots.add(new String[] {dir, prefix});
            return this;
        }

        public PostureOptions host(String value) {
            host = value;
            return this;
        }

        /** Checks of your own: maps of id, state ("pass", "fail", "unknown") and value. */
        public PostureOptions checks(Supplier<List<Map<String, Object>>> value) {
            checks = value;
            return this;
        }
    }

    public static final class ProxyOptions extends Module {
        String prefix;

        /** The path it answers on (default: eight characters from the secret). */
        public ProxyOptions prefix(String value) {
            prefix = value;
            return this;
        }
    }

    // ---- Per module: on, off, or its options ----

    public PlatformOptions firewall(boolean on) {
        firewall.enabled = on;
        return this;
    }

    public PlatformOptions firewall(Consumer<FirewallOptions> change) {
        change.accept(firewall);
        return this;
    }

    public PlatformOptions errors(boolean on) {
        errors.enabled = on;
        return this;
    }

    public PlatformOptions errors(Consumer<ErrorsOptions> change) {
        change.accept(errors);
        return this;
    }

    public PlatformOptions analytics(boolean on) {
        analytics.enabled = on;
        return this;
    }

    public PlatformOptions performance(boolean on) {
        performance.enabled = on;
        return this;
    }

    public PlatformOptions performance(Consumer<ServerNameOptions> change) {
        change.accept(performance);
        return this;
    }

    /**
     * Database query timings (Server speed -> Queries), on with the
     * performance module by default; false keeps Server speed and leaves
     * queries out (wrap(), mongoListener() and redisListener() then time nothing).
     */
    public PlatformOptions queries(boolean on) {
        queries = on;
        return this;
    }

    /**
     * Outgoing HTTP call timings (Server speed -> Calls), on with the
     * performance module by default; false keeps Server speed and leaves
     * calls out (the hooks then add only the error trail's steps).
     */
    public PlatformOptions calls(boolean on) {
        calls = on;
        return this;
    }

    public PlatformOptions crawlers(boolean on) {
        crawlers.enabled = on;
        return this;
    }

    public PlatformOptions crawlers(Consumer<ServerNameOptions> change) {
        change.accept(crawlers);
        return this;
    }

    public PlatformOptions forms(boolean on) {
        forms.enabled = on;
        return this;
    }

    public PlatformOptions headers(boolean on) {
        headers.enabled = on;
        return this;
    }

    public PlatformOptions audit(boolean on) {
        audit.enabled = on;
        return this;
    }

    public PlatformOptions flags(boolean on) {
        flags.enabled = on;
        return this;
    }

    public PlatformOptions maintenance(boolean on) {
        maintenance.enabled = on;
        return this;
    }

    public PlatformOptions maintenance(Consumer<MaintenanceOptions> change) {
        change.accept(maintenance);
        return this;
    }

    public PlatformOptions inventory(boolean on) {
        inventory.enabled = on;
        return this;
    }

    public PlatformOptions inventory(Consumer<InventoryOptions> change) {
        change.accept(inventory);
        return this;
    }

    public PlatformOptions posture(boolean on) {
        posture.enabled = on;
        return this;
    }

    public PlatformOptions posture(Consumer<PostureOptions> change) {
        change.accept(posture);
        return this;
    }

    public PlatformOptions resources(boolean on) {
        resources.enabled = on;
        return this;
    }

    public PlatformOptions resources(Consumer<ServerNameOptions> change) {
        change.accept(resources);
        return this;
    }

    public PlatformOptions proxy(boolean on) {
        proxy.enabled = on;
        return this;
    }

    public PlatformOptions proxy(Consumer<ProxyOptions> change) {
        change.accept(proxy);
        return this;
    }

    /** Every module off: a starting point for turning on only some. */
    public PlatformOptions allOff() {
        for (Module module : new Module[] {firewall, errors, analytics, performance, crawlers, forms, headers, audit, flags,
            maintenance, inventory, posture, resources, proxy}) {
            module.enabled = false;
        }
        return this;
    }
}
