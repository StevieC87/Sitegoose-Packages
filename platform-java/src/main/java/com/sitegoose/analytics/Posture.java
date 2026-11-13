package com.sitegoose.analytics;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.BasicFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Deque;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.regex.Pattern;

/**
 * How the server is set up (sdk/protocols/posture.md): the settings that
 * leave the app open (Spring Boot's, when it's a Spring Boot app), whether it
 * runs as root, code anyone on the machine can write, and files in the
 * folders it serves to the web that should never be public. Sent to POST
 * /events/posture a few minutes after start and then once a day.
 *
 * <p>It only reads: nothing here changes a setting, a permission or a file,
 * and no file's contents are sent -- paths, sizes, times and short values
 * only. The walk is bounded and runs in a background thread; with no folder
 * served to the web, only the settings are reported.
 */
final class Posture {
    static final double FIRST = 180;
    static final double RETRY_EVERY = 60 * 60;
    static final double EVERY = 24 * 60 * 60;
    static final int MAX_CHECKS = 200;
    static final int MAX_EXPOSURE = 50;
    static final int MAX_ENTRIES = 20000;
    static final int MAX_DEPTH = 6;
    static final int MAX_PERM_CHECKS = 3000;
    static final Set<String> SKIP_DIRS = new HashSet<>(Arrays.asList(".git", ".svn", ".hg", "node_modules", "vendor", "cache",
            ".cache", ".history", "__pycache__"));
    static final Set<String> VCS = new HashSet<>(Arrays.asList(".git", ".svn", ".hg", ".bzr"));
    static final Pattern CODE_FILE = Pattern.compile("\\.(py|pyw|js|cjs|mjs|php[0-9]?|phtml|rb|pl|sh|jsp|jspx|class|jar|war)$",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern CHECK_ID = Pattern.compile("[a-z][a-z0-9_.]*");
    /** Files that shouldn't be downloadable, by name; first match wins. */
    static final Object[][] EXPOSURE = {
        {"database_dump", Pattern.compile("\\.sql(\\.(gz|bz2|xz|zip))?$", Pattern.CASE_INSENSITIVE)},
        {"private_key", Pattern.compile("^(id_rsa|id_dsa|id_ecdsa|id_ed25519)$|\\.(pem|key|p12|pfx|jks)$", Pattern.CASE_INSENSITIVE)},
        {"env", Pattern.compile("^\\.env($|\\.)|^env\\.(ini|txt)$", Pattern.CASE_INSENSITIVE)},
        {"archive", Pattern.compile("\\.(zip|tar|tgz|tar\\.gz|tar\\.bz2|rar|7z)$", Pattern.CASE_INSENSITIVE)},
        {"backup", Pattern.compile("\\.(bak|old|orig|save|swp|copy|backup)$|~$|\\.(py|json|conf|config|ini|ya?ml|properties|xml)\\.(bak|old|orig|save|txt)$",
                Pattern.CASE_INSENSITIVE)},
        {"info", Pattern.compile("^(phpinfo|info|adminer)\\.php$", Pattern.CASE_INSENSITIVE)},
        {"log", Pattern.compile("^(debug|error|access)[-_.]?log$|\\.log$", Pattern.CASE_INSENSITIVE)},
    };

    /** A folder the web serves: on disk, or inside a jar (entries under a prefix). */
    static final class Root {
        final Path dir;
        final Path jar;
        final String entryPrefix;
        final String prefix;

        private Root(Path dir, Path jar, String entryPrefix, String prefix) {
            this.dir = dir;
            this.jar = jar;
            this.entryPrefix = entryPrefix;
            this.prefix = prefix == null ? "" : prefix.replaceAll("^/+|/+$", "");
        }

        static Root dir(String dir, String prefix) {
            return new Root(Paths.get(dir).toAbsolutePath().normalize(), null, null, prefix);
        }

        static Root jar(Path jar, String entryPrefix, String prefix) {
            String inside = entryPrefix.replaceAll("^/+", "");
            return new Root(null, jar, inside.isEmpty() || inside.endsWith("/") ? inside : inside + "/", prefix);
        }

        String id() {
            return dir != null ? dir.toString() : jar + "!/" + entryPrefix;
        }
    }

    static String kindOf(String name) {
        for (Object[] rule : EXPOSURE) {
            if (((Pattern) rule[1]).matcher(name).find()) {
                return (String) rule[0];
            }
        }
        return null;
    }

    /** A folder inside another folder on the list is already covered. */
    static List<Root> withoutNested(List<Root> roots) {
        Map<String, Root> unique = new LinkedHashMap<>();
        for (Root root : roots) {
            unique.putIfAbsent(root.id(), root);
        }
        List<Root> out = new ArrayList<>();
        for (Root root : unique.values()) {
            boolean nested = false;
            for (Root other : unique.values()) {
                if (other != root && (root.id() + "/").startsWith(other.id() + "/")) {
                    nested = true;
                }
            }
            if (!nested) {
                out.add(root);
            }
        }
        return out;
    }

    private final Core core;
    final String host;
    private volatile List<Root> roots;
    private final boolean rootsGiven;
    private final Supplier<List<Map<String, Object>>> extra;
    private volatile Supplier<List<Map<String, Object>>> frameworkChecks;
    private final Periodic job;

    Posture(Core core, PlatformOptions.PostureOptions options, String serverName) {
        this.core = core;
        List<Root> given = new ArrayList<>();
        if (options != null) {
            for (Object root : options.roots) {
                if (root instanceof String && !((String) root).isEmpty()) {
                    given.add(Root.dir((String) root, ""));
                } else if (root instanceof String[] && ((String[]) root).length >= 1) {
                    String[] pair = (String[]) root;
                    given.add(Root.dir(pair[0], pair.length > 1 ? pair[1] : ""));
                }
            }
        }
        this.roots = withoutNested(given);
        this.rootsGiven = !given.isEmpty();
        this.extra = options == null ? null : options.checks;
        String name = options != null && options.host != null ? options.host : serverName;
        this.host = Hosts.hostField(name);
        this.job = core.valid ? core.every(this::report, FIRST) : null;
    }

    /** The folders an integration knows the app serves, used when the options named none. */
    void defaultRoots(List<Root> found) {
        if (!rootsGiven && found != null && !found.isEmpty()) {
            List<Root> all = new ArrayList<>(roots);
            all.addAll(found);
            roots = withoutNested(all);
        }
    }

    /** Checks the framework integration knows how to make (Spring Boot's settings). */
    void frameworkChecks(Supplier<List<Map<String, Object>>> checks) {
        this.frameworkChecks = checks;
    }

    List<Root> roots() {
        return roots;
    }

    /** The real user id from /proc/self/status, or -1 where there is none. */
    static long uid() {
        try {
            for (String line : Files.readAllLines(Paths.get("/proc/self/status"))) {
                if (line.startsWith("Uid:")) {
                    return Long.parseLong(line.substring(4).trim().split("\\s+")[0]);
                }
            }
        } catch (Exception unreadable) {
            // not Linux
        }
        return -1;
    }

    static final class Walk {
        final List<Map<String, Object>> exposure = new ArrayList<>();
        final List<String> examples = new ArrayList<>();
        final Set<String> vcs = new HashSet<>();
        int writable;
        int checked;
        int entries;
        boolean truncated;
    }

    private static String join(String prefix, String relative) {
        return prefix.isEmpty() ? relative : relative.isEmpty() ? prefix : prefix + "/" + relative;
    }

    private static void expose(Walk walk, String path, String kind, Long size, Instant mtime) {
        if (walk.exposure.size() >= MAX_EXPOSURE) {
            return;
        }
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("path", path);
        row.put("kind", kind);
        if (size != null) {
            row.put("size", size);
        }
        if (mtime != null) {
            row.put("mtime", mtime.toString());
        }
        walk.exposure.add(row);
    }

    /** One bounded walk over every root. */
    static Walk walk(List<Root> roots) {
        Walk walk = new Walk();
        for (Root root : roots) {
            if (walk.truncated) {
                break;
            }
            if (root.jar != null) {
                walkJar(root, walk);
            } else {
                walkDir(root, walk);
            }
        }
        return walk;
    }

    private static void walkDir(Root root, Walk walk) {
        Deque<Object[]> queue = new ArrayDeque<>();
        queue.add(new Object[] {root.dir, 0});
        while (!queue.isEmpty()) {
            Object[] next = queue.poll();
            Path folder = (Path) next[0];
            int depth = (Integer) next[1];
            List<Path> names = new ArrayList<>();
            try (DirectoryStream<Path> listing = Files.newDirectoryStream(folder)) {
                for (Path path : listing) {
                    names.add(path);
                }
            } catch (IOException | RuntimeException unreadable) {
                continue;
            }
            for (Path path : names) {
                walk.entries += 1;
                if (walk.entries > MAX_ENTRIES) {
                    walk.truncated = true;
                    return;
                }
                String name = path.getFileName().toString();
                BasicFileAttributes info;
                try {
                    info = Files.readAttributes(path, BasicFileAttributes.class, LinkOption.NOFOLLOW_LINKS);
                } catch (IOException | RuntimeException gone) {
                    continue;
                }
                if (info.isSymbolicLink()) {
                    continue;
                }
                String relative = join(root.prefix, root.dir.relativize(path).toString().replace('\\', '/'));
                if (info.isDirectory()) {
                    if (VCS.contains(name)) {
                        expose(walk, relative + "/config", "vcs", null, null);
                        continue;
                    }
                    // A servlet container never serves WEB-INF/ or META-INF/ at the web app's root.
                    if (depth == 0 && root.prefix.isEmpty() && ("WEB-INF".equalsIgnoreCase(name) || "META-INF".equalsIgnoreCase(name))) {
                        continue;
                    }
                    if (depth + 1 <= MAX_DEPTH && !SKIP_DIRS.contains(name)) {
                        queue.add(new Object[] {path, depth + 1});
                    }
                    continue;
                }
                if (!info.isRegularFile()) {
                    continue;
                }
                String kind = kindOf(name);
                if (kind != null) {
                    expose(walk, relative, kind, info.size(), info.lastModifiedTime().toInstant());
                }
                if (walk.checked < MAX_PERM_CHECKS && CODE_FILE.matcher(name).find()) {
                    try {
                        Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS);
                        walk.checked += 1;
                        if (permissions.contains(PosixFilePermission.OTHERS_WRITE)) {
                            walk.writable += 1;
                            if (walk.examples.size() < 3) {
                                walk.examples.add(relative);
                            }
                        }
                    } catch (IOException | UnsupportedOperationException noPermissions) {
                        // not a POSIX file system: not checked
                    }
                }
            }
        }
    }

    /** A folder inside a jar (Spring Boot's classpath:/static/): names, sizes and times; no permissions there. */
    private static void walkJar(Root root, Walk walk) {
        try (JarFile jar = new JarFile(root.jar.toFile(), false)) {
            Enumeration<JarEntry> entries = jar.entries();
            while (entries.hasMoreElements()) {
                JarEntry entry = entries.nextElement();
                String name = entry.getName();
                if (!name.startsWith(root.entryPrefix)) {
                    continue;
                }
                String relative = name.substring(root.entryPrefix.length());
                if (relative.isEmpty()) {
                    continue;
                }
                walk.entries += 1;
                if (walk.entries > MAX_ENTRIES) {
                    walk.truncated = true;
                    return;
                }
                String[] parts = relative.split("/");
                if (parts.length > MAX_DEPTH + 1) {
                    continue;
                }
                boolean skipped = false;
                int folders = entry.isDirectory() ? parts.length : parts.length - 1;
                for (int i = 0; i < folders; i++) {
                    if (VCS.contains(parts[i])) {
                        String folder = join(root.prefix, String.join("/", Arrays.copyOf(parts, i + 1)));
                        if (walk.vcs.add(folder)) {
                            expose(walk, folder + "/config", "vcs", null, null);
                        }
                        skipped = true;
                        break;
                    }
                    if (SKIP_DIRS.contains(parts[i])) {
                        skipped = true;
                        break;
                    }
                }
                if (skipped || entry.isDirectory()) {
                    continue;
                }
                String kind = kindOf(parts[parts.length - 1]);
                if (kind != null) {
                    expose(walk, join(root.prefix, relative), kind, entry.getSize() >= 0 ? entry.getSize() : null,
                            entry.getTime() > 0 ? Instant.ofEpochMilli(entry.getTime()) : null);
                }
            }
        } catch (IOException | RuntimeException unreadable) {
            // nothing walked
        }
    }

    static Map<String, Object> check(String id, String state, String value) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("id", id);
        row.put("state", state);
        if (value != null && !value.isEmpty()) {
            row.put("value", value.length() > 200 ? value.substring(0, 200) : value);
        }
        return row;
    }

    private static void addChecks(List<Map<String, Object>> checks, Supplier<List<Map<String, Object>>> source) {
        if (source == null) {
            return;
        }
        try {
            List<Map<String, Object>> given = source.get();
            for (Map<String, Object> item : given == null ? Collections.<Map<String, Object>>emptyList() : given) {
                Object id = item == null ? null : item.get("id");
                Object state = item == null ? null : item.get("state");
                if (id == null || !Arrays.asList("pass", "fail", "unknown").contains(state)) {
                    continue;
                }
                String clean = String.valueOf(id).toLowerCase();
                if (clean.length() > 60) {
                    clean = clean.substring(0, 60);
                }
                if (!CHECK_ID.matcher(clean).matches()) {
                    continue;
                }
                Object value = item.get("value");
                checks.add(check(clean, (String) state, value == null ? null : String.valueOf(value)));
            }
        } catch (RuntimeException failed) {
            // fail quiet: a check that errors is left out
        }
    }

    /** What would be reported now (also used by the job and by tests). */
    Map<String, Object> body() {
        List<Root> current = roots;
        Walk walk = walk(current);
        List<Map<String, Object>> checks = new ArrayList<>();
        addChecks(checks, frameworkChecks);
        long uid = uid();
        if (uid >= 0) {
            // Running the web app as root turns any hole in it into the whole machine.
            checks.add(check("server.runs_as_root", uid == 0 ? "fail" : "pass", null));
        }
        if (walk.checked > 0) {
            checks.add(check("server.code_writable", walk.writable > 0 ? "fail" : "pass",
                    walk.writable > 0 ? walk.writable + " files, e.g. " + String.join(", ", walk.examples) : null));
        }
        addChecks(checks, extra);
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("site_id", core.siteId);
        body.put("host", host);
        body.put("at", Instant.now().toString());
        body.put("checks", checks.size() > MAX_CHECKS ? checks.subList(0, MAX_CHECKS) : checks);
        Map<String, Object> facts = new LinkedHashMap<>();
        facts.put("agent", "java/" + System.getProperty("java.version", ""));
        body.put("facts", facts);
        if (!current.isEmpty()) {
            // Left out when there's no folder to walk: the dashboard then says
            // this wasn't checked, instead of taking an empty walk for a clean one.
            body.put("exposure", walk.exposure);
            String webroot = current.get(0).id();
            facts.put("webroot", webroot.length() > 100 ? webroot.substring(webroot.length() - 100) : webroot);
        }
        if (walk.truncated) {
            body.put("truncated", true);
        }
        return body;
    }

    double report() {
        // The set-up checks ride the software inventory switch.
        if (!core.isOn("inventory")) {
            return RETRY_EVERY;
        }
        Core.Response res = core.postBearer("posture", "/events/posture", body());
        if (res == null || !res.ok()) {
            return RETRY_EVERY;
        }
        Map<String, Object> answer = Json.map(res.json());
        long every = answer == null ? 0 : Json.whole(answer.get("every"), 0);
        return Math.max(RETRY_EVERY, every > 0 ? every : EVERY);
    }

    void close() {
        if (job != null) {
            job.stop(core.stopWait());
        }
    }
}
