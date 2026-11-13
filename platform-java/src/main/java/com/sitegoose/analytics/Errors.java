package com.sitegoose.analytics;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.WeakHashMap;
import java.util.function.BiFunction;
import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;
import java.util.logging.Logger;

/**
 * Error monitoring module: the server's errors go to the collector (POST
 * /events/server-errors), where they join the browser's errors in the Errors
 * report. Uncaught exceptions (on any thread) are captured on their own and
 * the JVM still prints them as it would. The servlet filters capture request
 * errors (5xx); captureException() captures errors you catch; captureLogging
 * sends the exceptions your code logs. An error is sent once however many of
 * those see it. Errors are sent in small batches, a batch the collector
 * couldn't take is tried once more, and sending never throws. What still
 * can't be sent waits in a file and is sent once it can be, after a restart
 * too; each error carries when it happened, and the trail of its request or
 * job: the steps added with addBreadcrumb().
 */
final class Errors {
    static final int BATCH = 10;
    static final int QUEUE_MAX = 100;
    static final double FLUSH_EVERY = 2;
    /** A batch the collector couldn't take (unreachable, 429, 5xx) is sent once more after this. */
    static final long RETRY_AFTER_MS = 2000;
    static final double RESEND_EVERY = 60;
    static final long SPOOL_BYTES = 1024 * 1024;
    /** The collector keeps 4,000 characters of a stack and finds the frame in them. */
    static final int STACK_MAX = 4000;
    static final int FRAMES_PER_CAUSE = 40;

    private final Core core;
    final String serverName;
    final String release;
    private final BiFunction<Map<String, Object>, Throwable, Map<String, Object>> beforeSend;
    private final Object lock = new Object();
    private final Object resendLock = new Object();
    private List<Map<String, Object>> queue = new ArrayList<>();
    // The framework, your handler and logging can all see one error: sent once.
    private final Map<Throwable, Map<String, Object>> seen = Collections.synchronizedMap(new WeakHashMap<>());
    final Path spoolFile;
    private volatile double lastResend;
    private final Periodic job;
    private Thread.UncaughtExceptionHandler previous;
    private Thread.UncaughtExceptionHandler installed;
    private Handler logHandler;

    Errors(Core core, PlatformOptions.ErrorsOptions options, String serverName) {
        this.core = core;
        PlatformOptions.ErrorsOptions o = options == null ? new PlatformOptions.ErrorsOptions() : options;
        String name = o.serverName != null && !o.serverName.isEmpty() ? o.serverName
                : serverName != null && !serverName.isEmpty() ? serverName : Hosts.hostName();
        this.serverName = name.length() > 100 ? name.substring(0, 100) : name;
        // Which build this is, for "introduced in" in the Errors report.
        String given = o.release != null ? o.release : System.getenv("ANALYTICS_RELEASE");
        String clean = (given == null ? "" : given.trim()).replaceAll("[^\\w.+\\-]", "");
        this.release = clean.length() > 64 ? clean.substring(0, 64) : clean;
        this.beforeSend = o.beforeSend;
        // Named after the site and its secret, not the site id alone, so the
        // folder's listing tells nobody which site it is.
        Path spool = null;
        if (!o.noSpool && core.valid) {
            String dir = o.spoolDir != null ? o.spoolDir : System.getProperty("java.io.tmpdir");
            spool = Paths.get(dir, "analytics-errors-" + sha256(core.siteId + "|" + core.secret).substring(0, 16) + ".jsonl");
        }
        this.spoolFile = spool;
        this.job = core.valid ? core.every(this::flushJob, FLUSH_EVERY) : null;
        // The JVM's default handler is one for every app in it: inside a
        // container that runs several (a war in Tomcat, WildFly), it isn't
        // this app's to take, and it would keep the app's classes loaded after
        // an undeploy. There, uncaught errors of the app's own threads are
        // still reported through the filter.
        if (o.captureUncaught && !sharedContainer(Errors.class.getClassLoader())) {
            previous = Thread.getDefaultUncaughtExceptionHandler();
            installed = this::uncaught;
            Thread.setDefaultUncaughtExceptionHandler(installed);
        }
        if (o.captureLogging) {
            logHandler = new LogHandler(this);
            Logger.getLogger("").addHandler(logHandler);
        }
    }

    /** True when the class loader is a web app's inside a container that runs several. */
    static boolean sharedContainer(ClassLoader loader) {
        for (ClassLoader l = loader; l != null; l = l.getParent()) {
            String name = l.getClass().getName();
            if (name.contains("WebappClassLoader") || name.contains("WebAppClassLoader")
                    || name.startsWith("org.jboss.modules.") || name.startsWith("com.ibm.ws.classloading.")
                    || name.startsWith("weblogic.utils.classloaders.") || name.startsWith("org.glassfish.web.loader.")) {
                return true;
            }
        }
        return false;
    }

    static String sha256(String text) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8));
            StringBuilder out = new StringBuilder();
            for (byte b : digest) {
                out.append(String.format(Locale.ROOT, "%02x", b & 0xFF));
            }
            return out.toString();
        } catch (Exception error) {
            throw new IllegalStateException(error);
        }
    }

    private void uncaught(Thread thread, Throwable error) {
        // Closed, but someone put their handler after ours: pass it on and nothing more.
        if (installed == null) {
            if (previous != null) {
                previous.uncaughtException(thread, error);
            } else {
                System.err.print("Exception in thread \"" + thread.getName() + "\" ");
                error.printStackTrace(System.err);
            }
            return;
        }
        try {
            capture(error, null, 0, "error");
            // The file waits for the next start rather than delaying the exit.
            flush(false);
        } catch (Throwable ignored) {
            // never in the way of the JVM's own handling
        }
        if (previous != null) {
            previous.uncaughtException(thread, error);
        } else if (!(error instanceof ThreadDeath)) {
            System.err.print("Exception in thread \"" + thread.getName() + "\" ");
            error.printStackTrace(System.err);
        }
    }

    /**
     * Sends the exception of a java.util.logging record at SEVERE (logger.log(SEVERE, "...", error)).
     * A record without an exception isn't sent: it has no stack to group it by.
     */
    static final class LogHandler extends Handler {
        private final Errors errors;

        LogHandler(Errors errors) {
            this.errors = errors;
            setLevel(Level.SEVERE);
        }

        @Override
        public void publish(LogRecord record) {
            if (record == null || record.getThrown() == null || record.getLevel().intValue() < Level.SEVERE.intValue()) {
                return;
            }
            String name = record.getLoggerName();
            if (name != null && name.startsWith("com.sitegoose.analytics")) {
                return;
            }
            errors.capture(record.getThrown(), null, 0, "logged");
        }

        @Override
        public void flush() {
        }

        @Override
        public void close() {
        }
    }

    /** The stack as Java prints it, each cause's frames capped, at most STACK_MAX characters, cut on a line. */
    static String stackOf(Throwable error) {
        StringBuilder out = new StringBuilder();
        Set<Throwable> done = Collections.newSetFromMap(new IdentityHashMap<>());
        Throwable current = error;
        StackTraceElement[] enclosing = null;
        boolean first = true;
        // Each cause gets its share of the frames, so the root cause (often
        // the one that says what went wrong) is never cut off by the wrappers.
        int causes = 0;
        Set<Throwable> counted = Collections.newSetFromMap(new IdentityHashMap<>());
        for (Throwable c = error; c != null && counted.add(c) && causes < 10; c = c.getCause()) {
            causes++;
        }
        int perCause = causes <= 1 ? FRAMES_PER_CAUSE : Math.max(8, FRAMES_PER_CAUSE / causes);
        while (current != null && done.add(current)) {
            out.append(first ? "" : "Caused by: ").append(current).append('\n');
            StackTraceElement[] frames = current.getStackTrace();
            int same = 0;
            if (enclosing != null) {
                int m = frames.length - 1;
                int n = enclosing.length - 1;
                while (m >= 0 && n >= 0 && frames[m].equals(enclosing[n])) {
                    m--;
                    n--;
                    same++;
                }
            }
            int own = frames.length - same;
            int shown = Math.min(own, perCause);
            for (int i = 0; i < shown; i++) {
                out.append("\tat ").append(frames[i]).append('\n');
            }
            int hidden = frames.length - shown;
            if (hidden > 0) {
                out.append("\t... ").append(hidden).append(" more\n");
            }
            enclosing = frames;
            current = current.getCause();
            first = false;
            if (out.length() > STACK_MAX) {
                break;
            }
        }
        if (out.length() > STACK_MAX) {
            int cut = out.lastIndexOf("\n", STACK_MAX);
            out.setLength(cut > 0 ? cut + 1 : STACK_MAX);
        }
        return out.toString();
    }

    static String typeOf(Throwable error) {
        String name = error.getClass().getName();
        return name.length() <= 64 ? name : error.getClass().getSimpleName();
    }

    static String osName() {
        String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
        if (os.startsWith("linux")) {
            return "linux";
        }
        if (os.startsWith("windows")) {
            return "win32";
        }
        if (os.startsWith("mac")) {
            return "darwin";
        }
        return os.replace(' ', '-');
    }

    private static String cleanPath(String path) {
        int mark = path.indexOf('?');
        return mark >= 0 ? path.substring(0, mark) : path;
    }

    /** request: {method, path, route, session_id} (the integrations fill it in); null for this thread's request. */
    void capture(Throwable error, Map<String, String> request, int status, String kind) {
        if (error == null || !core.isOn("errors")) {
            return;
        }
        try {
            RequestContext context = RequestContext.current();
            Map<String, String> fields = request != null ? request : context != null ? context.fields() : null;
            Map<String, Object> waiting = seen.get(error);
            if (waiting != null) {
                upgrade(error, waiting, fields, status, kind);
                return;
            }
            String message = error.getMessage();
            Map<String, Object> event = new LinkedHashMap<>();
            event.put("message", message == null || message.isEmpty() ? error.getClass().getSimpleName() : message);
            event.put("error_type", typeOf(error));
            event.put("stack", stackOf(error));
            event.put("kind", kind);
            event.put("status_code", status);
            event.put("runtime", "Java");
            event.put("runtime_version", System.getProperty("java.version", ""));
            event.put("os", osName());
            event.put("server_name", serverName);
            event.put("release", release);
            // When it happened: a crash sent after a restart keeps its own time.
            event.put("at", Instant.now().truncatedTo(ChronoUnit.MILLIS).toString());
            if (context != null) {
                List<Map<String, Object>> trail = context.breadcrumbs();
                if (!trail.isEmpty()) {
                    event.put("breadcrumbs", trail);
                }
            }
            if (fields != null) {
                for (String key : new String[] {"method", "path", "route", "session_id"}) {
                    String value = fields.get(key);
                    event.put(key, value == null ? "" : value);
                }
            }
            String path = (String) event.get("path");
            if (path != null && !path.isEmpty()) {
                event.put("path", cleanPath(path));
                // Named as Server speed names the request, so the two match.
                Object route = event.get("route");
                if (route == null || ((String) route).isEmpty()) {
                    event.put("route", Performance.normalizeRoute((String) event.get("path")));
                }
            }
            if (beforeSend != null) {
                event = plain(beforeSend.apply(event, error));
                if (event == null) {
                    return;
                }
            }
            boolean full;
            synchronized (lock) {
                if (queue.size() >= QUEUE_MAX) {
                    core.log("errors", "queue full, error dropped");
                    return;
                }
                queue.add(event);
                full = queue.size() >= BATCH;
            }
            seen.put(error, event);
            if (full && job != null) {
                job.runNow();
            }
        } catch (RuntimeException failure) {
            core.log("errors", "could not capture error: " + failure);
        }
    }

    /**
     * An exception logged and then thrown on is captured first as "logged",
     * with no status; the framework's capture that follows knows the status,
     * the kind and the request.
     */
    private void upgrade(Throwable error, Map<String, Object> waiting, Map<String, String> request, int status, String kind) {
        if ("logged".equals(kind)) {
            return;
        }
        synchronized (lock) {
            int index = -1;
            for (int i = 0; i < queue.size(); i++) {
                if (queue.get(i) == waiting) {
                    index = i;
                    break;
                }
            }
            if (index == -1) {
                return;
            }
            Map<String, Object> event = new LinkedHashMap<>(waiting);
            if ("logged".equals(waiting.get("kind"))) {
                event.put("kind", kind);
            }
            Object code = waiting.get("status_code");
            if (!(code instanceof Number) || ((Number) code).intValue() == 0) {
                event.put("status_code", status);
            }
            if (request != null) {
                for (String key : new String[] {"method", "path", "route", "session_id"}) {
                    Object have = event.get(key);
                    String given = request.get(key);
                    if ((have == null || "".equals(have)) && given != null && !given.isEmpty()) {
                        event.put(key, given);
                    }
                }
            }
            Object path = event.get("path");
            if (path instanceof String && !((String) path).isEmpty()) {
                event.put("path", cleanPath((String) path));
                Object route = event.get("route");
                if (route == null || "".equals(route)) {
                    event.put("route", Performance.normalizeRoute((String) event.get("path")));
                }
            }
            if (beforeSend != null) {
                event = plain(beforeSend.apply(event, error));
            }
            if (event != null) {
                queue.set(index, event);
                seen.put(error, event);
            } else {
                queue.remove(index);
            }
        }
    }

    /** What beforeSend gave back, as plain JSON values; null (dropped) when it can't be sent. */
    private static Map<String, Object> plain(Map<String, Object> event) {
        try {
            return Json.safeMap(event);
        } catch (IllegalArgumentException refused) {
            Core.warn("an error event from beforeSend can't be sent and was dropped: " + refused.getMessage());
            return null;
        }
    }

    /** The errors waiting (tests). */
    List<Map<String, Object>> waiting() {
        synchronized (lock) {
            return new ArrayList<>(queue);
        }
    }

    private static boolean failed(Core.Response res) {
        return res == null || res.status == 429 || res.status >= 500;
    }

    private Core.Response sendBatch(List<Map<String, Object>> batch) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("errors", batch);
        return core.post("errors", "/events/server-errors", body);
    }

    void flush(boolean resend) {
        List<Map<String, Object>> waiting;
        synchronized (lock) {
            waiting = queue;
            queue = new ArrayList<>();
        }
        boolean sent = true;
        for (int i = 0; i < waiting.size(); i += BATCH) {
            List<Map<String, Object>> batch = waiting.subList(i, Math.min(waiting.size(), i + BATCH));
            Core.Response res = sendBatch(batch);
            if (failed(res) && !core.isClosing()) {
                try {
                    Thread.sleep(RETRY_AFTER_MS);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                }
                res = sendBatch(batch);
            }
            if (failed(res)) {
                sent = false;
                spool(batch);
            }
        }
        // Not straight after the collector failed this flush: it would only wait out another timeout.
        if (resend && sent && spoolFile != null && System.currentTimeMillis() / 1000.0 - lastResend >= RESEND_EVERY) {
            resend();
        }
    }

    /** Appends events to the file. Credentials are added when sent, never written down. */
    void spool(List<Map<String, Object>> events) {
        if (spoolFile == null || events.isEmpty()) {
            return;
        }
        try {
            if (Files.exists(spoolFile) && Files.size(spoolFile) > SPOOL_BYTES) {
                core.log("errors", "waiting errors file is full, errors dropped");
                return;
            }
            if (!Files.exists(spoolFile)) {
                try {
                    if (FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
                        Files.createFile(spoolFile, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")));
                    }
                } catch (IOException raced) {
                    // made meanwhile, or not ours to make: the append says which
                }
            }
            StringBuilder lines = new StringBuilder();
            for (Map<String, Object> event : events) {
                lines.append(Json.write(event)).append('\n');
            }
            try (OutputStream out = Files.newOutputStream(spoolFile, StandardOpenOption.CREATE, StandardOpenOption.APPEND,
                    StandardOpenOption.WRITE)) {
                out.write(lines.toString().getBytes(StandardCharsets.UTF_8));
            }
        } catch (IOException | RuntimeException failure) {
            core.log("errors", "could not keep errors to send later: " + failure);
        }
    }

    /**
     * Sends what earlier attempts (or an earlier run) couldn't. Taken by
     * renaming the file first, so two processes never send the same errors;
     * the taken file is deleted only once all of it is sent (what wasn't goes
     * back in the file). A file left taken by a process that stopped while
     * sending is picked up too.
     */
    void resend() {
        lastResend = System.currentTimeMillis() / 1000.0;
        if (spoolFile == null) {
            return;
        }
        synchronized (resendLock) {
            List<Path> files = new ArrayList<>();
            Path taken = Paths.get(spoolFile + "." + ProcessHandle.current().pid() + "." + Thread.currentThread().getId() + ".sending");
            try {
                Files.move(spoolFile, taken, StandardCopyOption.ATOMIC_MOVE);
                files.add(taken);
            } catch (IOException | RuntimeException nothing) {
                // no file, or not ours to take
            }
            files.addAll(abandoned());
            for (Path file : files) {
                if (!sendFile(file)) {
                    return;
                }
            }
        }
    }

    /** Files taken by a process that isn't running any more, claimed for this one. */
    private List<Path> abandoned() {
        List<Path> out = new ArrayList<>();
        Path dir = spoolFile.toAbsolutePath().getParent();
        String head = spoolFile.getFileName() + ".";
        if (dir == null) {
            return out;
        }
        try (java.nio.file.DirectoryStream<Path> list = Files.newDirectoryStream(dir, head.replace("[", "\\[") + "*.sending")) {
            long me = ProcessHandle.current().pid();
            for (Path file : list) {
                String[] parts = file.getFileName().toString().substring(head.length()).split("\\.");
                long pid;
                try {
                    pid = Long.parseLong(parts[0]);
                } catch (NumberFormatException | ArrayIndexOutOfBoundsException notOurs) {
                    continue;
                }
                if (pid == me || ProcessHandle.of(pid).map(ProcessHandle::isAlive).orElse(false)) {
                    continue;
                }
                Path claimed = Paths.get(spoolFile + "." + me + "." + Thread.currentThread().getId() + "." + out.size() + ".sending");
                try {
                    Files.move(file, claimed, StandardCopyOption.ATOMIC_MOVE);
                    out.add(claimed);
                } catch (IOException raced) {
                    // another process claimed it first
                }
                if (out.size() >= 10) {
                    break;
                }
            }
        } catch (IOException | RuntimeException unreadable) {
            // nothing to pick up
        }
        return out;
    }

    /** Sends one taken file; false when the collector stopped taking them (the rest is back in the spool). */
    private boolean sendFile(Path file) {
        List<Map<String, Object>> events = new ArrayList<>();
        try (BufferedReader reader = Files.newBufferedReader(file, StandardCharsets.UTF_8)) {
            String line;
            while ((line = reader.readLine()) != null) {
                try {
                    Map<String, Object> event = Json.map(Json.parse(line));
                    if (event != null) {
                        events.add(event);
                    }
                } catch (RuntimeException brokenLine) {
                    // a line cut short by a crash: the others still count
                }
            }
        } catch (IOException | RuntimeException unreadable) {
            return true;
        }
        boolean all = true;
        for (int i = 0; i < events.size(); i += BATCH) {
            List<Map<String, Object>> batch = events.subList(i, Math.min(events.size(), i + BATCH));
            if (failed(sendBatch(batch))) {
                spool(new ArrayList<>(events.subList(i, events.size())));
                all = false;
                break;
            }
        }
        try {
            Files.deleteIfExists(file);
        } catch (IOException ignored) {
            // left for a later run, which skips it while this process lives
        }
        return all;
    }

    private double flushJob() {
        flush(true);
        return FLUSH_EVERY;
    }

    void close() {
        if (job != null) {
            job.stop(core.stopWait());
        }
        if (installed != null && Thread.getDefaultUncaughtExceptionHandler() == installed) {
            Thread.setDefaultUncaughtExceptionHandler(previous);
        }
        installed = null;
        if (logHandler != null) {
            Logger.getLogger("").removeHandler(logHandler);
            logHandler = null;
        }
        // No resend of the file at close: it waits for the next start, so a
        // stop never waits on a collector that is down.
        flush(false);
    }
}
