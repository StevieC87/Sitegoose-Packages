package com.sitegoose.analytics;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Audit log module: who did what on your site, sent to POST /events/audit in
 * small batches in the background (Security -> Audit log). What goes in
 * (names, emails) is up to you. Spring Security's logins and logouts are
 * recorded on their own.
 */
final class Audit {
    static final int BATCH = 100;
    static final int QUEUE_MAX = 1000;
    static final double FLUSH_EVERY = 5;

    private final Core core;
    private List<Map<String, Object>> queue = new ArrayList<>();
    private final Periodic job;

    Audit(Core core) {
        this.core = core;
        this.job = core.valid ? core.every(this::flushJob, FLUSH_EVERY) : null;
    }

    private static String cut(String text, int max) {
        String value = text == null ? "" : text;
        return value.length() > max ? value.substring(0, max) : value;
    }

    void record(String action, String actor, String target, Object details, String actorIp, String sessionId) {
        if (!core.isOn("audit") || action == null || action.isEmpty()) {
            return;
        }
        Object plain;
        try {
            plain = Json.safe(details);
        } catch (IllegalArgumentException refused) {
            Core.warn("audit(\"" + action + "\") not recorded: " + refused.getMessage());
            return;
        }
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put("at", Instant.now().toString());
        entry.put("action", cut(action, 64));
        entry.put("actor", cut(actor, 200));
        entry.put("target", cut(target, 300));
        entry.put("details", plain);
        entry.put("actor_ip", actorIp == null ? "" : actorIp);
        entry.put("session_id", sessionId == null ? "" : sessionId);
        boolean full;
        synchronized (this) {
            if (queue.size() >= QUEUE_MAX) {
                return;
            }
            queue.add(entry);
            full = queue.size() >= BATCH;
        }
        if (full && job != null) {
            job.runNow();
        }
    }

    void flush() {
        List<Map<String, Object>> waiting;
        synchronized (this) {
            waiting = queue;
            queue = new ArrayList<>();
        }
        for (int i = 0; i < waiting.size(); i += BATCH) {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("entries", waiting.subList(i, Math.min(waiting.size(), i + BATCH)));
            core.post("audit", "/events/audit", body);
        }
    }

    private double flushJob() {
        flush();
        return FLUSH_EVERY;
    }

    void close() {
        if (job != null) {
            job.stop(core.stopWait());
        }
        flush();
    }
}
