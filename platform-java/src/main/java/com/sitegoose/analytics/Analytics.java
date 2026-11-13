package com.sitegoose.analytics;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/**
 * Analytics module: what only the server sees for sure (payments, sign-ups,
 * plan changes), next to the browser tracker's visits. Not pageviews: the
 * tracker counts those, and counting them here too would count them twice.
 *
 * <ul>
 *   <li>track(): events, batched to POST /events/server-events in the background.
 *       Each gets an event_uid, so a retried batch can be told apart from new events.</li>
 *   <li>identify(): links the browser's visit to your user ID (/events/identify),
 *       with optional traits about the user (plan, seats...).</li>
 *   <li>lead(): adds or updates a lead (/events/lead).</li>
 * </ul>
 * identify() and lead() wait for the answer (up to 5 seconds).
 */
final class Analytics {
    static final int BATCH = 100;
    static final int QUEUE_MAX = 1000;
    static final double FLUSH_EVERY = 2;
    static final double RETRY = 15;

    private final Core core;
    private List<Map<String, Object>> queue = new ArrayList<>();
    private final Periodic job;

    Analytics(Core core) {
        this.core = core;
        this.job = core.valid ? core.every(this::flushJob, FLUSH_EVERY) : null;
    }

    /**
     * name: the event's name; fields: value, numeric_value, currency, url,
     * event_label, variant, id, timestamp, event_uid, transaction_id, coupon...
     * Returns the event_uid, or "" when not queued.
     */
    String track(String name, Map<String, ?> fields, String sessionId) {
        if (name == null || name.isEmpty() || !core.isOn("analytics")) {
            return "";
        }
        Map<String, Object> plain;
        try {
            plain = Json.safeMap(fields);
        } catch (IllegalArgumentException refused) {
            Core.warn("track(\"" + name + "\") not sent: " + refused.getMessage());
            return "";
        }
        Map<String, Object> event = new LinkedHashMap<>();
        event.put("timestamp", Instant.now().toString());
        event.put("session_id", sessionId == null ? "" : sessionId);
        if (plain != null) {
            event.putAll(plain);
        }
        event.put("event_name", name.length() > 100 ? name.substring(0, 100) : name);
        Object uid = plain == null ? null : plain.get("event_uid");
        event.put("event_uid", uid instanceof String && !((String) uid).isEmpty() ? uid : UUID.randomUUID().toString());
        Object numeric = event.get("numeric_value");
        if (numeric instanceof Number) {
            // Sent as text so an amount stays exact (server-events.md).
            event.put("numeric_value", numeric instanceof java.math.BigDecimal ? ((java.math.BigDecimal) numeric).toPlainString() : numeric.toString());
        }
        boolean full;
        synchronized (this) {
            if (queue.size() >= QUEUE_MAX) {
                core.log("analytics", "queue full, event dropped");
                return "";
            }
            queue.add(event);
            full = queue.size() >= BATCH;
        }
        if (full && job != null) {
            job.runNow();
        }
        return (String) event.get("event_uid");
    }

    /** Sends what's waiting; false when some of it must be tried again. */
    boolean flush() {
        List<Map<String, Object>> waiting;
        synchronized (this) {
            waiting = queue;
            queue = new ArrayList<>();
        }
        boolean ok = true;
        for (int i = 0; i < waiting.size(); i += BATCH) {
            List<Map<String, Object>> batch = new ArrayList<>(waiting.subList(i, Math.min(waiting.size(), i + BATCH)));
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("events", batch);
            Core.Response res = core.post("analytics", "/events/server-events", body);
            if (res == null || res.status == 429 || res.status >= 500) {
                ok = false;
                synchronized (this) {
                    List<Map<String, Object>> again = new ArrayList<>(batch);
                    again.addAll(queue);
                    queue = again.size() > QUEUE_MAX ? new ArrayList<>(again.subList(0, QUEUE_MAX)) : again;
                }
            } else if (!res.ok()) {
                core.log("analytics", "events refused: " + res.text(300));
            }
        }
        return ok;
    }

    private double flushJob() {
        return flush() ? FLUSH_EVERY : RETRY;
    }

    /**
     * Links the visit to your user ID. True when stored. traits: what you know
     * about the user, name to text, number or boolean; anything else is left
     * out, and the collector cleans the names and values. null for none.
     */
    boolean identify(String userId, String sessionId, Map<String, ?> traits) {
        if (userId == null || userId.isEmpty() || sessionId == null || sessionId.isEmpty() || !core.isOn("analytics")) {
            return false;
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("user_id", userId);
        body.put("session_id", sessionId);
        Map<String, Object> kept = scalarTraits(traits);
        if (!kept.isEmpty()) {
            body.put("traits", kept);
        }
        Core.Response res = core.post("analytics", "/events/identify", body);
        return res != null && res.ok();
    }

    /** The traits that are text, a (finite) number or a boolean. */
    static Map<String, Object> scalarTraits(Map<String, ?> traits) {
        Map<String, Object> kept = new LinkedHashMap<>();
        if (traits == null) {
            return kept;
        }
        for (Map.Entry<String, ?> trait : traits.entrySet()) {
            Object value = trait.getValue();
            boolean finite = !(value instanceof Double || value instanceof Float) || Double.isFinite(((Number) value).doubleValue());
            if (trait.getKey() != null && (value instanceof String || value instanceof Boolean || (value instanceof Number && finite))) {
                kept.put(trait.getKey(), value);
            }
        }
        return kept;
    }

    /** fields: email or phone, and name, status, tags, note, deal fields... The answer ({status, lead_id}), or null. */
    Map<String, Object> lead(Map<String, ?> fields, String sessionId) {
        if (!core.isOn("analytics")) {
            return null;
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("session_id", sessionId == null ? "" : sessionId);
        try {
            Map<String, Object> plain = Json.safeMap(fields);
            if (plain != null) {
                body.putAll(plain);
            }
        } catch (IllegalArgumentException refused) {
            Core.warn("lead() not sent: " + refused.getMessage());
            return null;
        }
        Core.Response res = core.post("analytics", "/events/lead", body);
        if (res == null) {
            return null;
        }
        if (!res.ok()) {
            core.log("analytics", "lead refused: " + res.text(300));
            return null;
        }
        return Json.map(res.json());
    }

    void close() {
        if (job != null) {
            job.stop(core.stopWait());
        }
        flush();
    }
}
