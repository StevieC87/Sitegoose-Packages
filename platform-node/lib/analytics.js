// Analytics module: what only the server sees for sure (payments, sign-ups,
// plan changes), next to the browser tracker's visits. Not pageviews: the
// tracker counts those, and counting them here too would count them twice.
// - track(): events, batched to POST /events/server-events. Each gets an
//   event_uid, so a retried batch can be told apart from new events.
// - identify(): links the browser's visit to your user ID (/events/identify),
//   with optional traits about the user (plan, seats...).
// - lead(): adds or updates a lead (/events/lead).
// Pass `req` (or session_id) to link an event to the visit: the page sends
// window.analyticsSession.getId() in the x-analytics-session header.
"use strict";

const { sessionOf, builtin, jsonSafe } = require("./core.js");

// No Node built-ins required, so Hono can send events on any runtime
// (hono.js); Node 18 has no global crypto and loads it the old way.
const randomUUID = () => globalThis.crypto?.randomUUID?.() ?? builtin("crypto").randomUUID();

const BATCH = 100;
const QUEUE_MAX = 1000;
const FLUSH_MS = 2000;
const RETRY_MS = 15000;

// The traits that are text, a finite number or true/false; null when none is.
function scalarTraits(traits) {
  if (!traits || typeof traits !== "object" || Array.isArray(traits)) return null;
  const kept = {};
  for (const [name, value] of Object.entries(traits)) {
    if (typeof value === "string" || typeof value === "boolean" || (typeof value === "number" && Number.isFinite(value))) kept[name] = value;
  }
  return Object.keys(kept).length ? kept : null;
}

function createAnalytics(core) {
  const log = (...args) => core.log("analytics", ...args);
  let queue = [];
  let timer = null;
  let sending = Promise.resolve();

  function schedule(ms = FLUSH_MS) {
    if (timer || !queue.length) return;
    timer = setTimeout(() => {
      timer = null;
      flush();
    }, ms);
    timer.unref?.();
  }

  async function sendBatch(events) {
    const res = await core.send("analytics", "/events/server-events", { body: { events } });
    // Not taken: back to the front of the queue (as room allows), tried
    // again later. Not for a batch that can't be JSON (res.unsendable): it
    // never could be sent, and kept it would hold up every event after it.
    if (!res || res.status === 429 || res.status >= 500) {
      queue = [...events, ...queue].slice(0, QUEUE_MAX);
      schedule(RETRY_MS);
      return;
    }
    if (!res.ok) log("events refused:", await res.text().catch(() => ""));
  }

  function flush() {
    clearTimeout(timer);
    timer = null;
    const batches = [];
    while (queue.length) batches.push(queue.splice(0, BATCH));
    sending = sending.then(() => Promise.all(batches.map(sendBatch)));
    return sending;
  }

  // name: the event's name; fields: value, numeric_value, currency, url,
  // event_label, variant, id, session_id, timestamp, event_uid (see the
  // server events docs). Returns the event_uid, or "" when not queued.
  function track(name, fields = {}, { req } = {}) {
    try {
      if (!name || typeof name !== "string" || !core.isOn("analytics")) return "";
      const event = {
        timestamp: new Date().toISOString(),
        session_id: sessionOf(req),
        ...fields,
        event_name: name.slice(0, 100),
        event_uid: fields.event_uid || randomUUID(),
      };
      if (typeof event.numeric_value === "number") event.numeric_value = String(event.numeric_value);
      // Made JSON now (a BigInt as its digits, a Date as text), so a field
      // JSON can't carry is found here, in the caller's stack, and not at
      // flush time, where it would fail the whole batch again and again.
      let safe;
      try {
        safe = jsonSafe(event);
      } catch (error) {
        log(`event "${name}" dropped: its fields can't be sent as JSON (${error?.message})`);
        return "";
      }
      if (queue.length >= QUEUE_MAX) {
        log("queue full, event dropped");
        return "";
      }
      queue.push(safe);
      if (queue.length >= BATCH) flush();
      else schedule();
      return safe.event_uid;
    } catch (error) {
      log("could not queue event:", error?.message);
      return "";
    }
  }

  // Links the visit (req or session_id) to your user ID. traits: what you
  // know about the user, name -> text, number or true/false ({ plan: "pro",
  // seats: 5 }); anything else is left out, and the collector cleans the
  // names and values. Resolves true when stored.
  async function identify(userId, { req, session_id, traits } = {}) {
    const session = session_id || sessionOf(req);
    if (!userId || !session || !core.isOn("analytics")) return false;
    const body = { user_id: String(userId), session_id: session };
    const kept = scalarTraits(traits);
    if (kept) body.traits = kept;
    const res = await core.send("analytics", "/events/identify", { body });
    return Boolean(res?.ok);
  }

  // fields: email or phone, and name, status, tags, note, deal fields...
  // (the leads docs). Resolves to { status, lead_id }, or null.
  async function lead(fields = {}, { req } = {}) {
    if (!core.isOn("analytics")) return null;
    const res = await core.send("analytics", "/events/lead", { body: { session_id: sessionOf(req), ...fields } });
    if (!res) return null;
    const data = await res.json().catch(() => null);
    if (!res.ok) log("lead refused:", data?.error || res.status);
    return res.ok ? data : null;
  }

  return { track, identify, lead, flush, close: flush };
}

module.exports = { createAnalytics, randomUUID, scalarTraits };
