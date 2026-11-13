// Audit log module: who did what on your site, sent to POST /events/audit
// in small batches (Security → Audit log). audit("user.role_changed", {
// actor, target, details, req }); req adds the actor's address and visit.
// What goes in (names, emails) is up to you. Sending never throws.
"use strict";

const { sessionOf, jsonSafe } = require("./core.js");

const BATCH = 100;
const QUEUE_MAX = 1000;
const FLUSH_MS = 5000;

// clientIp(req): the firewall's way of finding the visitor's address.
function createAudit(core, { clientIp } = {}) {
  let queue = [];
  let timer = null;
  let sending = Promise.resolve();

  function flush() {
    clearTimeout(timer);
    timer = null;
    const batches = [];
    while (queue.length) batches.push(queue.splice(0, BATCH));
    sending = sending.then(() => Promise.all(batches.map((entries) => core.send("audit", "/events/audit", { body: { entries } }))));
    return sending;
  }

  // action: what happened, e.g. "user.login", "settings.changed" (letters,
  // numbers and . _ : -). Options: actor (who), target (what it happened
  // to), details (any JSON), req.
  function audit(action, { actor = "", target = "", details, req } = {}) {
    try {
      if (!core.isOn("audit") || typeof action !== "string" || !action) return;
      if (queue.length >= QUEUE_MAX) return core.log("audit", "queue full, entry dropped");
      // details as JSON now: one that can't be (a circular object) is
      // dropped here, not found at flush time with its whole batch.
      let safeDetails;
      try {
        safeDetails = jsonSafe(details);
      } catch (error) {
        return core.log("audit", `entry "${action}" dropped: its details can't be sent as JSON (${error?.message})`);
      }
      queue.push({
        at: new Date().toISOString(),
        action: action.slice(0, 64),
        actor: String(actor).slice(0, 200),
        target: String(target).slice(0, 300),
        details: safeDetails,
        actor_ip: req ? (clientIp ? clientIp(req) : req.ip || req.socket?.remoteAddress || "") : "",
        session_id: sessionOf(req),
      });
      if (queue.length >= BATCH) flush();
      else if (!timer) {
        timer = setTimeout(flush, FLUSH_MS);
        timer.unref?.();
      }
    } catch (error) {
      core.log("audit", "could not record:", error?.message);
    }
  }

  return { audit, flush, close: flush };
}

module.exports = { createAudit };
