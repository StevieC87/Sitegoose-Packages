"""Analytics module: what only the server sees for sure (payments, sign-ups,
plan changes), next to the browser tracker's visits. Not pageviews: the
tracker counts those, and counting them here too would count them twice.

- track(): events, batched to POST /events/server-events in the background.
  Each gets an event_uid, so a retried batch can be told apart from new events.
- identify(): links the browser's visit to your user ID (/events/identify),
  with optional traits about the user (plan, seats...).
- lead(): adds or updates a lead (/events/lead).
identify() and lead() wait for the answer (up to 5 seconds).
Pass session_id to link an event to the visit: the page sends
window.analyticsSession.getId() in the X-Analytics-Session header, and the
framework integrations give you platform.session_id(request).
"""
import math
import threading
import uuid
from datetime import datetime, timezone

from .core import Periodic, plain

BATCH = 100
QUEUE_MAX = 1000
FLUSH_EVERY = 2
RETRY = 15


def scalar_traits(traits):
    """The traits that are text, a finite number or True/False; {} when none is."""
    if not isinstance(traits, dict):
        return {}
    return {
        str(name): value for name, value in traits.items()
        if isinstance(value, (str, bool, int)) or (isinstance(value, float) and math.isfinite(value))
    }


class Analytics:
    def __init__(self, core, **_):
        self.core = core
        self.queue = []
        self.lock = threading.Lock()
        self.job = Periodic(self._flush_job, FLUSH_EVERY) if core.valid else None

    def track(self, name, fields=None, session_id=""):
        """name: the event's name; fields: value, numeric_value, currency, url,
        event_label, variant, id, timestamp, event_uid (the server events docs).
        Returns the event_uid, or "" when not queued. fields are taken as
        JSON there and then (plain()): a value JSON can't carry becomes text,
        never an error when the batch is sent."""
        if not name or not isinstance(name, str) or not self.core.is_on("analytics"):
            return ""
        fields = plain(dict(fields or {}))
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "session_id": session_id or "",
        }
        event.update(fields)
        event["event_name"] = name[:100]
        event["event_uid"] = fields.get("event_uid") or str(uuid.uuid4())
        if isinstance(event.get("numeric_value"), (int, float)):
            event["numeric_value"] = str(event["numeric_value"])
        with self.lock:
            if len(self.queue) >= QUEUE_MAX:
                self.core.log("analytics", "queue full, event dropped")
                return ""
            self.queue.append(event)
            full = len(self.queue) >= BATCH
        if full and self.job:
            self.job.run_now()
        return event["event_uid"]

    def flush(self):
        """Sends what's waiting; returns False when some of it must be tried again."""
        with self.lock:
            waiting, self.queue = self.queue, []
        ok = True
        for i in range(0, len(waiting), BATCH):
            batch = waiting[i:i + BATCH]
            res = self.core.send("analytics", "/events/server-events", body={"events": batch})
            if res is None or res.status == 429 or res.status >= 500:
                ok = False
                with self.lock:
                    self.queue = (batch + self.queue)[:QUEUE_MAX]
            elif res.unsendable:
                self.core.log("analytics", "events dropped: not JSON")
            elif not res.ok:
                self.core.log("analytics", "events refused:", res.body[:300])
        return ok

    def _flush_job(self):
        return FLUSH_EVERY if self.flush() else RETRY

    def identify(self, user_id, session_id="", traits=None):
        """Links the visit to your user ID. True when stored. traits: what you
        know about the user, name -> text, number or True/False
        ({"plan": "pro", "seats": 5}); anything else is left out, and the
        collector cleans the names and values."""
        if not user_id or not session_id or not self.core.is_on("analytics"):
            return False
        body = {"user_id": str(user_id), "session_id": session_id}
        kept = scalar_traits(traits)
        if kept:
            body["traits"] = kept
        res = self.core.send("analytics", "/events/identify", body=body)
        return bool(res and res.ok)

    def lead(self, fields, session_id=""):
        """fields: email or phone, and name, status, tags, note, deal fields...
        Returns {"status", "lead_id"}, or None."""
        if not self.core.is_on("analytics"):
            return None
        res = self.core.send("analytics", "/events/lead", body=plain(dict({"session_id": session_id or ""}, **(fields or {}))))
        if res is None:
            return None
        if not res.ok:
            self.core.log("analytics", "lead refused:", res.body[:300])
            return None
        return res.json()

    def close(self):
        if self.job:
            self.job.stop()
        self.flush()
