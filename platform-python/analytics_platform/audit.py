"""Audit log module: who did what on your site, sent to POST /events/audit in
small batches in the background (Security -> Audit log).
audit("user.role_changed", actor=..., target=..., details=..., request=...);
the request adds the actor's address and visit. What goes in (names, emails)
is up to you. Django's logins and logouts are recorded on their own.
"""
import threading
from datetime import datetime, timezone

from .core import Periodic, plain

BATCH = 100
QUEUE_MAX = 1000
FLUSH_EVERY = 5


class Audit:
    def __init__(self, core, **_):
        self.core = core
        self.queue = []
        self.lock = threading.Lock()
        self.job = Periodic(self._flush_job, FLUSH_EVERY) if core.valid else None

    def record(self, action, actor="", target="", details=None, actor_ip="", session_id=""):
        if not self.core.is_on("audit") or not isinstance(action, str) or not action:
            return
        entry = {
            "at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "action": action[:64], "actor": str(actor or "")[:200], "target": str(target or "")[:300],
            # Taken as JSON now: a value that isn't (a model, a date) is text,
            # rather than failing the batch it is sent in.
            "details": plain(details), "actor_ip": actor_ip or "", "session_id": session_id or "",
        }
        with self.lock:
            if len(self.queue) >= QUEUE_MAX:
                return
            self.queue.append(entry)
            full = len(self.queue) >= BATCH
        if full and self.job:
            self.job.run_now()

    def flush(self):
        with self.lock:
            waiting, self.queue = self.queue, []
        for i in range(0, len(waiting), BATCH):
            self.core.send("audit", "/events/audit", body={"entries": waiting[i:i + BATCH]})

    def _flush_job(self):
        self.flush()
        return FLUSH_EVERY

    def close(self):
        if self.job:
            self.job.stop()
        self.flush()
