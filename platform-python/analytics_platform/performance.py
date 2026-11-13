"""Performance & API monitoring module: times every request (from arriving
to the response being ready) and sends one row per minute, method, route and
status code (how many, total and slowest time, and a count per time bucket)
to POST /events/server-requests. Nothing about visitors is sent.

The route is the framework's own pattern when the integration knows it
(Django, Flask, FastAPI); otherwise numbers and IDs in the path become ":id",
and unmatched 404s are one route.
"""
import os
import platform as host
import re
import socket
import threading
import time
from datetime import datetime, timezone

from .core import Periodic

# Keep in step with the collector (expresscollect/Analytics/serverRequests.js).
BUCKET_EDGES_MS = [5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000]
FLUSH_EVERY = 60
MAX_KEYS = 300
# Past MAX_KEYS new routes fold into "(other)"; past this nothing new is kept
# until the next send (statuses are the app's, but a row per status adds up).
HARD_MAX_KEYS = 400
# The method is the visitor's to choose: anything else is one "OTHER", or a
# made-up method per request would be a row each.
METHODS = frozenset(("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "JOB"))
MAX_ROWS = 500
NOT_FOUND = "/(not found)"
_ID = re.compile(r"(\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{16,})\Z", re.I)


def normalize_route(path):
    """'/orders/123/items/9f8e...' -> '/orders/:id/items/:id'"""
    path = re.split(r"[?#]", str(path or "/"))[0] or "/"
    parts = [":id" if _ID.match(s) or (len(s) >= 20 and re.search(r"\d", s)) else s for s in path.split("/")]
    route = "/".join(parts)
    return (route if route.startswith("/") else "/" + route)[:200]


def bucket_of(ms):
    for i, edge in enumerate(BUCKET_EDGES_MS):
        if ms <= edge:
            return i
    return len(BUCKET_EDGES_MS)


def _on(option):
    return option is not False and option is not None


class Performance:
    """Options: server_name (default the host name); queries, calls and
    queues (False leaves database queries, outgoing calls or job queues out:
    queries.py, calls.py, queues.py)."""

    def __init__(self, core, server_name=None, queries=True, calls=True, queues=True, **_):
        self.core = core
        self.server_name = str(server_name or socket.gethostname())[:100]
        self.runtime = "Python " + host.python_version()
        self.rows = {}
        self.lock = threading.Lock()
        # Requests in progress now, and the most at once since the resources
        # module last asked. timed stays False until a request is timed, so
        # an app whose middleware isn't installed reports no peak, not 0.
        self.inflight = 0
        self.peak = 0
        self.timed = False
        self.inflight_lock = threading.Lock()
        self.job = Periodic(self._flush_job, FLUSH_EVERY) if core.valid else None
        if hasattr(os, "register_at_fork"):
            os.register_at_fork(after_in_child=self._forked)
        # The database queries and outgoing calls each request made, sent
        # beside its timings.
        self.queries = None
        if _on(queries) or _on(calls):
            try:
                from .queries import Queries
                self.queries = Queries(core, self, queries=_on(queries), calls=_on(calls))
            except Exception as error:
                print("[analytics-platform] database queries and calls could not be timed and are off: %s" % error)
        # Job queues, read once a minute (watch_queue).
        self.queues = None
        if _on(queues):
            try:
                from .queues import Queues
                self.queues = Queues(core, self)
            except Exception as error:
                print("[analytics-platform] job queues could not be read and are off: %s" % error)

    def _forked(self):
        """In a forked worker the parent's rows are the parent's to send."""
        self.lock = threading.Lock()
        self.rows = {}
        self.inflight_lock = threading.Lock()
        self.inflight = self.peak = 0
        self.timed = False

    def request_started(self):
        with self.inflight_lock:
            self.timed = True
            self.inflight += 1
            if self.inflight > self.peak:
                self.peak = self.inflight

    def request_ended(self):
        with self.inflight_lock:
            self.inflight = max(0, self.inflight - 1)

    def take_inflight_peak(self):
        """The most requests in progress at once since the last call (None
        until a request was timed); the peak starts again from what is in
        progress now."""
        with self.inflight_lock:
            if not self.timed:
                return None
            most, self.peak = self.peak, self.inflight
            return most

    def record(self, method, route, status, ms, path=""):
        """One finished request. route: the framework's pattern, or "" to
        work it out from path. Returns the (method, route) it was counted
        under, which its queries go under too; None when it wasn't."""
        if not self.core.is_on("performance"):
            return
        status = int(status or 0)
        if not route:
            route = NOT_FOUND if status == 404 else normalize_route(path)
        method = str(method or "GET").upper()
        method = method if method in METHODS else "OTHER"
        minute = int(time.time() // 60) * 60
        with self.lock:
            key = (minute, method, route[:200], status)
            if key not in self.rows and len(self.rows) >= MAX_KEYS:
                key = (minute, method, "(other)", status)
            if key not in self.rows and len(self.rows) >= HARD_MAX_KEYS:
                return method, key[2]
            row = self.rows.get(key)
            if row is None:
                row = self.rows[key] = {"count": 0, "sum_ms": 0.0, "max_ms": 0.0, "buckets": [0] * (len(BUCKET_EDGES_MS) + 1)}
            row["count"] += 1
            row["sum_ms"] += ms
            row["max_ms"] = max(row["max_ms"], ms)
            row["buckets"][bucket_of(ms)] += 1
        return method, key[2]

    def flush(self, everything=True):
        current = int(time.time() // 60) * 60
        with self.lock:
            ready = [(k, v) for k, v in self.rows.items() if everything or k[0] < current]
            for k, _ in ready:
                del self.rows[k]
        rows = [{
            "minute": datetime.fromtimestamp(k[0], timezone.utc).isoformat().replace("+00:00", "Z"),
            "method": k[1], "route": k[2], "status": k[3], "count": v["count"],
            "sum_ms": round(v["sum_ms"], 1), "max_ms": round(v["max_ms"], 1), "buckets": v["buckets"],
        } for k, v in ready]
        for i in range(0, len(rows), MAX_ROWS):
            self.core.send("performance", "/events/server-requests",
                           body={"server_name": self.server_name, "runtime": self.runtime, "rows": rows[i:i + MAX_ROWS]})
        if self.queries:
            try:
                self.queries.flush(everything)
            except Exception as error:
                self.core.log("performance", "could not send queries:", error)

    def _flush_job(self):
        self.flush(everything=False)
        return FLUSH_EVERY

    def close(self):
        if self.job:
            self.job.stop()
        if self.queues:
            self.queues.close()
        self.flush()
