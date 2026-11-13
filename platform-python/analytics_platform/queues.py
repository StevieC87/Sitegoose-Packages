"""Job queues (sdk/protocols/queues.md), part of the performance module:
platform.watch_queue(queue_or_app) reads a queue once a minute (how many jobs
wait, run, are delayed or kept as failed, and how long the oldest waiting one
has waited) and counts the jobs this process added to it and finished. One
row per queue a minute to POST /events/server-queues, for Health -> Server
speed -> Jobs. queues=False leaves them out.

- Celery with a Redis broker (celery.py): the broker's own lists, read
  straight from Redis, since Celery has no backlog API. With a RabbitMQ
  broker nothing is sent: the server agent reads RabbitMQ's management API.
- RQ (rq.py): the queue and its job registries.

Every process watching one queue reads the same gauges, and the dashboard
takes the largest, so watching it in each web server and worker is fine.
Readings are taken on a background thread; a reading that fails is a gap
that minute, never a zero.
"""
import os
import secrets
import threading
import time
import weakref
from datetime import datetime, timezone

from .core import Periodic
from .queries import own_redis

SAMPLE_EVERY = 60
MAX_QUEUES = 100
MAX_ROWS = 500
# The gauges a reader returns; the ones it can't say are left out of the row.
GAUGES = ("waiting", "running", "delayed", "failed", "oldest_s")


class Entry:
    """One queue: where it is, how to read it, and this process's counts."""
    __slots__ = ("system", "broker", "queue", "read", "added", "finished", "counts_added", "counts_finished")

    def __init__(self, system, broker, queue, read):
        self.system = system
        self.broker = str(broker)[:200]
        self.queue = str(queue)[:200]
        self.read = read  # () -> dict of gauges; raises when the broker didn't answer
        self.added = 0
        self.finished = 0
        self.counts_added = False
        self.counts_finished = False


class Queues:
    def __init__(self, core, performance):
        self.core = core
        self.performance = performance
        # This process, so the collector can tell a reading resent after a
        # failed answer from another process's with the same counts.
        self.sender = secrets.token_hex(8)
        self.entries = {}  # (system, broker, queue) -> Entry
        # What watch() was given, so watching it again changes nothing. Weak:
        # a Queue made per request and watched each time doesn't pile up.
        self.watched = weakref.WeakSet()
        self.lock = threading.Lock()
        self.job = Periodic(self._sample_job, SAMPLE_EVERY) if core.valid else None
        if hasattr(os, "register_at_fork"):
            os.register_at_fork(after_in_child=self._forked)

    def _forked(self):
        """A forked worker is another process: its own id and counts."""
        self.lock = threading.Lock()
        self.sender = secrets.token_hex(8)
        for entry in self.entries.values():
            entry.added = entry.finished = 0

    def on(self):
        return self.core.is_on("performance")

    def entry(self, system, broker, queue, read):
        """The queue's entry, made on first sight; None past MAX_QUEUES."""
        key = (system, str(broker)[:200], str(queue)[:200])
        with self.lock:
            found = self.entries.get(key)
            if found is None:
                if len(self.entries) >= MAX_QUEUES:
                    self.core.log("performance", "watch_queue: already watching %d queues; %s isn't" % (MAX_QUEUES, queue))
                    return None
                found = self.entries[key] = Entry(system, broker, queue, read)
        return found

    def count(self, entry, added=0, finished=0):
        if entry is None or not self.on():
            return
        with self.lock:
            entry.added += added
            entry.finished += finished

    def watch(self, target, queues=None):
        """A Celery app or an RQ Queue; returns it."""
        try:
            if target in self.watched:
                return target
        except TypeError:  # can't be held weakly: watched again, which entry() makes harmless
            pass
        try:
            # An RQ Worker has a job_class and a connection too; only a Queue enqueues.
            if hasattr(target, "enqueue") and hasattr(target, "job_class") and hasattr(target, "connection"):
                from .rq import watch_queue
                watch_queue(self, target)
            elif hasattr(target, "amqp") and hasattr(target, "conf"):
                from .celery import watch_queues
                watch_queues(self, target, queues)
            else:
                self.core.log("performance", "watch_queue: not a Celery app or an RQ Queue; not watched")
                return target
            try:
                self.watched.add(target)
            except TypeError:
                pass
        except Exception as error:
            self.core.log("performance", "watch_queue: could not watch it:", error)
        return target

    def sample(self):
        """One reading of every queue watched, a row each, sent at once."""
        if not self.entries or not self.on():
            return []
        minute = datetime.fromtimestamp(int(time.time() // 60) * 60, timezone.utc).isoformat().replace("+00:00", "Z")
        rows = []
        for entry in list(self.entries.values()):
            gauges = None
            try:
                # Through the app's own connection (RQ's), maybe watched:
                # our reads aren't its commands.
                with own_redis():
                    gauges = entry.read()
            except Exception as error:
                self.core.log("performance", "could not read queue %s:" % entry.queue, error)
            with self.lock:
                added, finished = entry.added, entry.finished
                entry.added = entry.finished = 0
            measured = {name: max(0, int(value)) for name, value in (gauges or {}).items()
                        if name in GAUGES and value is not None}
            if entry.counts_added:
                measured["added"] = added
            if entry.counts_finished:
                measured["finished"] = finished
            if measured:  # else nothing to say this minute: a gap
                rows.append(dict({"minute": minute, "system": entry.system, "broker": entry.broker,
                                  "queue": entry.queue, "shared": False}, **measured))
        for i in range(0, len(rows), MAX_ROWS):
            self.core.send("performance", "/events/server-queues", auth="bearer", body={
                "site_id": self.core.site_id, "server_name": self.performance.server_name,
                "runtime": self.performance.runtime, "sender": self.sender, "rows": rows[i:i + MAX_ROWS]})
        return rows

    def _sample_job(self):
        try:
            self.sample()
        except Exception as error:
            self.core.log("performance", "queue reading failed:", error)
        return SAMPLE_EVERY

    def close(self):
        if self.job:
            self.job.stop()


def redis_broker(kwargs):
    """host:port/db (or a socket's name/db) from redis-py connection
    arguments: never the user name or password."""
    db = kwargs.get("db") or 0
    try:
        db = int(db)
    except (TypeError, ValueError):
        db = 0
    path = kwargs.get("path")
    if isinstance(path, str) and path:
        return "%s/%d" % (path.rsplit("/", 1)[-1][:80], db)
    host = "".join(ch for ch in str(kwargs.get("host") or "localhost") if ch not in "@/ \t\n")[:120] or "localhost"
    try:
        port = int(kwargs.get("port") or 6379)
    except (TypeError, ValueError):
        port = 6379
    return "%s:%d/%d" % (host, port, db)


def seconds_since(at, now=None):
    """Whole seconds since a datetime (naive is UTC), never below 0."""
    if at is None:
        return None
    if at.tzinfo is None:
        at = at.replace(tzinfo=timezone.utc)
    now = now or datetime.now(timezone.utc)
    return max(0, int((now - at).total_seconds()))
