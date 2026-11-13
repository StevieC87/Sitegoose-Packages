"""Error monitoring module: the server's errors go to the collector (POST
/events/server-errors), where they join the browser's errors in the Errors
report. Uncaught exceptions (main thread and other threads) are captured on
their own and Python still prints and exits as it would. The framework
integrations capture request errors (5xx); capture_exception() captures
errors you catch; capture_logging sends the exceptions your code logs. An
error is sent once however many of those see it. Errors are sent in small
batches, a batch the collector couldn't take is tried once more, and sending
never raises. What still can't be sent (the collector is away, or the process
is crashing) waits in a file and is sent once it can be, after a restart too;
each error carries when it happened, and the trail of its request or job: the
steps you add with add_breadcrumb().
"""
import contextvars
import glob
import hashlib
import json
import logging
import os
import tempfile
import platform as host
import re
import socket
import sys
import threading
import time
import traceback
from datetime import datetime, timezone

from .core import SESSION_HEADER, Periodic, begin_exit, time_left
from .performance import normalize_route

BATCH = 10
QUEUE_MAX = 100
FLUSH_EVERY = 2
# A batch the collector couldn't take (unreachable, 429, 5xx) is sent once
# more after this many seconds.
RETRY_AFTER = 2
SEEN = "_analytics_platform_sent"
# The file of errors waiting to be sent: tried again this often (seconds), and
# kept under this size (past it, new ones are dropped rather than filling a disk).
RESEND_EVERY = 60
SPOOL_BYTES = 1024 * 1024
# A file a resend took and was still sending (rewritten after every batch)
# that hasn't changed for this long belongs to a process that was killed
# mid-send: the next resend takes it over.
ORPHAN_S = 300
# The longest message sent; the stack keeps the detail.
MAX_MESSAGE = 2000
# The visitor went away (closed the tab, lost the connection) while the
# request was read or answered: not a fault of the server, so not a 500.
_DISCONNECTS = (BrokenPipeError, ConnectionResetError, ConnectionAbortedError)
_DISCONNECT_NAMES = frozenset((
    "ClientDisconnect",      # Starlette / FastAPI, reading the body after the client left
    "ClientDisconnected",    # Werkzeug / Flask
    "UnreadablePostError",   # Django
))


def is_disconnect(error):
    """True for the client hanging up, as the framework or the socket saw it
    (looked for along the chain of causes, as frameworks wrap them)."""
    seen = 0
    while isinstance(error, BaseException) and seen < 5:
        if isinstance(error, _DISCONNECTS) or type(error).__name__ in _DISCONNECT_NAMES:
            return True
        error = error.__cause__ or error.__context__
        seen += 1
    return False

# The request being handled, set by the framework integrations: a callable
# returning {"method", "path", "route", "session_id"}, so an error captured
# without a request (logged, or caught deep in your code) still gets its route.
current_request = contextvars.ContextVar("analytics_platform_request", default=None)
# The steps of the request or job being handled, oldest first, set to a new
# list wherever current_request starts a request. Outside one, steps are dropped.
current_trail = contextvars.ContextVar("analytics_platform_trail", default=None)
CRUMB_MAX = 15


def add_breadcrumb(text):
    trail = current_trail.get()
    if trail is None:
        return
    trail.append({"type": "note", "text": str(text)[:200], "at": time.time()})
    del trail[:-CRUMB_MAX]


def _breadcrumbs():
    """The trail as the tracker sends it: how long before now each step happened."""
    now = time.time()
    return [{"type": crumb["type"], "text": crumb["text"], "ms": max(0, round((now - crumb["at"]) * 1000))}
            for crumb in current_trail.get() or []]


def _request_fields():
    fields = current_request.get()
    if fields is None:
        flask = sys.modules.get("flask")
        if flask is not None and flask.has_request_context():
            rule = getattr(flask.request, "url_rule", None)
            return {"method": flask.request.method, "path": flask.request.path, "route": getattr(rule, "rule", ""),
                    "session_id": flask.request.headers.get(SESSION_HEADER, "")}
        return None
    try:
        return fields()
    except Exception:
        return None


def _failed(res):
    return res is None or res.status == 429 or res.status >= 500


class _LogHandler(logging.Handler):
    """Sends the exception of a log record at ERROR or above (logger.exception,
    or exc_info=True). A record without an exception isn't sent: it has no
    traceback to group it by."""

    def __init__(self, errors):
        super().__init__(logging.ERROR)
        self.errors = errors

    def emit(self, record):
        exc = record.exc_info[1] if record.exc_info else None
        if isinstance(exc, BaseException) and not record.name.startswith("analytics_platform"):
            self.errors.capture_exception(exc, kind="logged")


class Errors:
    """Options: server_name (default the host name), release (which build this
    is; default the ANALYTICS_RELEASE environment variable), root (paths in tracebacks
    are made relative to it; default the working directory), capture_uncaught
    (default True), capture_logging (default False: exceptions logged at
    ERROR or above through the logging module are sent too),
    before_send(event, error) to change an event or drop it (return None),
    spool_dir (where errors that couldn't be sent wait; default the system's
    temp folder, False to keep none)."""

    def __init__(self, core, server_name=None, root=None, release=None, capture_uncaught=True, before_send=None,
                 capture_logging=False, spool_dir=None, **_):
        self.core = core
        self.server_name = str(server_name or socket.gethostname())[:100]
        self.root = str(root or os.getcwd()).rstrip("/\\")
        # Which build this is, for "introduced in" in the Errors report.
        self.release = re.sub(r"[^\w.+\-]", "", str(release or os.environ.get("ANALYTICS_RELEASE", "")).strip())[:64]
        self.before_send = before_send
        self.queue = []
        self.lock = threading.Lock()
        # Named after the site and its secret, not the site id alone, so the
        # folder's listing tells nobody which site it is.
        self.spool_file = None
        if spool_dir is not False and core.valid:
            name = hashlib.sha256(("%s|%s" % (core.site_id, core.secret)).encode()).hexdigest()[:16]
            self.spool_file = os.path.join(str(spool_dir or tempfile.gettempdir()), "analytics-errors-%s.jsonl" % name)
        self._last_resend = 0.0
        # One resend at a time (threads share the file), and what it is still
        # sending, written back if the process crashes meanwhile.
        self._resend_lock = threading.Lock()
        self._resending = []
        self._taken = None
        self.job = Periodic(self._flush_job, FLUSH_EVERY) if core.valid else None
        self._previous = None
        if capture_uncaught:
            self._previous = (sys.excepthook, threading.excepthook)
            sys.excepthook = self._excepthook
            threading.excepthook = self._thread_excepthook
        self._log_handler = None
        if capture_logging:
            self._log_handler = _LogHandler(self)
            logging.getLogger().addHandler(self._log_handler)
        if hasattr(os, "register_at_fork"):
            os.register_at_fork(after_in_child=self._forked)

    def _forked(self):
        """In a forked worker (gunicorn, a Celery pool process replaced after
        the main process captured a task's time limit): what was waiting is
        the parent's to send, or it would be sent twice, and a lock the parent
        held at the fork would stay held."""
        self.lock = threading.Lock()
        self._resend_lock = threading.Lock()
        self.queue = []
        self._resending = []
        self._taken = None

    def _excepthook(self, kind, value, tb):
        self.capture_exception(value, kind="error")
        # The process is ending: sent within the exit deadline, no retry, and
        # what's left (and the file) waits for the next start.
        begin_exit()
        self.flush(resend=False)
        self._keep_resending()
        self._previous[0](kind, value, tb)

    def _thread_excepthook(self, args):
        if args.exc_value is not None:
            self.capture_exception(args.exc_value, kind="error")
            self.flush(resend=False)
        self._previous[1](args)

    def _keep_resending(self):
        """The process is exiting: what a resend hasn't sent yet goes back in
        the file (and the copy it took is let go, or it would be sent twice)."""
        with self.lock:
            left, self._resending = self._resending, []
            taken, self._taken = self._taken, None
        self._spool(left)
        if taken and left:
            try:
                os.remove(taken)
            except OSError:
                pass

    def _relative(self, stack):
        return stack.replace(self.root + os.sep, "").replace(self.root + "/", "") if self.root else stack

    def capture_exception(self, error, request=None, status=0, kind="handled"):
        """request: {"method", "path", "route", "session_id"} (the integrations fill it in)."""
        if not self.core.is_on("errors"):
            return
        try:
            is_error = isinstance(error, BaseException)
            if request is None:
                request = _request_fields()
            # A visitor who hung up mid-request isn't a server error. Only
            # what the integrations (or logging) saw in a request: an error
            # you hand over yourself is sent whatever it is.
            if (is_error and kind != "handled" and (int(status or 0) >= 500 or request)
                    and is_disconnect(error)):
                return
            # The framework, your handler and logging can all see one error:
            # sent once, and a later capture fills in the event while it waits.
            if is_error and getattr(error, SEEN, None) is not None:
                self._upgrade(error, getattr(error, SEEN), request, status, kind)
                return
            stack = "".join(traceback.format_exception(type(error), error, error.__traceback__)) if is_error else ""
            event = {
                "message": (str(error) or (type(error).__name__ if is_error else "Unknown error"))[:MAX_MESSAGE],
                "error_type": type(error).__name__ if is_error else "Error",
                "stack": self._relative(stack),
                "kind": kind,
                "status_code": int(status or 0),
                "runtime": "Python",
                "runtime_version": host.python_version(),
                "os": sys.platform,
                "server_name": self.server_name,
                "release": self.release,
                # When it happened: a crash sent after a restart keeps its own time.
                "at": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            }
            trail = _breadcrumbs()
            if trail:
                event["breadcrumbs"] = trail
            event.update({k: str(v or "") for k, v in (request or {}).items() if k in ("method", "path", "route", "session_id")})
            if event.get("path"):
                event["path"] = event["path"].split("?")[0]
                # Named as Server speed names the request, so the two match.
                if not event.get("route"):
                    event["route"] = normalize_route(event["path"])
            if self.before_send:
                event = self.before_send(event, error)
                if not event:
                    return
            with self.lock:
                if len(self.queue) >= QUEUE_MAX:
                    self.core.log("errors", "queue full, error dropped")
                    return
                self.queue.append(event)
                full = len(self.queue) >= BATCH
            if is_error:
                try:
                    setattr(error, SEEN, event)
                except Exception:
                    pass
            if full and self.job:
                self.job.run_now()
        except Exception as failure:
            self.core.log("errors", "could not capture error:", failure)

    def _upgrade(self, error, waiting, request, status, kind):
        """An exception logged and then raised on is captured first as
        "logged", with no status; the framework's capture that follows knows
        the status, the kind and the request."""
        if kind == "logged":
            return
        with self.lock:
            index = next((i for i, queued in enumerate(self.queue) if queued is waiting), -1)
            if index == -1:
                return
            event = dict(waiting, kind=kind if waiting.get("kind") == "logged" else waiting.get("kind"),
                         status_code=waiting.get("status_code") or int(status or 0))
            for key in ("method", "path", "route", "session_id"):
                if not event.get(key) and (request or {}).get(key):
                    event[key] = str(request[key])
            if event.get("path"):
                event["path"] = event["path"].split("?")[0]
            if self.before_send:
                event = self.before_send(event, error)
            if event:
                self.queue[index] = event
                setattr(error, SEEN, event)
            else:
                del self.queue[index]

    def flush(self, resend=True):
        with self.lock:
            waiting, self.queue = self.queue, []
        sent = True
        for i in range(0, len(waiting), BATCH):
            body = {"errors": waiting[i:i + BATCH]}
            res = self.core.send("errors", "/events/server-errors", body=body)
            # Tried once more a little later, but not when the process is
            # ending: what's left waits in the file instead.
            if _failed(res) and time_left() is None:
                time.sleep(RETRY_AFTER)
                res = self.core.send("errors", "/events/server-errors", body=body)
            if _failed(res):
                sent = False
                self._spool(body["errors"])
        # Not straight after the collector failed this flush (it would only
        # wait out another timeout), nor when the process is ending.
        if (resend and sent and self.spool_file and time_left() is None
                and time.time() - self._last_resend >= RESEND_EVERY):
            self.resend()

    def _spool(self, events):
        """Appends events to the file. Credentials are added when sent, never written down."""
        if not self.spool_file or not events:
            return
        try:
            lines = []
            for event in events:
                try:
                    lines.append((json.dumps(event, allow_nan=False) + "\n").encode("utf-8"))
                except (TypeError, ValueError):
                    continue  # not JSON: it couldn't be sent later either
            have = os.path.getsize(self.spool_file) if os.path.exists(self.spool_file) else 0
            # What fits, oldest first: the file never grows past SPOOL_BYTES,
            # this write included.
            room = SPOOL_BYTES - have
            kept = []
            for line in lines:
                room -= len(line)
                if room < 0:
                    break
                kept.append(line)
            if len(kept) < len(lines):
                self.core.log("errors", "waiting errors file is full, %d errors dropped" % (len(lines) - len(kept)))
            if not kept:
                return
            fd = os.open(self.spool_file, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            with os.fdopen(fd, "ab") as out:
                out.write(b"".join(kept))
        except Exception as failure:
            self.core.log("errors", "could not keep errors to send later:", failure)

    def resend(self):
        """Sends what earlier attempts (or an earlier run) couldn't. Taken by
        renaming the file first, so two processes never send the same errors."""
        self._last_resend = time.time()
        if not self.spool_file or not self._resend_lock.acquire(blocking=False):
            return
        try:
            self._resend()
        finally:
            self._resend_lock.release()

    def _take(self):
        """The files to send: the waiting file, renamed to one of our own,
        and any a killed process left half sent."""
        mine = "%s.%d.%d.sending" % (self.spool_file, os.getpid(), threading.get_ident())
        taken = []
        try:
            os.replace(self.spool_file, mine)
            taken.append(mine)
        except OSError:
            pass  # nothing waiting
        now = time.time()
        for left in glob.glob(glob.escape(self.spool_file) + ".*.sending"):
            if left == mine:
                continue
            try:
                if now - os.path.getmtime(left) < ORPHAN_S:
                    continue  # another process is sending it
                adopted = "%s.%d.%d.%d.sending" % (self.spool_file, os.getpid(), threading.get_ident(), len(taken))
                os.replace(left, adopted)
                taken.append(adopted)
            except OSError:
                continue
        return taken

    def _rewrite(self, path, events):
        """What a file still has to send, after a batch went: written whole,
        or the file removed once it is all sent. Deleted only then, so a
        process killed mid-send leaves its errors on disk, not nowhere."""
        if not events:
            os.remove(path)
            return
        temp = path + ".tmp"
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            out.write("".join(json.dumps(event) + "\n" for event in events))
        os.replace(temp, path)

    def _resend(self):
        for taken in self._take():
            if not self._resend_file(taken):
                return

    def _resend_file(self, taken):
        """True when the file was all sent (or given up), False when the
        collector failed and the rest went back in the waiting file."""
        events = []
        try:
            with open(taken, encoding="utf-8") as waiting:
                for line in waiting:
                    try:
                        event = json.loads(line)
                    except ValueError:
                        continue
                    if isinstance(event, dict):
                        events.append(event)
        except OSError:
            return True
        with self.lock:
            self._resending = events
            self._taken = taken
        try:
            while True:
                with self.lock:
                    if self._resending is not events:
                        return True  # written back by a crash
                    if not events:
                        break
                    batch = events[:BATCH]
                if _failed(self.core.send("errors", "/events/server-errors", body={"errors": batch})):
                    with self.lock:
                        mine = self._resending is events
                        left = events if mine else []
                        self._resending = []
                        if mine:
                            self._taken = None
                    if mine:
                        self._spool(left)
                        self._remove(taken)
                    return False
                with self.lock:
                    if self._resending is not events:
                        return True
                    del events[:len(batch)]
                    try:
                        self._rewrite(taken, events)
                    except OSError as failure:
                        self.core.log("errors", "could not update the errors being sent:", failure)
            self._remove(taken)
            return True
        finally:
            with self.lock:
                if self._resending is events:
                    self._resending = []
                    self._taken = None

    @staticmethod
    def _remove(path):
        try:
            os.remove(path)
        except OSError:
            pass

    def _flush_job(self):
        self.flush()
        return FLUSH_EVERY

    def close(self):
        if self.job:
            self.job.stop()
        if self._previous:
            sys.excepthook, threading.excepthook = self._previous
            self._previous = None
        if self._log_handler:
            logging.getLogger().removeHandler(self._log_handler)
            self._log_handler = None
        self.flush()
