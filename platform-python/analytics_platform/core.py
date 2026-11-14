"""What every module shares: the site's credentials, sending to the
collector, logging, background jobs, and the dashboard's module switches
(Site settings -> Server, GET /events/platform/config about once a minute).

A module the dashboard turns off stays loaded but does nothing; until the
switches arrive, or when they can't be fetched, every loaded module stays on.
Sending never raises into the app. Background jobs are daemon threads that
start again in a forked worker (gunicorn, uWSGI), where threads don't survive.
"""
import atexit
import contextlib
import datetime as _dt
import decimal
import json
import math
import os
import platform
import re
import socket
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

VERSION = "0.3.12"
TIMEOUT = 5
MIN_SYNC = 30
RETRY = 60
SESSION_HEADER = "x-analytics-session"


class Response:
    def __init__(self, status, headers, body):
        self.status = status
        self.headers = headers
        self.body = body
        # True when the body could not be turned into JSON: nothing was sent,
        # and sending it again would fail the same way (unlike a network
        # failure, which send() answers with None).
        self.unsendable = False

    @property
    def ok(self):
        return 200 <= self.status < 300

    def json(self):
        try:
            return json.loads(self.body or b"null")
        except ValueError:
            return None


# No fork while another thread is sending to the collector: a thread inside
# OpenSSL at the fork leaves its lock held in the child, whose first request
# then waits on it forever (gunicorn --preload: a worker that never checked
# in; an RQ work horse stuck on its last send). A fork waits for the sends in
# flight, at most their timeout; a send waits for a fork.
_gate = threading.Condition()
_sends = {"in_flight": 0, "forking": False}


@contextlib.contextmanager
def _no_fork_meanwhile():
    with _gate:
        _gate.wait_for(lambda: not _sends["forking"], timeout=TIMEOUT)
        _sends["in_flight"] += 1
    try:
        yield
    finally:
        with _gate:
            _sends["in_flight"] -= 1
            _gate.notify_all()


def _before_fork():
    with _gate:
        _sends["forking"] = True
        _gate.wait_for(lambda: _sends["in_flight"] == 0, timeout=TIMEOUT + 1)


def _after_fork_in_parent():
    with _gate:
        _sends["forking"] = False
        _gate.notify_all()


def _after_fork_in_child():
    global _gate
    _gate = threading.Condition()  # another thread may have held it at the fork
    _sends.update(in_flight=0, forking=False)


if hasattr(os, "register_at_fork"):
    os.register_at_fork(before=_before_fork, after_in_parent=_after_fork_in_parent, after_in_child=_after_fork_in_child)

# At exit (and a job runner's shutdown) everything waiting gets one overall
# deadline, so the package never outlasts a container's or PM2's grace period
# (30 s, and it is the app's to use): each send waits at most what's left,
# none starts after it, no retry sleeps, and what wasn't sent waits in the
# errors file.
EXIT_DEADLINE = 5
_deadline = {"ends": None}


def _clock():
    return time.monotonic()


@contextlib.contextmanager
def within(seconds=EXIT_DEADLINE):
    """Every send (and job stop) inside the block ends within seconds from now."""
    before = _deadline["ends"]
    ends = _clock() + seconds
    _deadline["ends"] = ends if before is None else min(before, ends)
    try:
        yield
    finally:
        _deadline["ends"] = before


def begin_exit(seconds=EXIT_DEADLINE):
    """The process is ending: a deadline from now on for everything still to
    do, never lifted (the first exit hook starts it, the others share it)."""
    ends = _clock() + seconds
    before = _deadline["ends"]
    _deadline["ends"] = ends if before is None else min(before, ends)


def time_left():
    """Seconds left before the deadline, or None when there is none."""
    ends = _deadline["ends"]
    return None if ends is None else max(0.0, ends - _clock())


def send_timeout(normal):
    """How long one send may wait: normal, cut to what's left of a deadline,
    None once it has passed (nothing more is sent)."""
    left = time_left()
    if left is None:
        return normal
    if left < 0.05:
        return None
    return min(normal, left)


def plain(value, depth=0):
    """value as what JSON carries, taken when it is handed over: a date as
    ISO text, a Decimal as a number, a set or tuple as a list, bytes as
    text, NaN and infinity as null (the collector's JSON has neither), and
    anything else as its str(). So a payload can't fail at flush time, when
    it would take the rest of its batch with it, and the app changing an
    object afterwards doesn't change what is sent."""
    if value is None or isinstance(value, (bool, str)):
        return value
    if isinstance(value, int):
        return int(value)
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if depth >= 20:
        return str(value)
    if isinstance(value, dict):
        return {str(k): plain(v, depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [plain(v, depth + 1) for v in value]
    if isinstance(value, (_dt.datetime, _dt.date, _dt.time)):
        return value.isoformat()
    if isinstance(value, decimal.Decimal):
        return float(value) if value.is_finite() else None
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).decode("utf-8", "replace")
    try:
        return str(value)
    except Exception:
        return "<%s>" % type(value).__name__


_running = []


def _stop_all():
    """At exit: background threads finish before Python shuts down (a daemon
    thread still running then can crash the interpreter). All told to stop
    first, then waited for, within the exit deadline."""
    begin_exit()
    jobs = list(_running)
    for job in jobs:
        job.stop(wait=0)
    for job in jobs:
        job.join(2.0)


atexit.register(_stop_all)


class Periodic:
    """Runs job() in a daemon thread; job returns the seconds until its next run."""

    def __init__(self, job, first=0.0):
        self.job = job
        self.first = first
        self.stopped = threading.Event()
        self.wake = threading.Event()
        self.thread = None
        # Set just before a fork whose child shouldn't run this job (see
        # Core.fork_quietly); the parent clears it once it has forked.
        self.not_in_next_child = False
        self._start()
        _running.append(self)
        if hasattr(os, "register_at_fork"):
            os.register_at_fork(after_in_child=self._forked, after_in_parent=self._parent_forked)

    def _forked(self):
        if self.not_in_next_child:
            self.stopped.set()
            if self in _running:
                _running.remove(self)
            return
        self._start()

    def _parent_forked(self):
        self.not_in_next_child = False

    def _start(self):
        if self.stopped.is_set():
            return
        self.wake = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True, name="analytics-platform")
        self.thread.start()

    def _run(self):
        wait = self.first
        while not self.stopped.is_set():
            self.wake.wait(wait)
            self.wake.clear()
            if self.stopped.is_set():
                return
            try:
                wait = self.job()
            except Exception:  # never let a job die
                wait = RETRY

    def run_now(self):
        self.wake.set()

    def stop(self, wait=2.0):
        """Stops the job and waits (up to wait seconds, cut to a deadline's
        rest) for its thread to end."""
        self.stopped.set()
        self.wake.set()
        if self in _running:
            _running.remove(self)
        self.join(wait)

    def join(self, wait):
        left = time_left()
        if wait and left is not None:
            wait = min(wait, left)
        thread = self.thread
        if wait and wait > 0 and thread is not None and thread.is_alive() and thread is not threading.current_thread():
            thread.join(wait)


def _rss_mb():
    """This process's resident memory in MB, where the platform says (Linux
    /proc; elsewhere the peak, from resource); None when neither can."""
    try:
        with open("/proc/self/statm") as statm:
            return round(int(statm.read().split()[1]) * os.sysconf("SC_PAGE_SIZE") / 1048576)
    except Exception:
        pass
    try:
        import resource
        import sys
        peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        return round(peak / 1048576 if sys.platform == "darwin" else peak / 1024)
    except Exception:
        return None


# The names a package may give itself in its User-Agent: the collector hands a
# request rule aimed at Django only to a client that says it is Django
# (expresscollect/Analytics/firewall.js, clientOf and PLATFORMS).
CLIENTS = ("python", "django")



# A dashboard header is added only when it is one of the nine the dashboard
# can produce (expresscollect/Analytics/platform.js, headersOf), in any case,
# with a value of visible ASCII, spaces and tabs, so no line break, control
# character or byte a server rejects gets through. A list of what's allowed,
# not of what isn't: whoever got into our servers still couldn't make this
# app grant another site its users' data (Access-Control-Allow-*), send every
# page elsewhere (Refresh), log everyone out (Clear-Site-Data) or change what
# a response is. Shared cases: sdk/protocols/header-cases.json.
SECURITY_HEADERS = frozenset((
    "strict-transport-security", "x-content-type-options", "x-frame-options", "referrer-policy",
    "permissions-policy", "cross-origin-opener-policy", "content-security-policy",
    "content-security-policy-report-only", "reporting-endpoints"))
_HEADER_VALUE = re.compile(r"[\x20-\x7e\t]*")


def safe_header(pair):
    return (isinstance(pair, (list, tuple)) and len(pair) == 2 and isinstance(pair[0], str)
            and pair[0].lower() in SECURITY_HEADERS
            and isinstance(pair[1], str) and len(pair[1]) <= 4000 and _HEADER_VALUE.fullmatch(pair[1]) is not None)

class Core:
    def __init__(self, site_id, secret, endpoint, debug=False, server_name=None, client="python"):
        self.site_id = str(site_id or "")
        # The name this service checks in under (X-Platform-App, on the switches
        # request): server_name, as every module sends it, else the machine's.
        self.server_name = str(server_name or socket.gethostname())[:100]
        self._started = time.time()
        self.secret = str(secret or "")
        self.endpoint = str(endpoint or "").rstrip("/")
        self.valid = bool(re.fullmatch(r"[a-fA-F0-9]{24}", self.site_id) and self.secret and self.endpoint)
        self.debug = bool(debug)
        self.user_agent = "analytics-platform-%s/%s" % (client if client in CLIENTS else "python", VERSION)
        self._switches = {}
        self._headers = []
        self._flags = {}
        self._maintenance = {"on": False}
        self._etag = ""
        self._loaded = []
        self._job = None

    def log(self, module, *args):
        if self.debug:
            print("[analytics-platform:%s]" % module, *args)

    def send(self, module, path, method="POST", body=None, auth="body", headers=None):
        """JSON to the collector. auth "body" puts site_id and sitesecret in
        the body (the event endpoints), "bearer" sends the secret as a header
        (firewall, switches). Returns a Response, or None when it couldn't be sent."""
        if not self.valid:
            return None
        wait = send_timeout(TIMEOUT)
        if wait is None:
            self.log(module, "not sent: the process is ending (%s)" % path)
            return None
        all_headers = {"User-Agent": self.user_agent}
        data = None
        if body is not None:
            if auth == "body":
                body = dict(body, site_id=self.site_id, sitesecret=self.secret)
            try:
                data = json.dumps(body, allow_nan=False).encode("utf-8")
            except (TypeError, ValueError, RecursionError) as error:
                # Not a network failure: sending it again would fail the same way.
                self.log(module, "not sent, not JSON (%s): %s" % (path, error))
                unsendable = Response(0, {}, b"")
                unsendable.unsendable = True
                return unsendable
            all_headers["Content-Type"] = "application/json"
        if auth == "bearer":
            all_headers["Authorization"] = "Bearer " + self.secret
        all_headers.update(headers or {})
        request = urllib.request.Request(self.endpoint + path, data=data, headers=all_headers, method=method)
        try:
            with _no_fork_meanwhile(), urllib.request.urlopen(request, timeout=wait) as res:
                return Response(res.status, {k.lower(): v for k, v in res.headers.items()}, res.read())
        except urllib.error.HTTPError as error:
            if error.code != 304:
                self.log(module, "collector answered %s to %s" % (error.code, path))
            return Response(error.code, {k.lower(): v for k, v in (error.headers or {}).items()}, error.read() if error.fp else b"")
        except Exception as error:
            self.log(module, "could not reach the collector (%s): %s" % (path, error))
            return None

    # ---- Module switches ----

    def is_on(self, name):
        """False only when the dashboard turned the module off."""
        return self._switches.get(name) is not False

    def _check_in(self):
        """This service's check-in, form-encoded so any name is plain ASCII:
        Health -> All systems shows it running and when it was last heard from.
        None when it can't be built: the switches still sync, without it."""
        try:
            fields = {"server": self.server_name, "kind": "process", "pid": os.getpid(),
                      "up_s": int(time.time() - self._started), "runtime": "Python " + platform.python_version()}
            rss = _rss_mb()
            if rss is not None:
                fields["rss_mb"] = rss
            return urllib.parse.urlencode(fields) if self.server_name else None
        except Exception:
            return None

    def _sync_switches(self):
        headers = {"X-Platform-Modules": ",".join(self._loaded)}
        app = self._check_in()
        if app:
            headers["X-Platform-App"] = app
        if self._etag:
            headers["If-None-Match"] = self._etag
        res = self.send("core", "/events/platform/config?site_id=" + self.site_id, method="GET", auth="bearer", headers=headers)
        if res is not None and res.status == 200:
            data = res.json() or {}
            if data.get("v") == 1 and isinstance(data.get("modules"), dict):
                self._switches = data["modules"]
                self._flags = data.get("flags") if isinstance(data.get("flags"), dict) else {}
                self._maintenance = data.get("maintenance") if isinstance(data.get("maintenance"), dict) else {"on": False}
                self._headers = [(p[0], p[1]) for p in data.get("headers") or [] if safe_header(p)]
                self._etag = res.headers.get("etag", "")
            return max(MIN_SYNC, int(data.get("sync") or RETRY))
        return RETRY

    def flags(self):
        return self._flags

    def maintenance(self):
        return self._maintenance

    def security_headers(self):
        """The security headers picked on the dashboard, when the module is on."""
        return list(self._headers) if self.is_on("headers") else []

    def start(self, names):
        """Starts fetching the switches; names are the modules the code loaded."""
        self._loaded = list(names)
        if self.valid:
            self._job = Periodic(self._sync_switches)

    def stop(self):
        if self._job:
            self._job.stop()

    def fork_quietly(self, on=True):
        """The next fork is a child that lives for one job (an RQ work horse):
        it keeps the switches it inherits and neither fetches them nor checks
        in, so Health -> All systems shows the long-lived parent, not a new
        process per job. A forked worker that lives on (gunicorn) still checks
        in on its own. on=False takes it back (no fork happened)."""
        if self._job:
            self._job.not_in_next_child = on


def header(headers, name):
    """A header from a dict with lowercase names (or None)."""
    value = headers.get(name.lower())
    return value.strip() if isinstance(value, str) else ""


# The characters a path may carry unencoded (RFC 3986), which quote() leaves alone.
_PATH_SAFE = "/:@!$&'()*+,;=-._~"


# A scheme, then the authority only when "//" follows it (firewall.md, "Matching").
_ABSOLUTE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*:(?://[^/?#]*)?")


def origin_form(target):
    """The request target as the app routes it: an absolute-form one ("GET
    http://host/admin", sent as if to a proxy) is routed by its path, so it is
    cut to "/admin"; matched as written it began "http:" and missed every rule
    on "/admin". gunicorn's urlsplit reads "x:/admin" and "x:admin" as
    "/admin" too, with no "//" at all, so the scheme goes whatever follows it.
    "*" and a target already "/..." are kept as they are."""
    text = str(target or "")
    if not text or text.startswith("/") or text == "*":
        return text
    rest = _ABSOLUTE.sub("", text, count=1)
    return rest if rest.startswith("/") else "/" + rest


def request_target(path, query="", raw=None):
    """The request target as the visitor sent it, query string and all, which
    is what the request rules match (sdk/protocols/firewall.md): the Node and
    PHP clients hand over req.url and REQUEST_URI. raw: the server's own copy
    of it when it keeps one. Otherwise the path the framework has already
    decoded is encoded again, so the rules' one decoding pass is the only one.
    path: text, or the bytes it was decoded from."""
    if isinstance(raw, bytes):
        raw = raw.decode("latin-1")
    if isinstance(raw, str) and raw:
        target = raw
    else:
        target = urllib.parse.quote(path or "", safe=_PATH_SAFE)
    if isinstance(query, bytes):
        query = query.decode("latin-1")
    if query and "?" not in target:
        target += "?" + query
    return target
