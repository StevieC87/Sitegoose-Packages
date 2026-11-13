"""First-party proxy: serving the tracker from the site's own domain, so ad
blockers don't hide visitors.

Blockers stop analytics by recognising the address a script comes from and
what it is called ("track.js", "collect"). The answer is to serve both from
the site's own domain, which until now meant writing Nginx, Cloudflare or
Vercel rules by hand. This app is already a server on that domain, so the
package does it itself:

    <prefix>/js/<rest>   ->  <endpoint>/<rest>                  (tracker files)
    <prefix>/api/<rest>  ->  <endpoint>/collectanalytics/<rest> (the collector)

The same two rules as the hand-written ones, so one install check covers both.
The prefix comes from the site secret: not guessable from the page, and the
same every time, so a browser's cache and a CDN in front stay valid.

It answers before every other module: a visitor's beacon is our own traffic,
not a page of the site, so it shouldn't be counted, timed or rate-limited.
"""
import hashlib
import re
import threading
import time
import urllib.error
import urllib.request

# The tracker files, by name: anything else is refused rather than forwarded.
FILES = frozenset((
    "track.js", "s.js", "snapshot.js", "replay.js", "survey.js", "banner.js",
    "leadform.js", "notice.js", "editor.js", "picker.js", "feedback.js", "shield.js",
    "widget.js", "share.js",
))
# A pinned version never changes; /v<major>/ follows new releases, so it is
# held for an hour, the same as the collector serves it with.
TTL_PINNED_S = 7 * 24 * 60 * 60
TTL_MAJOR_S = 60 * 60
# The proxy runs on the site's own request threads: a collector that stops
# answering must not hold them. Short waits (urllib has one timeout, for the
# connection and each read), and after BREAKER_FAILURES failures in a row the
# collector is left alone for BREAKER_OPEN_S: answered straight away instead.
TIMEOUT = 2
BREAKER_FAILURES = 3
BREAKER_OPEN_S = 30
# A tracker file that couldn't be fetched isn't asked for again for this long.
FILE_RETRY_S = 30
MAX_BODY = 6 * 1024 * 1024
# The collector reads these; everything else, cookies above all, stays here.
PASS_HEADERS = ("content-type", "user-agent", "accept-language", "referer", "origin",
                "sec-fetch-site", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform")
SAFE_PATH = re.compile(r"[A-Za-z0-9/_.-]{1,120}\Z")
FILE_PATH = re.compile(r"v(\d+(?:\.\d+\.\d+)?)/([a-z]+\.js)\Z")
# What a collector answer may be served as from the site's own domain. Its
# type comes from the collector, so anything but these three becomes plain
# text, and nosniff stops a browser guessing: a server that is no longer ours
# still can't answer <prefix>/api/... with a page that runs as the customer's
# own site. Shared cases: sdk/protocols/proxy-answer-cases.json.
ANSWER_TYPES = frozenset(("application/json", "text/plain", "image/webp"))
_VISIBLE = re.compile(r"[\x20-\x7e]*")


def answer_type(value):
    value = value if isinstance(value, str) else ""
    kind = value.split(";", 1)[0].strip().lower()
    return value if kind in ANSWER_TYPES and _VISIBLE.fullmatch(value) else "text/plain; charset=utf-8"


NOT_FOUND = (404, [("Content-Type", "text/plain; charset=utf-8")], b"Not found")


def prefix_for(secret):
    return hashlib.sha256(("proxy|" + str(secret)).encode("utf-8")).hexdigest()[:8]


# Sent as X-Proxy-Key, so the collector believes the visitor addresses this
# proxy passes on: anyone can write X-Forwarded-For. Worked out from the secret
# as the collector does (expresscollect/utils/proxyKey.js).
def key_for(secret):
    return hashlib.sha256(("proxykey|" + str(secret)).encode("utf-8")).hexdigest()[:32]


class Proxy:
    """prefix: the path it answers on (default: from the secret)."""

    def __init__(self, core, prefix=None, enabled=True):
        self.core = core
        self.enabled = enabled
        self.prefix = re.sub(r"[^A-Za-z0-9_-]", "", str(prefix or prefix_for(core.secret)))
        self.key = key_for(core.secret) if core.secret else ""
        # One copy of each tracker file, so a repeat visitor costs no upstream
        # request. A handful of small files: it never grows.
        self._files = {}
        # When each file last failed to arrive (any version fits the pattern,
        # so the list is kept short).
        self._failed = {}
        self._lock = threading.Lock()
        self._failures = 0
        self._open_until = 0.0

    def resting(self):
        """True while the collector is being left alone (after
        BREAKER_FAILURES failures in a row). When the pause ends one request
        tries again; the others keep the short answer until it has."""
        now = time.monotonic()
        with self._lock:
            if self._failures < BREAKER_FAILURES:
                return False
            if now < self._open_until:
                return True
            self._open_until = now + TIMEOUT * 2
            return False

    def _worked(self):
        with self._lock:
            self._failures = 0

    def _broke(self):
        with self._lock:
            self._failures += 1
            if self._failures >= BREAKER_FAILURES:
                self._open_until = time.monotonic() + BREAKER_OPEN_S

    def _remember_failure(self, rest):
        with self._lock:
            self._failed.pop(rest, None)
            while len(self._failed) >= 200:
                del self._failed[next(iter(self._failed))]
            self._failed[rest] = time.monotonic()

    def _recently_failed(self, rest):
        with self._lock:
            at = self._failed.get(rest)
            return at is not None and at > time.monotonic() - FILE_RETRY_S

    def on(self):
        return bool(self.enabled and self.core.valid and self.prefix and self.core.is_on("proxy"))

    def script_url(self, version="1"):
        """The tracker's address on this site, for the page's script tag."""
        return "/%s/js/v%s/s.js" % (self.prefix, version)

    def collect_url(self):
        """Where visits are sent, for the tag's data-collect."""
        return "/%s/api/e" % self.prefix

    def match(self, path):
        """("js" | "api", the rest) when the address is ours, else None."""
        if not self.on():
            return None
        head = "/%s/" % self.prefix
        if not path.startswith(head):
            return None
        rest = path[len(head):]
        for kind in ("js", "api"):
            if rest.startswith(kind + "/"):
                tail = rest[len(kind) + 1:]
                if tail and ".." not in tail and SAFE_PATH.match(tail):
                    return kind, tail
                break
        return "bad", ""

    def handle(self, kind, rest, method="GET", query="", headers=None, body=None, client_ip=""):
        """(status, [(name, value)], body). Blocking: an ASGI caller runs it
        in a thread so the event loop keeps turning."""
        if kind == "js":
            return self._file(rest)
        if kind != "api":
            return NOT_FOUND
        return self._collector(rest, method, query, headers or {}, body, client_ip)

    def _file(self, rest):
        found = FILE_PATH.match(rest)
        if not found or found.group(2) not in FILES:
            return NOT_FOUND
        pinned = "." in found.group(1)
        held = self._files.get(rest)
        body = None
        if held and held[1] > time.time() - (TTL_PINNED_S if pinned else TTL_MAJOR_S):
            body = held[0]
        if body is None and not self._recently_failed(rest) and not self.resting():
            try:
                request = urllib.request.Request(self.core.endpoint + "/" + rest, method="GET")
                with urllib.request.urlopen(request, timeout=TIMEOUT) as answer:
                    fetched = answer.read(MAX_BODY)
                self._worked()
                if len(fetched) > 500:
                    body = fetched
                    self._files[rest] = (body, time.time())
                    with self._lock:
                        self._failed.pop(rest, None)
                else:
                    self._remember_failure(rest)
            except urllib.error.HTTPError as answer:
                # The collector answered: only its own failures count against it.
                self._broke() if answer.code >= 500 else self._worked()
                self._remember_failure(rest)
            except Exception as error:
                self._broke()
                self._remember_failure(rest)
                self.core.log("proxy", "could not fetch %s: %s" % (rest, error))
        # Upstream is unreachable: an old copy beats no tracker at all.
        if body is None and held:
            body = held[0]
        if body is None:
            return 502, [], b""
        return 200, [
            ("Content-Type", "application/javascript; charset=utf-8"),
            ("Cache-Control", "public, max-age=31536000, immutable" if pinned else "public, max-age=3600"),
            ("X-Content-Type-Options", "nosniff"),
        ], body

    def _collector(self, rest, method, query, headers, body, client_ip):
        method = (method or "GET").upper()
        if method == "OPTIONS":
            # Same origin as the page, so a preflight shouldn't happen; answer
            # it cheaply rather than passing it on.
            return 204, [("Access-Control-Allow-Methods", "GET, POST, OPTIONS"),
                         ("Access-Control-Allow-Headers", "Content-Type"),
                         ("Access-Control-Max-Age", "86400")], b""
        if method not in ("GET", "POST"):
            return NOT_FOUND
        if body is not None and len(body) > MAX_BODY:
            return 413, [], b""
        # The visitor's address: the collector needs it for the country, the
        # daily visitor ID and the per-visitor rate limit.
        out = {"X-Forwarded-For": client_ip or ""}
        if self.key:
            out["X-Proxy-Key"] = self.key
        for name in PASS_HEADERS:
            value = headers.get(name)
            if value:
                out[name.title()] = str(value).replace("\r", "").replace("\n", "")
        url = self.core.endpoint + "/collectanalytics/" + rest + (("?" + query) if query else "")
        # Left alone for now: answered straight away; the tracker treats a
        # failed beacon as lost and carries on.
        if self.resting():
            return 502, [("Retry-After", str(BREAKER_OPEN_S))], b""
        request = urllib.request.Request(url, data=body if method == "POST" else None, headers=out, method=method)
        try:
            with urllib.request.urlopen(request, timeout=TIMEOUT) as answer:
                result = answer.status, self._answer_headers(answer.headers), answer.read(MAX_BODY)
            self._worked()
            return result
        except urllib.error.HTTPError as answer:
            self._broke() if answer.code >= 500 else self._worked()
            return answer.code, self._answer_headers(answer.headers), answer.read(MAX_BODY)
        except Exception as error:
            # The tracker already treats a failed beacon as lost and carries on.
            self._broke()
            self.core.log("proxy", "could not reach the collector: %s" % error)
            return 502, [], b""

    @staticmethod
    def _answer_headers(headers):
        out = [("Content-Type", answer_type(headers.get("Content-Type"))), ("X-Content-Type-Options", "nosniff")]
        for name in ("Cache-Control", "Retry-After"):
            value = headers.get(name)
            if value:
                out.append((name, value))
        return out

    def flush(self):
        pass

    def close(self):
        pass
