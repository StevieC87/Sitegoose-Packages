"""Firewall module: rules from the collector (GET /events/firewall/rules,
protocol in sdk/protocols/firewall.md) every minute or so; every request is
checked against them in memory, so the app never waits on the collector.
What was blocked (or, in monitor mode, would have been) goes back in batches.

Fails open: until rules arrive, and whenever the collector can't be reached,
requests pass (with the last rules that arrived, if any). The rate limit
and the page limits count in this process: with several workers, pass
`counter` (e.g. Redis) for one count across them.
"""
import bisect
import ipaddress
import json
import os
import re
import socket
import threading
import time
from datetime import datetime, timezone

from . import challenge as browser_check
from .core import Periodic, RETRY, header
from .request_rules import MAX_TEXT, _decode_once, compile_limits, compile_rules, match_limits, match_request, normalize_target, prepare

PROTOCOL = 1
MIN_SYNC = 30
FLUSH_EVERY = 5
BATCH = 200
QUEUE_MAX = 2000
COUNTER_MAX = 100000
MAPPED = 0xFFFF << 32  # IPv4 as ::ffff:a.b.c.d, so one sorted list holds both
# The layers this server runs (X-Firewall-Layers): the address firewall and the browser check.
LAYERS = "app check"
# What a page limit's 429 says (firewall.md, "Page limits"): the visitor is
# most likely a person refreshing checkout, so it says what to do.
LIMIT_BODY = b"Too many requests to this page. Please wait a little and try again."
# Files a page load asks for by the dozen: not counted against `rate` or the
# page limits (the agent's nginx limit leaves the same extensions out), so a
# page with 40 images, scripts and fonts is one hit, not 41; and the asset
# folders (firewall.md, `rate`): /static/ is Django's and Flask's default for
# the files the app serves itself (WhiteNoise too). The extension follows a
# name in the last segment, not starts it: "/login/.css" is no file.
STATIC = re.compile(r"/[^/.][^/]*\.(?:css|js|mjs|map|png|jpe?g|gif|webp|avif|svg|ico|bmp|woff2?|ttf|otf|eot|mp4|webm|ogg|mp3|wav|pdf|wasm)\Z")
STATIC_PREFIXES = ("/static/", "/_next/static/", "/assets/")
# In a path decoded once: a "%xx" still there (double encoding, which a
# router that decodes again reads differently), a ";" (a path parameter to
# some servers and proxies, part of the name to others), a "\\" (a "/" to
# some), a "?" or "#" that was encoded, or a control character.
_UNSURE = re.compile(r"%[0-9a-fA-F]{2}|[;\\?#\x00-\x1f\x7f]")
# Only GET and HEAD fetch a file: a form posts to a page (Django's
# re_path(r"^login") takes POST /login.css too). No method given reads as GET.
_FETCHES = ("", "GET", "HEAD")
_ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


def ip_key(text):
    """An address as an int in IPv6 space, or None when invalid."""
    try:
        ip = ipaddress.ip_address(str(text).strip().split("%")[0])
    except ValueError:
        return None
    if ip.version == 4:
        return MAPPED | int(ip)
    return int(ip)


def parse_range(entry):
    """'1.2.3.0/24' -> (start, end) as ip_key()s, or None. None too for an
    IPv6 range that holds all of ::ffff:0:0/96 (::/64, ::/0): with IPv4 kept
    as ::ffff:a.b.c.d it would match every IPv4 visitor, a /64 that is one
    machine in IPv6 being the whole IPv4 internet here."""
    try:
        net = ipaddress.ip_network(str(entry).strip(), strict=False)
    except ValueError:
        return None
    start, end = int(net.network_address), int(net.broadcast_address)
    if net.version == 4:
        return MAPPED | start, MAPPED | end
    if start <= MAPPED and end >= MAPPED | 0xFFFFFFFF:
        return None
    return start, end


class IpSet:
    """Addresses and ranges, merged and sorted, looked up by binary search."""

    def __init__(self, entries=()):
        ranges = sorted(r for r in (parse_range(e) for e in entries if isinstance(e, str)) if r)
        self.starts, self.ends = [], []
        for start, end in ranges:
            if self.ends and start <= self.ends[-1] + 1:
                self.ends[-1] = max(self.ends[-1], end)
            else:
                self.starts.append(start)
                self.ends.append(end)

    def has(self, key):
        i = bisect.bisect_right(self.starts, key) - 1
        return i >= 0 and self.ends[i] >= key

    def __len__(self):
        return len(self.starts)


def compile_probes(probes):
    """The rules' probes (addresses of files no visitor asks for: .env,
    .git/...) -> {"exact": set, "prefix": tuple, "ban": seconds}, or None."""
    if not isinstance(probes, dict):
        return None
    def paths(key):
        return [p.lower() for p in probes.get(key) or [] if isinstance(p, str) and p]
    exact, prefix = set(paths("exact")), tuple(paths("prefix"))
    if not exact and not prefix:
        return None
    try:
        ban = max(0, int(probes.get("ban") or 0))
    except (TypeError, ValueError):
        ban = 0
    return {"exact": exact, "prefix": prefix, "ban": ban}


def is_probe(path, probes):
    """True when the path (no query, lower-cased, "//" as "/") is a probe, as
    sent or as the router reads it (";params" dropped, "." and ".." resolved,
    decoded once: "/x/..;/.env" is "/.env")."""
    if not probes:
        return False
    clean = re.sub(r"/{2,}", "/", re.split(r"[?#]", str(path or ""), 1)[0].lower())
    for text in {clean, normalize_target(path)}:
        if text in probes["exact"] or (bool(probes["prefix"]) and text.startswith(probes["prefix"])):
            return True
    return False


def is_static(path, method="GET"):
    """True for a request for a static file (by extension, or in an asset
    folder), read from the target as sent decoded once, as PATH_INFO has it,
    lower case, "//" as "/". Only a path every router reads the same way can
    be a file: one with a "." or ".." segment, a ";", a "\\", an encoded "/"
    or a "%xx" left after decoding is a page, so "/static/../login",
    "/static%2F..%2Flogin", "/login;x.css" and "/login%3Bx.css" all count. A
    browser asks for its files with none of those. Nor is a path past the
    rules' 2,000 characters: cut there, "/search/xxx...x.css/more" would end
    in .css and flood a catch-all route past the limits. Only GET and HEAD
    fetch a file."""
    if (method or "") not in _FETCHES:
        return False
    raw = re.split(r"[?#]", str(path or ""), 1)[0]
    if len(raw) > MAX_TEXT or not raw.startswith("/") or "%2f" in raw.lower():
        return False
    decoded = _decode_once(raw)
    if _UNSURE.search(decoded):
        return False
    # A-Z only, as every package: "İ" is "i" lower-cased by some.
    segments = decoded.translate(_ASCII_LOWER).split("/")
    if "." in segments or ".." in segments:
        return False
    parts = [segment for segment in segments if segment]
    clean = "/" + "/".join(parts)
    if parts and not segments[-1]:
        clean += "/"  # "/app.css/" isn't a file
    return clean.startswith(STATIC_PREFIXES) or STATIC.search(clean) is not None


# A response's Content-Type that is a file's (an image, a font, a script, a
# stylesheet, a video, a PDF, a download): what a route serving files answers.
_FILE_TYPES = re.compile(r"^(?:image|font|audio|video)/|^text/css|javascript|^application/(?:wasm|pdf|octet-stream|vnd\.ms-fontobject|(?:x-)?font)", re.I)


def routed_to_page(pattern, content_type=""):
    """After the response to a static-looking request (firewall.md, `rate`):
    whether the router sent it to a route of its own that isn't a file's, so
    it counts after all. pattern: the route it took (Django's
    resolver_match.route, Flask's url_rule.rule, Starlette's route.path), ""
    or None when none did. A pattern that is itself a file's by the same rule
    ("avatars/<int:id>.png", "/static/{path:path}") is left alone, and so is
    a route that answered a file's Content-Type."""
    if not pattern or _FILE_TYPES.search(str(content_type or "").strip()):
        return False
    text = str(pattern).lstrip("^").rstrip("$")
    return not is_static(text if text.startswith("/") else "/" + text)


def who(ip):
    """Who the rate limit, the login count and the bans here are about: an
    IPv4 address (::ffff:a.b.c.d as a.b.c.d), or an IPv6 address's /64, which
    one machine usually holds whole, as the browser check binds its pass.
    Keyed by the full address, a visitor rotating through its /64 would get a
    fresh count on every request. The /64 is written as its network,
    compressed ("2001:db8:1:2::/64"): every package builds the shared
    counter's key the same way (firewall.md), so a site mixing languages on
    one Redis counts a visitor once."""
    try:
        address = ipaddress.ip_address(str(ip).strip().split("%", 1)[0])
    except ValueError:
        return str(ip)
    if address.version == 6 and address.ipv4_mapped:
        address = address.ipv4_mapped
    if address.version == 4:
        return str(address)
    return ipaddress.IPv6Network((int(address) >> 64 << 64, 64)).compressed


def make_room(table):
    """A table at COUNTER_MAX loses its oldest entries (insertion order), not
    everyone's count at once: one /64 can mint any number of addresses, and
    clearing the table would reset every other visitor's count and ban."""
    while len(table) >= COUNTER_MAX:
        try:
            del table[next(iter(table))]
        except (StopIteration, KeyError, RuntimeError):
            return


def compile_page_limits(data):
    """The rules' page limits -> {"exempt": IpSet, "rules": [...]}, or None
    when there are none (absent, null, or every one malformed)."""
    if not isinstance(data, dict):
        return None
    limits = compile_limits(data)
    if not limits:
        return None
    return {"exempt": IpSet(data.get("exempt") or []), "rules": limits}


def compile_challenge(data):
    """The rules' browser check -> {"skip": prefixes, "exempt": IpSet}, or
    None when the site isn't to be checked."""
    if not isinstance(data, dict):
        return None
    return {"skip": browser_check.compile_skip(data.get("skip")), "exempt": IpSet(data.get("exempt") or [])}


def server_name():
    """This machine's host name for X-Server-Name: plain ASCII, 100 characters at most."""
    try:
        name = socket.gethostname()
    except Exception:
        return ""
    return re.sub(r"[^\x21-\x7e]", "", str(name or ""))[:100]


# Cloudflare's published ranges (cloudflare.com/ips), the same list as
# sdk/protocols/cloudflare-ranges.json (tests/test_firewall.py compares them):
# CF-Connecting-IP is believed only from these, since anyone who reaches the
# origin directly can send it.
CLOUDFLARE = (
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
    "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
    "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
    "2a06:98c0::/29", "2c0f:f248::/32",
)
_cloudflare = None


def from_cloudflare(ip):
    """True when a connection's address is one of Cloudflare's."""
    global _cloudflare
    key = ip_key(ip)
    if key is None:
        return False
    if _cloudflare is None:
        _cloudflare = IpSet(CLOUDFLARE)
    return _cloudflare.has(key)


_V4_PORT = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3}):\d{1,5}\Z")


def hop(text):
    """One hop of X-Forwarded-For (or CF-Connecting-IP) as an address:
    "[2001:db8::1]:443" and "203.0.113.5:54321" lose the port, as Azure App
    Service and Application Gateway send them."""
    s = str(text or "").strip()
    if s.startswith("["):
        close = s.find("]")
        return s[1:close] if close > 0 else s
    found = _V4_PORT.match(s)
    return found.group(1) if found else s


def client_ip(remote, headers, trust_proxy):
    """The visitor's address. trust_proxy: None/0 the connection's address; a
    number of proxies in X-Forwarded-For (True = 1); "cloudflare" reads
    CF-Connecting-IP, believed only when the connection comes from one of
    Cloudflare's addresses; a function gets the headers and returns it.

    A hop that isn't an address (a name, "unknown", whatever a client sent)
    gives the connection's address instead, so the firewall still checks the
    request rather than passing everything; a port on a hop is dropped.

    X-Forwarded-For is read from the right, as each proxy appends what it
    saw, so only entries your own proxies wrote are believed. Don't count a
    hop twice: a server that has already resolved the address *and removed
    what it used* from the header (Apache's mod_remoteip) leaves only the
    visitor's own entries there; with it, leave trust_proxy unset (README)."""
    remote = hop(remote)
    if callable(trust_proxy):
        given = hop(trust_proxy(headers) or "")
        return given if ip_key(given) is not None else remote
    if trust_proxy == "cloudflare":
        forwarded = hop(header(headers, "cf-connecting-ip"))
        return forwarded if from_cloudflare(remote) and ip_key(forwarded) is not None else remote
    hops = 1 if trust_proxy is True else (trust_proxy if isinstance(trust_proxy, int) else 0)
    if isinstance(trust_proxy, str) and re.fullmatch(r"[0-9]{1,2}", trust_proxy):
        hops = int(trust_proxy)
    if hops > 0:
        chain = [s.strip() for s in header(headers, "x-forwarded-for").split(",") if s.strip()]
        if chain:
            chosen = hop(chain[max(0, len(chain) - hops)])
            if ip_key(chosen) is not None:
                return chosen
    return remote


class Firewall:
    """Options: trust_proxy, mode ("monitor"/"block": overrides the dashboard),
    counter (callable(key, ttl) -> hits, shared between workers), cache_file
    (rules kept there between restarts)."""

    def __init__(self, core, trust_proxy=None, mode=None, counter=None, cache_file=None):
        self.core = core
        self.trust_proxy = trust_proxy
        self.mode = mode if mode in ("monitor", "block") else None
        self.counter = counter
        self.cache_file = cache_file
        self.rules = None
        self.etag = ""
        self.lock = threading.Lock()
        self.counts = {}
        # Page limits: (limit id, who, "") -> [window, hits], capped as counts is.
        self.limit_counts = {}
        # The counts per page (`each: "path"`), (limit id, who, page) ->
        # [window, hits], in a table of their own capped the same: anyone can
        # make thousands by asking for made-up paths, and in the same table
        # they would push the login limit's counts out mid-window and start
        # them again.
        self.page_counts = {}
        # With a shared counter: the counts this process saw go over (their
        # key, window and all), so a static file asked for after them can be
        # turned away without adding to them (a counter can only add).
        self.over_noted = {}
        self.queue = {}
        # Bot protection here: address -> when its ban ends; address -> [window start, failed logins].
        self.bans = {}
        self.logins = {}
        # The browser check's passes are signed with the site secret, so any
        # of the site's servers accepts one another handed out.
        self.pass_key = browser_check.pass_key(getattr(core, "secret", ""))
        if cache_file:
            try:
                with open(cache_file) as f:
                    cached = json.load(f)
                self.rules = self._compile(cached["rules"])
                self.etag = cached.get("etag", "")
            except (OSError, ValueError, KeyError, TypeError):
                pass
        self.jobs = []
        if core.valid:
            self.jobs = [Periodic(self._sync), Periodic(self._flush_job, FLUSH_EVERY)]

    def _compile(self, data):
        if not isinstance(data, dict) or data.get("v") != PROTOCOL:
            raise ValueError("unknown rules version")
        rate = data.get("rate") or None
        if rate and int(rate.get("limit") or 0) > 0:
            rate = {"limit": int(rate["limit"]), "window": max(1, int(rate.get("window") or 60))}
        else:
            rate = None
        return {
            "enabled": data.get("enabled") is True,
            "mode": "block" if data.get("mode") == "block" else "monitor",
            "sync": max(MIN_SYNC, int(data.get("sync") or RETRY)),
            "allow": IpSet(data.get("allow") or []),
            # Crawlers the rate limit must not catch (absent in older rules).
            "goodbots": IpSet(data.get("goodbots") or []),
            "deny": IpSet(data.get("deny") or []),
            "list": IpSet(data.get("lists") or []),
            "shared": IpSet(data.get("shared") or []),
            "rate": rate,
            "banned": IpSet(data.get("banned") or []),
            "ban": int((data.get("ban") or {}).get("seconds") or 0),
            "login": data.get("login") if isinstance(data.get("login"), dict) and int(data["login"].get("limit") or 0) > 0 else None,
            "probes": compile_probes(data.get("probes")),
            # Virtual patching: rules that match the request, not the address.
            "requests": compile_rules(data.get("requests")),
            # Page limits: a cap on one kind of request (absent in older rules).
            "limits": compile_page_limits(data.get("limits")),
            # The browser check: present only when the site is to be checked.
            "challenge": compile_challenge(data.get("challenge")),
        }

    def _sync(self):
        headers = {"X-Firewall-Layers": LAYERS}
        name = server_name()
        if name:
            headers["X-Server-Name"] = name
        if self.etag:
            headers["If-None-Match"] = self.etag
        res = self.core.send("firewall", "/events/firewall/rules?site_id=" + self.core.site_id, method="GET", auth="bearer", headers=headers)
        if res is not None and res.status == 200:
            data = res.json()
            try:
                self.rules = self._compile(data)
                self.etag = res.headers.get("etag", "")
                if self.cache_file:
                    self._write_cache(data)
            except ValueError as error:
                self.core.log("firewall", "rules not used:", error)
        return self.rules["sync"] if self.rules else RETRY

    def _write_cache(self, data):
        """Written whole or not at all (a temporary file, then renamed over
        the old one): a crash halfway would otherwise leave a cut-off file
        that the next start can't read, and it would start with no rules."""
        temp = "%s.%d.tmp" % (self.cache_file, os.getpid())
        try:
            with open(temp, "w") as f:
                json.dump({"etag": self.etag, "rules": data}, f)
            os.replace(temp, self.cache_file)
        except (OSError, TypeError, ValueError) as error:
            try:
                os.remove(temp)
            except OSError:
                pass
            self.core.log("firewall", "rules not kept in the cache file:", error)

    def _over_rate(self, ip, rate, peek=False):
        """peek: only compared with the count so far, nothing added (a static file)."""
        key = who(ip)
        window = int(time.time() // rate["window"])
        if self.counter:
            name = "afw:%s:%s:%s" % (self.core.site_id, key, window)
            if peek:
                return name in self.over_noted
            return self._note_over(name, int(self.counter(name, rate["window"] * 2)) > rate["limit"])
        with self.lock:
            entry = self.counts.get(key)
            if peek:
                return bool(entry) and entry[0] == window and entry[1] > rate["limit"]
            if not entry or entry[0] != window:
                # Taken out and put back, so the table runs oldest window
                # first and a full one loses the addresses quiet longest.
                self.counts.pop(key, None)
                make_room(self.counts)
                entry = self.counts[key] = [window, 0]
            entry[1] += 1
            return entry[1] > rate["limit"]

    def _note_over(self, name, over):
        """A shared count seen over, remembered under its key (window and
        all, so an old one never matches again) for a static file's peek."""
        if over:
            with self.lock:
                if name not in self.over_noted:
                    make_room(self.over_noted)
                self.over_noted[name] = True
        return over

    def _over_limits(self, ip, limits, method, path, prepared=None, peek=False):
        """Counts the request toward every page limit it matches, each in its
        own fixed window. -> the limits now over their count, in the order
        sent. `each: "path"` counts every page apart, and those counts stay
        here: one key per page and visitor would fill a shared counter with
        keys nobody else reads. peek: as _over_rate's."""
        matched, page = match_limits(limits, method, path, prepared=prepared)
        if not matched:
            return []
        counted = who(ip)
        now = time.time()
        over = []
        for limit in matched:
            window = int(now // limit["window"])
            if self.counter and not limit["each"]:
                key = "afw:%s:l:%s:%s:%s" % (self.core.site_id, limit["id"], counted, window)
                if peek:
                    hits = limit["limit"] + 1 if key in self.over_noted else 0
                else:
                    hits = int(self.counter(key, limit["window"] * 2))
                    self._note_over(key, hits > limit["limit"])
            else:
                key = (limit["id"], counted, page if limit["each"] else "")
                table = self.page_counts if limit["each"] else self.limit_counts
                with self.lock:
                    entry = table.get(key)
                    if peek:
                        hits = entry[1] if entry and entry[0] == window else 0
                        if hits > limit["limit"]:
                            over.append(limit)
                        continue
                    if not entry or entry[0] != window:
                        # Oldest window first, as the rate counts, so a full
                        # table loses the visitors quiet longest.
                        table.pop(key, None)
                        make_room(table)
                        entry = table[key] = [window, 0]
                    entry[1] += 1
                    hits = entry[1]
            if hits > limit["limit"]:
                over.append(limit)
        return over

    def _banned_here(self, ip):
        key = who(ip)
        until = self.bans.get(key)
        if not until:
            return False
        if until > time.time():
            return True
        with self.lock:
            self.bans.pop(key, None)
        return False

    def _ban_here(self, ip, seconds):
        if seconds > 0:
            key = who(ip)
            with self.lock:
                until = max(self.bans.pop(key, 0), time.time() + seconds)
                make_room(self.bans)
                self.bans[key] = until

    def login_failed(self, ip):
        """A failed login on your site: counted here (past the site's limit the
        address is banned straight away) and reported, so it counts on the
        Security page and gets banned on the other servers too."""
        key = ip_key(ip)
        rules = self.rules
        if key is None or (rules and rules["allow"].has(key)):
            return
        login = rules["login"] if rules else None
        if login:
            now = time.time()
            counted = who(ip)
            with self.lock:
                entry = self.logins.get(counted)
                if not entry or now - entry[0] >= int(login.get("window") or 3600):
                    self.logins.pop(counted, None)
                    make_room(self.logins)
                    entry = self.logins[counted] = [now, 0]
                entry[1] += 1
                reached = entry[1] >= int(login["limit"])
                if reached:
                    self.logins.pop(counted, None)
            if reached:
                self._ban_here(str(ip), int(login.get("ban") or 3600))
        self._report({"ip": str(ip), "rule": "login", "action": "monitor", "method": "", "path": "", "user_agent": ""})

    def _report(self, event):
        key = "|".join((event["ip"], event["rule"], event["action"], event["method"], event["path"]))
        with self.lock:
            row = self.queue.get(key)
            if row:
                row["hits"] += 1
            elif len(self.queue) < QUEUE_MAX:
                self.queue[key] = dict(event, at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"), hits=1)

    def flush(self):
        with self.lock:
            rows, self.queue = list(self.queue.values()), {}
        for i in range(0, len(rows), BATCH):
            self.core.send("firewall", "/events/firewall/events", auth="bearer",
                           body={"site_id": self.core.site_id, "events": rows[i:i + BATCH]})

    def _flush_job(self):
        self.flush()
        return FLUSH_EVERY

    def check(self, ip, method="", path="", user_agent="", accept="", cookie="", now=None):
        """-> {"action": "allow" | "block" | "monitor", "rule": ..., "status": ...}.
        Allowed addresses skip every other rule. accept and cookie (the
        request's headers) are for the browser check: rule "challenge",
        status 503, answered with challenge_page()."""
        allow = {"action": "allow", "rule": "", "status": 200}
        rules = self.rules
        if not rules or not rules["enabled"]:
            return allow
        key = ip_key(ip)
        if key is None or rules["allow"].has(key):
            return allow
        action = "block" if (self.mode or rules["mode"]) == "block" else "monitor"
        rule = self._address_rule(rules, key, ip)
        if not rule and is_probe(path, rules["probes"]):
            rule = "probe"
            # Asking for a secret file: banned here in block mode; the report bans it on the other servers.
            if action == "block":
                self._ban_here(str(ip), rules["probes"]["ban"])
        matched = None
        limits = rules.get("limits")
        # Prepared once (decoded, routed) for the request rules and the page limits both.
        prepared = (prepare(method, path, user_agent)
                    if not rule and (rules.get("requests") or (limits and limits["rules"])) else None)
        if not rule:
            matched = match_request(rules.get("requests") or [], method, path, user_agent, prepared=prepared)
            if matched:
                rule = "request:" + matched["id"]
                # A rule the dashboard only watches passes even in block mode;
                # one that blocks also bans the address here, as a flood does.
                action = "block" if action == "block" and matched["action"] == "block" else "monitor"
                if action == "block" and matched["ban"]:
                    self._ban_here(str(ip), matched["ban"])
        # A static file isn't counted toward the page limits or the rate,
        # only compared with the counts so far: an address already over them
        # is turned away for its files too. It counts after the response when
        # the router sent it to a page after all ("search/<q>" took
        # "/search/x.css") or it answered an error (count_static).
        static = is_static(path, method)
        late_rate = late_limits = False
        # Step 6, page limits. Never a ban: a shopper who refreshes checkout
        # too often is a customer, and the cap lifts when the window ends.
        watched = ""
        if not rule and limits and not rules["goodbots"].has(key) and not limits["exempt"].has(key):
            late_limits = static
            over = self._over_limits(str(ip), limits["rules"], method, path, prepared, peek=static)
            blocking = [limit for limit in over if action == "block" and limit["action"] == "block"]
            if blocking:
                rule = "limit:" + blocking[0]["id"]
            elif over:
                # Only watched: the check goes on to the rate limit, so
                # watching the login page doesn't let a flood through it.
                watched = "limit:" + over[0]["id"]
        if not rule and rules["rate"] and not rules["goodbots"].has(key):
            late_rate = static
        if (not rule and rules["rate"] and not rules["goodbots"].has(key)
                and self._over_rate(str(ip), rules["rate"], peek=static)):
            rule = "rate"
            # Banned here straight away in block mode, as a probe is; the report bans it on the other servers.
            if action == "block":
                self._ban_here(str(ip), rules["ban"])
        def event(name, act):
            return {"ip": str(ip), "rule": name, "action": act,
                    "method": str(method)[:10], "path": str(path).split("?")[0][:300], "user_agent": str(user_agent)[:300]}

        # A watched page limit is reported whatever comes after it: the rate
        # limit or the browser check deciding doesn't hide it.
        if watched:
            if rule:
                self._report(event(watched, "monitor"))
            else:
                rule, action = watched, "monitor"
        # Not a mode matter: the collector only sends `challenge` when the site
        # is to be checked, and a match only watched (monitor) gets it too
        # (firewall.md, step 8).
        if (not rule or action != "block") and self._needs_check(rules, key, str(ip), method, path, accept, cookie, now):
            if rule:
                self._report(event(rule, action))
            rule, action = "challenge", "block"
        # What count_static needs after the response of a static file that goes on to the app.
        late = None
        if (late_rate or late_limits) and (not rule or action != "block"):
            late = {"ip": str(ip), "rate": late_rate, "limits": late_limits, "method": method, "path": path,
                    "prepared": prepared}
        if not rule:
            return dict(allow, static=late) if late else allow
        self._report(event(rule, action))
        status = 429 if rule == "rate" or rule.startswith("limit:") else 503 if rule == "challenge" else 403
        decision = {"action": action, "rule": rule, "status": status}
        if late:
            decision["static"] = late
        return decision

    def count_static(self, hit, status, routed=False):
        """After the response to a static file check() let through (its
        decision's "static"): counted toward the rate and the page limits it
        skipped when it answered 400 or more (a flood of made-up file names)
        or the router sent it to a route that isn't a file's (routed), unless
        it answered 304 (a browser checking a file it keeps)."""
        rules = self.rules
        try:
            status = int(status or 0)
        except (TypeError, ValueError):
            status = 0
        if not hit or not rules or not (status >= 400 or (routed and status != 304)):
            return
        if hit["rate"] and rules["rate"]:
            self._over_rate(hit["ip"], rules["rate"])
        limits = rules.get("limits")
        if hit["limits"] and limits and limits["rules"]:
            self._over_limits(hit["ip"], limits["rules"], hit["method"], hit["path"], hit["prepared"])

    def _address_rule(self, rules, key, ip):
        """The rules about the address alone (deny, bans, lists, shared): "" when none."""
        if rules["deny"].has(key):
            return "deny"
        if rules["banned"].has(key) or self._banned_here(str(ip)):
            return "ban"
        if rules["list"].has(key):
            return "list"
        return "shared" if rules["shared"].has(key) else ""

    def check_address(self, ip, method="", path="", user_agent=""):
        """The address rules only, for the tracker's own addresses (the
        proxy): a denied or banned address gets nothing from us either, but
        beacons are never rate-limited, checked or matched against request
        rules. -> the same shape as check()."""
        allow = {"action": "allow", "rule": "", "status": 200}
        rules = self.rules
        if not rules or not rules["enabled"]:
            return allow
        key = ip_key(ip)
        if key is None or rules["allow"].has(key):
            return allow
        rule = self._address_rule(rules, key, ip)
        if not rule:
            return allow
        action = "block" if (self.mode or rules["mode"]) == "block" else "monitor"
        self._report({"ip": str(ip), "rule": rule, "action": action, "method": str(method)[:10],
                      "path": str(path).split("?")[0][:300], "user_agent": str(user_agent)[:300]})
        return {"action": action, "rule": rule, "status": 403}

    def _needs_check(self, rules, key, ip, method, path, accept, cookie, now):
        """Step 8: the browser check is on, the request asks for a page outside
        skip, the address is in none of allow (already passed), goodbots and
        exempt, and it has no valid pass."""
        check = rules.get("challenge")
        if not check or not browser_check.asks_for_page(method, path, accept, check["skip"]):
            return False
        if rules["goodbots"].has(key) or check["exempt"].has(key):
            return False
        return not browser_check.has_pass(self.pass_key, ip, cookie, now)

    def challenge_page(self, ip, method):
        """(503, headers, body) for a request check() gave rule "challenge"."""
        return browser_check.page(self.pass_key, ip, method)

    def retry_after(self, rule=""):
        """Retry-After for a 429: the page limit's own window for rule
        "limit:<id>", else the rate limit's."""
        rules = self.rules
        if rules and rule.startswith("limit:") and rules.get("limits"):
            for limit in rules["limits"]["rules"]:
                if "limit:" + limit["id"] == rule:
                    return str(limit["window"])
        return str(rules["rate"]["window"]) if rules and rules["rate"] else "60"

    def client_ip(self, remote, headers):
        return client_ip(remote, headers, self.trust_proxy)

    def close(self):
        for job in self.jobs:
            job.stop()
        self.flush()
