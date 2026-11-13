"""What the reviews of the Ruby, Java, .NET and Go ports found, checked here:
addresses with ports, counters per /64, bounded rows, the proxy's breaker,
the exit deadline, static files and the rate limit, joined Cookie headers,
visitors who hang up, payloads JSON can't carry, router-normalised paths,
the errors file, the maintenance cookie, the Django client name, `$` in
validation patterns and the regex group allow-list.

    python3 -m unittest discover -s tests
"""
import asyncio
import datetime
import decimal
import glob
import json
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analytics_platform import Platform, PlatformMiddleware  # noqa: E402
from analytics_platform import errors as errors_mod  # noqa: E402
from analytics_platform import firewall as firewall_mod  # noqa: E402
from analytics_platform.analytics import Analytics  # noqa: E402
from analytics_platform.challenge import has_pass, make_pass, pass_key  # noqa: E402
from analytics_platform.core import Core, plain, within  # noqa: E402
from analytics_platform.crawlers import HARD_MAX_KEYS as CRAWLER_HARD_MAX, Crawlers  # noqa: E402
from analytics_platform.errors import MAX_MESSAGE, Errors, is_disconnect  # noqa: E402
from analytics_platform.firewall import Firewall, client_ip, hop, is_probe, compile_probes  # noqa: E402
from analytics_platform.maintenance import Maintenance  # noqa: E402
from analytics_platform.performance import HARD_MAX_KEYS, METHODS, Performance  # noqa: E402
from analytics_platform.proxy import BREAKER_FAILURES, Proxy  # noqa: E402
from analytics_platform.request_rules import compile_rules, match_request, safe_pattern  # noqa: E402

SITE = "a" * 24
DEAD = "http://127.0.0.1:1"  # refuses at once: nothing listens on port 1


class Quiet:
    valid = False
    site_id = SITE
    secret = "s3cret"
    endpoint = DEAD

    def __init__(self, maintenance=None):
        self._maintenance = maintenance or {"on": False}

    def is_on(self, name):
        return True

    def log(self, *args):
        pass

    def maintenance(self):
        return self._maintenance


def wall(**rules):
    fw = Firewall(Quiet())
    fw.rules = fw._compile(dict({"v": 1, "enabled": True, "mode": "block"}, **rules))
    return fw


def quiet_platform(**options):
    """A Platform whose core is invalid: modules load, nothing is sent."""
    with mock.patch("builtins.print"):
        return Platform(site_id="x", secret="", endpoint="", **options)


class Addresses(unittest.TestCase):
    """1. A port on a hop made the address unparseable, and the firewall let
    everything through; a hop that isn't an address falls back to the peer."""

    def test_ports_are_dropped(self):
        self.assertEqual(hop("203.0.113.5:54321"), "203.0.113.5")
        self.assertEqual(hop("[2001:db8::1]:443"), "2001:db8::1")
        self.assertEqual(hop("[2001:db8::1]"), "2001:db8::1")
        self.assertEqual(hop("2001:db8::1"), "2001:db8::1", "a bare IPv6 address keeps its colons")
        self.assertEqual(client_ip("10.0.0.1", {"x-forwarded-for": "198.51.100.7, 203.0.113.5:54321"}, 1), "203.0.113.5")
        self.assertEqual(client_ip("10.0.0.1", {"x-forwarded-for": "[2001:db8::1]:443"}, 1), "2001:db8::1")

    def test_a_hop_that_is_not_an_address_gives_the_peer(self):
        for junk in ("unknown", "evil.example", "1.2.3.4.5", "<script>"):
            self.assertEqual(client_ip("10.0.0.1", {"x-forwarded-for": junk}, 1), "10.0.0.1", junk)
        self.assertEqual(client_ip("10.0.0.1", {}, lambda h: "nope"), "10.0.0.1")
        self.assertEqual(client_ip("172.64.1.2", {"cf-connecting-ip": "garbage"}, "cloudflare"), "172.64.1.2")

    def test_a_denied_address_with_a_port_is_still_denied(self):
        fw = wall(deny=["203.0.113.0/24"])
        fw.trust_proxy = 1
        ip = fw.client_ip("10.0.0.1", {"x-forwarded-for": "203.0.113.5:54321"})
        self.assertEqual(fw.check(ip, "GET", "/")["rule"], "deny")


class FrameworkAddress(unittest.TestCase):
    """2. werkzeug's ProxyFix inside the middleware: the firewall reads the
    header with its x_for, so the two agree; a trust_proxy given wins."""

    def proxy_fix(self, x_for):
        cls = type("ProxyFix", (), {"__module__": "werkzeug.middleware.proxy_fix"})
        app = cls()
        app.x_for, app.app = x_for, (lambda environ, start: [b""])
        return app

    def test_proxy_fix_sets_the_hops_when_trust_proxy_is_unset(self):
        platform = quiet_platform()
        platform.wsgi(self.proxy_fix(2))
        self.assertEqual(platform.firewall.trust_proxy, 2)

    def test_a_trust_proxy_given_wins(self):
        platform = quiet_platform(trust_proxy="cloudflare")
        platform.wsgi(self.proxy_fix(2))
        self.assertEqual(platform.firewall.trust_proxy, "cloudflare")

    def test_asgi_joins_a_header_sent_twice(self):
        platform = quiet_platform(trust_proxy=1)
        platform.firewall.rules = platform.firewall._compile({"v": 1, "enabled": True, "mode": "block", "deny": ["203.0.113.9"]})
        sent = []

        async def app(scope, receive, send):
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b"ok"})

        async def receive():
            return {"type": "http.request"}

        async def send(message):
            sent.append(message)

        scope = {"type": "http", "method": "GET", "path": "/", "query_string": b"", "client": ("10.0.0.1", 1),
                 "headers": [(b"x-forwarded-for", b"198.51.100.1"), (b"x-forwarded-for", b"203.0.113.9")]}
        asyncio.run(PlatformMiddleware(app, platform)(scope, receive, send))
        self.assertEqual(sent[0]["status"], 403, "the last proxy's line is the one believed")


class PerSlash64(unittest.TestCase):
    """3. Counters and bans per /64, mapped IPv4 as IPv4, and a full table
    loses its oldest entries, not everyone's."""

    def test_rotating_within_a_64_hits_the_limit(self):
        fw = wall(mode="monitor", rate={"limit": 3, "window": 60})
        rules = [fw.check("2001:db8:0:1::%x" % i, "GET", "/")["rule"] for i in range(1, 6)]
        self.assertEqual(rules, ["", "", "", "rate", "rate"])
        self.assertEqual(fw.check("2001:db8:0:2::1", "GET", "/")["rule"], "", "another /64 counts on its own")

    def test_a_ban_covers_the_64_and_mapped_ipv4_is_ipv4(self):
        fw = wall(rate={"limit": 1, "window": 60}, ban={"seconds": 600})
        fw.check("2001:db8:0:1::1", "GET", "/")
        self.assertEqual(fw.check("2001:db8:0:1::2", "GET", "/")["rule"], "rate")
        self.assertEqual(fw.check("2001:db8:0:1::ffff", "GET", "/")["rule"], "ban")
        fw.check("203.0.113.9", "GET", "/")
        self.assertEqual(fw.check("::ffff:203.0.113.9", "GET", "/")["rule"], "rate", "one count for both spellings")

    def test_login_failures_count_per_64(self):
        fw = wall(login={"limit": 3, "window": 3600, "ban": 3600})
        for i in range(3):
            fw.login_failed("2001:db8:0:1::%x" % (i + 1))
        self.assertEqual(fw.check("2001:db8:0:1::99", "GET", "/")["rule"], "ban")

    def test_a_full_table_drops_the_oldest(self):
        with mock.patch.object(firewall_mod, "COUNTER_MAX", 3):
            fw = wall(mode="monitor", rate={"limit": 1, "window": 60})
            fw.check("198.51.100.1", "GET", "/")
            fw.check("198.51.100.1", "GET", "/")
            for i in range(2, 6):
                fw.check("198.51.100.%d" % i, "GET", "/")
            self.assertEqual(len(fw.counts), 3)
            self.assertNotIn("198.51.100.1", fw.counts)
            self.assertEqual(fw.check("198.51.100.5", "GET", "/")["rule"], "rate", "the newest kept its count")


class Methods(unittest.TestCase):
    """4. The method is the visitor's to choose: past the known ones, one OTHER."""

    def test_made_up_methods_are_one_row_and_rows_are_capped(self):
        perf = Performance(Quiet())
        for i in range(2000):
            perf.record("X%d" % i, "/r%d" % i, 200 + i % 300, 1.0)
        self.assertLessEqual(len(perf.rows), HARD_MAX_KEYS)
        self.assertEqual({key[1] for key in perf.rows}, {"OTHER"})
        perf.rows.clear()
        for method in ("get", "JOB", "PROPFIND", "options"):
            perf.record(method, "/", 200, 1.0)
        self.assertEqual({key[1] for key in perf.rows}, {"GET", "JOB", "OTHER", "OPTIONS"})
        self.assertIn("JOB", METHODS)


class CrawlerRows(unittest.TestCase):
    """17. Crawler rows have a hard cap as Server speed's do."""

    def test_rows_are_capped(self):
        crawlers = Crawlers(Quiet())
        for i in range(3000):
            crawlers.record("Googlebot", "/p%d" % i, i)
        self.assertLessEqual(len(crawlers.rows), CRAWLER_HARD_MAX)


class Breaker(unittest.TestCase):
    """5. A collector that doesn't answer doesn't hold the site's threads."""

    def test_after_three_failures_the_collector_is_left_alone(self):
        proxy = Proxy(type("C", (Quiet,), {"valid": True})())
        calls = []
        real = __import__("urllib.request").request.urlopen

        def counting(*args, **kwargs):
            calls.append(kwargs.get("timeout"))
            return real(*args, **kwargs)

        with mock.patch("urllib.request.urlopen", counting):
            kind, rest = proxy.match(proxy.collect_url())
            for _ in range(BREAKER_FAILURES):
                self.assertEqual(proxy.handle(kind, rest, method="POST", body=b"{}")[0], 502)
            status, headers, _ = proxy.handle(kind, rest, method="POST", body=b"{}")
            self.assertEqual(status, 502)
            self.assertEqual(dict(headers).get("Retry-After"), "30")
            self.assertEqual(len(calls), BREAKER_FAILURES, "answered without asking")
            self.assertTrue(all(t <= 2 for t in calls), "short waits")

    def test_a_failed_tracker_file_is_not_fetched_again_at_once(self):
        proxy = Proxy(type("C", (Quiet,), {"valid": True})())
        calls = []
        real = __import__("urllib.request").request.urlopen
        with mock.patch("urllib.request.urlopen", lambda *a, **k: calls.append(1) or real(*a, **k)):
            for _ in range(3):
                self.assertEqual(proxy.handle(*proxy.match(proxy.script_url()))[0], 502)
        self.assertEqual(len(calls), 1)

    def test_a_denied_address_gets_no_proxy(self):
        with mock.patch("builtins.print"):
            platform = Platform(site_id=SITE, secret="s", endpoint=DEAD)
        try:
            platform.firewall.rules = platform.firewall._compile(
                {"v": 1, "enabled": True, "mode": "block", "deny": ["203.0.113.9"], "rate": {"limit": 1, "window": 60}})
            path = platform.proxy.collect_url()
            self.assertEqual(platform.proxy_response(path, "POST", "", {}, b"{}", "203.0.113.9")[0], 403)
            with mock.patch.object(platform.proxy, "handle", return_value=(204, [], b"")):
                answers = [platform.proxy_response(path, "POST", "", {}, b"{}", "198.51.100.1")[0] for _ in range(3)]
            self.assertEqual(answers, [204, 204, 204], "beacons are never rate-limited")
        finally:
            platform.close()


class ExitDeadline(unittest.TestCase):
    """6. One deadline at exit: no retry sleep, sends cut short, the rest spooled."""

    def test_past_the_deadline_nothing_is_sent(self):
        core = Core(SITE, "s", DEAD)
        with within(0):
            started = time.monotonic()
            self.assertIsNone(core.send("errors", "/events/server-errors", body={"errors": []}))
            self.assertLess(time.monotonic() - started, 0.05)

    def test_errors_flush_at_exit_skips_the_retry_and_spools(self):
        with tempfile.TemporaryDirectory() as spool:
            core = type("C", (Quiet,), {"valid": True, "send": lambda self, *a, **k: None})()
            errors = Errors(core, capture_uncaught=False, spool_dir=spool)
            errors.job.stop()
            errors.capture_exception(ValueError("x"), status=500, kind="error")
            with mock.patch.object(errors_mod, "RETRY_AFTER", 10), within(5):
                started = time.monotonic()
                errors.flush()
                self.assertLess(time.monotonic() - started, 1, "no retry sleep")
            with open(errors.spool_file) as f:
                self.assertEqual(len(f.readlines()), 1)

    def test_the_taken_file_is_deleted_only_after_it_was_sent(self):
        with tempfile.TemporaryDirectory() as spool:
            seen = []

            class C(Quiet):
                valid = True

                def send(self, module, path, body=None, **_):
                    seen.append(len(glob.glob(os.path.join(spool, "*.sending"))))
                    return type("R", (), {"status": 202})()

            errors = Errors(C(), capture_uncaught=False, spool_dir=spool)
            errors.job.stop()
            errors._spool([{"message": "m%d" % i} for i in range(25)])
            errors.resend()
            self.assertEqual(seen, [1, 1, 1], "on disk while it is sent")
            self.assertEqual(glob.glob(os.path.join(spool, "*")), [])

    def test_a_killed_senders_file_is_taken_over(self):
        with tempfile.TemporaryDirectory() as spool:
            sent = []

            class C(Quiet):
                valid = True

                def send(self, module, path, body=None, **_):
                    sent.extend(body["errors"])
                    return type("R", (), {"status": 202})()

            errors = Errors(C(), capture_uncaught=False, spool_dir=spool)
            errors.job.stop()
            left = errors.spool_file + ".99999.1.sending"
            with open(left, "w") as f:
                f.write(json.dumps({"message": "kept"}) + "\n")
            old = time.time() - errors_mod.ORPHAN_S - 10
            os.utime(left, (old, old))
            errors.resend()
            self.assertEqual([e["message"] for e in sent], ["kept"])
            self.assertFalse(os.path.exists(left))


class StaticFiles(unittest.TestCase):
    """7. A page's 40 assets are not 40 hits."""

    def test_static_files_are_not_counted(self):
        fw = wall(mode="monitor", rate={"limit": 2, "window": 60})
        for path in ("/app.css", "/img/a.PNG?v=3", "/static/site", "/font.woff2", "/x.js") * 5:
            self.assertEqual(fw.check("198.51.100.1", "GET", path)["rule"], "", path)
        rules = [fw.check("198.51.100.1", "GET", p)["rule"] for p in ("/", "/a", "/admin;x.css")]
        self.assertEqual(rules, ["", "", "rate"], "a ;param doesn't make a page a file")

    # Tricks that would make a page read as a static file, so a flood of them
    # skips the rate and the page limits, and real assets: the cases every
    # package shares (sdk/protocols/static-cases.json, firewall.md, `rate`).
    with open(os.path.join(os.path.dirname(__file__), "..", "..", "protocols", "static-cases.json")) as f:
        CASES = [c for c in json.load(f)["cases"] if "python" in c.get("only", ["python"])]
    NOT_STATIC = tuple((c["path"], c.get("method", "GET")) for c in CASES if not c["static"])
    STATIC = tuple((c["path"], c.get("method", "GET")) for c in CASES if c["static"])

    def test_tricks_count_toward_the_rate_and_page_limits(self):
        for target, method in self.NOT_STATIC:
            self.assertFalse(firewall_mod.is_static(target, method), method + " " + target[:60])
        for target, method in self.STATIC:
            self.assertTrue(firewall_mod.is_static(target, method), method + " " + target)
        rate = wall(rate={"limit": 1, "window": 60})
        limits = wall(limits={"rules": [{"id": "all", "action": "block", "limit": 1, "window": 60, "path": {"prefix": ["/"]}}]})
        for i, (target, method) in enumerate(self.NOT_STATIC + self.STATIC):
            ip = "203.0.113.%d" % (i + 1)
            counted = i < len(self.NOT_STATIC)
            rate.check(ip, method, target)
            self.assertEqual(rate.check(ip, method, target)["rule"], "rate" if counted else "", target[:60])
            limits.check(ip, method, target)
            self.assertEqual(limits.check(ip, method, target)["rule"], "limit:all" if counted else "", target[:60])


class Cookies(unittest.TestCase):
    """8. Two Cookie headers joined with "," or ", " still carry the pass."""

    def test_a_pass_in_a_second_header_counts(self):
        key = pass_key("s3cret")
        token = make_pass(key, "198.51.100.1")
        for header in ("a=1,__sg_pass=" + token, "a=1, __sg_pass=" + token, "__sg_pass=stale, __sg_pass=" + token):
            self.assertTrue(has_pass(key, "198.51.100.1", header), header)


class Disconnects(unittest.TestCase):
    """9. A visitor who hung up isn't a 500."""

    def capture(self, error, **kwargs):
        core = Quiet()
        errors = Errors(core, capture_uncaught=False)
        errors.capture_exception(error, **kwargs)
        return len(errors.queue)

    def test_disconnects_are_skipped(self):
        named = type("ClientDisconnect", (Exception,), {})
        self.assertEqual(self.capture(BrokenPipeError(), status=500, kind="error"), 0)
        self.assertEqual(self.capture(ConnectionResetError(), status=500, kind="error"), 0)
        self.assertEqual(self.capture(named(), status=500, kind="error"), 0)
        try:
            try:
                raise ConnectionResetError()
            except ConnectionResetError as inner:
                raise OSError("read failed") from inner
        except OSError as wrapped:
            self.assertTrue(is_disconnect(wrapped))

    def test_real_errors_and_your_own_captures_are_sent(self):
        self.assertEqual(self.capture(ValueError("x"), status=500, kind="error"), 1)
        self.assertEqual(self.capture(ConnectionResetError(), kind="handled"), 1, "you chose to send it")


class Payloads(unittest.TestCase):
    """10. A value JSON can't carry is converted when it is handed over."""

    def test_track_takes_json_at_call_time(self):
        analytics = Analytics(Quiet())
        fields = {"value": decimal.Decimal("4.5"), "at": datetime.date(2026, 11, 3), "tags": {"a"},
                  "bad": float("nan"), "obj": object(), "nested": {"when": datetime.datetime(2026, 1, 1)}}
        analytics.track("purchase", fields)
        fields["value"] = "changed"
        event = analytics.queue[0]
        json.dumps(event, allow_nan=False)
        self.assertEqual(event["value"], 4.5)
        self.assertEqual(event["at"], "2026-11-03")
        self.assertIsNone(event["bad"])

    def test_identify_passes_scalar_traits_through(self):
        core = Quiet()
        sent = []
        core.send = lambda module, path, body=None, **_: sent.append(body) or mock.Mock(ok=True)
        analytics = Analytics(core)
        self.assertTrue(analytics.identify("u1", "s1"))
        self.assertTrue(analytics.identify("u1", "s1", traits={"plan": "pro", "Seats": 5, "ratio": 0.5, "trial": False,
                                                               "tags": ["a"], "meta": {"a": 1}, "gone": None, "bad": float("nan")}))
        self.assertTrue(analytics.identify("u1", "s1", {"tags": ["a"]}))
        self.assertEqual(sent, [
            {"user_id": "u1", "session_id": "s1"},
            {"user_id": "u1", "session_id": "s1", "traits": {"plan": "pro", "Seats": 5, "ratio": 0.5, "trial": False}},
            {"user_id": "u1", "session_id": "s1"},
        ])

    def test_plain_handles_deep_and_odd_values(self):
        deep = []
        cur = deep
        for _ in range(50):
            cur.append([])
            cur = cur[0]
        json.dumps(plain({"deep": deep, b"k": b"\xff"}))

    def test_a_body_that_is_not_json_is_unsendable_not_a_network_failure(self):
        core = Core(SITE, "s", DEAD)
        res = core.send("analytics", "/events/server-events", body={"events": [object()]})
        self.assertIsNotNone(res)
        self.assertTrue(res.unsendable)


class RouterPaths(unittest.TestCase):
    """11. A rule on /admin also catches /x;y/../admin."""

    def test_normalised_paths_match(self):
        rules = compile_rules({"rules": [{"id": "admin", "action": "block", "path": {"prefix": ["/admin"]}}]})
        for target in ("/x;y/../admin", "/static/..%2fadmin/", "/a/./b/../../admin?x=1", "/admin"):
            self.assertEqual((match_request(rules, "GET", target, "") or {}).get("id"), "admin", target)
        self.assertIsNone(match_request(rules, "GET", "/home/admin/../x", ""))

    def test_probes_too(self):
        probes = compile_probes({"exact": ["/.env"], "prefix": ["/.git/"]})
        self.assertTrue(is_probe("/x/..;/.env", probes))
        self.assertTrue(is_probe("/a/%2e%2e/.git/config", probes))
        self.assertFalse(is_probe("/env", probes))


class Limits(unittest.TestCase):
    """12. Messages capped, the errors file never past its size, the rules
    cache written whole or not at all."""

    def test_the_message_is_capped(self):
        errors = Errors(Quiet(), capture_uncaught=False)
        errors.capture_exception(ValueError("x" * 10000))
        self.assertEqual(len(errors.queue[0]["message"]), MAX_MESSAGE)

    def test_the_spool_never_grows_past_its_size(self):
        with tempfile.TemporaryDirectory() as spool, mock.patch.object(errors_mod, "SPOOL_BYTES", 1000):
            errors = Errors(type("C", (Quiet,), {"valid": True})(), capture_uncaught=False, spool_dir=spool)
            errors.job.stop()
            errors._spool([{"message": "x" * 300}] * 10)
            self.assertLessEqual(os.path.getsize(errors.spool_file), 1000)
            errors._spool([{"message": "y" * 300}])
            self.assertLessEqual(os.path.getsize(errors.spool_file), 1000)

    def test_the_rules_cache_is_replaced_whole(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, "rules.json")
            with open(path, "w") as f:
                json.dump({"etag": "old", "rules": {"v": 1}}, f)
            fw = Firewall(Quiet(), cache_file=path)
            fw._write_cache({"v": 1, "bad": object()})
            with open(path) as f:
                self.assertEqual(json.load(f)["etag"], "old")
            self.assertEqual(os.listdir(folder), ["rules.json"], "no temporary file left behind")
            fw._write_cache({"v": 1, "enabled": False})
            with open(path) as f:
                self.assertEqual(json.load(f)["rules"]["enabled"], False)


class MaintenanceBypass(unittest.TestCase):
    """13. The code compared in constant time; Secure over HTTPS."""

    def setUp(self):
        self.m = Maintenance(Quiet({"on": True, "bypass": "c0de"}))

    def test_secure_over_https(self):
        status, headers = self.m.decide("198.51.100.1", "/", "site_preview=c0de", "", secure=True)
        self.assertEqual(status, "pass")
        self.assertIn("; Secure", headers[0][1])
        self.assertNotIn("Secure", self.m.decide("198.51.100.1", "/", "site_preview=c0de", "")[1][0][1])

    def test_the_cookie_in_a_joined_header_counts(self):
        self.assertIsNone(self.m.decide("198.51.100.1", "/", "", 'x="a b", site_preview=c0de'))
        self.assertEqual(self.m.decide("198.51.100.1", "/", "", "site_preview=c0dE")[0], 503)

    def test_x_forwarded_proto_counts(self):
        platform = quiet_platform()
        platform.core._maintenance = {"on": True, "bypass": "c0de"}
        answer = platform.maintenance_response("198.51.100.1", {"x-forwarded-proto": "https"}, "/", "site_preview=c0de")
        self.assertIn("; Secure", answer[1][0][1])


class ClientName(unittest.TestCase):
    """14. Django says it is Django, so Django-only request rules reach it."""

    def test_the_user_agent_names_the_framework(self):
        self.assertTrue(Core(SITE, "s", DEAD, client="django").user_agent.startswith("analytics-platform-django/"))
        self.assertTrue(Core(SITE, "s", DEAD).user_agent.startswith("analytics-platform-python/"))
        self.assertTrue(Core(SITE, "s", DEAD, client="evil/1 x").user_agent.startswith("analytics-platform-python/"))
        self.assertTrue(quiet_platform(client="django").core.user_agent.startswith("analytics-platform-django/"))


class TrailingNewline(unittest.TestCase):
    """15. "$" lets a trailing newline through; "\\Z" doesn't."""

    def test_the_proxy_refuses_a_newline(self):
        proxy = Proxy(type("C", (Quiet,), {"valid": True})())
        self.assertEqual(proxy.match("/%s/js/v1/s.js\n" % proxy.prefix), ("bad", ""))
        self.assertEqual(proxy.handle("js", "v1/s.js\n")[0], 404)


class RegexGroups(unittest.TestCase):
    """16. Only (?:, (?= and (?!; no references, no engine extras."""

    def test_refused(self):
        for pattern in ("(?P<x>a)", "(?P=x)", "(?i)a", "(?>a)", "(?(1)a|b)", "(?#c)a", "(?<=a)b", "(?<!a)b",
                        r"(a)\1", r"\k<x>", r"\g<1>", r"\N{DASH}", "a++", "a*+", "a?+", "a{2,}+"):
            self.assertFalse(safe_pattern(pattern), pattern)

    def test_allowed(self):
        for pattern in ("(?:a)b", "(?=a)a", "(?!a)b", r"a\++", "[+*]+x", r"\.php\b", "a{2}b", "a+?b"):
            self.assertTrue(safe_pattern(pattern), pattern)



class SharedKeysAndHeaders(unittest.TestCase):
    def test_the_counter_key_is_the_same_text_in_every_package(self):
        self.assertEqual(firewall_mod.who("198.51.100.7"), "198.51.100.7")
        self.assertEqual(firewall_mod.who("::ffff:198.51.100.7"), "198.51.100.7")
        self.assertEqual(firewall_mod.who("2001:db8:1:2:aa::1"), "2001:db8:1:2::/64")
        self.assertEqual(firewall_mod.who("2001:0:0:0:5::"), "2001::/64")

    def test_dashboard_headers_are_visible_ascii_and_never_framing(self):
        from analytics_platform.core import safe_header
        self.assertTrue(safe_header(["X-Frame-Options", "DENY"]))
        self.assertTrue(safe_header(["Content-Security-Policy", "default-src\t'self'"]))
        self.assertFalse(safe_header(["Content-Security-Policy", "default-src \u2018self\u2019"]))
        self.assertFalse(safe_header(["X-A", "a\x01b"]))
        self.assertFalse(safe_header(["X-A", "a\nSet-Cookie: x=1"]))
        for name in ("Content-Length", "transfer-encoding", "Connection", "Set-Cookie", "Content-Type"):
            self.assertFalse(safe_header([name, "1"]), name)

if __name__ == "__main__":
    unittest.main()
