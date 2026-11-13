"""Page limits (firewall.md, "Page limits" and step 6 of "Checking a
request"): the shared cases every client runs
(sdk/protocols/page-limits-cases.json), a window ending, and the 429 as each
integration answers it.

    python3 -m unittest discover -s tests
"""
import asyncio
import contextlib
import copy
import io
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analytics_platform import create_platform  # noqa: E402
from analytics_platform.firewall import LIMIT_BODY, Firewall  # noqa: E402
import test_challenge  # noqa: E402
from test_challenge import FakeDjangoRequest, FakeDjangoResponse, asgi_site, site, wsgi_call  # noqa: E402

CASES = os.path.join(os.path.dirname(__file__), "..", "..", "protocols", "page-limits-cases.json")
with open(CASES) as handle:
    SHARED = json.load(handle)

LOGIN = {"id": "wp.login", "action": "block", "limit": 2, "window": 45,
         "methods": ["POST"], "path": {"exact": ["/wp-login.php"]}}


class FakeCore:
    valid = False
    site_id = "a" * 24
    secret = "s"

    def log(self, *_args):
        pass


def scenario_rules(scenario):
    data = copy.deepcopy(SHARED["base"])
    data.update(scenario.get("rules") or {})
    data["limits"] = scenario["limits"]
    return data


class SharedCases(unittest.TestCase):
    def test_every_scenario(self):
        for scenario in SHARED["scenarios"]:
            wall = Firewall(FakeCore())
            wall.rules = wall._compile(scenario_rules(scenario))
            for number, request in enumerate(scenario["requests"], 1):
                where = "%s, request %d: %s %s from %s" % (scenario["name"], number, request["method"],
                                                         request["target"], request["ip"])
                wall.queue = {}
                got = wall.check(request["ip"], request["method"], request["target"], "Mozilla/5.0")
                reported = sorted({row["rule"] for row in wall.queue.values()})
                if request["expect"] == "allow":
                    self.assertEqual(got["action"], "allow", where)
                    self.assertEqual(reported, [], where + ": passed with nothing reported")
                else:
                    self.assertEqual({k: got[k] for k in ("action", "rule", "status")}, request["expect"], where)
                if "reports" in request:
                    self.assertEqual(reported, sorted(request["reports"]), where)


class Window(unittest.TestCase):
    def test_a_window_ending_lifts_the_cap(self):
        wall = Firewall(FakeCore())
        wall.rules = wall._compile(dict(SHARED["base"], limits={"rules": [LOGIN]}))
        with mock.patch("analytics_platform.firewall.time.time", return_value=4500.0):
            got = [wall.check("198.51.100.7", "POST", "/wp-login.php")["rule"] for _ in range(3)]
            self.assertEqual(got, ["", "", "limit:wp.login"])
        with mock.patch("analytics_platform.firewall.time.time", return_value=4545.0):
            self.assertEqual(wall.check("198.51.100.7", "POST", "/wp-login.php")["rule"], "", "a new window, a new count")
        self.assertEqual(wall.bans, {}, "a page limit never bans")

    def test_a_shared_counter_gets_its_own_key_and_each_path_stays_here(self):
        keys = []
        wall = Firewall(FakeCore(), counter=lambda key, ttl: keys.append((key, ttl)) or 1)
        every_page = {"id": "any", "action": "monitor", "limit": 5, "window": 600, "each": "path", "path": {"prefix": ["/"]}}
        wall.rules = wall._compile(dict(SHARED["base"], limits={"rules": [LOGIN, every_page]}))
        with mock.patch("analytics_platform.firewall.time.time", return_value=4500.0):
            wall.check("2001:db8:1:2::1", "POST", "/wp-login.php")
        self.assertEqual(keys, [("afw:%s:l:wp.login:2001:db8:1:2::/64:100" % FakeCore.site_id, 90)])
        self.assertEqual(list(wall.page_counts), [("any", "2001:db8:1:2::/64", "/wp-login.php")])
        self.assertEqual(wall.limit_counts, {})

    def test_filling_the_per_page_counts_does_not_reset_a_limit(self):
        # The "any one page" watcher makes a count per address and page;
        # asking for made-up paths must not push the login limit's count out
        # and start it again. The cap made small, as test_hardening does.
        every_page = {"id": "any", "action": "monitor", "limit": 600, "window": 600, "each": "path", "path": {"prefix": ["/"]}}
        with mock.patch("analytics_platform.firewall.COUNTER_MAX", 5), \
                mock.patch("analytics_platform.firewall.time.time", return_value=4500.0):
            wall = Firewall(FakeCore())
            wall.rules = wall._compile(dict(SHARED["base"], limits={"rules": [LOGIN, every_page]}))
            self.assertEqual(wall.check("198.51.100.7", "POST", "/wp-login.php")["rule"], "")
            for i in range(20):
                wall.check("198.51.100.9", "GET", "/made-up/%d" % i)
            self.assertEqual(len(wall.page_counts), 5, "the per-page table is capped")
            self.assertEqual(wall.check("198.51.100.7", "POST", "/wp-login.php")["rule"], "", "the second")
            self.assertEqual(wall.check("198.51.100.7", "POST", "/wp-login.php")["rule"], "limit:wp.login",
                             "the third: still counted from the first")


def limited_platform():
    with contextlib.redirect_stdout(io.StringIO()):  # no site_id: it says nothing is sent
        made = create_platform(site_id="", secret="s", endpoint="", firewall={},
                               errors=False, analytics=False, performance=False, crawlers=False, forms=False,
                               headers=False, audit=False, flags=False, maintenance=False, inventory=False,
                               posture=False, resources=False, proxy=False)
    made.firewall.rules = made.firewall._compile(dict(SHARED["base"], rate={"limit": 1000, "window": 60},
                                                      limits={"rules": [LOGIN]}))
    return made


class Answers(unittest.TestCase):
    """429 with the limit's own window as Retry-After and the plain-text body,
    in every integration that answers the rate limit's 429."""

    def test_wsgi(self):
        app = limited_platform().wsgi(site)
        for _ in range(2):
            self.assertEqual(wsgi_call(app, method="POST", path="/wp-login.php")[2], b"the site")
        status, headers, body = wsgi_call(app, method="POST", path="/wp-login.php")
        self.assertEqual((status, headers["Retry-After"], body), ("429 Too Many Requests", "45", LIMIT_BODY))
        self.assertEqual(headers["Content-Type"], "text/plain; charset=utf-8")

    def test_asgi(self):
        app = limited_platform().asgi(asgi_site)
        calls = [asgi_login(app) for _ in range(3)]
        self.assertEqual([call[0] for call in calls], [200, 200, 429])
        status, headers, body = calls[2]
        self.assertEqual((headers[b"retry-after"], body), (b"45", LIMIT_BODY))

    # Django's stand-in comes from test_challenge; borrowed, not inherited,
    # so its own tests don't run twice.
    setUp = test_challenge.Django.setUp
    tearDown = test_challenge.Django.tearDown

    def test_django(self):
        self.integration._platform = limited_platform()
        middleware = self.integration.PlatformMiddleware(lambda request: FakeDjangoResponse(b"the site"))

        def login():
            request = FakeDjangoRequest(method="POST")
            request.path = request.META["RAW_URI"] = "/wp-login.php"
            return middleware(request)

        self.assertEqual([login().content for _ in range(2)], [b"the site"] * 2)
        response = login()
        self.assertEqual((response.status_code, response.headers["Retry-After"], response.content), (429, "45", LIMIT_BODY))


def asgi_login(app):
    """A POST to the login page (test_challenge's asgi_call asks for /pricing)."""
    scope = {"type": "http", "method": "POST", "path": "/wp-login.php", "raw_path": b"/wp-login.php",
             "query_string": b"", "scheme": "http", "client": ("203.0.113.5", 5000), "headers": []}
    sent = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    asyncio.run(app(scope, receive, send))
    return sent[0]["status"], dict(sent[0]["headers"]), b"".join(m.get("body", b"") for m in sent[1:])


class Prepared(unittest.TestCase):
    def test_the_matchers_take_a_prepared_request_alike(self):
        from analytics_platform.request_rules import compile_limits, compile_rules, match_limits, match_request, prepare
        limits = compile_limits({"rules": [{"id": "any", "action": "block", "limit": 1, "window": 60,
                                            "each": "path", "path": {"prefix": ["/"]}}]})
        rules = compile_rules({"rules": [{"id": "dots", "action": "block", "path": {"contains": ["/admin"]}}]})
        raw = ("get", "/x;y/../admin?q=1", "UA")
        prepared = prepare(*raw)
        self.assertEqual(match_limits(limits, prepared=prepared), match_limits(limits, raw[0], raw[1]))
        self.assertEqual(match_request(rules, prepared=prepared), match_request(rules, *raw))


if __name__ == "__main__":
    unittest.main()
