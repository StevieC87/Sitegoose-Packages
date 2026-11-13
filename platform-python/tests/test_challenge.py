"""The browser check (rule `challenge`): the shared cases every client runs
(sdk/protocols/challenge-cases.json), then the check as each integration
answers it.

    python3 -m unittest discover -s tests
"""
import asyncio
import contextlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import types
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analytics_platform import challenge, create_platform  # noqa: E402
from analytics_platform.firewall import LAYERS, Firewall  # noqa: E402

CASES = os.path.join(os.path.dirname(__file__), "..", "..", "protocols", "challenge-cases.json")
with open(CASES) as handle:
    SHARED = json.load(handle)

HTML = "text/html,application/xhtml+xml,*/*;q=0.8"


class FakeCore:
    valid = False
    site_id = "a" * 24
    secret = SHARED["secret"]

    def log(self, *_args):
        pass


def rules(mode="monitor", check=SHARED["challenge"], **more):
    return dict({"v": 1, "enabled": True, "mode": mode, "challenge": check}, **more)


def firewall(**options):
    wall = Firewall(FakeCore())
    wall.rules = wall._compile(rules(**options))
    return wall


class SharedCases(unittest.TestCase):
    key = challenge.pass_key(SHARED["secret"])

    def test_tokens(self):
        for case in SHARED["tokens"]:
            self.assertEqual(challenge.who(case["ip"]), case["who"], case["ip"])
            self.assertEqual(challenge.make_pass(self.key, case["ip"], case["now"]), case["token"], case["ip"])

    def test_checks(self):
        for case in SHARED["checks"]:
            got = challenge.is_valid(self.key, case["ip"], case["cookie"], case["now"])
            self.assertEqual(got, case["valid"], case["why"])

    def test_decisions(self):
        for case in SHARED["decisions"]:
            request = case["request"]
            wall = firewall()
            cookie = "__sg_pass=" + request["cookie"] if request["cookie"] else ""
            decision = wall.check(request["ip"], request["method"], request["path"], "Mozilla/5.0",
                                  request["accept"], cookie, case["now"])
            self.assertEqual(decision["rule"] == "challenge", case["challenged"], case["why"])
            if case["challenged"]:
                self.assertEqual((decision["action"], decision["status"]), ("block", 503), case["why"])


class Decision(unittest.TestCase):
    def test_allow_and_goodbots_are_never_checked(self):
        wall = firewall(allow=["198.51.100.9"], goodbots=["192.0.2.0/24"])
        self.assertEqual(wall.check("198.51.100.9", "GET", "/", "", HTML)["rule"], "")
        self.assertEqual(wall.check("192.0.2.5", "GET", "/", "", HTML)["rule"], "")
        self.assertEqual(wall.check("203.0.113.5", "GET", "/", "", HTML)["rule"], "challenge")

    def test_blocks_even_in_monitor_mode_and_with_the_mode_overridden(self):
        wall = Firewall(FakeCore(), mode="monitor")
        wall.rules = wall._compile(rules(mode="block"))
        self.assertEqual(wall.check("203.0.113.5", "GET", "/", "", HTML)["action"], "block")

    def test_earlier_rules_win_in_block_mode(self):
        wall = firewall(mode="block", deny=["203.0.113.0/24"])
        self.assertEqual(wall.check("203.0.113.5", "GET", "/", "", HTML)["rule"], "deny")
        wall = firewall(mode="block", rate={"limit": 1, "window": 60})
        got = [wall.check("203.0.113.5", "GET", "/", "", HTML)["rule"] for _ in range(2)]
        self.assertEqual(got, ["challenge", "rate"])

    def test_a_match_only_watched_still_gets_the_check(self):
        wall = firewall(deny=["203.0.113.0/24"])
        got = wall.check("203.0.113.5", "GET", "/", "", HTML)
        self.assertEqual((got["rule"], got["action"], got["status"]), ("challenge", "block", 503))
        self.assertEqual(sorted((r["rule"], r["action"]) for r in wall.queue.values()),
                         [("challenge", "block"), ("deny", "monitor")])
        # Not a page load: the watched match passes, as before.
        self.assertEqual(wall.check("203.0.113.5", "POST", "/", "", HTML)["action"], "monitor")

    def test_a_pass_from_this_server_lets_the_next_request_through(self):
        wall = firewall()
        token = challenge.make_pass(wall.pass_key, "203.0.113.5")
        cookie = "theme=dark; __sg_pass=" + token
        self.assertEqual(wall.check("203.0.113.5", "GET", "/", "", HTML, cookie)["rule"], "")

    def test_no_challenge_key_changes_nothing(self):
        wall = firewall(check=None)
        self.assertEqual(wall.check("203.0.113.5", "GET", "/", "", HTML), {"action": "allow", "rule": "", "status": 200})

    def test_reported_as_challenge_block(self):
        wall = firewall()
        for _ in range(2):
            wall.check("203.0.113.5", "GET", "/pricing?x=1", "Mozilla/5.0", HTML)
        rows = list(wall.queue.values())
        self.assertEqual(len(rows), 1)
        self.assertEqual({k: rows[0][k] for k in ("ip", "rule", "action", "method", "path", "hits")},
                         {"ip": "203.0.113.5", "rule": "challenge", "action": "block", "method": "GET",
                          "path": "/pricing", "hits": 2})


class Page(unittest.TestCase):
    key = challenge.pass_key("s")

    def test_page(self):
        status, headers, body = challenge.page(self.key, "203.0.113.5", "GET")
        headers = dict(headers)
        self.assertEqual(status, 503)
        self.assertEqual(headers["Content-Type"], "text/html; charset=utf-8")
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(headers["X-Robots-Tag"], "noindex")
        nonce = re.search(r"script-src 'nonce-([^']+)'", headers["Content-Security-Policy"]).group(1)
        text = body.decode()
        self.assertIn('<script nonce="%s">' % nonce, text)
        self.assertIn(challenge.make_pass(self.key, "203.0.113.5"), text)
        self.assertIn("Max-Age=86400; Path=/; SameSite=Lax", text)
        self.assertIn('s=location.protocol==="https:"', text)
        self.assertIn('(s?"; Secure":"")', text)
        self.assertIn("location.reload()", text)
        self.assertIn("<noscript>", text)

    def test_a_ten_digit_day_is_read(self):
        # Ten digits, as the Node and PHP clients take (far off, but the three agree).
        now = 1234567890 * 86400
        value = challenge.make_pass(self.key, "203.0.113.5", now)
        self.assertTrue(value.startswith("1234567890."))
        self.assertTrue(challenge.is_valid(self.key, "203.0.113.5", value, now))

    def test_the_script_stops_after_three_reloads_a_minute(self):
        script = challenge.script("20761.0ddc48fd8c38f7a225623a9a27f1d364")
        self.assertIn('sessionStorage.getItem(k)', script)
        self.assertIn("r>=3", script)
        self.assertIn("Date.now()-x<60000", script)
        self.assertIn("address keeps changing", script)

    @unittest.skipUnless(shutil.which("node"), "node runs the page's script")
    def test_the_script_in_a_stub_browser(self):
        # Each run is one page load: the cookie jar and sessionStorage carry
        # over between them, as they do in a browser tab.
        harness = r"""
        const script = process.argv[1];
        function load(state) {
          let reloaded = false, text = "";
          global.location = { protocol: state.https ? "https:" : "http:", reload() { reloaded = true; } };
          global.document = {
            get cookie() { return state.jar; },
            set cookie(v) {
              state.set.push(v);
              if (!state.cookies) return;
              const [k, val] = v.split(";")[0].split("=");
              const jar = new Map(state.jar ? state.jar.split("; ").map((c) => c.split("=")) : [["theme", "dark"]]);
              jar.set(k, val);
              state.jar = [...jar].map(([a, b]) => a + "=" + b).join("; ");
            },
            getElementById() { return { set textContent(t) { text = t; } }; },
          };
          global.sessionStorage = state.storage === null
            ? { getItem() { throw new Error("blocked"); }, setItem() { throw new Error("blocked"); } }
            : { getItem(k) { return state.storage[k] ?? null; }, setItem(k, v) { state.storage[k] = v; } };
          eval(script);
          return { reloaded, text };
        }
        const out = {};
        let s = { jar: "", set: [], cookies: true, storage: {}, https: true };
        out.loads = [1, 2, 3, 4].map(() => load(s));
        out.secure = s.set[0];
        s = { jar: "", set: [], cookies: false, storage: {}, https: false };
        out.noCookies = load(s); out.plain = s.set[0];
        s = { jar: "", set: [], cookies: true, storage: null, https: false };
        out.blocked = [1, 2, 3, 4].map(() => load(s));
        out.blockedJar = s.jar;
        console.log(JSON.stringify(out));
        """
        script = challenge.script("20761.0ddc48fd8c38f7a225623a9a27f1d364")
        out = json.loads(subprocess.run(["node", "-e", harness, script], capture_output=True, text=True,
                                        check=True, timeout=30).stdout)
        self.assertEqual([load["reloaded"] for load in out["loads"]], [True, True, True, False])
        self.assertIn("address keeps changing", out["loads"][3]["text"])
        self.assertTrue(out["secure"].endswith("; Path=/; SameSite=Lax; Secure"))
        self.assertEqual(out["noCookies"]["reloaded"], False)
        self.assertIn("allow cookies", out["noCookies"]["text"])
        self.assertTrue(out["plain"].endswith("SameSite=Lax"), "no Secure on http")
        # Storage blocked: the tries are counted in a cookie instead, so it
        # still stops rather than reloading for ever.
        self.assertEqual([load["reloaded"] for load in out["blocked"]], [True, True, True, False])
        self.assertIn("__sg_tries=3", out["blockedJar"])

    def test_a_fresh_nonce_each_time(self):
        first = dict(challenge.page(self.key, "203.0.113.5", "GET")[1])["Content-Security-Policy"]
        second = dict(challenge.page(self.key, "203.0.113.5", "GET")[1])["Content-Security-Policy"]
        self.assertNotEqual(first, second)

    def test_head_gets_no_body(self):
        status, headers, body = challenge.page(self.key, "203.0.113.5", "HEAD")
        self.assertEqual((status, body), (503, b""))
        self.assertIn("Content-Security-Policy", dict(headers))


class FetchHeaders(unittest.TestCase):
    def test_layers_and_server_name_on_every_fetch(self):
        sent = []

        class Core(FakeCore):
            def send(self, module, path, **options):
                sent.append(options["headers"])
                return None

        wall = Firewall(Core())
        wall._sync()
        wall.etag = '"x"'
        wall._sync()
        for headers in sent:
            self.assertEqual(headers["X-Firewall-Layers"], LAYERS)
            self.assertEqual(LAYERS, "app check")
            self.assertTrue(0 < len(headers["X-Server-Name"]) <= 100)
        self.assertEqual(sent[1]["If-None-Match"], '"x"')


def platform(check=SHARED["challenge"], **firewall_options):
    with contextlib.redirect_stdout(io.StringIO()):  # no site_id: it says nothing is sent
        made = create_platform(site_id="", secret="s", endpoint="", firewall=dict(firewall_options),
                               errors=False, analytics=False, performance=False, crawlers=False, forms=False,
                               headers=False, audit=False, flags=False, maintenance=False, inventory=False,
                               posture=False, resources=False, proxy=False)
    made.firewall.rules = made.firewall._compile(rules(check=check))
    return made


def site(environ, start_response):
    start_response("200 OK", [("Content-Type", "text/plain")])
    return [b"the site"]


def wsgi_call(app, method="GET", accept=HTML, path="/pricing", cookie=None, **extra):
    environ = {"REQUEST_METHOD": method, "PATH_INFO": path, "QUERY_STRING": "", "REMOTE_ADDR": "203.0.113.5",
               "wsgi.url_scheme": "http", "HTTP_ACCEPT": accept}
    if cookie:
        environ["HTTP_COOKIE"] = cookie
    environ.update(extra)
    seen = {}

    def start_response(status, headers, exc_info=None):
        seen["status"], seen["headers"] = status, dict(headers)

    body = b"".join(app(environ, start_response))
    return seen["status"], seen["headers"], body


class Wsgi(unittest.TestCase):
    def test_a_browser_page_gets_the_check(self):
        status, headers, body = wsgi_call(platform().wsgi(site))
        self.assertEqual(status, "503 Service Unavailable")
        self.assertEqual(headers["Content-Type"], "text/html; charset=utf-8")
        self.assertIn(b"__sg_pass", body)

    def test_head_gets_the_check_without_a_body(self):
        status, _, body = wsgi_call(platform().wsgi(site), method="HEAD")
        self.assertEqual((status, body), ("503 Service Unavailable", b""))

    def test_post_and_json_reach_the_site(self):
        app = platform().wsgi(site)
        self.assertEqual(wsgi_call(app, method="POST")[2], b"the site")
        self.assertEqual(wsgi_call(app, accept="application/json")[2], b"the site")
        self.assertEqual(wsgi_call(app, path="/api/orders")[2], b"the site")

    def test_with_a_pass_the_site_answers(self):
        made = platform()
        token = challenge.make_pass(made.firewall.pass_key, "203.0.113.5")
        self.assertEqual(wsgi_call(made.wsgi(site), cookie="__sg_pass=" + token)[2], b"the site")

    def test_no_challenge_changes_nothing(self):
        self.assertEqual(wsgi_call(platform(check=None).wsgi(site))[2], b"the site")

    def test_other_refusals_keep_their_status_line(self):
        made = platform()
        made.firewall.rules = made.firewall._compile(rules(mode="block", deny=["203.0.113.5"]))
        self.assertEqual(wsgi_call(made.wsgi(site))[0], "403 Forbidden")


def asgi_call(app, method="GET", accept=HTML, extra=()):
    scope = {"type": "http", "method": method, "path": "/pricing", "raw_path": b"/pricing", "query_string": b"",
             "scheme": "http", "client": ("203.0.113.5", 5000), "headers": [(b"accept", accept.encode()), *extra]}
    sent = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    asyncio.run(app(scope, receive, send))
    return sent[0]["status"], dict(sent[0]["headers"]), b"".join(m.get("body", b"") for m in sent[1:])


async def asgi_site(scope, receive, send):
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": b"the site"})


class Asgi(unittest.TestCase):
    def test_a_browser_page_gets_the_check(self):
        status, headers, body = asgi_call(platform().asgi(asgi_site))
        self.assertEqual(status, 503)
        self.assertIn(b"content-security-policy", headers)
        self.assertIn(b"__sg_pass", body)

    def test_post_and_json_reach_the_site(self):
        app = platform().asgi(asgi_site)
        self.assertEqual(asgi_call(app, method="POST"), (200, {}, b"the site"))
        self.assertEqual(asgi_call(app, accept="application/json"), (200, {}, b"the site"))

    def test_no_challenge_changes_nothing(self):
        self.assertEqual(asgi_call(platform(check=None).asgi(asgi_site)), (200, {}, b"the site"))

    def test_a_pass_in_a_second_cookie_field_counts(self):
        # HTTP/2 may split the Cookie header over several fields.
        made = platform()
        token = challenge.make_pass(challenge.pass_key("s"), "203.0.113.5")
        extra = [(b"cookie", b"__sg_pass=" + token.encode()), (b"cookie", b"theme=dark")]
        self.assertEqual(asgi_call(made.asgi(asgi_site), extra=extra), (200, {}, b"the site"))


class FakeDjangoResponse:
    def __init__(self, content=b"", status=200):
        self.content, self.status_code, self.headers = content, status, {}

    def __setitem__(self, name, value):
        self.headers[name] = value


class FakeDjangoRequest:
    def __init__(self, method="GET", accept=HTML):
        self.method, self.path = method, "/pricing"
        self.headers = {"Accept": accept}
        self.META = {"REMOTE_ADDR": "203.0.113.5", "QUERY_STRING": "", "RAW_URI": "/pricing"}
        self.body = b""


class Django(unittest.TestCase):
    """The Django middleware, with django itself stood in for (it isn't a
    dependency of the package or its tests)."""

    def setUp(self):
        stubs = {"django": types.ModuleType("django"), "django.conf": types.ModuleType("django.conf"),
                 "django.http": types.ModuleType("django.http")}
        stubs["django.conf"].settings = types.SimpleNamespace(ANALYTICS_PLATFORM={})
        stubs["django.http"].HttpResponse = FakeDjangoResponse
        self.saved = {name: sys.modules.get(name) for name in list(stubs) + ["analytics_platform.django"]}
        sys.modules.update(stubs)
        sys.modules.pop("analytics_platform.django", None)
        import analytics_platform.django as integration
        self.integration = integration

    def tearDown(self):
        for name, module in self.saved.items():
            if module is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = module

    def middleware(self, check=SHARED["challenge"]):
        self.integration._platform = platform(check=check)
        return self.integration.PlatformMiddleware(lambda request: FakeDjangoResponse(b"the site"))

    def test_a_browser_page_gets_the_check(self):
        response = self.middleware()(FakeDjangoRequest())
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.headers["Content-Type"], "text/html; charset=utf-8")
        self.assertIn(b"__sg_pass", response.content)

    def test_head_gets_no_body(self):
        response = self.middleware()(FakeDjangoRequest(method="HEAD"))
        self.assertEqual((response.status_code, response.content), (503, b""))

    def test_post_and_json_reach_the_site(self):
        middleware = self.middleware()
        self.assertEqual(middleware(FakeDjangoRequest(method="POST")).content, b"the site")
        self.assertEqual(middleware(FakeDjangoRequest(accept="application/json")).content, b"the site")

    def test_no_challenge_changes_nothing(self):
        self.assertEqual(self.middleware(check=None)(FakeDjangoRequest()).content, b"the site")


if __name__ == "__main__":
    unittest.main()
