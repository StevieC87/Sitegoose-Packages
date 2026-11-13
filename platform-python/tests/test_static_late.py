"""A static-looking request counted after the response (firewall.md,
`rate`): compared with the counts first, so an address already over is
refused its files, then counted toward the rate and the page limits it
skipped when the router sent it to a route that isn't a file's
("search/<str:q>" took "/search/x.css") or it answered 400 or more. Through
plain WSGI, Flask (stood in for), ASGI (Starlette, FastAPI) and Django
(stood in for).

    python3 -m unittest discover -s tests
"""
import asyncio
import contextlib
import io
import os
import sys
import types
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analytics_platform import create_platform  # noqa: E402
from analytics_platform.firewall import Firewall, routed_to_page  # noqa: E402
import test_challenge  # noqa: E402
from test_challenge import FakeDjangoRequest, FakeDjangoResponse  # noqa: E402

IP = "203.0.113.5"
SEARCH = {"rules": [{"id": "search", "action": "block", "limit": 2, "window": 60, "path": {"prefix": ["/search"]}}]}


def rules(**more):
    data = {"v": 1, "enabled": True, "mode": "block", "allow": [], "deny": [], "lists": [], "shared": [],
            "goodbots": [], "rate": None, "banned": [], "ban": None, "limits": SEARCH}
    data.update(more)
    return data


def limited(**more):
    with contextlib.redirect_stdout(io.StringIO()):
        made = create_platform(site_id="", secret="s", endpoint="", firewall={},
                               errors=False, analytics=False, performance=False, crawlers=False, forms=False,
                               headers=False, audit=False, flags=False, maintenance=False, inventory=False,
                               posture=False, resources=False, proxy=False)
    made.firewall.rules = made.firewall._compile(rules(**more))
    return made


class FakeCore:
    valid = False
    site_id = "a" * 24
    secret = "s"

    def log(self, *_args):
        pass


def wsgi_get(app, path):
    """One GET as a WSGI server sends it, closing the response once sent."""
    environ = {"REQUEST_METHOD": "GET", "PATH_INFO": path, "QUERY_STRING": "", "REMOTE_ADDR": IP, "wsgi.url_scheme": "http"}
    seen = {}

    def start_response(status, headers, exc_info=None):
        seen["status"] = int(status.split(" ")[0])

    result = app(environ, start_response)
    b"".join(result)
    if hasattr(result, "close"):
        result.close()
    return seen["status"]


def wsgi_site(route=None, status="200 OK", content_type="text/html"):
    def site(environ, start_response):
        if route:
            environ["analytics_platform.route"] = route
        start_response(status, [("Content-Type", content_type)])
        return [b"x"]
    return site


class Firewalls(unittest.TestCase):
    def test_peek_adds_nothing_and_an_address_over_is_refused_its_files(self):
        wall = Firewall(FakeCore())
        wall.rules = wall._compile(rules())
        for _ in range(5):
            self.assertEqual(wall.check(IP, "GET", "/search/app.css")["rule"], "")
        self.assertEqual([wall.check(IP, "GET", "/search")["rule"] for _ in range(3)], ["", "", "limit:search"])
        self.assertEqual(wall.check(IP, "GET", "/search/app.css")["rule"], "limit:search")

    def test_a_shared_count_seen_over_refuses_the_files_without_adding(self):
        shared = {}

        def counter(key, ttl):
            shared[key] = shared.get(key, 0) + 1
            return shared[key]
        wall = Firewall(FakeCore(), counter=counter)
        wall.rules = wall._compile(rules())
        self.assertTrue(wall.check(IP, "GET", "/search/app.css")["static"])
        self.assertEqual(shared, {})
        self.assertEqual([wall.check(IP, "GET", "/search")["rule"] for _ in range(3)], ["", "", "limit:search"])
        self.assertEqual(wall.check(IP, "GET", "/search/app.css")["rule"], "limit:search")
        self.assertEqual(list(shared.values()), [3])

    def test_routed_to_page(self):
        self.assertTrue(routed_to_page("search/<str:q>", "text/html; charset=utf-8"))
        self.assertTrue(routed_to_page("/search/{q}", ""))
        self.assertTrue(routed_to_page("^search/(?P<q>[^/]+)$", ""))
        self.assertFalse(routed_to_page("", "text/html"))
        self.assertFalse(routed_to_page(None, "text/html"))
        self.assertFalse(routed_to_page("avatars/<int:id>.png", "text/html"))
        self.assertFalse(routed_to_page("/static/{path:path}", ""))
        self.assertFalse(routed_to_page("/files/<name>", "application/pdf"))


class Wsgi(unittest.TestCase):
    def test_plain_wsgi_counts_an_error_only(self):
        made = limited()
        page = made.wsgi(wsgi_site())
        for _ in range(5):
            self.assertEqual(wsgi_get(page, "/search/x.css"), 200, "no router to ask: a 200 isn't counted")
        missing = made.wsgi(wsgi_site(status="404 Not Found"))
        self.assertEqual([wsgi_get(missing, "/search/y.css") for _ in range(4)], [404, 404, 404, 429])

    def test_a_file_answered_is_handed_back_as_the_app_gave_it(self):
        # The server's file wrapper (sendfile) stays: only a response that
        # may count is wrapped.
        made = limited(rate={"limit": 2, "window": 60})
        body = [b"body{}"]

        def files(environ, start_response):
            start_response("200 OK", [("Content-Type", "text/css")])
            return body
        environ = {"REQUEST_METHOD": "GET", "PATH_INFO": "/app.css", "QUERY_STRING": "", "REMOTE_ADDR": IP, "wsgi.url_scheme": "http"}
        self.assertIs(made.wsgi(files)(environ, lambda *a: None), body)
        missing = made.wsgi(wsgi_site(status="404 Not Found"))(dict(environ, PATH_INFO="/gone.css"), lambda *a: None)
        self.assertIsNot(missing, body)
        self.assertTrue(hasattr(missing, "close"))

    def test_flask_counts_a_routed_request_and_leaves_its_static_endpoint_alone(self):
        flask = types.ModuleType("flask")
        flask.g = types.SimpleNamespace()
        flask.request = types.SimpleNamespace()
        flask.got_request_exception = types.SimpleNamespace(connect=lambda *a, **k: None)
        saved = sys.modules.get("flask")
        sys.modules["flask"] = flask
        self.addCleanup(lambda: sys.modules.pop("flask") if saved is None else sys.modules.update(flask=saved))

        class App:
            def __init__(self):
                self.after = []
                self.wsgi_app = self.dispatch

            def before_request(self, fn):
                return fn

            def after_request(self, fn):
                self.after.append(fn)
                return fn

            def dispatch(self, environ, start_response):
                path = environ["PATH_INFO"]
                endpoint, rule, kind = (("static", "/search/<path:filename>", "text/css") if path.startswith("/search/files/")
                                        else ("search", "/search/<q>", "text/html"))
                flask.request.url_rule = types.SimpleNamespace(endpoint=endpoint, rule=rule)
                flask.request.environ = environ
                response = types.SimpleNamespace(status_code=200)
                for fn in self.after:
                    fn(response)
                start_response("200 OK", [("Content-Type", kind)])
                return [b"x"]

        app = limited().init_flask(App())
        for _ in range(5):
            self.assertEqual(wsgi_get(app.wsgi_app, "/search/files/app.css"), 200)
        self.assertEqual([wsgi_get(app.wsgi_app, "/search/x.css") for _ in range(4)], [200, 200, 200, 429])


def asgi_get(app, path, route=None, endpoint=None, content_type=b"text/html"):
    scope = {"type": "http", "method": "GET", "path": path, "raw_path": path.encode(), "query_string": b"",
             "scheme": "http", "client": (IP, 5000), "headers": []}
    sent = []

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    async def site(scope, receive, send):
        # The router updates the scope it was given, as Starlette's does.
        if route is not None:
            scope["route"] = route
        if endpoint is not None:
            scope["endpoint"] = endpoint
        await send({"type": "http.response.start", "status": 200, "headers": [(b"content-type", content_type)]})
        await send({"type": "http.response.body", "body": b"x"})

    asyncio.run(app(site)(scope, receive, send))
    return sent[0]["status"]


class StaticFiles:
    """Starlette's, by its name."""


class Asgi(unittest.TestCase):
    def test_a_route_counts_a_static_files_mount_does_not(self):
        made = limited()
        mount = types.SimpleNamespace(path="/search/files", app=StaticFiles())
        for _ in range(5):
            self.assertEqual(asgi_get(made.asgi, "/search/files/a.css", route=mount), 200)
            self.assertEqual(asgi_get(made.asgi, "/search/files/b.css", endpoint=StaticFiles()), 200)
            self.assertEqual(asgi_get(made.asgi, "/search/c.css", route=types.SimpleNamespace(path="/search/{q}"),
                                      content_type=b"text/css"), 200)
        route = types.SimpleNamespace(path="/search/{q}")
        self.assertEqual([asgi_get(made.asgi, "/search/x.css", route=route) for _ in range(4)], [200, 200, 200, 429])

    def test_a_starlette_endpoint_without_a_route_counts(self):
        made = limited()
        self.assertEqual([asgi_get(made.asgi, "/search/x.css", endpoint=lambda r: None) for _ in range(4)],
                         [200, 200, 200, 429])


    def test_a_visitor_gone_before_the_answer_is_not_an_error(self):
        made = limited(rate={"limit": 2, "window": 60})
        scope = {"type": "http", "method": "GET", "path": "/app.css", "raw_path": b"/app.css", "query_string": b"",
                 "scheme": "http", "client": (IP, 5000), "headers": []}

        async def receive():
            return {"type": "http.disconnect"}

        async def send(message):
            pass

        async def site(scope, receive, send):
            raise asyncio.CancelledError()

        for _ in range(5):
            with self.assertRaises(asyncio.CancelledError):
                asyncio.run(made.asgi(site)(dict(scope), receive, send))
        self.assertEqual(made.firewall.check(IP, "GET", "/app.css")["rule"], "")


class Django(unittest.TestCase):
    setUp = test_challenge.Django.setUp
    tearDown = test_challenge.Django.tearDown

    def ask(self, middleware, path):
        request = FakeDjangoRequest()
        request.path = request.META["RAW_URI"] = path
        response = middleware(request)
        for close in getattr(response, "_resource_closers", []):
            close()
        return response.status_code

    def test_a_resolved_view_counts_a_file_view_does_not(self):
        self.integration._platform = limited()

        def view(request):
            response = FakeDjangoResponse(b"x")
            response._resource_closers = []
            if request.path.startswith("/search/files/"):
                request.resolver_match = types.SimpleNamespace(route="search/files/<path:path>", _func_path="django.views.static.serve")
                response.headers["Content-Type"] = "text/html"
            else:
                request.resolver_match = types.SimpleNamespace(route="search/<str:q>", _func_path="shop.views.search")
                response.headers["Content-Type"] = "text/html; charset=utf-8"
            return response
        middleware = self.integration.PlatformMiddleware(view)
        for _ in range(5):
            self.assertEqual(self.ask(middleware, "/search/files/app.css"), 200)
        self.assertEqual([self.ask(middleware, "/search/x.css") for _ in range(4)], [200, 200, 200, 429])

    def test_whitenoise_answers_before_the_resolver(self):
        self.integration._platform = limited()

        def whitenoise(request):
            response = FakeDjangoResponse(b"body{}")
            response.headers["Content-Type"] = "text/css"
            return response
        middleware = self.integration.PlatformMiddleware(whitenoise)
        self.assertEqual([self.ask(middleware, "/search/app.css") for _ in range(5)], [200] * 5)


if __name__ == "__main__":
    unittest.main()
