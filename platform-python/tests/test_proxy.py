"""The first-party proxy: which addresses it answers, what it refuses, and
what it passes on to the collector. A real collector stands in for ours, so
the forwarding itself is checked and not just the gate.

    python3 -m unittest discover -s tests
"""
import os
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analytics_platform.proxy import Proxy, key_for, prefix_for  # noqa: E402

TRACKER = b"// a tracker" + b"x" * 600


class FakeCore:
    """A core with no sending of its own: the proxy talks to the collector."""

    valid = True
    secret = "s3cret"

    def __init__(self, endpoint):
        self.endpoint = endpoint
        self.logged = []

    def is_on(self, name):
        return True

    def log(self, module, *args):
        self.logged.append((module, args))


class Collector(BaseHTTPRequestHandler):
    """Stands in for our collector, and records what reached it."""

    seen = []

    def _answer(self):
        length = int(self.headers.get("content-length") or 0)
        body = self.rfile.read(length) if length else b""
        Collector.seen.append({"path": self.path, "method": self.command, "headers": dict(self.headers), "body": body})
        if self.path.endswith(".js"):
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.end_headers()
            self.wfile.write(TRACKER)
        else:
            self.send_response(202)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok":true}')

    do_GET = _answer
    do_POST = _answer

    def log_message(self, *args):
        pass


class ProxyTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = HTTPServer(("127.0.0.1", 0), Collector)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.endpoint = "http://127.0.0.1:%d" % cls.server.server_address[1]

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        Collector.seen = []
        self.proxy = Proxy(FakeCore(self.endpoint))

    def test_the_proxy_key_is_worked_out_as_the_collector_does(self):
        # The same vector is pinned in the collector, the backend and the other packages.
        self.assertEqual(key_for("0123456789abcdef01234567"), "8fc74dbbd4f088449862841cd29fcaee")

    def test_the_address_comes_from_the_secret(self):
        self.assertEqual(prefix_for("s3cret"), prefix_for("s3cret"))
        self.assertNotEqual(prefix_for("s3cret"), prefix_for("other"))
        self.assertRegex(prefix_for("s3cret"), r"^[a-f0-9]{8}$")

    def test_anything_that_is_not_ours_is_left_alone(self):
        for path in ("/", "/about", "/admin", "/%sx/js/v1/s.js" % self.proxy.prefix):
            self.assertIsNone(self.proxy.match(path), path)

    def test_only_the_tracker_files_we_know(self):
        for tail in ("js/", "js/v1/evil.js", "js/v1/../../../etc/passwd", "js/v1/s.php",
                     "other/v1/s.js", "api/", "api/../../secret"):
            found = self.proxy.match("/%s/%s" % (self.proxy.prefix, tail))
            kind, rest = found if found else ("bad", "")
            status, _, _ = self.proxy.handle(kind, rest)
            self.assertEqual(status, 404, tail)
        self.assertEqual(Collector.seen, [], "nothing reached the collector")

    def test_the_tracker_is_fetched_once_and_then_held(self):
        for _ in range(3):
            status, headers, body = self.proxy.handle(*self.proxy.match(self.proxy.script_url()))
            self.assertEqual(status, 200)
            self.assertEqual(body, TRACKER)
        self.assertEqual(len(Collector.seen), 1, "asked the collector once for three requests")
        self.assertEqual(Collector.seen[0]["path"], "/v1/s.js")

    def test_a_pinned_version_is_held_longer_than_a_major_one(self):
        def cache_control(tail):
            _, headers, _ = self.proxy.handle(*self.proxy.match("/%s/js/%s" % (self.proxy.prefix, tail)))
            return dict(headers).get("Cache-Control", "")

        self.assertIn("immutable", cache_control("v1.2.3/track.js"))
        self.assertIn("max-age=3600", cache_control("v1/s.js"))

    def test_visits_reach_the_collector_without_cookies(self):
        kind, rest = self.proxy.match(self.proxy.collect_url())
        status, _, body = self.proxy.handle(
            kind, rest, method="POST", query="v=1",
            headers={"content-type": "text/plain", "cookie": "sessionid=secret", "user-agent": "Mozilla/5.0"},
            body=b'{"event":"pageview"}', client_ip="198.51.100.4")
        self.assertEqual(status, 202)
        self.assertEqual(body, b'{"ok":true}')
        got = Collector.seen[0]
        self.assertEqual(got["path"], "/collectanalytics/e?v=1")
        self.assertEqual(got["body"], b'{"event":"pageview"}')
        self.assertEqual(got["headers"].get("X-Forwarded-For"), "198.51.100.4")
        self.assertEqual(got["headers"].get("X-Proxy-Key"), key_for("s3cret"), "so the collector believes the address")
        self.assertEqual(got["headers"].get("User-Agent"), "Mozilla/5.0")
        self.assertIsNone(got["headers"].get("Cookie"), "the site's own cookies stay on the site")

    def test_methods_the_tracker_never_uses_are_not_forwarded(self):
        kind, rest = self.proxy.match(self.proxy.collect_url())
        status, _, _ = self.proxy.handle(kind, rest, method="PUT")
        self.assertEqual(status, 404)
        self.assertEqual(Collector.seen, [])

    def test_switched_off_it_answers_nothing(self):
        off = Proxy(FakeCore(self.endpoint), enabled=False)
        self.assertIsNone(off.match(off.script_url()))


if __name__ == "__main__":
    unittest.main()
