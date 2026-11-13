"""The one-line setup: keys from ANALYTICS_* or a .env file (never written to
os.environ), and analytics_platform.start putting itself in front of Flask
and FastAPI/Starlette apps on their first request, and Django's settings
block becoming optional. The framework tests skip where the framework isn't
installed; run them where Flask, FastAPI (with httpx) and Django are."""
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analytics_platform import Platform, PlatformMiddleware, _env  # noqa: E402

SITE = "a" * 24
KEYS = {"ANALYTICS_SITE_ID": SITE, "ANALYTICS_SITE_SECRET": "s3cret", "ANALYTICS_ENDPOINT": "http://127.0.0.1:9"}
OFF = {name: False for name in ("firewall", "errors", "analytics", "performance", "crawlers", "forms", "headers", "audit",
                                "flags", "maintenance", "inventory", "posture", "resources", "proxy")}


def installed(name):
    try:
        __import__(name)
        return True
    except Exception:
        return False


class EnvTest(unittest.TestCase):
    def test_options_from_the_environment(self):
        found = _env.options_from({**KEYS, "ANALYTICS_TRUST_PROXY": "2", "ANALYTICS_SERVER_NAME": "api"})
        self.assertEqual(found, {"site_id": SITE, "secret": "s3cret", "endpoint": "http://127.0.0.1:9",
                                 "server_name": "api", "trust_proxy": 2})
        self.assertEqual(_env.options_from({"ANALYTICS_TRUST_PROXY": "Cloudflare"})["trust_proxy"], "cloudflare")
        self.assertEqual(_env.options_from({"ANALYTICS_FIREWALL_ENDPOINT": "https://x"})["endpoint"], "https://x")
        self.assertEqual(_env.options_from({"ANALYTICS_TRUST_PROXY": "nonsense", "ANALYTICS_SITE_ID": "  "}), {})

    def test_dotenv_lines_are_read_and_never_loaded(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, ".env")
            with open(path, "w") as handle:
                handle.write('DATABASE_URL=x\nANALYTICS_SITE_ID="%s"\nexport ANALYTICS_SITE_SECRET=from-file # note\n' % SITE)
            with mock.patch.dict(os.environ, {"ANALYTICS_ENDPOINT": "http://127.0.0.1:9"}, clear=True):
                filled = _env.from_environment({"secret": None}, path)
                self.assertNotIn("ANALYTICS_SITE_SECRET", os.environ)
                self.assertNotIn("DATABASE_URL", os.environ)
        self.assertEqual((filled["site_id"], filled["secret"], filled["endpoint"]), (SITE, "from-file", "http://127.0.0.1:9"))

    def test_the_environment_wins_over_the_file_and_given_options_over_both(self):
        with tempfile.TemporaryDirectory() as folder:
            path = os.path.join(folder, ".env")
            with open(path, "w") as handle:
                handle.write("ANALYTICS_SITE_SECRET=file\nANALYTICS_SERVER_NAME=file\n")
            with mock.patch.dict(os.environ, {"ANALYTICS_SITE_SECRET": "env"}, clear=True):
                filled = _env.from_environment({"server_name": "given"}, path)
        self.assertEqual((filled["secret"], filled["server_name"]), ("env", "given"))

    def test_platform_with_no_keys_reads_them_from_the_environment(self):
        with mock.patch.dict(os.environ, KEYS, clear=True):
            platform = Platform(**OFF)
        self.assertTrue(platform.core.valid)
        with mock.patch.dict(os.environ, {}, clear=True), mock.patch("builtins.print") as printed:
            self.assertFalse(Platform(**OFF).core.valid)
        self.assertIn("ANALYTICS_SITE_SECRET", printed.call_args[0][0])


def started():
    """analytics_platform.start, with a fresh platform made from KEYS."""
    from analytics_platform import start
    start._made = None
    return start


@unittest.skipUnless(installed("flask"), "Flask isn't installed")
class FlaskTest(unittest.TestCase):
    def test_hooks_itself_in_on_the_first_request_wherever_the_import_is(self):
        from flask import Flask
        app = Flask("before")  # made before the import
        app.get("/")(lambda: "ok")
        with mock.patch.dict(os.environ, KEYS):
            start = started()
            response = app.test_client().get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIs(app.extensions["analytics_platform"], start._made)
        wrapped = app.wsgi_app
        app.test_client().get("/")
        self.assertIs(app.wsgi_app, wrapped, "wrapped once, not on every request")

    def test_an_app_set_up_by_hand_is_left_alone(self):
        from flask import Flask
        with mock.patch.dict(os.environ, KEYS):
            started()
            own = Platform(**OFF)
            app = Flask("by_hand")
            app.get("/")(lambda: "ok")
            own.init_flask(app)
            wrapped = app.wsgi_app
            self.assertEqual(app.test_client().get("/").status_code, 200)
        self.assertIs(app.extensions["analytics_platform"], own)
        self.assertIs(app.wsgi_app, wrapped)


@unittest.skipUnless(installed("fastapi") and installed("httpx"), "FastAPI or httpx isn't installed")
class FastAPITest(unittest.TestCase):
    def test_outermost_of_your_middleware_and_not_in_a_mounted_app(self):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from starlette.middleware.gzip import GZipMiddleware
        with mock.patch.dict(os.environ, KEYS):
            started()
            app = FastAPI()
            app.add_middleware(GZipMiddleware)
            sub = FastAPI()
            sub.get("/x")(lambda: {"ok": True})
            app.mount("/sub", sub)
            app.get("/")(lambda: {"ok": True})
            client = TestClient(app)
            self.assertEqual(client.get("/").status_code, 200)
            self.assertEqual(client.get("/sub/x").status_code, 200)
        self.assertEqual([m.cls for m in app.user_middleware], [PlatformMiddleware, GZipMiddleware])
        self.assertEqual([m.cls for m in sub.user_middleware], [], "a mounted app isn't counted twice")

    def test_an_app_with_it_by_hand_gets_no_second_one(self):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        with mock.patch.dict(os.environ, KEYS):
            started()
            app = FastAPI()
            app.add_middleware(PlatformMiddleware, platform=Platform(**OFF))
            app.get("/")(lambda: {"ok": True})
            self.assertEqual(TestClient(app).get("/").status_code, 200)
        self.assertEqual([m.cls for m in app.user_middleware], [PlatformMiddleware])


@unittest.skipUnless(installed("django"), "Django isn't installed")
class DjangoTest(unittest.TestCase):
    def test_no_settings_block_the_keys_from_the_projects_dotenv(self):
        from django.conf import settings
        with tempfile.TemporaryDirectory() as folder:
            with open(os.path.join(folder, ".env"), "w") as handle:
                handle.write("\n".join("%s=%s" % item for item in KEYS.items()))
            if not settings.configured:
                settings.configure(BASE_DIR=folder)
            else:
                settings.BASE_DIR = folder
            from analytics_platform import django as integration
            integration._platform = None
            with mock.patch.dict(os.environ, {}, clear=True):
                platform = integration.get_platform()
                self.assertNotIn("ANALYTICS_SITE_SECRET", os.environ)
        self.assertTrue(platform.core.valid)


if __name__ == "__main__":
    unittest.main()
