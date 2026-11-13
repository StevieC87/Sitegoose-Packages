"""Database query timings (sdk/protocols/queries.md): the normalizer against
the cases every package shares (sdk/protocols/query-cases.json), which
request a query is counted under, the caps, the payload, and the hooks:
sqlite3 through watch_database for real, Django and SQLAlchemy for real when
they're installed.

    python3 -m unittest discover -s tests
"""
import asyncio
import json
import os
import sqlite3
import sys
import unittest
from importlib.util import find_spec
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analytics_platform import create_platform  # noqa: E402
from analytics_platform import queries as q  # noqa: E402

CASES = os.path.join(os.path.dirname(__file__), "..", "..", "protocols", "query-cases.json")
SITE = "a1b2c3d4e5f6a1b2c3d4e5f6"


def make_platform(**options):
    return create_platform(site_id=SITE, secret="s", endpoint="http://127.0.0.1:9",
                           firewall=False, analytics=False, flags=False, inventory=False, posture=False,
                           resources=False, proxy=False, maintenance=False, crawlers=False, forms=False,
                           audit=False, headers=False, errors=False, **options)


class Response:
    def __init__(self, status):
        self.status = status
        self.ok = 200 <= status < 300


class SharedCases(unittest.TestCase):
    def test_every_shared_case_comes_out_character_for_character(self):
        with open(CASES, encoding="utf-8") as handle:
            cases = json.load(handle)
        self.assertEqual(cases["max_statement"], q.MAX_STATEMENT)
        for case in cases["cases"]:
            self.assertEqual(q.normalize_statement(case["statement"], case["db"]), case["expected"],
                             "%s: %r" % (case["db"], case["statement"][:120]))

    def test_percent_placeholders_are_placeholders(self):
        sql = q._percent_placeholders("SELECT * FROM t WHERE a IN (%s, %s) AND b = %(b)s AND c %% 2 = 0")
        self.assertEqual(q.normalize_statement(sql, "postgresql"), "SELECT * FROM t WHERE a IN (?) AND b = ? AND c % ? = ?")

    def test_a_mongo_command_keeps_its_shape(self):
        text = q.mongo_text("find", {"find": "users", "filter": {"email": "a@b.c", "age": {"$gt": float("nan")}}})
        self.assertEqual(q.normalize_statement(text, "mongodb"), 'find users {"email":"?","age":{"$gt":"?"}}')
        text = q.mongo_text("delete", {"delete": "carts", "deletes": [{"q": {"_id": object()}, "limit": 1}]})
        self.assertEqual(q.normalize_statement(text, "mongodb"), 'delete carts {"_id":"?"}')
        self.assertEqual(q.mongo_text("insert", {"insert": "orders", "documents": [{"total": 9}]}), "insert orders")


class Recording(unittest.TestCase):
    def setUp(self):
        self.platform = make_platform()
        self.queries = self.platform._modules["performance"].queries
        self.db = self.platform.watch_database(sqlite3.connect(":memory:"))
        self.db.execute("CREATE TABLE orders (id INTEGER, total REAL)")
        self.queries.rows.clear()
        self.queries.per_minute.clear()

    def tearDown(self):
        self.queries.rows.clear()
        self.queries.retry = []
        self.platform.close()

    def rows(self):
        return {key[1:]: row for key, row in self.queries.rows.items()}

    def test_queries_go_under_the_route_the_request_is_timed_under(self):
        def app(environ, start_response):
            self.db.execute("SELECT total FROM orders WHERE id = ?", (12,))
            self.db.cursor().execute("SELECT total FROM orders WHERE id = 13")
            start_response("200 OK", [])
            return [b"ok"]

        self.platform.wsgi(app)({"REQUEST_METHOD": "GET", "PATH_INFO": "/orders/12", "REMOTE_ADDR": "1.2.3.4"}, lambda *a: None)
        rows = self.rows()
        self.assertEqual(list(rows), [("GET", "/orders/:id", "sqlite", "SELECT total FROM orders WHERE id = ?")])
        row = next(iter(rows.values()))
        self.assertEqual((row["count"], row["errors"], sum(row["buckets"])), (2, 0, 2))
        perf = self.platform._modules["performance"].rows
        self.assertEqual([key[1:3] for key in perf], [("GET", "/orders/:id")], "the same method and route as Server speed")

    def test_outside_any_request_a_query_is_background_and_inside_a_job_the_jobs(self):
        self.db.execute("SELECT 1")
        with self.platform.job("nightly-import"):
            self.db.execute("DELETE FROM orders WHERE total < 5")
        self.assertEqual(set(self.rows()), {
            ("JOB", "(background)", "sqlite", "SELECT ?"),
            ("JOB", "/(job) nightly-import", "sqlite", "DELETE FROM orders WHERE total < ?"),
        })

    def test_asgi_requests_fold_their_queries_by_the_routers_route(self):
        async def app(scope, receive, send):
            self.db.execute("SELECT * FROM orders WHERE id IN (1, 2, 3)")
            scope["route"] = type("Route", (), {"path": "/orders/{id}"})()
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b""})

        async def nothing(_):
            pass

        asyncio.run(self.platform.asgi(app)({"type": "http", "method": "POST", "path": "/orders/1", "headers": []}, None, nothing))
        self.assertEqual(list(self.rows()), [("POST", "/orders/{id}", "sqlite", "SELECT * FROM orders WHERE id IN (?)")])

    def test_a_failed_query_is_counted_and_raised(self):
        with self.assertRaises(sqlite3.OperationalError):
            self.db.execute("SELECT * FROM nowhere")
        row = self.rows()[("JOB", "(background)", "sqlite", "SELECT * FROM nowhere")]
        self.assertEqual((row["count"], row["errors"]), (1, 1))

    def test_past_50_statements_a_request_folds_the_rest_into_other(self):
        with self.platform.job("many"):
            for i in range(60):
                self.db.execute("SELECT total AS c%d FROM orders" % i)
        statements = [key[3] for key in self.rows()]
        self.assertEqual(len(statements), 51)
        self.assertEqual(self.rows()[("JOB", "/(job) many", "sqlite", "(other)")]["count"], 10)

    def test_past_200_keys_a_minute_folds_into_other_and_past_300_keeps_nothing_new(self):
        request = self.queries.request()
        for i in range(400):
            request.entries = {("sqlite", "SELECT c%d" % i): q._entry()}
            self.queries.finish("GET", "/r%d" % i, request)
        self.assertEqual(len(self.queries.rows), q.HARD_MAX_KEYS)
        self.assertEqual(sum(1 for key in self.queries.rows if key[4] == "(other)"), 100,
                         "routes past 200 keys get one (other) each, until 300")

    def test_the_payload_and_what_is_resent(self):
        with mock.patch.object(q, "MAX_KEYS", 1000), mock.patch.object(q, "HARD_MAX_KEYS", 1000):
            for i in range(501):  # past the caps on purpose: 501 rows are two requests
                self.queries.background("postgresql", "SELECT c%d" % i, 12.34, i == 0)
        sent = []
        with mock.patch.object(self.platform.core, "send", side_effect=lambda *a, **k: sent.append((a, k)) or Response(503 if len(sent) == 2 else 202)):
            self.platform._modules["performance"].flush()
        self.assertEqual([len(k["body"]["rows"]) for _, k in sent], [500, 1])
        (module, path), named = sent[0]
        self.assertEqual((module, path, named["auth"]), ("performance", "/events/server-queries", "bearer"))
        body = named["body"]
        self.assertEqual(body["site_id"], SITE)
        self.assertTrue(body["runtime"].startswith("Python "))
        row = next(r for r in body["rows"] if r["statement"] == "SELECT c0")
        self.assertRegex(row["minute"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:00Z$")
        self.assertEqual({k: row[k] for k in ("method", "route", "db", "count", "errors", "sum_ms", "max_ms")},
                         {"method": "JOB", "route": "(background)", "db": "postgresql", "count": 1, "errors": 1,
                          "sum_ms": 12.3, "max_ms": 12.3})
        self.assertEqual(row["buckets"], [0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        self.assertEqual(len(self.queries.retry), 1, "the batch a 503 turned away waits for the next send")
        with mock.patch.object(self.platform.core, "send", return_value=Response(400)) as send:
            self.platform._modules["performance"].flush()
        self.assertEqual(len(send.call_args[1]["body"]["rows"]), 1)
        self.assertEqual(self.queries.retry, [], "a 400 isn't sent again")

    def test_an_outer_layer_timing_the_query_means_the_connection_leaves_it(self):
        token = q._timing.set(True)
        try:
            self.db.execute("SELECT 1")
        finally:
            q._timing.reset(token)
        self.assertEqual(self.queries.rows, {})

    def test_server_speed_switched_off_records_nothing(self):
        with mock.patch.object(self.platform.core, "_switches", {"performance": False}):
            with self.platform.job("x"):
                self.db.execute("SELECT 1")
            self.db.execute("SELECT 2")
        self.assertEqual(self.queries.rows, {})

    def test_the_watched_connection_behaves_as_the_drivers(self):
        with self.db as same:
            self.assertIs(same, self.db)
            same.executemany("INSERT INTO orders VALUES (?, ?)", [(1, 2.5), (2, 3.5)])
        self.db.row_factory = sqlite3.Row
        cursor = self.db.cursor()
        self.assertIs(cursor.execute("SELECT id FROM orders ORDER BY id"), cursor)
        self.assertEqual([row["id"] for row in cursor], [1, 2])
        self.assertEqual(self.db.execute("SELECT count(*) FROM orders").fetchone()[0], 2)
        self.assertIn(("JOB", "(background)", "sqlite", "INSERT INTO orders VALUES (?)"), self.rows())


class Off(unittest.TestCase):
    def test_queries_false_keeps_server_speed_and_leaves_connections_alone(self):
        platform = make_platform(queries=False)
        try:
            self.assertIsNotNone(platform._modules.get("performance"))
            self.assertFalse(platform._modules["performance"].queries.has("queries"), "calls are still timed")
            self.assertIsNone(platform._queries())
            raw = sqlite3.connect(":memory:")
            self.assertIs(platform.watch_database(raw), raw)
        finally:
            platform.close()


@unittest.skipUnless(find_spec("sqlalchemy"), "SQLAlchemy isn't installed")
class SQLAlchemy(unittest.TestCase):
    def setUp(self):
        self.platform = make_platform()
        self.queries = self.platform._modules["performance"].queries

    def tearDown(self):
        self.queries.rows.clear()
        self.platform.close()

    def test_every_engine_is_timed_once_even_over_a_watched_connection(self):
        from sqlalchemy import create_engine, text
        engine = create_engine("sqlite://", creator=lambda: self.platform.watch_database(sqlite3.connect(":memory:")))
        with self.platform.job("report"):
            with engine.connect() as conn:
                conn.execute(text("SELECT :a, 'secret'"), {"a": 1})
                with self.assertRaises(Exception):
                    conn.execute(text("SELECT * FROM nowhere WHERE id = 5"))
        rows = {key[1:]: row for key, row in self.queries.rows.items()}
        self.assertEqual(rows[("JOB", "/(job) report", "sqlite", "SELECT ?, ?")]["count"], 1)
        failed = rows[("JOB", "/(job) report", "sqlite", "SELECT * FROM nowhere WHERE id = ?")]
        self.assertEqual((failed["count"], failed["errors"]), (1, 1))
        self.assertFalse(q._timing.get())


@unittest.skipUnless(find_spec("django"), "Django isn't installed")
class Django(unittest.TestCase):
    def test_every_connection_is_wrapped_once_and_its_queries_counted(self):
        import django
        from django.conf import settings
        if not settings.configured:
            settings.configure(DATABASES={"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}},
                               INSTALLED_APPS=[], ANALYTICS_PLATFORM={
                                   "site_id": SITE, "secret": "s", "endpoint": "http://127.0.0.1:9", "firewall": False,
                                   "errors": False, "analytics": False, "flags": False, "inventory": False,
                                   "posture": False, "resources": False, "proxy": False, "maintenance": False,
                                   "crawlers": False, "forms": False, "audit": False})
            django.setup()
        from django.db import connection
        from analytics_platform import django as integration
        platform = integration.get_platform()
        queries = platform._modules["performance"].queries
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT %s, %s WHERE 1 IN (%s, %s)", [1, "secret", 2, 3])
            connection.close()
            connection.connect()
            self.assertEqual(connection.execute_wrappers.count(q._django_execute), 1)
            rows = {key[1:]: row for key, row in queries.rows.items()}
            self.assertEqual(rows[("JOB", "(background)", "sqlite", "SELECT ?, ? WHERE ? IN (?)")]["count"], 1)
        finally:
            queries.rows.clear()
            platform.close()


if __name__ == "__main__":
    unittest.main()
