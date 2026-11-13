"""Outgoing calls (sdk/protocols/calls.md), ClickHouse query timing
(queries.md) and job queues (queues.md): requests for real against a local
server, httpx when it's installed, the ClickHouse clients, RQ and Celery
against stand-ins (none of them is needed).

    python3 -m unittest discover -s tests
"""
import asyncio
import os
import socket
import sys
import threading
import types
import unittest
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib.util import find_spec
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analytics_platform import create_platform  # noqa: E402
from analytics_platform import queries as q  # noqa: E402

SITE = "a1b2c3d4e5f6a1b2c3d4e5f6"


def make_platform(endpoint="http://127.0.0.1:9", **options):
    return create_platform(site_id=SITE, secret="s", endpoint=endpoint,
                           firewall=False, analytics=False, flags=False, inventory=False, posture=False,
                           resources=False, proxy=False, maintenance=False, crawlers=False, forms=False,
                           audit=False, headers=False, errors=False, **options)


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        status = int(self.path.strip("/").split("/")[0] or 200) if self.path.strip("/").split("/")[0].isdigit() else 200
        self.send_response(status)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    do_POST = do_GET

    def log_message(self, *_):
        pass


def refused_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Server:
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.port = cls.server.server_address[1]
        cls.base = "http://127.0.0.1:%d" % cls.port
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()


def call_rows(platform):
    queries = platform._modules["performance"].queries
    return {key[1:]: row for key, row in queries.kinds["calls"].rows.items()}


def wsgi_request(platform, path, body):
    def app(environ, start_response):
        body()
        start_response("200 OK", [])
        return [b"ok"]

    platform.wsgi(app)({"REQUEST_METHOD": "GET", "PATH_INFO": path, "REMOTE_ADDR": "1.2.3.4"}, lambda *a: None)


class Hosts(unittest.TestCase):
    def test_a_calls_host_keeps_its_port_only_when_it_isnt_the_schemes_own(self):
        self.assertEqual(q.host_of_url("https://API.Stripe.com/v1/charges?key=sk_1"), "api.stripe.com")
        self.assertEqual(q.host_of_url("https://api.stripe.com:443/v1"), "api.stripe.com")
        self.assertEqual(q.host_of_url("http://localhost:8080/x"), "localhost:8080")
        self.assertEqual(q.host_of_url("http://[::1]:3000/"), "[::1]:3000")
        self.assertEqual(q.host_of_url("https://user:pass@example.com/"), "example.com")
        self.assertEqual(q.host_of_url("not a url"), "")
        self.assertEqual(q.host_of_url("http://exa mple.com/"), "")
        self.assertEqual(q.normal_address("HTTP://LOCALHOST:80/collect/"), "http://localhost/collect")


@unittest.skipUnless(find_spec("requests"), "requests isn't installed")
class Requests(Server, unittest.TestCase):
    def setUp(self):
        import requests
        self.requests = requests
        self.platform = make_platform()
        self.session = self.platform.watch_http(requests.Session())

    def tearDown(self):
        self.session.close()
        self.platform.close()

    def test_a_requests_calls_are_filed_under_its_route_by_host_only(self):
        def calls():
            self.session.get(self.base + "/200/v1/customers/cus_8x?key=secret")
            self.session.post(self.base + "/503/charge")
            self.session.get(self.base + "/404/missing")

        wsgi_request(self.platform, "/checkout", calls)
        host = "127.0.0.1:%d" % self.port
        rows = call_rows(self.platform)
        self.assertEqual(set(rows), {("GET", "/checkout", "GET", host), ("GET", "/checkout", "POST", host)})
        get = rows[("GET", "/checkout", "GET", host)]
        self.assertEqual((get["count"], get["errors"]), (2, 0), "a 4xx is the other side's answer")
        self.assertEqual(rows[("GET", "/checkout", "POST", host)]["errors"], 1, "a 5xx is a failure")

    def test_a_call_nobody_answered_is_a_failure_and_one_outside_a_request_is_background(self):
        with self.assertRaises(self.requests.ConnectionError):
            self.session.get("http://127.0.0.1:%d/" % refused_port(), timeout=2)
        [(key, row)] = call_rows(self.platform).items()
        self.assertEqual(key[:3], ("JOB", "(background)", "GET"))
        self.assertEqual((row["count"], row["errors"]), (1, 1))

    def test_watching_twice_counts_once_and_the_adapters_settings_stay(self):
        adapter = self.requests.adapters.HTTPAdapter(max_retries=3)
        session = self.requests.Session()
        session.mount("http://", adapter)
        session = self.platform.watch_http(self.platform.watch_http(session))
        self.assertEqual(session.get_adapter("http://x/").max_retries.total, 3)
        session.get(self.base + "/200")
        [row] = call_rows(self.platform).values()
        self.assertEqual(row["count"], 1)

    def test_the_collectors_own_address_isnt_counted_and_calls_false_counts_none(self):
        own = make_platform(endpoint="http://LOCALHOST:%d" % self.port)
        try:
            session = own.watch_http(self.requests.Session())
            session.get("http://localhost:%d/events/server-queries" % self.port)
            self.assertEqual(call_rows(own), {})
        finally:
            own.close()
        off = make_platform(calls=False)
        try:
            session = self.requests.Session()
            adapter = session.get_adapter("http://x/")
            self.assertIs(off.watch_http(session).get_adapter("http://x/"), adapter, "left alone")
            self.assertTrue(off._modules["performance"].queries.has("queries"), "queries are still timed")
        finally:
            off.close()

    def test_server_speed_off_counts_nothing(self):
        self.platform.core._switches["performance"] = False
        self.session.get(self.base + "/200")
        self.assertEqual(call_rows(self.platform), {})

    def test_a_call_inside_a_timed_query_is_the_querys(self):
        token = q._timing.set(True)
        try:
            self.session.get(self.base + "/200")
        finally:
            q._timing.reset(token)
        self.assertEqual(call_rows(self.platform), {})

    def test_the_payload_goes_to_server_calls_with_the_bearer_secret(self):
        wsgi_request(self.platform, "/checkout", lambda: self.session.get(self.base + "/200"))
        sent = []
        with mock.patch.object(self.platform.core, "send", side_effect=lambda *a, **k: sent.append((a, k))):
            self.platform._modules["performance"].flush()
        [(args, named)] = [s for s in sent if s[0][1] == "/events/server-calls"]
        self.assertEqual((args[0], named["auth"]), ("performance", "bearer"))
        [row] = named["body"]["rows"]
        self.assertEqual({k: row[k] for k in ("method", "route", "call_method", "host", "count", "errors")},
                         {"method": "GET", "route": "/checkout", "call_method": "GET",
                          "host": "127.0.0.1:%d" % self.port, "count": 1, "errors": 0})
        self.assertEqual(len(row["buckets"]), 12)
        self.assertNotIn("db", row)


@unittest.skipUnless(find_spec("httpx"), "httpx isn't installed")
class Httpx(Server, unittest.TestCase):
    def setUp(self):
        import httpx
        self.httpx = httpx
        self.platform = make_platform()

    def tearDown(self):
        self.platform.close()

    def test_a_clients_event_hooks_time_answered_calls(self):
        client = self.platform.watch_http(self.httpx.Client())
        self.platform.watch_http(client)
        with client:
            wsgi_request(self.platform, "/sync", lambda: (client.get(self.base + "/200"), client.get(self.base + "/500")))
        [row] = call_rows(self.platform).values()
        self.assertEqual((row["count"], row["errors"]), (2, 1))

    def test_a_watched_transport_sees_refused_calls_and_counts_once_beside_the_hooks(self):
        transport = self.platform.watch_http(self.httpx.HTTPTransport())
        client = self.platform.watch_http(self.httpx.Client(transport=transport))
        with client:
            client.get(self.base + "/200")
            with self.assertRaises(self.httpx.ConnectError):
                client.get("http://127.0.0.1:%d/" % refused_port())
        rows = call_rows(self.platform)
        self.assertEqual(sum(r["count"] for r in rows.values()), 2)
        self.assertEqual(sum(r["errors"] for r in rows.values()), 1)

    def test_an_async_client_in_an_asgi_request(self):
        async def app(scope, receive, send):
            async with self.platform.watch_http(self.httpx.AsyncClient(
                    transport=self.platform.watch_http(self.httpx.AsyncHTTPTransport()))) as client:
                await client.get(self.base + "/200")
            await send({"type": "http.response.start", "status": 200, "headers": []})
            await send({"type": "http.response.body", "body": b""})

        async def nothing(_):
            pass

        asyncio.run(self.platform.asgi(app)({"type": "http", "method": "GET", "path": "/a", "headers": []}, None, nothing))
        self.assertEqual([k[:3] for k in call_rows(self.platform)], [("GET", "/a", "GET")])


# ---- ClickHouse ----

class QueryResult:
    result_rows = [(1,)]


class ConnectClient:
    """clickhouse-connect's client, as far as watch_database looks."""

    def __init__(self):
        self.ran = []

    def query(self, query=None, parameters=None, settings=None):
        self.ran.append(query)
        if "nowhere" in query:
            raise RuntimeError("Code: 60. Table doesn't exist")
        return QueryResult()

    def command(self, cmd, parameters=None, data=None, settings=None):
        self.ran.append(cmd)
        return 1

    def insert(self, table=None, data=None, column_names="*", database=""):
        self.ran.append(table)

    def query_df(self, query=None, parameters=None):
        return self.query(query, parameters)  # its own query isn't a second one


ConnectClient.__module__ = "clickhouse_connect.driver.httpclient"


class DriverClient:
    def execute(self, query, params=None, with_column_types=False):
        return [(1,)]


DriverClient.__module__ = "clickhouse_driver.client"


class ClickHouse(unittest.TestCase):
    def setUp(self):
        self.platform = make_platform()
        self.queries = self.platform._modules["performance"].queries

    def tearDown(self):
        self.platform.close()

    def rows(self):
        return {key[3:]: row for key, row in self.queries.rows.items()}

    def test_clickhouse_connect_queries_commands_and_inserts_are_timed_without_their_values(self):
        client = self.platform.watch_database(ConnectClient())
        self.assertIs(self.platform.watch_database(client), client, "watched once")
        with self.platform.job("rollup"):
            self.assertEqual(client.query("SELECT * FROM t WHERE email = %(e)s", {"e": "a@b.c"}).result_rows, [(1,)])
            client.query("SELECT * FROM t WHERE id = {id:UInt32}", parameters={"id": 7})
            client.command("OPTIMIZE TABLE t FINAL")
            client.insert("events", [[1]], database="analytics")
            client.query_df("SELECT 1")
            with self.assertRaises(RuntimeError):
                client.query("SELECT * FROM nowhere")
        self.assertEqual(set(self.rows()), {
            ("clickhouse", "SELECT * FROM t WHERE email = ?"),
            ("clickhouse", "SELECT * FROM t WHERE id = {id:UInt32}"),
            ("clickhouse", "OPTIMIZE TABLE t FINAL"),
            ("clickhouse", "INSERT INTO analytics.events FORMAT Native"),
            ("clickhouse", "SELECT ?"),
            ("clickhouse", "SELECT * FROM nowhere"),
        })
        self.assertEqual(self.rows()[("clickhouse", "SELECT ?")]["count"], 1, "query_df is one query")
        self.assertEqual(self.rows()[("clickhouse", "SELECT * FROM nowhere")]["errors"], 1)
        self.assertEqual(client.ran[0], "SELECT * FROM t WHERE email = %(e)s", "the client gets what it was given")

    def test_clickhouse_driver_execute_is_timed(self):
        client = self.platform.watch_database(DriverClient())
        self.assertEqual(client.execute("INSERT INTO t (a) VALUES", [(1,), (2,)]), [(1,)])
        client.execute("SELECT a FROM t WHERE b = %(b)s", {"b": "x"})
        self.assertEqual(set(self.rows()), {("clickhouse", "INSERT INTO t (a) VALUES"),
                                            ("clickhouse", "SELECT a FROM t WHERE b = ?")})


# ---- Queues ----

class FakeRedis:
    """Lists, sorted-set sizes and hashes, through a pipeline like redis-py's."""

    def __init__(self, lists=None, zsets=None, hashes=None, kwargs=None, fail=False):
        self.lists = lists or {}
        self.zsets = zsets or {}
        self.hashes = hashes or {}
        self.fail = fail
        self.connection_pool = types.SimpleNamespace(connection_kwargs=kwargs or {
            "host": "cache", "port": 6380, "db": 2, "password": "hunter2", "username": "app"})

    def _check(self):
        if self.fail:
            raise ConnectionError("Redis is down")

    def llen(self, key):
        return len(self.lists.get(key, []))

    def zcard(self, key):
        return self.zsets.get(key, 0)

    def lindex(self, key, at):
        items = self.lists.get(key, [])
        return items[at] if items else None

    def hget(self, key, field):
        self._check()
        return self.hashes.get(key, {}).get(field)

    def pipeline(self, transaction=True):
        redis = self

        class Pipe:
            def __init__(self):
                self.calls = []

            def __getattr__(self, name):
                return lambda *a: self.calls.append((name, a))

            def execute(self):
                redis._check()
                return [getattr(redis, name)(*a) for name, a in self.calls]

        return Pipe()


class Registry:
    def __init__(self, key):
        self.key = key


class RQJob:
    @staticmethod
    def key_for(job_id):
        return b"rq:job:" + job_id.encode()


class RQQueue:
    job_class = RQJob

    def __init__(self, name, connection):
        self.name = name
        self.connection = connection
        self.key = "rq:queue:" + name
        for kind in ("started", "scheduled", "deferred", "failed"):
            setattr(self, kind + "_job_registry", Registry("rq:%s:%s" % (kind, name)))

    def enqueue(self, *args, **kwargs):
        raise NotImplementedError


RQQueue.__module__ = "rq.queue"


class RQWorker:
    def execute_job(self, job, queue):
        job.ran = True


rq_module = types.ModuleType("rq")
rq_module.Worker = RQWorker


class QueuesBase(unittest.TestCase):
    modules = {}

    def setUp(self):
        self.patched = mock.patch.dict(sys.modules, self.modules)
        self.patched.start()
        for name in ("analytics_platform.rq", "analytics_platform.celery"):
            sys.modules.pop(name, None)
        self.platform = make_platform()
        self.queues = self.platform._modules["performance"].queues
        self.sent = []
        # The switches' own fetch runs on its thread meanwhile: only queue rows are kept.
        self.platform.core.send = lambda *a, **k: a[1] == "/events/server-queues" and self.sent.append((a, k))

    def tearDown(self):
        self.platform.close()
        self.patched.stop()
        for name in ("analytics_platform.rq", "analytics_platform.celery"):
            sys.modules.pop(name, None)


class RQ(QueuesBase):
    modules = {"rq": rq_module}

    def redis(self, **over):
        ago = (datetime.now(timezone.utc) - timedelta(seconds=610)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        options = dict(lists={"rq:queue:emails": [b"j1", b"j2", b"j3"]},
                       zsets={"rq:started:emails": 2, "rq:scheduled:emails": 4, "rq:deferred:emails": 1, "rq:failed:emails": 3},
                       hashes={b"rq:job:j1": {"enqueued_at": ago.encode()}})
        options.update(over)
        return FakeRedis(**options)

    def test_an_rq_queue_is_read_with_its_registries_and_the_oldest_wait(self):
        queue = RQQueue("emails", self.redis())
        self.assertIs(self.platform.watch_queue(queue), queue)
        [row] = self.queues.sample()
        oldest = row.pop("oldest_s")
        self.assertTrue(609 <= oldest <= 612, oldest)
        self.assertRegex(row.pop("minute"), r"^\d{4}-\d\d-\d\dT\d\d:\d\d:00Z$")
        self.assertEqual(row, {"system": "rq", "broker": "cache:6380/2", "queue": "emails", "waiting": 3,
                               "running": 2, "delayed": 5, "failed": 3, "shared": False})
        [(args, named)] = self.sent
        self.assertEqual((args[1], named["auth"]), ("/events/server-queues", "bearer"))
        body = named["body"]
        self.assertRegex(body["sender"], r"^[0-9a-f]{16}$")
        self.assertEqual(body["site_id"], SITE)
        self.assertNotIn("hunter2", repr(body))

    def test_the_worker_counts_the_jobs_it_finished_for_good(self):
        queue = RQQueue("emails", self.redis(lists={}))
        self.platform.watch_queue(queue)
        worker = self.platform.rq_worker()()
        for status in ("finished", "failed", "scheduled"):  # scheduled: to be retried
            job = types.SimpleNamespace(func_name="jobs.send", get_status=lambda refresh=True, s=status: s)
            worker.execute_job(job, queue)
            self.assertTrue(job.ran)
        [row] = self.queues.sample()
        self.assertEqual((row["waiting"], row["oldest_s"], row["finished"]), (0, 0, 2))
        self.assertNotIn("added", row, "RQ has no hook for a job being added")

    def test_a_reading_that_fails_is_a_gap_not_zeros(self):
        self.platform.watch_queue(RQQueue("emails", self.redis(fail=True)))
        self.assertEqual(self.queues.sample(), [])
        self.assertEqual(self.sent, [])

    def test_with_server_speed_off_nothing_is_read_or_sent_and_queues_false_leaves_them_out(self):
        self.platform.watch_queue(RQQueue("emails", self.redis()))
        self.platform.core._switches["performance"] = False
        self.assertEqual(self.queues.sample(), [])
        off = make_platform(queues=False)
        try:
            queue = RQQueue("emails", self.redis())
            self.assertIs(off.watch_queue(queue), queue)
            self.assertIsNone(off._modules["performance"].queues)
        finally:
            off.close()


class CelerySignal:
    def __init__(self):
        self.receivers = {}

    def connect(self, receiver, sender=None, weak=True, dispatch_uid=None):
        self.receivers[dispatch_uid or id(receiver)] = receiver

    def send(self, sender=None, **named):
        for receiver in list(self.receivers.values()):
            receiver(sender=sender, signal=self, **named)


SIGNALS = ("task_prerun", "task_failure", "task_postrun", "worker_process_shutdown", "worker_shutdown",
           "after_task_publish", "worker_init", "worker_process_init")


class CeleryApp:
    def __init__(self, broker_url, options=None):
        self.conf = types.SimpleNamespace(broker_url=broker_url, broker_transport_options=options or {},
                                          task_default_queue="celery")
        self.amqp = types.SimpleNamespace(queues={"celery": None, "emails": None})


CeleryApp.__module__ = "celery.app.base"


class Celery(QueuesBase):
    def setUp(self):
        self.signals = types.SimpleNamespace(**{name: CelerySignal() for name in SIGNALS})
        celery = types.ModuleType("celery")
        celery.signals = self.signals
        self.redis = FakeRedis(lists={"celery": [b"m"] * 4, "celery\x06\x169": [b"m"], "emails": []},
                               kwargs={"host": "cache", "port": 6379, "db": 0, "password": "pw"})
        redis_module = types.ModuleType("redis")
        redis_module.Redis = types.SimpleNamespace(from_url=self.from_url)
        self.urls = []
        self.modules = {"celery": celery, "celery.signals": self.signals, "redis": redis_module}
        super().setUp()

    def from_url(self, url, **options):
        self.urls.append(url)
        return self.redis

    def test_a_redis_brokers_lists_are_read_and_this_process_counts_what_it_published_and_ran(self):
        app = CeleryApp("redis://:pw@cache:6379/0")
        self.platform.watch_queue(app)
        self.signals.after_task_publish.send(sender="shop.send", routing_key="emails", exchange="")
        self.signals.after_task_publish.send(sender="shop.send", routing_key="emails", exchange="")
        self.signals.worker_process_init.send()
        task = types.SimpleNamespace(request=types.SimpleNamespace(delivery_info={"routing_key": "emails"}))
        for state in ("SUCCESS", "RETRY", "FAILURE"):
            self.signals.task_postrun.send(sender=task, task=task, task_id="t", state=state)
        rows = {row["queue"]: row for row in self.queues.sample()}
        self.assertEqual({k: v for k, v in rows["celery"].items() if k != "minute"},
                         {"system": "celery", "broker": "cache:6379/0", "queue": "celery", "waiting": 5,
                          "added": 0, "finished": 0, "shared": False})
        self.assertEqual((rows["emails"]["waiting"], rows["emails"]["oldest_s"], rows["emails"]["added"],
                          rows["emails"]["finished"]), (0, 0, 2, 2), "a retry isn't finished")
        self.assertNotIn("running", rows["emails"], "Celery can't say")

    def test_a_rabbitmq_broker_is_left_to_the_agent(self):
        self.platform.watch_queue(CeleryApp("amqp://guest:guest@rabbit:5672//"))
        self.assertEqual(self.queues.entries, {})
        self.assertEqual(self.urls, [])


if __name__ == "__main__":
    unittest.main()
