"""Databases and queues (sdk/protocols/databases.md, queues.md): the
statements lose their values as every package's queries do, counters become
deltas and a reset gives nothing, a password never reaches a command line,
and a figure a database can't give is null, never 0.

    python3 -m unittest discover -s test
"""
import importlib.util
import json
import os
import sys
import unittest
from unittest import mock

AGENT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "analytics-agent")
if "analytics_agent" in sys.modules:
    agent = sys.modules["analytics_agent"]
else:
    spec = importlib.util.spec_from_loader("analytics_agent", importlib.machinery.SourceFileLoader("analytics_agent", AGENT))
    agent = importlib.util.module_from_spec(spec)
    sys.modules["analytics_agent"] = agent
    spec.loader.exec_module(agent)
CASES = os.path.join(os.path.dirname(AGENT), "..", "protocols", "query-cases.json")
NOW = 1793787200  # 2026-11-04T10:13:20Z


class Normalizer(unittest.TestCase):
    def test_every_shared_case(self):
        with open(CASES, encoding="utf-8") as f:
            cases = json.load(f)["cases"]
        for case in cases:
            with self.subTest(statement=case["statement"][:60], db=case["db"]):
                self.assertEqual(agent.normalize_statement(case["statement"], case["db"]), case["expected"])

    def test_a_profiled_mongo_command_reads_as_the_packages_write_it(self):
        text = agent.mongo_text({"find": "users", "filter": {"email": "bob@example.com"}, "limit": 1, "$db": "app"})
        self.assertEqual(agent.normalize_statement(text, "mongodb"), 'find users {"email":"?"}')
        update = agent.mongo_text({"update": "users", "updates": [{"q": {"_id": 5}, "u": {"$set": {"a": 1}}}]})
        self.assertEqual(agent.normalize_statement(update, "mongodb"), 'update users {"_id":"?"}')
        self.assertEqual(agent.mongo_text({"ping": 1}), "ping")


class Config(unittest.TestCase):
    def test_entries_that_cannot_be_read_are_skipped(self):
        with mock.patch.object(agent, "log"):
            listed = agent.database_list([{"postgresql": "local"}, {"oracle": "x"}, {"clickhouse": "127.0.0.1:8123"},
                                          {"mongodb": "mongodb://127.0.0.1"}, "mysql"])
            self.assertEqual([d["kind"] for d in listed], ["postgresql", "mongodb"])
            self.assertEqual(agent.queue_list([{"rabbitmq": "http://u:p@127.0.0.1:15672"}, {"rabbitmq": "amqp://x"}]),
                             [{"kind": "rabbitmq", "target": "http://u:p@127.0.0.1:15672"}])

    def test_an_address_loses_its_user_and_password(self):
        clean, user, password, netloc = agent.split_url("http://agent:s%40cret@127.0.0.1:8123/")
        self.assertEqual((clean, user, password, netloc), ("http://127.0.0.1:8123/", "agent", "s@cret", "127.0.0.1:8123"))
        self.assertEqual(agent.split_url("mongodb://u:p@a:1,b:2/app?replicaSet=r")[3], "a:1,b:2")

    def test_counters_that_went_down_give_nothing(self):
        before = {"a": {"calls": 10, "total_ms": 5.0}, "b": {"calls": 10, "total_ms": 5.0}}
        now = {"a": {"calls": 15, "total_ms": 9.0}, "b": {"calls": 2, "total_ms": 1.0}, "c": {"calls": 1, "total_ms": 1.0}}
        self.assertEqual(agent.counter_deltas(before, now), {"a": {"calls": 5, "total_ms": 4.0}})


class Fake:
    """Answers a database's client by the SQL it was given."""

    def __init__(self, answers):
        self.answers = answers
        self.calls = []

    def __call__(self, args, env=None, cwd=None, timeout=None):
        self.calls.append((args, env))
        text = " ".join(args)
        for pattern, out in self.answers:
            if pattern in text:
                return (0, out) if isinstance(out, str) else out
        return 1, ""


def pg_answers(calls, total, tables_seq=5):
    info = {"version": "16.4", "version_num": 160004, "port": "5432", "max_connections": 100, "connections": 12,
            "running": 2, "waiting": 1, "longest_s": 3.25, "hit": 900 + calls * 10, "read": 100,
            "databases": ["shop"], "statements": True, "sees_all": True}
    statements = [{"key": "1:42", "database": "shop", "statement": "SELECT * FROM orders WHERE id = $1 AND note = 'x'",
                   "calls": calls, "total_ms": total, "rows": calls, "blocks": calls * 2}]
    tables = [{"table": "public.orders", "seq_scan": tables_seq, "seq_tup_read": tables_seq * 1000, "idx_scan": 7, "n_live_tup": 1000}]
    return [("current_setting('server_version')", json.dumps(info)), ("pg_stat_statements s", json.dumps(statements)),
            ("pg_stat_user_tables", json.dumps(tables))]


class PostgreSQL(unittest.TestCase):
    def test_second_reading_sends_deltas_with_values_taken_out(self):
        reader = agent.DatabaseReader("postgresql", "local", "/tmp")
        with mock.patch.object(agent, "_command", Fake(pg_answers(10, 50.0))), mock.patch.object(agent.os, "geteuid", return_value=0):
            first = reader.read(NOW)
        self.assertEqual(first["statements"], [])
        self.assertEqual(first["health"]["cache_hit_pct"], None)
        fake = Fake(pg_answers(25, 80.0, tables_seq=8))
        with mock.patch.object(agent, "_command", fake), mock.patch.object(agent.os, "geteuid", return_value=0):
            second = reader.read(NOW + 60)
        self.assertEqual(second["db"], "postgresql")
        self.assertEqual(second["instance"], "local:5432")
        self.assertEqual(second["minute"], "2026-11-04T10:14:00.000Z")
        [statement] = second["statements"]
        self.assertEqual(statement["statement"], "SELECT * FROM orders WHERE id = $1 AND note = ?")
        self.assertEqual((statement["calls"], statement["total_ms"], statement["rows_returned"]), (15, 30.0, 15))
        self.assertIsNone(statement["rows_read"])
        self.assertEqual(statement["bytes_read"], 30 * 8192)
        self.assertEqual(second["tables"][0]["full_scans"], 3)
        self.assertEqual(second["tables"][0]["rows_scanned"], 3000)
        # 150 more hits, no more reads.
        self.assertEqual(second["health"]["cache_hit_pct"], 100.0)
        self.assertEqual(fake.calls[0][0][:4], ["runuser", "-u", "postgres", "--"])

    def test_a_password_goes_in_the_environment(self):
        reader = agent.DatabaseReader("postgresql", "postgresql://agent:hunter2@db.internal:6432/shop", "/tmp")
        fake = Fake(pg_answers(1, 1.0))
        with mock.patch.object(agent, "_command", fake):
            reading = reader.read(NOW)
        self.assertEqual(reading["instance"], "db.internal:6432")
        args, env = fake.calls[0]
        self.assertNotIn("hunter2", " ".join(args))
        self.assertEqual((env["PGPASSWORD"], env["PGHOST"], env["PGPORT"]), ("hunter2", "db.internal", "6432"))

    def test_without_pg_stat_statements_it_says_so(self):
        answers = pg_answers(1, 1.0)
        info = json.loads(answers[0][1])
        info["statements"] = False
        reader = agent.DatabaseReader("postgresql", "local", "/tmp")
        with mock.patch.object(agent, "_command", Fake([(answers[0][0], json.dumps(info))] + answers[2:])):
            self.assertEqual(reader.read(NOW)["notes"], ["no_pg_stat_statements"])

    def test_without_the_right_to_see_others_sessions_their_work_is_unknown(self):
        answers = pg_answers(1, 1.0)
        info = json.loads(answers[0][1])
        info["sees_all"] = False
        reader = agent.DatabaseReader("postgresql", "local", "/tmp")
        with mock.patch.object(agent, "_command", Fake([(answers[0][0], json.dumps(info))] + answers[1:])):
            health = reader.read(NOW)["health"]
        self.assertEqual((health["running"], health["waiting"], health["longest_s"], health["connections"]), (None, None, None, 12))

    def test_statements_are_keyed_per_user_and_an_unreadable_list_keeps_its_baseline(self):
        reader = agent.DatabaseReader("postgresql", "local", "/tmp")
        fake = Fake(pg_answers(10, 50.0))
        with mock.patch.object(agent, "_command", fake):
            reader.read(NOW)
        sql = [" ".join(args) for args, _ in fake.calls if "pg_stat_statements s" in " ".join(args)][0]
        self.assertIn("s.userid::text", sql)
        self.assertIn("s.queryid IS NOT NULL", sql)
        broken = [a for a in pg_answers(20, 60.0) if a[0] != "pg_stat_statements s"]
        with mock.patch.object(agent, "_command", Fake(broken)):
            self.assertEqual(reader.read(NOW + 60)["notes"], ["no_pg_stat_statements"])
        with mock.patch.object(agent, "_command", Fake(pg_answers(25, 80.0))):
            [statement] = reader.read(NOW + 120)["statements"]
        # Counted from the last reading that worked.
        self.assertEqual(statement["calls"], 15)

    def test_a_connection_string_with_a_database_reads_each_listed_one_exactly(self):
        answers = pg_answers(1, 1.0)
        info = json.loads(answers[0][1])
        info["databases"] = ["shop", "postgres"]
        fake = Fake([(answers[0][0], json.dumps(info))] + answers[1:])
        reader = agent.DatabaseReader("postgresql", "postgresql://agent:pw@db:5432/shop", "/tmp")
        with mock.patch.object(agent, "_command", fake):
            reader.read(NOW)
        databases = [args[args.index("-d") + 1] for args, _ in fake.calls if "pg_stat_user_tables" in " ".join(args)]
        self.assertEqual(databases, ["shop", "postgres"])
        self.assertEqual(fake.calls[0][0][fake.calls[0][0].index("-d") + 1], "shop")

    def test_a_database_that_cannot_be_read_is_skipped(self):
        reader = agent.DatabaseReader("postgresql", "local", "/tmp")
        with mock.patch.object(agent, "_command", Fake([])), mock.patch.object(agent, "log"):
            self.assertIsNone(reader.read(NOW))


class MySQL(unittest.TestCase):
    def answers(self, calls, scanned):
        info = {"version": "10.11.6-MariaDB", "port": 3306, "max_connections": 151, "schema": 1, "running": 1, "waiting": 0, "longest_s": 0,
                "sees_all": 1}
        status = {"THREADS_CONNECTED": "9", "INNODB_BUFFER_POOL_READ_REQUESTS": str(1000 * calls), "INNODB_BUFFER_POOL_READS": "10"}
        digest = {"key": "shop:abc", "database": "shop", "statement": "SELECT * FROM `orders` WHERE `email` = ?", "calls": calls,
                  "timer": calls * 2 * 10 ** 9, "errors": 0, "examined": calls * 1000, "sent": calls, "no_index": calls}
        table = {"key": "shop|orders", "scanned": scanned, "rows": 900}
        return [("JSON_OBJECT('version'", json.dumps(info)), ("information_schema.GLOBAL_STATUS", json.dumps(status)),
                ("events_statements_summary_by_digest", json.dumps(digest)), ("table_io_waits", json.dumps(table))]

    def test_mariadb_digests_and_tables_without_a_scan_count(self):
        reader = agent.DatabaseReader("mysql", "mysql://agent:p%22w@127.0.0.1:3306", agent.tempfile.gettempdir())
        with mock.patch.object(agent, "_command", Fake(self.answers(10, 5000))):
            reader.read(NOW)
        fake = Fake(self.answers(14, 9000))
        with mock.patch.object(agent, "_command", fake):
            reading = reader.read(NOW + 60)
        self.assertEqual(reading["db"], "mariadb")
        [statement] = reading["statements"]
        self.assertEqual((statement["calls"], statement["total_ms"], statement["rows_read"], statement["no_index"]), (4, 8.0, 4000, 4))
        self.assertEqual(reading["tables"], [{"database": "shop", "table": "orders", "full_scans": None, "rows_scanned": 4000,
                                              "index_scans": None, "rows": 900}])
        self.assertEqual(reading["health"]["connections"], 9)
        for args, _ in fake.calls:
            self.assertNotIn('p"w', " ".join(args))
            self.assertTrue(args[1].startswith("--defaults-extra-file="))
        self.assertFalse([f for f in os.listdir(agent.tempfile.gettempdir()) if f.startswith("mysql-") and f.endswith(".cnf")])


    def test_without_process_others_threads_are_unknown(self):
        answers = self.answers(1, 1)
        info = json.loads(answers[0][1])
        info["sees_all"] = 0
        reader = agent.DatabaseReader("mysql", "local", "/tmp")
        with mock.patch.object(agent, "_command", Fake([(answers[0][0], json.dumps(info))] + answers[1:])):
            health = reader.read(NOW)["health"]
        self.assertEqual((health["running"], health["waiting"], health["longest_s"], health["connections"]), (None, None, None, 9))


class ClickHouse(unittest.TestCase):
    def test_the_query_log_from_where_the_last_reading_stopped(self):
        info = [{"version": "25.8.1", "port": 9000, "connections": "4", "max_connections": "4096", "running": "1", "longest_s": 0.5,
                 "memory": str(512 * 1048576), "memory_setting": 0, "memory_ratio": 0.9, "ram": 16 * 1024 ** 3,
                 "container_ram": 2 * 1024 ** 3, "parts_max": "40", "merges": "1", "until": "2026-11-04 10:13:05"}]
        seen = []

        def http(url, user="", password="", body=None, timeout=None, lines=False):
            seen.append((url, user, password, body))
            if "system.query_log" in body:
                return [{"database": "analytics", "statement": "SELECT count() FROM t WHERE id = ?", "calls": "3", "errors": "1",
                         "total_ms": "120", "rows_read": "3000", "rows_returned": "3", "bytes_read": "9000", "peak_memory_mb": 1.5}]
            return info

        reader = agent.DatabaseReader("clickhouse", "http://agent:secret@127.0.0.1:8123", "/tmp")
        with mock.patch.object(agent, "http_json", http):
            first = reader.read(NOW)
            self.assertEqual(first["statements"], [])
            self.assertEqual(first["health"]["memory_mb"], 512)
            # No limit in its config: 0.9 of the container's 2 GB, smaller than the machine's 16.
            self.assertEqual(first["health"]["memory_limit_mb"], 1843)
            second = reader.read(NOW + 60)
        self.assertEqual(second["instance"], "127.0.0.1:8123")
        self.assertEqual(second["statements"][0]["errors"], 1)
        log_query = [body for _, _, _, body in seen if "system.query_log" in body][0]
        self.assertIn("event_time > toDateTime('2026-11-04 10:13:05')", log_query)
        self.assertTrue(all(url == "http://127.0.0.1:8123/" and user == "agent" for url, user, _, _ in seen))

    def test_a_memory_limit_in_its_config_only_lowers_the_ceiling(self):
        base = {"memory_ratio": 0.9, "ram": 16 * 1024 ** 3, "container_ram": 0}
        self.assertEqual(agent.clickhouse_memory_limit({**base, "memory_setting": 4 * 1024 ** 3}), 4096)
        self.assertEqual(agent.clickhouse_memory_limit({**base, "memory_setting": 64 * 1024 ** 3}), 14745)
        self.assertIsNone(agent.clickhouse_memory_limit({}))

    def test_refused_is_no_access(self):
        reader = agent.DatabaseReader("clickhouse", "http://agent:wrong@127.0.0.1:8123", "/tmp")
        with mock.patch.object(agent, "http_json", lambda *a, **k: {"_error": 403, "_detail": "AUTHENTICATION_FAILED"}):
            self.assertEqual(reader.read(NOW)["notes"], ["no_access"])


class MongoDB(unittest.TestCase):
    def test_profiled_operations_are_grouped_and_their_values_taken_out(self):
        out = {"version": "8.0.3", "connections": {"current": 20, "available": 800}, "memory": 300,
               "ops": {"running": 2, "waiting": 0, "longest": 1}, "anyOn": True,
               "profiled": {"app": {"until": "2026-11-04T10:13:20Z", "ops": [
                   {"command": {"find": "users", "filter": {"email": "a@b.c"}}, "millis": 40, "docsExamined": 5000, "nreturned": 1,
                    "planSummary": "COLLSCAN"},
                   {"command": {"find": "users", "filter": {"email": "d@e.f"}}, "millis": 60, "docsExamined": 5000, "nreturned": 1,
                    "planSummary": "COLLSCAN"}]}}}
        fake = Fake([("mongosh", json.dumps(out))])
        reader = agent.DatabaseReader("mongodb", "mongodb://agent:pw@127.0.0.1:27017/app", "/tmp")
        with mock.patch.object(agent, "_command", fake):
            reading = reader.read(NOW)
        [statement] = reading["statements"]
        self.assertEqual(statement["statement"], 'find users {"email":"?"}')
        self.assertEqual((statement["calls"], statement["total_ms"], statement["rows_read"], statement["no_index"]), (2, 100, 10000, 2))
        self.assertEqual(reading["health"]["max_connections"], 820)
        self.assertEqual(reading["instance"], "127.0.0.1:27017")
        self.assertEqual(reader.watermark, {"app": "2026-11-04T10:13:20Z"})
        args, env = fake.calls[0]
        self.assertNotIn("pw@", " ".join(args))
        self.assertEqual(env["SITEGOOSE_MONGO_URI"], "mongodb://agent:pw@127.0.0.1:27017/app")


    def test_a_profiled_update_or_remove_is_named_by_its_op(self):
        self.assertEqual(agent.mongo_text({"q": {"_id": 1}, "u": {"$set": {"a": 2}}, "multi": False}, "update", "app.users"),
                         'update users {"_id":1}')
        self.assertEqual(agent.mongo_text({"q": {"email": "x"}, "limit": 1}, "remove", "app.sessions"), 'delete sessions {"email":"x"}')
        self.assertEqual(agent.mongo_text({"find": "users", "filter": {}}, "query", "app.users"), "find users {}")

    def test_the_profiler_is_read_up_to_seconds_ago_and_a_full_page_resumes_where_it_stopped(self):
        fake = Fake([("mongosh", json.dumps({"version": "8.0.3", "connections": {}, "profiled": {}, "anyOn": False}))])
        with mock.patch.object(agent, "_command", fake):
            agent.DatabaseReader("mongodb", "mongodb://127.0.0.1:27017", "/tmp").read(NOW)
        script = fake.calls[0][0][-1]
        self.assertIn("Date.now() - 15000", script)
        self.assertIn("if (page.length === %d) until = page[page.length - 1].ts" % (agent.DB_READ_LIMIT * 5), script)


class FakeRedis:
    """A Redis on 127.0.0.1 that answers each command with answer(args):
    bytes (sent as a bulk string), a list, an int, or an Exception (an
    error reply). Every command it was sent is kept."""

    def __init__(self, answer):
        import socket
        import threading
        self.answer = answer
        self.commands = []
        self.server = socket.socket()
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(4)
        self.port = self.server.getsockname()[1]
        threading.Thread(target=self.serve, daemon=True).start()

    def encode(self, value):
        if isinstance(value, Exception):
            return b"-%s\r\n" % str(value).encode()
        if isinstance(value, int):
            return b":%d\r\n" % value
        if isinstance(value, list):
            return b"*%d\r\n" % len(value) + b"".join(self.encode(v) for v in value)
        if isinstance(value, str):
            value = value.encode()
        return b"$%d\r\n%s\r\n" % (len(value), value)

    def serve(self):
        while True:
            try:
                conn, _ = self.server.accept()
            except OSError:
                return
            f = conn.makefile("rb")
            try:
                while True:
                    line = f.readline()
                    if not line:
                        break
                    args = []
                    for _ in range(int(line[1:])):
                        size = int(f.readline()[1:])
                        args.append(f.read(size + 2)[:-2].decode())
                    self.commands.append(args)
                    conn.sendall(self.encode(self.answer(args)))
            except OSError:
                pass
            finally:
                f.close()
                conn.close()

    def close(self):
        self.server.close()


def redis_info(gets, get_usec, hits, misses, evicted, run_id="abc", total=1000):
    return "\r\n".join([
        "# Server", "redis_version:7.2.4", "run_id:%s" % run_id, "", "# Clients", "connected_clients:12", "maxclients:10000",
        "blocked_clients:3", "# Memory", "used_memory:%d" % (300 * 1048576), "maxmemory:%d" % (1024 * 1048576),
        "# Stats", "total_commands_processed:%d" % total, "evicted_keys:%d" % evicted, "keyspace_hits:%d" % hits,
        "keyspace_misses:%d" % misses, "# Commandstats",
        "cmdstat_get:calls=%d,usec=%d,usec_per_call=2.00,rejected_calls=0,failed_calls=1" % (gets, get_usec),
        "cmdstat_client|setname:calls=%d,usec=10,usec_per_call=1.00,rejected_calls=0,failed_calls=0" % gets,
        "cmdstat_blpop:calls=%d,usec=99999999,usec_per_call=1.00,rejected_calls=0,failed_calls=0" % gets,
        "cmdstat_info:calls=%d,usec=500,usec_per_call=1.00,rejected_calls=0,failed_calls=0" % gets,
        "cmdstat_slowlog|get:calls=%d,usec=500,usec_per_call=1.00,rejected_calls=0,failed_calls=0" % gets, ""])


class Redis(unittest.TestCase):
    def reader(self, answer, target="redis://agent:hunter2@127.0.0.1:%d/2"):
        fake = FakeRedis(answer)
        self.addCleanup(fake.close)
        return fake, agent.DatabaseReader("redis", target % fake.port, "/tmp")

    def test_commands_hit_rate_evictions_and_the_slow_log_since_the_last_reading(self):
        state = {"info": redis_info(100, 300, 900, 100, 5), "slow": [[7, NOW, 40000, ["GET", "user:42"], "10.0.0.1:5000", "app"]]}

        def answer(args):
            if args[0] == "AUTH":
                return "OK"
            return state["info"] if args[0] == "INFO" else state["slow"]

        fake, reader = self.reader(answer)
        first = reader.read(NOW)
        self.assertEqual(first["statements"], [])
        self.assertEqual((first["health"]["cache_hit_pct"], first["health"]["evicted"], first["health"]["longest_s"]), (None, None, None))
        state["info"] = redis_info(160, 500, 1290, 110, 9)
        state["slow"] = [[9, NOW, 250000, ["SET", "x"]], [8, NOW, 120000, ["GET", "y"]], [7, NOW, 40000, ["GET", "user:42"]]]
        second = reader.read(NOW + 60)
        self.assertEqual((second["db"], second["instance"], second["version"]), ("redis", "127.0.0.1:%d" % fake.port, "7.2.4"))
        by_name = {row["statement"]: row for row in second["statements"]}
        # The blocking and the agent's own commands are left out.
        self.assertEqual(sorted(by_name), ["CLIENT SETNAME", "GET"])
        self.assertEqual((by_name["GET"]["calls"], by_name["GET"]["total_ms"], by_name["GET"]["errors"], by_name["GET"]["database"]),
                         (60, 0.2, 0, ""))
        self.assertIsNone(by_name["GET"]["rows_read"])
        health = second["health"]
        self.assertEqual(health, {"connections": 12, "max_connections": 10000, "running": None, "waiting": None, "longest_s": 0.25,
                                  "cache_hit_pct": 97.5, "memory_mb": 300, "memory_limit_mb": 1024, "evicted": 4})
        self.assertEqual(fake.commands[0], ["AUTH", "agent", "hunter2"])
        self.assertEqual({c[0] for c in fake.commands}, {"AUTH", "INFO", "SLOWLOG"})
        self.assertNotIn("hunter2", json.dumps([first, second]))
        # Nothing new in the slow log: no command slower than its threshold.
        self.assertEqual(reader.read(NOW + 120)["health"]["longest_s"], 0.0)

    def test_a_restart_or_reset_counts_nothing_that_reading(self):
        state = {"info": redis_info(100, 300, 900, 100, 5)}
        _, reader = self.reader(lambda args: state["info"] if args[0] == "INFO" else [], "redis://127.0.0.1:%d")
        reader.read(NOW)
        state["info"] = redis_info(10, 30, 9, 1, 0, run_id="new")
        reading = reader.read(NOW + 60)
        self.assertEqual((reading["statements"], reading["health"]["evicted"], reading["health"]["cache_hit_pct"]), ([], None, None))
        state["info"] = redis_info(5, 30, 900, 100, 5, run_id="new", total=10)
        self.assertEqual(reader.read(NOW + 120)["statements"], [])
        state["info"] = redis_info(8, 60, 900, 100, 5, run_id="new", total=20)
        self.assertEqual([row["calls"] for row in reader.read(NOW + 180)["statements"]], [3, 3])

    def test_refused_is_no_access_and_a_refused_slow_log_only_loses_the_longest(self):
        _, reader = self.reader(lambda args: Exception("WRONGPASS invalid username-password pair"))
        self.assertEqual(reader.read(NOW)["notes"], ["no_access"])
        _, reader = self.reader(lambda args: Exception("NOAUTH Authentication required."), "redis://127.0.0.1:%d")
        self.assertEqual(reader.read(NOW)["notes"], ["no_access"])
        info = redis_info(1, 1, 1, 1, 0)
        _, reader = self.reader(lambda args: info if args[0] == "INFO" else Exception("NOPERM no permission"), "redis://127.0.0.1:%d")
        reader.read(NOW)
        reading = reader.read(NOW + 60)
        self.assertEqual((reading["notes"], reading["health"]["longest_s"], reading["health"]["connections"]), (["no_access"], None, 12))

    def test_addresses_keep_the_password_out_of_the_instance(self):
        address = agent.redis_address("rediss://:s%40cret@cache.internal:6380/0?ssl_cert_reqs=none")
        self.assertEqual((address["instance"], address["password"], address["tls"], address["verify"]), ("cache.internal:6380", "s@cret", True, False))
        self.assertEqual(agent.redis_address("redis://secret@127.0.0.1")["password"], "secret")
        self.assertEqual(agent.redis_address("unix:///run/redis/redis.sock?password=x")["instance"], "/run/redis/redis.sock")
        self.assertIsNone(agent.redis_address("http://127.0.0.1:6379"))
        with mock.patch.object(agent.os, "stat", side_effect=OSError):
            self.assertEqual(agent.redis_address("local")["instance"], "127.0.0.1:6379")
        with mock.patch.object(agent, "log") as log:
            self.assertEqual([d["kind"] for d in agent.database_list([{"redis": "local"}, {"redis": "tcp://u:hunter2@h"}])], ["redis"])
        self.assertNotIn("hunter2", " ".join(str(a) for call in log.call_args_list for a in call[0]))

    def test_a_reply_too_big_in_all_is_refused_though_each_string_fits(self):
        fake = FakeRedis(lambda args: [b"x" * (3 * 1048576)] * 3)
        self.addCleanup(fake.close)
        connection = agent.RedisConnection({"host": "127.0.0.1", "port": fake.port})
        self.addCleanup(connection.close)
        with self.assertRaises(OSError):
            connection.call("SLOWLOG", "GET", "128")

    def test_a_redis_answering_a_line_at_a_time_is_given_up_on_at_the_deadline(self):
        import socket
        import threading
        import time
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        self.addCleanup(server.close)

        def trickle():
            conn, _ = server.accept()
            try:
                conn.recv(1024)
                conn.sendall(b"*1000\r\n")
                for _ in range(1000):
                    time.sleep(0.05)
                    conn.sendall(b":1\r\n")
            except OSError:
                pass
            finally:
                conn.close()

        threading.Thread(target=trickle, daemon=True).start()
        # Each line comes well inside the per-read timeout; the whole reply doesn't.
        connection = agent.RedisConnection({"host": "127.0.0.1", "port": server.getsockname()[1]}, timeout=1, deadline=0.4)
        self.addCleanup(connection.close)
        started = time.monotonic()
        with self.assertRaises(OSError):
            connection.call("INFO", "all")
        self.assertLess(time.monotonic() - started, 1.5)

    def test_a_redis_that_does_not_answer_is_skipped(self):
        fake, reader = self.reader(lambda args: "x")
        fake.close()
        with mock.patch.object(agent, "log"):
            self.assertIsNone(agent.DatabaseReader("redis", "redis://127.0.0.1:%d" % fake.port, "/tmp").read(NOW))


class RabbitMQ(unittest.TestCase):
    def test_backlog_and_counts_since_the_last_reading(self):
        def queues(publish, ack):
            return [{"name": "emails", "vhost": "/", "messages_ready": 30, "messages_unacknowledged": 2,
                     "head_message_timestamp": NOW - 90, "message_stats": {"publish": publish, "ack": ack}},
                    {"name": "idle", "vhost": "shop", "messages_ready": 0, "messages_unacknowledged": 0},
                    {"name": "amq.gen-x", "vhost": "/", "messages_ready": 1}]

        reader = agent.RabbitReader("http://guest:guest@127.0.0.1:15672")
        with mock.patch.object(agent, "http_json", lambda *a, **k: queues(100, 90)):
            first = reader.read(NOW)
        with mock.patch.object(agent, "http_json", lambda *a, **k: queues(160, 140)):
            rows = reader.read(NOW + 60)
        self.assertEqual([r["queue"] for r in rows], ["emails", "shop/idle"])
        self.assertIsNone(first[0]["added"])
        emails, idle = rows
        self.assertEqual((emails["waiting"], emails["running"], emails["added"], emails["finished"]), (30, 2, 60, 50))
        self.assertEqual(emails["oldest_s"], 150)
        self.assertEqual((emails["broker"], emails["shared"], emails["delayed"]), ("127.0.0.1:15672", True, None))
        self.assertEqual((idle["oldest_s"], idle["added"]), (0, None))


class Posting(unittest.TestCase):
    def test_every_site_gets_them_and_off_slows_the_readings(self):
        config = dict(agent.DEFAULTS, site_id="a" * 24, secret="s", endpoint="https://c", sites=[{"site_id": "b" * 24, "secret": "t"}],
                      databases=[{"postgresql": "local"}], queues=[])
        sent = []

        def request(site, method, path, body=None, headers=None):
            sent.append((site["site_id"], path, body))
            return 202, {}, b'{"enabled": false}'

        job = agent.Readings(config)
        reading = {"minute": "2026-11-04T10:13:00.000Z", "db": "postgresql", "instance": "local:5432", "version": "16",
                   "health": {}, "statements": [], "tables": [], "notes": []}
        with mock.patch.object(agent, "request", request), mock.patch.object(job, "read", return_value=([reading], [])):
            job.tick(NOW)
            job.tick(NOW + 61)
        self.assertEqual([(s, p) for s, p, _ in sent][:2], [("a" * 24, "/events/server-databases"), ("b" * 24, "/events/server-databases")])
        self.assertEqual(len(sent), 4)
        self.assertEqual(job.enabled, {"a" * 24: False, "b" * 24: False})
        # Off in the dashboard: the next reading is in ten minutes.
        self.assertEqual(job.next_at, NOW + 61 + 600)
        self.assertEqual(sent[0][2]["databases"], [reading])

    def test_one_site_off_does_not_slow_the_other_and_a_long_gap_sends_no_counts(self):
        config = dict(agent.DEFAULTS, site_id="a" * 24, secret="s", endpoint="https://c", sites=[{"site_id": "b" * 24, "secret": "t"}],
                      databases=[{"postgresql": "local"}], queues=[])
        sent = []

        def request(site, method, path, body=None, headers=None):
            sent.append((site["site_id"], body))
            return 202, {}, b'{"enabled": %s}' % (b"true" if site["site_id"] == "a" * 24 else b"false")

        job = agent.Readings(config)
        reading = {"db": "postgresql", "health": {"connections": 3}, "statements": [{"calls": 1}], "tables": [{"rows_scanned": 9}]}
        queue = {"queue": "q", "waiting": 1, "added": 5, "finished": 4}
        with mock.patch.object(agent, "request", request), mock.patch.object(job, "read", return_value=([reading], [queue])):
            job.tick(NOW)
            sent.clear()
            job.tick(NOW + 60)
            # b is off: asked once now, then not for ten minutes; a still every minute.
            self.assertEqual(sorted({s for s, _ in sent}), ["a" * 24, "b" * 24])
            self.assertEqual(job.next_at, NOW + 120)
            sent.clear()
            job.tick(NOW + 120)
            self.assertEqual({s for s, _ in sent}, {"a" * 24})
            self.assertEqual(sent[0][1]["databases"][0]["statements"], [{"calls": 1}])
            sent.clear()
            # Asleep for five minutes: what counts since the last reading would land on one minute.
            job.tick(NOW + 420)
        databases = [body["databases"][0] for _, body in sent if "databases" in body]
        rows = [body["rows"][0] for _, body in sent if "rows" in body]
        self.assertEqual((databases[0]["statements"], databases[0]["tables"], databases[0]["health"]), ([], [], {"connections": 3}))
        self.assertEqual((rows[0]["added"], rows[0]["finished"], rows[0]["waiting"]), (None, None, 1))

    def test_a_list_entry_that_is_wrong_is_logged_without_its_values(self):
        with mock.patch.object(agent, "log") as log:
            agent.database_list([{"postgres": "postgresql://u:hunter2@h/db"}])
            agent.queue_list([{"rabbit": "http://u:hunter2@h:15672"}])
        logged = " ".join(str(a) for call in log.call_args_list for a in call[0])
        self.assertNotIn("hunter2", logged)
        self.assertIn("postgres", logged)


if __name__ == "__main__":
    unittest.main()
