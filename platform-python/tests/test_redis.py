"""Redis command timings (sdk/protocols/queries.md, "Redis"): redis_command
against the shared cases, and the redis-py hooks (sync, asyncio, pipelines,
transactions, a Django cache) against stand-ins shaped as redis-py's objects
are; the package doesn't depend on redis-py.

    python3 -m unittest discover -s tests
"""
import asyncio
import json
import os
import sys
import threading
import types
import unittest
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


class ResponseError(Exception):
    pass


class WatchError(Exception):
    pass


def reply(args):
    """What the stand-in server answers: nil for "missing", an error reply for "text"."""
    key = args[1] if len(args) > 1 else None
    if isinstance(key, bytes):
        key = key.decode()
    if key == "missing":
        return None
    if key == "text":
        raise ResponseError("WRONGTYPE Operation against a key holding the wrong kind of value")
    return b"v"


# ---- redis-py's shapes: every command through the client's execute_command;
# a Pipeline (a Redis subclass) stages commands, runs WATCH and what follows
# it at once, and sends the rest on execute() ----

class Redis:
    def __init__(self):
        self.sent = []

    def execute_command(self, *args, **options):
        self.sent.append(args)
        return reply(args)

    def get(self, name):
        return self.execute_command("GET", name)

    def incr(self, name):
        return self.execute_command("INCR", name)

    def client_setname(self, name):
        return self.execute_command("CLIENT SETNAME", name)

    def blpop(self, keys, timeout=0):
        return self.execute_command("BLPOP", *keys, timeout)

    def eval(self, script, numkeys, *keys_and_args):
        return self.execute_command("EVAL", script, numkeys, *keys_and_args)

    def pipeline(self, transaction=True, shard_hint=None):
        return Pipeline(self, transaction)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return None


class Pipeline(Redis):
    def __init__(self, redis, transaction):
        super().__init__()
        self.redis = redis
        self.transaction = transaction
        self.stack = []
        self.watching = False
        self.explicit_transaction = False

    def execute_command(self, *args, **kwargs):
        if (self.watching or args[0] == "WATCH") and not self.explicit_transaction:
            return self.immediate_execute_command(*args, **kwargs)
        return self.pipeline_execute_command(*args, **kwargs)

    def immediate_execute_command(self, *args, **options):
        if args[0] == "WATCH":
            self.watching = True
            return True
        return reply(args)

    def pipeline_execute_command(self, *args, **options):
        self.stack.append(args)
        return self

    def watch(self, *names):
        return self.execute_command("WATCH", *names)

    def multi(self):
        self.explicit_transaction = True

    def reset(self):
        self.stack, self.watching, self.explicit_transaction = [], False, False

    def execute(self, raise_on_error=True):
        try:
            if any(args[1:2] == ("changed",) for args in self.stack):
                raise WatchError("Watched variable changed.")
            replies = []
            for args in self.stack:
                try:
                    replies.append(reply(args))
                except ResponseError as error:
                    if raise_on_error:
                        raise
                    replies.append(error)
            return replies
        finally:
            Pipeline.reset(self)


class AsyncRedis(Redis):
    async def execute_command(self, *args, **options):
        await asyncio.sleep(0)
        return reply(args)

    def pipeline(self, transaction=True, shard_hint=None):
        return AsyncPipeline(self, transaction)


class AsyncPipeline(Pipeline):
    async def immediate_execute_command(self, *args, **options):
        return Pipeline.immediate_execute_command(self, *args, **options)

    async def execute(self, raise_on_error=True):
        await asyncio.sleep(0)
        return Pipeline.execute(self, raise_on_error)

    async def reset(self):
        Pipeline.reset(self)


# Detected by their module, as redis-py's own are.
for _class in (Redis, Pipeline, AsyncRedis, AsyncPipeline):
    _class.__module__ = "redis.client"


class SharedCases(unittest.TestCase):
    def test_every_shared_redis_command_case_comes_out_character_for_character(self):
        with open(CASES, encoding="utf-8") as handle:
            cases = json.load(handle)
        self.assertGreater(len(cases["redis_commands"]), 20)
        for case in cases["redis_commands"]:
            self.assertEqual(q.redis_command(case["args"]), case["expected"], repr(case["args"]))

    def test_unicode_letters_are_not_ascii_letters(self):
        self.assertIsNone(q.redis_command(["ſet", "k"]))
        self.assertEqual(q.redis_command(["SET", "straße:1"]), "SET ?:?")
        self.assertEqual(q.normalize_statement("xread　k", "redis"), "XREAD k")


class Hooks(unittest.TestCase):
    def setUp(self):
        self.platform = make_platform()
        self.queries = self.platform._modules["performance"].queries
        self.queries.rows.clear()
        self.queries.per_minute.clear()

    def tearDown(self):
        self.queries.rows.clear()
        self.queries.retry = []
        self.platform.close()

    def redis_rows(self):
        return {key[4]: (row["count"], row["errors"]) for key, row in self.queries.rows.items() if key[3] == "redis"}

    def test_each_command_is_timed_with_errors_counted_nil_not_and_blocking_ones_left_out(self):
        original = Redis.__dict__["execute_command"]
        redis = Redis()
        self.assertIs(self.platform.watch_database(redis), redis)
        self.assertIs(self.platform.watch_database(redis), redis)
        self.assertEqual(redis.get("user:42:cart"), b"v")
        self.assertEqual(redis.get(b"user:7:cart"), b"v")
        self.assertIsNone(redis.get("missing"))
        with self.assertRaises(ResponseError):
            redis.incr("text")
        redis.client_setname("web-1")
        redis.eval("return 1", 1, "lock:order:9", "hunter2")
        redis.blpop(["jobs"], 0)
        self.assertEqual(self.redis_rows(), {
            "GET user:?:cart": (2, 0), "GET missing": (1, 0), "INCR text": (1, 1),
            "CLIENT SETNAME": (1, 0), "EVAL lock:order:?": (1, 0)})
        self.assertIs(Redis.__dict__["execute_command"], original, "the class is left alone")

    def test_a_pipeline_or_transaction_is_one_call_named_by_its_first_command(self):
        redis = self.platform.watch_database(Redis())
        pipe = redis.pipeline(transaction=False)
        pipe.get("user:1")
        pipe.incr("user:2")
        self.assertEqual(pipe.execute(), [b"v", b"v"])
        with redis.pipeline() as tx:
            tx.execute_command("SET", "cart:9", "x")
            tx.get("cart:9")
            tx.execute()
        broken = redis.pipeline(transaction=False)
        broken.get("user:3")
        broken.incr("text")
        self.assertIsInstance(broken.execute(raise_on_error=False)[1], ResponseError)
        # An empty one isn't a call.
        redis.pipeline().execute()
        self.assertEqual(self.redis_rows(), {"PIPELINE GET user:?": (2, 1), "MULTI SET cart:?": (1, 0)})

    def test_a_watch_runs_its_commands_at_once_and_a_called_off_transaction_isnt_a_failure(self):
        redis = self.platform.watch_database(Redis())
        pipe = redis.pipeline()
        pipe.watch("stock:9")
        pipe.get("stock:9")
        pipe.multi()
        pipe.execute_command("SET", "changed", "1")
        with self.assertRaises(WatchError):
            pipe.execute()
        self.assertEqual(self.redis_rows(), {"WATCH stock:?": (1, 0), "GET stock:?": (1, 0), "MULTI SET changed": (1, 0)})

    def test_asyncio_clients_and_pipelines(self):
        redis = self.platform.watch_database(AsyncRedis())

        async def run():
            self.assertEqual(await redis.get("user:42"), b"v")
            with self.assertRaises(ResponseError):
                await redis.incr("text")
            pipe = redis.pipeline(transaction=False)
            pipe.get("user:1")
            pipe.get("user:2")
            self.assertEqual(await pipe.execute(), [b"v", b"v"])

        asyncio.run(run())
        self.assertEqual(self.redis_rows(), {"GET user:?": (1, 0), "INCR text": (1, 1), "PIPELINE GET user:?": (1, 0)})

    def test_the_packages_own_queue_reads_on_the_same_client_arent_timed(self):
        redis = self.platform.watch_database(Redis())
        queues = self.platform._modules["performance"].queues

        def read():
            pipe = redis.pipeline(transaction=False)
            pipe.execute_command("LLEN", "rq:queue:default")
            pipe.execute()
            redis.execute_command("HGET", "rq:job:1", "enqueued_at")
            return {"waiting": 0}

        queues.entry("rq", "localhost:6379/0", "default", read)
        with mock.patch.object(queues.core, "send"):
            queues.sample()
        redis.get("user:1")
        self.assertEqual(self.redis_rows(), {"GET user:?": (1, 0)})

    def test_djangos_redis_cache_watches_each_client_it_makes(self):
        class RedisCacheClient:
            def __init__(self):
                self._client = Redis

            def get_client(self, key=None, *, write=False):
                return self._client()

        class RedisCache:
            def __init__(self):
                self._cache = RedisCacheClient()

            def get(self, key):
                return self._cache.get_client(key).get(":1:" + key)

        RedisCache.__module__ = "django.core.cache.backends.redis"
        cache = RedisCache()
        self.assertIs(self.platform.watch_database(cache), cache)
        self.platform.watch_database(cache)
        cache.get("views")
        cache.get("views")
        self.assertEqual(self.redis_rows(), {"GET :?:views": (2, 0)})

    def test_a_django_cache_made_for_another_thread_is_watched_too(self):
        class RedisCacheClient:
            def get_client(self, key=None, *, write=False):
                return self._client()

        class RedisCache:
            def __init__(self):
                self._cache = RedisCacheClient()
                self._cache._client = Redis

            def get(self, key):
                return self._cache.get_client(key).get(":1:" + key)

        RedisCache.__module__ = "django.core.cache.backends.redis"

        class CacheHandler:
            """As Django's caches: one cache object per alias per thread."""
            def __init__(self):
                self.local = threading.local()

            def __iter__(self):
                return iter(["default", "other"])

            def create_connection(self, alias):
                return RedisCache()

            def __getitem__(self, alias):
                made = getattr(self.local, alias, None)
                if made is None:
                    made = self.create_connection(alias)
                    setattr(self.local, alias, made)
                return made

        caches = CacheHandler()
        module = types.ModuleType("django.core.cache")
        module.caches = caches
        with mock.patch.dict(sys.modules, {"django": types.ModuleType("django"), "django.core": types.ModuleType("django.core"),
                                           "django.core.cache": module}):
            self.platform.watch_database(caches["default"])
            self.platform.watch_database(caches["default"])
            caches["default"].get("views")
            thread = threading.Thread(target=lambda: (caches["default"].get("views"), caches["other"].get("views")))
            thread.start()
            thread.join()
        self.assertEqual(self.redis_rows(), {"GET :?:views": (2, 0)})

    def test_a_sync_cluster_transaction_is_multi_and_its_watch_doesnt_name_it(self):
        class TransactionStrategy:
            pass

        class ClusterPipeline(Redis):
            def __init__(self):
                super().__init__()
                self._execution_strategy = TransactionStrategy()
                self.stack = []

            def execute_command(self, *args, **kwargs):
                if args[0] != "WATCH":
                    self.stack.append(args)
                return self

            def execute(self, raise_on_error=True):
                stack, self.stack = self.stack, []
                return [reply(args) for args in stack]

        class RedisCluster(Redis):
            def pipeline(self, transaction=None, shard_hint=None):
                return ClusterPipeline()

        RedisCluster.__module__ = ClusterPipeline.__module__ = "redis.cluster"
        redis = self.platform.watch_database(RedisCluster())
        pipe = redis.pipeline(transaction=True)
        pipe.execute_command("WATCH", "stock:9")
        pipe.get("stock:9")
        self.assertEqual(pipe.execute(), [b"v"])
        self.assertEqual(self.redis_rows(), {"MULTI GET stock:?": (1, 0)})

    def test_django_redis_watches_the_clients_it_holds_and_connects(self):
        held = Redis()

        class DefaultClient:
            def __init__(self):
                self._clients = [held, None]

            def connect(self, index=0):
                return Redis()

            def get_client(self, write=True):
                if self._clients[1] is None:
                    self._clients[1] = self.connect(1)
                return self._clients[0 if write else 1]

        class RedisCache:
            client = DefaultClient()

        RedisCache.__module__ = "django_redis.cache"
        cache = RedisCache()
        self.platform.watch_database(cache)
        cache.client.get_client(write=True).get("session:a1")
        cache.client.get_client(write=False).get("session:b2")
        self.assertEqual(self.redis_rows(), {"GET session:?": (2, 0)})

    def test_a_django_redis_client_that_isnt_redis_pys_is_handed_back_untouched(self):
        class Custom:
            """A CLIENT_CLASS's connection: no execute_command to watch."""
            __slots__ = ()

        class DefaultClient:
            _clients = [None]

            def connect(self, index=0):
                return Custom()

        class RedisCache:
            client = DefaultClient()

        RedisCache.__module__ = "django_redis.cache"
        cache = RedisCache()
        self.platform.watch_database(cache)
        self.assertIsInstance(cache.client.connect(0), Custom)

    def test_with_server_speed_off_nothing_is_timed(self):
        platform = make_platform(performance=False)
        redis = Redis()
        self.assertIs(platform.watch_database(redis), redis)
        redis.get("user:1")
        platform.close()
        self.assertEqual(self.redis_rows(), {})


if __name__ == "__main__":
    unittest.main()
