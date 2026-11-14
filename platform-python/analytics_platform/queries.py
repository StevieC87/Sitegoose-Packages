"""Database query timings (sdk/protocols/queries.md), part of the performance
module: per minute, request method and route, database and query, how many
ran, how many failed, their total and slowest time and a count per time
bucket, to POST /events/server-queries. Every value is taken out of a query
before it is counted (normalize_statement), and bound parameters are never read.

Caught by, with nothing to set up beyond the platform itself:

- Django: a wrapper on every connection's execute_wrappers (the Django
  integration adds it as connections open).
- SQLAlchemy: listeners on the Engine class, so every engine.
- pymongo: a global command listener. pymongo only gives it to clients made
  after it is registered, so create the platform before your MongoClient.
- Anything else on a DB-API driver (psycopg, psycopg2, mysqlclient, PyMySQL,
  sqlite3...): conn = platform.watch_database(conn).
- ClickHouse: a clickhouse-connect client (query, command, insert...) or a
  clickhouse-driver Client (execute): client = platform.watch_database(client).
- Redis: a redis-py client (Redis, RedisCluster, sync or asyncio), watched in
  place: platform.watch_database(r); a Django cache on Redis the same way.

A query is timed at one layer only: the outer one (Django, SQLAlchemy) marks
it as being timed, and a watched connection under it leaves it alone.

The same requests' outgoing HTTP calls (sdk/protocols/calls.md) are filed
alongside, by call method and host (calls.py has the hooks), and go to
POST /events/server-calls; calls=False leaves them out.
"""
import contextvars
import inspect
import json
import os
import re
import sys
import threading
import time
import weakref
from collections.abc import Mapping
from contextlib import contextmanager
from datetime import datetime, timezone
from importlib.util import find_spec

from .performance import BUCKET_EDGES_MS, MAX_ROWS, bucket_of

MAX_STATEMENT = 1000
OTHER_STATEMENT = "(other)"
BACKGROUND = ("JOB", "(background)")
# The databases a row may name; anything else is "other".
DATABASES = frozenset(("postgresql", "mysql", "mariadb", "sqlite", "mssql", "oracle", "clickhouse", "mongodb", "redis", "other"))
# Past this many statements in one request, new ones are one "(other)".
PER_REQUEST = 50
# Past MAX_KEYS in a minute new statements fold into "(other)"; past
# HARD_MAX_KEYS nothing new is kept until the next minute.
MAX_KEYS = 200
HARD_MAX_KEYS = 300
# Rows the collector couldn't take (unreachable, 429, 5xx), kept for the next send.
MAX_RETRY_ROWS = 2000
# Normalized statements kept, so a request running one query 10,000 times
# scans its text once. Long ones (a big insert) aren't kept.
CACHE_SIZE = 2000
CACHE_TEXT = 4000
# Connection chatter, never recorded.
MONGO_CHATTER = frozenset(("hello", "isMaster", "ismaster", "ping", "buildInfo", "saslStart", "saslContinue",
                           "getMore", "endSessions", "killCursors", "getLastError"))

# The request (or job) the code is in: its queries, folded into the minute's
# rows when it finishes. None outside one.
current_queries = contextvars.ContextVar("analytics_platform_queries", default=None)
# True while an outer layer (Django, SQLAlchemy) times a query, so a watched
# connection under it doesn't count it again.
_timing = contextvars.ContextVar("analytics_platform_query_timing", default=False)
# True while the package reads Redis for itself (a queue's depth, queues.py):
# a watched client it shares with the app leaves those commands out.
_own_redis = contextvars.ContextVar("analytics_platform_own_redis", default=False)

# ---- Normalizing: a port of expresscollect/Analytics/queryText.js ----

# JavaScript's \s, so text is trimmed and spaces collapse exactly as there.
_SPACE = "\t\n\v\f\r                  　﻿"
_SPACES = frozenset(_SPACE)
_S = "[" + re.escape(_SPACE) + "]"
# A digit right after one of these is part of a name or a placeholder
# (table2, $1, @p1, :1), not a value. ASCII only, in every package.
_WORD = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_$@:")
_DIGITS = frozenset("0123456789")
_WORD_RUN = re.compile(r"[A-Za-z0-9_$@:]+")
_NUMBER = re.compile(r"0[xX][0-9a-fA-F]+|(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]+)?")
_DOLLAR_TAG = re.compile(r"\$(?:[A-Za-z_][A-Za-z0-9_]*)?\$")
_NAME = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_")
_PLACEHOLDER = r"(?:\?|\$[0-9]+|:[A-Za-z0-9_]+|@[A-Za-z0-9_]+)"
_LIST = re.compile(r"\(%s*%s(?:%s*,%s*%s)*%s*\)" % (_S, _PLACEHOLDER, _S, _S, _PLACEHOLDER, _S))
_ROWS = re.compile(r"\(\?\)(?:%s*,%s*\(\?\))+" % (_S, _S))
# Where "..." may hold a value rather than a name: SQLite takes a
# double-quoted string as a literal when no column has that name (SQLCipher's
# PRAGMA key = "x'2DD2..'"), Oracle writes a password as a quoted name, and an
# unknown database may do either. There "..." is kept only when it reads as a
# plain name, closed: "email", never "x'2D..'", "N3w P@ss" or an unclosed one.
_VALUE_QUOTES = frozenset(("sqlite", "oracle", "other"))
_QUOTED_NAME = re.compile(r'"[A-Za-z_][A-Za-z0-9_$#]{0,127}"')
# A password or key written as a name, on any database: Oracle's
# ALTER USER u IDENTIFIED BY pw and SQLCipher's PRAGMA key = "passphrase".
# What follows is "?" whether it was a word or a quoted name. ASCII flags, as
# JavaScript's \b and case-insensitive matching are.
_SECRET_NAME = r'("(?:[^"]|"")*"?|`(?:[^`]|``)*`?|[^%s;,()]+)' % re.escape(_SPACE)
_IDENTIFIED = re.compile(r"(\bIDENTIFIED BY )" + _SECRET_NAME, re.I | re.A)
_PRAGMA_KEY = re.compile(r"(\bPRAGMA (?:[A-Za-z_][A-Za-z0-9_]*\.)?(?:HEX)?(?:RE)?KEY ?[=(] ?)" + _SECRET_NAME, re.I | re.A)
_MONGO = re.compile(r"([^%s]+)(?: ([^%s]+))?(?: (.*))?\Z" % (re.escape(_SPACE), re.escape(_SPACE)), re.S)
_INDEX_KEY = re.compile(r"(?:0|[1-9][0-9]*)\Z")
_LONE_SURROGATE = re.compile("[\ud800-\udfff]")


def database_of(db):
    name = str(db if db is not None else "").lower()
    return name if name in DATABASES else "other"


def _quote_end(sql, start, quote, backslash=True):
    """The index after the quoted run starting at start (the opening quote),
    or the text's length. A doubled quote escapes, and a backslash too
    unless backslash is False."""
    i = start + 1
    n = len(sql)
    while i < n:
        c = sql[i]
        if c == "\\" and backslash:
            i += 2
        elif c == quote:
            if i + 1 < n and sql[i + 1] == quote:
                i += 2
            else:
                return i + 1
        else:
            i += 1
    return n


def _prefix(out):
    """A string's one-letter prefix (E'..' N'..' X'..' B'..'): the output's
    last character, when what comes before it isn't a letter, digit or _;
    else ""."""
    piece = out[-1] if out else ""
    if not piece or piece[-1] not in "EeNnXxBb":
        return ""
    before = piece[-2] if len(piece) > 1 else (out[-2][-1] if len(out) > 1 else "")
    return "" if before and before in _NAME else piece[-1]


def _drop_prefix(out):
    """The prefix goes with its string."""
    piece = out[-1]
    if len(piece) > 1:
        out[-1] = piece[:-1]
    else:
        out.pop()


def _sql_shape(sql, db, backslash_literal=None):
    mysql = db in ("mysql", "mariadb")
    postgres = db == "postgresql"
    # Where a backslash in a string is just a character: PostgreSQL's plain
    # strings (standard_conforming_strings, on since 9.1), SQLite, SQL Server
    # and Oracle. Read as an escape there, 'C:\' ends late and lets what
    # follows out. MySQL, MariaDB, ClickHouse and unknown databases escape.
    literal = (postgres or db in ("sqlite", "mssql", "oracle")) if backslash_literal is None else backslash_literal
    out = []  # pieces; "last" is the output's last character, for spaces
    last = ""
    n = len(sql)
    i = 0
    while i < n:
        c = sql[i]
        nxt = sql[i + 1] if i + 1 < n else ""
        prev = sql[i - 1] if i > 0 else ""
        if (c == "-" and nxt == "-") or (c == "#" and mysql):
            end = sql.find("\n", i)
            i = n if end == -1 else end
            if out and last != " ":
                out.append(" ")
                last = " "
        elif c == "/" and nxt == "*":
            end = sql.find("*/", i + 2)
            i = n if end == -1 else end + 2
            if out and last != " ":
                out.append(" ")
                last = " "
        elif c == "'" or (c == '"' and mysql):
            # Only PostgreSQL's E'..' escapes with a backslash where it is literal.
            prefix = _prefix(out)
            escapes = not literal or (postgres and prefix in ("E", "e"))
            if prefix:
                _drop_prefix(out)
            i = _quote_end(sql, i, c, escapes)
            out.append("?")
            last = "?"
        elif c == '"' or c == "`":
            end = _quote_end(sql, i, c, not literal)
            run = sql[i:end]
            if c == '"' and db in _VALUE_QUOTES and not _QUOTED_NAME.fullmatch(run):
                run = "?"
            out.append(run)
            last = run[-1]
            i = end
        elif c == "$" and prev not in _WORD and _DOLLAR_TAG.match(sql[i:i + 64]):
            tag = _DOLLAR_TAG.match(sql[i:i + 64]).group(0)
            end = sql.find(tag, i + len(tag))
            i = n if end == -1 else end + len(tag)
            out.append("?")
            last = "?"
        elif (c in _DIGITS or (c == "." and nxt in _DIGITS)) and prev not in _WORD:
            i = _NUMBER.match(sql, i, i + 400).end()
            out.append("?")
            last = "?"
        elif c in _SPACES:
            i += 1
            if out and last != " ":
                out.append(" ")
                last = " "
        elif c in _WORD:
            # A name, keyword or placeholder, whole: inside it every
            # character follows a word character, so none starts a value.
            end = _WORD_RUN.match(sql, i).end()
            out.append(sql[i:end])
            last = sql[end - 1]
            i = end
        else:
            out.append(c)
            last = c
            i += 1
    text = _PRAGMA_KEY.sub(r"\g<1>?", _IDENTIFIED.sub(r"\g<1>?", "".join(out)))
    return _ROWS.sub("(?)", _LIST.sub("(?)", text)).strip(_SPACE)


def _index_key(key):
    return bool(_INDEX_KEY.match(key)) and int(key) < 4294967295


def _ordered(value):
    """An object's entries in JavaScript's order: index-like keys ("0",
    "42") first, ascending, then the rest as they came."""
    indexes = sorted((k for k in value if _index_key(k)), key=int)
    return [(k, value[k]) for k in indexes] + [(k, v) for k, v in value.items() if not _index_key(k)]


def _mongo_shape(value, depth=0):
    """A Mongo filter or pipeline's shape: keys kept, every value "?", and an
    array whose items all have the same shape kept as one."""
    if depth >= 6 or not isinstance(value, (dict, list)):
        return "?"
    if isinstance(value, list):
        items = [_mongo_shape(item, depth + 1) for item in value]
        seen = {_json(item) for item in items}
        return [items[0]] if len(seen) == 1 else items
    return _Object((k, _mongo_shape(v, depth + 1)) for k, v in _ordered(value))


class _Object(list):
    """An object's entries in the order JavaScript writes them."""


def _json(value):
    """JSON.stringify: compact, non-ASCII as itself, a lone surrogate escaped."""
    if isinstance(value, _Object):
        return "{" + ",".join(_json(k) + ":" + _json(v) for k, v in value) + "}"
    if isinstance(value, list):
        return "[" + ",".join(_json(item) for item in value) + "]"
    text = json.dumps(value, ensure_ascii=False)
    return _LONE_SURROGATE.sub(lambda m: "\\u%04x" % ord(m.group(0)), text)


def _no_constant(name):
    raise ValueError(name)


def _mongo_statement(text):
    """"find users {...}": the command, the collection, and the filter's shape."""
    match = _MONGO.match(text.strip(_SPACE))
    if not match:
        return ""
    command, collection, rest = match.groups()
    # A "collection" with a brace, bracket or quote in it is the filter's start.
    if collection and any(ch in collection for ch in "{}[]\"'"):
        rest = collection if rest is None else collection + " " + rest
        collection = None
    shape = ""
    if rest:
        try:
            shape = _json(_mongo_shape(json.loads(rest, parse_constant=_no_constant)))
        except (ValueError, RecursionError):
            shape = ""
    return " ".join(part for part in (command, collection, shape) if part)


# Redis: the command and its first key's shape, never an argument or value
# (queries.md, "Redis"). A key keeps each ":" segment that is only letters
# and "_" (32 at most); every other segment is "?", so IDs, slugs, emails and
# hashes never leave the server: user:42:cart -> user:?:cart.
_REDIS_WORD = re.compile(r"[A-Za-z][A-Za-z0-9_.|-]{0,39}\Z")
_REDIS_SEGMENT = re.compile(r"[A-Za-z_]{1,32}\Z")
# Commands whose second word is a subcommand (CLIENT SETNAME, XINFO STREAM).
_REDIS_CONTAINERS = frozenset(("ACL", "CLIENT", "CLUSTER", "COMMAND", "CONFIG", "DEBUG", "FUNCTION", "LATENCY", "MEMORY",
                               "MODULE", "OBJECT", "PUBSUB", "SCRIPT", "SLOWLOG", "XGROUP", "XINFO"))
# Of those, the ones with a key after the subcommand.
_REDIS_SUB_KEY = frozenset(("OBJECT", "MEMORY", "XGROUP", "XINFO"))
# No key: what follows is a password, a message, a number or nothing.
_REDIS_NO_KEY = frozenset(("PING", "ECHO", "INFO", "AUTH", "HELLO", "SELECT", "QUIT", "RESET", "MULTI", "EXEC", "DISCARD",
                           "UNWATCH", "DBSIZE", "TIME", "FLUSHDB", "FLUSHALL", "SAVE", "BGSAVE", "BGREWRITEAOF", "LASTSAVE",
                           "SCAN", "RANDOMKEY", "SWAPDB", "SHUTDOWN", "ROLE", "REPLICAOF", "SLAVEOF", "READONLY", "READWRITE",
                           "LOLWUT", "FAILOVER", "PSYNC", "SYNC", "REPLCONF", "MIGRATE"))
# Script calls: script or name, then how many keys, then the keys.
_REDIS_SCRIPTS = frozenset(("EVAL", "EVALSHA", "EVAL_RO", "EVALSHA_RO", "FCALL", "FCALL_RO"))
# How many keys first, then the keys.
_REDIS_NUMKEYS = frozenset(("ZUNION", "ZINTER", "ZDIFF", "SINTERCARD", "ZINTERCARD", "LMPOP", "ZMPOP"))
# Waiting, not working: a queue worker sits in these for seconds, so timing
# them would put every idle worker at the top of the slow list.
_REDIS_WAITING = frozenset(("BLPOP", "BRPOP", "BRPOPLPUSH", "BLMOVE", "BLMPOP", "BZPOPMIN", "BZPOPMAX", "BZMPOP", "WAIT",
                            "WAITAOF", "SUBSCRIBE", "PSUBSCRIBE", "SSUBSCRIBE", "UNSUBSCRIBE", "PUNSUBSCRIBE",
                            "SUNSUBSCRIBE", "MONITOR"))
_REDIS_PREFIXES = frozenset(("PIPELINE", "MULTI"))
# ASCII only, as JavaScript's /[a-z]/: str.upper() would change "ß" and "ı".
_ASCII_UPPER = str.maketrans("abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
_JS_DECIMAL = re.compile(r"[+-]?(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]+)?\Z")
_JS_RADIX = re.compile(r"0[xXoObB][0-9a-fA-F]+\Z")
_SPACE_RUN = re.compile(_S + "+")


def _upper(text):
    return text.translate(_ASCII_UPPER)


def _positive(value):
    """JavaScript's Number(value) > 0, for what a command's argument can be."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value > 0
    if not isinstance(value, str):
        return False
    text = value.strip(_SPACE)
    if _JS_DECIMAL.match(text):
        return float(text) > 0
    if _JS_RADIX.match(text):
        try:
            return int(text, 0) > 0
        except ValueError:
            return False
    return text in ("Infinity", "+Infinity")


def redis_key_shape(key):
    # An empty key is "?" too: "GET " would come back from the collector as "GET".
    if not isinstance(key, str) or key == "":
        return "?"
    return ":".join(part if part == "" or _REDIS_SEGMENT.match(part) else "?" for part in key.split(":"))


def redis_command(args):
    """A command as the client sends it (["GET", "user:42"]) -> "GET user:?",
    or None for one that isn't timed (blocking, or not a command)."""
    if not isinstance(args, (list, tuple)) or not args or not isinstance(args[0], str) or not _REDIS_WORD.match(args[0]):
        return None
    name = _upper(args[0])

    def word(i):
        return _upper(args[i]) if isinstance(args[i], str) else ""

    if name in _REDIS_WAITING:
        return None
    command = name
    key = None
    if name in _REDIS_CONTAINERS:
        if len(args) > 1 and isinstance(args[1], str) and _REDIS_WORD.match(args[1]):
            command = name + " " + _upper(args[1])
            # Only after a subcommand: "OBJECT user" would read back as OBJECT USER.
            if name in _REDIS_SUB_KEY:
                key = 2
    elif name in _REDIS_SCRIPTS:
        if len(args) > 2 and _positive(args[2]):
            key = 3
    elif name in _REDIS_NUMKEYS:
        if len(args) > 1 and _positive(args[1]):
            key = 2
    elif name == "BITOP":
        key = 2
    elif name in ("XREAD", "XREADGROUP"):
        # Its options, then STREAMS and the keys. XREADGROUP's group and
        # consumer come first and may be named anything, as may a stream ("block").
        at = -1
        for i in range(4 if name == "XREADGROUP" else 1, len(args)):
            if word(i) == "BLOCK":
                return None
            if word(i) == "STREAMS":
                at = i
                break
        if at > 0:
            key = at + 1
    elif name not in _REDIS_NO_KEY and name not in _REDIS_PREFIXES:
        key = 1
    return command + " " + redis_key_shape(args[key]) if key is not None and key < len(args) else command


def _redis_statement(text):
    """A statement a package sent: [PIPELINE|MULTI] COMMAND [SUBCOMMAND] [key].
    Anything else (an argument a package let through) is (other)."""
    words = _SPACE_RUN.split(text.strip(_SPACE))
    if words[0] == "":
        return ""
    out = []
    i = 0
    if _upper(words[0]) in _REDIS_PREFIXES and len(words) > 1:
        out.append(_upper(words[0]))
        i = 1
    if not _REDIS_WORD.match(words[i]):
        return OTHER_STATEMENT
    name = _upper(words[i])
    i += 1
    if name in _REDIS_WAITING:
        return OTHER_STATEMENT
    out.append(name)
    if name in _REDIS_CONTAINERS and i < len(words) and _REDIS_WORD.match(words[i]):
        out.append(_upper(words[i]))
        i += 1
    if i < len(words) - 1:
        return OTHER_STATEMENT
    if i < len(words):
        out.append(redis_key_shape(words[i]))
    return " ".join(out)


def normalize_statement(text, db):
    """The statement to store, or "" when nothing is left of it."""
    if not isinstance(text, str):
        return ""
    if text == OTHER_STATEMENT:
        return text
    db = database_of(db)
    if db == "mongodb":
        shaped = _mongo_statement(text)
    elif db == "redis":
        shaped = _redis_statement(text)
    elif db == "other" and "\\" in text:
        # A database we don't know may or may not take a backslash as an
        # escape, and each reading leaks what the other hides. When they
        # disagree the query keeps its timing under (other) and its text is
        # left out.
        escaped = _sql_shape(text, db, False)
        shaped = escaped if escaped == _sql_shape(text, db, True) else OTHER_STATEMENT
    else:
        shaped = _sql_shape(text, db)
    return shaped[:MAX_STATEMENT].strip(_SPACE) if len(shaped) > MAX_STATEMENT else shaped


# %s and %(name)s (the format and pyformat drivers, and Django) as the "?"
# the normalizer knows, so IN (%s, %s) is IN (?) too; %% is the % it stands for.
_PERCENT = re.compile(r"%\([A-Za-z0-9_]+\)s|%s|%%")


def _percent_placeholders(sql):
    return _PERCENT.sub(lambda m: "%" if m.group(0) == "%%" else "?", sql)


# ---- Recording ----

def _entry():
    return {"count": 0, "errors": 0, "sum_ms": 0.0, "max_ms": 0.0, "buckets": [0] * (len(BUCKET_EDGES_MS) + 1)}


def _add(entry, ms, failed):
    entry["count"] += 1
    entry["errors"] += 1 if failed else 0
    entry["sum_ms"] += ms
    entry["max_ms"] = max(entry["max_ms"], ms)
    entry["buckets"][bucket_of(ms)] += 1


def _combine(into, entry):
    into["count"] += entry["count"]
    into["errors"] += entry["errors"]
    into["sum_ms"] += entry["sum_ms"]
    into["max_ms"] = max(into["max_ms"], entry["max_ms"])
    into["buckets"] = [a + b for a, b in zip(into["buckets"], entry["buckets"])]


def _file(entries, a, b, ms, failed):
    """One query or call into a request's map, keyed (a, b): past
    PER_REQUEST keys new ones are (a, "(other)")."""
    entry = entries.get((a, b))
    if entry is None:
        key = (a, b) if len(entries) < PER_REQUEST else (a, OTHER_STATEMENT)
        entry = entries.get(key)
        if entry is None:
            entry = entries[key] = _entry()
    _add(entry, ms, failed)


class RequestQueries:
    """One request's (or job run's) queries, by database and statement, and
    its outgoing calls, by call method and host: a request running 10,000
    queries costs what one running ten does. done: (method, route) once the
    request was counted, so a query or call it didn't wait for still goes
    under it."""
    __slots__ = ("owner", "entries", "calls", "done")

    def __init__(self, owner):
        self.owner = owner
        self.entries = {}
        self.calls = {}
        self.done = None

    def add(self, db, statement, ms, failed):
        _file(self.entries, db, statement, ms, failed)

    def add_call(self, call_method, host, ms, failed):
        _file(self.calls, call_method, host, ms, failed)


class _Minutes:
    """One kind's rows by minute | method | route | its two key fields."""
    __slots__ = ("path", "fields", "rows", "per_minute", "retry")

    def __init__(self, path, fields):
        self.path = path
        self.fields = fields
        self.rows = {}
        self.per_minute = {}
        self.retry = []


_latest = None  # the latest Queries, for queries outside any request


class Queries:
    """Made by the performance module (its "queries" and "calls" options:
    False leaves that kind out), and sent when it sends: finished minutes
    every minute, everything on shutdown."""

    def __init__(self, core, performance, queries=True, calls=True):
        global _latest
        self.core = core
        self.performance = performance
        self.kinds = {}
        if queries:
            self.kinds["queries"] = _Minutes("/events/server-queries", ("db", "statement"))
        if calls:
            self.kinds["calls"] = _Minutes("/events/server-calls", ("call_method", "host"))
        self.lock = threading.Lock()
        self.cache = {}
        # The collector's own address: the package's calls to it aren't counted.
        self.own_address = normal_address(core.endpoint)
        _latest = weakref.ref(self)
        if queries:
            _watch_sqlalchemy(core)
            _watch_pymongo(core)
        if hasattr(os, "register_at_fork"):
            os.register_at_fork(after_in_child=self._forked)

    # The queries kind's rows, as they were before calls joined them.
    rows = property(lambda self: self._kind("queries").rows)
    per_minute = property(lambda self: self._kind("queries").per_minute)
    retry = property(lambda self: self._kind("queries").retry,
                     lambda self, value: setattr(self._kind("queries"), "retry", value))

    def _kind(self, kind):
        return self.kinds.get(kind) or _Minutes("", ())

    def has(self, kind):
        return kind in self.kinds

    def _forked(self):
        """In a forked worker the parent's rows are the parent's to send."""
        self.lock = threading.Lock()
        for minutes in self.kinds.values():
            minutes.rows, minutes.per_minute, minutes.retry = {}, {}, []

    def on(self):
        return self.core.is_on("performance")

    def request(self):
        return RequestQueries(self)

    def statement(self, db, sql):
        if len(sql) > CACHE_TEXT:
            return normalize_statement(sql, db)
        key = (db, sql)
        found = self.cache.get(key)
        if found is None:
            if len(self.cache) >= CACHE_SIZE:
                self.cache.clear()
            found = self.cache[key] = normalize_statement(sql, db)
        return found

    def finish(self, method, route, request):
        """The request finished, as the performance module recorded it: its
        queries and calls go into this minute's rows under its method and route."""
        if request is None or request.owner is not self:
            return
        request.done = (method, route)
        entries, request.entries = request.entries, {}
        calls, request.calls = request.calls, {}
        if not entries and not calls:
            return
        minute = int(time.time() // 60) * 60
        with self.lock:
            for kind, filed in (("queries", entries), ("calls", calls)):
                minutes = self.kinds.get(kind)
                if minutes is None:
                    continue
                for (a, b), entry in filed.items():
                    self._merge(minutes, (minute, method, route, a, b), entry)

    def background(self, db, statement, ms, failed, kind="queries", under=BACKGROUND):
        """A query (or call) outside any request or job, or after the one it
        ran in was counted (under: its method and route)."""
        minutes = self.kinds.get(kind)
        if minutes is None:
            return
        entry = _entry()
        _add(entry, ms, failed)
        minute = int(time.time() // 60) * 60
        with self.lock:
            self._merge(minutes, (minute,) + tuple(under) + (db, statement), entry)

    def _merge(self, minutes, key, entry):
        rows = minutes.rows
        row = rows.get(key)
        if row is None:
            keys = minutes.per_minute.get(key[0], 0)
            if keys >= MAX_KEYS:
                key = key[:4] + (OTHER_STATEMENT,)
                row = rows.get(key)
                if row is None and keys >= HARD_MAX_KEYS:
                    return
            if row is None:
                row = rows[key] = _entry()
                minutes.per_minute[key[0]] = keys + 1
        _combine(row, entry)

    def flush(self, everything=True):
        for minutes in self.kinds.values():
            self._flush(minutes, everything)

    def _flush(self, minutes, everything):
        current = int(time.time() // 60) * 60
        a, b = minutes.fields
        with self.lock:
            ready = [(k, v) for k, v in minutes.rows.items() if everything or k[0] < current]
            for k, _ in ready:
                del minutes.rows[k]
            for minute in [m for m in minutes.per_minute if everything or m < current]:
                del minutes.per_minute[minute]
            rows, minutes.retry = minutes.retry, []
        rows += [{
            "minute": datetime.fromtimestamp(k[0], timezone.utc).isoformat().replace("+00:00", "Z"),
            "method": k[1], "route": k[2], a: k[3], b: k[4], "count": v["count"], "errors": v["errors"],
            "sum_ms": round(v["sum_ms"], 1), "max_ms": round(v["max_ms"], 1), "buckets": v["buckets"],
        } for k, v in ready]
        for i in range(0, len(rows), MAX_ROWS):
            batch = rows[i:i + MAX_ROWS]
            res = self.core.send("performance", minutes.path, auth="bearer", body={
                "site_id": self.core.site_id, "server_name": self.performance.server_name,
                "runtime": self.performance.runtime, "rows": batch})
            # Unreachable, too many or storage down: these rows are still good
            # for the next send. A 400 or 401 won't get better by resending.
            status = getattr(res, "status", 0)
            if not getattr(res, "unsendable", False) and (res is None or status == 429 or status >= 500):
                with self.lock:
                    minutes.retry = (minutes.retry + batch)[-MAX_RETRY_ROWS:]


def _owner(request):
    owner = request.owner if request is not None else (_latest() if _latest else None)
    return owner if owner is not None and owner.on() else None


def record(db, sql, ms, failed=False):
    """One query that ran, from any hook: into the request it ran in, else
    straight into the minute's rows as JOB (background)."""
    request = current_queries.get()
    owner = _owner(request)
    if owner is None or "queries" not in owner.kinds:
        return
    try:
        statement = owner.statement(db, sql)
        if not statement:
            return
        if request is None:
            owner.background(db, statement, ms, failed)
        elif request.done is not None:
            owner.background(db, statement, ms, failed, under=request.done)
        else:
            request.add(db, statement, ms, failed)
    except Exception as error:
        owner.core.log("performance", "could not record a query:", error)


# ---- Outgoing calls (sdk/protocols/calls.md); the hooks are in calls.py ----

_HOST = re.compile(r"[a-z0-9._\-\[\]:]{1,255}\Z")
_CALL_METHOD = re.compile(r"[A-Z]{1,10}\Z")
_DEFAULT_PORTS = {"http": "80", "https": "443", "ws": "80", "wss": "443"}


def _split_address(url):
    """(scheme, host as calls.md stores it, path) of a URL, or None."""
    try:
        text = str(url)
    except Exception:
        return None
    scheme, sep, rest = text.partition("://")
    if not sep or not scheme:
        return None
    scheme = scheme.lower()
    cut = len(rest)
    for mark in "/?#":
        at = rest.find(mark)
        if at != -1 and at < cut:
            cut = at
    netloc, path = rest[:cut].rpartition("@")[2].lower(), rest[cut:]
    if netloc.startswith("["):
        end = netloc.find("]")
        if end == -1:
            return None
        name, port = netloc[:end + 1], netloc[end + 1:]
        if port and not port.startswith(":"):
            return None
        port = port[1:]
    else:
        name, _, port = netloc.partition(":")
    if port and (not port.isdigit() or int(port) > 65535):
        return None
    if port and port.lstrip("0") == _DEFAULT_PORTS.get(scheme):
        port = ""
    host = name + (":" + str(int(port)) if port else "")
    if not name or not _HOST.match(host):
        return None
    return scheme, host, path.split("?")[0].split("#")[0]


def host_of_url(url):
    """The host of an outgoing call: lower case, its port only when it isn't
    the scheme's own; "" when it isn't one."""
    parts = _split_address(url)
    return parts[1] if parts else ""


def normal_address(url):
    """scheme://host/path with no trailing slash, as the collector's own
    address is compared."""
    parts = _split_address(url)
    return "%s://%s%s" % (parts[0], parts[1], parts[2].rstrip("/")) if parts else ""


def call_started(url, method):
    """A call about to be sent: what call_ended needs, or None when it isn't
    counted (Server speed off, calls: False, a call to the collector, a
    database client's own request, or not an address). Never raises: it runs
    inside the app's own call."""
    try:
        if _timing.get():
            return None
        request = current_queries.get()
        owner = _owner(request)
        if owner is None or "calls" not in owner.kinds:
            return None
        address = str(url)
        own = owner.own_address
        if own:
            normal = normal_address(address)
            if normal == own or normal.startswith(own + "/"):
                return None
        host = host_of_url(address)
        call_method = str(method or "GET").upper()
        if not host or not _CALL_METHOD.match(call_method):
            return None
        return (request, owner, call_method, host, time.perf_counter())
    except Exception:
        return None


def call_ended(started, status):
    """The call got its response's headers (status), or no answer (0)."""
    if started is None:
        return
    try:
        request, owner, call_method, host, at = started
        ms = (time.perf_counter() - at) * 1000
        try:
            status = int(status or 0)
        except (TypeError, ValueError):
            status = 0
        failed = not (0 < status < 500)
        if request is None:
            owner.background(call_method, host, ms, failed, kind="calls")
        elif request.done is not None:
            owner.background(call_method, host, ms, failed, kind="calls", under=request.done)
        else:
            request.add_call(call_method, host, ms, failed)
    except Exception:
        pass  # the call is left out; the app's own call goes on


def _active():
    """Whether anything would keep a query: skip the timing when not."""
    return current_queries.get() is not None or (_latest is not None and _latest() is not None)


def _timed(db, text, call, args, kwargs, mark):
    """call(*args, **kwargs), timed as one query. mark: an outer layer, so
    a watched connection under it leaves the query alone."""
    token = _timing.set(True) if mark else None
    started = time.perf_counter()
    failed = True
    try:
        result = call(*args, **kwargs)
        failed = False
        return result
    finally:
        ms = (time.perf_counter() - started) * 1000
        if token is not None:
            _reset(token)
        try:
            record(db, text() if callable(text) else text, ms, failed)
        except Exception:
            pass  # never in place of the query's own result or error


def _reset(token):
    try:
        _timing.reset(token)
    except ValueError:  # set in another context
        _timing.set(False)


# ---- Django ----

DJANGO_VENDORS = {"postgresql": "postgresql", "mysql": "mysql", "sqlite": "sqlite", "oracle": "oracle",
                  "microsoft": "mssql"}


def _django_execute(execute, sql, params, many, context):
    if _timing.get() or not _active():
        return execute(sql, params, many, context)
    db = DJANGO_VENDORS.get(getattr(context.get("connection"), "vendor", ""), "other")
    # Django writes every placeholder %s, whichever the database; with no
    # parameters the text is sent as it is.
    text = (lambda: _percent_placeholders(sql) if params is not None and isinstance(sql, str) else _text(sql, None))
    return _timed(db, text, execute, (sql, params, many, context), {}, True)


def _django_connected(sender=None, connection=None, **_):
    wrappers = getattr(connection, "execute_wrappers", None)
    # connection_created comes again on every reconnect. First, not last: a
    # connection opened inside the app's own `with connection.execute_wrapper(x)`
    # pops the last wrapper when the block ends, which must stay x.
    if isinstance(wrappers, list) and _django_execute not in wrappers:
        wrappers.insert(0, _django_execute)


def watch_django():
    """Every Django connection, as it opens (the Django integration calls it),
    and the ones this thread has open already."""
    from django.db.backends.signals import connection_created
    connection_created.connect(_django_connected, weak=False, dispatch_uid="analytics_platform_queries")
    from django.db import connections
    try:
        opened = connections.all(initialized_only=True)
    except TypeError:  # before Django 4.1
        opened = connections.all()
    for connection in opened:
        _django_connected(connection=connection)


# ---- SQLAlchemy ----

_STARTED = "analytics_platform_query"
_hooked = set()


def _sa_before(conn, cursor, statement, parameters, context, executemany):
    stack = conn.info.setdefault(_STARTED, [])
    if _timing.get() or not _active():
        stack.append(None)
    else:
        stack.append((time.perf_counter(), _timing.set(True)))


def _sa_done(conn, statement, parameters, failed):
    stack = conn.info.get(_STARTED) if conn is not None else None
    if not stack:
        return
    started = stack.pop()
    if started is None:
        return
    ms = (time.perf_counter() - started[0]) * 1000
    _reset(started[1])
    dialect = conn.dialect
    db = database_of(getattr(dialect, "name", ""))
    style = getattr(dialect, "paramstyle", "")
    text = _percent_placeholders(statement) if style in ("format", "pyformat") and parameters and isinstance(statement, str) else statement
    record(db, _text(text, None), ms, failed)


def _sa_after(conn, cursor, statement, parameters, context, executemany):
    _sa_done(conn, statement, parameters, False)


def _sa_error(context):
    _sa_done(context.connection, context.statement, context.parameters, True)


def _watch_sqlalchemy(core):
    if "sqlalchemy" in _hooked:
        return
    try:
        if find_spec("sqlalchemy") is None:
            return
        from sqlalchemy import event
        from sqlalchemy.engine import Engine
        event.listen(Engine, "before_cursor_execute", _sa_before)
        event.listen(Engine, "after_cursor_execute", _sa_after)
        event.listen(Engine, "handle_error", _sa_error)
        _hooked.add("sqlalchemy")
    except Exception as error:
        core.log("performance", "SQLAlchemy queries aren't timed:", error)


# ---- pymongo ----

# The part of a command that is its filter (sdk/protocols/queries.md).
MONGO_FILTER = {"find": "filter", "aggregate": "pipeline", "count": "query", "distinct": "query",
                "findAndModify": "query"}
MONGO_FIRST = {"delete": "deletes", "update": "updates"}


def _plain(value, depth=0):
    """A BSON value as JSON can hold it: only the shape matters, so any value
    JSON has no word for (an ObjectId, a date, NaN) is "?"."""
    if depth > 8:
        return "?"
    if isinstance(value, Mapping):
        return {str(k): _plain(v, depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(v, depth + 1) for v in value]
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float) and value == value and value not in (float("inf"), float("-inf")):
        return value
    return "?"


def mongo_text(command_name, command):
    """"<command> <collection> <filter as JSON>", as the normalizer takes it."""
    collection = command.get(command_name)
    # aggregate: 1 (a database's own pipeline) is named 1, as the other packages do.
    if isinstance(collection, int) and not isinstance(collection, bool):
        collection = str(collection)
    collection = collection if isinstance(collection, str) else ""
    found = None
    if command_name in MONGO_FILTER:
        found = command.get(MONGO_FILTER[command_name])
    elif command_name in MONGO_FIRST:
        items = command.get(MONGO_FIRST[command_name])
        if isinstance(items, (list, tuple)) and items and isinstance(items[0], Mapping):
            found = items[0].get("q")
    text = command_name + (" " + collection if collection else "")
    # With no collection the filter would be read as one, values and all.
    if found is not None and collection:
        text += " " + json.dumps(_plain(found), separators=(",", ":"), ensure_ascii=False)
    return text


def _watch_pymongo(core):
    if "pymongo" in _hooked:
        return
    try:
        if find_spec("pymongo") is None:
            return
        from pymongo import monitoring
    except Exception as error:
        core.log("performance", "pymongo queries aren't timed:", error)
        return

    started = {}

    class Listener(monitoring.CommandListener):
        def started(self, event):
            if event.command_name in MONGO_CHATTER or not _active():
                return
            if len(started) > 10000:  # ends that never came
                started.clear()
            try:
                started[(event.connection_id, event.request_id)] = mongo_text(event.command_name, event.command)
            except Exception:
                pass

        def succeeded(self, event):
            text = started.pop((event.connection_id, event.request_id), None)
            if text is not None:
                record("mongodb", text, event.duration_micros / 1000, False)

        def failed(self, event):
            text = started.pop((event.connection_id, event.request_id), None)
            if text is not None:
                record("mongodb", text, event.duration_micros / 1000, True)

    monitoring.register(Listener())
    _hooked.add("pymongo")


# ---- Any DB-API connection: watch_database(conn) ----

# By the driver's top-level module.
DRIVERS = {"sqlite3": "sqlite", "pysqlite2": "sqlite", "pysqlite3": "sqlite", "apsw": "sqlite",
           "psycopg": "postgresql", "psycopg2": "postgresql", "pg8000": "postgresql",
           "MySQLdb": "mysql", "pymysql": "mysql", "mysql": "mysql", "mariadb": "mariadb",
           "oracledb": "oracle", "cx_Oracle": "oracle", "pymssql": "mssql",
           "clickhouse_connect": "clickhouse", "clickhouse_driver": "clickhouse"}


def _text(sql, connection):
    """The statement as text: psycopg's sql.Composed and bytes too."""
    if isinstance(sql, str):
        return sql
    if isinstance(sql, (bytes, bytearray)):
        return bytes(sql).decode("utf-8", "replace")
    try:
        text = sql.as_string(connection)
        return text if isinstance(text, str) else _text(text, None)
    except Exception:
        return ""


class _Watched:
    """Everything not timed goes to the driver's own object."""

    def __init__(self, inner, db, style):
        object.__setattr__(self, "_inner", inner)
        object.__setattr__(self, "_db", db)
        object.__setattr__(self, "_style", style)

    def __getattr__(self, name):
        return getattr(self._inner, name)

    def __setattr__(self, name, value):
        setattr(self._inner, name, value)

    def __enter__(self):
        self._inner.__enter__()
        return self

    def __exit__(self, *exc):
        return self._inner.__exit__(*exc)

    def _run(self, call, sql, args, kwargs, connection):
        if _timing.get() or not _active():
            return call(sql, *args, **kwargs)

        def text():
            plain = _text(sql, connection)
            has_params = (args and args[0] is not None) or kwargs.get("params") is not None or kwargs.get("parameters") is not None
            return _percent_placeholders(plain) if self._style in ("format", "pyformat") and has_params else plain

        return _timed(self._db, text, call, (sql,) + tuple(args), kwargs, False)


class _Cursor(_Watched):
    def execute(self, sql, *args, **kwargs):
        result = self._run(self._inner.execute, sql, args, kwargs, getattr(self._inner, "connection", None))
        return self if result is self._inner else result

    def executemany(self, sql, *args, **kwargs):
        result = self._run(self._inner.executemany, sql, args, kwargs, getattr(self._inner, "connection", None))
        return self if result is self._inner else result

    def executescript(self, sql, *args, **kwargs):
        result = self._run(self._inner.executescript, sql, args, kwargs, None)
        return self if result is self._inner else result

    def __iter__(self):
        return iter(self._inner)

    def __next__(self):
        return next(self._inner)


class _Connection(_Watched):
    def cursor(self, *args, **kwargs):
        return _Cursor(self._inner.cursor(*args, **kwargs), self._db, self._style)

    def _cursor_of(self, result):
        # sqlite3's and psycopg's connection.execute() hand back a cursor.
        return _Cursor(result, self._db, self._style) if hasattr(result, "fetchone") and result is not self._inner else result

    def execute(self, sql, *args, **kwargs):
        return self._cursor_of(self._run(self._inner.execute, sql, args, kwargs, self._inner))

    def executemany(self, sql, *args, **kwargs):
        return self._cursor_of(self._run(self._inner.executemany, sql, args, kwargs, self._inner))

    def executescript(self, sql, *args, **kwargs):
        return self._cursor_of(self._run(self._inner.executescript, sql, args, kwargs, None))


# ---- ClickHouse clients: watch_database(client) ----

def _arg(args, kwargs, name, at=0):
    if name in kwargs:
        return kwargs[name]
    return args[at] if len(args) > at else None


def _clickhouse_sql(sql, params):
    """The statement as text; client-side %(name)s / %s parameters as "?"
    (server-side {name:Type} ones are names and stay)."""
    text = _text(sql, None) if sql is not None else ""
    return _percent_placeholders(text) if params is not None and text else text


class _ClickHouse(_Watched):
    """The client's own methods, each timed as one query until it answers.
    Only the object passed is wrapped: methods it calls on itself inside
    (query_df running a query) are the one query."""

    def _time(self, call, text, args, kwargs):
        if _timing.get() or not _active():
            return call(*args, **kwargs)
        # Marked as timed, so an HTTP client under it isn't an outgoing call.
        return _timed("clickhouse", text, call, args, kwargs, True)


class _ClickHouseConnect(_ClickHouse):
    """clickhouse-connect's client: query (and query_df, query_np,
    query_arrow, raw_query) reads its whole result before it returns, so the
    time is the result's too; command and the inserts until they answer. The
    streaming queries (query_*_stream) aren't timed."""

    def _query(self, name, args, kwargs, sql_name="query"):
        call = getattr(self._inner, name)
        return self._time(call, lambda: _clickhouse_sql(_arg(args, kwargs, sql_name), _arg(args, kwargs, "parameters", 1)),
                          args, kwargs)

    def _insert(self, name, args, kwargs, fmt):
        call = getattr(self._inner, name)

        def text():
            table = _arg(args, kwargs, "table")
            database = kwargs.get("database")
            if not isinstance(table, str) or not table:
                return ""
            return "INSERT INTO %s%s FORMAT %s" % (database + "." if isinstance(database, str) and database else "", table, fmt)

        return self._time(call, text, args, kwargs)

    def query(self, *args, **kwargs):
        return self._query("query", args, kwargs)

    def raw_query(self, *args, **kwargs):
        return self._query("raw_query", args, kwargs)

    def query_df(self, *args, **kwargs):
        return self._query("query_df", args, kwargs)

    def query_np(self, *args, **kwargs):
        return self._query("query_np", args, kwargs)

    def query_arrow(self, *args, **kwargs):
        return self._query("query_arrow", args, kwargs)

    def command(self, *args, **kwargs):
        return self._query("command", args, kwargs, "cmd")

    def insert(self, *args, **kwargs):
        return self._insert("insert", args, kwargs, "Native")

    def insert_df(self, *args, **kwargs):
        return self._insert("insert_df", args, kwargs, "Native")

    def insert_arrow(self, *args, **kwargs):
        return self._insert("insert_arrow", args, kwargs, "Arrow")


class _ClickHouseDriver(_ClickHouse):
    """clickhouse-driver's Client: execute (and query_dataframe,
    insert_dataframe) until it returns. execute_iter streams, and isn't timed."""

    def _run_sql(self, name, args, kwargs):
        call = getattr(self._inner, name)
        return self._time(call, lambda: _clickhouse_sql(_arg(args, kwargs, "query"), _arg(args, kwargs, "params", 1)),
                          args, kwargs)

    def execute(self, *args, **kwargs):
        return self._run_sql("execute", args, kwargs)

    def query_dataframe(self, *args, **kwargs):
        return self._run_sql("query_dataframe", args, kwargs)

    def insert_dataframe(self, *args, **kwargs):
        # Its second argument is the frame, not parameters.
        call = self._inner.insert_dataframe
        return self._time(call, lambda: _clickhouse_sql(_arg(args, kwargs, "query"), None), args, kwargs)


def _clickhouse_client(connection, root):
    """The ClickHouse client class to wrap connection in, or None for a
    DB-API connection (theirs have a cursor) or anything else."""
    if hasattr(connection, "cursor"):
        return None
    if root == "clickhouse_connect" and all(callable(getattr(connection, n, None)) for n in ("query", "command", "insert")):
        return _ClickHouseConnect
    if root == "clickhouse_driver" and callable(getattr(connection, "execute", None)):
        return _ClickHouseDriver
    return None


# ---- Redis clients: watch_database(client) (queries.md, "Redis") ----
# Each command is one query under db "redis": its name and its first key's
# shape (redis_command), never an argument. A pipeline or transaction is one,
# timed as a whole: "PIPELINE " or "MULTI " and its first command. Blocking
# commands (BLPOP, XREAD BLOCK) aren't timed. An error reply or no answer is
# a failure; a nil reply isn't, and nor is a transaction a WATCH called off.
#
# The client itself is watched, not wrapped: its own execute_command (every
# command goes through it) and pipeline() are replaced on that one object, so
# it stays the client you made and nothing else is changed.

_REDIS_MARK = "_analytics_platform_watched"
# What redis-py splits a command's first argument on ("CLIENT SETNAME").
_ASCII_SPACE = re.compile(r"[ \t\n\r\x0b\x0c]+")
# Not what names a batch: its framing, and a WATCH a cluster pipeline sends at once.
_REDIS_FRAMING = frozenset(("MULTI", "EXEC", "DISCARD", "WATCH", "UNWATCH"))


@contextmanager
def own_redis():
    """The package reading Redis for itself: a watched client leaves it out."""
    token = _own_redis.set(True)
    try:
        yield
    finally:
        _own_redis.reset(token)


def _redis_arg(value):
    """Bytes as text, as a key is read; a long value isn't a key worth
    decoding. Anything else as it is (a number makes "?")."""
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).decode("utf-8", "replace") if len(value) <= 1024 else None
    return value


def _redis_list(args):
    """The command as redis_command reads it: its first argument split into
    words, as redis-py does to send it, then the rest. The key is at most the
    third argument, so only the first few are taken, but all of XREAD's."""
    if not args:
        return None
    first = _redis_arg(args[0])
    head = [w for w in _ASCII_SPACE.split(first) if w] if isinstance(first, str) and _ASCII_SPACE.search(first) else [first]
    name = head[0] if head else ""
    end = len(args) if isinstance(name, str) and _upper(name) in ("XREAD", "XREADGROUP") else min(len(args), 5 - len(head))
    return head + [_redis_arg(args[i]) for i in range(1, end)]


def _redis_start(args):
    """The statement a command starting now is timed as, or None."""
    if _own_redis.get() or not _active():
        return None
    try:
        return redis_command(_redis_list(args))
    except Exception:
        return None


def _redis_failed(error):
    # EXEC answering nil: the transaction a WATCH called off.
    return error is not None and type(error).__name__ != "WatchError"


def _replies_failed(replies):
    """A pipeline run with raise_on_error=False hands its errors back."""
    return isinstance(replies, (list, tuple)) and any(isinstance(r, Exception) and _redis_failed(r) for r in replies)


def _redis_record(statement, started, error, replies=None):
    try:
        failed = _redis_failed(error) or _replies_failed(replies)
        record("redis", statement, (time.perf_counter() - started) * 1000, failed)
    except Exception:
        pass  # never in place of the command's own result or error


def _redis_timed(call, begin, batch=False):
    """call (sync or async) timed as the statement begin(args) gives, or run
    untimed when that's None. A batch's replies can hold its error replies."""
    if inspect.iscoroutinefunction(call):
        async def timed_async(*args, **kwargs):
            statement = begin(args)
            if statement is None:
                return await call(*args, **kwargs)
            started, error, result = time.perf_counter(), None, None
            try:
                result = await call(*args, **kwargs)
                return result
            except BaseException as raised:
                error = raised
                raise
            finally:
                _redis_record(statement, started, error, result if batch else None)
        return timed_async

    def timed(*args, **kwargs):
        statement = begin(args)
        if statement is None:
            return call(*args, **kwargs)
        started, error, result = time.perf_counter(), None, None
        try:
            result = call(*args, **kwargs)
            return result
        except BaseException as raised:
            error = raised
            raise
        finally:
            _redis_record(statement, started, error, result if batch else None)
    return timed


def _timed_batch(pipe, call, batch):
    """call, a pipeline's execute, timed as one call named by its first command."""
    def begin(_args):
        first, batch[0] = batch[0], None
        if first is None or _own_redis.get() or not _active():
            return None
        # transaction (sync), is_transaction (asyncio), _transaction (an asyncio
        # cluster's); a sync cluster's says so only by the strategy it runs.
        multi = any(getattr(pipe, name, False) is True
                    for name in ("transaction", "is_transaction", "_transaction", "explicit_transaction")) \
            or type(getattr(pipe, "_execution_strategy", None)).__name__ == "TransactionStrategy"
        return ("MULTI " if multi else "PIPELINE ") + first

    return _redis_timed(call, begin, batch=True)


def _watch_redis_pipeline(pipe):
    """A pipeline (or transaction) from a watched client: the commands queued
    name it, execute() times it. The ones a WATCH makes run at once (redis-py's
    immediate_execute_command) are timed on their own."""
    batch = [None]

    def note(args):
        if batch[0] is None:
            statement = _redis_start(args)
            if statement and statement.split(" ", 1)[0] not in _REDIS_FRAMING:
                batch[0] = statement

    immediate = getattr(pipe, "immediate_execute_command", None)
    staged = "pipeline_execute_command" if callable(immediate) and callable(getattr(pipe, "pipeline_execute_command", None)) \
        else "execute_command"
    queue = getattr(pipe, staged)

    def queued(*args, **options):
        note(args)
        return queue(*args, **options)

    setattr(pipe, staged, queued)
    if staged == "pipeline_execute_command":
        pipe.immediate_execute_command = _redis_timed(immediate, _redis_start)
    reset = getattr(pipe, "reset", None)
    if callable(reset):
        def reset_batch(*args, **kwargs):
            batch[0] = None
            return reset(*args, **kwargs)
        pipe.reset = reset_batch
    pipe.execute = _timed_batch(pipe, pipe.execute, batch)
    return pipe


def _watch_redis(client):
    """A redis-py client (sync or asyncio, Redis or RedisCluster), in place."""
    if getattr(client, _REDIS_MARK, False):
        return client
    client.execute_command = _redis_timed(client.execute_command, _redis_start)
    pipeline = getattr(client, "pipeline", None)
    if callable(pipeline):
        def watched_pipeline(*args, **kwargs):
            pipe = pipeline(*args, **kwargs)
            try:
                _watch_redis_pipeline(pipe)
            except Exception:
                pass  # its commands still run, untimed
            return pipe
        client.pipeline = watched_pipeline
    setattr(client, _REDIS_MARK, True)
    return client


def _is_redis_client(client):
    """redis-py's (or valkey-py's) Redis or RedisCluster, or a subclass of one."""
    if not callable(getattr(client, "execute_command", None)) or not callable(getattr(client, "pipeline", None)):
        return False
    return any(klass.__module__.split(".")[0] in ("redis", "valkey") for klass in type(client).__mro__)


def _making_watched(make):
    """make, a function that makes (or connects) a Redis client, made to
    hand back each client watched."""
    def make_watched(*args, **kwargs):
        client = make(*args, **kwargs)
        # Inside the app's cache call: a client we can't watch (a custom
        # CLIENT_CLASS's) is handed back as it is, never an error.
        try:
            if _is_redis_client(client):
                _watch_redis(client)
        except Exception:
            pass
        return client
    setattr(make_watched, _REDIS_MARK, True)
    return make_watched


def _watch_django_cache(cache):
    """A Django cache on Redis: Django's own RedisCache makes a client for each
    operation, so the clients it makes are watched as it makes them;
    django-redis keeps its clients, and those it has and connects are."""
    module = type(cache).__module__
    if module.startswith("django.core.cache.backends.redis"):
        inner = cache._cache
        if not getattr(inner._client, _REDIS_MARK, False):
            inner._client = _making_watched(inner._client)
        return True
    if module.startswith("django_redis"):
        inner = cache.client
        connect = getattr(inner, "connect", None)
        if not callable(connect) or getattr(connect, _REDIS_MARK, False):
            return callable(connect)
        inner.connect = _making_watched(connect)
        held = list(getattr(inner, "_clients", None) or []) + list((getattr(inner, "_serverdict", None) or {}).values())
        for client in held:
            if client is not None and _is_redis_client(client):
                _watch_redis(client)
        return True
    return False


def _watch_django_alias(cache):
    """Django keeps a cache object per thread: the one watched is this
    thread's. The others of its alias are watched as Django makes them."""
    try:
        from django.core.cache import caches
    except Exception:
        return
    try:
        alias = next((name for name in caches if caches[name] is cache), None)
        if alias is None:
            return
        aliases = getattr(caches, _REDIS_MARK, None)
        if aliases is None:
            create = caches.create_connection

            def create_watched(name, *args, **kwargs):
                made = create(name, *args, **kwargs)
                if name in aliases:
                    try:
                        _watch_django_cache(made)
                    except Exception:
                        pass  # that thread's cache still works, untimed
                return made
            aliases = set()
            caches.create_connection = create_watched
            setattr(caches, _REDIS_MARK, aliases)
        aliases.add(alias)
    except Exception:
        pass  # this thread's cache is still watched


def watch_database(connection, db=None):
    """A DB-API connection, a clickhouse-connect / clickhouse-driver client,
    a redis-py client or a Django cache on Redis, whose queries are timed:
    use what it returns in place of the connection (a Redis client or cache
    comes back as itself, watched). db: one of DATABASES (default: by its driver)."""
    if isinstance(connection, (_Connection, _ClickHouse)):
        return connection
    if _is_redis_client(connection):
        return _watch_redis(connection)
    if type(connection).__module__.startswith(("django.core.cache.backends.redis", "django_redis")):
        if _watch_django_cache(connection):
            _watch_django_alias(connection)
        return connection
    root = type(connection).__module__.split(".")[0]
    client = _clickhouse_client(connection, root)
    if client is not None:
        return client(connection, "clickhouse", "")
    db = database_of(db) if db is not None else DRIVERS.get(root, "other")
    module = sys.modules.get(root)
    # clickhouse-driver and clickhouse-connect keep DB-API's paramstyle in their dbapi module.
    style = getattr(module, "paramstyle", "") or getattr(sys.modules.get(root + ".dbapi"), "paramstyle", "")
    return _Connection(connection, db, style)
