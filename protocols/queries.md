# Queries protocol (v1)

What every server package reports about **the database queries the site's own
code runs**: per minute, per route and per query, how many ran, how many
failed, their total and slowest time and a count per time bucket. It is the
half of Server speed that says *why* a route is slow: `/checkout` takes 900 ms,
and 800 of them are one query, or forty small ones.

The dashboard shows it in Health → Server speed → Queries
(`backend/Sections/Analytics/health/serverQueries.js`). The collector side is
`expresscollect/Analytics/serverQueries.js`; the table is
`analytics.server_queries` (`clickhouse_worker/migrations/20261104_server_queries.sql`).
OpenTelemetry senders get the same rows from their database spans
(`expresscollect/Analytics/otlp/traces.js`).

**No values ever leave the customer's server.** Every literal in a query is
replaced by `?` in the package, before it is counted (below), and the collector
does it again on arrival. Bound parameters are never read at all.

## Endpoint

`POST /events/server-queries`, `Authorization: Bearer <secret>`, a `User-Agent`
naming the client and its version, like resources and posture:

```json
{
  "site_id": "<24 hex>",
  "server_name": "web-1",
  "runtime": "Node 26.13.0",
  "rows": [
    {
      "minute": "2026-11-04T10:15:00.000Z",
      "method": "GET",
      "route": "/products/:id",
      "db": "postgresql",
      "statement": "SELECT * FROM products WHERE id = $1",
      "count": 42,
      "errors": 0,
      "sum_ms": 310.4,
      "max_ms": 41.2,
      "buckets": [30, 8, 3, 1, 0, 0, 0, 0, 0, 0, 0, 0]
    }
  ]
}
```

- `server_name`, `runtime`: as the performance module sends them.
- `minute`: the minute the **request** finished, UTC, as ISO 8601.
- `method`, `route`: exactly what the performance module records for the request
  the query ran in, so the dashboard can join the two (queries per request,
  database share of a route's time). A query outside any request or job is
  `method: "JOB"`, `route: "(background)"`. Inside a background job it is the
  job's own `JOB` row's route.
- `db`: one of `postgresql`, `mysql`, `mariadb`, `sqlite`, `mssql`, `oracle`,
  `clickhouse`, `mongodb`, `redis`, `other`. Anything else is stored as `other`.
- `statement`: normalized (below), at most 1000 code points.
- `count`, `errors`: how many ran, how many of them threw.
- `sum_ms`, `max_ms`: rounded to 0.1 ms.
- `buckets`: the performance module's 12 buckets, same edges:
  `[5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000]` ms, the last one
  everything slower.

At most 500 rows a request; more go in further requests. Answers: `202`
stored (`enabled: false` when Server speed is off: nothing kept), `400`/`401`
refused, `429`/`503` with `Retry-After`. A package treats a failed send the way
its performance module does: dropped, or held (a bounded number of rows) and
resent with the next flush. Never an unbounded backlog in the customer's memory.

Drivers that write placeholders as `%s` or `%(name)s` (Python's `format` and
`pyformat` styles) turn them into `?` before normalizing, when parameters were
passed, so `IN (%s, %s)` collapses like any other list.

## Turning it on

Queries ride on the **performance** module switch in `GET /events/platform/config`:
with Server speed off, nothing is recorded. Each package also takes a
`queries: false` option (`queries=False`, `Queries = false`...) that keeps
Server speed and leaves queries out.

## Recording

1. **Time each query** through the database library's public hook (table at the
   end). Never patch a library's private code.
2. **Normalize it** (below). An empty result is not recorded.
3. **Add it to the request it ran in**: a small map per request, keyed by
   `db` + statement, holding count, errors, sum, max and buckets. A request
   that runs 10,000 queries costs what one running ten does. Past **50**
   distinct statements in one request, new ones go under `(other)`.
4. **When the request finishes** and the performance module knows its method and
   route, add the request's map into that minute's rows, keyed by
   `minute | method | route | db | statement`. Past **200** keys in a minute,
   new statements go under `(other)` (same method, route and db); past **300**
   nothing new is kept.
5. A query with no request around it is added straight into the minute's rows
   as `JOB` `(background)`.
6. **Flush** finished minutes every 60 seconds, as the performance module does,
   and everything on shutdown.

### Never count a query twice

When two layers can both report one query (an ORM on top of a driver), record
it at **one** layer. Each package documents which; where both hooks may be on,
the outer one marks the query as being timed (a flag in the request's context)
and the inner one skips it.

## Normalizing

`expresscollect/Analytics/queryText.js` is the reference;
[`query-cases.json`](query-cases.json) the cases every package must pass,
character for character. The rule, for any `db` but `mongodb`:

Scan left to right, building the output:

| Input | Output |
| --- | --- |
| `--` to end of line; `#` to end of line on `mysql`/`mariadb`; `/* … */` (or to the end) | one space |
| `'…'` (a doubled `''` escapes; so does a backslash on `mysql`, `mariadb`, `clickhouse` and `other`, but on `postgresql`, `sqlite`, `mssql` and `oracle` a backslash is a plain character, in strings and in `"…"`/`` `…` `` names alike, except in `postgresql`'s `E'…'`; unclosed runs to the end). On `mysql`/`mariadb` also `"…"` | `?`. A one-letter prefix `E N X B` (either case) right before the quote, not preceded by a letter, digit or `_`, is dropped with it |
| `"…"` (other databases) and `` `…` `` (same backslash rule) | copied unchanged: names |
| `$tag$…$tag$` or `$$…$$`, when the `$` does not follow a word character | `?` |
| a number (`0x1F`, `12`, `1.5`, `.5`, `1.`, `2e-3`) whose first character does not follow a word character | `?` |
| any run of whitespace | one space |
| anything else | itself |

A **word character** is ASCII `A-Z a-z 0-9 _ $ @ :`, so `table2`, `$1`, `@p1`
and `:1` are kept. Then:

1. A parenthesised list of only placeholders (`?`, `$1`, `:name`, `@p1`),
   comma-separated with optional spaces, becomes `(?)`: `IN (1, 2, 3)` and
   `VALUES ($1, $2)` alike.
2. Two or more `(?)` separated by commas become one `(?)`: a 500-row insert is
   one statement.
3. Trim. Cut to 1000 code points and trim again.

An unknown database (`other`) may or may not take a backslash as an escape,
and each reading leaks what the other hides. So when an `other` statement has
a backslash in it, it is shaped both ways (backslash escaping, backslash
plain); if the two results differ the statement is `(other)` (its timing kept,
its text left out), and if they agree that result is used.

### MongoDB

The package builds `"<command> <collection> <filter as JSON>"` and the
normalizer replaces every value in the JSON with `"?"`: keys stay, objects keep
their key order, an array whose items all come out the same is kept as one
item, and anything deeper than six levels is `"?"`. JSON is written compact
(no spaces), with non-ASCII characters as themselves. A filter that isn't
valid JSON is dropped, leaving `"<command> <collection>"`.

The filter is the command's `filter` (`find`), `pipeline` (`aggregate`),
`query` (`count`, `distinct`, `findAndModify`), or the first item's `q`
(`delete`, `update`). Other commands send `"<command> <collection>"` only.
Connection chatter is never recorded: `hello`, `isMaster`, `ismaster`, `ping`,
`buildInfo`, `saslStart`, `saslContinue`, `getMore`, `endSessions`,
`killCursors`, `getLastError`.

### Redis

The package hands the command as the client sends it (`["SET",
"session:abc123", "<value>", "EX", "60"]`) to `redisCommand` and records what
comes back: the command name, upper-cased (ASCII only), and the shape of its
first key, never an argument or a value. `SET session:?`.

- A key keeps each `:`-separated segment that is only ASCII letters and `_`,
  at most 32 of them; every other segment becomes `?`. So an ID, slug, email,
  hash or token never leaves the server: `user:42:cart` → `user:?:cart`,
  `profile:bob@x.com` → `profile:?`, `cache:views:my-post` → `cache:views:?`.
  A key that isn't a string, or is empty, is `?`. A segment of letters only
  is kept, so a letters-only name in a key (`user:alice`) does leave the server.
- Which argument is the key: the first, except script calls (`EVAL`,
  `EVALSHA`, `FCALL` and their `_RO` forms: the first key after the key
  count, none when it's 0), `ZUNION`-style commands with a key count first,
  `BITOP` (the destination), `XREAD`/`XREADGROUP` (after the first `STREAMS`
  among the options; `BLOCK` is looked for only there), and
  `OBJECT`/`MEMORY`/`XGROUP`/`XINFO` (after the subcommand). A command with
  a subcommand keeps it (`CLIENT SETNAME`, `CONFIG SET`). Commands whose
  argument is a password, a message or a number have no key: `AUTH`,
  `HELLO`, `ECHO`, `SELECT`, `PING`, `SCAN`, `INFO` and the rest of
  `REDIS_NO_KEY` in `queryText.js`. Several keys: the first one's shape.
- **Not timed at all** (`redisCommand` gives null): commands that wait
  rather than work, so an idle queue worker would top the slow list —
  `BLPOP`, `BRPOP`, `BRPOPLPUSH`, `BLMOVE`, `BLMPOP`, `BZPOPMIN`,
  `BZPOPMAX`, `BZMPOP`, `XREAD`/`XREADGROUP` with `BLOCK`, `WAIT`,
  `WAITAOF`, the `SUBSCRIBE` family and `MONITOR`. Nor the package's own
  queue-depth reads (`queues.md`).
- A pipeline is one call, `PIPELINE <its first timed command>`, timed as a
  whole; a transaction sent as one unit is `MULTI <…>`. A hook that only sees
  commands one at a time records each.
- An error is an error reply (`WRONGTYPE`, `OOM`, `NOSCRIPT`…) or no answer.
  A nil reply, and a cluster's `MOVED`/`ASK`, are not.
- On arrival the collector accepts only `[PIPELINE|MULTI] COMMAND
  [SUBCOMMAND] [key]` and shapes the key again; anything more (an argument a
  package let through) is stored as `(other)`.

Shared cases: `query-cases.json` has text cases with `db: "redis"`, and
`redis_commands` (`args` → `expected`, null meaning not timed) for
`redisCommand`. OTLP spans with `db.system` `redis` are split on spaces and
go through the same `redisCommand`.

## Hooks per package

| Package | Caught by | Setup |
| --- | --- | --- |
| Node | `platform.watchDatabase(x)`: a `pg` Pool/Client, `mysql2` pool/connection, `mongodb` MongoClient (Mongoose's `mongoose.connection.getClient()`), knex, a Prisma client (model calls, e.g. `User.findMany`, not SQL), a `@clickhouse/client` client (`query`, `insert`, `command`, `exec`; a query is timed until its result is read) | one line |
| Python | Django: a wrapper added to every connection's `execute_wrappers` on `connection_created`. SQLAlchemy: listeners on the `Engine` class. pymongo: a global `monitoring.register` listener. `watch_database(conn)` for others. ClickHouse: `watch_database(client)` for a clickhouse-connect client or a clickhouse-driver `Client` | automatic, or one line |
| PHP (Laravel) | `DB::listen` | automatic |
| PHP (Symfony) | a Doctrine DBAL middleware (`doctrine.middleware` tag) | services.yaml |
| PHP (plain) | `new TimedPdo(...)` instead of `new PDO(...)`; the mongodb extension's global `addSubscriber`; `new TimedClickHouse($client)` for smi2/phpclickhouse | one line |
| WordPress | a `wp-content/db.php` drop-in subclassing `wpdb`; when that can't be written or another drop-in is there, `SAVEQUERIES` defined at plugin load (misses queries before plugins load) | automatic |
| Ruby | Rails: `sql.active_record` (leaving out `SCHEMA` and `CACHE`). clickhouse-activerecord is labelled `clickhouse`. Sequel: `SiteGoose.watch_database(DB)`. ClickHouse (`click_house` gem): `SiteGoose.watch_database(conn)`. Mongo: a global `Mongo::Monitoring` subscriber | automatic, or one line |
| Java | Spring Boot: a bean post-processor wrapping every `DataSource` bean. Plain JDBC: `platform.wrap(dataSource)`. ClickHouse's JDBC driver (`jdbc:clickhouse:`, `jdbc:ch:`) through the same wrapper; client-v2 has no hook and isn't timed. Mongo: `platform.mongoListener()` in `MongoClientSettings` (Spring Boot: a settings customizer bean) | automatic, or one line |
| .NET | `DiagnosticListener` (`SqlClientDiagnosticListener`) and `ActivitySource` (`Npgsql`, `MySqlConnector`, `ClickHouse.Client`/`ClickHouse.Driver`); EF Core's listener only for providers that publish nothing (SQLite). Mongo: `platform.WatchMongo(settings)` | automatic, or one line |
| Go | `platform.OpenDB(driverName, dsn)` / `p.WrapConnector(c)` / `p.WrapDriver(d)` for `database/sql`; `sitegoosepgx.Tracer(p)` for pgx v5, `sitegoosemongo.Monitor(p)` for the Mongo driver v2 and `sitegooseclickhouse.Wrap(p, conn)` for clickhouse-go's native API (its `database/sql` driver needs nothing), each a module of its own (`/pgx`, `/mongo`, `/clickhouse`) so the package stays standard library only. The request is found from the `ctx` a query is given | one line |
| OpenTelemetry | the collector maps `CLIENT` spans with `db.system`/`db.system.name` and `db.query.text`/`db.statement` | nothing |

Redis (`db: "redis"`, rules above):

| Package | Caught by | Setup |
| --- | --- | --- |
| Node | `platform.watchDatabase(client)` on an ioredis `Redis`/`Cluster` or a node-redis 4–6 client (its `sendCommand`, `pipeline()`/`multi()` on that instance). With ioredis `enableAutoPipelining` each command is timed on its own, a `pipeline()` too. Not node-redis cluster, pool or sentinel; on node-redis 4 `eval` shows no key | one line |
| Python | `platform.watch_database(client)` on a redis-py (or valkey-py) `Redis`/`RedisCluster`, sync or asyncio, with its pipelines; `watch_database(caches["default"])` for Django's `RedisCache` and django-redis | one line |
| PHP (Laravel) | `Redis::enableEvents()` + `CommandExecuted`; failures only from Laravel 12 (`CommandFailed`), and phpredis's error replies aren't seen. A phpredis pipeline isn't announced at all; a Predis one is a bare `PIPELINE` | automatic |
| PHP (plain) | `new TimedRedis(new \Redis())` (also `\RedisCluster`), `new TimedPredis(new Predis\Client())` | one line |
| WordPress | none: object-cache drop-ins have no command hook. The agent's database view covers the server's Redis | — |
| Ruby | `RedisClient.register` middleware (redis-client, so the `redis` gem 5 too; not gem 4). Global, so Sidekiq's non-blocking commands are counted; its queue-depth reads aren't | automatic |
| Java | Lettuce 6.1+ `CommandListener`: `redisClient.addListener(platform.redisListener())`; Spring Boot adds it to the `LettuceConnectionFactory`. Each command on its own (no pipeline boundary). Not Jedis | automatic in Spring Boot, else one line |
| .NET | StackExchange.Redis `RegisterProfiler`: `platform.WatchRedis(multiplexer)`. **Command names only** (the profiler has no key) and never failed (it doesn't say how a command ended); replaces a profiler the app registered; batches only on library versions after 2.8.16 | one line |
| Go | `client.AddHook(sitegooseredis.Hook(p))` (submodule `redis/`, go-redis v9: `Client`, `ClusterClient`, `Ring`, `UniversalClient`); other clients call `p.RecordRedis` | one line |
| OpenTelemetry | `CLIENT` spans with `db.system` `redis`, split on spaces into `redisCommand` | automatic |
