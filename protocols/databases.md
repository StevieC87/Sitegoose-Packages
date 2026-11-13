# Databases protocol (v1)

What the server agent reports about **the databases on its machine, as the
database itself sees them**: which statements cost the most time, how many
rows each reads to return how many, which tables are read end to end for want
of an index, and how full the database is (connections, lock waits, the
longest-running query). The packages time queries from the app's side
(`queries.md`): they can say a query is slow, but only the database can say it
read 2 million rows to return 10.

The dashboard shows it in Health → Server speed → Database, below the app's
own queries (`backend/Sections/Analytics/health/serverDatabases.js`). The
collector side is `expresscollect/Analytics/serverDatabases.js`; the tables are
`analytics.server_db_health`, `server_db_statements` and `server_db_tables`
(`clickhouse_worker/migrations/20261104_server_databases.sql`, Redis's two columns in `20261107_server_db_redis.sql`).

**Read-only, and no values.** The agent only runs `SELECT`s on the database's
own statistics (Redis: `INFO` and `SLOWLOG GET`); it never changes a setting, never installs an extension and
never turns a profiler on. Every statement is normalized by the agent with the
rules of `queries.md` (the databases' own texts are already normalized, but not
always fully) and again by the collector.

## Endpoint

`POST /events/server-databases`, `Authorization: Bearer <secret>`, from the
agent (`sdk/vps-agent`):

```json
{
  "site_id": "<24 hex>",
  "server_name": "db-1",
  "runtime": "agent 0.7.0",
  "databases": [
    {
      "minute": "2026-11-04T10:15:00.000Z",
      "db": "postgresql",
      "instance": "127.0.0.1:5432",
      "version": "16.4",
      "health": {
        "connections": 42, "max_connections": 100, "running": 3, "waiting": 0,
        "longest_s": 2.4, "cache_hit_pct": 99.2
      },
      "statements": [
        {
          "database": "shop", "statement": "SELECT * FROM orders WHERE customer_id = $1",
          "calls": 1200, "errors": 0, "total_ms": 5400.2, "rows_read": null,
          "rows_returned": 1180, "bytes_read": 48234496, "peak_memory_mb": null, "no_index": 0
        }
      ],
      "tables": [
        { "database": "shop", "table": "public.orders", "full_scans": 340, "rows_scanned": 68000000, "index_scans": 12, "rows": 200000 }
      ],
      "notes": []
    }
  ]
}
```

- `db`: `postgresql`, `mysql`, `mariadb`, `clickhouse`, `mongodb` or `redis`
  (Valkey and KeyDB too, with their own version).
- `instance`: which server of that kind, as the agent reached it: host and port,
  or the socket's name. Never a user name or password. At most 100 characters.
- `version`: the server's version, at most 32 characters.
- `health`: **gauges** at the reading; any of them `null` (or absent) where the
  database can't say:
  - `connections` / `max_connections`: in use and allowed.
  - `running`: queries running now. `waiting`: of them, the ones waiting on a lock.
  - `longest_s`: how long the longest-running query has run. Redis: its
    slowest command since the last reading, from the slow log (to the
    millisecond; 0 when nothing new reached the log).
  - `cache_hit_pct`: reads served from memory since the last reading (PostgreSQL's
    buffer cache, InnoDB's buffer pool). Redis: lookups that found their key
    (`keyspace_hits` of hits and misses), `null` when there were none.
  - `memory_mb`: memory the server is using (ClickHouse, MongoDB, Redis).
  - `memory_limit_mb`: the memory it may use (Redis's `maxmemory`, `null` when
    none is set; ClickHouse's own ceiling, `max_server_memory_usage_to_ram_ratio`
    of the machine's or container's memory, lowered by a smaller
    `max_server_memory_usage`, as the server works it out at start-up).
  - `evicted`: a **count since the last reading**, not a gauge: keys Redis
    dropped to stay under `maxmemory`.
  - `parts_max`, `merges`: ClickHouse's most parts in one partition, and merges running.
- `statements`: **counters since the last reading**, per database and statement,
  at most 100, the most time first:
  - `calls`, `errors`, `total_ms`. Redis: one per command, by its name
    (`GET`, `CLIENT SETNAME`) with `database` `""`; `errors` are its failed
    and rejected calls.
  - `rows_read`: rows the database read to answer (MySQL's rows examined,
    ClickHouse's read rows, MongoDB's documents examined). `rows_returned`:
    rows it sent back.
  - `bytes_read`: PostgreSQL's blocks touched × 8 KiB; ClickHouse's bytes read.
  - `peak_memory_mb`: the most memory one run took (ClickHouse).
  - `no_index`: runs that used no index (MySQL's `no_index_used`, MongoDB's
    `COLLSCAN`).
  - `null` where the database doesn't count it.
- `tables`: **counters since the last reading**, at most 50, the most rows
  scanned first: `full_scans` (reads of the whole table), `rows_scanned` (rows
  those reads went through), `index_scans`; `rows` is a gauge, the table's size.
  PostgreSQL and MySQL only. MySQL counts the rows read with no index but not
  how many reads those were, so its `full_scans` and `index_scans` are `null`;
  a table row needs `full_scans` or `rows_scanned` above 0.
- `notes`: what the agent couldn't read, as codes the dashboard explains:
  `no_pg_stat_statements`, `no_performance_schema`, `profiler_off`, `no_query_log`,
  `no_access`. Redis: `no_access` when `INFO` or `SLOWLOG` is refused; with
  only `SLOWLOG` refused the rest is still read and `longest_s` is `null`.

A database's **first reading** sends health and notes only: counters need a
reading before them to subtract. A counter that went down (statistics reset, a
restart) starts again from that reading. Redis's restart is its `run_id`
changing, a `CONFIG RESETSTAT` its `total_commands_processed` going down:
either way that reading sends no statements, `evicted` or hit rate.

At most 20 databases a request. Answers as `queries.md`: `202` stored
(`enabled: false` when Server speed is off: nothing kept, and the agent asks
less often), `400`/`401` refused, `429`/`503` with `Retry-After`.

## Turning it on

Databases ride on the **performance** module switch. On the agent's side, the
databases to read are listed in its config file, never set from the
dashboard (as with `services.md`):

```json
"databases": [
  {"postgresql": "local"},
  {"mysql": "local"},
  {"clickhouse": "http://agent:secret@127.0.0.1:8123"},
  {"mongodb": "mongodb://127.0.0.1:27017"},
  {"redis": "local"}
]
```

`"local"` reaches the database the way its own tools do as root on that
machine: `runuser -u postgres -- psql` (peer authentication) and `mysql` over
its socket (`auth_socket`); Redis's socket (`/run/redis/redis-server.sock` or
`/var/run/redis/redis.sock`), else `127.0.0.1:6379`. Otherwise a connection
string: for Redis `redis://[user:pass@]host:port`, `rediss://` (TLS) or
`unix:///path`. The config file is readable by root only, and a password
never leaves it: not in `instance`, a log line or an error.

## Sources

| Database | Read with | Statements | Tables | Health |
| --- | --- | --- | --- | --- |
| PostgreSQL 10+ | `psql` | `pg_stat_statements`, when the extension is installed in the `postgres` database (`no_pg_stat_statements` otherwise) | `pg_stat_user_tables` of every database | `pg_stat_activity`, `pg_stat_database`, `max_connections` |
| MySQL 8 / MariaDB 10.5+ | `mysql` | `performance_schema.events_statements_summary_by_digest` (`no_performance_schema` when it's off) | `performance_schema.table_io_waits_summary_by_index_usage`, full scans being reads with no index | `Threads_connected`, `Threads_running`, `max_connections`, the processlist, the InnoDB buffer pool |
| ClickHouse 23.3+ | its HTTP interface, as a user with `SELECT` on `system.*` (no settings are sent, so a read-only user works) | `system.query_log` since the last reading, by `normalized_query_hash`; the agent's own queries left out | — | `system.metrics`, `system.server_settings`, `system.asynchronous_metrics` (`OSMemoryTotal`, `CGroupMemoryTotal`, for the memory limit), `system.parts`, `system.merges`, `system.processes` |
| MongoDB | `mongosh` | `system.profile` since the last reading, per database, when the profiler is already on (`profiler_off` otherwise) | — | `serverStatus` (`connections`, `mem`), `currentOp` |
| Redis 2.8+, Valkey, KeyDB | the agent itself, over its socket (RESP2): `AUTH` when there is a password, `INFO all`, `SLOWLOG GET 128`; nothing else, not even `CLIENT SETNAME`. An ACL user needs `+info +slowlog` | `INFO commandstats`, changes since the last reading; failed and rejected calls from 6.2. Commands that wait (`BLPOP`, `SUBSCRIBE`… as `queries.md` leaves out) and the agent's own (`INFO`, `SLOWLOG`, `AUTH`, `PING`, `HELLO`) are left out | — | `connected_clients`, `maxclients`, `used_memory`, `maxmemory`, `evicted_keys`, `keyspace_hits`/`misses`; the slow log's entries newer than the last one seen, of which only the duration is read, never the arguments, client address or name. `running`/`waiting` are `null`: `blocked_clients` are workers waiting for a job, not on a lock |

The agent reads once a minute, with a timeout of a few seconds per database;
one that doesn't answer is skipped for that minute.
