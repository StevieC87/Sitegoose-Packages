# Queues protocol (v1)

What a server package or the server agent reports about **the site's job
queues**: per minute and queue, how many jobs are waiting, running, delayed
and failed, how long the oldest waiting job has waited, and how many jobs were
added and finished. Jobs piling up is the bottleneck Server speed's request
timings can't show: every request is quick, and the emails go out an hour late.

The dashboard shows it in Health → Server speed → Jobs
(`backend/Sections/Analytics/health/serverQueues.js`), above the job timings
`platform.job()` already sends. The collector side is
`expresscollect/Analytics/serverQueues.js`; the table is
`analytics.server_queues` (`clickhouse_worker/migrations/20261104_server_queues.sql`).

## Endpoint

`POST /events/server-queues`, `Authorization: Bearer <secret>`, a `User-Agent`
naming the client and its version:

```json
{
  "site_id": "<24 hex>",
  "server_name": "worker-1",
  "runtime": "Node 26.13.0",
  "rows": [
    {
      "minute": "2026-11-04T10:15:00.000Z",
      "system": "bullmq",
      "broker": "127.0.0.1:6379/0",
      "queue": "emails",
      "waiting": 1240,
      "running": 4,
      "delayed": 12,
      "failed": 3,
      "oldest_s": 610,
      "added": 220,
      "finished": 180,
      "shared": false
    }
  ]
}
```

- `minute`: the minute the reading was taken, UTC, ISO 8601.
- `system`: `bullmq`, `bull`, `sidekiq`, `laravel`, `celery`, `rq`, `hangfire`,
  `asynq`, `rabbitmq`, or `other`. Anything else is stored as `other`.
- `broker`: where the queue lives, so two queues of one name on two brokers
  stay two: host, port and database (`127.0.0.1:6379/0`), a RabbitMQ
  management address's host and port. **Never a user name or password.** At
  most 200 characters.
- `queue`: the queue's name (a RabbitMQ queue outside the default vhost is
  `vhost/name`). At most 200 characters.
- `waiting`, `running`, `delayed`, `failed`: **gauges**, what the queue holds
  at the reading. `failed` is the jobs kept as failed (BullMQ's failed set,
  Sidekiq's dead set), not a count of failures this minute. `null` where the
  system can't say (RabbitMQ has no delayed or failed jobs).
- `oldest_s`: seconds the oldest waiting job has waited; `null` where unknown,
  `0` with nothing waiting.
- `added`, `finished`: **counters** for this minute. A finished job is one that
  left the queue, done or failed for good: an attempt that will be retried
  isn't one. `null` where unknown.
- `shared`: `false` when `added` and `finished` are this process's own counts
  (each process counts the jobs it added or ran; the readers add them up);
  `true` when they are the broker's for the whole queue, which every reporter
  reads alike (the readers take one).

- `sender` (top level, optional): a random id per process, made when it
  starts. A request resent after a failed answer (the same `sender`,
  `server_name` and rows, up to two days later) is stored once, and one sent
  again while the first is still being stored is answered `503`. Without a
  `sender` nothing is held back: two processes on one machine that read the
  same counts in a minute can't be told from a resend. Up to 64 letters,
  digits, `-` or `_`.

At most 500 rows a request. Answers as `queries.md`: `202` stored
(`enabled: false` when Server speed is off), `400`/`401` refused, `429`/`503`
with `Retry-After`.

## Reading one queue from several places

A queue is read by every process watching it: three web servers adding jobs
and two workers running them is five readers of one queue. Gauges are the
same for all of them, so the readers take the **largest** reading per minute,
system, broker and queue; never the sum. Own counters are summed; shared ones
are taken once (the largest).

## Turning it on

Queues ride on the **performance** module switch. Each package takes a
`queues: false` option that keeps Server speed and leaves queues out.

## Sources

| Source | Gauges | Counters | Setup |
| --- | --- | --- | --- |
| Node, BullMQ (and Bull) | `queue.getJobCounts()`; the oldest waiting job's `timestamp` | own: the `Queue`'s `waiting` event and BullMQ's `addBulk` (added; a `FlowProducer`'s jobs aren't counted), a `Worker`'s `completed` event and its `failed` event on a job's last attempt (`finishedOn` set) (finished) | `platform.watchQueue(queue)`, and `platform.watchQueue(worker)` where jobs run |
| Python, Celery (Redis broker) | `LLEN` of each queue's list and its priority lists (kombu's names, `global_keyprefix`): waiting only; `oldest_s` 0 when empty, else unknown. A RabbitMQ broker sends nothing: the agent reads it | own: `after_task_publish` by routing key (added); `task_postrun` in SUCCESS/FAILURE/IGNORED/REJECTED (finished, once the process runs tasks) | `platform.watch_queue(app)` |
| Python, RQ | `LLEN` of the queue; `ZCARD` of the started (running), scheduled + deferred (delayed) and failed registries; the first job's `enqueued_at` | own: finished in `platform.rq_worker()`'s `execute_job`; added unknown (RQ has no enqueue hook) | `platform.watch_queue(queue)` |
| PHP, Laravel | `queue:work`'s `Looping` event, once a minute: `pendingSize`/`delayedSize`/`reservedSize`/`creationTimeOfOldestPendingJob` where the queue has them, else `size()`; failed from the failed-job store's `count()`. `queue:work --once` and `queue:listen` don't loop, so they read nothing | own: `JobQueued` (added, every process), `JobProcessed` when neither released nor failed, and `JobFailed` (finished, the worker; a job that failed itself counts once) | automatic; `ANALYTICS_WATCH_QUEUES` for more queues |
| Ruby, Sidekiq | `sidekiq/api` per queue: `Queue#size` (waiting), `#latency` (oldest), `WorkSet` (running), `ScheduledSet` + `RetrySet` (delayed), `DeadSet` (failed); one Sidekiq process reads a minute; with several queues, a set over 1,000 jobs is left out rather than read | own: a client middleware (added, once a job: it marks the job `sitegoose_added`, so the scheduler, a retry or the Web UI pushing it back isn't counted again) and the server middleware plus death handler (finished) | `SiteGoose::Sidekiq.install` |
| .NET, Hangfire | `IMonitoringApi`: `EnqueuedCount` per queue (waiting), the first enqueued job's `EnqueuedAt` (oldest); `ProcessingCount`, `ScheduledCount`, `FailedCount` are the whole storage's, on a `(all queues)` row | shared: succeeded + deleted + failed-for-good deltas (finished); added unknown | `platform.WatchHangfire(JobStorage.Current)` |
| Go, asynq | `Inspector.Queues()` + `GetQueueInfo`: Pending (waiting), Active (running), Scheduled + Retry + Aggregating (delayed), Archived (failed), Latency (oldest) | shared: the running `ProcessedTotal` − `FailedTotal` deltas (the day's `Processed` − `Failed` from workers older than asynq 0.24) plus Archived growth (finished); added unknown | `sitegooseasynq.Watch(p, inspector, redisOpt)` |
| Agent, RabbitMQ | the management API's `/api/queues`: `messages_ready` (waiting), `messages_unacknowledged` (running), `head_message_timestamp` (oldest, when publishers set a timestamp) | shared: `message_stats.publish` and `message_stats.ack` deltas | `"queues": [{"rabbitmq": "http://user:pass@127.0.0.1:15672"}]` in the agent's config |

Readings are taken once a minute. A reading that fails sends nothing for that
minute: a gap, never a zero, since zero waiting is good news. Java has no
reader: it has no job library most apps share.
