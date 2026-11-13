"""Celery: every task runs as a platform.job() named after the task. Its
errors carry "/(job) <task name>" as their route, a task that raises is sent
(status 500), and each run is timed (Health -> Server speed -> Jobs).

    app = Celery("shop", broker=...)
    platform.init_celery(app)

A retry times its run as failed but sends nothing: the error is sent when
the last attempt fails, not once per attempt. Ignore (a task replaced by
another) counts as done, Reject as failed. A run cut short (SystemExit,
KeyboardInterrupt, its hard time limit, the worker stopping) is timed as
failed and not sent: the main process sends a time limit's error. One
killed outright (SIGKILL, out of memory) isn't timed: nothing of it is left
to say how long it ran. What's waiting is sent when a worker process ends
(prefork children leave through os._exit, which skips atexit), when the
worker stops, and at exit.
"""
import atexit
import contextvars
import sys

from celery import signals

from . import _Job

# The run's status by the state Celery ended it in. None: cut short by
# SystemExit, KeyboardInterrupt or the worker stopping it, which is how a
# pool process ends a task past its hard time limit (SIGTERM).
STATUS = {"SUCCESS": 200, "IGNORED": 200, "FAILURE": 500, "RETRY": 500, "REJECTED": 500, None: 500}


_at_exit = set()


def _name(task):
    return getattr(task, "name", None) or "task"


def connect(platform, app=None):
    # The run this thread (or task) is in: (task id, its job, the run it
    # started inside, for an eager task called from another). Not a dict by task id: a retry keeps its
    # id, and another thread can start it before the first run has ended.
    running = contextvars.ContextVar("analytics_platform_celery_%d" % id(platform), default=None)
    uid = "analytics_platform_celery_%d_%d" % (id(platform), id(app))

    def ours(task):
        return task is not None and (app is None or getattr(task, "app", None) is app)

    def started(sender=None, task_id=None, task=None, **_):
        task = task or sender
        if ours(task):
            job = _Job(platform, _name(task))
            job.__enter__()
            running.set((task_id, job, running.get()))

    def failed(sender=None, exception=None, **_):
        if not ours(sender) or not isinstance(exception, Exception):
            return
        # Celery sends a copy it can pickle when the exception can't be. The
        # one being handled is the task's own: grouped by its own type, and
        # sent once if your code captured it too.
        handled = sys.exc_info()[1]
        if isinstance(handled, Exception) and type(exception).__name__ == "UnpickleableExceptionWrapper":
            exception = handled
        # Still inside the run, so the error keeps the task's trail.
        platform.capture_exception(exception, status=500, kind="error", request=_Job(platform, _name(sender))._fields())

    def finished(sender=None, task_id=None, state=None, **_):
        run = running.get()
        if run is None or run[0] != task_id:
            return
        _, job, outer = run
        running.set(outer)
        try:
            job._leave(STATUS.get(state))
        except Exception as error:
            platform.core.log("celery", "could not time a task:", error)

    def flush(**_):
        platform.flush_before_exit()  # the process is ending

    signals.task_prerun.connect(started, weak=False, dispatch_uid=uid)
    signals.task_failure.connect(failed, weak=False, dispatch_uid=uid)
    signals.task_postrun.connect(finished, weak=False, dispatch_uid=uid)
    signals.worker_process_shutdown.connect(flush, weak=False, dispatch_uid=uid)
    signals.worker_shutdown.connect(flush, weak=False, dispatch_uid=uid)
    # A cold shutdown of the eventlet pool skips worker_shutdown; at exit,
    # before the background threads are stopped (atexit runs last first).
    if uid not in _at_exit:
        _at_exit.add(uid)
        atexit.register(flush)


# ---- Queue backlog (sdk/protocols/queues.md): platform.watch_queue(app) ----

# Finished for good: a retry goes back to the broker and isn't.
FINISHED = frozenset(("SUCCESS", "FAILURE", "IGNORED", "REJECTED"))
# kombu's Redis transport: a queue is a list named after it, and one more per
# priority step past 0 (name + sep + step).
PRIORITY_STEPS = (0, 3, 6, 9)
PRIORITY_SEP = "\x06\x16"
READ_TIMEOUT = 5


def _broker_url(app):
    url = app.conf.broker_url or ""
    if isinstance(url, (list, tuple)):
        url = url[0] if url else ""
    return str(url).split(";")[0].strip()


def _redis_client(url):
    """A redis-py client of its own for a redis://, rediss:// or socket
    broker URL; None for any other broker (RabbitMQ: the agent reads it)."""
    scheme = url.split("://", 1)[0].lower() if "://" in url else ""
    if scheme == "redis+socket":
        url = "unix://" + url.split("://", 1)[1]
    elif scheme not in ("redis", "rediss", "unix"):
        return None
    import redis
    return redis.Redis.from_url(url, socket_timeout=READ_TIMEOUT, socket_connect_timeout=READ_TIMEOUT)


def _queue_names(app, names):
    if names:
        return [str(n) for n in names]
    try:
        found = list(app.amqp.queues.keys())
    except Exception:
        found = []
    return found or [app.conf.task_default_queue or "celery"]


def _route_of(delivery_info):
    if not isinstance(delivery_info, dict):
        return None
    return delivery_info.get("routing_key") or None


def watch_queues(queues, app, names=None):
    """The app's queues (names, default its configured ones) read from a
    Redis broker every minute, and this process's published and finished
    tasks counted. With any other broker nothing is watched."""
    url = _broker_url(app)
    client = _redis_client(url)
    if client is None:
        queues.core.log("performance", "watch_queue: the Celery broker isn't Redis; nothing is read "
                                       "(the server agent reads RabbitMQ)")
        return
    from .queues import redis_broker
    broker = redis_broker(client.connection_pool.connection_kwargs)
    options = app.conf.broker_transport_options or {}
    prefix = str(options.get("global_keyprefix") or "")
    steps = options.get("priority_steps") or PRIORITY_STEPS
    sep = options.get("sep") or PRIORITY_SEP

    def reader(name):
        keys = [prefix + name + (sep + str(step) if step else "") for step in steps]

        def read():
            pipe = client.pipeline(transaction=False)
            for key in keys:
                pipe.llen(key)
            waiting = sum(int(n or 0) for n in pipe.execute())
            # A message carries no time it was sent: how long the oldest has
            # waited is unknown, except that nothing waits.
            return {"waiting": waiting, "oldest_s": 0} if waiting == 0 else {"waiting": waiting}

        return read

    entries = {}
    for name in _queue_names(app, names):
        entry = queues.entry("celery", broker, name, reader(name))
        if entry is not None:
            entry.counts_added = True
            entries[name] = entry
    if not entries:
        return
    # Finished is counted where tasks run: a worker, its pool processes, or
    # wherever a task first runs.
    def runs_tasks(**_):
        for entry in entries.values():
            entry.counts_finished = True

    def published(sender=None, routing_key=None, **_):
        queues.count(entries.get(routing_key), added=1)

    def ran(sender=None, state=None, task=None, **_):
        task = task or sender
        if state in FINISHED:
            request = getattr(task, "request", None)
            queues.count(entries.get(_route_of(getattr(request, "delivery_info", None))), finished=1)

    uid = "analytics_platform_queues_%d_%d" % (id(queues), id(app))
    signals.after_task_publish.connect(published, weak=False, dispatch_uid=uid)
    signals.task_postrun.connect(ran, weak=False, dispatch_uid=uid)
    signals.task_prerun.connect(runs_tasks, weak=False, dispatch_uid=uid)
    signals.worker_init.connect(runs_tasks, weak=False, dispatch_uid=uid)
    signals.worker_process_init.connect(runs_tasks, weak=False, dispatch_uid=uid)
