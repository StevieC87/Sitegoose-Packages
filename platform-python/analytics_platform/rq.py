"""RQ: a worker class whose jobs each run as a platform.job() named after
the job's function. Its errors carry "/(job) <function>" as their route, a
job that raises is sent (status 500), and each run is timed (Health ->
Server speed -> Jobs).

    # jobs.py
    PlatformWorker = platform.rq_worker()

    rq worker -w jobs.PlatformWorker

A failure that will be retried (Retry(max=...)) is timed as failed but not
sent: the error is sent when the last attempt fails. A run cut short
(SystemExit, the job's timeout) is timed as failed; only an exception is
sent. RQ runs each job in a process of its own that leaves through
os._exit, so what the job left waiting is sent as it ends; that process
doesn't check in (only the worker shows on Health -> All systems). One
killed outright (out of memory, or 60 s past its timeout) is sent and timed
by the worker, as WorkHorseKilled.
"""
import atexit
import os
import time
from datetime import datetime, timezone

from rq import Worker

from . import _Job


class WorkHorseKilled(Exception):
    """The process running a job died without saying how (SIGKILL: out of
    memory, or RQ's own kill of a job 60 s past its timeout)."""


def _name(job):
    try:
        return job.func_name or "job"
    except Exception:  # a job that can't be read (DeserializationError)
        return "job"


def worker_class(platform, base=None):
    atexit.register(platform.flush_before_exit)  # SimpleWorker: the worker runs the jobs itself

    class PlatformWorker(base or Worker):
        def perform_job(self, job, queue, *args, **kwargs):
            run = _Job(platform, _name(job))
            run.__enter__()
            done = False
            try:
                done = super().perform_job(job, queue, *args, **kwargs)
                return done
            finally:
                try:
                    run._leave(200 if done else 500)
                    if getattr(self, "_is_horse", False):
                        platform.flush_before_exit()  # the work horse ends after its job
                except Exception as error:
                    platform.core.log("rq", "could not time a job:", error)

        def fork_work_horse(self, job, queue):
            # The work horse lives for one job: only this worker checks in.
            platform.core.fork_quietly()
            try:
                return super().fork_work_horse(job, queue)
            finally:
                platform.core.fork_quietly(False)  # SpawnWorker starts its horse without a fork

        def handle_work_horse_killed(self, job, retpid, ret_val, rusage):
            # Nothing of the run is left in the horse, so this worker sends
            # it, timed from when it handed the job over.
            try:
                run = _Job(platform, _name(job))
                started = getattr(job, "started_at", None)
                seconds = (datetime.now(timezone.utc) - started).total_seconds() if started is not None else 0
                if not getattr(job, "should_retry", False):
                    if ret_val is None:  # RQ killed it itself and didn't keep the status
                        message = "work horse killed by the worker, 60 s past the job's timeout"
                    else:
                        signal = " (signal %d)" % os.WTERMSIG(ret_val) if os.WIFSIGNALED(ret_val) else ""
                        message = "work horse %s ended unexpectedly%s" % (retpid, signal)
                    platform.capture_exception(WorkHorseKilled(message),
                                               status=500, kind="error", request=run._fields())
                platform.time_request("JOB", run.route, 500, time.perf_counter() - max(0, seconds), run.route)
            except Exception as error:
                platform.core.log("rq", "could not report a killed work horse:", error)
            return super().handle_work_horse_killed(job, retpid, ret_val, rusage)

        def execute_job(self, job, queue, *args, **kwargs):
            try:
                return super().execute_job(job, queue, *args, **kwargs)
            finally:
                _count_finished(platform, job, queue)

        def handle_exception(self, job, *exc_info):
            # Called inside the run, so the error keeps the job's trail.
            error = exc_info[1] if len(exc_info) > 1 else None
            if isinstance(error, Exception) and not getattr(job, "should_retry", False):
                platform.capture_exception(error, status=500, kind="error", request=_Job(platform, _name(job))._fields())
            return super().handle_exception(job, *exc_info)

    PlatformWorker.__name__ = PlatformWorker.__qualname__ = "Platform" + (base or Worker).__name__
    return PlatformWorker


# ---- Queue backlog (sdk/protocols/queues.md): platform.watch_queue(queue) ----

# A job's end for good: one to be retried is scheduled or queued again.
DONE = frozenset(("finished", "failed", "stopped", "canceled"))


def _registry_key(queue, name, cls_name):
    registry = getattr(queue, name, None)
    if registry is None:
        import rq.registry
        registry = getattr(rq.registry, cls_name)(queue=queue)
    return registry.key


def _broker(queue):
    from .queues import redis_broker
    return redis_broker(queue.connection.connection_pool.connection_kwargs)


def _parse_time(value):
    if isinstance(value, bytes):
        value = value.decode("ascii", "replace")
    if not value:
        return None
    text = str(value).replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(text)
    except ValueError:
        try:
            return datetime.strptime(str(value), "%Y-%m-%dT%H:%M:%S.%fZ")
        except ValueError:
            return None


def watch_queue(queues, queue):
    """The queue and its registries, read every minute: waiting (the queue),
    running (StartedJobRegistry), delayed (Scheduled and Deferred), failed
    (FailedJobRegistry), and the first job's enqueued_at. Jobs this process
    finished are counted by platform.rq_worker()'s worker; RQ has no hook for
    a job being added, so added isn't sent."""
    from .queues import seconds_since
    connection = queue.connection
    job_class = getattr(queue, "job_class", None)
    keys = (_registry_key(queue, "started_job_registry", "StartedJobRegistry"),
            _registry_key(queue, "scheduled_job_registry", "ScheduledJobRegistry"),
            _registry_key(queue, "deferred_job_registry", "DeferredJobRegistry"),
            _registry_key(queue, "failed_job_registry", "FailedJobRegistry"))

    def read():
        pipe = connection.pipeline(transaction=False)
        pipe.llen(queue.key)
        for key in keys:
            pipe.zcard(key)
        pipe.lindex(queue.key, 0)  # RQ adds at the end and takes from the front
        waiting, running, scheduled, deferred, failed, first = pipe.execute()
        out = {"waiting": int(waiting or 0), "running": int(running or 0),
               "delayed": int(scheduled or 0) + int(deferred or 0), "failed": int(failed or 0)}
        if not out["waiting"]:
            out["oldest_s"] = 0
        elif first and job_class is not None:
            job_id = first.decode("utf-8", "replace") if isinstance(first, bytes) else str(first)
            # The one field, not the job: its data is never loaded.
            at = _parse_time(connection.hget(job_class.key_for(job_id), "enqueued_at"))
            if at is not None:
                out["oldest_s"] = seconds_since(at)
        return out

    entry = queues.entry("rq", _broker(queue), queue.name, read)
    return entry


def _count_finished(platform, job, queue):
    """In the worker's own process once a job is over: one that ended for
    good counts as finished on its queue, when that queue is watched."""
    try:
        queues = platform._queues_module()
        if queues is None or not queues.on():
            return
        entry = queues.entries.get(("rq", _broker(queue), str(queue.name)[:200]))
        if entry is None:
            return
        entry.counts_finished = True
        status = job.get_status(refresh=True)
        status = getattr(status, "value", status)
        if status in DONE:
            queues.count(entry, finished=1)
    except Exception as error:
        platform.core.log("rq", "could not count a finished job:", error)
