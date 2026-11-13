"""The RQ worker class and the Dramatiq middleware, against stand-ins for
both (neither is needed): a job or message runs as a job(), its failure is
sent once with its route unless it will be retried, each run is timed by
how it ended, and what's waiting is sent as a work horse or worker ends.

    python3 -m unittest discover -s tests
"""
import os
import sys
import threading
import types
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analytics_platform import create_platform  # noqa: E402
from analytics_platform.errors import add_breadcrumb, current_request, current_trail  # noqa: E402


def make_platform():
    return create_platform(site_id="a1b2c3d4e5f6a1b2c3d4e5f6", secret="s", endpoint="http://127.0.0.1:9",
                           firewall=False, analytics=False, flags=False, inventory=False, posture=False,
                           resources=False, proxy=False, maintenance=False, crawlers=False, forms=False,
                           audit=False, errors={"capture_uncaught": False, "spool_dir": False})


class Base(unittest.TestCase):
    modules = {}

    def setUp(self):
        self.patched = mock.patch.dict(sys.modules, self.modules)
        self.patched.start()
        for name in ("analytics_platform.rq", "analytics_platform.dramatiq"):
            sys.modules.pop(name, None)
        self.platform = make_platform()
        self.errors = self.platform._modules["errors"]
        self.performance = self.platform._modules["performance"]

    def tearDown(self):
        self.errors.queue = []
        self.performance.rows = {}
        self.platform.close()
        self.patched.stop()

    def timings(self):
        return sorted((key[2], key[3], row["count"]) for key, row in self.performance.rows.items())


# ---- RQ ----

class Worker:
    """As rq.Worker.perform_job: the job's exception goes to handle_exception, and False is returned."""
    _is_horse = False
    forked = None

    def fork_work_horse(self, job, queue):
        self.forked = job

    def handle_work_horse_killed(self, job, retpid, ret_val, rusage):
        self.killed = retpid

    def perform_job(self, job, queue, execution=None):
        try:
            job.perform()
        except:  # noqa: E722 (RQ catches everything, SystemExit too)
            self.handle_exception(job, *sys.exc_info())
            return False
        return True

    def handle_exception(self, job, *exc_info):
        self.handled = exc_info


class Job:
    def __init__(self, func_name, body, retries_left=None):
        self.func_name = func_name
        self.perform = body
        self.should_retry = bool(retries_left)


rq = types.ModuleType("rq")
rq.Worker = Worker


class RQTest(Base):
    modules = {"rq": rq}

    def test_a_failing_job_is_sent_with_its_route_and_timed(self):
        def charge():
            add_breadcrumb("Order saved")
            raise ValueError("card declined")

        worker = self.platform.rq_worker()()
        self.assertFalse(worker.perform_job(Job("jobs.charge", charge), None, None))
        [event] = self.errors.queue
        self.assertEqual((event["method"], event["route"], event["status_code"], event["kind"]), ("JOB", "/(job) jobs.charge", 500, "error"))
        self.assertEqual([crumb["text"] for crumb in event["breadcrumbs"]], ["Order saved"])
        self.assertEqual(worker.handled[0], ValueError, "RQ's own handling still runs")
        self.assertEqual(self.timings(), [("/(job) jobs.charge", 500, 1)])
        self.assertIsNone(current_request.get())
        self.assertIsNone(current_trail.get())

    def test_a_job_that_will_be_retried_is_timed_but_not_sent(self):
        def flaky():
            raise RuntimeError("upstream timeout")

        worker = self.platform.rq_worker()()
        worker.perform_job(Job("jobs.flaky", flaky, retries_left=2), None)
        self.assertEqual(self.errors.queue, [])
        self.assertEqual(self.timings(), [("/(job) jobs.flaky", 500, 1)])

    def test_an_error_captured_inside_a_job_carries_its_route_and_systemexit_is_timed_only(self):
        worker = self.platform.rq_worker()()
        worker.perform_job(Job("jobs.sync", lambda: self.platform.capture_exception(KeyError("sku"))), None)

        def quits():
            raise SystemExit(3)

        worker.perform_job(Job("jobs.quits", quits), None)
        self.assertEqual([event["route"] for event in self.errors.queue], ["/(job) jobs.sync"])
        self.assertEqual(self.timings(), [("/(job) jobs.quits", 500, 1), ("/(job) jobs.sync", 200, 1)])

    def test_a_work_horse_sends_whats_waiting_before_it_exits(self):
        flushed = []
        self.platform.flush = lambda: flushed.append(True)
        worker = self.platform.rq_worker()()
        worker.perform_job(Job("jobs.ok", lambda: None), None)
        self.assertEqual(flushed, [], "a SimpleWorker leaves it to the timer")
        worker._is_horse = True
        worker.perform_job(Job("jobs.ok", lambda: None), None)
        self.assertEqual(flushed, [True])

    def test_a_work_horse_doesnt_check_in_but_the_worker_does(self):
        worker = self.platform.rq_worker()()
        quiet = []
        self.platform.core.fork_quietly = lambda on=True: quiet.append(on)
        worker.fork_work_horse(Job("jobs.ok", None), None)
        self.assertEqual(quiet, [True, False], "for the one fork only")
        self.assertIsNotNone(worker.forked)

    def test_a_work_horse_killed_outright_is_sent_and_timed_by_the_worker(self):
        import signal
        from datetime import datetime, timedelta, timezone
        worker = self.platform.rq_worker()()
        job = Job("jobs.hog", None)
        job.started_at = datetime.now(timezone.utc) - timedelta(seconds=61)
        status = signal.SIGKILL  # as waitpid reports a process killed by it
        worker.handle_work_horse_killed(job, 4321, status, None)
        [event] = self.errors.queue
        self.assertEqual((event["route"], event["status_code"], event["error_type"]), ("/(job) jobs.hog", 500, "WorkHorseKilled"))
        self.assertIn("(signal 9)", event["message"])
        [(key, row)] = self.performance.rows.items()
        self.assertEqual((key[2], key[3]), ("/(job) jobs.hog", 500))
        self.assertGreaterEqual(row["max_ms"], 61000)
        self.assertEqual(worker.killed, 4321, "RQ's own handling still runs")
        worker.handle_work_horse_killed(job, None, None, None)  # RQ's own kill keeps no status
        self.assertIn("past the job's timeout", self.errors.queue[1]["message"])

    def test_a_base_class_of_your_own(self):
        class Simple(Worker):
            pass

        cls = self.platform.rq_worker(Simple)
        self.assertTrue(issubclass(cls, Simple))
        self.assertEqual(cls.__name__, "PlatformSimple")


# ---- Dramatiq ----

class Middleware:
    pass


class Retries(Middleware):
    pass


class TimeLimitExceeded(BaseException):
    pass


class Shutdown(BaseException):
    pass


class Broker:
    def __init__(self, retries=True):
        self.middleware = [Retries()] if retries else []

    def add_middleware(self, middleware, before=None, after=None):
        index = next((i for i, m in enumerate(self.middleware) if before and isinstance(m, before)), len(self.middleware))
        self.middleware.insert(index, middleware)


class Message:
    def __init__(self, actor_name, message_id="m1"):
        self.actor_name = actor_name
        self.message_id = message_id
        self.failed = False


dramatiq = types.ModuleType("dramatiq")
dramatiq.Middleware = Middleware
dramatiq.get_broker = lambda: Broker()
dramatiq_middleware = types.ModuleType("dramatiq.middleware")
dramatiq_middleware.Retries = Retries
dramatiq_middleware.TimeLimitExceeded = TimeLimitExceeded
dramatiq.middleware = dramatiq_middleware


class DramatiqTest(Base):
    modules = {"dramatiq": dramatiq, "dramatiq.middleware": dramatiq_middleware}

    def setUp(self):
        super().setUp()
        self.broker = self.platform.init_dramatiq(Broker())
        self.middleware = self.broker.middleware[0]

    def process(self, message, body, final=True):
        """As Dramatiq's worker: before, the actor, after (Retries has failed the message by then)."""
        self.middleware.before_process_message(self.broker, message)
        try:
            body()
        except BaseException as error:
            message.failed = final
            self.middleware.after_process_message(self.broker, message, exception=error)
        else:
            self.middleware.after_process_message(self.broker, message, result=None)

    def test_it_runs_after_retries_so_it_knows_a_message_has_failed(self):
        self.assertIsInstance(self.broker.middleware[1], Retries)

    def test_a_failing_message_is_sent_with_its_route_and_timed(self):
        def charge():
            add_breadcrumb("Order saved")
            raise ValueError("card declined")

        self.process(Message("charge"), charge)
        [event] = self.errors.queue
        self.assertEqual((event["route"], event["status_code"], event["kind"]), ("/(job) charge", 500, "error"))
        self.assertEqual([crumb["text"] for crumb in event["breadcrumbs"]], ["Order saved"])
        self.assertEqual(self.timings(), [("/(job) charge", 500, 1)])
        self.assertIsNone(current_request.get())

    def test_a_retried_message_is_timed_not_sent_and_a_time_limit_is_sent(self):
        def flaky():
            raise RuntimeError("upstream timeout")

        def slow():
            raise TimeLimitExceeded()

        def stopping():
            raise Shutdown()

        self.process(Message("flaky"), flaky, final=False)
        self.process(Message("slow"), slow)
        self.process(Message("stopping"), stopping)
        self.process(Message("ok"), lambda: None)
        self.assertEqual([event["route"] for event in self.errors.queue], ["/(job) slow"])
        self.assertEqual(self.timings(), [("/(job) flaky", 500, 1), ("/(job) ok", 200, 1), ("/(job) slow", 500, 1), ("/(job) stopping", 500, 1)])

    def test_messages_on_other_threads_keep_their_own_runs(self):
        seen = {}
        both = threading.Barrier(2)

        def work(name):
            def body():
                add_breadcrumb("in " + name)
                both.wait()
                self.platform.capture_exception(KeyError(name))
            self.process(Message(name, message_id=name), body)

        threads = [threading.Thread(target=work, args=(name,)) for name in ("a", "b")]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        for event in self.errors.queue:
            seen[event["route"]] = [crumb["text"] for crumb in event["breadcrumbs"]]
        self.assertEqual(seen, {"/(job) a": ["in a"], "/(job) b": ["in b"]})

    def test_a_skipped_message_is_not_timed_and_a_worker_sends_whats_waiting_as_it_stops(self):
        message = Message("old")
        self.middleware.before_process_message(self.broker, message)
        self.middleware.after_skip_message(self.broker, message)
        self.assertEqual(self.timings(), [])
        self.assertIsNone(current_request.get())
        flushed = []
        self.platform.flush = lambda: flushed.append(True)
        self.middleware.after_worker_shutdown(self.broker, None)
        self.assertEqual(flushed, [True])

    def test_without_retries_every_failure_is_sent(self):
        broker = self.platform.init_dramatiq(Broker(retries=False))
        self.middleware = broker.middleware[0]
        self.process(Message("charge"), lambda: 1 / 0, final=False)
        self.assertEqual(len(self.errors.queue), 1)


if __name__ == "__main__":
    unittest.main()
