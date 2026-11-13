"""The Celery integration, against stand-ins for Celery's signals (Celery
isn't needed): a task runs as a job, its failure is sent once with the
task's route, each run is timed by how it ended, and a worker process sends
what's waiting as it ends.

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

NAMES = ("task_prerun", "task_failure", "task_postrun", "worker_process_shutdown", "worker_shutdown")


class Signal:
    def __init__(self):
        self.receivers = {}

    def connect(self, receiver, sender=None, weak=True, dispatch_uid=None):
        assert weak is False, "a closure connected weakly is dropped at once"
        self.receivers[dispatch_uid or id(receiver)] = receiver

    def send(self, sender=None, **named):
        for receiver in list(self.receivers.values()):
            receiver(sender=sender, signal=self, **named)


class Task:
    def __init__(self, name, app):
        self.name = name
        self.app = app


def make_platform():
    return create_platform(site_id="a1b2c3d4e5f6a1b2c3d4e5f6", secret="s", endpoint="http://127.0.0.1:9",
                           firewall=False, analytics=False, flags=False, inventory=False, posture=False,
                           resources=False, proxy=False, maintenance=False, crawlers=False, forms=False,
                           audit=False, errors={"capture_uncaught": False, "spool_dir": False})


class CeleryTest(unittest.TestCase):
    def setUp(self):
        self.signals = types.SimpleNamespace(**{name: Signal() for name in NAMES})
        celery = types.ModuleType("celery")
        celery.signals = self.signals
        self.modules = mock.patch.dict(sys.modules, {"celery": celery, "celery.signals": self.signals})
        self.modules.start()
        sys.modules.pop("analytics_platform.celery", None)
        self.app = object()
        self.platform = make_platform()
        self.platform.init_celery(self.app)
        self.errors = self.platform._modules["errors"]
        self.performance = self.platform._modules["performance"]

    def tearDown(self):
        self.errors.queue = []
        self.performance.rows = {}
        self.platform.close()
        self.modules.stop()

    def run_task(self, task, body, state="SUCCESS", task_id="t1"):
        """As Celery's tracer does: prerun, the task, failure from inside its except, postrun."""
        self.signals.task_prerun.send(sender=task, task_id=task_id, task=task, args=(), kwargs={})
        try:
            body()
        except Exception as error:
            self.signals.task_failure.send(sender=task, task_id=task_id, exception=error, traceback=error.__traceback__)
            state = "FAILURE"
        self.signals.task_postrun.send(sender=task, task_id=task_id, task=task, state=state)

    def timings(self):
        return sorted((key[1], key[2], key[3], row["count"]) for key, row in self.performance.rows.items())

    def test_a_failing_task_is_sent_as_a_failing_job_and_timed(self):
        def charge():
            add_breadcrumb("Order saved")
            raise ValueError("card declined")

        self.run_task(Task("shop.charge", self.app), charge)
        [event] = self.errors.queue
        self.assertEqual((event["method"], event["route"], event["path"]), ("JOB", "/(job) shop.charge", "/(job) shop.charge"))
        self.assertEqual((event["status_code"], event["kind"], event["error_type"]), (500, "error", "ValueError"))
        self.assertIn('raise ValueError("card declined")', event["stack"])
        self.assertEqual([crumb["text"] for crumb in event["breadcrumbs"]], ["Order saved"])
        self.assertEqual(self.timings(), [("JOB", "/(job) shop.charge", 500, 1)])
        self.assertIsNone(current_request.get(), "the task's route ends with it")
        self.assertIsNone(current_trail.get())

    def test_an_error_captured_inside_a_task_carries_its_route(self):
        self.run_task(Task("shop.sync", self.app), lambda: self.platform.capture_exception(KeyError("sku")))
        [event] = self.errors.queue
        self.assertEqual((event["route"], event["kind"], event["status_code"]), ("/(job) shop.sync", "handled", 0))
        self.assertEqual(self.timings(), [("JOB", "/(job) shop.sync", 200, 1)])

    def test_an_error_your_code_captured_and_raised_on_is_sent_once(self):
        def charge():
            try:
                raise ValueError("card declined")
            except ValueError as error:
                self.platform.capture_exception(error)
                raise

        self.run_task(Task("shop.charge", self.app), charge)
        [event] = self.errors.queue
        self.assertEqual(event["status_code"], 500, "the task's failure fills in the status")

    def test_runs_are_timed_by_how_they_ended(self):
        task = Task("shop.mail", self.app)
        for state in ("RETRY", "IGNORED", "REJECTED", None):
            self.run_task(task, lambda: None, state=state)
        self.assertEqual(self.errors.queue, [], "a retry sends nothing: the last attempt's failure is sent")
        # None: cut short (SystemExit, a hard time limit's SIGTERM, the worker stopping).
        self.assertEqual(self.timings(), [("JOB", "/(job) shop.mail", 200, 1), ("JOB", "/(job) shop.mail", 500, 3)])

    def test_another_apps_tasks_are_left_alone(self):
        self.run_task(Task("other.job", object()), lambda: 1 / 0)
        self.assertEqual(self.errors.queue, [])
        self.assertEqual(self.timings(), [])

    def test_the_copy_celery_can_pickle_is_replaced_by_the_tasks_own_exception(self):
        class UnpickleableExceptionWrapper(Exception):
            pass

        task = Task("shop.weird", self.app)
        self.signals.task_prerun.send(sender=task, task_id="t1", task=task)
        try:
            raise OSError("the task's own")
        except OSError:
            self.signals.task_failure.send(sender=task, task_id="t1", exception=UnpickleableExceptionWrapper("copy"))
        self.signals.task_postrun.send(sender=task, task_id="t1", task=task, state="FAILURE")
        [event] = self.errors.queue
        self.assertEqual((event["error_type"], event["message"]), ("OSError", "the task's own"))

    def test_a_failure_the_main_process_sees_is_sent_without_a_run(self):
        # A hard time limit: the pool process is killed, and the main process says so.
        self.signals.task_failure.send(sender=Task("shop.slow", self.app), task_id="t1", exception=TimeoutError("TimeLimitExceeded(1,)"))
        [event] = self.errors.queue
        self.assertEqual((event["route"], event["status_code"]), ("/(job) shop.slow", 500))
        self.assertEqual(self.timings(), [])

    def test_a_retry_started_on_another_thread_before_the_first_run_ended(self):
        task = Task("shop.flaky", self.app)
        self.signals.task_prerun.send(sender=task, task_id="same", task=task)
        retried = threading.Thread(target=self.run_task, args=(task, lambda: None, "SUCCESS", "same"))
        retried.start()
        retried.join()
        self.signals.task_postrun.send(sender=task, task_id="same", task=task, state="RETRY")
        self.assertEqual(self.timings(), [("JOB", "/(job) shop.flaky", 200, 1), ("JOB", "/(job) shop.flaky", 500, 1)])
        self.assertIsNone(current_request.get())

    def test_an_eager_task_inside_a_request_hands_the_request_back(self):
        request = lambda: {"method": "POST", "path": "/checkout", "route": "/checkout", "session_id": ""}  # noqa: E731
        token = current_request.set(request)
        try:
            outer, inner = Task("shop.order", self.app), Task("shop.receipt", self.app)

            def order():
                self.run_task(inner, lambda: self.platform.capture_exception(KeyError("in the receipt")), task_id="t2")
                self.platform.capture_exception(KeyError("in the order"))

            self.run_task(outer, order)
            self.assertIs(current_request.get(), request)
        finally:
            current_request.reset(token)
        self.assertEqual([event["route"] for event in self.errors.queue], ["/(job) shop.receipt", "/(job) shop.order"])

    def test_a_worker_process_sends_whats_waiting_as_it_ends(self):
        flushed = []
        self.platform.flush = lambda: flushed.append(True)
        self.signals.worker_process_shutdown.send(sender=None, pid=1, exitcode=0)
        self.signals.worker_shutdown.send(sender=object())
        self.assertEqual(len(flushed), 2)

    def test_init_celery_twice_connects_once(self):
        at_exit = len(sys.modules["analytics_platform.celery"]._at_exit)
        self.platform.init_celery(self.app)
        self.assertEqual(len(self.signals.task_prerun.receivers), 1)
        self.assertEqual(len(sys.modules["analytics_platform.celery"]._at_exit), at_exit, "and flushes at exit once")

    @unittest.skipUnless(hasattr(os, "fork"), "needs fork")
    def test_a_process_forked_after_a_capture_leaves_it_to_the_parent(self):
        # The main process captures a time limit, then forks a new pool process.
        self.platform.capture_exception(ValueError("main process"), status=500)
        self.performance.record("JOB", "/(job) x", 200, 1.0)
        read, write = os.pipe()
        pid = os.fork()
        if pid == 0:
            os.write(write, b"%d %d" % (len(self.errors.queue), len(self.performance.rows)))
            os._exit(0)
        os.close(write)
        os.waitpid(pid, 0)
        self.assertEqual(os.read(read, 32), b"0 0")
        os.close(read)
        self.assertEqual(len(self.errors.queue), 1, "still the parent's to send")


if __name__ == "__main__":
    unittest.main()
