"""The errors module: an error is sent once however many handlers see it,
exceptions logged through logging are sent when asked, a request's route
follows errors captured without it, and a failed batch is tried once more.

    python3 -m unittest discover -s tests
"""
import json
import logging
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analytics_platform import errors as mod  # noqa: E402
from analytics_platform.errors import Errors, add_breadcrumb, current_request, current_trail  # noqa: E402


class Answer:
    def __init__(self, status):
        self.status = status


class FakeCore:
    valid = False  # no background job: the tests flush by hand

    def __init__(self, answers=None):
        self.answers = list(answers or [])
        self.sent = []

    def is_on(self, name):
        return True

    def log(self, *args):
        pass

    def send(self, module, path, body=None, **_):
        self.sent.append(body["errors"])
        status = self.answers.pop(0) if self.answers else 202
        return None if status is None else Answer(status)


def events(core):
    return [event for batch in core.sent for event in batch]


class ErrorsTest(unittest.TestCase):
    def setUp(self):
        self.retry = mod.RETRY_AFTER
        mod.RETRY_AFTER = 0

    def tearDown(self):
        mod.RETRY_AFTER = self.retry

    def test_one_error_is_sent_once(self):
        core = FakeCore()
        errors = Errors(core, capture_uncaught=False)
        error = ValueError("payment failed")
        errors.capture_exception(error, status=500, kind="error")
        errors.capture_exception(error)
        errors.capture_exception(ValueError("payment failed"))
        errors.close()
        self.assertEqual(len(events(core)), 2)

    def test_capture_logging_sends_logged_exceptions_only_when_on(self):
        logger = logging.getLogger("shop.checkout")
        quiet = logging.NullHandler()  # keeps logging's last-resort printer out of the test output
        logger.addHandler(quiet)
        try:
            core = FakeCore()
            off = Errors(core, capture_uncaught=False)
            try:
                raise RuntimeError("off")
            except RuntimeError:
                logger.exception("not sent")
            off.close()
            self.assertEqual(core.sent, [])

            on = Errors(core, capture_uncaught=False, capture_logging=True)
            try:
                raise RuntimeError("card declined")
            except RuntimeError:
                logger.exception("charge failed")
            logger.error("plain text is not sent")
            on.close()
            sent = events(core)
            self.assertEqual(len(sent), 1)
            self.assertEqual(sent[0]["message"], "card declined")
            self.assertEqual(sent[0]["kind"], "logged")
            self.assertNotIn(on._log_handler, logging.getLogger().handlers)
        finally:
            logger.removeHandler(quiet)

    def test_the_current_request_fills_in_an_error_captured_without_one(self):
        core = FakeCore()
        errors = Errors(core, capture_uncaught=False)
        token = current_request.set(lambda: {"method": "POST", "path": "/orders/12", "route": "/orders/<int:id>"})
        try:
            errors.capture_exception(ValueError("deep inside"))
        finally:
            current_request.reset(token)
        errors.capture_exception(ValueError("outside"))
        errors.close()
        inside, outside = events(core)
        self.assertEqual(inside["route"], "/orders/<int:id>")
        self.assertEqual(inside["method"], "POST")
        self.assertNotIn("route", outside)

    def test_a_failed_batch_is_sent_once_more_and_only_once(self):
        for answers, expected in (([503, 503], 2), ([None, 202], 2), ([400], 1)):
            core = FakeCore(answers)
            errors = Errors(core, capture_uncaught=False)
            errors.capture_exception(ValueError("x"))
            errors.flush()
            self.assertEqual(len(core.sent), expected, answers)


    def test_an_exception_logged_then_raised_keeps_the_frameworks_status_and_request(self):
        logger = logging.getLogger("shop.pay")
        quiet = logging.NullHandler()
        logger.addHandler(quiet)
        try:
            core = FakeCore()
            errors = Errors(core, capture_uncaught=False, capture_logging=True)
            try:
                raise RuntimeError("charge failed")
            except RuntimeError as error:
                logger.exception("charge failed")
                errors.capture_exception(error, status=500, kind="error",
                                         request={"method": "POST", "path": "/pay", "route": "/pay"})
            errors.close()
            sent = events(core)
            self.assertEqual(len(sent), 1)
            self.assertEqual((sent[0]["kind"], sent[0]["status_code"], sent[0]["route"]), ("error", 500, "/pay"))
        finally:
            logger.removeHandler(quiet)

    def test_without_a_route_an_error_is_named_as_server_speed_names_the_request(self):
        core = FakeCore()
        errors = Errors(core, capture_uncaught=False)
        errors.capture_exception(ValueError("x"), request={"method": "GET", "path": "/orders/123/items?x=1"})
        errors.close()
        self.assertEqual(events(core)[0]["route"], "/orders/:id/items")

    def test_errors_the_collector_could_not_take_wait_in_a_file_and_are_sent_later(self):
        import tempfile
        import shutil
        folder = tempfile.mkdtemp()
        try:
            core = FakeCore([503, 503])
            core.valid, core.site_id, core.secret = True, "a1b2c3d4e5f6a1b2c3d4e5f6", "s"
            errors = Errors(core, capture_uncaught=False, spool_dir=folder)
            errors.job.stop()  # flushed by hand
            errors._last_resend = 10 ** 12  # no resend inside this flush
            errors.capture_exception(ValueError("collector away"))
            errors.flush()
            files = os.listdir(folder)
            self.assertEqual(len(files), 1)
            kept = open(os.path.join(folder, files[0])).read()
            self.assertIn("collector away", kept)
            self.assertNotIn("a1b2c3d4e5f6a1b2c3d4e5f6", kept + files[0])
            self.assertRegex(kept, r'"at": "\d{4}-\d\d-\d\dT[^"]+Z"')
            core.sent = []
            errors.resend()
            self.assertEqual(events(core)[0]["message"], "collector away")
            self.assertEqual(os.listdir(folder), [])
        finally:
            shutil.rmtree(folder, ignore_errors=True)

    def test_a_job_names_its_errors_and_sends_the_one_it_raises(self):
        from analytics_platform import _Job

        class FakePlatform:
            def __init__(self, errors):
                self.errors, self.timed = errors, []

            def capture_exception(self, error, **kwargs):
                self.errors.capture_exception(error, **kwargs)

            def time_request(self, method, route, status, started, path=""):
                self.timed.append((method, route, status))

        core = FakeCore()
        errors = Errors(core, capture_uncaught=False)
        platform = FakePlatform(errors)

        @_Job(platform, "receipts")
        def receipts():
            errors.capture_exception(ValueError("one receipt failed"))
            raise RuntimeError("the job failed")

        with self.assertRaises(RuntimeError):
            receipts()
        errors.close()
        inside, raised = events(core)
        self.assertEqual((inside["method"], inside["route"]), ("JOB", "/(job) receipts"))
        self.assertEqual(raised["status_code"], 500)
        self.assertEqual(platform.timed, [("JOB", "/(job) receipts", 500)])

        # Cancelled, not failed: neither sent nor timed.
        import asyncio
        with self.assertRaises(asyncio.CancelledError):
            with _Job(platform, "receipts"):
                raise asyncio.CancelledError()
        self.assertEqual(len(platform.timed), 1)

    def spooling(self, answers):
        import tempfile
        import shutil
        folder = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, folder, True)
        core = FakeCore(answers)
        core.valid, core.site_id, core.secret = True, "a1b2c3d4e5f6a1b2c3d4e5f6", "s"
        errors = Errors(core, capture_uncaught=False, spool_dir=folder)
        errors.job.stop()  # flushed by hand
        return core, errors

    def test_a_flush_whose_own_sends_failed_does_not_resend_straight_after(self):
        core, errors = self.spooling([503, 503])
        errors.capture_exception(ValueError("collector away"))
        errors.flush()
        self.assertEqual(len(core.sent), 2, "the send and its one retry, no resend of the file")
        self.assertTrue(os.path.exists(errors.spool_file))

    def test_one_resend_at_a_time(self):
        core, errors = self.spooling([503, 503])
        errors._last_resend = 10 ** 12
        errors.capture_exception(ValueError("waiting"))
        errors.flush()
        core.sent = []
        with errors._resend_lock:
            errors.resend()  # another thread is resending
        self.assertEqual(core.sent, [])
        self.assertTrue(os.path.exists(errors.spool_file))

    def test_errors_being_resent_when_the_process_crashes_go_back_in_the_file(self):
        core, errors = self.spooling([])
        errors._spool([{"message": "e%d" % i} for i in range(12)])
        calls = []

        def send(module, path, body=None, **_):
            calls.append(body["errors"])
            if len(calls) == 1:
                return Answer(202)
            errors._keep_resending()  # the crash, while the second batch is out
            return None
        core.send = send
        errors.resend()
        kept = open(errors.spool_file).read().splitlines()
        self.assertEqual([json.loads(line)["message"] for line in kept], ["e10", "e11"], "once, and not what was sent")


class Breadcrumbs(unittest.TestCase):
    def capture(self, errors, message):
        errors.capture_exception(ValueError(message))

    def test_an_error_carries_the_last_steps_of_its_request(self):
        core = FakeCore()
        errors = Errors(core, capture_uncaught=False)
        add_breadcrumb("outside a request, kept nowhere")
        self.capture(errors, "no trail")
        token = current_trail.set([])
        try:
            for i in range(20):
                add_breadcrumb("step %d" % i)
            self.capture(errors, "after the steps")
        finally:
            current_trail.reset(token)
        self.capture(errors, "no trail either")
        errors.flush()
        first, second, third = core.sent[0]
        self.assertNotIn("breadcrumbs", first)
        self.assertNotIn("breadcrumbs", third)
        crumbs = second["breadcrumbs"]
        self.assertEqual(len(crumbs), 15)
        self.assertEqual(crumbs[0]["text"], "step 5")
        self.assertEqual(crumbs[-1]["type"], "note")
        self.assertNotIn("at", crumbs[0])
        self.assertGreaterEqual(crumbs[0]["ms"], 0)

    def test_a_job_has_its_own_trail_and_keeps_it_for_the_error_it_raises(self):
        from analytics_platform import create_platform
        platform = create_platform(site_id="a1b2c3d4e5f6a1b2c3d4e5f6", secret="s", endpoint="http://127.0.0.1:9",
                                   firewall=False, analytics=False, flags=False, inventory=False, posture=False,
                                   resources=False, proxy=False, maintenance=False, crawlers=False, forms=False,
                                   audit=False, errors={"capture_uncaught": False, "spool_dir": False})
        seen = []
        platform._modules["errors"].before_send = lambda event, error: seen.append(event) or None
        with self.assertRaises(ValueError):
            with platform.job("send-receipts"):
                platform.add_breadcrumb("Order saved")
                raise ValueError("in a job")
        self.assertEqual([crumb["text"] for crumb in seen[0]["breadcrumbs"]], ["Order saved"])
        self.assertIsNone(current_trail.get(), "the trail ends with the job")
        platform.close()


if __name__ == "__main__":
    unittest.main()
