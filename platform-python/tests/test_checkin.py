"""The check-in on the switches request (X-Platform-App): what names this
service on Health -> All systems."""
import os
import threading
import time
import unittest
import urllib.parse
from unittest import mock

from analytics_platform import core as core_module
from analytics_platform.core import Core, Periodic


class CheckInTest(unittest.TestCase):
    def test_switches_request_says_which_service_asks_and_that_it_runs(self):
        core = Core("a" * 24, "s", "http://collector", server_name="api wörker")
        with mock.patch.object(core, "send", return_value=None) as send:
            core._sync_switches()
        header = send.call_args.kwargs["headers"]["X-Platform-App"]
        fields = dict(urllib.parse.parse_qsl(header))
        self.assertEqual(fields["server"], "api wörker")
        self.assertEqual(fields["kind"], "process")
        self.assertEqual(fields["pid"], str(os.getpid()))
        self.assertTrue(fields["runtime"].startswith("Python "))
        self.assertTrue(header.isascii())

    def test_default_name_is_the_machines(self):
        self.assertTrue(Core("a" * 24, "s", "http://collector").server_name)


    @unittest.skipUnless(hasattr(os, "fork"), "needs fork")
    def test_a_child_forked_quietly_doesnt_check_in_and_the_next_one_does(self):
        def child_runs_it():
            read, write = os.pipe()
            pid = os.fork()
            if pid == 0:
                os.write(write, b"1" if job.thread.is_alive() and not job.stopped.is_set() else b"0")
                os._exit(0)
            os.close(write)
            os.waitpid(pid, 0)
            answer = os.read(read, 1)
            os.close(read)
            return answer == b"1"

        job = Periodic(lambda: 3600, first=3600)
        core = Core("a" * 24, "s", "http://collector")
        core._job = job
        try:
            core.fork_quietly()
            self.assertFalse(child_runs_it(), "an RQ work horse: the worker checks in for it")
            self.assertTrue(child_runs_it(), "a gunicorn worker: checks in on its own")
            core.fork_quietly()
            core.fork_quietly(False)
            self.assertTrue(child_runs_it(), "taken back")
        finally:
            job.stop()


    @unittest.skipUnless(hasattr(os, "fork"), "needs fork")
    def test_a_fork_waits_for_a_send_in_flight_and_the_child_can_send(self):
        sending, ends = threading.Event(), []

        def send():
            with core_module._no_fork_meanwhile():
                sending.set()
                time.sleep(0.3)
                ends.append(time.monotonic())

        thread = threading.Thread(target=send)
        thread.start()
        sending.wait()
        read, write = os.pipe()
        pid = os.fork()
        if pid == 0:
            with core_module._no_fork_meanwhile():  # would hang on a gate held at the fork
                os.write(write, b"%f" % time.monotonic())
            os._exit(0)
        os.close(write)
        os.waitpid(pid, 0)
        forked_at = float(os.read(read, 64))
        os.close(read)
        thread.join()
        self.assertGreaterEqual(forked_at, ends[0], "the fork came after the send ended")


if __name__ == "__main__":
    unittest.main()
