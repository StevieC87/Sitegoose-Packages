"""Dramatiq: every message runs as a platform.job() named after its actor.
Its errors carry "/(job) <actor>" as their route, a message that raises is
sent (status 500), and each run is timed (Health -> Server speed -> Jobs).

    broker = RedisBroker(...)
    dramatiq.set_broker(broker)
    platform.init_dramatiq(broker)

A failure the Retries middleware will retry is timed as failed but not sent:
the error is sent when the last attempt fails. A run cut short is timed as
failed, and sent when it was its time limit (not SystemExit or Shutdown). A message
skipped before it ran isn't timed. What's waiting is sent as each worker
process stops (they leave through os._exit, which skips atexit).
"""
import contextvars

from dramatiq import Middleware
from dramatiq.middleware import Retries, TimeLimitExceeded

from . import _Job


class PlatformMiddleware(Middleware):
    def __init__(self, platform):
        self.platform = platform
        # The message this worker thread is running: (message id, its job).
        self.running = contextvars.ContextVar("analytics_platform_dramatiq_%d" % id(self), default=None)
        self.retries = False

    def before_process_message(self, broker, message):
        job = _Job(self.platform, message.actor_name or "actor")
        job.__enter__()
        self.running.set((message.message_id, job))

    def after_process_message(self, broker, message, *, result=None, exception=None):
        run = self.running.get()
        if run is None or run[0] != message.message_id:
            return
        self.running.set(None)
        try:
            # Placed before Retries, so this runs after it: a message it
            # didn't fail is one it will retry.
            # A time limit is raised into the thread as an interrupt, not an
            # Exception, but it is the message failing; Shutdown isn't.
            failed = isinstance(exception, (Exception, TimeLimitExceeded))
            if failed and (message.failed or not self.retries):
                self.platform.capture_exception(exception, status=500, kind="error", request=run[1]._fields())
            run[1]._leave(200 if exception is None else 500)
        except Exception as error:
            self.platform.core.log("dramatiq", "could not time a message:", error)

    def after_skip_message(self, broker, message):
        run = self.running.get()
        if run is not None and run[0] == message.message_id:
            self.running.set(None)
            run[1]._leave(None)

    def after_worker_shutdown(self, broker, worker):
        self.platform.flush_before_exit()


def connect(platform, broker=None):
    import dramatiq
    broker = broker or dramatiq.get_broker()
    middleware = PlatformMiddleware(platform)
    middleware.retries = any(isinstance(m, Retries) for m in broker.middleware)
    broker.add_middleware(middleware, before=Retries) if middleware.retries else broker.add_middleware(middleware)
    return broker
