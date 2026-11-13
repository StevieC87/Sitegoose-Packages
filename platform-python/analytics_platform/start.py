"""The one-line setup. Near the top of the module that makes your app:

    from analytics_platform.start import platform

It reads ANALYTICS_SITE_ID, ANALYTICS_SITE_SECRET and ANALYTICS_ENDPOINT from
the environment, or else from the ANALYTICS_* lines of the .env in the folder
the server starts in (read, never written to os.environ).

Flask and FastAPI (any Starlette app): that's all. On an app's first request
it puts itself in front, as platform.init_flask(app) and
app.add_middleware(PlatformMiddleware, platform=platform) do by hand, so it
doesn't matter whether this import comes before or after the app is made. An
app that already has either by hand gets nothing added a second time, and a
Starlette app mounted inside another isn't counted twice.

Django: add "analytics_platform.django.PlatformMiddleware" first in
MIDDLEWARE instead, and use get_platform() from there.

The platform is made on first use (the first request, or the first
platform.track()), not on import: under Gunicorn or uWSGI with the app loaded
before the workers fork, its background threads then start in each worker,
not in the master. Use the same import wherever you call platform.track() and
the rest: it's one platform for the process.
"""
import os
import threading

from . import Platform, PlatformMiddleware, _env

_lock = threading.Lock()
_made = None


def _platform():
    global _made
    if _made is None:
        with _lock:
            if _made is None:
                _made = Platform(**_env.from_environment({}, os.path.join(os.getcwd(), ".env")))
    return _made


class _Platform:
    """Stands for the platform until its first use, then hands every
    attribute to it."""

    def __getattr__(self, name):
        return getattr(_platform(), name)

    def __repr__(self):
        return "<analytics_platform.start platform%s>" % ("" if _made is not None else " (not made yet)")


platform = _Platform()

_MARK = "_analytics_platform_started"


def _hook_flask():
    try:
        from flask import Flask
    except Exception:
        return
    if getattr(Flask.__call__, _MARK, False):
        return
    original = Flask.__call__
    hook_lock = threading.Lock()

    # The first request's own thread hooks the app in before Flask marks it
    # as started (after that it refuses new before_request functions); other
    # threads wait for it, so none gets past without it.
    def __call__(self, environ, start_response):
        if not self.__dict__.get(_MARK):
            with hook_lock:
                if not self.__dict__.get(_MARK):
                    try:
                        _platform().init_flask(self)
                    except Exception as error:
                        print("[analytics-platform] couldn't add itself to this Flask app; call platform.init_flask(app) by hand: %s" % error)
                    self.__dict__[_MARK] = True
        return original(self, environ, start_response)

    setattr(__call__, _MARK, True)
    Flask.__call__ = __call__


def _hook_starlette():
    try:
        from starlette.applications import Starlette
        from starlette.middleware import Middleware
    except Exception:
        return
    if getattr(Starlette.__call__, _MARK, False):
        return
    original = Starlette.__call__

    # Before the app builds its middleware stack, on its first call. Only the
    # outermost app: a mounted one is called with scope["app"] already set by
    # the app it's mounted in. Outermost of your own middleware, as
    # add_middleware() called last puts it.
    async def __call__(self, scope, receive, send):
        if not self.__dict__.get(_MARK):
            self.__dict__[_MARK] = True
            outermost = "app" not in scope
            by_hand = any(getattr(m, "cls", None) is PlatformMiddleware for m in getattr(self, "user_middleware", []))
            if outermost and not by_hand and getattr(self, "middleware_stack", None) is None:
                self.user_middleware.insert(0, Middleware(PlatformMiddleware, platform=platform))
        await original(self, scope, receive, send)

    setattr(__call__, _MARK, True)
    Starlette.__call__ = __call__


# Each only when its framework is installed.
_hook_flask()
_hook_starlette()

__all__ = ["platform"]
