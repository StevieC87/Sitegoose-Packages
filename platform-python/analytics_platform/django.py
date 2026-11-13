"""Django: add the middleware first in MIDDLEWARE. That's all when the keys
are in the environment or in the project's .env (beside manage.py):
ANALYTICS_SITE_ID, ANALYTICS_SITE_SECRET and ANALYTICS_ENDPOINT.

    MIDDLEWARE = ["analytics_platform.django.PlatformMiddleware", ...]

Options in code go in settings, and win over the environment:

    ANALYTICS_PLATFORM = {"trust_proxy": 1, "errors": {"capture_logging": True}}

In your code, get_platform() is the same platform: get_platform().track(...).
The visitor's address is REMOTE_ADDR unless you set trust_proxy. The package
says it is Django (analytics-platform-django/<version>), so request rules
aimed at Django sites reach it. Every connection's queries are timed for
Server speed, under the request that ran them ("queries": False leaves them out).
"""
import os
import time

from django.conf import settings
from django.http import HttpResponse

from . import _env
from . import SESSION_HEADER, Platform, _inflight_end, _inflight_start, _queries_end, _queries_start
from .errors import current_request, current_trail

_platform = None


def get_platform():
    global _platform
    if _platform is None:
        # Settings first, then ANALYTICS_* in the environment, then the
        # ANALYTICS_* lines of the project's .env (beside manage.py), which is
        # read, never loaded into the environment.
        options = dict(getattr(settings, "ANALYTICS_PLATFORM", {}))
        options.setdefault("client", "django")
        base = getattr(settings, "BASE_DIR", None) or os.getcwd()
        options = _env.from_environment(options, os.path.join(str(base), ".env"))
        _platform = Platform(**options)
        _connect_login_failed()
        _watch_queries(_platform)
    return _platform


def _watch_queries(platform):
    """Every connection's queries timed, as it opens (Server speed)."""
    if platform._queries() is None:
        return
    try:
        from .queries import watch_django
        watch_django()
    except Exception as error:
        platform.core.log("performance", "Django queries aren't timed:", error)


def _connect_login_failed():
    """Failed Django logins count for bot protection, on their own."""
    try:
        from django.contrib.auth.signals import user_login_failed
    except Exception:
        return

    def on_failed(sender, credentials=None, request=None, **_):
        if request is not None:
            get_platform().login_failed(request)

    user_login_failed.connect(on_failed, weak=False, dispatch_uid="analytics_platform_login_failed")

    # Logins and logouts in the audit log.
    from django.contrib.auth.signals import user_logged_in, user_logged_out

    def on_login(sender, request=None, user=None, **_):
        get_platform().audit("user.login", actor=getattr(user, "get_username", lambda: "")() if user else "", request=request)

    def on_logout(sender, request=None, user=None, **_):
        get_platform().audit("user.logout", actor=getattr(user, "get_username", lambda: "")() if user else "", request=request)

    user_logged_in.connect(on_login, weak=False, dispatch_uid="analytics_platform_login")
    user_logged_out.connect(on_logout, weak=False, dispatch_uid="analytics_platform_logout")


class PlatformMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response
        self.platform = get_platform()

    def __call__(self, request):
        headers = {k.lower(): v for k, v in request.headers.items()}
        started = time.perf_counter()
        ip = request.META.get("REMOTE_ADDR", "")
        # The tracker's own addresses, answered before anything else: a
        # visitor's beacon is our traffic, not a page of the site.
        answered = self.platform.proxy_response(
            request.path, request.method, request.META.get("QUERY_STRING", ""),
            headers, request.body if request.method == "POST" else None, ip)
        if answered:
            status, extra, body = answered
            response = HttpResponse(body, status=status)
            for name, value in extra:
                response[name] = value
            return response
        # The target as sent: request.path is decoded, get_full_path() encodes it again.
        target = request.META.get("RAW_URI") or request.META.get("REQUEST_URI") or request.get_full_path()
        late = {}
        blocked = self.platform.blocked(ip, headers, request.method, target, late)
        if blocked:
            status, body, extra = blocked
            response = HttpResponse(body, status=status)
            for name, value in extra:
                response[name] = value
            # A crawler the firewall turned away is still a crawler, and
            # counted with the status it got.
            self.platform.record_crawler(headers.get("user-agent", ""), request.path, status, started, 0, ip)
            return response
        closed = self.platform.maintenance_response(request.META.get("REMOTE_ADDR", ""), headers, request.path,
                                                    request.META.get("QUERY_STRING", ""), _is_secure(request))
        if closed and closed[0] != "pass":
            response = HttpResponse(closed[2], status=503)
            for name, value in closed[1]:
                response[name] = value
            return response
        # Errors captured during the request (logged, or caught without the
        # request) still know which request they came from.
        token = current_request.set(lambda: _request_fields(request))
        trail = current_trail.set([])
        queries = _queries_start(self.platform)
        inflight = _inflight_start(self.platform)
        try:
            try:
                response = self.get_response(request)
            finally:
                current_request.reset(token)
                current_trail.reset(trail)
                _inflight_end(inflight)
            for name, value in self.platform.security_headers(response.headers.keys()):
                response[name] = value
            if closed:
                response["Set-Cookie"] = closed[1][0][1]
            # The request's queries go under its route with its timing.
            self.platform.time_request(request.method, _route(request), response.status_code, started, request.path)
        finally:
            _queries_end(queries)
        self.platform.record_crawler(headers.get("user-agent", ""), request.path, response.status_code, started,
                                     response.headers.get("Content-Length") or 0, ip)
        if late:
            self._count_static_later(request, response, late)
        return response

    def _count_static_later(self, request, response, late):
        """A static-looking request counts toward the rate and the page
        limits after all when it answered 400 or more, or Django's URL
        resolver sent it to a view (firewall.md, `rate`): "search/<str:q>"
        takes "/search/x.css". Django's own file views (static.serve,
        staticfiles' serve) and whitenoise, which answers before the
        resolver, serve files. Counted once the server has sent the body
        (the response's closers), else now. Never raises."""
        def count():
            try:
                match = getattr(request, "resolver_match", None)
                routed = False
                if match is not None and not _serves_files(match):
                    from .firewall import routed_to_page
                    headers = getattr(response, "headers", None)
                    content_type = headers.get("Content-Type", "") if headers is not None else response.get("Content-Type", "")
                    routed = routed_to_page(getattr(match, "route", "") or "/", content_type)
                self.platform.count_static(late, response.status_code, routed)
            except Exception:
                pass

        closers = getattr(response, "_resource_closers", None)
        if isinstance(closers, list):
            closers.append(count)
        else:
            count()

    def process_exception(self, request, exception):
        self.platform.capture_exception(exception, status=500, kind="error", request=_request_fields(request))
        return None


# Django's views that serve files: an image on a page is a request to one.
_FILE_VIEWS = ("django.views.static.", "django.contrib.staticfiles.views.")


def _serves_files(match):
    name = getattr(match, "_func_path", "") or ""
    if not name:
        func = getattr(match, "func", None)
        name = "%s.%s" % (getattr(func, "__module__", ""), getattr(func, "__name__", ""))
    return name.startswith(_FILE_VIEWS)


# The URL pattern, as Server speed names it, so an error's route and the
# route's timings match.
def _route(request):
    route = getattr(getattr(request, "resolver_match", None), "route", "") or ""
    return ("/" + route.lstrip("^").rstrip("$").lstrip("/")) if route else ""


def _request_fields(request):
    return {"method": request.method, "path": request.path, "route": _route(request),
            "session_id": request.headers.get(SESSION_HEADER, "")}


def _is_secure(request):
    """Django's word on https (SECURE_PROXY_SSL_HEADER included)."""
    try:
        return bool(request.is_secure())
    except Exception:
        return False
