"""Outgoing HTTP calls (sdk/protocols/calls.md), part of the performance
module: per minute, request method and route, the host called and the call's
own method, how many, how many failed, their total and slowest time and a
count per time bucket. Only the host is kept: a call's path, query string,
headers and body never leave the server.

A call is timed from being sent to its response's headers arriving. No
answer (refused, timed out, reset) or a 5xx is a failure; a 4xx is the other
side's answer. Through each library's public API only, on the object passed:

    session = platform.watch_http(requests.Session())   # every adapter it has mounted
    client = platform.watch_http(httpx.Client())        # event hooks; AsyncClient too
    client = httpx.Client(transport=platform.watch_http(httpx.HTTPTransport()))

httpx's event hooks see only calls that were answered: a call refused or
timed out raises before any hook. A watched transport sees those too (pass
it to the client you build; AsyncHTTPTransport for an AsyncClient). Both on
one client count a call once.

urllib3 (and urllib.request) have no public hook, so their calls aren't
counted. The package's own calls to the collector aren't, whichever library.
"""
import os
import sys
import threading
import weakref

from .queries import call_ended, call_started


def watch_http(target):
    """target, its calls timed (see the module). Returns what to use: the
    same session or client, or a wrapped transport."""
    if _is_requests_session(target):
        return _watch_requests(target)
    httpx = sys.modules.get("httpx")  # already imported, or target isn't one of its
    if httpx is not None:
        if isinstance(target, (httpx.Client, httpx.AsyncClient)):
            return _watch_httpx_client(target)
        if isinstance(target, (httpx.BaseTransport, httpx.AsyncBaseTransport)) or (
                callable(getattr(target, "handle_request", None)) or callable(getattr(target, "handle_async_request", None))):
            return _watch_httpx_transport(target)  # httpx's, or one of your own
    raise TypeError("watch_http takes a requests Session, an httpx Client or AsyncClient, or an httpx transport")


# ---- requests ----

def _is_requests_session(target):
    return isinstance(getattr(target, "adapters", None), dict) and callable(getattr(target, "mount", None))


def _watch_requests(session):
    """Each adapter the session has mounted ("https://", "http://", and your
    own) is wrapped in one that times its send and hands everything else to
    it, so its retries, pool and TLS settings stay as they are. Mount your
    own adapters before watching: one mounted after isn't timed."""
    timed = _adapter_class()
    for prefix, adapter in list(session.adapters.items()):
        if not getattr(type(adapter), "_analytics_platform", False):
            session.mount(prefix, timed(adapter))
    return session


TimedAdapter = None  # made on first use, so requests is imported only then


def _adapter_class():
    global TimedAdapter
    if TimedAdapter is not None:
        return TimedAdapter
    from requests.adapters import BaseAdapter

    class _TimedAdapter(BaseAdapter):
        _analytics_platform = True

        def __init__(self, inner):
            super().__init__()
            self.inner = inner

        def send(self, request, *args, **kwargs):
            # HTTPAdapter answers once the headers are in; the body is read after.
            started = call_started(request.url, request.method)
            if started is None:
                return self.inner.send(request, *args, **kwargs)
            try:
                response = self.inner.send(request, *args, **kwargs)
            except Exception:
                call_ended(started, 0)
                raise
            call_ended(started, getattr(response, "status_code", 0))
            return response

        def close(self):
            return self.inner.close()

        def __getattr__(self, name):
            if name == "inner":  # not set yet (a session being unpickled)
                raise AttributeError(name)
            return getattr(self.inner, name)

    # Named where pickle looks for it: a session can still be pickled.
    _TimedAdapter.__name__ = _TimedAdapter.__qualname__ = "TimedAdapter"
    TimedAdapter = _TimedAdapter
    return TimedAdapter


# ---- httpx ----

# The request -> what call_ended needs, from the request hook to the
# response hook. Weak: a request that never got an answer leaves nothing.
_pending = weakref.WeakKeyDictionary()
_lock = threading.Lock()


def _forked():
    # A lock held by another thread at the fork would never be let go.
    global _pending, _lock
    _pending, _lock = weakref.WeakKeyDictionary(), threading.Lock()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_forked)


def _take(request):
    """The request hook's start for request, which is then the caller's to end."""
    try:
        with _lock:
            return _pending.pop(request, None)
    except Exception:
        return None


# A hook that raised would fail the app's call: these never do.

def _request_hook(request):
    try:
        started = call_started(request.url, request.method)
        if started is not None:
            with _lock:
                _pending[request] = started
    except Exception:
        pass


def _response_hook(response):
    try:
        request = response.request
    except Exception:  # httpx raises RuntimeError for a response with none
        return
    call_ended(_take(request), getattr(response, "status_code", 0))


async def _async_request_hook(request):
    _request_hook(request)


async def _async_response_hook(response):
    _response_hook(response)


def _watch_httpx_client(client):
    import httpx
    asynchronous = isinstance(client, httpx.AsyncClient)
    before, after = (_async_request_hook, _async_response_hook) if asynchronous else (_request_hook, _response_hook)
    hooks = client.event_hooks
    requests_, responses = list(hooks.get("request", [])), list(hooks.get("response", []))
    if before in requests_:
        return client
    # Last before sending and first after the headers: your own hooks'
    # time (one that reads the body) isn't the call's.
    client.event_hooks = {**hooks, "request": requests_ + [before], "response": [after] + responses}
    return client


def _watch_httpx_transport(transport):
    if getattr(type(transport), "_analytics_platform", False):
        return transport
    return _timed_transport_class()(transport)


TimedTransport = None


def _timed_transport_class():
    """One wrapper for sync and async transports alike (httpx's
    MockTransport is both): each method hands over to the same one of the
    transport it wraps."""
    global TimedTransport
    if TimedTransport is not None:
        return TimedTransport
    import httpx

    class _TimedTransport(httpx.BaseTransport, httpx.AsyncBaseTransport):
        _analytics_platform = True

        def __init__(self, inner):
            self._inner = inner

        def __getattr__(self, name):
            if name == "_inner":
                raise AttributeError(name)
            return getattr(self._inner, name)

        def handle_request(self, request):
            _take(request)  # timed here, not by the client's hooks
            started = call_started(request.url, request.method)
            if started is None:
                return self._inner.handle_request(request)
            try:
                response = self._inner.handle_request(request)
            except Exception:
                call_ended(started, 0)
                raise
            call_ended(started, response.status_code)
            return response

        async def handle_async_request(self, request):
            _take(request)
            started = call_started(request.url, request.method)
            if started is None:
                return await self._inner.handle_async_request(request)
            try:
                response = await self._inner.handle_async_request(request)
            except Exception:  # cancelled (CancelledError) isn't one: not counted
                call_ended(started, 0)
                raise
            call_ended(started, response.status_code)
            return response

        def close(self):
            self._inner.close()

        async def aclose(self):
            await self._inner.aclose()

        def __enter__(self):
            self._inner.__enter__()
            return self

        def __exit__(self, *exc):
            self._inner.__exit__(*exc)

        async def __aenter__(self):
            await self._inner.__aenter__()
            return self

        async def __aexit__(self, *exc):
            await self._inner.__aexit__(*exc)

    _TimedTransport.__name__ = _TimedTransport.__qualname__ = "TimedTransport"
    TimedTransport = _TimedTransport
    return TimedTransport
