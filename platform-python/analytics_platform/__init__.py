"""One package for a site's Python server, run from the analytics dashboard:
firewall, error monitoring and server analytics. Each module is separate:
only the ones turned on are loaded, and one failing never stops the others;
the firewall in particular never waits on reporting. A loaded module can
also be switched off in the dashboard (Site settings -> Server).

    platform = create_platform(site_id=..., secret=..., endpoint=...)

    # FastAPI / Starlette          # Flask                  # Django: see analytics_platform.django
    app.add_middleware(            platform.init_flask(app)
        PlatformMiddleware, platform=platform)

A module is on with True (or its options as a dict) and off with False.
No dependencies; Python 3.8+.
"""
import asyncio
import atexit
import functools
import http
import time
import weakref

from . import _env
from .core import Core, EXIT_DEADLINE, SESSION_HEADER, VERSION, begin_exit, header, request_target, within
from .errors import add_breadcrumb, current_request, current_trail
from .queries import current_queries

__all__ = ["create_platform", "Platform", "PlatformMiddleware", "VERSION"]


def _load(name, core, opts):
    if name == "firewall":
        from .firewall import Firewall
        return Firewall(core, **opts)
    if name == "errors":
        from .errors import Errors
        return Errors(core, **opts)
    if name == "analytics":
        from .analytics import Analytics
        return Analytics(core, **opts)
    if name == "performance":
        from .performance import Performance
        return Performance(core, **opts)
    if name == "crawlers":
        from .crawlers import Crawlers
        return Crawlers(core, **opts)
    if name == "forms":
        from .forms import Forms
        return Forms(core, **opts)
    if name == "headers":
        return _Headers()
    if name == "audit":
        from .audit import Audit
        return Audit(core, **opts)
    if name == "flags":
        from .flags import Flags
        return Flags(core, **opts)
    if name == "maintenance":
        from .maintenance import Maintenance
        return Maintenance(core, **opts)
    if name == "inventory":
        from .inventory import Inventory
        return Inventory(core, **opts)
    if name == "posture":
        from .posture import Posture
        return Posture(core, **opts)
    if name == "resources":
        from .resources import Resources
        return Resources(core, **opts)
    if name == "proxy":
        from .proxy import Proxy
        return Proxy(core, **opts)
    raise ValueError(name)


MODULES = ("proxy", "firewall", "errors", "analytics", "performance", "crawlers", "forms", "headers", "audit", "flags", "maintenance", "inventory", "posture", "resources")


class Platform:
    """site_id, secret (site settings; keep it on the server), endpoint (the
    collector's URL), each read from ANALYTICS_SITE_ID, ANALYTICS_SITE_SECRET and
    ANALYTICS_ENDPOINT when left out; trust_proxy (ANALYTICS_TRUST_PROXY) (how to find the visitor's address: None
    uses the connection's, a number of proxies in X-Forwarded-For,
    "cloudflare"); debug (print send problems); per module True / False / {options}.
    client: the name this package goes by to the collector ("python", or
    "django", which the Django integration passes), so a request rule aimed
    at one framework reaches it. queries=False, calls=False and queues=False
    keep Server speed and leave database queries, outgoing calls or job
    queues out of it."""

    def __init__(self, site_id=None, secret=None, endpoint=None, trust_proxy=None, debug=False, firewall=True, errors=True, analytics=True,
                 performance=True, crawlers=True, forms=True, headers=True, audit=True, flags=True, maintenance=True,
                 inventory=True,
                 posture=True, resources=True, proxy=True, server_name=None, client="python", queries=True,
                 calls=True, queues=True):
        # Each of these left out is read from ANALYTICS_* in the environment (_env.py).
        given = _env.from_environment({"site_id": site_id, "secret": secret, "endpoint": endpoint,
                                       "trust_proxy": trust_proxy, "server_name": server_name})
        site_id, secret, endpoint = given["site_id"], given["secret"], given["endpoint"]
        trust_proxy, server_name = given["trust_proxy"], given["server_name"]
        self.core = Core(site_id, secret, endpoint, debug, server_name=server_name, client=client)
        if not self.core.valid:
            print("[analytics-platform] site_id, secret and endpoint are required (or ANALYTICS_SITE_ID, ANALYTICS_SITE_SECRET "
                  "and ANALYTICS_ENDPOINT in the environment); nothing is sent and every request passes")
        settings = {"firewall": firewall, "errors": errors, "analytics": analytics, "performance": performance,
                    "crawlers": crawlers, "forms": forms,
                    "headers": headers, "audit": audit, "flags": flags, "maintenance": maintenance, "inventory": inventory,
                    "posture": posture, "resources": resources, "proxy": proxy}
        self._modules = {}
        for name in MODULES:
            setting = settings[name]
            if setting is False or setting is None:
                continue
            opts = dict(setting) if isinstance(setting, dict) else {}
            if name == "firewall":
                opts.setdefault("trust_proxy", trust_proxy)
            # server_name names this service for every module that sends one,
            # so its errors, timings and resources can be told apart.
            if server_name and name in ("errors", "performance", "crawlers", "resources"):
                opts.setdefault("server_name", server_name)
            if name == "performance":
                opts.setdefault("queries", queries)
                opts.setdefault("calls", calls)
                opts.setdefault("queues", queues)
            # Inventory and posture call it host, and are stored one per site
            # and host: without it two services on one machine overwrite each other's.
            if server_name and name in ("inventory", "posture"):
                opts.setdefault("host", server_name)
            try:
                self._modules[name] = _load(name, self.core, opts)
            except Exception as error:
                print("[analytics-platform] the %s module could not start and is off: %s" % (name, error))
        # Requests in progress at once (the limits pass), from the request timing.
        if "performance" in self._modules and "resources" in self._modules:
            self._modules["resources"].inflight_peak = self._modules["performance"].take_inflight_peak
        self.core.start(list(self._modules))
        # At exit, what's waiting is sent within one deadline for every
        # module together (EXIT_DEADLINE): registered after the core's own
        # hook, so it runs before the background threads are stopped.
        if self.core.valid:
            atexit.register(_exit_flush, weakref.ref(self))

    # ---- Modules ----

    @property
    def modules(self):
        """The modules that are on."""
        return list(self._modules)

    @property
    def firewall(self):
        return self._modules.get("firewall")

    @property
    def proxy(self):
        """The first-party proxy: proxy.script_url() and proxy.collect_url()
        are the two addresses the page's script tag needs, on this site's own
        domain, so ad blockers have nothing of ours to recognise."""
        return self._modules.get("proxy")

    def proxy_response(self, path, method="GET", query="", headers=None, body=None, remote=""):
        """(status, [(name, value)], body) when the address belongs to the
        proxy, else None. Called first by every integration: a visitor's
        beacon is our traffic, not a page of the site, so it is answered
        before the firewall, the crawler count and the timing."""
        proxy = self._modules.get("proxy")
        if proxy is None:
            return None
        found = proxy.match(path)
        if found is None:
            return None
        kind, rest = found
        headers = headers or {}
        firewall = self._modules.get("firewall")
        ip = firewall.client_ip(remote, headers) if firewall else remote
        # Not past the address rules: a denied or banned address (deny, bans,
        # lists, shared) gets nothing from us either. Beacons are never rate
        # limited, checked or matched against request rules.
        if firewall:
            try:
                decision = firewall.check_address(ip, method, path, header(headers, "user-agent"))
                if decision["action"] == "block":
                    return 403, [("Content-Type", "text/plain; charset=utf-8"), ("Cache-Control", "no-store")], b"Forbidden"
            except Exception as error:
                self.core.log("firewall", "check failed, request passed:", error)
        try:
            return proxy.handle(kind, rest, method=method, query=query, headers=headers, body=body, client_ip=ip)
        except Exception as error:
            self.core.log("proxy", "failed:", error)
            return 502, [], b""

    def capture_exception(self, error, request=None, status=0, kind="handled"):
        errors = self._modules.get("errors")
        if errors:
            errors.capture_exception(error, request=request, status=status, kind=kind)

    def add_breadcrumb(self, text):
        """A step of your own in the trail shown before an error in this
        request or job."""
        if self._modules.get("errors"):
            add_breadcrumb(text)

    def job(self, name):
        """A background job (a queue consumer, a cron task), as a decorator or
        a with block: its errors are sent with the job's name as their route,
        and each run is timed (Health → Server speed → Jobs); a run that raises
        counts as failed, and the exception is raised on.

            @platform.job("send-receipts")
            def send_receipts(): ...

            with platform.job("nightly-import"): ...
        """
        return _Job(self, name)

    def init_celery(self, app=None):
        """Celery: every task of app (None: of every app) as a job(), named
        after the task. Call it where the app is made, so the worker runs it."""
        from .celery import connect
        connect(self, app)
        return app

    def rq_worker(self, base=None):
        """RQ: a worker class (base: default rq.Worker) whose jobs each run as
        a job(), named after the job's function: rq worker -w jobs.PlatformWorker."""
        from .rq import worker_class
        return worker_class(self, base)

    def init_dramatiq(self, broker=None):
        """Dramatiq: every message of broker (default the global one) as a
        job(), named after its actor."""
        from .dramatiq import connect
        return connect(self, broker)

    def login_failed(self, request_or_ip):
        """A failed login (bot protection): the address, or a Django, Flask or
        Starlette request (its address as trust_proxy says)."""
        firewall = self._modules.get("firewall")
        if not firewall:
            return
        ip = request_or_ip if isinstance(request_or_ip, str) else self.request_ip(request_or_ip)
        if ip:
            firewall.login_failed(ip)

    def request_ip(self, request):
        """The visitor's address for a Django, Flask or Starlette request."""
        firewall = self._modules.get("firewall")
        headers = getattr(request, "headers", None) or {}
        lowered = {str(k).lower(): v for k, v in headers.items()} if hasattr(headers, "items") else {}
        meta = getattr(request, "META", None)
        if meta is not None:
            remote = meta.get("REMOTE_ADDR", "")
        elif getattr(request, "client", None) is not None:
            remote = request.client.host or ""
        else:
            remote = getattr(request, "remote_addr", "") or ""
        return firewall.client_ip(remote, lowered) if firewall else remote

    def is_enabled(self, key, user=None, default=False):
        """A feature flag from the dashboard (user: for rollouts and user lists;
        default: until the flag is known, or with the module off)."""
        flags = self._modules.get("flags")
        return flags.is_enabled(key, user, default) if flags else default

    def maintenance_response(self, remote, headers, path, query, secure=None):
        """Maintenance mode: None to let the request through, ("pass", extra
        headers) to let it through and remember the preview link, or (status,
        headers, body) for the "back soon" page. secure: the request came
        over HTTPS (None: from X-Forwarded-Proto), so the preview cookie is Secure."""
        maintenance = self._modules.get("maintenance")
        if not maintenance:
            return None
        firewall = self._modules.get("firewall")
        try:
            ip = firewall.client_ip(remote, headers) if firewall else remote
            if not secure:
                secure = _forwarded_https(headers)
            return maintenance.decide(ip, path, query, header(headers, "cookie"), secure=bool(secure))
        except Exception as error:
            self.core.log("maintenance", "check failed, request passed:", error)
            return None

    def audit(self, action, actor="", target="", details=None, request=None):
        """Records who did what (Security -> Audit log). action: e.g.
        "user.role_changed"; request adds the actor's address and visit."""
        audit = self._modules.get("audit")
        if not audit:
            return
        try:
            ip = self.request_ip(request) if request is not None else ""
            audit.record(action, actor, target, details, ip, self.session_id(request) if request is not None else "")
        except Exception as error:
            self.core.log("audit", "could not record:", error)

    def check_form(self, request=None, fields=None, email=None, name=None, form=None):
        """Form protection: checks a form before you accept it. The form is
        request.POST (Django) or request.form (Flask), else pass fields (FastAPI:
        fields=dict(await request.form())). -> {"ok", "spam", "reasons", "checked"};
        spam goes to Leads -> Spam."""
        forms = self._modules.get("forms")
        if not forms:
            return {"ok": True, "spam": False, "reasons": [], "checked": False}
        if fields is None and request is not None:
            source = getattr(request, "POST", None)
            if source is None:
                source = getattr(request, "form", None)
            if source is not None:
                fields = {k: (source.getlist(k) if hasattr(source, "getlist") and len(source.getlist(k)) > 1 else source.get(k)) for k in source.keys()}
        try:
            return forms.check(fields or {}, self.request_ip(request) if request is not None else "", email, name, form)
        except Exception as error:
            self.core.log("forms", "could not check a form:", error)
            return {"ok": True, "spam": False, "reasons": ["unchecked"], "checked": False}

    def track(self, name, fields=None, session_id=""):
        analytics = self._modules.get("analytics")
        return analytics.track(name, fields, session_id) if analytics else ""

    def identify(self, user_id, session_id="", traits=None):
        analytics = self._modules.get("analytics")
        return analytics.identify(user_id, session_id, traits) if analytics else False

    def lead(self, fields, session_id=""):
        analytics = self._modules.get("analytics")
        return analytics.lead(fields, session_id) if analytics else None

    def security_headers(self, present=()):
        """The dashboard's security headers the response doesn't set itself
        (present: the header names it has)."""
        if "headers" not in self._modules:
            return []
        have = {str(name).lower() for name in present}
        return [(n, v) for n, v in self.core.security_headers() if n.lower() not in have]

    def time_request(self, method, route, status, started, path=""):
        """Records a finished request for Server speed (started:
        time.perf_counter()), and the database queries it ran under the same
        method and route."""
        performance = self._modules.get("performance")
        if performance:
            try:
                timed = performance.record(method, route, status, (time.perf_counter() - started) * 1000, path)
                if timed and performance.queries:
                    performance.queries.finish(timed[0], timed[1], current_queries.get())
            except Exception as error:
                self.core.log("performance", "could not time a request:", error)

    def watch_database(self, connection, db=None):
        """A DB-API connection (psycopg, psycopg2, mysqlclient, PyMySQL,
        sqlite3...) or a ClickHouse client (clickhouse-connect,
        clickhouse-driver) whose queries are timed for Server speed: use what
        it returns in its place. db: "postgresql", "mysql"... when the driver
        doesn't say. Django, SQLAlchemy and pymongo need nothing of this.
        A redis-py client (Redis, RedisCluster, sync or asyncio) or a Django
        cache on Redis is watched in place and handed back as itself."""
        queries = self._queries()
        if queries is None:
            return connection
        from .queries import watch_database
        try:
            return watch_database(connection, db)
        except Exception as error:
            self.core.log("performance", "watch_database: its queries aren't timed:", error)
            return connection

    def watch_http(self, client):
        """A requests Session, an httpx Client or AsyncClient, or an httpx
        transport whose outgoing calls are timed for Server speed (by host
        only): use what it returns. See analytics_platform.calls."""
        if self._calls() is None:
            return client
        try:
            from .calls import watch_http
            return watch_http(client)
        except Exception as error:
            self.core.log("performance", "watch_http: its calls aren't timed:", error)
            return client

    def watch_queue(self, queue_or_app, queues=None):
        """A Celery app (Redis broker; queues: the names to read, default
        its configured ones) or an RQ Queue, read once a minute for Server
        speed -> Jobs. Returns what it was given."""
        watcher = self._queues_module()
        return watcher.watch(queue_or_app, queues) if watcher is not None else queue_or_app

    def _queries(self):
        performance = self._modules.get("performance")
        queries = performance.queries if performance else None
        return queries if queries is not None and queries.has("queries") else None

    def _calls(self):
        performance = self._modules.get("performance")
        queries = performance.queries if performance else None
        return queries if queries is not None and queries.has("calls") else None

    def _queues_module(self):
        performance = self._modules.get("performance")
        return performance.queues if performance else None

    def record_crawler(self, user_agent, path, status, started=None, size=0, ip=""):
        """Records a finished request when it came from a crawler or AI bot
        (Off-site → Crawlers). started: time.perf_counter() when it arrived."""
        crawlers = self._modules.get("crawlers")
        if crawlers:
            try:
                ms = 0 if started is None else (time.perf_counter() - started) * 1000
                crawlers.middleware(user_agent, path, status, ms, size, ip)
            except Exception as error:
                self.core.log("crawlers", "could not count a crawler request:", error)

    @staticmethod
    def session_id(request):
        """The browser's visit, from a Django, Flask or Starlette request."""
        headers = getattr(request, "headers", None)
        try:
            value = headers.get(SESSION_HEADER) if headers is not None else ""
        except Exception:
            value = ""
        return value if isinstance(value, str) else ""

    def flush(self):
        """Sends everything waiting (serverless: before returning)."""
        for module in self._modules.values():
            try:
                module.flush()
            except Exception as error:
                self.core.log("core", "flush failed:", error)

    def flush_before_exit(self, seconds=EXIT_DEADLINE):
        """flush(), when the process is about to end (a worker shutting down):
        all of it within seconds, no retry sleeps, and the errors that
        weren't sent wait in the file for the next start."""
        with within(seconds):
            self.flush()

    def close(self):
        """Stops background work and sends what's waiting."""
        self.core.stop()
        for module in self._modules.values():
            module.close()

    # ---- Requests ----

    def blocked(self, remote, headers, method, path, late=None):
        """(status, body, headers) when the firewall turns the request away,
        else None. headers: a dict with lowercase names. path: the request
        target as sent, query string and all, not yet decoded (request_target).
        late: a dict given "static" when the request is a static file let
        through, for count_static() after the response."""
        firewall = self._modules.get("firewall")
        if not firewall:
            return None
        try:
            ip = firewall.client_ip(remote, headers)
            decision = firewall.check(ip, method, path, header(headers, "user-agent"),
                                      header(headers, "accept"), header(headers, "cookie"))
            if decision["action"] == "block" and decision["rule"] == "challenge":
                status, extra, body = firewall.challenge_page(ip, method)
                return status, body, extra
            if late is not None and decision.get("static") and decision["action"] != "block":
                late["static"] = decision["static"]
        except Exception as error:
            self.core.log("firewall", "check failed, request passed:", error)
            return None
        if decision["action"] != "block":
            return None
        extra = [("Content-Type", "text/plain; charset=utf-8"), ("Cache-Control", "no-store")]
        if decision["status"] == 429:
            from .firewall import LIMIT_BODY
            extra.append(("Retry-After", firewall.retry_after(decision["rule"])))
            return 429, LIMIT_BODY if decision["rule"].startswith("limit:") else b"Too Many Requests", extra
        return 403, b"Forbidden", extra

    def count_static(self, late, status, routed=False):
        """After the response: a static-looking request blocked() let through
        (late["static"]) counts toward the rate and the page limits after all
        when it answered 400 or more or the router sent it to a page
        (firewall.md, `rate`). Never raises."""
        firewall = self._modules.get("firewall")
        if not firewall or not late or not late.get("static"):
            return
        try:
            firewall.count_static(late["static"], status, routed)
        except Exception as error:
            self.core.log("firewall", "could not count a static file:", error)

    def wsgi(self, app, timing=True):
        """WSGI middleware (Flask, Bottle, Pyramid, plain WSGI). timing=False
        leaves timing to the framework integration (Flask, which knows the route)."""
        platform = self
        self._adopt_proxy_fix(app)

        def middleware(environ, start_response):
            started = time.perf_counter()
            headers = {k[5:].replace("_", "-").lower(): v for k, v in environ.items() if k.startswith("HTTP_")}
            if environ.get("CONTENT_TYPE"):
                headers["content-type"] = environ["CONTENT_TYPE"]
            answered = platform.proxy_response(
                environ.get("PATH_INFO", ""), environ.get("REQUEST_METHOD", ""), environ.get("QUERY_STRING", ""),
                headers, _wsgi_body(environ), environ.get("REMOTE_ADDR", ""))
            if answered:
                status, extra, body = answered
                start_response("%d " % status, list(extra))
                return [body]
            late = {}
            blocked = platform.blocked(environ.get("REMOTE_ADDR", ""), headers, environ.get("REQUEST_METHOD", ""),
                                       _wsgi_target(environ), late)
            if blocked:
                status, body, extra = blocked
                start_response("%d %s" % (status, _reason(status)), extra)
                return [body]
            closed = platform.maintenance_response(environ.get("REMOTE_ADDR", ""), headers, environ.get("PATH_INFO", ""),
                                                   environ.get("QUERY_STRING", ""), environ.get("wsgi.url_scheme") == "https")
            if closed and closed[0] != "pass":
                start_response("503 Service Unavailable", closed[1])
                return [closed[2]]
            remember = closed[1] if closed else []
            seen = {"status": 500}

            def timed_start_response(status, response_headers, exc_info=None):
                try:
                    seen["status"] = int(str(status).split(" ", 1)[0])
                except ValueError:
                    pass
                seen["started"] = True
                if late:
                    seen["type"] = next((v for n, v in response_headers if str(n).lower() == "content-type"), "")
                response_headers = list(response_headers) + platform.security_headers(n for n, _ in response_headers) + remember
                return start_response(status, response_headers, exc_info) if exc_info else start_response(status, response_headers)

            trail = current_trail.set([])
            queries = _queries_start(platform)
            inflight = _inflight_start(platform)
            try:
                result = app(environ, timed_start_response)
                # A static-looking request counts once its body is sent (the
                # server closes the iterable): toward the rate and the page
                # limits when it answered 400 or more, or Flask routed it to a
                # view (init_flask leaves the word in the environ). Plain WSGI
                # has no router to ask, so there only an error counts.
                if not late or _nothing_to_count(environ, seen):
                    # A file a page asked for, answered already: the server's
                    # own file wrapper (sendfile) is left as it is.
                    return result
                return _Counted(result, lambda: platform.count_static(
                    late, seen["status"], _wsgi_routed(environ, seen.get("type", ""))))
            except Exception as error:
                if late:
                    platform.count_static(late, 500)
                platform.capture_exception(error, status=500, kind="error", request={
                    "method": environ.get("REQUEST_METHOD", ""), "path": environ.get("PATH_INFO", ""),
                    "session_id": headers.get(SESSION_HEADER, ""),
                })
                raise
            finally:
                current_trail.reset(trail)
                _inflight_end(inflight)
                try:
                    if timing:
                        platform.time_request(environ.get("REQUEST_METHOD", ""), "", seen["status"], started, environ.get("PATH_INFO", ""))
                finally:
                    _queries_end(queries)

        return middleware

    def _adopt_proxy_fix(self, app):
        """werkzeug's ProxyFix inside this middleware (app.wsgi_app = ProxyFix(...)
        before init_flask or wsgi()) resolves the address only after the
        firewall has looked: with trust_proxy unset, the firewall then reads
        X-Forwarded-For with ProxyFix's own x_for, so the two agree on who
        the visitor is. Outside it, ProxyFix has already set REMOTE_ADDR, and
        unset trust_proxy uses that. A trust_proxy you set always wins."""
        firewall = self._modules.get("firewall")
        if firewall is None or firewall.trust_proxy is not None:
            return
        seen = 0
        while app is not None and seen < 10:
            if type(app).__name__ == "ProxyFix" and type(app).__module__.startswith("werkzeug"):
                hops = getattr(app, "x_for", 0)
                if isinstance(hops, int) and hops > 0:
                    firewall.trust_proxy = hops
                return
            app = getattr(app, "app", None)
            seen += 1

    def init_flask(self, app):
        """Flask: the firewall in front of the app, and its request errors."""
        # Once per app, by hand or by analytics_platform.start.
        extensions = getattr(app, "extensions", None)
        if isinstance(extensions, dict):
            if "analytics_platform" in extensions:
                return app
            extensions["analytics_platform"] = self
        app.wsgi_app = self.wsgi(app.wsgi_app, timing=False)
        from flask import g, got_request_exception, request

        @app.before_request
        def _analytics_started():
            g._analytics_started = time.perf_counter()

        @app.after_request
        def _analytics_timed(response):
            # The rule the request matched, for a static-looking request's
            # count after the response (wsgi() above): Flask's own static
            # endpoint (and a blueprint's) serves files.
            try:
                rule = getattr(request, "url_rule", None)
                if rule is not None and rule.endpoint != "static" and not str(rule.endpoint).endswith(".static"):
                    request.environ[_ROUTE_KEY] = rule.rule
            except Exception:
                pass
            started = getattr(g, "_analytics_started", None)
            if started is not None:
                rule = getattr(request, "url_rule", None)
                self.time_request(request.method, getattr(rule, "rule", ""), response.status_code, started, request.path)
            return response

        def on_error(sender, exception, **_):
            rule = getattr(request, "url_rule", None)
            self.capture_exception(exception, status=500, kind="error", request={
                "method": request.method, "path": request.path, "route": getattr(rule, "rule", ""),
                "session_id": request.headers.get(SESSION_HEADER, ""),
            })

        got_request_exception.connect(on_error, app, weak=False)
        return app

    def asgi(self, app):
        """ASGI middleware around any ASGI app (FastAPI, Starlette, Django ASGI)."""
        return PlatformMiddleware(app, platform=self)


def _exit_flush(ref):
    platform = ref()
    if platform is not None:
        begin_exit()
        platform.flush()


def _queries_start(platform):
    """A request or job starts: the queries it runs are kept for it."""
    performance = (getattr(platform, "_modules", None) or {}).get("performance")
    queries = getattr(performance, "queries", None)
    return current_queries.set(queries.request()) if queries else None


def _inflight_start(platform):
    """A request starts (not a job): counted as in progress until it ends."""
    performance = (getattr(platform, "_modules", None) or {}).get("performance")
    if performance is None:
        return None
    performance.request_started()
    return performance


def _inflight_end(performance):
    if performance is not None:
        performance.request_ended()


def _queries_end(token):
    """The request or job has finished: queries after this are another's."""
    if token is not None:
        try:
            current_queries.reset(token)
        except ValueError:  # set in another context
            current_queries.set(None)


def _forwarded_https(headers):
    """A TLS-ending proxy's word that the visitor is on https. Only ever used
    to add Secure to a cookie: a visitor who lies gets a cookie their own
    plain-http browser won't send back."""
    return header(headers, "x-forwarded-proto").split(",")[0].strip().lower() == "https"


def _reason(status):
    try:
        return http.HTTPStatus(status).phrase
    except ValueError:
        return ""


def _wsgi_target(environ):
    # gunicorn keeps the target as sent (RAW_URI), uWSGI and mod_wsgi too
    # (REQUEST_URI); PATH_INFO is decoded, and PEP 3333 hands its bytes over as latin-1.
    path = environ.get("SCRIPT_NAME", "") + environ.get("PATH_INFO", "")
    try:
        path = path.encode("latin-1")
    except UnicodeEncodeError:
        pass
    return request_target(path, environ.get("QUERY_STRING", ""), environ.get("RAW_URI") or environ.get("REQUEST_URI"))


def _wsgi_body(environ):
    try:
        length = int(environ.get("CONTENT_LENGTH") or 0)
    except ValueError:
        return b""
    return environ["wsgi.input"].read(length) if length > 0 else b""


class _Headers:
    """The security headers module: the headers come with the module switches (core)."""

    def flush(self):
        pass

    def close(self):
        pass


class _Job:
    """platform.job(name): a with block (sync or async) or a decorator."""

    def __init__(self, platform, name):
        self.platform = platform
        self.name = name
        self.route = "/(job) " + str(name or "job")[:180]
        self._runs = []

    def _fields(self):
        return {"method": "JOB", "path": self.route, "route": self.route, "session_id": ""}

    def __enter__(self):
        self._runs.append((time.perf_counter(), current_request.set(self._fields), current_trail.set([]),
                           _queries_start(self.platform)))
        return self

    def __exit__(self, kind, value, tb):
        if value is not None and not isinstance(value, Exception):
            self._leave(None)  # cancelled or interrupted (CancelledError, KeyboardInterrupt): not a run that failed
        else:
            self._leave(500 if value is not None else 200, value)
        return False

    def _leave(self, status, error=None):
        """Ends the latest run: its error sent, and timed with status (None: not timed)."""
        started, token, trail, queries = self._runs.pop()
        current_request.reset(token)
        try:
            if error is not None:
                self.platform.capture_exception(error, status=500, kind="error", request=self._fields())
            if status is not None:
                self.platform.time_request("JOB", self.route, status, started, self.route)
        finally:
            current_trail.reset(trail)
            _queries_end(queries)

    async def __aenter__(self):
        return self.__enter__()

    async def __aexit__(self, kind, value, tb):
        return self.__exit__(kind, value, tb)

    def __call__(self, fn):
        if asyncio.iscoroutinefunction(fn):
            @functools.wraps(fn)
            async def run_async(*args, **kwargs):
                with _Job(self.platform, self.name):
                    return await fn(*args, **kwargs)
            return run_async

        @functools.wraps(fn)
        def run(*args, **kwargs):
            with _Job(self.platform, self.name):
                return fn(*args, **kwargs)
        return run


_ROUTE_KEY = "analytics_platform.route"


def _wsgi_routed(environ, content_type):
    """Whether the router sent a WSGI request to a page: the route a
    framework integration left in the environ (init_flask), else none."""
    from .firewall import routed_to_page
    return routed_to_page(environ.get(_ROUTE_KEY), content_type)


def _nothing_to_count(environ, seen):
    """A WSGI response already started (its status known) that won't count
    toward the rate and the page limits: under 400, and not routed to a page
    (or a 304)."""
    try:
        if not seen.get("started"):
            return False
        status = seen["status"]
        return status < 400 and (status == 304 or not _wsgi_routed(environ, seen.get("type", "")))
    except Exception:
        return False


class _Counted:
    """A WSGI response that runs `done` once the server has sent it (close),
    passing the server's close() on. Only wraps a static-looking request."""

    def __init__(self, result, done):
        self._result = result
        self._done = done

    def __iter__(self):
        return iter(self._result)

    def close(self):
        try:
            close = getattr(self._result, "close", None)
            if close is not None:
                close()
        finally:
            done, self._done = self._done, None
            if done:
                done()


def _asgi_routed(scope, content_type):
    """Whether Starlette's router (FastAPI's too) sent the request to a
    route: scope["route"] (FastAPI) or the endpoint Starlette left in the
    scope. A StaticFiles mount serves files."""
    from .firewall import routed_to_page
    route = scope.get("route")
    endpoint = scope.get("endpoint")
    app = getattr(route, "app", None) if route is not None else endpoint
    if type(app).__name__ == "StaticFiles" or type(endpoint).__name__ == "StaticFiles":
        return False
    pattern = getattr(route, "path", None) if route is not None else ("*" if endpoint is not None else None)
    return routed_to_page(pattern, content_type)


class PlatformMiddleware:
    """ASGI middleware: app.add_middleware(PlatformMiddleware, platform=platform)."""

    def __init__(self, app, platform):
        self.app = app
        self.platform = platform

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            return await self.app(scope, receive, send)
        headers = {}
        for k, v in scope.get("headers") or []:
            name, value = k.decode("latin-1").lower(), v.decode("latin-1")
            # HTTP/2 may split cookies over several fields (RFC 9113 8.2.3);
            # any other header sent twice is one list (X-Forwarded-For from
            # two proxies that each added a line), as WSGI servers join it.
            if name in headers:
                headers[name] = headers[name] + ("; " if name == "cookie" else ", ") + value
            else:
                headers[name] = value
        client = scope.get("client") or ("",)
        # The tracker's own addresses, answered before anything else: a
        # visitor's beacon is our traffic, not a page of the site. Sending
        # runs in a thread, so the event loop keeps turning while it waits.
        proxy = self.platform.proxy
        if proxy is not None and proxy.match(scope.get("path", "")) is not None:
            body = b""
            while True:
                message = await receive()
                body += message.get("body", b"") or b""
                if not message.get("more_body"):
                    break
            answered = await asyncio.get_running_loop().run_in_executor(
                None,
                lambda: self.platform.proxy_response(
                    scope.get("path", ""), scope.get("method", ""),
                    scope.get("query_string", b"").decode("latin-1"), headers, body, client[0] or ""),
            )
            status, extra, out = answered or (404, [], b"")
            await send({"type": "http.response.start", "status": status,
                        "headers": [(k.lower().encode(), str(v).encode()) for k, v in extra]})
            await send({"type": "http.response.body", "body": out})
            return
        # raw_path is the path as sent; servers that leave it out get path encoded again.
        target = request_target(scope.get("path", ""), scope.get("query_string", b""), scope.get("raw_path"))
        late = {}
        blocked = self.platform.blocked(client[0] or "", headers, scope.get("method", ""), target, late)
        if blocked:
            status, body, extra = blocked
            await send({"type": "http.response.start", "status": status,
                        "headers": [(k.lower().encode(), v.encode()) for k, v in extra]})
            await send({"type": "http.response.body", "body": body})
            return
        query = scope.get("query_string", b"").decode("latin-1")
        closed = self.platform.maintenance_response(client[0] or "", headers, scope.get("path", ""), query,
                                                    scope.get("scheme") in ("https", "wss"))
        if closed and closed[0] != "pass":
            await send({"type": "http.response.start", "status": 503, "headers": [(k.lower().encode(), v.encode()) for k, v in closed[1]]})
            await send({"type": "http.response.body", "body": closed[2]})
            return
        remember = [(k.lower().encode(), v.encode()) for k, v in closed[1]] if closed else []
        started = time.perf_counter()
        seen = {"status": 500}

        async def timed_send(message):
            if message.get("type") == "http.response.start":
                seen["status"] = int(message.get("status") or 500)
                if late:
                    seen["type"] = next((v.decode("latin-1") for k, v in message.get("headers") or [] if k.lower() == b"content-type"), "")
                present = [k.decode("latin-1") for k, _ in message.get("headers") or []]
                extra = self.platform.security_headers(present)
                if extra or remember:
                    message = dict(message, headers=list(message.get("headers") or []) + [(n.lower().encode(), v.encode("latin-1", "replace")) for n, v in extra] + remember)
            await send(message)

        # Errors captured during the request (logged, or caught without the
        # request) still know which request they came from. The router sets
        # scope["route"] on the way in, so it is read when the error is.
        token = current_request.set(lambda: {
            "method": scope.get("method", ""), "path": scope.get("path", ""),
            "route": getattr(scope.get("route"), "path", ""), "session_id": headers.get(SESSION_HEADER, ""),
        })
        trail = current_trail.set([])
        queries = _queries_start(self.platform)
        inflight = _inflight_start(self.platform)
        try:
            await self.app(scope, receive, timed_send)
        except asyncio.CancelledError:
            # The visitor went away (a page left while its files load): no
            # answer, and not the app's error.
            seen["gone"] = True
            raise
        except Exception as error:
            self.platform.capture_exception(error, status=500, kind="error", request={
                "method": scope.get("method", ""), "path": scope.get("path", ""),
                "route": getattr(scope.get("route"), "path", ""), "session_id": headers.get(SESSION_HEADER, ""),
            })
            raise
        finally:
            current_request.reset(token)
            current_trail.reset(trail)
            _inflight_end(inflight)
            # The router sets scope["route"] (FastAPI, Starlette) on the way in.
            try:
                self.platform.time_request(scope.get("method", ""), getattr(scope.get("route"), "path", "") or "",
                                           seen["status"], started, scope.get("path", ""))
            finally:
                _queries_end(queries)
                # A static-looking request, once its body is sent: counted when
                # it answered 400 or more or the router sent it to a route.
                if late and not (seen.get("gone") and "type" not in seen):
                    try:
                        routed = _asgi_routed(scope, seen.get("type", ""))
                    except Exception:
                        routed = False
                    self.platform.count_static(late, seen["status"], routed)


def create_platform(**options):
    return Platform(**options)
