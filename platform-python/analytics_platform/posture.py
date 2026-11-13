"""How the server is set up (protocol in sdk/protocols/posture.md): the
settings that leave the app open (Django's, when it's a Django site), whether
it runs as root, code anyone on the machine can write, and files in the
folders it serves to the web that should never be public. Sent to
POST /events/posture a few minutes after start and then once a day (the
collector's `every`), so Security -> Security check can say what to change.

It only reads: nothing here changes a setting, a permission or a file, and no
file's contents are sent -- paths, sizes, times and short values only. The
walk is bounded and runs in a background thread, never in a request; with no
folder served to the web there is nothing to walk and only the settings are
reported.
"""
import os
import re
import socket
import stat
from datetime import datetime, timezone

from .core import Periodic

FIRST = 180
RETRY_EVERY = 60 * 60
EVERY = 24 * 60 * 60
MAX_CHECKS = 200
MAX_EXPOSURE = 50
MAX_ENTRIES = 20000
MAX_DEPTH = 6
MAX_PERM_CHECKS = 3000
SKIP_DIRS = {".git", ".svn", ".hg", "node_modules", "vendor", "cache", ".cache", ".history", "__pycache__"}
CODE_FILE = re.compile(r"\.(py|pyw|js|cjs|mjs|php[0-9]?|phtml|rb|pl|sh)\Z", re.I)
# Files that shouldn't be downloadable, by name; first match wins.
EXPOSURE = [
    ("database_dump", re.compile(r"\.sql(\.(gz|bz2|xz|zip))?\Z", re.I)),
    ("private_key", re.compile(r"^(id_rsa|id_dsa|id_ecdsa|id_ed25519)\Z|\.(pem|key|p12|pfx|jks)\Z", re.I)),
    ("env", re.compile(r"^\.env(\Z|\.)|^env\.(ini|txt)\Z", re.I)),
    ("archive", re.compile(r"\.(zip|tar|tgz|tar\.gz|tar\.bz2|rar|7z)\Z", re.I)),
    ("backup", re.compile(r"\.(bak|old|orig|save|swp|copy|backup)\Z|~\Z|\.(py|json|conf|config|ini|ya?ml)\.(bak|old|orig|save|txt)\Z", re.I)),
    ("info", re.compile(r"^(phpinfo|info|adminer)\.php\Z", re.I)),
    ("log", re.compile(r"^(debug|error|access)[-_.]?log\Z|\.log\Z", re.I)),
]
# Django's own placeholders, and what a key looks like when nobody set one.
INSECURE_KEYS = ("django-insecure-", "changeme", "secret", "your-secret-key", "put-your-secret-key-here")


def kind_of(name):
    for kind, pattern in EXPOSURE:
        if pattern.search(name):
            return kind
    return None


def without_nested(roots):
    """A folder inside another folder on the list is already covered: without
    this, every file under it would be reported twice."""
    unique = {}
    for root in roots:
        unique.setdefault(root["dir"], root)
    return [root for root in unique.values()
            if not any(other != root["dir"] and (root["dir"] + "/").startswith(other + "/") for other in unique)]


def roots_of(given):
    """[{"dir", "prefix"}]: `prefix` is where the web serves the folder, so the
    path we report is the one the dashboard can ask the site for. Not told:
    Django's STATIC_ROOT and MEDIA_ROOT, when they're set and there."""
    roots = []
    for entry in given or []:
        folder = entry.get("dir") if isinstance(entry, dict) else entry
        if not folder:
            continue
        prefix = str(entry.get("prefix") or "").strip("/") if isinstance(entry, dict) else ""
        roots.append({"dir": os.path.abspath(str(folder)), "prefix": prefix})
    if roots:
        return without_nested(roots)
    for folder, url in django_static_dirs():
        if folder and os.path.isdir(folder):
            roots.append({"dir": os.path.abspath(folder), "prefix": str(url or "").strip("/")})
    return without_nested(roots)


def django_settings():
    """Django's settings, or None when this isn't a configured Django site."""
    try:
        from django.conf import settings
        if not settings.configured:
            return None
        settings.DEBUG  # raises when there are no settings to read
        return settings
    except Exception:
        return None


def django_static_dirs():
    settings = django_settings()
    if settings is None:
        return []
    out = []
    for folder, url in ((getattr(settings, "STATIC_ROOT", None), getattr(settings, "STATIC_URL", "")),
                        (getattr(settings, "MEDIA_ROOT", None), getattr(settings, "MEDIA_URL", ""))):
        if folder:
            out.append((str(folder), str(url or "")))
    return out


def django_checks():
    """The Django settings that decide how much a hole in the site is worth."""
    settings = django_settings()
    if settings is None:
        return []
    checks = []

    def add(check_id, failed, value=""):
        row = {"id": check_id, "state": "unknown" if failed is None else ("fail" if failed else "pass")}
        if value:
            row["value"] = value
        checks.append(row)

    add("app.django_debug", bool(getattr(settings, "DEBUG", False)))
    key = str(getattr(settings, "SECRET_KEY", "") or "")
    add("app.secret_key", not key or len(key) < 32 or any(mark in key.lower() for mark in INSECURE_KEYS))
    hosts = list(getattr(settings, "ALLOWED_HOSTS", []) or [])
    add("app.allowed_hosts", "*" in hosts, ", ".join(str(h) for h in hosts[:10]))
    # Cookie flags only matter once the site is on HTTPS, which these say it is.
    https = bool(getattr(settings, "SECURE_SSL_REDIRECT", False)) or bool(getattr(settings, "SESSION_COOKIE_SECURE", False)) \
        or bool(getattr(settings, "CSRF_COOKIE_SECURE", False)) or bool(getattr(settings, "SECURE_HSTS_SECONDS", 0))
    add("app.session_cookie_httponly", not getattr(settings, "SESSION_COOKIE_HTTPONLY", True))
    if https:
        add("app.session_cookie_secure", not getattr(settings, "SESSION_COOKIE_SECURE", False))
        add("app.csrf_cookie_secure", not getattr(settings, "CSRF_COOKIE_SECURE", False))
        add("app.https_redirect", not getattr(settings, "SECURE_SSL_REDIRECT", False))
    return checks


def app_checks():
    checks = []
    for check in django_checks():
        checks.append(check)
    if hasattr(os, "getuid"):
        # Running the web app as root turns any hole in it into the whole machine.
        checks.append({"id": "server.runs_as_root", "state": "fail" if os.getuid() == 0 else "pass"})
    return checks


def walk(roots):
    """One bounded walk per root: (exposure, writable or None, examples, truncated)."""
    exposure, examples = [], []
    writable = checked = entries = 0
    for root in roots:
        queue = [(root["dir"], 0)]
        while queue:
            folder, depth = queue.pop(0)
            try:
                names = os.listdir(folder)
            except OSError:
                continue
            for name in names:
                entries += 1
                if entries > MAX_ENTRIES:
                    return exposure, (writable if checked else None), examples, True
                path = os.path.join(folder, name)
                if os.path.islink(path):
                    continue
                relative = "/".join(p for p in (root["prefix"], os.path.relpath(path, root["dir"]).replace(os.sep, "/")) if p)
                if os.path.isdir(path):
                    if name in (".git", ".svn", ".hg", ".bzr"):
                        if len(exposure) < MAX_EXPOSURE:
                            exposure.append({"path": relative + "/config", "kind": "vcs"})
                        continue
                    if depth + 1 <= MAX_DEPTH and name not in SKIP_DIRS:
                        queue.append((path, depth + 1))
                    continue
                if not os.path.isfile(path):
                    continue
                kind = kind_of(name)
                if kind and len(exposure) < MAX_EXPOSURE:
                    row = {"path": relative, "kind": kind}
                    try:
                        info = os.stat(path)
                        row["size"] = info.st_size
                        row["mtime"] = datetime.fromtimestamp(info.st_mtime, timezone.utc).isoformat().replace("+00:00", "Z")
                    except OSError:
                        pass
                    exposure.append(row)
                if checked < MAX_PERM_CHECKS and CODE_FILE.search(name):
                    checked += 1
                    try:
                        if os.stat(path).st_mode & stat.S_IWOTH:
                            writable += 1
                            if len(examples) < 3:
                                examples.append(relative)
                    except OSError:
                        pass
    return exposure, (writable if checked else None), examples, False


class Posture:
    """Options: roots (the folders the web serves, as "public" or
    {"dir": ..., "prefix": "static"}; default: Django's STATIC_ROOT and
    MEDIA_ROOT), host (the server's name), checks (a callable returning more
    checks of your own)."""

    def __init__(self, core, roots=None, host=None, checks=None, **_):
        self.core = core
        self.roots = roots_of(roots)
        self.extra = checks
        self.host = re.sub(r"[^A-Za-z0-9._-]", "-", str(host if host is not None else socket.gethostname()))[:100] or "server"
        self.job = Periodic(self._report, FIRST) if core.valid else None

    def report(self):
        """What would be reported now (also used by the job and by tests)."""
        exposure, writable, examples, truncated = walk(self.roots)
        checks = app_checks()
        if writable is not None:
            row = {"id": "server.code_writable", "state": "fail" if writable else "pass"}
            if writable:
                row["value"] = "%d files, e.g. %s" % (writable, ", ".join(examples))
            checks.append(row)
        try:
            for check in (self.extra() if callable(self.extra) else []) or []:
                if isinstance(check, dict) and check.get("id") and check.get("state") in ("pass", "fail", "unknown"):
                    row = {"id": str(check["id"]).lower()[:60], "state": check["state"]}
                    if check.get("value"):
                        row["value"] = str(check["value"])[:200]
                    checks.append(row)
        except Exception:
            pass
        import platform as _platform
        body = {
            "site_id": self.core.site_id,
            "host": self.host,
            "at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "checks": checks[:MAX_CHECKS],
            "facts": {"agent": "python/%s" % _platform.python_version()},
        }
        if self.roots:
            # Left out when there's no folder to walk: the dashboard then says
            # this wasn't checked, instead of taking an empty walk for a clean one.
            body["exposure"] = exposure[:MAX_EXPOSURE]
            body["facts"]["webroot"] = self.roots[0]["dir"]
        if truncated:
            body["truncated"] = True
        return body

    def _report(self):
        # The set-up checks ride the software inventory switch.
        if not self.core.is_on("inventory"):
            return RETRY_EVERY
        res = self.core.send("posture", "/events/posture", auth="bearer", body=self.report())
        if res is None or not getattr(res, "ok", False):
            return RETRY_EVERY
        try:
            answer = res.json()
        except Exception:
            answer = {}
        every = int(answer.get("every") or EVERY) if isinstance(answer, dict) else EVERY
        return max(RETRY_EVERY, every)

    def flush(self):
        pass

    def close(self):
        if self.job:
            self.job.stop()
