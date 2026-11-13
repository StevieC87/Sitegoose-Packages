"""Software inventory module (protocol in sdk/protocols/inventory.md): the
packages installed in the app's environment (importlib.metadata) and its
Python version, sent to POST /events/inventory a minute after start and then
once a day (the collector's `every`), so the Security check can match them
against known security holes. Runs in a background thread, never in a
request; names and versions only.
"""
import platform
import re
import socket
from datetime import datetime, timezone

from .core import Periodic

FIRST = 60
RETRY_EVERY = 60 * 60
EVERY = 24 * 60 * 60
MAX_PACKAGES = 5000


def installed_packages():
    """[{"ecosystem": "PyPI", "name", "version"}], one per distribution (by
    its normalized name), as published."""
    try:
        from importlib import metadata
    except ImportError:  # Python 3.7
        return []
    found = {}
    for dist in metadata.distributions():
        try:
            name = dist.metadata["Name"]
            version = dist.version
        except Exception:
            continue
        if not name or not version:
            continue
        key = re.sub(r"[-_.]+", "-", name).lower()
        found.setdefault(key, {"ecosystem": "PyPI", "name": name, "version": str(version)})
    return sorted(found.values(), key=lambda p: p["name"].lower())


class Inventory:
    """Options: host (the server's name; default the host name)."""

    def __init__(self, core, host=None, **_):
        self.core = core
        self.host = re.sub(r"[^A-Za-z0-9._-]", "-", str(host if host is not None else socket.gethostname()))[:100] or "server"
        self.job = Periodic(self._report, FIRST) if core.valid else None

    def _report(self):
        if not self.core.is_on("inventory"):
            return RETRY_EVERY
        packages = installed_packages()
        res = self.core.send("inventory", "/events/inventory", auth="bearer", body={
            "site_id": self.core.site_id,
            "host": self.host,
            "at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "runtime": {"python": platform.python_version()},
            "packages": packages[:MAX_PACKAGES],
            "truncated": len(packages) > MAX_PACKAGES,
        })
        if res is None or not res.ok:
            return RETRY_EVERY
        every = (res.json() or {}).get("every")
        return max(RETRY_EVERY, int(every)) if isinstance(every, int) and every > 0 else EVERY

    def flush(self):
        pass

    def close(self):
        if self.job:
            self.job.stop()
