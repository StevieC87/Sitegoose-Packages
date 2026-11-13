"""Maintenance mode module: while it's on (Site settings -> Server), visitors
get a "back soon" page (503, so search engines know it's temporary), except
allowed addresses and whoever opened the preview link (?site_preview=<code>,
remembered for a day in a cookie).
"""
import html
from urllib.parse import parse_qs

from .challenge import cookie_values, secure_compare
from .firewall import IpSet, ip_key

COOKIE = "site_preview"


def page(message):
    text = html.escape(message or "We're doing some maintenance. Please check back in a few minutes.")
    return ("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            "<title>Back soon</title><style>body{margin:0;min-height:100vh;display:grid;place-items:center;font:16px/1.5 system-ui,sans-serif;"
            "background:#f8fafc;color:#0f172a}main{max-width:32rem;padding:2rem;text-align:center}h1{font-size:1.6rem;margin:0 0 .5rem}"
            "p{color:#475569;margin:0}@media(prefers-color-scheme:dark){body{background:#0f172a;color:#e2e8f0}p{color:#94a3b8}}</style></head>"
            "<body><main><h1>Back soon</h1><p>%s</p></main></body></html>" % text).encode("utf-8")


class Maintenance:
    """Options: skip(path) -> True lets a request through (health checks)."""

    def __init__(self, core, skip=None, **_):
        self.core = core
        self.skip = skip
        self._allow_for = None
        self._allow = IpSet([])

    def decide(self, ip, path, query, cookie_header, secure=False):
        """None to let the request through, else (status, headers, body).
        secure: the request came over HTTPS (the cookie is then Secure)."""
        m = self.core.maintenance() if self.core.is_on("maintenance") else None
        if not m or not m.get("on") or (self.skip and self.skip(path)):
            return None
        if self._allow_for is not m.get("allow"):
            self._allow_for = m.get("allow")
            self._allow = IpSet(m.get("allow") or [])
        key = ip_key(ip)
        if key is not None and self._allow.has(key):
            return None
        code = m.get("bypass") or ""
        if code:
            # Compared in constant time: the code is a password to the site.
            if secure_compare(parse_qs(query or "").get(COOKIE, [""])[0], code):
                return ("pass", [("Set-Cookie", "%s=%s; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax%s"
                                  % (COOKIE, code, "; Secure" if secure else ""))])
            if any(secure_compare(value, code) for value in cookie_values(cookie_header, COOKIE)):
                return None
        return (503, [("Content-Type", "text/html; charset=utf-8"), ("Retry-After", "600"), ("Cache-Control", "no-store")], page(m.get("message")))

    def flush(self):
        pass

    def close(self):
        pass
