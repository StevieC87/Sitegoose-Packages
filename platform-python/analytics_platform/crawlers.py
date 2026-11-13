"""Crawlers module: counts the search engines and AI bots that fetch the site
and sends one row a minute per bot, page and status to POST /events/crawlers
(the protocol is sdk/protocols/crawlers.md). This traffic is invisible to the
browser tracker, because crawlers don't run JavaScript: the server is the only
place it can be counted.

Only requests whose user agent names a known crawler are counted, so visitors
are never counted twice. Nothing about a visitor is sent; bot addresses go
with the batch only so the collector can check a crawler is itself, and are
not stored.
"""
import platform as host
import re
import socket
import threading
import time
from datetime import datetime, timezone

from .core import Periodic

FLUSH_EVERY = 60
MAX_KEYS = 300
# Past MAX_KEYS new paths fold into "(other)"; past this nothing new is kept
# until the next send.
HARD_MAX_KEYS = MAX_KEYS + 100
MAX_ROWS = 500
MAX_IPS_PER_BOT = 5
MAX_PATH = 400

# The catalogue of the protocol, most specific first: "ChatGPT-User" must be
# tried before "GPTBot", "Claude-User" before "ClaudeBot". Keep in step with
# the collector (expresscollect/Analytics/crawlers.js CATALOGUE).
BOTS = [
    # Fetched because a person asked an AI about the page.
    ("ChatGPT-User", r"ChatGPT-User"),
    ("OAI-SearchBot", r"OAI-SearchBot"),
    ("Perplexity-User", r"Perplexity-User"),
    ("Claude-User", r"Claude-User"),
    ("Claude-SearchBot", r"Claude-SearchBot"),
    ("MistralAI-User", r"MistralAI-User"),
    ("MistralAI-SearchBot", r"MistralAI-SearchBot"),
    ("Meta-ExternalFetcher", r"meta-externalfetcher"),
    # Bulk collection, for training or a dataset.
    ("GPTBot", r"GPTBot"),
    ("ClaudeBot", r"ClaudeBot|Claude-Web"),
    ("anthropic-ai", r"anthropic-ai"),
    ("CCBot", r"CCBot"),
    ("Bytespider", r"Bytespider"),
    ("Meta-ExternalAgent", r"meta-externalagent|facebookbot"),
    ("Amazonbot", r"Amazonbot"),
    ("Diffbot", r"Diffbot"),
    ("omgili", r"omgili"),
    ("AI2Bot", r"AI2Bot"),
    ("Timpibot", r"Timpibot"),
    ("Webzio-Extended", r"Webzio-Extended"),
    ("PerplexityBot", r"PerplexityBot"),
    ("DuckAssistBot", r"DuckAssistBot"),
    ("YouBot", r"YouBot"),
    # Search engines. Google's tools before Googlebot itself.
    ("Google-InspectionTool", r"Google-InspectionTool"),
    ("Storebot-Google", r"Storebot-Google"),
    ("AdsBot-Google", r"AdsBot-Google"),
    ("Googlebot", r"Googlebot|Google-Site-Verification"),
    ("bingbot", r"bingbot|BingPreview|adidxbot"),
    ("YandexBot", r"Yandex(Bot|Mobile|Images|Webmaster)?"),
    ("Baiduspider", r"Baiduspider"),
    ("DuckDuckBot", r"DuckDuckBot|DuckDuckGo-Favicons"),
    ("Applebot", r"Applebot"),
    ("PetalBot", r"PetalBot|AspiegelBot"),
    ("SeznamBot", r"SeznamBot"),
    ("Yeti", r"Yeti/"),
    ("MojeekBot", r"MojeekBot"),
    ("Qwantbot", r"Qwantbot|Qwantify"),
    # SEO and backlink tools.
    ("AhrefsBot", r"AhrefsBot|AhrefsSiteAudit"),
    ("SemrushBot", r"SemrushBot|SiteAuditBot"),
    ("DotBot", r"DotBot"),
    ("MJ12bot", r"MJ12bot"),
    ("BLEXBot", r"BLEXBot"),
    ("DataForSeoBot", r"DataForSeoBot"),
    ("Barkrowler", r"Barkrowler"),
    ("ScreamingFrog", r"Screaming\s?Frog"),
    ("ZoominfoBot", r"ZoominfoBot"),
    # Link previews.
    ("facebookexternalhit", r"facebookexternalhit"),
    ("Twitterbot", r"Twitterbot"),
    ("LinkedInBot", r"LinkedInBot"),
    ("Slackbot", r"Slackbot|Slack-ImgProxy"),
    ("Discordbot", r"Discordbot"),
    ("TelegramBot", r"TelegramBot"),
    ("WhatsApp", r"WhatsApp"),
    ("Pinterestbot", r"Pinterest(bot)?/"),
    ("redditbot", r"redditbot"),
    # Uptime and speed checks.
    ("UptimeRobot", r"UptimeRobot"),
    ("Pingdom", r"Pingdom"),
    ("BetterUptime", r"Better\s?Uptime|betteruptime"),
    ("Lighthouse", r"Chrome-Lighthouse|Google Page Speed"),
    ("GTmetrix", r"GTmetrix"),
    # Archives.
    ("ia_archiver", r"ia_archiver"),
    ("archive.org_bot", r"archive\.org_bot|Wayback"),
]
_BOTS = [(name, re.compile(pattern, re.I)) for name, pattern in BOTS]

# Anything else that names itself a bot: counted as "Other bot", so a new
# crawler shows up as traffic instead of disappearing.
_GENERIC = re.compile(
    r"bot\b|crawler|crawling|spider|scrapy|curl/|wget/|python-requests|headlesschrome|http-client|okhttp|java/|go-http-client",
    re.I,
)


def detect(user_agent):
    """The crawler's catalogue name, or "" when the user agent isn't one."""
    ua = str(user_agent or "")
    if not ua:
        return ""
    for name, pattern in _BOTS:
        if pattern.search(ua):
            return name
    return "Other bot" if _GENERIC.search(ua) else ""


class Crawlers:
    """Options: server_name (default the host name)."""

    def __init__(self, core, server_name=None, **_):
        self.core = core
        self.server_name = str(server_name or socket.gethostname())[:100]
        self.runtime = "Python " + host.python_version()
        self.rows = {}
        self.agents = {}
        self.lock = threading.Lock()
        self.job = Periodic(self._flush_job, FLUSH_EVERY) if core.valid else None

    def record(self, bot, path, status, ms=0, size=0, ip=""):
        """One finished request from a crawler. bot: detect(user_agent)."""
        if not bot or not self.core.is_on("crawlers"):
            return
        clean = (re.split(r"[?#]", str(path or "/"))[0] or "/")[:MAX_PATH]
        minute = int(time.time() // 60) * 60
        with self.lock:
            key = (minute, bot, clean, int(status or 0))
            # Past MAX_KEYS a crawler asking for thousands of URLs becomes one row.
            if key not in self.rows and len(self.rows) >= MAX_KEYS:
                key = (minute, bot, "(other)", int(status or 0))
            # Past that, nothing new is kept until the next send: a status
            # per row and a bot per row still add up.
            if key not in self.rows and len(self.rows) >= HARD_MAX_KEYS:
                return
            row = self.rows.get(key)
            if row is None:
                row = self.rows[key] = {"count": 0, "bytes": 0, "sum_ms": 0}
            row["count"] += 1
            row["bytes"] += max(0, int(size or 0))
            row["sum_ms"] += max(0, int(ms or 0))
            if ip:
                seen = self.agents.setdefault(bot, [])
                if len(seen) < MAX_IPS_PER_BOT and ip not in seen:
                    seen.append(ip)

    def middleware(self, user_agent, path, status, ms=0, size=0, ip=""):
        """Records a finished request when it came from a crawler."""
        self.record(detect(user_agent), path, status, ms, size, ip)

    def flush(self, everything=True):
        current = int(time.time() // 60) * 60
        with self.lock:
            ready = [(k, v) for k, v in self.rows.items() if everything or k[0] < current]
            for k, _ in ready:
                del self.rows[k]
            sent = {k[1] for k, _ in ready}
            agents = [{"bot": bot, "ips": list(ips)} for bot, ips in self.agents.items() if bot in sent]
            if ready:
                # A bot with rows still waiting (this minute isn't over) keeps
                # its addresses, so the next batch can be checked as well.
                waiting = {key[1] for key in self.rows}
                self.agents = {bot: ips for bot, ips in self.agents.items() if bot in waiting}
        rows = [{
            "minute": datetime.fromtimestamp(k[0], timezone.utc).isoformat().replace("+00:00", "Z"),
            "bot": k[1], "path": k[2], "status": k[3],
            "count": v["count"], "bytes": v["bytes"], "sum_ms": v["sum_ms"],
        } for k, v in ready]
        for i in range(0, len(rows), MAX_ROWS):
            self.core.send("crawlers", "/events/crawlers", body={
                "server_name": self.server_name, "runtime": self.runtime,
                "rows": rows[i:i + MAX_ROWS], "agents": agents if i == 0 else [],
            })

    def _flush_job(self):
        self.flush(everything=False)
        return FLUSH_EVERY

    def close(self):
        if self.job:
            self.job.stop()
        self.flush()
