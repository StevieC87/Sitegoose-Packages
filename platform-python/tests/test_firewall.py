"""The firewall's own decisions: when an address gets banned here, and what
the middleware hands the request rules.

    python3 -m unittest discover -s tests
"""
import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analytics_platform import _wsgi_target  # noqa: E402
from analytics_platform.firewall import CLOUDFLARE, Firewall, IpSet, client_ip, ip_key, parse_range  # noqa: E402


class FakeCore:
    valid = False
    site_id = "a" * 24

    def log(self, *_args):
        pass


def firewall(mode):
    wall = Firewall(FakeCore())
    wall.rules = wall._compile({"v": 1, "enabled": True, "mode": mode, "rate": {"limit": 2, "window": 60},
                                "ban": {"seconds": 600}})
    return wall


class RateBan(unittest.TestCase):
    def test_monitor_mode_bans_nobody(self):
        wall = firewall("monitor")
        rules = [wall.check("203.0.113.9", "GET", "/")["rule"] for _ in range(5)]
        self.assertEqual(rules, ["", "", "rate", "rate", "rate"], "over the limit, reported as rate, never banned")
        self.assertEqual(wall.bans, {})

    def test_block_mode_bans_here(self):
        wall = firewall("block")
        rules = [wall.check("203.0.113.9", "GET", "/")["rule"] for _ in range(4)]
        self.assertEqual(rules, ["", "", "rate", "ban"])


class CrossSite(unittest.TestCase):
    """A request another site made the browser send comes from the visitor's
    own address: refused, but nobody is banned for it here or elsewhere."""

    def wall(self):
        wall = Firewall(FakeCore())
        wall.rules = wall._compile({
            "v": 1, "enabled": True, "mode": "block", "rate": {"limit": 2, "window": 60}, "ban": {"seconds": 600},
            "probes": {"exact": ["/.env"], "ban": 600},
            "requests": {"rules": [{"id": "shell", "action": "block", "ban": 600, "path": {"exact": ["/shell.php"]}}]},
        })
        return wall

    def actions(self, wall):
        return {row["rule"]: row["action"] for row in wall.queue.values()}

    def test_a_probe_or_a_rule_is_refused_but_bans_nobody(self):
        for value in ("cross-site", "Same-Site"):
            wall = self.wall()
            for path, rule in (("/.env", "probe"), ("/shell.php", "request:shell")):
                decision = wall.check("203.0.113.9", "GET", path, fetch_site=value)
                self.assertEqual((decision["action"], decision["rule"], decision["status"]), ("block", rule, 403))
            self.assertEqual(wall.bans, {}, value)
            self.assertEqual(self.actions(wall), {"probe": "refused", "request:shell": "refused"})
            self.assertEqual(wall.check("203.0.113.9", "GET", "/")["rule"], "", "not banned afterwards")

    def test_the_rate_is_answered_but_bans_nobody(self):
        wall = self.wall()
        rules = [wall.check("203.0.113.9", "GET", "/", fetch_site="cross-site")["rule"] for _ in range(4)]
        self.assertEqual(rules, ["", "", "rate", "rate"])
        self.assertEqual(wall.bans, {})
        self.assertEqual(self.actions(wall), {"rate": "refused"})

    def test_same_origin_or_no_header_bans_as_before(self):
        for value in ("same-origin", "none", ""):
            wall = self.wall()
            self.assertEqual(wall.check("203.0.113.9", "GET", "/.env", fetch_site=value)["rule"], "probe")
            self.assertEqual(self.actions(wall), {"probe": "block"})
            self.assertEqual(wall.check("203.0.113.9", "GET", "/")["rule"], "ban", value)

    def test_every_adapter_hands_the_header_over(self):
        from analytics_platform import Platform
        platform = Platform.__new__(Platform)
        wall = self.wall()
        platform._modules = {"firewall": wall}
        status, _, _ = platform.blocked("203.0.113.9", {"sec-fetch-site": "cross-site"}, "GET", "/.env")
        self.assertEqual(status, 403)
        self.assertEqual(wall.bans, {})


class Cloudflare(unittest.TestCase):
    """CF-Connecting-IP is the visitor only from Cloudflare: anyone who reaches
    the origin directly can send it, and would pick their own address past
    every rule."""

    def test_the_ranges_are_the_shared_file(self):
        path = os.path.join(os.path.dirname(__file__), "..", "..", "protocols", "cloudflare-ranges.json")
        with open(path, encoding="utf-8") as f:
            self.assertEqual(list(CLOUDFLARE), json.load(f)["ranges"])

    def test_the_header_only_from_a_cloudflare_connection(self):
        headers = {"cf-connecting-ip": "198.51.100.7"}
        self.assertEqual(client_ip("172.64.1.2", headers, "cloudflare"), "198.51.100.7")
        self.assertEqual(client_ip("::ffff:162.158.0.9", headers, "cloudflare"), "198.51.100.7")
        self.assertEqual(client_ip("2606:4700::1", headers, "cloudflare"), "198.51.100.7")
        self.assertEqual(client_ip("203.0.113.50", headers, "cloudflare"), "203.0.113.50")
        self.assertEqual(client_ip("172.64.1.2", {}, "cloudflare"), "172.64.1.2")


class MappedSpace(unittest.TestCase):
    """IPv4 is kept as ::ffff:a.b.c.d, so an IPv6 range holding all of
    ::ffff:0:0/96 would match every IPv4 visitor: never compiled."""

    def test_ranges_covering_ipv4_are_dropped(self):
        for wide in ("::/64", "::ffff:0:0/64", "::/0", "::ffff:0:0/96", "::/8"):
            self.assertIsNone(parse_range(wide), wide)
            self.assertFalse(IpSet([wide]).has(ip_key("203.0.113.9")), wide)

    def test_narrower_ranges_still_count(self):
        self.assertTrue(IpSet(["::ffff:203.0.113.0/120"]).has(ip_key("203.0.113.9")))
        self.assertTrue(IpSet(["2001:db8:0:1::/64"]).has(ip_key("2001:db8:0:1::9")))
        self.assertTrue(IpSet(["203.0.113.0/24", "::/64"]).has(ip_key("203.0.113.9")))

    def test_a_banned_v6_64_does_not_block_ipv4(self):
        wall = Firewall(FakeCore())
        wall.rules = wall._compile({"v": 1, "enabled": True, "mode": "block", "banned": ["::/64"], "shared": ["::ffff:0:0/64"]})
        self.assertEqual(wall.check("203.0.113.9", "GET", "/")["rule"], "")


class WsgiTarget(unittest.TestCase):
    def test_the_raw_target_is_used_when_the_server_keeps_it(self):
        self.assertEqual(_wsgi_target({"RAW_URI": "/a%252e?q=1", "PATH_INFO": "/a%2e", "QUERY_STRING": "q=1"}),
                         "/a%252e?q=1")

    def test_otherwise_path_info_is_encoded_again_with_its_query(self):
        # PEP 3333: the bytes as latin-1; here a UTF-8 "é".
        environ = {"SCRIPT_NAME": "/app", "PATH_INFO": "/cafÃ©", "QUERY_STRING": "id=1%20union"}
        self.assertEqual(_wsgi_target(environ), "/app/caf%C3%A9?id=1%20union")


if __name__ == "__main__":
    unittest.main()
