"""Flood protection beyond nginx (sdk/protocols/firewall.md, "Which layers a
server has"): the page limit counted from any web server's access logs
(`logs`), and the browser check in Apache, LiteSpeed, OpenLiteSpeed, Caddy and
HAProxy (`apache-check`, `litespeed-check`, `caddy-check`, `haproxy-check`).

The lines in access-logs/ were written by the real servers (Apache 2.4 on
Ubuntu and Rocky, OpenLiteSpeed 1.9, LiteSpeed 6.3, Caddy 2.11, Traefik 3.7,
HAProxy 3.0), some with forged Referer, User-Agent and paths naming
203.0.113.x: no such address may ever come out of them.

    python3 -m unittest discover -s test
"""
import base64
import calendar
import glob
import hashlib
import importlib.machinery
import importlib.util
import ipaddress
import json
import os
import random
import re
import shutil
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
AGENT = os.path.join(HERE, "..", "analytics-agent")
CASES = os.path.join(HERE, "..", "..", "protocols", "challenge-cases.json")
LOGS = os.path.join(HERE, "access-logs")
if "analytics_agent" in sys.modules:
    agent = sys.modules["analytics_agent"]
else:
    spec = importlib.util.spec_from_loader("analytics_agent", importlib.machinery.SourceFileLoader("analytics_agent", AGENT))
    agent = importlib.util.module_from_spec(spec)
    sys.modules["analytics_agent"] = agent
    spec.loader.exec_module(agent)
# The tests never reach this machine's own web servers or logs.
agent.DEFAULTS.update(web_checks=[], access_logs=[])
# Nor this machine's iptables and ipset (test_iptables.py patches them in per test).
agent.ipt_tools = lambda refresh=False: None
# Nor this machine's own addresses (test_webservers.py tests the real lookup).
if not hasattr(agent, "real_own_addresses"):
    agent.real_own_addresses = agent.own_addresses
agent.own_addresses = lambda now=None: []

with open(CASES) as f:
    CHALLENGE_CASES = json.load(f)

FLOOD = {"conn_rate": 30, "conn_max": 100, "req_rate": 1, "req_burst": 2, "ban": 600,
         "exempt": ["173.245.48.0/20", "66.249.64.0/27"]}
DAY = 20761
NOW = DAY * 86400 + 3600


def rules(**extra):
    base = {"v": 1, "enabled": True, "mode": "block", "sync": 60, "allow": ["203.0.113.7"],
            "goodbots": ["23.98.142.176/28", "2a05:d014:f2f:4600::/56"], "flood": dict(FLOOD),
            "challenge": dict(CHALLENGE_CASES["challenge"])}
    base.update(extra)
    return base


def config(tmp=None, **extra):
    tmp = tmp or tempfile.mkdtemp()
    base = dict(agent.DEFAULTS, site_id="a" * 24, secret=CHALLENGE_CASES["secret"], endpoint="https://c.example",
                state_dir=tmp, sites=[], backend="nftables", ports=[80, 443],
                nginx_check_log=os.path.join(tmp, "nginx-check.log"), litespeed_dir=os.path.join(tmp, "lsws"))
    base.update(extra)
    return base


def done(code=0, stdout="", stderr=""):
    return SimpleNamespace(returncode=code, stdout=stdout, stderr=stderr)


def lines_of(name):
    with open(os.path.join(LOGS, name)) as f:
        return [line.rstrip("\n") for line in f if line.strip()]


def clf(address, path="/", second=0, fraction=""):
    return '%s - - [03/Nov/2026:17:00:%02d%s +0000] "GET %s HTTP/1.1" 200 5 "-" "x"' % (address, second, fraction, path)


# ---- access log lines ----------------------------------------------------------


class Fixtures(unittest.TestCase):
    """Every line the real servers wrote is read, and only their own address field counts."""
    EXPECT = {"apache-forged.log": 4, "apache-rhel.log": 27, "apache-vhost.log": 27, "caddy.log": 17,
              "haproxy-checked.log": 3, "haproxy.log": 24, "litespeed.log": 6, "openlitespeed.log": 6,
              "traefik-common.log": 3, "traefik-json.log": 3}

    def test_every_line_parses_and_names_only_the_real_sender(self):
        self.assertEqual(sorted(os.path.basename(p) for p in glob.glob(os.path.join(LOGS, "*.log"))), sorted(self.EXPECT))
        for name, count in self.EXPECT.items():
            parsed = [agent.parse_access(line) for line in lines_of(name)]
            self.assertEqual(len(parsed), count, name)
            self.assertNotIn(None, parsed, name)
            for address, page, at, coarse, checked, local in parsed:
                self.assertIn(address, ("198.51.100.10", "198.51.100.77", "127.0.0.1", "172.17.0.1"), name)
                self.assertTrue(1793700000 < at < 1793800000, (name, at))

    def test_forged_referer_user_agent_and_path(self):
        parsed = [agent.parse_access(line) for line in lines_of("apache-forged.log")]
        self.assertEqual([(a, page) for a, page, *_ in parsed],
                         [("198.51.100.10", True), ("198.51.100.10", True), ("198.51.100.10", False), ("198.51.100.10", True)],
                         "a.css?x=1 is a static file, but counts where it was a 404")
        self.assertEqual(parsed[0][2], calendar.timegm((2026, 11, 3, 17, 46, 51)))
        self.assertTrue(parsed[0][3], "whole seconds")

    def test_vhost_combined_puts_the_host_first(self):
        line = lines_of("apache-vhost.log")[0]
        self.assertRegex(line, r"^\S+:\d+ 198\.51\.100\.10 ")
        self.assertEqual(agent.parse_access(line)[0], "198.51.100.10")

    def test_caddy_marks_the_check_page_only(self):
        checked = [agent.parse_access(line)[4] for line in lines_of("caddy.log")]
        self.assertEqual(checked[:2], [True, True])
        self.assertEqual(sum(checked), 3)
        self.assertFalse(agent.parse_access(lines_of("caddy.log")[0])[3], "Caddy's time has a fraction")

    def test_haproxy_with_each_syslog_prefix_and_its_check(self):
        parsed = [agent.parse_access(line) for line in lines_of("haproxy.log")]
        self.assertEqual([p[4] for p in parsed], [True, False, False] * 8,
                         "our check (it captured sg_check), a static file, the owner's own 503: in each format")
        self.assertEqual([p[1] for p in parsed[:3]], [True, False, True], "the owner's 503 page is a page")
        self.assertTrue(all(p[5] for p in parsed), "HAProxy writes local time")
        self.assertAlmostEqual(parsed[0][2], calendar.timegm((2026, 11, 3, 21, 5, 19)) + 0.096, places=5,
                               msg="read as UTC; the agent finds the offset per log")
        self.assertEqual([agent.parse_access(l)[4] for l in lines_of("haproxy-checked.log")], [False] * 3)

    def test_traefik_both_formats(self):
        common = [agent.parse_access(l) for l in lines_of("traefik-common.log")]
        js = [agent.parse_access(l) for l in lines_of("traefik-json.log")]
        self.assertEqual([p[1] for p in common], [True, False, True])
        self.assertEqual([p[1] for p in js], [True, False, True])
        self.assertAlmostEqual(js[0][2], calendar.timegm((2026, 11, 3, 17, 46, 36)) + 0.660340433, places=5)


class Lines(unittest.TestCase):
    def test_a_user_name_cant_move_the_time_or_request(self):
        line = ('198.51.100.10 - a b] [01/Jan/2020:00:00:00 +0000] \\"GET /x.css\\" [03/Nov/2026:17:00:00 +0000] '
                '"GET /page HTTP/1.1" 200 5 "-" "x"')
        address, page, at, *_ = agent.parse_access(line)
        self.assertEqual((address, page, at), ("198.51.100.10", True, calendar.timegm((2026, 11, 3, 17, 0, 0))))

    def test_zone_fraction_ipv6_and_mapped(self):
        self.assertEqual(agent.parse_access('2001:db8::1 - - [03/Nov/2026:19:00:00 +0200] "GET / HTTP/1.1" 200 1')[:4],
                         ("2001:db8::1", True, calendar.timegm((2026, 11, 3, 17, 0, 0)), True))
        self.assertEqual(agent.parse_access(clf("::ffff:198.51.100.4", fraction=".250"))[:4],
                         ("198.51.100.4", True, calendar.timegm((2026, 11, 3, 17, 0, 0)) + 0.25, False))

    def test_not_access_lines(self):
        for line in ["", "garbage", "203.0.113.5", '{"msg": "203.0.113.5"}', "[1, 2]", "{broken",
                     '203.0.113.5 - - [03/Foo/2026:17:00:00 +0000] "GET / HTTP/1.1" 200 1',
                     'example.com 203.0.113.5 - - [03/Nov/2026:17:00:00 +0000] "GET / HTTP/1.1" 200 1',
                     '{"logger": "http.log.error", "ts": 1, "request": {"remote_ip": "203.0.113.5", "uri": "/"}}',
                     '{"logger": "http.log.access", "ts": true, "request": {"remote_ip": "203.0.113.5", "uri": "/"}}',
                     '{"ClientHost": "203.0.113.5", "RequestPath": "/"}',
                     '<134>Nov  3 17:18:22 localhost sshd[8]: 203.0.113.5:50064 [03/Nov/2026:17:18:22.936] web web/<NOSRV> '
                     '0/-1/-1/-1/0 503 318 - - LR-- 1/1/0/0/0 0/0 "GET / HTTP/1.1"']:
            self.assertIsNone(agent.parse_access(line), line)

    def test_haproxy_captured_headers_are_the_senders(self):
        line = ('198.51.100.10:1 [03/Nov/2026:17:18:21.233] web app/s1 0/0/0/0/0 200 88 - - ---- 1/1/0/0/0 0/0 '
                '{203.0.113.5|x} {} "GET /p HTTP/1.1"')
        self.assertEqual(agent.parse_access(line)[:2], ("198.51.100.10", True))

    def test_caddy_client_ip_wins_over_the_proxy(self):
        entry = {"logger": "http.log.access.log0", "ts": 1793727666.5,
                 "request": {"remote_ip": "10.0.0.2", "client_ip": "198.51.100.10", "uri": "/x.png?y=1"}}
        self.assertEqual(agent.parse_access(json.dumps(entry)), ("198.51.100.10", False, 1793727666.5, False, False, False))
        entry["status"], entry["resp_headers"] = 503, {"X-Robots-Tag": ["noindex"]}
        self.assertFalse(agent.parse_access(json.dumps(entry))[4], "a 503 of the site's own isn't the check")

    def test_a_head_the_server_wrote_counts_whatever_follows(self):
        # A request line no pattern takes (2.8 KB of \xhh), a 600-character
        # user name, a line syslog cut short: the request still counts.
        long_request = clf("198.51.100.10", "/?" + "\\xff" * 3000)
        self.assertEqual(agent.parse_access(long_request)[:2], ("198.51.100.10", True))
        user = '198.51.100.10 - %s [03/Nov/2026:17:00:00 +0000] "GET /x.css HTTP/1.1" 200 5' % ("u" * 600)
        self.assertEqual(agent.parse_access(user)[:2], ("198.51.100.10", False), "static, and parsed in full")
        cut = '198.51.100.10 - - [03/Nov/2026:17:00:00 +0000] "GET /x.css?' + "a" * 50
        self.assertEqual(agent.parse_access(cut)[:2], ("198.51.100.10", True))
        hap = '198.51.100.10:5 [03/Nov/2026:17:18:21.233] web app/s1 0/0/0/0/0 200 88 - - ---- 1/1/0/0/0 0/0 "GET /x.css?' + "a" * 50
        self.assertEqual(agent.parse_access(hap)[:2], ("198.51.100.10", False), "cut short: the path still reads")
        self.assertEqual(agent.parse_access('198.51.100.10:5 [03/Nov/2026:17:18:21.233] web junk')[:2], ("198.51.100.10", True))
        start = time.time()
        agent.parse_access('198.51.100.10 - ' + "x " * 4000 + "[" + "a" * 4000)
        self.assertLess(time.time() - start, 0.5)

    def test_static_files_count_when_they_are_errors(self):
        line = lambda status: '198.51.100.10 - - [03/Nov/2026:17:00:00 +0000] "GET /x123.css HTTP/1.1" %s 5' % status
        self.assertEqual([agent.parse_access(line(s))[1] for s in ("200", "304", "404", "500", "-")],
                         [False, False, True, True, False])
        traefik = {"ClientHost": "198.51.100.10", "RequestPath": "/index.php/x.css", "StartUTC": "2026-11-03T17:00:00Z",
                   "DownstreamStatus": 404}
        self.assertTrue(agent.parse_access(json.dumps(traefik))[1])
        caddy = {"logger": "http.log.access", "ts": 1.0, "status": 502, "request": {"remote_ip": "198.51.100.10", "uri": "/a.js"}}
        self.assertTrue(agent.parse_access(json.dumps(caddy))[1])

    def test_haproxy_time_is_local_and_its_offset_found(self):
        line = '198.51.100.10:5 [03/Nov/2026:19:00:00.500] web app/s1 0/0/0/0/0 200 88 - - ---- 1/1/0/0/0 0/0 "GET / HTTP/1.1"'
        parsed = agent.parse_access(line)
        self.assertEqual((parsed[2], parsed[5]), (calendar.timegm((2026, 11, 3, 19, 0, 0)) + 0.5, True))
        firewall = agent.Agent(config())
        now = calendar.timegm((2026, 11, 3, 17, 0, 3))  # the log is two hours ahead (UTC+2)
        self.assertEqual(firewall.local_time("h", parsed[2], now), calendar.timegm((2026, 11, 3, 17, 0, 0)) + 0.5)
        self.assertEqual(firewall.local_time("h", parsed[2] + 60, now + 60), calendar.timegm((2026, 11, 3, 17, 1, 0)) + 0.5)
        # Daylight saving time ends: an hour less.
        self.assertEqual(firewall.local_time("h", parsed[2] - 3600 + 7200, now + 7200), now - 3 + 0.5 + 7200)

    def test_haproxy_counts_only_its_own_check(self):
        base = '198.51.100.10:5 [03/Nov/2026:17:18:21.233] web web/<NOSRV> 0/-1/-1/-1/0 503 318 - - LR-- 1/1/0/0/0 0/0 %s"GET / HTTP/1.1"'
        self.assertTrue(agent.parse_access(base % "{sg_check} ")[4])
        self.assertTrue(agent.parse_access(base % "{Mozilla|sg_check} {x} ")[4])
        self.assertFalse(agent.parse_access(base % "")[4], "the owner's own http-request return 503")
        self.assertFalse(agent.parse_access(base % "{} {sg_check} ")[4], "a response capture isn't the block's")

    def test_request_path(self):
        self.assertEqual(agent.request_path("GET http://h.example/a/b.css?x HTTP/1.1"), "/a/b.css")
        self.assertEqual(agent.request_path("GET /x%2Ecss#f HTTP/1.1"), "/x.css")
        self.assertEqual(agent.request_path("-"), "")
        self.assertEqual(agent.request_path("GET https://h.example HTTP/1.1"), "/")


# ---- the count ------------------------------------------------------------------


class Limit(unittest.TestCase):
    def test_burst_plus_one_at_once_then_rate(self):
        limit = agent.PageLimit(1, 2)
        self.assertEqual([limit.hit("a", 10.0) for _ in range(4)], [False, False, False, True])
        self.assertFalse(limit.hit("a", 11.0), "one more a second")
        self.assertTrue(limit.hit("a", 11.0))
        self.assertFalse(limit.hit("b", 11.0), "per key")

    def test_whole_seconds_get_a_seconds_worth_more(self):
        limit = agent.PageLimit(1, 2)
        self.assertEqual([limit.hit("a", 10, coarse=True) for _ in range(5)], [False] * 4 + [True])

    def test_a_refused_request_isnt_counted(self):
        limit = agent.PageLimit(1, 0)
        limit.hit("a", 0)
        self.assertTrue(limit.hit("a", 0))
        self.assertTrue(limit.hit("a", 0))
        self.assertFalse(limit.hit("a", 1))

    def test_a_clock_that_goes_back(self):
        limit = agent.PageLimit(1, 1)
        limit.hit("a", 100)
        self.assertFalse(limit.hit("a", 50), "a little back: no time passed")
        self.assertTrue(limit.hit("a", 50))
        self.assertEqual(limit.state["a"][1], 100)
        limit.hit("b", 100)
        limit.hit("b", 0)  # more than a minute back: nginx's 1 ms
        self.assertEqual(limit.state["b"][1], 0)

    def test_the_cap_drops_the_longest_unseen(self):
        limit = agent.PageLimit(1, 0, cap=2)
        limit.hit("a", 0)
        limit.hit("b", 0)
        limit.hit("a", 5)
        limit.hit("c", 5)
        self.assertEqual(list(limit.state), ["a", "c"])

    def test_prune_drops_only_what_ran_out(self):
        limit = agent.PageLimit(1, 5)
        limit.hit("a", 0)
        limit.hit("a", 0)
        limit.hit("a", 0)  # excess 2
        limit.hit("b", 0)
        limit.prune(1)
        self.assertEqual(list(limit.state), ["a"])
        limit.prune(2)
        self.assertEqual(list(limit.state), [])


class AddressRanges(unittest.TestCase):
    def test_lookup(self):
        ranges = agent.Ranges(agent.networks(["10.0.0.0/8", "10.1.0.0/16", "11.0.0.0/8", "198.51.100.7", "2001:db8::/32"]))
        self.assertEqual(ranges.spans[4][0], [int(ipaddress.ip_address("10.0.0.0")), int(ipaddress.ip_address("198.51.100.7"))])
        for address, inside in [("10.2.3.4", True), ("11.255.255.255", True), ("12.0.0.0", False), ("9.255.255.255", False),
                                ("198.51.100.7", True), ("198.51.100.8", False), ("::ffff:10.0.0.1", True),
                                ("2001:db8:1::1", True), ("2001:db9::1", False), ("junk", False), ("", False)]:
            self.assertEqual(address in ranges, inside, address)
        self.assertNotIn("10.0.0.1", agent.Ranges(([], [])))


class AddressRegex(unittest.TestCase):
    """OpenLiteSpeed's exempt ranges, as regexes of the text it writes."""

    def test_numbers(self):
        for low, high in [(0, 0), (0, 255), (7, 7), (13, 200), (100, 199), (0, 9), (250, 255)]:
            r = re.compile("^%s$" % agent.number_regex(low, high, 10))
            self.assertTrue(all(bool(r.match(str(n))) == (low <= n <= high) for n in range(300)), (low, high))
            self.assertIsNone(r.match("0" + str(low)), "no leading zero")
        for low, high in [(0, 0xffff), (0x4600, 0x46ff), (0x10, 0x10), (0x123, 0x9abc)]:
            r = re.compile("^%s$" % agent.number_regex(low, high, 16))
            self.assertTrue(all(bool(r.match("%x" % n)) == (low <= n <= high) for n in range(0, 0x10000, 7)), (low, high))

    def test_networks(self):
        rng = random.Random(5)
        for text in ["173.245.48.0/20", "10.0.0.0/8", "0.0.0.0/0", "203.0.113.7/32", "66.249.64.0/27", "1.2.3.128/25"]:
            r, net = re.compile(agent.address_regex(text)), ipaddress.ip_network(text)
            for _ in range(500):
                ip = ipaddress.IPv4Address(rng.getrandbits(32)) if rng.random() < .5 else net[rng.randrange(net.num_addresses)]
                self.assertEqual(bool(r.match(str(ip))), ip in net, (text, ip))
            self.assertTrue(r.match("::ffff:%s" % net[0]))
        for text in ["2001:db8::/32", "2001:db8:0:1::/64", "2a05:d014:f2f:4600::/56", "fc00::/7", "fe80::/10", "::1/128",
                     "::/0", "2001:db8::abcd:0:0/96", "0:0:1::/48", "2001:db8:0:0:5::/80"]:
            r, net = re.compile(agent.address_regex(text)), ipaddress.ip_network(text)
            host = 128 - net.prefixlen
            for _ in range(800):
                base = int(net.network_address) if rng.random() < .5 else int(net.network_address) ^ (1 << rng.randrange(128))
                bits = 0
                for g in range(8):
                    if rng.random() < .3:
                        bits |= rng.getrandbits(16) << (16 * g)
                ip = ipaddress.IPv6Address(base & ~((1 << host) - 1) & ((1 << 128) - 1) | bits & ((1 << host) - 1))
                self.assertEqual(bool(r.match(ip.compressed)), ip in net, (text, ip.compressed))


# ---- the logs layer in the agent ------------------------------------------------


class LogsLayer(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)
        self.log = os.path.join(self.dir, "access.log")
        open(self.log, "w").close()
        self.config = config(self.dir, access_logs=[self.log])
        self.sent, self.banned = [], []
        for p in [mock.patch.object(agent, "report", lambda config, events: self.sent.extend(events)),
                  mock.patch.object(agent, "nft_ban", lambda timeouts: self.banned.append(dict(timeouts)) or True),
                  mock.patch.object(agent, "flood_elements", lambda name: {}),
                  mock.patch.object(agent, "log")]:
            p.start()
            self.addCleanup(p.stop)

    def firewall(self, **extra):
        firewall = agent.Agent(self.config)
        firewall.rules = rules(**extra)
        firewall.p = agent.plan(firewall.rules)
        firewall.flood_applied = "x"
        firewall.access_step(firewall.p, 1000)
        self.addCleanup(lambda: [t.close() for t in firewall.access_tails.values()])
        return firewall

    def write(self, lines, path=None):
        with open(path or self.log, "a") as f:
            f.write("".join(line + "\n" for line in lines))

    def test_over_the_limit_is_banned_and_reported_once_as_rate(self):
        firewall = self.firewall()
        self.assertFalse(firewall.running["logs"], "nothing read yet")
        self.write([clf("198.51.100.9")] * 6 + [clf("198.51.100.8")] * 4)
        firewall.read_access(firewall.p, 1001)
        self.assertTrue(firewall.running["logs"])
        self.assertEqual(self.banned, [{"198.51.100.9": 600}], "burst 2 + 1 at once, + 1 for whole seconds")
        self.write([clf("198.51.100.9")] * 3)
        firewall.tick(1001 + agent.BAN_REPORT_AFTER)
        self.assertEqual([(e["ip"], e["rule"], e["action"], e["hits"]) for e in self.sent], [("198.51.100.9", "rate", "block", 5)])
        self.assertEqual(len(self.banned), 1)

    def test_monitor_mode_bans_nobody_and_reports_once_a_ban_period(self):
        firewall = self.firewall(mode="monitor")
        self.write([clf("198.51.100.9")] * 6)
        firewall.read_access(firewall.p, 1001)
        self.write([clf("198.51.100.9", second=1)] * 6)
        firewall.read_access(firewall.p, 1002)
        self.assertEqual(self.banned, [])
        events = firewall.due_bans(firewall.p, 1001 + agent.BAN_REPORT_AFTER)
        self.assertEqual([(e["ip"], e["rule"], e["action"]) for e in events], [("198.51.100.9", "rate", "monitor")])
        self.assertEqual(firewall.due_bans(firewall.p, 1500), [])

    def test_exempt_static_and_ipv6_by_its_64(self):
        firewall = self.firewall()
        self.write([clf(a) for a in ("203.0.113.7", "66.249.64.5", "10.1.2.3", "23.98.142.180") for _ in range(9)])
        self.write([clf("198.51.100.9", "/a/b.JS")] * 9)
        self.write([clf("2001:db8:0:1::%d" % i) for i in range(1, 6)])
        firewall.read_access(firewall.p, 1001)
        self.assertEqual(self.banned, [{"2001:db8:0:1::/64": 600}])

    def test_each_log_counts_on_its_own(self):
        other = os.path.join(self.dir, "proxy.log")
        open(other, "w").close()
        self.config["access_logs"] = [self.log, other]
        firewall = self.firewall()
        self.write([clf("198.51.100.9", fraction=".1")] * 3)
        self.write([clf("198.51.100.9", fraction=".1")] * 3, other)
        firewall.read_access(firewall.p, 1001)
        self.assertEqual(self.banned, [], "a proxy and its backend logging one request: one request")

    def test_nginx_own_log_isnt_counted_while_nginx_counts(self):
        firewall = self.firewall()
        firewall.nginx_dump = (set(), [], [self.log])
        firewall.running["nginx"] = True
        firewall.access_step(firewall.p, 1001)
        self.assertEqual(firewall.access_counted, set())
        self.assertFalse(firewall.running["logs"])
        self.assertIn("nginx counts its own", agent.log.call_args[0][0])
        firewall.running["nginx"] = False
        firewall.access_step(firewall.p, 1002)
        self.assertEqual(firewall.access_counted, {self.log})

    def test_only_with_the_kernel_ban_set(self):
        for conf, extra in [(dict(backend="nginx"), {}), ({}, dict(flood=None)), ({}, dict(enabled=False))]:
            self.config.update(conf)
            firewall = self.firewall(**extra)
            self.assertEqual(firewall.access_tails, {})
            self.assertFalse(firewall.running["logs"])
            self.config["backend"] = "nftables"
        firewall = self.firewall()
        firewall.flood_applied = ""
        firewall.access_step(firewall.p, 1001)
        self.assertIsNone(firewall.limiter)

    def test_iptables_bans_in_its_own_set(self):
        self.config["backend"] = "iptables"
        ipt = []
        with mock.patch.object(agent, "ipt_ban", lambda timeouts: ipt.append(dict(timeouts)) or True):
            firewall = self.firewall()
            self.write([clf("198.51.100.9")] * 6)
            firewall.read_access(firewall.p, 1001)
        self.assertTrue(firewall.running["logs"])
        self.assertEqual((ipt, self.banned), ([{"198.51.100.9": 600}], []))

    def test_caddy_and_haproxy_checks_are_reported_from_the_access_log(self):
        firewall = self.firewall(flood=None)
        firewall.running["caddy-check"] = True
        firewall.access_step(firewall.p, 1001)
        self.write(lines_of("caddy.log")[:4])
        firewall.read_access(firewall.p, 1002)
        self.assertEqual(self.banned, [])
        self.assertEqual(firewall.checked_events(1003)[0]["ip"], "198.51.100.10")
        self.assertEqual(firewall.checked_events(1004), [])

    def test_which_files(self):
        for name in ("access.log.1", "access.log.gz", "access_log-20261103", "access-2026-11-03T16-20-01.000.log",
                     "analytics-check.log", "other.log", "nginx-check.log"):
            open(os.path.join(self.dir, name), "w").close()
        os.mkdir(os.path.join(self.dir, "dir.log"))
        self.config["access_logs"] = [os.path.join(self.dir, "*.log*"), os.path.join(self.dir, "*_log*"), "relative.log", 7]
        self.assertEqual(agent.Agent(self.config).find_access_logs(),
                         [os.path.join(self.dir, "access.log"), os.path.join(self.dir, "other.log")])
        self.config["access_logs"] = []
        self.assertEqual(agent.Agent(self.config).find_access_logs(), [])

    def test_no_rate_goes_once_logs_count(self):
        seen = {}

        def fake(config, method, path, body=None, headers=None):
            seen.update(headers or {})
            return 304, {}, b""

        with mock.patch.object(agent, "request", fake):
            agent.fetch_rules(config(), "e", layers=["kernel", "logs"])
        self.assertNotIn("no-rate", seen["User-Agent"])


# ---- the check's files ------------------------------------------------------------


SCRIPT_HARNESS = r"""
const vm = require("vm");
const [script, cases] = [process.argv[1], JSON.parse(process.argv[2])];
const out = cases.map(c => {
  const jar = new Map(Object.entries(c.cookies || {}));
  const store = new Map(), message = {textContent: ""};
  let reloads = 0;
  const document = {
    getElementById: () => message,
    get cookie() { return [...jar].map(([k, v]) => k + "=" + v).join("; "); },
    set cookie(text) { if (c.refuse) return; const [k, v] = text.split(";")[0].split("="); jar.set(k, v); },
  };
  const sessionStorage = {
    getItem: k => { if (c.noStorage) throw new Error("blocked"); return store.has(k) ? store.get(k) : null; },
    setItem: (k, v) => { if (c.noStorage) throw new Error("blocked"); store.set(k, v); },
  };
  const window = {}, location = {protocol: c.https ? "https:" : "http:", reload: () => { reloads++; }};
  const context = vm.createContext({window, document, sessionStorage, location, JSON, Date});
  for (let i = 0; i < (c.runs || 1); i++) {
    if (c.fresh) context.window = {};
    if (c.dropPass) jar.delete("__sg_passn");
    vm.runInContext(script, context);
  }
  return {reloads, message: message.textContent, cookies: Object.fromEntries(jar)};
});
console.log(JSON.stringify(out));
"""


@unittest.skipUnless(shutil.which("node"), "node runs the check page's script")
class Script(unittest.TestCase):
    """The check page's script, run by node against a fake page."""

    def run_cases(self, *cases):
        import subprocess
        token = agent.check_tokens(config(), DAY)[0]
        out = subprocess.run(["node", "-e", SCRIPT_HARNESS, agent.challenge_script(token), json.dumps(cases)],
                             capture_output=True, text=True, timeout=30)
        self.assertEqual(out.returncode, 0, out.stderr)
        return token, json.loads(out.stdout)

    def test_each_case(self):
        token, (plain, twice, refused, no_storage, looping) = self.run_cases(
            {}, {"runs": 2}, {"refuse": True},
            {"noStorage": True, "fresh": True, "dropPass": True, "runs": 5}, {"fresh": True, "dropPass": True, "runs": 5})
        self.assertEqual((plain["reloads"], plain["message"], plain["cookies"]["__sg_passn"]), (1, "", token))
        self.assertEqual(twice["reloads"], 1, "inline and as /__sg_check.js on one page: runs once")
        self.assertEqual(refused["reloads"], 0)
        self.assertIn("turned down the cookie", refused["message"])
        self.assertEqual(no_storage["reloads"], 3, "storage blocked: the tries are counted in a cookie")
        self.assertEqual(no_storage["cookies"]["__sg_tries"], "3")
        self.assertIn("try again in a minute", no_storage["message"])
        self.assertEqual(looping["reloads"], 3, "a pass lost between loads: 3 tries a minute, not for ever")

    def test_a_browser_that_held_the_pass_isnt_reloaded(self):
        token = agent.check_tokens(config(), DAY)[0]
        _, (held, again) = self.run_cases({"cookies": {"a": "1", "__sg_passn": token}}, {"fresh": True, "runs": 3})
        self.assertEqual(held["reloads"], 0)
        self.assertEqual(again["reloads"], 1, "the pass sent but the check shown again: said, not reloaded")
        self.assertIn("cannot be reached right now", again["message"])
        self.assertIn("cannot be reached right now", held["message"], "a 503 of the site's own, behind the same page")


class Probe(unittest.TestCase):
    def setUp(self):
        self.config = config(ports=[80, 443])
        self.p = agent.plan(rules())
        self.token = agent.check_tokens(self.config, DAY)[0]

    def test_csp_runs_script(self):
        ours = agent.challenge_csp(self.token, True)
        for policies, external, ok in [
                ([ours], True, True), ([], False, True),
                (["default-src 'self'"], True, True), (["default-src 'self'"], False, False),
                (["script-src 'unsafe-inline'"], False, True),
                (["script-src 'unsafe-inline' 'nonce-abc'"], True, False),
                (["script-src 'self' 'strict-dynamic' 'nonce-x'"], True, False),
                (["img-src 'none'"], False, True),
                ([ours, "script-src 'none'"], True, False),
                (["default-src 'none'; script-src-elem https:"], True, True)]:
            self.assertEqual(agent.csp_runs_script(policies, ours, external), ok, policies)

    def answers(self, first, script=None, second=(200, {}, "site")):
        asked = []

        def ask(host, port, tls, path="/", headers=None, timeout=None):
            asked.append((host, port, tls, path, dict(headers or {})))
            if path == agent.CHECK_SCRIPT:
                return script
            return second if "Cookie" in (headers or {}) else first
        return asked, ask

    def page(self, csp=None):
        return (503, {"content-security-policy": [csp or agent.challenge_csp(self.token, True)]},
                agent.challenge_page(self.token, nonce=None, external=True))

    def test_running_needs_the_check_without_the_pass_and_none_with_it(self):
        check = agent.CaddyCheck(self.config)
        check.sites = [{"hosts": ["shop.test"], "check": True, "deferred_csp": True}]
        asked, ask = self.answers(self.page(), (200, {}, agent.challenge_script(self.token)))
        with mock.patch.object(agent, "http_probe", ask):
            self.assertTrue(check.probe(self.p, DAY))
        self.assertEqual(asked[0], ("shop.test", 80, False, "/", {"Accept": "text/html", "X-Analytics-Probe": "1"}))
        self.assertEqual(asked[-1][4]["Cookie"], "__sg_passn=" + self.token)
        _, ask = self.answers(self.page(), None, self.page())
        with mock.patch.object(agent, "http_probe", ask):
            self.assertFalse(check.probe(self.p, DAY))
        self.assertIn("even with today's pass", check.probe_note)
        _, ask = self.answers((200, {}, "<html>site</html>"))
        with mock.patch.object(agent, "http_probe", ask):
            self.assertFalse(check.probe(self.p, DAY))
        self.assertIn("answered 200 at http://shop.test:80/ without the check page", check.probe_note)

    def test_a_site_policy_that_blocks_the_script(self):
        check = agent.CaddyCheck(self.config)
        check.sites = [{"hosts": ["shop.test"], "check": True, "deferred_csp": True}]
        _, ask = self.answers(self.page("default-src 'self'"), (404, {}, "no"))
        with mock.patch.object(agent, "http_probe", ask):
            self.assertFalse(check.probe(self.p, DAY))
        self.assertIn("isn't served there", check.probe_note)
        self.assertIn("shop.test sets it deferred", check.probe_note)
        _, ask = self.answers(self.page("default-src 'self'"), (200, {}, agent.challenge_script(self.token)))
        with mock.patch.object(agent, "http_probe", ask):
            self.assertTrue(check.probe(self.p, DAY), "'self' runs the script it serves")

    def test_nothing_to_ask(self):
        check = agent.CaddyCheck(self.config)
        with mock.patch.object(agent, "http_probe", lambda *a, **k: None):
            self.assertIsNone(check.probe(self.p, DAY))
        self.assertEqual(check.probe_targets(), [("localhost", 80, False), ("localhost", 443, True)])
        p = agent.plan(rules(challenge=dict(CHALLENGE_CASES["challenge"], skip=["/"])))
        self.assertIsNone(check.probe(p, DAY))
        self.assertIn("`/` is skipped", check.probe_note)

    def test_against_a_real_socket(self):
        import http.server
        import threading
        token = self.token

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                passed = ("__sg_passn=" + token) in (self.headers.get("Cookie") or "")
                body = (b"ok" if passed else agent.challenge_page(token, nonce=None).encode())
                self.send_response(200 if passed else 503)
                if not passed:
                    self.send_header("Content-Security-Policy", agent.challenge_csp(token))
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        check = agent.ApacheCheck(dict(self.config, ports=[server.server_port]))
        self.assertTrue(check.probe(self.p, DAY), check.probe_note)


FIB_TRIE = """Main:
  +-- 0.0.0.0/0 3 0 5
     |-- 0.0.0.0
        /0 universe UNICAST
     +-- 10.0.0.0/24 2 0 2
        |-- 10.0.0.5
           /32 host LOCAL
     |-- 95.217.1.2
        /32 host LOCAL
     |-- 95.217.1.255
        /32 link BROADCAST
     |-- 127.0.0.1
        /32 host LOCAL
Local:
     |-- 95.217.1.2
        /32 host LOCAL
"""
IF_INET6 = """00000000000000000000000000000001 01 80 10 80       lo
2a0104f9c0101234000000000000000a 02 40 00 80     eth0
fe800000000000000000000000000001 02 40 20 80     eth0
"""


class OwnAddresses(unittest.TestCase):
    """Requests the server sends itself through its public address never get the check, nor count."""

    def setUp(self):
        agent._own_addresses.update(at=None, list=[])
        self.addCleanup(agent._own_addresses.update, at=None, list=[])
        files = {"/proc/net/fib_trie": FIB_TRIE, "/proc/net/if_inet6": IF_INET6}
        self.reads = []
        p = mock.patch.object(agent, "read_text", lambda path, limit=65536: self.reads.append(path) or files.get(path))
        p.start()
        self.addCleanup(p.stop)

    def test_read_from_proc(self):
        self.assertEqual(agent.real_own_addresses(NOW), ["95.217.1.2", "2a01:4f9:c010:1234::a"],
                         "public only: private, loopback, broadcast and link-local left out")
        agent.real_own_addresses(NOW + 1)
        self.assertEqual(len(self.reads), 2, "looked at once every few minutes")
        agent.real_own_addresses(NOW + agent.OWN_ADDRESSES_EVERY)
        self.assertEqual(len(self.reads), 4)

    def test_in_every_check_and_the_logs_layer(self):
        own = lambda now=None: agent.real_own_addresses(NOW)
        with mock.patch.object(agent, "own_addresses", own):
            p = agent.plan(rules())
            v4, v6 = agent.check_exempt(p)
            self.assertIn("95.217.1.2/32", v4)
            self.assertIn("2a01:4f9:c010:1234::a/128", v6)
            conf = config()
            nginx = agent.nginx_flood_text(conf, p, DAY)
            for name in ("sg_flood_exempt", "sg_check_exempt"):
                geo = nginx.split("geo $%s {" % name, 1)[1].split("}", 1)[0]
                self.assertIn("    95.217.1.2/32 1;", geo, name)
            self.assertIn("95.217.1.2/32", agent.apache_check_text(conf, p, DAY, "/x.conf", "/c.log"))
            self.assertIn("client_ip 10.0.0.0/8 23.98.142.176/28 66.249.64.0/27 95.217.1.2/32 ", agent.caddy_check_text(conf, p, DAY))
            self.assertIn("95.217.1.2/32", "".join(agent.haproxy_files(conf, p, DAY, "/d").values()))
            ols = agent.openlitespeed_check_text(conf, p, DAY, "/x.html", "/x.js")
            self.assertTrue(any(re.search(l.split(" ", 2)[2].rsplit(" [OR]", 1)[0], "95.217.1.2")
                                for l in ols.splitlines() if l.startswith("RewriteCond %{REMOTE_ADDR}")))
            tmp = tempfile.mkdtemp()
            self.addCleanup(shutil.rmtree, tmp)
            log_path = os.path.join(tmp, "access.log")
            open(log_path, "w").close()
            banned = []
            with mock.patch.object(agent, "nft_ban", lambda t: banned.append(t) or True), \
                    mock.patch.object(agent, "flood_elements", lambda name: {}), mock.patch.object(agent, "log"), \
                    mock.patch.object(agent, "report", lambda config, events: None):
                firewall = agent.Agent(config(tmp, access_logs=[log_path]))
                firewall.rules = rules()
                firewall.p = agent.plan(firewall.rules)
                firewall.flood_applied = "x"
                firewall.access_step(firewall.p, 1000)
                self.addCleanup(lambda: [t.close() for t in firewall.access_tails.values()])
                with open(log_path, "a") as f:
                    f.write("".join(clf(a) + "\n" for a in ["95.217.1.2"] * 9 + ["2a01:4f9:c010:1234::a"] * 9 + ["198.51.100.9"] * 9))
                firewall.read_access(firewall.p, 1001)
            self.assertEqual(banned, [{"198.51.100.9": 600}], "only the stranger")


class SkipPaths(unittest.TestCase):
    def test_a_trailing_newline_is_no_path(self):
        p = agent.plan(rules(challenge={"skip": ["/api/", "/api/\n", "/x\n/y/", "/ok/"], "exempt": []}))
        self.assertEqual(p["challenge"]["skip"], ["/api/", "/ok/"])
        with self.assertRaises(ValueError):
            agent.CaddyCheck(config(caddy_check_file="/etc/caddy/x.caddy\n"))


class Texts(unittest.TestCase):
    def setUp(self):
        self.config = config()
        self.p = agent.plan(rules())
        self.off = agent.plan(rules(challenge=None))
        self.tokens = agent.check_tokens(self.config, DAY)

    def test_the_hash_policy_matches_the_page(self):
        page = agent.challenge_page(self.tokens[0], nonce=None)
        script = re.search(r"<script>(.*?)</script>", page, re.S).group(1)
        style = re.search(r"<style>(.*?)</style>", page, re.S).group(1)
        digest = lambda t: "'sha256-%s'" % base64.b64encode(hashlib.sha256(t.encode()).digest()).decode()
        csp = agent.challenge_csp(self.tokens[0])
        self.assertIn("script-src %s;" % digest(script), csp)
        self.assertIn("style-src %s;" % digest(style), csp)
        self.assertIn("frame-ancestors 'none'", csp)
        self.assertFalse(set(page) & set('"\\`$%'))
        self.assertNotIn("nonce", page)

    def test_the_cookie_regex(self):
        r = re.compile(agent._cookie_regex(self.tokens))
        for cookie, ok in [("__sg_passn=%s" % self.tokens[0], True), ("a=1; __sg_passn=%s; b=2" % self.tokens[1], True),
                           ("x__sg_passn=%s" % self.tokens[0], False), ("__sg_passn=%sx" % self.tokens[0], False),
                           ("__sg_passn=%s" % self.tokens[0].replace(".", "a"), False)]:
            self.assertEqual(bool(r.search(cookie)), ok, cookie)

    def test_apache(self):
        text = agent.apache_check_text(self.config, self.p, DAY, "/etc/httpd/conf.d/x.conf", "/var/log/httpd/c.log")
        lines = text.splitlines()
        self.assertTrue(lines[3].startswith("# Exempt"))
        self.assertTrue(lines[5].startswith("<If \"(-R '10.0.0.0/8' || -R '23.98.142.176/28' || "), lines[5])
        self.assertTrue(lines[5].endswith("|| -R 'fc00::/7' || -R 'fe80::/10') && -z req('X-Analytics-Probe')\">"), lines[5])
        self.assertIn("-R '2a05:d014:f2f:4600::/56'", text)
        self.assertIn("-R '203.0.113.7/32'", text)
        check = next(l for l in lines if l.startswith("<ElseIf") and "IS_SUBREQ" in l)
        for part in ["%{REQUEST_METHOD} in {'GET', 'HEAD'}", "m#text/html#i", "! %{THE_REQUEST} =~ m#^\\S+\\s+(?:[a-z][a-z0-9+.-]*://[^/\\s]+)?(?:/api/|/wp-json/|/\\.well-known/)#i",
                     "-z reqenv('REDIRECT_STATUS')", self.tokens[0].replace(".", "\\."), self.tokens[1].replace(".", "\\.")]:
            self.assertIn(part, check)
        self.assertIn("    Redirect 503", lines)
        self.assertIn('    Header always set Content-Security-Policy "%s"' % agent.challenge_csp(self.tokens[0]), lines)
        self.assertTrue(lines[-1].startswith('GlobalLog "/var/log/httpd/c.log" "%{sec}t %a" "expr=%{REQUEST_STATUS} == 503'))
        page = next(l for l in lines if "ErrorDocument" in l)
        self.assertEqual(page.count('"'), 2)
        off = agent.apache_check_text(self.config, self.off, DAY, "/x.conf", "/c.log")
        self.assertFalse([l for l in off.splitlines() if not l.startswith("#")])

    def test_apache_chunks_long_exempt_lists(self):
        many = ["198.18.%d.0/24" % (2 * i) for i in range(100)]
        p = agent.plan(rules(challenge={"skip": [], "exempt": many}))
        text = agent.apache_check_text(self.config, p, DAY, "/x.conf", "/c.log")
        heads = [l for l in text.splitlines() if l.startswith(("<If", "<ElseIf"))]
        self.assertGreater(len(heads), 3)
        self.assertTrue(all(l.count("-R ") <= agent.EXEMPT_CHUNK for l in heads))
        self.assertNotIn("THE_REQUEST", text, "no skip list, no skip condition")

    def ols_rules(self, text):
        return text.split("rules <<<END_rules\n", 1)[1].split("\nEND_rules", 1)[0].splitlines()

    def assert_exempt_then_check(self, rules_, check_rule):
        exempt = agent.check_exempt(self.p)
        addresses = [l for l in rules_ if l.startswith("RewriteCond %{REMOTE_ADDR} ^(?:")]
        self.assertEqual(rules_[:len(addresses)], addresses, "the exempt addresses come first")
        self.assertEqual(len(addresses), len(exempt[0] + exempt[1]))
        self.assertTrue(all(l.endswith(" [OR]") for l in addresses[:-1]) and not addresses[-1].endswith("[OR]"))
        n = len(addresses)
        self.assertEqual(rules_[n:n + 2], ["RewriteCond %{HTTP:X-Analytics-Probe} !^1$", "RewriteRule ^ - [S=1]"],
                         "an exempt address skips only the check: the site's own rules still run after it")
        self.assertIn("RewriteCond %{THE_REQUEST} ^(?:GET|HEAD)\\s", rules_)
        self.assertIn("RewriteCond %{THE_REQUEST} !(?i)^\\S+\\s+(?:[a-z][a-z0-9+.-]*://[^/\\s]+)?(?:/api/|/wp-json/|/\\.well-known/)", rules_)
        self.assertEqual(rules_[-1], check_rule)
        for address, exempt_ in [("10.1.2.3", True), ("::ffff:66.249.64.31", True), ("66.249.64.32", False),
                                 ("2a05:d014:f2f:46ff::1", True), ("2a05:d014:f2f:4700::1", False), ("198.51.100.10", False)]:
            hit = any(re.search(l.split(" ", 2)[2].rsplit(" [OR]", 1)[0], address) for l in addresses)
            self.assertEqual(hit, exempt_, address)

    def test_openlitespeed(self):
        text = agent.openlitespeed_check_text(self.config, self.p, DAY, "/usr/local/lsws/conf/analytics-check.html",
                                              "/usr/local/lsws/analytics-check/check.js")
        self.assertIn("rewrite {\n  enable 1\n  autoLoadHtaccess 1\n", text, "the site's .htaccess still loads")
        rules_ = self.ols_rules(text)
        self.assert_exempt_then_check(rules_, "RewriteRule ^ - [R=503,L]")
        self.assertIn("RewriteCond %{REQUEST_URI} !^/__sg_check\\.(?:html|js)$", rules_, "the page and script are never checked")
        self.assertIn("errorPage 503 {\n  url /__sg_check.html\n}", text)
        self.assertIn("Content-Security-Policy %s" % agent.challenge_csp(self.tokens[0], external=True), text)
        self.assertIn("context /__sg_check.js {\n  location /usr/local/lsws/analytics-check/check.js\n", text)
        off = agent.openlitespeed_check_text(self.config, self.off, DAY, "/x.html", "/x.js").split("is off")[1]
        self.assertEqual(off.split("\n", 1)[1], "rewrite {\n  enable 1\n  autoLoadHtaccess 1\n}\n",
                         "off keeps the rewrite settings the vhost's own block gave up")

    def test_litespeed_enterprise(self):
        text = agent.litespeed_apache_text(self.config, self.p, DAY, "/usr/local/lsws/analytics-check/check.js")
        lines = text.splitlines()
        rules_ = lines[lines.index("RewriteEngine On") + 1:]
        rules_ = rules_[:next(i for i, l in enumerate(rules_) if l.startswith("RewriteRule ^ - [R=503")) + 1]
        self.assert_exempt_then_check(rules_, "RewriteRule ^ - [R=503,L,E=sg_check:1]")
        self.assertNotIn("expr", text, "LiteSpeed ignores RewriteCond expr")
        self.assertEqual(len([l for l in lines if l.startswith("Header always set") and l.endswith("env=sg_check")]), 4)
        self.assertIn('Header always set Content-Security-Policy "%s" env=sg_check' % agent.challenge_csp(self.tokens[0], external=True), lines)
        self.assertEqual(lines[-1], "Alias /__sg_check.js /usr/local/lsws/analytics-check/check.js")
        self.assertNotIn("<If", text)

    def test_caddy(self):
        text = agent.caddy_check_text(self.config, self.p, DAY)
        self.assertIn("\t\tnot {\n\t\t\tclient_ip 10.0.0.0/8 23.98.142.176/28 ", text)
        self.assertIn("\n\t\t\tnot header X-Analytics-Probe 1\n\t\t}\n", text, "exempt, but not the agent's probe")
        self.assertIn("\t\tnot {\n\t\t\tremote_ip 10.0.0.0/8 23.98.142.176/28 ", agent.caddy_check_text(self.config, self.p, DAY, client_ip=False))
        self.assertIn("\t\tnot vars_regexp {http.request.orig_uri.path} `(?i)^(?:/api/|/wp-json/|/\\.well-known/)`\n", text,
                      "skipped by the path asked for, not one a try_files rewrote")
        self.assertIn("\t@analytics_check_js vars_regexp {http.request.orig_uri.path} ^/__sg_check\\.js$\n", text)
        self.assertIn("\t\theader Content-Security-Policy \"%s\"\n" % agent.challenge_csp(self.tokens[0], external=True), text)
        self.assertLess(text.index("handle @analytics_check_js"), text.index("handle @analytics_check {"))
        self.assertIn("\t\tmethod GET HEAD\n\t\theader_regexp Accept (?i)text/html\n", text)
        self.assertIn("\thandle @analytics_check {", text)
        self.assertTrue(text.rstrip().endswith("503\n\t}\n}"))
        self.assertEqual("".join(l for l in text.splitlines() if not l.startswith("#")).count("`"), 8, "script, skip, cookie and the page, each one backtick token")
        off = agent.caddy_check_text(self.config, self.off, DAY)
        self.assertTrue(off.endswith("(analytics_check) {\n}\n"))

    def test_haproxy(self):
        files = agent.haproxy_files(self.config, self.p, DAY, "/etc/haproxy/analytics")
        self.assertEqual(sorted(os.path.basename(f) for f in files), sorted(agent.HAProxyCheck.FILES))
        body = lambda name: [l for l in files["/etc/haproxy/analytics/" + name].splitlines() if not l.startswith("#")]
        self.assertEqual(body("on.lst"), ["0.0.0.0/0", "::/0"])
        self.assertEqual(body("pass.lst"), self.tokens)
        self.assertEqual(body("skip.lst"), ["/api/", "/wp-json/", "/.well-known/"])
        self.assertIn("10.0.0.0/8", body("exempt.lst"))
        self.assertEqual(body("csp.map"), ["csp " + agent.challenge_csp(self.tokens[0], external=True)])
        self.assertEqual(files["/etc/haproxy/analytics/check.js"], agent.challenge_script(self.tokens[0]) + "\n")
        self.assertIn("<script src='/__sg_check.js'>", files["/etc/haproxy/analytics/check.html"])
        self.assertIn(agent.haproxy_block("/etc/haproxy/analytics"), files["/etc/haproxy/analytics/block.cfg"])
        off = agent.haproxy_files(self.config, self.off, DAY, "/d")
        self.assertEqual([l for l in off["/d/on.lst"].splitlines() if not l.startswith("#")], [])
        self.assertEqual(sorted(off), sorted("/d/" + n for n in agent.HAProxyCheck.FILES),
                         "the same files, so the pasted block still loads")


class Detection(unittest.TestCase):
    """Whether each server really reads the agent's file: no layer otherwise."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)

    def put(self, name, text):
        path = os.path.join(self.dir, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(text)
        return path

    def test_apache_dump_includes(self):
        out = "Included configuration files:\n  (*) /etc/apache2/apache2.conf\n    (146) /etc/apache2/conf-enabled/analytics-check.conf\n"
        self.assertEqual(agent.apache_includes(out), ["/etc/apache2/apache2.conf", "/etc/apache2/conf-enabled/analytics-check.conf"])

    def test_openlitespeed_includes(self):
        path = "/usr/local/lsws/conf/analytics-check.conf"
        good = self.put("a/vhconf.conf", "docRoot $VH_ROOT/html\ninclude %s\ncontext / {\n  rewrite {\n    enable 1\n  }\n}\n" % path)
        own = self.put("b/vhconf.conf", "include %s\nrewrite  {\n  enable 1\n  rules <<<END_rules\nrewrite {\nEND_rules\n}\n" % path)
        heredoc = self.put("c/vhconf.conf", "x <<<END_x\ninclude %s\nEND_x\n" % path)
        commented = self.put("d/vhconf.conf", "# include %s\n" % path)
        settings = self.put("e/vhconf.conf", "include %s\nrewrite {\n  enable 1\n  autoLoadHtaccess 1\n}\n" % path)
        above = self.put("f/vhconf.conf", "rewrite {\n  enable 1\n}\ninclude %s\n" % path)
        page = self.put("g/vhconf.conf", "include %s\nerrorPage 503 {\n  url /down.html\n}\n" % path)
        template = self.put("t/tpl.conf", "configFile $SERVER_ROOT/conf/vhosts/$VH_NAME/vhconf.conf\n"
                            "virtualHostConfig {\n  include %s\n}\n" % path)
        self.assertEqual(agent.openlitespeed_includes([good, own, heredoc, commented, settings, above, page, template], path),
                         ([good, settings, template], [(own, "rewrite"), (above, "order"), (page, "503")]))

    def test_openlitespeed_vhosts(self):
        self.put("conf/httpd_config.conf", "\n".join([
            "listener Default {", "  address *:80", "  map Example example.com, www.example.com", "  map docker *", "}",
            "virtualhost Example {", "  vhRoot Example/", "  configFile $SERVER_ROOT/conf/vhosts/$VH_NAME/vhconf.conf", "}",
            "vhTemplate docker {", "  templateFile conf/templates/docker.conf",
            "  member localhost {", "    vhDomain localhost, *", "  }", "  member shop", "}", ""]))
        self.put("conf/templates/docker.conf", "configFile $SERVER_ROOT/conf/vhosts/$VH_NAME/vhconf.conf\nvirtualHostConfig {\n}\n")
        own = self.put("conf/vhosts/shop/vhconf.conf", "docRoot /srv/shop\n")
        vhosts = agent.openlitespeed_vhosts(self.dir)
        self.assertEqual([(v["name"], v["file"]) for v in vhosts], [
            ("Example", os.path.join(self.dir, "conf/vhosts/Example/vhconf.conf")),
            ("localhost", os.path.join(self.dir, "conf/templates/docker.conf")),
            ("shop", own)], "a member reads the template until a file of its own is written")
        self.assertEqual(vhosts[0]["domains"], ["example.com", "www.example.com"])
        self.assertEqual(vhosts[1]["domains"], ["localhost", "*"])

    def test_apache_vhosts(self):
        check = os.path.join(self.dir, "check.conf")
        conf = self.put("httpd.conf", "Include sites/*.conf\nIncludeOptional extra\n")
        self.put("sites/a.conf", "<VirtualHost *:80>\n  ServerName a.test\n  ServerAlias www.a.test\n"
                                 "  Include check.conf\n</VirtualHost>\n")
        self.put("sites/b.conf", "<VirtualHost *:80>\n  ServerName b.test\n  Include inner.inc\n</VirtualHost>\n")
        self.put("inner.inc", "Include %s\nErrorDocument 503 /down.html\n" % check)
        self.put("extra/c.conf", "<VirtualHost *:443>\n  ServerName c.test\n</VirtualHost>\n")
        vhosts = agent.apache_vhosts(conf, check)
        self.assertEqual([(v["name"], v["names"], v["check"], v["own503"]) for v in vhosts], [
            ("a.test", ["a.test", "www.a.test"], True, False),
            ("b.test", ["b.test"], True, True),
            ("c.test", ["c.test"], False, False)],
            "relative paths from the config's folder; a file included in a vhost is part of it; folders read whole")

    def test_litespeed_enterprise_vhost_includes(self):
        check = os.path.join(self.dir, "check.conf")
        self.put("httpd_config.xml", "<loadApacheConf>1</loadApacheConf><apacheConfFile>%s</apacheConfFile>"
                 % os.path.join(self.dir, "httpd.conf"))
        os.makedirs(os.path.join(self.dir, "conf"))
        shutil.move(os.path.join(self.dir, "httpd_config.xml"), os.path.join(self.dir, "conf", "httpd_config.xml"))
        conf = self.put("httpd.conf", "Include %s\nInclude sites/*.conf\n" % check)
        self.assertEqual(agent.litespeed_apache_conf(self.dir), conf)
        self.assertFalse(agent.apache_vhost_includes(conf, check), "outside any <VirtualHost>")
        self.put("sites/a.conf", "<VirtualHost *:80>\n  Include \"%s\"\n</VirtualHost>\n" % check)
        self.assertTrue(agent.apache_vhost_includes(conf, check))
        self.put("conf/httpd_config.xml", "<loadApacheConf>0</loadApacheConf>")
        self.assertIsNone(agent.litespeed_apache_conf(self.dir))

    def test_haproxy_block(self):
        block = agent.haproxy_block("/etc/haproxy/analytics")
        pasted = "\n".join("        " + " ".join(l.split()) for l in block.splitlines())
        head = "global\n    log stdout local0\ndefaults\n    mode http\n"
        self.assertTrue(agent.haproxy_has_block(head + "frontend web\n    bind :80\n" + pasted + "\n    default_backend app\n", block))
        self.assertTrue(agent.haproxy_has_block(head + "listen web\n" + block, block))
        self.assertFalse(agent.haproxy_has_block(head + "backend app\n" + block, block))
        self.assertFalse(agent.haproxy_has_block(head + "frontend web\n" + "\n".join(block.splitlines()[:-1]), block))
        commented = block.replace("    acl sg_pass", "    # acl sg_pass")
        self.assertFalse(agent.haproxy_has_block(head + "frontend web\n" + commented, block))

    def test_caddy_adapt_and_version(self):
        check = agent.CaddyCheck(config(self.dir))
        def adapted(*sites):
            routes = [{"match": [{"host": hosts}] if hosts else [], "handle": [{"handler": "subroute", "routes": [body]}]}
                      for hosts, body in sites]
            return json.dumps({"apps": {"http": {"servers": {"srv0": {"routes": routes}}}}})
        ours = {"match": [{"header_regexp": {"Cookie": {"pattern": "__sg_passn=x"}}}]}
        theirs = {"handle": [{"handler": "headers", "response": {"deferred": True, "set": {"Content-Security-Policy": ["x"]}}}]}
        with mock.patch.object(agent, "run_command", lambda args, timeout: done(0, adapted((["a.test"], ours), ([], ours), ([], {})))):
            self.assertTrue(check.included(), "a site with no name is all the server's plain routes together")
            self.assertEqual(check.hosts(), ["a.test"])
        with mock.patch.object(agent, "run_command", lambda args, timeout: done(0, adapted((["a.test"], ours), (["b.test"], theirs)))):
            self.assertFalse(check.included())
            self.assertIn("in b.test:", check.missing())
            self.assertEqual([s["deferred_csp"] for s in check.sites], [False, True])
        with mock.patch.object(agent, "run_command", lambda args, timeout: done(0, "{}")):
            self.assertFalse(check.included())
        with mock.patch.object(agent, "run_command", lambda args, timeout: done(1)):
            self.assertIsNone(check.included())
        for out, newer in [("v2.6.4 h1:abc", False), ("v2.11.7 h1:x", True), ("", False)]:
            check.version = None
            with mock.patch.object(agent, "run_command", lambda args, timeout: done(0, out)):
                self.assertEqual(check.client_ip(), newer, out)

    def test_litespeed_kind(self):
        conf = config(self.dir)
        self.assertIsNone(agent.litespeed_kind(conf))
        self.put("lsws/bin/lshttpd", "")
        self.assertEqual(agent.litespeed_kind(conf), "enterprise")
        with mock.patch.object(agent, "_which", lambda names: "apachectl"):
            self.assertFalse(agent.ApacheCheck(conf).installed(), "LiteSpeed Enterprise ignores <If>: its own check runs")
        self.put("lsws/bin/openlitespeed", "")
        self.assertEqual(agent.litespeed_kind(conf), "open")

    def test_a_path_that_isnt_plain_is_refused(self):
        with self.assertRaises(ValueError):
            agent.CaddyCheck(config(self.dir, caddy_check_file="/etc/caddy/x y; rm"))


# ---- writing them -------------------------------------------------------------------


class Write(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)
        self.old = os.path.join(self.dir, "old.conf")
        self.new = os.path.join(self.dir, "sub", "new.conf")
        with open(self.old, "w") as f:
            f.write("old\n")
        self.ran = []
        self.codes = {}
        p = mock.patch.object(agent, "log")
        p.start()
        self.addCleanup(p.stop)

    def fake_run(self, args, timeout, stdin=None):
        self.ran.append(args[0])
        return done(self.codes.get(args[0], 0), "", "boom")

    def write(self, owed=False, **kwargs):
        with mock.patch.object(agent, "run_command", self.fake_run):
            return agent.config_write({self.old: "new\n", self.new: "x\n"}, ["test"], ["reload"], "web", owed, **kwargs)

    def read(self, path):
        with open(path) as f:
            return f.read()

    def test_tested_then_reloaded(self):
        self.assertTrue(self.write())
        self.assertEqual(self.ran, ["test", "reload"])
        self.assertEqual((self.read(self.old), self.read(self.new)), ("new\n", "x\n"))
        self.ran.clear()
        self.assertTrue(self.write(), "unchanged")
        self.assertEqual(self.ran, [])

    def test_a_failed_test_restores_and_undoes(self):
        self.codes["test"] = 1
        undone = []
        self.assertIs(self.write(enable=lambda: lambda: undone.append(1)), False)
        self.assertEqual(self.ran, ["test"])
        self.assertEqual(self.read(self.old), "old\n")
        self.assertFalse(os.path.exists(self.new))
        self.assertEqual(undone, [1])

    def test_a_failed_reload_is_owed(self):
        self.codes["reload"] = 1
        self.assertIsNone(self.write())
        self.assertEqual(self.read(self.old), "new\n", "the tested files stay")
        self.ran.clear()
        self.codes.clear()
        self.assertTrue(self.write(owed=True))
        self.assertEqual(self.ran, ["test", "reload"], "owed: reloaded though nothing changed")

    def test_not_running_after_the_reload_restores_and_reloads_again(self):
        self.assertIs(self.write(verify=lambda: False), False)
        self.assertEqual(self.ran, ["test", "reload", "reload"])
        self.assertEqual(self.read(self.old), "old\n")

    def test_litespeed_has_no_test_and_asks_if_it_runs(self):
        conf = config(self.dir)
        os.makedirs(os.path.join(self.dir, "lsws", "bin"))
        open(os.path.join(self.dir, "lsws", "bin", "openlitespeed"), "w").close()
        check = agent.LiteSpeedCheck(dict(conf, litespeed_check_script=os.path.join(self.dir, "lsws", "check", "check.js")))
        calls, clock = [], [1000.0]
        status = iter(["[ERROR] litespeed is not running."] * 100 + ["litespeed is running with PID 5."])

        def run(args, timeout, stdin=None):
            calls.append(args[1])
            clock[0] += 0.5
            return done(0, next(status) if args[1] == "status" else "")

        texts = check.texts(agent.plan(rules()), DAY)
        self.assertEqual(sorted(texts), sorted([check.file, check.page, check.script]))
        with mock.patch.object(agent, "run_command", run), mock.patch.object(agent.time, "time", lambda: clock[0]), \
                mock.patch.object(agent.time, "sleep", lambda n: clock.__setitem__(0, clock[0] + n)):
            self.assertIs(check.write(texts, False), False)
        asked = calls.count("status")
        self.assertEqual(calls, ["restart"] + ["status"] * asked + ["restart"])
        self.assertLessEqual(asked, agent.LITESPEED_WAIT, "asked for LITESPEED_WAIT seconds at most, not forever")
        self.assertFalse(os.path.exists(check.file))
        self.assertFalse(os.path.exists(check.script))


class FakeCheck(agent.WebCheck):
    name, layer = "caddy", "caddy-check"

    def __init__(self, config, results=(), seen=True):
        super().__init__(config)
        self.results, self.seen_value, self.writes = list(results), seen, []
        self.file = os.path.join(config["state_dir"], "check.conf")

    def installed(self):
        return True

    def texts(self, p, day):
        return {self.file: "on %d\n" % day if p["challenge"] else "off\n"}

    def write(self, texts, owed):
        self.writes.append(owed)
        result = self.results.pop(0) if self.results else True
        if result is not False:
            for path, text in texts.items():
                with open(path, "w") as f:
                    f.write(text)
        return result

    def included(self):
        return self.seen_value

    def probe(self, p, day):
        self.probe_note = "" if self.live else "it answers without the check"
        return self.live

    live = True

    def missing(self):
        return "add the import"


class Steps(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)
        self.config = config(self.dir)
        self.p = agent.plan(rules())
        self.off = agent.plan(rules(challenge=None))
        for p in [mock.patch.object(agent, "log"), mock.patch.object(agent, "report", lambda config, events: None)]:
            p.start()
            self.addCleanup(p.stop)

    def firewall(self, check):
        firewall = agent.Agent(self.config)
        firewall.web = {check.name: check}
        self.addCleanup(lambda: [t.close() for t in firewall.check_tails.values()])
        return firewall

    def test_running_only_once_written_and_used(self):
        check = FakeCheck(self.config)
        firewall = self.firewall(check)
        firewall.web_step(self.p, NOW)
        self.assertTrue(firewall.running["caddy-check"])
        firewall.web_step(self.p, NOW + 1)
        self.assertEqual(check.writes, [False], "unchanged: written once")
        check.seen_value = False
        firewall.web_step(self.p, NOW + agent.WEB_LOOK_EVERY)
        self.assertFalse(firewall.running["caddy-check"])
        self.assertEqual(agent.log.call_args[0][0], "add the import")
        firewall.web_step(self.p, NOW + 2 * agent.WEB_LOOK_EVERY)
        self.assertEqual(agent.log.call_count, 1, "said once")

    def test_a_failed_reload_is_owed_across_a_restart(self):
        check = FakeCheck(self.config, results=[None])
        firewall = self.firewall(check)
        firewall.web_step(self.p, NOW)
        self.assertFalse(firewall.running["caddy-check"])
        self.assertTrue(check.owed)
        firewall.save()
        again = agent.Agent(self.config)
        self.assertEqual(again.web_owed, {"caddy": True})
        firewall.web_step(self.p, NOW + 1)
        self.assertEqual(check.writes, [False, True])
        self.assertTrue(firewall.running["caddy-check"])

    def test_refused_files_are_no_layer(self):
        check = FakeCheck(self.config, results=[False])
        firewall = self.firewall(check)
        firewall.web_step(self.p, NOW)
        self.assertFalse(firewall.running["caddy-check"])
        self.assertIn("didn't take", agent.log.call_args[0][0])

    def test_refused_files_arent_tried_again_until_they_change_or_an_hour_passes(self):
        check = FakeCheck(self.config, results=[False] * 10)
        firewall = self.firewall(check)
        firewall.web_step(self.p, NOW)
        for i in range(1, 5):
            firewall.web_step(self.p, NOW + i * agent.WEB_LOOK_EVERY)
        self.assertEqual(len(check.writes), 1, "no test or restart every round")
        firewall.web_step(self.p, NOW + agent.WEB_REFUSED_RETRY)
        self.assertEqual(len(check.writes), 2)
        firewall.web_step(self.p, NOW + agent.WEB_REFUSED_RETRY + 1)
        self.assertEqual(len(check.writes), 2)
        firewall.web_step(self.p, NOW + 86400)
        self.assertEqual(len(check.writes), 3, "other files (a new day's pass) are tried at once")

    def test_running_only_once_the_server_answers_with_it(self):
        check = FakeCheck(self.config)
        check.live = False
        firewall = self.firewall(check)
        firewall.web_step(self.p, NOW)
        self.assertFalse(firewall.running["caddy-check"])
        self.assertEqual(agent.log.call_args[0][0], "it answers without the check")
        check.live = True
        firewall.web_step(self.p, NOW + agent.WEB_LOOK_EVERY)
        self.assertTrue(firewall.running["caddy-check"])

    def test_off_writes_nothing_new_but_turns_off_what_is_there(self):
        check = FakeCheck(self.config)
        firewall = self.firewall(check)
        firewall.web_step(self.off, NOW)
        self.assertEqual(check.writes, [])
        firewall.web_step(self.p, NOW)
        firewall.web_step(self.off, NOW + 1)
        with open(check.file) as f:
            self.assertEqual(f.read(), "off\n")
        self.assertFalse(firewall.running["caddy-check"])

    def test_a_new_day_writes_a_new_pass(self):
        check = FakeCheck(self.config)
        firewall = self.firewall(check)
        firewall.rules, firewall.p = rules(), self.p
        firewall.web_step(self.p, NOW)
        firewall.tick(NOW + 86400)
        with open(check.file) as f:
            self.assertEqual(f.read(), "on %d\n" % (DAY + 1))

    def test_the_check_log_is_read_while_the_check_runs(self):
        check = FakeCheck(self.config)
        check.check_log = os.path.join(self.dir, "check.log")
        open(check.check_log, "w").close()
        firewall = self.firewall(check)
        firewall.web_step(self.p, NOW)
        with open(check.check_log, "a") as f:
            f.write("1793727734 198.51.100.10\n1793727734 198.51.100.10\nbroken\n")
        firewall.read_check_logs()
        self.assertEqual(firewall.checked, {"198.51.100.10": 2})
        check.seen_value = False
        firewall.web_step(self.p, NOW + agent.WEB_LOOK_EVERY)
        self.assertEqual(firewall.check_tails, {})

    def apache(self, modules, includes=True):
        self.config.update(apache_ctl="apachectl", apache_check_file=os.path.join(self.dir, "a.conf"),
                           apache_check_log=os.path.join(self.dir, "a.log"), apache_reload=["reload"])
        ran = []

        def run(args, timeout, stdin=None):
            ran.append(args[1] if len(args) > 1 else args[0])
            if args[1:] == ["-M"]:
                return done(1) if modules is None else done(0, "".join(" %s (shared)\n" % m for m in modules))
            if "DUMP_INCLUDES" in args:
                return done(0, "  (*) %s\n" % self.config["apache_check_file"] if includes else "")
            return done()

        check = agent.ApacheCheck(self.config)
        firewall = self.firewall(check)
        with mock.patch.object(agent, "run_command", run):
            firewall.web_step(self.p, NOW)
        return firewall, ran

    def test_apache(self):
        with mock.patch.object(agent.ApacheCheck, "probe", lambda self, p, day: True):
            firewall, ran = self.apache(["headers_module", "alias_module", "log_config_module"])
        self.assertTrue(firewall.running["apache-check"])
        self.assertEqual(ran, ["-M", "configtest", "reload", "-t"])
        self.assertIn(os.path.join(self.dir, "a.log"), firewall.check_tails)

    def test_apache_without_mod_headers(self):
        firewall, ran = self.apache(["alias_module", "log_config_module"])
        self.assertFalse(firewall.running["apache-check"])
        self.assertEqual(ran, ["-M"], "nothing there, nothing written")
        self.assertIn("Apache lacks headers_module", agent.log.call_args[0][0])

    def test_apache_whose_config_doesnt_load_is_left_alone(self):
        with open(os.path.join(self.dir, "a.conf"), "w") as f:
            f.write("before\n")
        firewall, ran = self.apache(None)
        self.assertEqual(ran, ["-M"])
        with open(os.path.join(self.dir, "a.conf")) as f:
            self.assertEqual(f.read(), "before\n")
        self.assertIn("left as it is", agent.log.call_args[0][0])

    def test_missing_modules_are_asked_again(self):
        self.config.update(apache_ctl="apachectl")
        check = agent.ApacheCheck(self.config)
        answers = iter([done(0, " alias_module (shared)\n log_config_module (shared)\n"),
                        done(0, " headers_module (shared)\n alias_module (shared)\n log_config_module (shared)\n")])
        asked = []
        with mock.patch.object(agent, "run_command", lambda args, timeout: asked.append(1) or next(answers)):
            self.assertFalse(check.has_modules(NOW))
            self.assertFalse(check.has_modules(NOW + 1), "not asked every round")
            self.assertTrue(check.has_modules(NOW + agent.WEB_LOOK_EVERY), "a2enmod headers is seen without a restart")
            self.assertTrue(check.has_modules(NOW + 10 * agent.WEB_LOOK_EVERY))
        self.assertEqual(len(asked), 2, "present modules aren't asked again")

    def test_apache_on_debian_enables_its_conf(self):
        os.makedirs(os.path.join(self.dir, "conf-available"))
        check = agent.ApacheCheck(dict(self.config, apache_root=self.dir, apache_ctl="apache2ctl"))
        check.file = os.path.join(self.dir, "conf-available", "analytics-check.conf")
        ran = []
        with mock.patch.object(agent, "run_command", lambda args, timeout: ran.append(args) or done()):
            undo = check.enable()
            undo()
        self.assertEqual(ran, [["a2enconf", "-q", "analytics-check"], ["a2disconf", "-q", "analytics-check"]])
        os.makedirs(os.path.join(self.dir, "conf-enabled"))
        os.symlink(check.file, os.path.join(self.dir, "conf-enabled", "analytics-check.conf"))
        self.assertIsNone(check.enable(), "already linked")

    def test_clear_turns_each_check_off(self):
        folder = os.path.join(self.dir, "haproxy")
        cfg = os.path.join(self.dir, "haproxy.cfg")
        open(cfg, "w").close()
        conf = dict(self.config, web_checks=["haproxy"], haproxy_dir=folder, haproxy_config=cfg, backend="none")
        check = agent.HAProxyCheck(conf)
        os.makedirs(folder)
        for path, text in check.texts(self.p, DAY).items():
            with open(path, "w") as f:
                f.write(text)
        ran = []
        with mock.patch.object(agent.shutil, "which", lambda name: "/usr/sbin/" + name), \
                mock.patch.object(agent, "run_command", lambda args, timeout, stdin=None: ran.append(args) or done()), \
                mock.patch.object(agent, "nft_installed", lambda: False), \
                mock.patch.object(agent, "nginx_installed", lambda config: False):
            agent.clear(conf)
        with open(os.path.join(folder, "on.lst")) as f:
            self.assertNotIn("0.0.0.0/0", f.read())
        self.assertEqual(ran, [["haproxy", "-c", "-f", cfg], ["systemctl", "reload", "haproxy"]])


if __name__ == "__main__":
    unittest.main()
