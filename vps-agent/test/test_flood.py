"""Flood protection (sdk/protocols/firewall.md, "Flood protection" and "Which
layers a server has"): the text that reaches nftables and nginx, what is read
back from nginx's logs and the kernel's sets, and what is reported.

    python3 -m unittest discover -s test
"""
import importlib.machinery
import importlib.util
import json
import os
import shutil
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
AGENT = os.path.join(HERE, "..", "analytics-agent")
CASES = os.path.join(HERE, "..", "..", "protocols", "challenge-cases.json")
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

FLOOD = {"conn_rate": 30, "conn_max": 100, "req_rate": 20, "req_burst": 60, "ban": 600,
         "exempt": ["173.245.48.0/20", "66.249.64.0/27"]}


def rules(**extra):
    base = {"v": 1, "enabled": True, "mode": "block", "sync": 60, "allow": ["203.0.113.7"],
            "goodbots": ["23.98.142.176/28", "2a05:d014:f2f:4600::/56"], "flood": dict(FLOOD),
            "origin": {"only": ["173.245.48.0/20", "2400:cb00::/32"]},
            "challenge": dict(CHALLENGE_CASES["challenge"])}
    base.update(extra)
    return base


def config(tmp=None, **extra):
    tmp = tmp or tempfile.mkdtemp()
    base = dict(agent.DEFAULTS, site_id="a" * 24, secret=CHALLENGE_CASES["secret"], endpoint="https://c.example",
                state_dir=tmp, sites=[], backend="nftables", ports=[80, 443],
                nginx_flood_file=os.path.join(tmp, "analytics-flood.conf"),
                nginx_check_file=os.path.join(tmp, "analytics-check.conf"),
                nginx_check_log=os.path.join(tmp, "analytics-check.log"))
    base.update(extra)
    return base


def done(code=0, stdout="", stderr=""):
    return SimpleNamespace(returncode=code, stdout=stdout, stderr=stderr)


class KernelRuleset(unittest.TestCase):
    def ruleset(self, **extra):
        return agent.flood_ruleset({"ports": [80, 443]}, agent.plan(rules(**extra)))

    def rules_of(self, text):
        prefix = "add rule inet analytics_flood prerouting "
        return [line[len(prefix):] for line in text.splitlines() if line.startswith(prefix)]

    def test_limits_on_the_web_ports_tcp_and_udp(self):
        rules_ = self.rules_of(self.ruleset())
        self.assertEqual(rules_[:4], ["iif lo accept", "meta l4proto != { tcp, udp } accept",
                                      "tcp dport != { 80, 443 } accept", "udp dport != { 80, 443 } accept"])
        self.assertIn("ct state new update @rate4 { ip saddr timeout 60s limit rate over 30/second burst 60 packets }"
                      " add @ban4 { ip saddr timeout 600s } drop", rules_)
        self.assertIn("ct state new add @conns4 { ip saddr ct count over 100 } add @ban4 { ip saddr timeout 600s } drop", rules_)

    def test_ssh_and_other_ports_are_never_touched(self):
        text = self.ruleset()
        self.assertNotIn("22", " ".join(l for l in self.rules_of(text) if "dport" in l))
        # Everything but the web ports is accepted before any limit or lock.
        rules_ = self.rules_of(text)
        first_limit = min(i for i, r in enumerate(rules_) if "@origin" in r or "@ban" in r or "@rate" in r)
        self.assertLess(rules_.index("tcp dport != { 80, 443 } accept"), first_limit)

    def test_ipv6_is_counted_and_banned_by_its_64(self):
        rules_ = self.rules_of(self.ruleset())
        mask = "ip6 saddr & ffff:ffff:ffff:ffff::"
        self.assertIn("%s @ban6 drop" % mask, rules_)
        self.assertIn("ct state new update @rate6 { %s timeout 60s limit rate over 30/second burst 60 packets }"
                      " add @ban6 { %s timeout 600s } drop" % (mask, mask), rules_)
        self.assertIn("ct state new add @conns6 { %s ct count over 100 } add @ban6 { %s timeout 600s } drop" % (mask, mask), rules_)

    def test_exempt_holds_allow_goodbots_exempt_and_the_local_ranges(self):
        text = self.ruleset()
        exempt4 = [l for l in text.splitlines() if l.startswith("add element inet analytics_flood exempt4")][0]
        for net in ("203.0.113.7/32", "23.98.142.176/28", "173.245.48.0/20", "66.249.64.0/27",
                    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "100.64.0.0/10", "169.254.0.0/16"):
            self.assertIn(net, exempt4)
        exempt6 = [l for l in text.splitlines() if l.startswith("add element inet analytics_flood exempt6")][0]
        for net in ("2a05:d014:f2f:4600::/56", "::1/128", "fc00::/7", "fe80::/10"):
            self.assertIn(net, exempt6)
        rules_ = self.rules_of(text)
        self.assertLess(rules_.index("ip saddr @exempt4 accept"), rules_.index("ip saddr @ban4 drop"))

    def test_local_ranges_come_before_the_origin_lock_and_allow_is_in_it(self):
        text = self.ruleset()
        rules_ = self.rules_of(text)
        self.assertLess(rules_.index("ip saddr @local4 accept"), rules_.index("ip saddr != @origin4 drop"))
        origin4 = [l for l in text.splitlines() if l.startswith("add element inet analytics_flood origin4")][0]
        self.assertIn("173.245.48.0/20", origin4)
        self.assertIn("203.0.113.7/32", origin4)
        # The search engines' ranges in flood.exempt don't get around the lock.
        self.assertNotIn("66.249.64.0/27", origin4)
        self.assertLess(rules_.index("ip saddr != @origin4 drop"), rules_.index("ip saddr @exempt4 accept"))

    def test_the_origin_lock_counts_per_source_apart_from_dropping(self):
        rules_ = self.rules_of(self.ruleset())
        self.assertIn("ip saddr != @origin4 update @seen4 { ip saddr }", rules_)
        self.assertIn("ip6 saddr != @origin6 update @seen6 { ip6 saddr & ffff:ffff:ffff:ffff:: }", rules_)
        self.assertIn("ip6 saddr != @origin6 drop", rules_)

    def test_monitor_mode_only_counts(self):
        rules_ = self.rules_of(self.ruleset(mode="monitor"))
        self.assertFalse([r for r in rules_ if r.endswith(" drop")], "nothing is dropped in monitor mode")
        self.assertIn("ip saddr @ban4 accept", rules_)
        # Still banned (counted), so it is reported once.
        self.assertTrue(any("add @ban4" in r for r in rules_))
        self.assertTrue(any("update @seen4" in r for r in rules_))

    def test_without_origin_or_flood_their_rules_are_left_out(self):
        no_origin = self.rules_of(self.ruleset(origin=None))
        self.assertFalse([r for r in no_origin if "@origin" in r or "@seen" in r])
        no_flood = self.rules_of(self.ruleset(flood=None))
        self.assertFalse([r for r in no_flood if "@ban" in r or "@rate" in r or "@exempt" in r])
        self.assertTrue([r for r in no_flood if "@origin4" in r])

    def test_a_limit_the_rules_leave_out_has_no_rule(self):
        rules_ = self.rules_of(self.ruleset(flood=dict(FLOOD, conn_max=None)))
        self.assertFalse([r for r in rules_ if "ct count" in r])
        self.assertTrue([r for r in rules_ if "limit rate" in r])

    def test_the_table_is_changed_in_place_not_deleted(self):
        text = self.ruleset()
        self.assertNotIn("delete table", text, "deleting the table would let every banned address back in")
        self.assertIn("flush chain inet analytics_flood prerouting", text)
        for name in ("ban", "seen", "rate", "conns"):
            self.assertNotIn("flush set inet analytics_flood %s4" % name, text)
        for name in ("local", "exempt", "origin"):
            self.assertIn("flush set inet analytics_flood %s4" % name, text)

    def test_the_set_declarations_do_not_depend_on_the_rules(self):
        decl = lambda text: [l for l in text.splitlines() if l.startswith("  set ")]
        a = decl(self.ruleset())
        b = decl(self.ruleset(mode="monitor", flood=dict(FLOOD, ban=60, conn_rate=5), origin=None))
        self.assertEqual(a, b, "a set declared differently can't be changed in place")

    def test_fresh_starts_the_table_over(self):
        text = agent.flood_ruleset({"ports": [80, 443]}, agent.plan(rules()), fresh=True)
        self.assertIn("table inet analytics_flood\ndelete table inet analytics_flood\n", text)

    def test_nothing_from_the_network_but_addresses_reaches_the_ruleset(self):
        text = self.ruleset(flood=dict(FLOOD, exempt=["1.2.3.4 }; chain x { policy drop; }"], conn_rate="30; drop",
                                       ban={"x": 1}),
                            origin={"only": ["5.6.7.8; drop", "198.51.100.0/24"]})
        self.assertNotIn("policy drop", text.replace("policy accept", ""))
        self.assertNotIn("30; drop", text)
        self.assertIn("timeout 600s", text, "a ban that isn't a number is the default")
        self.assertFalse([r for r in self.rules_of(text) if "limit rate" in r])

    def test_a_bool_is_not_a_number(self):
        p = agent.plan(rules(flood=dict(FLOOD, conn_rate=True)))
        self.assertIsNone(p["flood"]["conn_rate"])

    def test_rules_off_means_no_flood_origin_or_check(self):
        p = agent.plan(rules(enabled=False))
        self.assertEqual((p["flood"], p["origin"], p["challenge"]), (None, None, None))

    def test_an_origin_lock_naming_nobody_fails_open(self):
        self.assertIsNone(agent.plan(rules(origin={"only": ["not an address"]}))["origin"])

    def test_the_address_table_is_not_rewritten_by_a_flood_change(self):
        a = agent.main_plan(agent.plan(rules()))
        b = agent.main_plan(agent.plan(rules(flood=None, origin=None, challenge=None)))
        self.assertEqual(a, b)


    def test_the_servers_own_traffic_over_lo_is_never_limited(self):
        rules_ = self.rules_of(self.ruleset())
        self.assertEqual(rules_[0], "iif lo accept", "before the origin lock and every limit")
        # One of our addresses as the source on another interface is spoofed.
        self.assertFalse([r for r in rules_ if "fib saddr" in r])

class KernelApply(unittest.TestCase):
    def test_a_refused_change_starts_the_table_over(self):
        calls = []

        def fake(*args, stdin=None):
            calls.append(stdin or args)
            return done(1, stderr="Could not process rule: File exists") if len(calls) == 1 else done(0)

        with mock.patch.object(agent, "nft", fake), mock.patch.object(agent, "log"):
            self.assertTrue(agent.flood_apply({"ports": [80, 443]}, agent.plan(rules())))
        self.assertNotIn("delete table", calls[0])
        self.assertIn("delete table", calls[1])

    def test_no_flood_and_no_origin_removes_the_table(self):
        calls = []
        with mock.patch.object(agent, "nft", lambda *a, stdin=None: calls.append(a) or done()), \
                mock.patch.object(agent, "nft_table_present", lambda table=agent.TABLE: True):
            agent.flood_apply({"ports": [80]}, agent.plan(rules(flood=None, origin=None)))
        self.assertEqual(calls, [("delete", "table", "inet", "analytics_flood")])

    def test_bans_from_nginx_go_in_as_checked_addresses(self):
        sent = []
        with mock.patch.object(agent, "nft", lambda *a, stdin=None: sent.append(stdin) or done()):
            agent.nft_ban({"198.51.100.9": 600, "2001:db8:0:1::/64": 600})
        self.assertEqual(sent[0], "add element inet analytics_flood ban4 { 198.51.100.9 timeout 600s }\n"
                                  "add element inet analytics_flood ban6 { 2001:db8:0:1:: timeout 600s }\n")

    def test_set_elements_are_read_from_nfts_json(self):
        out = json.dumps({"nftables": [{"metainfo": {}}, {"set": {"name": "ban6", "elem": [
            {"elem": {"val": "2001:db8:0:1::", "timeout": 600, "expires": 592, "counter": {"packets": 56, "bytes": 4144}}},
            "not an element", {"elem": {"val": {"prefix": {}}}}]}}]})
        with mock.patch.object(agent, "nft", lambda *a, stdin=None: done(0, out)):
            self.assertEqual(agent.flood_elements("ban6"), {"2001:db8:0:1::": (56, 592)})


    def test_a_table_started_over_says_so(self):
        replies = iter([done(1, stderr="File exists"), done(0)])
        with mock.patch.object(agent, "nft", lambda *a, stdin=None: next(replies)), mock.patch.object(agent, "log"):
            self.assertEqual(agent.flood_apply({"ports": [80]}, agent.plan(rules())), "fresh")

    def test_bans_go_in_by_chunks_each_with_its_time_and_a_full_set_stops_them(self):
        sent = []

        def fake(*a, stdin=None):
            sent.append(stdin)
            return done(1, stderr="Could not process rule: No space left on device") if len(sent) == 2 else done()

        with mock.patch.object(agent, "nft", fake), mock.patch.object(agent, "log"):
            ok = agent.nft_ban({"198.18.%d.%d" % (i // 256, i % 256): 600 for i in range(2500)})
        self.assertFalse(ok)
        self.assertEqual(len(sent), 2, "the rest isn't tried once the set is full")
        self.assertEqual(sent[0].count(" timeout 600s"), agent.NFT_BAN_CHUNK)
        sent.clear()
        with mock.patch.object(agent, "nft", lambda *a, stdin=None: sent.append(stdin) or done()):
            self.assertTrue(agent.nft_ban({"198.51.100.9": 30, "198.51.100.10": 0}))
        self.assertEqual(sent, ["add element inet analytics_flood ban4 { 198.51.100.9 timeout 30s }\n"])

    def test_a_hung_or_missing_command_is_a_failure(self):
        out = agent.run_command(["sleep", "5"], 0.2)
        self.assertEqual(out.returncode, 1)
        self.assertIn("timed out", out.stderr)
        self.assertEqual(agent.run_command(["/nonexistent/nft"], 1).returncode, 1)
        seen = []
        with mock.patch.object(agent.subprocess, "run", lambda args, **kw: seen.append(kw.get("timeout")) or done()):
            agent.nft("list", "tables")
        self.assertEqual(seen, [agent.NFT_TIMEOUT])

class Keys(unittest.TestCase):
    def test_ipv6_by_its_64_and_mapped_ipv4_as_ipv4(self):
        self.assertEqual(agent.flood_key("2001:db8:0:1::42"), "2001:db8:0:1::/64")
        self.assertEqual(agent.flood_key("2001:DB8:0:1:ffff::1"), "2001:db8:0:1::/64")
        self.assertEqual(agent.flood_key("2001:db8:0:1::"), "2001:db8:0:1::/64")
        self.assertEqual(agent.flood_key("::ffff:203.0.113.7"), "203.0.113.7")
        self.assertEqual(agent.flood_key("203.0.113.7"), "203.0.113.7")
        self.assertIsNone(agent.flood_key("203.0.113.7; drop"))

    def test_covered(self):
        nets = agent.networks(["66.249.64.0/27", "2001:4860:4801:10::/64"])
        self.assertTrue(agent.covered("66.249.64.5", nets))
        self.assertTrue(agent.covered("::ffff:66.249.64.5", nets))
        self.assertTrue(agent.covered("2001:4860:4801:10::7", nets))
        self.assertFalse(agent.covered("66.249.65.5", nets))
        self.assertFalse(agent.covered("nonsense", nets))


class Pass(unittest.TestCase):
    """challenge-cases.json is shared by every client; the agent's nginx uses `who` = *."""

    def test_the_shared_tokens(self):
        for case in CHALLENGE_CASES["tokens"]:
            if case["who"] == "*":
                self.assertEqual(agent.challenge_token(CHALLENGE_CASES["secret"], agent.utc_day(case["now"])), case["token"])

    def test_the_star_token_is_not_an_address_token(self):
        star = agent.challenge_token(CHALLENGE_CASES["secret"], 20761)
        for case in CHALLENGE_CASES["tokens"]:
            if case["who"] != "*":
                self.assertNotEqual(star, case["token"])
                self.assertEqual(agent.challenge_token(CHALLENGE_CASES["secret"], 20761, case["who"]), case["token"])


class NginxFiles(unittest.TestCase):
    def setUp(self):
        self.config = config()
        self.day = agent.utc_day(CHALLENGE_CASES["tokens"][0]["now"])

    def flood_text(self, **extra):
        return agent.nginx_flood_text(self.config, agent.plan(rules(**extra)), self.day)

    def check_text(self, **extra):
        return agent.nginx_check_text(self.config, agent.plan(rules(**extra)), self.day)

    def test_request_limits(self):
        text = self.flood_text()
        self.assertIn("limit_req_zone $sg_flood_key zone=analytics_flood:10m rate=20r/s;", text)
        self.assertIn("limit_req zone=analytics_flood burst=60 nodelay;", text)
        self.assertIn("limit_req_status 429;", text)
        self.assertNotIn("limit_req_dry_run", text)

    def test_no_limits_without_flood(self):
        text = self.flood_text(flood=None)
        self.assertNotIn("limit_req", text)
        text = self.flood_text(flood=dict(FLOOD, req_rate=None))
        self.assertNotIn("limit_req", text)

    def test_the_key_is_empty_for_exempt_addresses_and_static_files(self):
        text = self.flood_text()
        geo = text[text.index("geo $sg_flood_exempt"):text.index("}", text.index("geo $sg_flood_exempt"))]
        for net in ("203.0.113.7/32", "23.98.142.176/28", "173.245.48.0/20", "66.249.64.0/27", "10.0.0.0/8",
                    "127.0.0.0/8", "::1/128", "fc00::/7", "2a05:d014:f2f:4600::/56"):
            self.assertIn("    %s 1;" % net, geo)
        self.assertIn('"~*\\.(css|js|', text)
        self.assertIn('map "$sg_flood_exempt$sg_flood_static" $sg_flood_key {\n    "00" $sg_flood_addr;\n    default "";\n}', text)

    def test_ipv6_counts_by_its_first_eight_bytes_but_mapped_ipv4_whole(self):
        self.assertIn('"~(?s)^(?!\\x00{10}\\xff\\xff)(.{8}).{8}$" $1;', self.flood_text())

    def test_the_check_maps_carry_todays_and_yesterdays_pass(self):
        text = self.flood_text()
        star = [c for c in CHALLENGE_CASES["tokens"] if c["who"] == "*"][0]["token"]
        self.assertIn('    "%s" 1;' % star, text)
        self.assertIn('    "%s" 1;' % agent.challenge_token(CHALLENGE_CASES["secret"], self.day - 1), text)
        self.assertNotIn(agent.challenge_token(CHALLENGE_CASES["secret"], self.day + 1), text)
        self.assertIn("map $cookie___sg_passn $sg_check_pass {", text)
        self.assertIn('    "11100" 1;', text)

    def test_skip_paths_and_exempt_addresses(self):
        text = self.flood_text()
        self.assertIn('    "~*^/api/" 0;', text)
        self.assertIn('    "~*^/\\.well-known/" 0;', text)
        geo = text[text.index("geo $sg_check_exempt"):]
        self.assertIn("2001:4860:4801:10::/64 1;", geo)
        self.assertIn("66.249.64.0/27 1;", geo)
        self.assertIn("203.0.113.7/32 1;", geo, "allow is never checked")
        self.assertIn("23.98.142.176/28 1;", geo, "nor goodbots")

    def test_a_skip_entry_that_isnt_a_plain_path_is_dropped(self):
        text = self.flood_text(challenge={"skip": ['/a" 1; } server { ', "/b$x", "/c\\d", "no-slash", "/OK/"], "exempt": []})
        self.assertIn('    "~*^/ok/" 0;', text)
        for bad in ('/a"', "$x", "\\d", "no-slash"):
            self.assertNotIn(bad, text)

    def test_with_challenge_null_the_check_is_a_no_op(self):
        text = self.flood_text(challenge=None)
        self.assertIn("map $request_method $sg_check {\n    default 0;\n}", text)
        self.assertNotIn("sg_check_pass", text)
        self.assertIn("log_format analytics_check", text, "the server file still names it")
        check = self.check_text(challenge=None)
        self.assertIn("if ($sg_check) {", check)

    def test_the_check_page(self):
        text = self.check_text()
        for line in ("if ($sg_check) {\n    rewrite ^ /__sg_check last;\n}", "location = /__sg_check {", "    internal;",
                     '    default_type "text/html; charset=utf-8";',
                     '    add_header Cache-Control "no-store" always;',
                     '    add_header X-Robots-Tag "noindex" always;',
                     "    access_log %s analytics_check;" % self.config["nginx_check_log"]):
            self.assertIn(line, text)
        csp = [l for l in text.splitlines() if "Content-Security-Policy" in l][0]
        self.assertIn("script-src 'nonce-$request_id'", csp)
        self.assertTrue(csp.endswith(" always;"))
        body = [l for l in text.splitlines() if l.startswith("    return 503 ")][0]
        star = [c for c in CHALLENGE_CASES["tokens"] if c["who"] == "*"][0]["token"]
        self.assertIn("<script nonce='$request_id'>", body)
        self.assertIn("var v='%s'" % star, body)
        self.assertIn("Max-Age=86400; Path=/; SameSite=Lax", body)
        self.assertIn("s=location.protocol==='https:'", body)
        self.assertIn("(s?'; Secure':'')", body)
        self.assertIn("if(!h()){m.textContent='Your browser turned down", body, "reloads only if the cookie reads back")
        self.assertIn("<noscript>", body)
        inner = body[len('    return 503 "'):-2]
        self.assertNotIn('"', inner)
        self.assertNotIn("\\", inner)

    def test_the_check_page_stops_after_three_reloads_a_minute(self):
        text = self.check_text()
        csp = [l for l in text.splitlines() if "Content-Security-Policy" in l][0]
        self.assertIn("frame-ancestors 'none'", csp)
        body = [l for l in text.splitlines() if l.startswith("    return 503 ")][0]
        self.assertIn("var k='__sg_tries',r=0,t;try{t=JSON.parse(sessionStorage.getItem(k)||'[]')"
                      ".filter(function(x){return Date.now()-x<60000;});", body)
        self.assertIn("catch(e){t=/(?:^|; )__sg_tries=([0-9]+)/.exec(document.cookie)", body, "a cookie where storage throws")
        self.assertIn("if(r>=3){m.textContent='This page could not be opened", body)
        # Counted only once the cookie reads back, and before the reload
        # (test_webservers.Script runs it).
        self.assertLess(body.index("if(!h())"), body.index("__sg_tries"))
        self.assertLess(body.index("sessionStorage.setItem"), body.index("location.reload()"))

    def test_a_config_path_that_isnt_plain_is_refused(self):
        with self.assertRaises(ValueError):
            agent.nginx_check_text(dict(self.config, nginx_check_log="/var/log/x; return 200"), agent.plan(rules()), 1)


class NginxWrite(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)
        self.a, self.b = os.path.join(self.dir, "a.conf"), os.path.join(self.dir, "b.conf")
        with open(self.a, "w") as f:
            f.write("old a\n")

    def read(self, path):
        with open(path) as f:
            return f.read()

    def run_write(self, test_code):
        calls = []

        def run(args, **kwargs):
            calls.append(args)
            return done(test_code if args == ["nginx", "-t"] else 0)

        with mock.patch.object(agent.subprocess, "run", run), mock.patch.object(agent, "log"):
            ok = agent.nginx_write({"nginx_test": ["nginx", "-t"], "nginx_reload": ["nginx", "-s", "reload"]},
                                   {self.a: "new a\n", self.b: "new b\n"})
        return ok, calls

    def test_a_failed_test_restores_every_file_and_skips_the_reload(self):
        ok, calls = self.run_write(1)
        self.assertFalse(ok)
        self.assertEqual(self.read(self.a), "old a\n")
        self.assertFalse(os.path.exists(self.b))
        self.assertNotIn(["nginx", "-s", "reload"], calls)

    def test_a_passed_test_reloads(self):
        ok, calls = self.run_write(0)
        self.assertTrue(ok)
        self.assertEqual(self.read(self.b), "new b\n")
        self.assertEqual(calls, [["nginx", "-t"], ["nginx", "-s", "reload"]])

    def test_unchanged_files_are_left_alone(self):
        self.run_write(0)
        ok, calls = self.run_write(0)
        self.assertTrue(ok)
        self.assertEqual(calls, [])

    def test_a_failed_reload_is_owed_and_done_next_time(self):
        calls, code = [], {"reload": 1}

        def run(args, **kwargs):
            calls.append(args)
            return done(code["reload"] if args == ["nginx", "-s", "reload"] else 0)

        conf = {"nginx_test": ["nginx", "-t"], "nginx_reload": ["nginx", "-s", "reload"]}
        files = {self.a: "new a\n"}
        with mock.patch.object(agent.subprocess, "run", run), mock.patch.object(agent, "log"):
            self.assertIsNone(agent.nginx_write(conf, files), "written, not live")
            self.assertEqual(self.read(self.a), "new a\n")
            calls.clear()
            code["reload"] = 0
            self.assertTrue(agent.nginx_write(conf, files, owed=True))
        self.assertEqual(calls, [["nginx", "-t"], ["nginx", "-s", "reload"]], "the same files, tested and reloaded")

    def test_a_hung_test_is_a_refusal(self):
        def run(args, **kwargs):
            raise agent.subprocess.TimeoutExpired(args, kwargs["timeout"])

        with mock.patch.object(agent.subprocess, "run", run), mock.patch.object(agent, "log"):
            ok = agent.nginx_write({"nginx_test": ["nginx", "-t"], "nginx_reload": ["nginx", "-s", "reload"]},
                                   {self.a: "new a\n"})
        self.assertIs(ok, False)
        self.assertEqual(self.read(self.a), "old a\n")


class NginxDump(unittest.TestCase):
    def test_includes_and_error_logs(self):
        files, logs = agent.parse_nginx_dump("\n".join([
            "nginx: the configuration file /etc/nginx/nginx.conf syntax is ok",
            "# configuration file /etc/nginx/nginx.conf:",
            "error_log /var/log/nginx/error.log;",
            "http {",
            "    include /etc/nginx/analytics-flood.conf;",
            "    # error_log /var/log/commented.log;",
            "# configuration file /etc/nginx/analytics-flood.conf:",
            "# configuration file /etc/nginx/sites-enabled/default:",
            "    error_log  /var/log/nginx/site.error.log warn;",
            "    error_log syslog:server=unix:/dev/log;",
            "    error_log stderr;",
            "    error_log logs/relative.log;",
            "    error_log /var/log/nginx/error.log;",
        ]))
        self.assertEqual(files, {"/etc/nginx/nginx.conf", "/etc/nginx/analytics-flood.conf", "/etc/nginx/sites-enabled/default"})
        self.assertEqual(logs, ["/var/log/nginx/error.log", "/var/log/nginx/site.error.log"])


class LimitLines(unittest.TestCase):
    def test_real_lines(self):
        # As nginx 1.26 and 1.31 write them, block and monitor (dry run).
        self.assertEqual(agent.parse_limited(
            '2026/11/03 16:20:01 [error] 7#7: *5 limiting requests, excess: 3.968 by zone "analytics_flood", client: '
            '127.0.0.1, server: , request: "GET /api/x HTTP/1.1", host: "127.0.0.1"'), "127.0.0.1")
        self.assertEqual(agent.parse_limited(
            '2026/11/03 16:20:33 [error] 8#8: *5 limiting requests, dry run, excess: 3.962 by zone "analytics_flood", '
            'client: 2001:db8:0:1::42, server: example.com, request: "GET / HTTP/2.0", host: "example.com"'), "2001:db8:0:1::42")

    def test_other_zones_and_lines_are_not_ours(self):
        self.assertIsNone(agent.parse_limited(
            '2026/11/03 16:20:01 [error] 7#7: *5 limiting requests, excess: 3.968 by zone "site_own", client: 1.2.3.4, server: '))
        self.assertIsNone(agent.parse_limited('2026/11/03 [error] open() "/x" failed, client: 1.2.3.4, server: '))
        self.assertIsNone(agent.parse_limited(
            '[error] limiting requests, excess: 1 by zone "analytics_flood", client: 1.2.3.4; rm -rf /, server: '))

    def test_a_forged_referer_is_not_a_limit(self):
        # nginx copies Referer and Host into its lines unescaped.
        forged = ('2026/11/03 16:20:01 [error] 7#7: *5 open() "/usr/share/nginx/html/x" failed (2: No such file or '
                  'directory), client: 198.51.100.66, server: example.com, request: "GET /x HTTP/1.1", host: '
                  '"example.com", referrer: "limiting requests, excess: 1 by zone "analytics_flood", client: 203.0.113.50,"')
        self.assertIsNone(agent.parse_limited(forged))
        self.assertIsNone(agent.parse_limited(
            'x 2026/11/03 16:20:01 [error] 7#7: *5 limiting requests, excess: 1 by zone "analytics_flood", client: 1.2.3.4, '))


class Tail(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)
        self.path = os.path.join(self.dir, "error.log")

    def append(self, text, path=None):
        with open(path or self.path, "a") as f:
            f.write(text)

    def tail(self):
        tail = agent.LogTail(self.path)
        self.addCleanup(tail.close)
        return tail

    def test_only_what_is_written_after_it_starts(self):
        self.append("before\n")
        tail = self.tail()
        self.assertEqual(tail.lines(), [])
        self.append("one\ntwo\npart")
        self.assertEqual(tail.lines(), ["one", "two"])
        self.append("ial\n")
        self.assertEqual(tail.lines(), ["partial"])

    def test_a_renamed_log_is_read_to_its_end_then_the_new_one_from_its_start(self):
        self.append("")
        tail = self.tail()
        self.append("old 1\n")
        self.assertEqual(tail.lines(), ["old 1"])
        self.append("old 2\n")
        os.rename(self.path, self.path + ".1")
        self.append("new 1\n")
        self.assertEqual(tail.lines(), ["old 2", "new 1"])
        self.append("new 2\n")
        self.assertEqual(tail.lines(), ["new 2"])

    def test_a_truncated_log_is_read_again_from_the_top(self):
        self.append("x" * 100 + "\n")
        tail = self.tail()
        open(self.path, "w").close()  # copytruncate
        self.append("after\n")
        self.assertEqual(tail.lines(), ["after"])

    def test_a_log_that_appears_later_is_read_from_its_start(self):
        tail = self.tail()
        self.assertEqual(tail.lines(), [])
        self.append("first\n")
        self.assertEqual(tail.lines(), ["first"])

    def test_a_removed_log_waits_for_the_next_one(self):
        self.append("")
        tail = self.tail()
        os.remove(self.path)
        self.assertEqual(tail.lines(), [])
        self.append("again\n")
        self.assertEqual(tail.lines(), ["again"])

    def test_a_backlog_beyond_four_reads_is_skipped(self):
        self.append("")
        tail = self.tail()
        self.append("".join("line %d\n" % i for i in range(1000)))
        lines = tail.lines(limit=100)
        self.assertTrue(lines and all(l.startswith("line ") for l in lines))
        self.assertEqual(lines[-1], "line 999")
        self.assertLess(len(lines), 20)


class Flows(unittest.TestCase):
    """The agent between fetches: nginx's logs, the kernel's sets, reports."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)
        self.config = config(self.dir)
        self.error_log = os.path.join(self.dir, "error.log")
        open(self.error_log, "w").close()
        open(self.config["nginx_check_log"], "w").close()
        self.sent, self.banned, self.written = [], [], []
        self.elements = {}
        self.included = {self.config["nginx_flood_file"], self.config["nginx_check_file"]}
        patches = [
            mock.patch.object(agent, "report", lambda config, events: self.sent.extend(events)),
            mock.patch.object(agent, "nft_ban", lambda timeouts: self.banned.append(dict(timeouts)) or True),
            mock.patch.object(agent, "flood_elements", lambda name: dict(self.elements.get(name, {}))),
            mock.patch.object(agent, "nginx_installed", lambda config: True),
            mock.patch.object(agent, "nginx_write", lambda config, texts, owed=False: self.written.append(texts) or True),
            mock.patch.object(agent, "nginx_dump", lambda config: (set(self.included), [self.error_log])),
            mock.patch.object(agent, "log"),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def firewall(self, **extra):
        firewall = agent.Agent(self.config)
        firewall.rules = rules(**extra)
        firewall.p = agent.plan(firewall.rules)
        firewall.flood_applied = "x"
        firewall.nginx_step(firewall.p, 1000)
        self.addCleanup(lambda: [tail.close() for tail in firewall.tails.values()])
        return firewall

    def limited(self, address, times=1):
        with open(self.error_log, "a") as f:
            for _ in range(times):
                f.write('2026/11/03 16:20:01 [error] 7#7: *5 limiting requests, excess: 3.968 by zone "analytics_flood", '
                        'client: %s, server: , request: "GET / HTTP/1.1", host: "x"\n' % address)

    def test_nginx_limited_addresses_are_banned_in_the_kernel_and_reported_once(self):
        firewall = self.firewall()
        self.limited("198.51.100.9", 3)
        self.limited("2001:db8:0:1::42")
        self.limited("2001:db8:0:1::99")
        self.limited("66.249.64.5")  # exempt: never banned
        firewall.tick(1001)
        self.assertEqual(self.banned, [{"198.51.100.9": 600, "2001:db8:0:1::/64": 600}])
        self.assertEqual(self.sent, [], "reported once it has run a little")
        self.limited("198.51.100.9", 2)
        firewall.tick(1001 + agent.BAN_REPORT_AFTER)
        self.assertEqual(sorted((e["ip"], e["rule"], e["action"], e["hits"], e["method"], e["path"]) for e in self.sent),
                         [("198.51.100.9", "rate", "block", 5, "", ""), ("2001:db8:0:1::/64", "rate", "block", 2, "", "")])
        self.sent.clear()
        self.limited("198.51.100.9")
        firewall.tick(1100)
        self.assertEqual(self.sent, [], "once per ban")
        self.assertEqual(len(self.banned), 1, "already banned")
        firewall.tick(1001 + 601)
        self.limited("198.51.100.9")
        firewall.tick(1001 + 602)
        firewall.tick(1001 + 602 + agent.BAN_REPORT_AFTER)
        self.assertEqual([(e["ip"], e["rule"]) for e in self.sent], [("198.51.100.9", "rate")], "a new ban after the last ran out")

    def test_monitor_mode_reports_as_monitor(self):
        firewall = self.firewall(mode="monitor")
        self.elements["ban4"] = {"198.51.100.2": (50, 590)}
        firewall.tick(2000)
        firewall.tick(2000 + agent.FLOOD_READ_EVERY)
        self.assertEqual([(e["rule"], e["action"]) for e in self.sent], [("flood", "monitor")])

    def test_monitor_mode_leaves_nginx_limiting_nothing(self):
        # limit_req_dry_run can't be scoped to one zone: it would make the
        # site's own limit_req lines log-only too. So nginx limits nothing.
        firewall = self.firewall(mode="monitor")
        text = self.written[0][self.config["nginx_flood_file"]]
        self.assertFalse([l for l in text.splitlines() if l.startswith("limit_req")])
        self.assertFalse(firewall.running["nginx"])
        self.assertTrue(firewall.running["nginx-check"], "the check still runs where the rules send it")
        # Read for the site's own limits (TheSitesOwnRefusals), not for ours.
        self.assertIn(self.error_log, firewall.tails)
        self.limited("198.51.100.9")
        firewall.tick(1001)
        firewall.tick(1001 + agent.BAN_REPORT_AFTER)
        self.assertEqual((self.banned, self.sent), ([], []))

    def test_without_the_flood_table_nginx_bans_are_still_reported(self):
        firewall = self.firewall()
        firewall.flood_applied = ""
        self.limited("198.51.100.9")
        firewall.tick(1001)
        firewall.tick(1001 + agent.BAN_REPORT_AFTER)
        self.assertEqual(self.banned, [])
        self.assertEqual([e["rule"] for e in self.sent], ["rate"])

    def test_kernel_bans_are_reported_once_each_with_their_packets(self):
        firewall = self.firewall()
        self.elements["ban4"] = {"198.51.100.2": (50, 590)}
        self.elements["ban6"] = {"2001:db8:0:1::": (7, 300)}
        firewall.tick(2000)
        firewall.tick(2000 + agent.FLOOD_READ_EVERY)
        self.elements["ban4"] = {"198.51.100.2": (80, 575)}
        firewall.tick(2000 + 2 * agent.FLOOD_READ_EVERY)
        rows = sorted((e["ip"], e["rule"], e["hits"]) for e in self.sent)
        self.assertEqual(rows, [("198.51.100.2", "flood", 50), ("2001:db8:0:1::/64", "flood", 7)])
        self.sent.clear()
        for t in range(3, 10):
            firewall.tick(2000 + t * agent.FLOOD_READ_EVERY)
        self.assertEqual(self.sent, [])
        # Gone, then banned again: a new ban.
        self.elements["ban4"] = {}
        firewall.tick(2000 + 10 * agent.FLOOD_READ_EVERY)
        self.elements["ban4"] = {"198.51.100.2": (3, 599)}
        firewall.tick(2000 + 11 * agent.FLOOD_READ_EVERY)
        firewall.tick(2000 + 12 * agent.FLOOD_READ_EVERY)
        self.assertEqual([(e["ip"], e["hits"]) for e in self.sent], [("198.51.100.2", 3)])

    def test_bans_reported_are_remembered_across_a_restart(self):
        firewall = self.firewall()
        self.elements["ban4"] = {"198.51.100.2": (50, 590)}
        firewall.tick(2000)
        firewall.tick(2000 + agent.FLOOD_READ_EVERY)
        self.assertEqual(len(self.sent), 1)
        again = self.firewall()
        again.tick(2000 + 2 * agent.FLOOD_READ_EVERY)
        again.tick(2000 + 3 * agent.FLOOD_READ_EVERY)
        self.assertEqual(len(self.sent), 1)

    def test_the_origin_lock_reports_per_source_after_a_baseline(self):
        firewall = self.firewall()
        self.elements["seen4"] = {"198.51.100.200": (4, 3500)}
        firewall.tick(3000)
        self.assertEqual(self.sent, [], "what came before a start was reported then")
        self.elements["seen4"] = {"198.51.100.200": (10, 3599), "192.0.2.1": (2, 3599)}
        self.elements["seen6"] = {"2001:db8:9:9::": (1, 3599)}
        firewall.tick(3000 + agent.FLOOD_READ_EVERY)
        self.assertEqual(sorted((e["ip"], e["rule"], e["action"], e["hits"]) for e in self.sent),
                         [("192.0.2.1", "origin", "block", 2), ("198.51.100.200", "origin", "block", 6),
                          ("2001:db8:9:9::/64", "origin", "block", 1)])

    def test_checked_requests_are_reported_per_address(self):
        firewall = self.firewall()
        with open(self.config["nginx_check_log"], "a") as f:
            f.write("1793722639.673 198.51.100.9\n1793722639.678 198.51.100.9\n1793722639.700 ::ffff:192.0.2.4\nnonsense\n")
        firewall.tick(1001)
        self.assertEqual(sorted((e["ip"], e["rule"], e["action"], e["hits"]) for e in self.sent),
                         [("192.0.2.4", "challenge", "block", 1), ("198.51.100.9", "challenge", "block", 2)])

    def test_checks_are_summed_between_reports_busiest_first(self):
        firewall = self.firewall()
        with open(self.config["nginx_check_log"], "a") as f:
            f.write("1 198.51.100.9\n")
        firewall.tick(1001)
        self.sent.clear()
        with open(self.config["nginx_check_log"], "a") as f:
            f.write("2 198.51.100.9\n3 198.51.100.8\n3 198.51.100.8\n")
        firewall.tick(1006)
        self.assertEqual(self.sent, [], "every FLOOD_READ_EVERY, not every look")
        with open(self.config["nginx_check_log"], "a") as f:
            f.write("4 198.51.100.8\n")
        firewall.tick(1001 + agent.FLOOD_READ_EVERY)
        self.assertEqual([(e["ip"], e["hits"]) for e in self.sent], [("198.51.100.8", 3), ("198.51.100.9", 1)])

    def test_a_ban_listed_a_moment_past_its_end_is_not_a_second_ban(self):
        firewall = self.firewall()
        self.elements["ban4"] = {"198.51.100.2": (50, 20)}
        firewall.tick(2000)  # until 2020
        firewall.tick(2010)
        self.assertEqual(len(self.sent), 1)
        self.elements["ban4"] = {"198.51.100.2": (55, 0)}  # nft still lists it
        firewall.tick(2021)
        firewall.tick(2026)
        self.elements["ban4"] = {}
        firewall.tick(2036)
        self.assertEqual(len(self.sent), 1)
        self.assertEqual(firewall.bans, {})

    def test_a_corrupt_ban_file_entry_is_dropped(self):
        with open(os.path.join(self.dir, "flood.json"), "w") as f:
            json.dump({"bans": {
                "198.51.100.2": {"rule": "rate", "first": 1, "hits": 1, "reported": False},
                "198.51.100.3": {"rule": "rate", "first": 1, "until": "soon", "hits": 1, "reported": False},
                "198.51.100.4": {"rule": "rate", "first": 1, "until": 5000, "hits": True, "reported": False},
                "198.51.100.5": "x",
                "198.51.100.6": {"rule": "nope", "first": 1, "until": 5000, "hits": 1, "reported": False},
                "198.51.100.7": {"rule": "rate", "first": 1000, "until": 5000, "hits": 2, "reported": False}}}, f)
        firewall = self.firewall()
        self.assertEqual(list(firewall.bans), ["198.51.100.7"])
        firewall.tick(1001)
        firewall.tick(1001 + agent.BAN_REPORT_AFTER)
        self.assertEqual([e["ip"] for e in self.sent], ["198.51.100.7"])

    def test_watched_bans_are_capped_the_soonest_to_end_going_first(self):
        with mock.patch.object(agent, "BANS_MAX", 2):
            firewall = self.firewall()
            firewall.bans = {key: {"rule": "rate", "first": 900, "until": until, "hits": 1, "reported": True}
                             for key, until in (("198.51.100.1", 1100), ("198.51.100.2", 1300))}
            self.limited("198.51.100.3")
            firewall.tick(1001)
        self.assertEqual(sorted(firewall.bans), ["198.51.100.2", "198.51.100.3"])
        self.assertEqual(self.banned, [{"198.51.100.3": 600}])

    def test_a_failed_reload_is_tried_again_and_no_layer_until_it_works(self):
        replies, owed = [None, True], []

        def write(config, texts, owed_=False):
            owed.append(owed_)
            return replies.pop(0)

        with mock.patch.object(agent, "nginx_write", write):
            firewall = self.firewall()
            self.assertFalse(firewall.running["nginx"] or firewall.running["nginx-check"])
            self.assertTrue(firewall.nginx_owed)
            firewall.nginx_step(firewall.p, 1100)
        self.assertEqual(owed, [False, True])
        self.assertTrue(firewall.running["nginx"])
        self.assertFalse(firewall.nginx_owed)

    def test_a_failed_new_pass_is_tried_once_a_minute_not_every_look(self):
        now = CHALLENGE_CASES["tokens"][0]["now"]
        firewall = self.firewall()
        firewall.nginx_step(firewall.p, now)
        tries = []
        with mock.patch.object(agent, "nginx_write", lambda config, texts, owed=False: tries.append(1) or False):
            for t in range(0, 120, agent.FLOOD_TICK):
                firewall.tick(now + 86400 + t)
        self.assertEqual(len(tries), 2)

    def test_a_new_day_writes_a_new_pass(self):
        now = CHALLENGE_CASES["tokens"][0]["now"]
        firewall = self.firewall()
        firewall.nginx_step(firewall.p, now)
        self.written.clear()
        firewall.tick(now + 3600)
        self.assertEqual(self.written, [], "same day")
        firewall.tick(now + 86400)
        self.assertEqual(len(self.written), 1)
        text = self.written[0][self.config["nginx_flood_file"]]
        tomorrow = agent.utc_day(now) + 1
        self.assertIn(agent.challenge_token(self.config["secret"], tomorrow), text)
        self.assertIn(agent.challenge_token(self.config["secret"], tomorrow - 1), text, "yesterday's still counts")
        self.assertIn("var v='%s'" % agent.challenge_token(self.config["secret"], tomorrow),
                      self.written[0][self.config["nginx_check_file"]])

    def test_layers_are_only_what_runs(self):
        firewall = self.firewall()
        self.assertTrue(firewall.running["nginx"] and firewall.running["nginx-check"])
        self.included = {self.config["nginx_flood_file"]}
        firewall.nginx_step(firewall.p, 5000)
        self.assertEqual((firewall.running["nginx"], firewall.running["nginx-check"]), (True, False),
                         "the check needs the server file included")
        self.included = set()
        firewall.nginx_step(firewall.p, 10000)
        self.assertFalse(firewall.running["nginx"] or firewall.running["nginx-check"])
        with mock.patch.object(agent, "nginx_installed", lambda config: False):
            firewall.nginx_step(firewall.p, 20000)
        self.assertNotIn("nginx", firewall.layers())

    def test_a_refused_nginx_file_is_no_layer(self):
        with mock.patch.object(agent, "nginx_write", lambda config, texts, owed=False: False):
            firewall = self.firewall()
        self.assertFalse(firewall.running["nginx"] or firewall.running["nginx-check"])

    def test_nothing_is_written_when_nothing_is_wanted_and_nothing_is_there(self):
        self.firewall(flood=None, challenge=None)
        self.assertEqual(self.written, [])


class Backends(unittest.TestCase):
    """Switching the backend, the flood table between rounds, the lists in nginx."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)
        self.tables = {"analytics_firewall", "analytics_flood"}
        self.deleted, self.writes, self.included, self.reply = [], [], set(), True
        self.nginx_file = os.path.join(self.dir, "analytics-firewall.conf")

        def nft(*args, stdin=None):
            if args[:2] == ("delete", "table"):
                self.deleted.append(args[3])
                self.tables.discard(args[3])
            return done()

        patches = [
            mock.patch.object(agent, "fetch_rules", lambda config, etag, **_: (None, etag)),
            mock.patch.object(agent, "nft_installed", lambda: True),
            mock.patch.object(agent, "nft_table_present", lambda table=agent.TABLE: table in self.tables),
            mock.patch.object(agent, "nft", nft),
            mock.patch.object(agent, "nft_counters", lambda: {}),
            mock.patch.object(agent, "nft_apply", lambda config, p: True),
            mock.patch.object(agent, "nginx_installed", lambda config: True),
            mock.patch.object(agent, "nginx_dump", lambda config: (set(self.included), [])),
            mock.patch.object(agent, "nginx_write", self.write),
            mock.patch.object(agent, "log"),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def write(self, config, texts, owed=False):
        self.writes.append((sorted(texts), owed))
        for path, text in texts.items():
            with open(path, "w") as f:
                f.write(text)
        return self.reply

    def firewall(self, backend, **extra):
        firewall = agent.Agent(config(self.dir, backend=backend, nginx_file=self.nginx_file))
        firewall.rules = rules(**extra)
        firewall.running.update(flood=True, origin=True)  # as an nftables run left them
        firewall.flood_applied = "x"
        return firewall

    def test_another_backend_removes_the_kernel_tables(self):
        for backend in ("nginx", "none"):
            self.tables, self.deleted = {"analytics_firewall", "analytics_flood"}, []
            firewall = self.firewall(backend)
            firewall.step()
            self.assertEqual(sorted(self.deleted), ["analytics_firewall", "analytics_flood"], backend)
            self.assertFalse(firewall.running["flood"] or firewall.running["origin"] or firewall.running["kernel"])
            self.assertEqual(firewall.flood_applied, "")
            firewall.step()
            self.assertEqual(len(self.deleted), 2, "once gone, nothing more to do")

    def test_clear_removes_the_kernel_tables_whatever_the_backend(self):
        for backend in ("nginx", "none", "nftables"):
            self.tables, self.deleted = {"analytics_firewall", "analytics_flood"}, []
            agent.clear(config(self.dir, backend=backend, nginx_file=self.nginx_file))
            self.assertEqual(sorted(self.deleted), ["analytics_firewall", "analytics_flood"], backend)

    def test_a_flood_table_no_round_saved_is_removed(self):
        firewall = self.firewall("nftables", flood=None, origin=None)
        firewall.flood_applied = ""  # the run that made it died before saving
        self.tables = {"analytics_flood"}
        firewall.flood_step(agent.plan(firewall.rules))
        self.assertEqual(self.deleted, ["analytics_flood"])
        self.assertFalse(firewall.running["flood"] or firewall.running["origin"])

    def test_bans_go_back_when_the_table_is_made_again(self):
        firewall = self.firewall("nftables")
        firewall.bans = {key: {"rule": rule, "first": 900, "until": until, "hits": 3, "reported": True}
                         for key, rule, until in (("198.51.100.9", "rate", 1500), ("2001:db8:0:1::/64", "flood", 1200),
                                                  ("198.51.100.10", "rate", 999))}
        self.tables = set()  # a reboot
        banned = []
        with mock.patch.object(agent, "nft_ban", lambda timeouts: banned.append(dict(timeouts)) or True):
            firewall.flood_step(agent.plan(firewall.rules), now=1000)
            self.assertEqual(banned, [{"198.51.100.9": 500, "2001:db8:0:1::/64": 200}])
            self.tables.add("analytics_flood")
            firewall.flood_applied = "an older rules digest"
            firewall.flood_step(agent.plan(firewall.rules), now=1010)
        self.assertEqual(len(banned), 1, "a change in place keeps the bans: nothing to put back")

    def test_the_nginx_lists_layer_needs_block_mode_and_the_include(self):
        firewall = self.firewall("nginx")
        firewall.step()
        self.assertFalse(firewall.running["nginx-lists"], "not included")
        self.included = {self.nginx_file}
        firewall.nginx_dump_at = 0
        firewall.step()
        self.assertTrue(firewall.running["nginx-lists"])
        firewall.rules = rules(mode="monitor")
        firewall.step()
        self.assertFalse(firewall.running["nginx-lists"], "monitor mode writes no lines")

    def test_a_failed_reload_of_the_lists_is_tried_again(self):
        firewall = self.firewall("nginx", flood=None, origin=None, challenge=None)
        self.reply = None
        firewall.step()
        self.assertTrue(firewall.nginx_owed)
        self.assertEqual(firewall.applied, "", "not applied while the reload is owed")
        self.reply = True
        firewall.step()
        self.assertEqual([owed for paths, owed in self.writes if paths == [self.nginx_file]], [False, True])
        self.assertFalse(firewall.nginx_owed)
        self.assertTrue(firewall.applied)
        with open(os.path.join(self.dir, "state.json")) as f:
            self.assertIs(json.load(f)["nginx_owed"], False)

    def test_the_nftables_backend_empties_lines_an_nginx_run_left(self):
        with open(self.nginx_file, "w") as f:
            f.write("deny 198.51.100.7;\n")
        firewall = self.firewall("nftables")
        firewall.step()
        with open(self.nginx_file) as f:
            text = f.read()
        self.assertNotIn("deny", text)
        self.assertTrue(text.startswith("# Written by analytics-agent"))


class Headers(unittest.TestCase):
    def fetch(self, layers, hostname="web-1"):
        seen = {}

        def fake(config, method, path, body=None, headers=None):
            seen.update(headers or {})
            return 304, {}, b""

        with mock.patch.object(agent, "request", fake), mock.patch.object(agent.socket, "gethostname", lambda: hostname):
            agent.fetch_rules(config(), "etag-1", layers=layers)
        return seen

    def test_layers_and_server_name_on_every_fetch(self):
        seen = self.fetch(["kernel", "flood", "nginx"])
        self.assertEqual(seen["X-Firewall-Layers"], "kernel flood nginx")
        self.assertEqual(seen["X-Server-Name"], "web-1")
        self.assertEqual(seen["If-None-Match"], "etag-1")
        self.assertEqual(self.fetch([])["X-Firewall-Layers"], "")

    def test_a_long_host_name_is_cut_to_100(self):
        self.assertEqual(len(self.fetch([], "h" * 300)["X-Server-Name"]), 100)

    def test_no_rate_goes_once_nginx_counts_requests(self):
        self.assertNotIn("User-Agent", self.fetch(["kernel"]), "request() adds the (no-rate) one")
        self.assertNotIn("no-rate", self.fetch(["kernel", "nginx"])["User-Agent"])

    def test_an_upgraded_agent_with_its_table_in_place_says_kernel(self):
        conf = config(backend="nftables")
        r = rules(flood=None, origin=None, challenge=None)
        digest = agent.hashlib.sha256(json.dumps(["nftables", [80, 443], agent.main_plan(agent.plan(r))],
                                                 sort_keys=True).encode()).hexdigest()
        with open(os.path.join(conf["state_dir"], "state.json"), "w") as f:
            json.dump({"etag": "e", "rules": r, "applied": digest}, f)  # as 0.6.0 left it: no "running"
        firewall = agent.Agent(conf)
        applied = []
        with mock.patch.object(agent, "fetch_rules", lambda config, etag, **_: (None, etag)), \
                mock.patch.object(agent, "nft_table_present", lambda table=agent.TABLE: True), \
                mock.patch.object(agent, "nft_counters", lambda: {}), \
                mock.patch.object(agent, "nft_apply", lambda config, p: applied.append(p) or True), \
                mock.patch.object(agent, "nft", lambda *a, stdin=None: done()), \
                mock.patch.object(agent, "nginx_installed", lambda config: False):
            firewall.step()
        self.assertEqual(applied, [], "the same rules aren't applied again")
        self.assertEqual(firewall.layers(), ["kernel"])

    def test_the_agent_sends_what_runs(self):
        firewall = agent.Agent(config())
        firewall.running.update(kernel=True, origin=True, flood=False)
        self.assertEqual(firewall.layers(), ["kernel", "origin"])


class SynCookies(unittest.TestCase):
    def check(self, value):
        def read(path, limit=65536):
            return value if path == "/proc/sys/net/ipv4/tcp_syncookies" else ""

        with mock.patch.object(agent, "read_text", read), mock.patch.object(agent, "pending_updates", lambda: None), \
                mock.patch.object(agent, "authorized_keys_files", lambda: []), mock.patch.object(agent, "cron_files", lambda: []):
            body = agent.posture_report(config())
        return [c for c in body["checks"] if c["id"] == "server.tcp_syncookies"]

    def test_off_is_a_finding(self):
        self.assertEqual(self.check("0\n"), [{"id": "server.tcp_syncookies", "state": "fail", "value": "off"}])

    def test_on_or_always_passes(self):
        self.assertEqual(self.check("1\n"), [{"id": "server.tcp_syncookies", "state": "pass"}])
        self.assertEqual(self.check("2\n"), [{"id": "server.tcp_syncookies", "state": "pass"}])

    def test_unreadable_is_left_out(self):
        self.assertEqual(self.check(""), [])


if __name__ == "__main__":
    unittest.main()
