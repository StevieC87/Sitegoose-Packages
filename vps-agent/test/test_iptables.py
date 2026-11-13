"""The iptables + ipset backend ("backend": "iptables"): the rules and set
scripts that reach iptables-restore and ipset, what is read back, bans and
their expiry, monitor mode, the origin lock, clearing and switching backends,
and which iptables (legacy or nft) is used. A fake kernel stands in for
iptables and ipset; the same paths were run against the real ones (README).

    python3 -m unittest discover -s test
"""
import importlib.machinery
import importlib.util
import os
import shutil
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
AGENT = os.path.join(HERE, "..", "analytics-agent")
if "analytics_agent" in sys.modules:
    agent = sys.modules["analytics_agent"]
else:
    spec = importlib.util.spec_from_loader("analytics_agent", importlib.machinery.SourceFileLoader("analytics_agent", AGENT))
    agent = importlib.util.module_from_spec(spec)
    sys.modules["analytics_agent"] = agent
    spec.loader.exec_module(agent)
agent.DEFAULTS.update(web_checks=[], access_logs=[])
METER_SIZE = agent.ipt_meter_size
METER_FAMILIES = agent.ipt_families  # the real one, for the test that needs it

TOOLS = {"mode": "legacy", "version": (1, 8, 9), "4": ["iptables-legacy", "-w"], "6": ["ip6tables-legacy", "-w"],
         "restore4": ["iptables-legacy-restore", "--noflush", "-w"], "restore6": ["ip6tables-legacy-restore", "--noflush", "-w"]}
FLOOD = {"conn_rate": 30, "conn_max": 100, "req_rate": 20, "req_burst": 60, "ban": 600, "exempt": ["173.245.48.0/20"]}


def rules(**extra):
    base = {"v": 1, "enabled": True, "mode": "block", "sync": 60, "allow": ["203.0.113.7", "2001:db8:aaaa::/48"],
            "deny": ["198.51.100.0/24", "2001:db8:bad::/48"], "banned": ["192.0.2.66"], "lists": [], "shared": [],
            "goodbots": ["66.249.64.0/27"], "flood": dict(FLOOD), "origin": {"only": ["173.245.48.0/20", "2400:cb00::/32"]}}
    base.update(extra)
    return base


def done(code=0, stdout="", stderr=""):
    return SimpleNamespace(returncode=code, stdout=stdout, stderr=stderr)


class Kernel:
    """iptables' mangle table (per family) and ipset, as far as the agent uses them."""

    def __init__(self):
        self.chains = {"4": {}, "6": {}}  # family: {chain: [rules]}
        self.prerouting = {"4": [], "6": []}
        self.sets = {}  # name: {"type": text, "elements": {element: (packets, timeout)}}
        self.restores, self.scripts = [], []
        self.refuse = None  # a function(text) -> error text, to refuse a restore or script

    def state(self, family):
        return set(self.chains[family]), list(self.prerouting[family])

    def restore(self, family, text):
        self.restores.append((family, text))
        error = self.refuse and self.refuse(text)
        if error:
            return done(1, stderr=error)
        chains, pre = {k: list(v) for k, v in self.chains[family].items()}, list(self.prerouting[family])
        for line in text.splitlines():
            if line.startswith(":"):
                chains[line[1:].split()[0]] = []
            elif line.startswith("-X "):
                chains.pop(line[3:].strip())
            elif line.startswith("-D PREROUTING "):
                pre.remove(line[len("-D PREROUTING "):])
            elif line.startswith("-I PREROUTING "):
                _, _, at, rule = line.split(" ", 3)
                pre.insert(int(at) - 1, rule)
            elif line.startswith("-A "):
                _, chain, rule = line.split(" ", 2)
                chains[chain].append(rule)
        self.chains[family], self.prerouting[family] = chains, pre
        return done()

    def ipset(self, *args, stdin=None):
        args = list(args)
        if args == ["list", "-n"]:
            return done(stdout="".join(name + "\n" for name in self.sets))
        if args[:1] == ["save"]:
            names = args[1:] or list(self.sets)
            out = []
            for name in names:
                for element, (packets, timeout) in self.sets.get(name, {"elements": {}})["elements"].items():
                    out.append("add %s %s timeout %d packets %d bytes %d" % (name, element, timeout, packets, packets * 60))
            return done(stdout="\n".join(out) + "\n")
        if args[:1] == ["destroy"]:
            self.sets.pop(args[1], None)
            return done()
        if args == ["-exist", "restore"]:
            self.scripts.append(stdin)
            error = self.refuse and self.refuse(stdin)
            if error:
                return done(1, stderr=error)
            for line in stdin.splitlines():
                words = line.split()
                if not words:
                    continue
                if words[0] == "create":
                    kind = " ".join(words[2:])
                    if words[1] in self.sets and self.sets[words[1]]["type"] != kind:
                        return done(1, stderr="ipset v7.1: Set cannot be created: set with the same name already exists")
                    self.sets.setdefault(words[1], {"type": kind, "elements": {}})
                elif words[0] == "add":
                    timeout = int(words[4]) if len(words) > 4 and words[3] == "timeout" else 0
                    self.sets[words[1]]["elements"][words[2]] = (0, timeout)
                elif words[0] == "del":
                    self.sets.get(words[1], {"elements": {}})["elements"].pop(words[2], None)
                elif words[0] == "destroy":
                    self.sets.pop(words[1])
                elif words[0] == "swap":
                    self.sets[words[1]], self.sets[words[2]] = self.sets[words[2]], self.sets[words[1]]
            return done()
        raise AssertionError("unexpected ipset %s" % args)

    def patches(self, families=("4", "6")):
        return [
            mock.patch.object(agent, "ipt_tools", lambda refresh=False: TOOLS),
            mock.patch.object(agent, "ipt_families", lambda: families),
            mock.patch.object(agent, "ipt_state", self.state),
            mock.patch.object(agent, "ipt_restore", self.restore),
            mock.patch.object(agent, "ipset", self.ipset),
            mock.patch.dict(agent.IPT_CAPS, {"counters": True, "set_timeout": True}),
        ]


class KernelCase(unittest.TestCase):
    def setUp(self):
        self.kernel = Kernel()
        for p in self.kernel.patches() + [mock.patch.object(agent, "log")]:
            p.start()
            self.addCleanup(p.stop)
        self.config = {"ports": [80, 443], "backend": "iptables"}


class Rules(unittest.TestCase):
    def setUp(self):
        p = mock.patch.object(agent, "ipt_meter_size", lambda path=None: 262144)
        p.start()
        self.addCleanup(p.stop)

    def meter(self, family, rate):
        return "sg%s-%s" % (family, agent.hashlib.sha256(("%d 262144" % rate).encode()).hexdigest()[:8])

    def test_the_lists_allow_first_then_each_list_dropped(self):
        p = agent.plan(rules())
        self.assertEqual(agent.ipt_main_rules(p, "4"), [
            "-m set --match-set analytics-list-allow4 src -j RETURN",
            "-m set --match-set analytics-list-deny4 src -j DROP",
            "-m set --match-set analytics-list-ban4 src -j DROP",
            "-m set --match-set analytics-list-list4 src -j DROP",
            "-m set --match-set analytics-list-shared4 src -j DROP"])

    def test_monitor_mode_never_drops_and_off_matches_nothing(self):
        monitor = agent.ipt_main_rules(agent.plan(rules(mode="monitor")), "6")
        self.assertTrue(all(rule.endswith("-j RETURN") for rule in monitor))
        self.assertEqual(len(monitor), 5, "still matched, so still counted")
        self.assertEqual(agent.ipt_main_rules(agent.plan(rules(enabled=False)), "4"),
                         ["-m set --match-set analytics-list-allow4 src -j RETURN"])
        flood = agent.ipt_flood_rules(agent.plan(rules(mode="monitor")), "4")
        self.assertFalse([rule for rule in flood if "DROP" in rule])
        # A full hashlimit meter drops a new address's packet whatever the rule
        # says: no meter in monitor mode (connlimit still counts).
        self.assertFalse([rule for rule in flood if "hashlimit" in rule])
        self.assertTrue([rule for rule in flood if "connlimit" in rule])
        self.assertFalse(agent.ipt_counts_rate(agent.plan(rules(mode="monitor"))))
        self.assertTrue(agent.ipt_counts_rate(agent.plan(rules())))

    def test_the_meter_is_sized_past_the_connection_table_and_named_by_rate_and_size(self):
        folder = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, folder)
        path = os.path.join(folder, "nf_conntrack_max")
        for value, size in (("262144", 524288), ("1024", agent.IPT_METER_MIN), ("99999999", agent.IPT_METER_MAX),
                            ("junk", agent.IPT_METER_DEFAULT)):
            with open(path, "w") as f:
                f.write(value + "\n")
            self.assertEqual(METER_SIZE(path), size, value)
        self.assertEqual(METER_SIZE(os.path.join(folder, "missing")), agent.IPT_METER_DEFAULT)
        self.assertNotEqual(self.meter("4", 30), self.meter("4", 50), "a new rate is a new meter")

    def test_no_accept_anywhere_so_the_owners_mangle_rules_still_run(self):
        p = agent.plan(rules())
        for family in "46":
            for rule in agent.ipt_main_rules(p, family) + agent.ipt_flood_rules(p, family):
                self.assertNotIn("ACCEPT", rule)

    def test_the_limits(self):
        r = agent.ipt_flood_rules(agent.plan(rules()), "4")
        self.assertEqual(r[:2], ["-i lo -j RETURN", "-m set --match-set analytics-flood-local4 src -j RETURN"])
        self.assertIn("-m conntrack --ctstate NEW -m hashlimit --hashlimit-above 30/sec --hashlimit-burst 60 "
                      "--hashlimit-mode srcip --hashlimit-srcmask 32 --hashlimit-name %s --hashlimit-htable-size 32768 "
                      "--hashlimit-htable-max 262144 --hashlimit-htable-expire 60000 "
                      "-j SET --add-set analytics-flood-ban4 src --exist --timeout 600" % self.meter("4", 30), r)
        self.assertIn("-m conntrack --ctstate NEW -m connlimit --connlimit-above 100 --connlimit-mask 32 "
                      "-j SET --add-set analytics-flood-ban4 src --exist --timeout 600", r)
        self.assertEqual(r[-1], "-m set --match-set analytics-flood-ban4 src -j DROP", "over a limit: dropped now")

    def test_ipv6_is_limited_by_its_64(self):
        r = " ".join(agent.ipt_flood_rules(agent.plan(rules()), "6"))
        self.assertIn("--hashlimit-srcmask 64 --hashlimit-name %s" % self.meter("6", 30), r)
        self.assertIn("--connlimit-mask 64", r)
        self.assertNotIn("4 src", r)

    def test_exempt_and_bans_come_before_the_limits_and_the_lock_before_those(self):
        r = agent.ipt_flood_rules(agent.plan(rules()), "4")
        order = [i for i, rule in enumerate(r) for needle in ("origin4 src -j SET", "origin4 src -j DROP", "exempt4", "ban4 src -j DROP",
                                                               "hashlimit", "connlimit") if needle in rule]
        self.assertEqual(order, sorted(order))
        self.assertIn("-m set ! --match-set analytics-flood-origin4 src -m set --match-set analytics-flood-seen4 src", r,
                      "the lock counts per source, apart from dropping")

    def test_a_family_with_no_origin_range_is_not_locked_in_either_backend(self):
        p = agent.plan(rules(origin={"only": ["173.245.48.0/20"]}, allow=["2001:db8:aaaa::/48"]))
        self.assertEqual(p["origin"]["locked"], (True, False), "allow isn't an origin range")
        self.assertTrue([rule for rule in agent.ipt_flood_rules(p, "4") if "origin4" in rule])
        self.assertFalse([rule for rule in agent.ipt_flood_rules(p, "6") if "origin" in rule])
        nft = agent.flood_rules({"ports": [80, 443]}, p)
        self.assertTrue([rule for rule in nft if "@origin4" in rule])
        self.assertFalse([rule for rule in nft if "@origin6" in rule])

    def test_a_lock_with_no_valid_range_is_no_lock(self):
        p = agent.plan(rules(origin={"only": ["not an address", "0.0.0.0/33"]}))
        self.assertIsNone(p["origin"])
        self.assertFalse([rule for rule in agent.ipt_flood_rules(p, "4") if "origin" in rule])

    def test_a_limit_the_rules_leave_out_has_no_rule(self):
        r = " ".join(agent.ipt_flood_rules(agent.plan(rules(flood=dict(FLOOD, conn_max=None))), "4"))
        self.assertIn("hashlimit", r)
        self.assertNotIn("connlimit", r)
        r = agent.ipt_flood_rules(agent.plan(rules(flood=None)), "4")
        self.assertFalse([rule for rule in r if "ban4" in rule or "exempt" in rule])

    def test_a_rate_past_what_hashlimit_takes_is_capped(self):
        r = " ".join(agent.ipt_flood_rules(agent.plan(rules(flood=dict(FLOOD, conn_rate=900000))), "4"))
        self.assertIn("--hashlimit-above 10000/sec --hashlimit-burst 10000", r)

    def test_without_a_timeout_in_the_kernels_set_target_the_ban_has_none(self):
        with mock.patch.dict(agent.IPT_CAPS, {"set_timeout": False}):
            r = " ".join(agent.ipt_flood_rules(agent.plan(rules()), "4"))
        self.assertIn("-j SET --add-set analytics-flood-ban4 src -m", r + " -m")
        self.assertNotIn("--timeout", r)
        self.assertNotIn("--exist", r)

    def test_web_ports_only_tcp_and_udp_fifteen_to_a_match(self):
        self.assertEqual(agent.ipt_jumps({"ports": [80, 443]}, "ANALYTICS-FW"), [
            "-p tcp -m multiport --dports 80,443 -m addrtype --dst-type LOCAL -m comment --comment analytics-agent -j ANALYTICS-FW",
            "-p udp -m multiport --dports 80,443 -m addrtype --dst-type LOCAL -m comment --comment analytics-agent -j ANALYTICS-FW"])
        jumps = agent.ipt_jumps({"ports": list(range(8000, 8020))}, "ANALYTICS-FLOOD")
        self.assertEqual(len(jumps), 4)
        self.assertTrue(all(len(j.split("--dports ")[1].split()[0].split(",")) <= 15 for j in jumps))
        self.assertNotIn("22", " ".join(agent.ipt_jumps({"ports": [80, 443]}, "ANALYTICS-FW")))


class Local(unittest.TestCase):
    def test_only_what_is_addressed_to_this_server_in_both_backends(self):
        """A packet routed through the server (a VM's, a VPN client's, a container's
        on its own public IPv6) is neither limited, locked out nor listed."""
        self.assertTrue(all("-m addrtype --dst-type LOCAL" in j for j in agent.ipt_jumps({"ports": [80, 443, 8443]}, "ANALYTICS-FLOOD")))
        p = agent.plan(rules())
        flood = agent.flood_rules({"ports": [80, 443]}, p)
        self.assertLess(flood.index("fib daddr type != local accept"), flood.index("ip saddr @local4 accept"))
        table = agent.nft_ruleset({"ports": [80, 443]}, p)
        self.assertLess(table.index("fib daddr type != local accept"), table.index("ip saddr @allow4 accept"))


class Chains(unittest.TestCase):
    OWNER = ["-p tcp -m tcp --dport 22 -j MARK --set-xmark 0x2/0xffffffff", "-s 10.9.9.9/32 -j MARK --set-xmark 0x1/0xffffffff"]

    def test_jumps_go_in_once_at_the_top_and_the_owners_rules_stay(self):
        config = {"ports": [80, 443]}
        text = agent.ipt_chain_text(config, "ANALYTICS-FW", ["-j RETURN"], (set(), list(self.OWNER)))
        self.assertEqual(text.splitlines(), [
            "*mangle", ":ANALYTICS-FW - [0:0]", "-A ANALYTICS-FW -j RETURN",
            "-I PREROUTING 1 -p tcp -m multiport --dports 80,443 -m addrtype --dst-type LOCAL -m comment --comment analytics-agent -j ANALYTICS-FW",
            "-I PREROUTING 2 -p udp -m multiport --dports 80,443 -m addrtype --dst-type LOCAL -m comment --comment analytics-agent -j ANALYTICS-FW",
            "COMMIT"])
        present = agent.ipt_jumps(config, "ANALYTICS-FW") + self.OWNER
        again = agent.ipt_chain_text(config, "ANALYTICS-FW", ["-j RETURN"], ({"ANALYTICS-FW"}, present))
        self.assertNotIn("PREROUTING", again, "already in place: nothing in PREROUTING moves")
        self.assertNotIn("\n-F", again, "never a flush of anything but our own chain")

    def test_the_flood_chain_comes_first_and_the_lists_after_it(self):
        config = {"ports": [80]}
        flood = agent.ipt_jumps(config, "ANALYTICS-FLOOD")
        text = agent.ipt_chain_text(config, "ANALYTICS-FW", [], ({"ANALYTICS-FLOOD"}, flood + self.OWNER))
        self.assertIn("-I PREROUTING 3 -p tcp", text)
        text = agent.ipt_chain_text(config, "ANALYTICS-FLOOD", [], ({"ANALYTICS-FW"}, agent.ipt_jumps(config, "ANALYTICS-FW")))
        self.assertIn("-I PREROUTING 1 -p tcp", text)

    def test_changed_ports_move_only_our_jumps(self):
        old = agent.ipt_jumps({"ports": [80]}, "ANALYTICS-FW")
        text = agent.ipt_chain_text({"ports": [80, 443]}, "ANALYTICS-FW", [], ({"ANALYTICS-FW"}, self.OWNER[:1] + old))
        deleted = [line for line in text.splitlines() if line.startswith("-D")]
        self.assertEqual(deleted, ["-D PREROUTING " + rule for rule in old])

    def test_removal_takes_out_only_ours(self):
        state = ({"ANALYTICS-FW", "OWNER"}, self.OWNER + agent.ipt_jumps({"ports": [80]}, "ANALYTICS-FW"))
        text = agent.ipt_drop_text(("ANALYTICS-FLOOD", "ANALYTICS-FW"), state)
        self.assertEqual(text.splitlines(), [
            "*mangle", "-D PREROUTING -p tcp -m multiport --dports 80 -m addrtype --dst-type LOCAL -m comment --comment analytics-agent -j ANALYTICS-FW",
            "-D PREROUTING -p udp -m multiport --dports 80 -m addrtype --dst-type LOCAL -m comment --comment analytics-agent -j ANALYTICS-FW",
            ":ANALYTICS-FW - [0:0]", "-X ANALYTICS-FW", "COMMIT"])
        self.assertIsNone(agent.ipt_drop_text(("ANALYTICS-FW",), ({"OWNER"}, self.OWNER)))


class Sets(unittest.TestCase):
    def test_a_list_is_filled_under_another_name_and_swapped_in(self):
        lines = agent.ipt_swap_lines("analytics-list-deny4", "4", ["198.51.100.0/24"], True, set())
        kind = "hash:net family inet hashsize 1024 maxelem 65536 counters"
        self.assertEqual(lines, ["create analytics-list-deny4-new %s" % kind, "add analytics-list-deny4-new 198.51.100.0/24",
                                 "create analytics-list-deny4 %s" % kind, "swap analytics-list-deny4-new analytics-list-deny4",
                                 "destroy analytics-list-deny4-new"])
        again = agent.ipt_swap_lines("analytics-list-deny4", "4", [], True, {"analytics-list-deny4", "analytics-list-deny4-new"})
        self.assertEqual(again[0], "destroy analytics-list-deny4-new", "a half-made one an earlier run left")
        self.assertNotIn("create analytics-list-deny4 %s" % kind, again)

    def test_everyone_is_held_as_two_halves(self):
        """hash:net can't hold a /0. Dropping it would empty an `allow` of everyone
        (in origin.only too: the lock would shut out all of IPv6) or a `deny` of everyone."""
        v4 = agent.ipt_swap_lines("analytics-list-deny4", "4", ["0.0.0.0/0"], True, set())
        self.assertEqual([l for l in v4 if l.startswith("add")],
                         ["add analytics-list-deny4-new 0.0.0.0/1", "add analytics-list-deny4-new 128.0.0.0/1"])
        p = agent.plan(rules(allow=["::/0"], origin={"only": ["173.245.48.0/20", "2400:cb00::/32"]}))
        self.assertEqual(p["origin"]["only"][1], ["::/0"])
        with mock.patch.object(agent, "ipt_families", lambda: ("4", "6")), mock.patch.dict(agent.IPT_CAPS, {"counters": True}):
            lines = agent.ipt_flood_lines(p, set())
        self.assertEqual([l for l in lines if l.startswith("add analytics-flood-origin6-new")],
                         ["add analytics-flood-origin6-new ::/1", "add analytics-flood-origin6-new 8000::/1"])

    def test_a_big_list_gets_room(self):
        many = ["10.%d.%d.0/24" % (a, b) for a in range(200) for b in range(200)]
        self.assertIn("maxelem 80000", agent.ipt_swap_lines("analytics-list-list4", "4", many, True, set())[0])

    def test_the_ban_sets_time_each_entry_and_ipv6_counts_by_its_64(self):
        with mock.patch.object(agent, "ipt_families", lambda: ("4", "6")):
            lines = agent.ipt_flood_lines(agent.plan(rules()), set())
        self.assertIn("create analytics-flood-ban4 hash:ip family inet hashsize 1024 maxelem 65536 timeout 0 counters", lines)
        self.assertIn("create analytics-flood-ban6 hash:ip family inet6 netmask 64 hashsize 1024 maxelem 65536 timeout 0 counters", lines)
        self.assertIn("create analytics-flood-seen6 hash:ip family inet6 netmask 64 hashsize 1024 maxelem 65536 timeout 3600 counters", lines)
        self.assertFalse([line for line in lines if line.startswith(("destroy analytics-flood-ban", "destroy analytics-flood-seen"))])
        self.assertIn("add analytics-flood-local4-new 192.168.0.0/16", lines)
        self.assertIn("add analytics-flood-origin6-new 2400:cb00::/32", lines)
        self.assertIn("add analytics-flood-exempt4-new 203.0.113.7/32", lines, "allow is exempt")

    def test_read_back(self):
        out = done(stdout="create analytics-flood-ban4 hash:ip family inet timeout 0 counters\n"
                          "add analytics-flood-ban4 198.51.100.9 timeout 590 packets 41 bytes 2460\n"
                          "add analytics-flood-ban6 2001:db8:0:1:: timeout 0 packets 3 bytes 180\n"
                          "add analytics-list-deny4 198.51.100.0/24 packets 7 bytes 420\n"
                          "add analytics-list-deny4 192.0.2.1 packets 0 bytes 0\n"
                          "add analytics-list-allow4 203.0.113.7 packets 9 bytes 540\n")
        with mock.patch.object(agent, "ipset", lambda *a, stdin=None: out):
            self.assertEqual(agent.ipt_save()["analytics-flood-ban4"], {"198.51.100.9": (41, 590)})
            self.assertEqual(agent.ipt_elements("ban6"), {"2001:db8:0:1::": (3, 0)})
            self.assertEqual(agent.ipt_counters(), {("deny", "198.51.100.0/24"): 7}, "allow isn't a list; nothing counted, nothing sent")
        self.assertEqual(agent.flood_key("2001:db8:0:1::"), "2001:db8:0:1::/64")

    def test_bans_go_in_by_chunks_each_with_its_time_and_a_full_set_stops_them(self):
        scripts = []

        def fake(*args, stdin=None):
            scripts.append(stdin)
            return done(1 if len(scripts) == 2 else 0, stderr="Hash is full, cannot add more elements")
        timeouts = {"198.51.%d.%d" % (i // 250, i % 250): 600 for i in range(2500)}
        with mock.patch.object(agent, "ipset", fake), mock.patch.object(agent, "ipt_families", lambda: ("4", "6")), \
                mock.patch.object(agent, "log") as logged:
            self.assertFalse(agent.ipt_ban(timeouts))
        self.assertEqual(len(scripts), 2, "the chunk that failed was the last tried")
        self.assertEqual(len(scripts[0].splitlines()), agent.IPT_BAN_CHUNK)
        self.assertIn("add analytics-flood-ban4 198.51.0.0 timeout 600", scripts[0])
        self.assertIn("is the ban set full", logged.call_args[0][0])

    def test_ipv6_by_its_64_and_none_where_there_is_no_ipv6(self):
        scripts = []
        with mock.patch.object(agent, "ipset", lambda *a, stdin=None: scripts.append(stdin) or done()), \
                mock.patch.object(agent, "ipt_families", lambda: ("4", "6")):
            agent.ipt_ban({"2001:db8:0:1::/64": 300})
        self.assertEqual(scripts, ["add analytics-flood-ban6 2001:db8:0:1:: timeout 300\n"])
        scripts.clear()
        with mock.patch.object(agent, "ipset", lambda *a, stdin=None: scripts.append(stdin) or done()), \
                mock.patch.object(agent, "ipt_families", lambda: ("4",)):
            agent.ipt_ban({"2001:db8:0:1::/64": 300, "198.51.100.9": 600})
        self.assertEqual(scripts, ["add analytics-flood-ban4 198.51.100.9 timeout 600\n"])


class Apply(KernelCase):
    def test_lists_and_chains_in_place_allow_swapped_in_first(self):
        p = agent.plan(rules())
        self.assertTrue(agent.ipt_apply(self.config, p))
        script = self.kernel.scripts[-1]
        self.assertLess(script.index("swap analytics-list-allow4-new"), script.index("swap analytics-list-deny4-new"))
        self.assertEqual(set(self.kernel.sets["analytics-list-deny6"]["elements"]), {"2001:db8:bad::/48"})
        self.assertNotIn("analytics-list-deny4-new", self.kernel.sets)
        for family in "46":
            self.assertEqual(self.kernel.chains[family]["ANALYTICS-FW"], agent.ipt_main_rules(p, family))
            self.assertEqual(len(self.kernel.prerouting[family]), 2)
        self.assertTrue(agent.ipt_present("ANALYTICS-FW"))

    def test_a_list_change_is_a_swap_and_leaves_prerouting_alone(self):
        agent.ipt_apply(self.config, agent.plan(rules()))
        before = dict(self.kernel.prerouting)
        agent.ipt_apply(self.config, agent.plan(rules(deny=["198.51.100.0/25"])))
        self.assertEqual(set(self.kernel.sets["analytics-list-deny4"]["elements"]), {"198.51.100.0/25"})
        self.assertEqual(self.kernel.prerouting, before)
        self.assertNotIn("PREROUTING", self.kernel.restores[-1][1])

    def test_a_kernel_without_set_counters_is_asked_again_without(self):
        self.kernel.refuse = lambda text: "ipset v6.11: Unknown argument: `counters'" if "counters" in text else None
        self.assertTrue(agent.ipt_apply(self.config, agent.plan(rules())))
        self.assertFalse(agent.IPT_CAPS["counters"])
        self.assertNotIn("counters", self.kernel.sets["analytics-list-deny4"]["type"])

    def test_a_refusal_is_a_failure(self):
        self.kernel.refuse = lambda text: "iptables-restore: line 3 failed" if text.startswith("*mangle") else None
        self.assertFalse(agent.ipt_apply(self.config, agent.plan(rules())))

    def test_the_flood_chain_keeps_its_bans_through_a_rules_change(self):
        self.assertIs(agent.ipt_flood_apply(self.config, agent.plan(rules())), True)
        self.kernel.sets["analytics-flood-ban4"]["elements"]["198.51.100.9"] = (40, 500)
        self.assertIs(agent.ipt_flood_apply(self.config, agent.plan(rules(flood=dict(FLOOD, conn_rate=50, ban=300)))), True)
        self.assertEqual(self.kernel.sets["analytics-flood-ban4"]["elements"], {"198.51.100.9": (40, 500)})
        meter = lambda chain: [w for rule in chain if "hashlimit" in rule for w in [rule.split("--hashlimit-name ")[1].split()[0]]]
        self.assertEqual(meter(self.kernel.chains["4"]["ANALYTICS-FLOOD"]),
                         meter(agent.ipt_flood_rules(agent.plan(rules(flood=dict(FLOOD, conn_rate=50))), "4")))
        self.assertNotEqual(meter(self.kernel.chains["4"]["ANALYTICS-FLOOD"]), meter(agent.ipt_flood_rules(agent.plan(rules()), "4")),
                            "a new meter for a new rate: the kernel would keep an old one's")
        self.assertEqual(self.kernel.prerouting["4"][0].split(" -j ")[-1], "ANALYTICS-FLOOD")

    def test_sets_of_ours_made_otherwise_are_started_over(self):
        self.kernel.sets["analytics-flood-ban4"] = {"type": "hash:net family inet", "elements": {"198.51.100.9": (1, 9)}}
        self.assertEqual(agent.ipt_flood_apply(self.config, agent.plan(rules())), "fresh")
        self.assertIn("timeout 0", self.kernel.sets["analytics-flood-ban4"]["type"])
        self.assertEqual(self.kernel.sets["analytics-flood-ban4"]["elements"], {})

    def test_a_kernel_whose_set_target_takes_no_timeout_is_asked_again_without(self):
        self.kernel.refuse = lambda text: "iptables-restore: unknown option \"--exist\"" if "--exist" in text else None
        self.assertIs(agent.ipt_flood_apply(self.config, agent.plan(rules())), True)
        self.assertFalse(agent.IPT_CAPS["set_timeout"])
        self.assertIn("-j SET --add-set analytics-flood-ban4 src", " ".join(self.kernel.chains["4"]["ANALYTICS-FLOOD"]))

    def test_some_other_refusal_keeps_the_timeout(self):
        self.kernel.refuse = lambda text: "iptables-restore: line 9 failed" if text.startswith("*mangle") else None
        self.assertFalse(agent.ipt_flood_apply(self.config, agent.plan(rules())))
        self.assertTrue(agent.IPT_CAPS["set_timeout"])

    def test_no_flood_and_no_origin_removes_the_chain_and_its_sets_not_the_lists(self):
        agent.ipt_apply(self.config, agent.plan(rules()))
        agent.ipt_flood_apply(self.config, agent.plan(rules()))
        self.assertIs(agent.ipt_flood_apply(self.config, agent.plan(rules(flood=None, origin=None))), True)
        self.assertNotIn("ANALYTICS-FLOOD", self.kernel.chains["4"])
        self.assertFalse([n for n in self.kernel.sets if n.startswith("analytics-flood-")])
        self.assertIn("ANALYTICS-FW", self.kernel.chains["6"])
        self.assertTrue(all(rule.endswith("ANALYTICS-FW") for rule in self.kernel.prerouting["4"]))

    def test_remove_all_leaves_the_owners_rules_and_sets(self):
        self.kernel.prerouting["4"].append("-s 10.9.9.9/32 -j MARK --set-xmark 0x1/0xffffffff")
        self.kernel.sets["owners-own"] = {"type": "hash:ip", "elements": {}}
        agent.ipt_apply(self.config, agent.plan(rules()))
        agent.ipt_flood_apply(self.config, agent.plan(rules()))
        self.assertTrue(agent.ipt_remove_all())
        self.assertEqual(self.kernel.prerouting, {"4": ["-s 10.9.9.9/32 -j MARK --set-xmark 0x1/0xffffffff"], "6": []})
        self.assertEqual(self.kernel.chains, {"4": {}, "6": {}})
        self.assertEqual(list(self.kernel.sets), ["owners-own"])


class Loop(KernelCase):
    """The Agent with "backend": "iptables": rounds, ticks, bans, switching."""

    def setUp(self):
        super().setUp()
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)
        self.sent, self.tables, self.deleted = [], set(), []

        def nft(*args, stdin=None):
            if args[:2] == ("delete", "table"):
                self.deleted.append(args[3])
                self.tables.discard(args[3])
            return done()
        for p in [mock.patch.object(agent, "fetch_rules", lambda config, etag, **_: (None, etag)),
                  mock.patch.object(agent, "report", lambda config, events: self.sent.extend(events)),
                  mock.patch.object(agent, "nft_installed", lambda: True),
                  mock.patch.object(agent, "nft_table_present", lambda table=agent.TABLE: table in self.tables),
                  mock.patch.object(agent, "nft", nft),
                  mock.patch.object(agent, "nginx_installed", lambda config: False)]:
            p.start()
            self.addCleanup(p.stop)

    def firewall(self, backend="iptables", **extra):
        firewall = agent.Agent(dict(agent.DEFAULTS, site_id="a" * 24, secret="s", endpoint="https://c.example", sites=[],
                                    state_dir=self.dir, backend=backend, ports=[80, 443],
                                    nginx_file=os.path.join(self.dir, "fw.conf")))
        firewall.rules = rules(**extra)
        return firewall

    def test_a_round_puts_everything_in_place_and_says_so(self):
        firewall = self.firewall()
        firewall.step()
        self.assertEqual(firewall.layers(), ["kernel", "flood", "origin"])
        self.assertIn("ANALYTICS-FW", self.kernel.chains["4"])
        self.assertIn("ANALYTICS-FLOOD", self.kernel.chains["6"])
        restores = len(self.kernel.restores)
        firewall.step()
        self.assertEqual(len(self.kernel.restores), restores, "nothing changed: nothing rewritten")

    def test_after_a_reboot_it_all_goes_back_with_the_bans(self):
        firewall = self.firewall()
        firewall.step()
        firewall.bans = {"198.51.100.9": {"rule": "flood", "first": 1, "until": agent.time.time() + 300, "hits": 3, "reported": True}}
        self.kernel.__init__()  # a reboot: no chains, no sets
        firewall.step()
        self.assertIn("ANALYTICS-FW", self.kernel.chains["4"])
        self.assertIn("ANALYTICS-FLOOD", self.kernel.chains["4"])
        left = self.kernel.sets["analytics-flood-ban4"]["elements"]["198.51.100.9"][1]
        self.assertTrue(295 <= left <= 300, left)

    def test_kernel_bans_are_reported_once_each(self):
        firewall = self.firewall()
        firewall.step()
        self.kernel.sets["analytics-flood-ban4"]["elements"]["198.51.100.9"] = (41, 590)
        self.kernel.sets["analytics-flood-ban6"]["elements"]["2001:db8:0:1::"] = (5, 590)
        firewall.tick(2000)
        firewall.tick(2000 + agent.FLOOD_READ_EVERY)
        self.assertEqual(sorted((e["ip"], e["rule"], e["action"], e["hits"]) for e in self.sent),
                         [("198.51.100.9", "flood", "block", 41), ("2001:db8:0:1::/64", "flood", "block", 5)])

    def test_a_ban_with_no_time_on_it_is_ended_by_the_agent(self):
        firewall = self.firewall()
        firewall.step()
        self.kernel.sets["analytics-flood-ban4"]["elements"]["198.51.100.9"] = (4, 0)  # an older kernel's SET target
        firewall.tick(2000)
        self.assertEqual(firewall.bans["198.51.100.9"]["until"], 2000 + 600)
        firewall.tick(2000 + agent.FLOOD_READ_EVERY)
        self.assertIn("198.51.100.9", self.kernel.sets["analytics-flood-ban4"]["elements"])
        firewall.tick(2000 + 601)
        self.assertNotIn("198.51.100.9", self.kernel.sets["analytics-flood-ban4"]["elements"], "ended at its time")
        self.assertEqual([e["ip"] for e in self.sent], ["198.51.100.9"], "reported once")

    def test_list_matches_are_reported_from_the_set_counters(self):
        firewall = self.firewall()
        firewall.step()
        self.kernel.sets["analytics-list-deny4"]["elements"]["198.51.100.0/24"] = (12, 0)
        firewall.collect()
        self.assertEqual([(e["ip"], e["rule"], e["hits"]) for e in self.sent], [("198.51.100.0/24", "deny", 12)])

    def test_the_access_log_limit_bans_into_the_ipset(self):
        firewall = self.firewall()
        firewall.step()
        self.assertTrue(firewall.counting(firewall.p))
        self.assertTrue(firewall.kernel_ban({"198.51.100.20": 600}))
        self.assertEqual(self.kernel.sets["analytics-flood-ban4"]["elements"]["198.51.100.20"], (0, 600))

    def test_iptables_removes_what_nftables_left_and_back(self):
        self.tables = {"analytics_firewall", "analytics_flood"}
        firewall = self.firewall("iptables")
        firewall.step()
        self.assertEqual(sorted(self.deleted), ["analytics_firewall", "analytics_flood"])
        self.assertIn("ANALYTICS-FW", self.kernel.chains["4"])
        with mock.patch.object(agent, "nft_apply", lambda config, p: True), \
                mock.patch.object(agent, "flood_apply", lambda config, p: True), mock.patch.object(agent, "nft_counters", lambda: {}):
            self.firewall("nftables").step()
        self.assertEqual(self.kernel.chains, {"4": {}, "6": {}})
        self.assertEqual(self.kernel.prerouting, {"4": [], "6": []})
        self.assertEqual(self.kernel.sets, {})

    def test_the_cleanup_of_the_other_backend_runs_once_a_start(self):
        with mock.patch.object(agent, "nft_apply", lambda config, p: True), \
                mock.patch.object(agent, "flood_apply", lambda config, p: True), mock.patch.object(agent, "nft_counters", lambda: {}):
            firewall = self.firewall("nftables")
            firewall.step()
            states = len([1 for _ in self.kernel.restores])
            with mock.patch.object(agent, "ipt_state", side_effect=AssertionError("looked again")):
                firewall.step()
        self.assertEqual(states, 0, "nothing of ours was there to remove")

    def test_nginx_or_none_removes_both_kernels(self):
        agent.ipt_apply({"ports": [80, 443]}, agent.plan(rules()))
        self.tables = {"analytics_flood"}
        firewall = self.firewall("none")
        firewall.running.update(flood=True, origin=True)
        firewall.step()
        self.assertEqual(self.deleted, ["analytics_flood"])
        self.assertEqual(self.kernel.sets, {})
        self.assertFalse(firewall.running["flood"] or firewall.running["kernel"])

    def test_clear_removes_both_whatever_the_backend(self):
        for backend in ("iptables", "nftables", "nginx"):
            agent.ipt_apply({"ports": [80, 443]}, agent.plan(rules()))
            agent.ipt_flood_apply({"ports": [80, 443]}, agent.plan(rules()))
            self.tables, self.deleted = {"analytics_firewall", "analytics_flood"}, []
            agent.clear(self.firewall(backend).config)
            self.assertEqual(sorted(self.deleted), ["analytics_firewall", "analytics_flood"], backend)
            self.assertEqual((self.kernel.chains, self.kernel.sets), ({"4": {}, "6": {}}, {}), backend)

    def test_without_ipset_nothing_is_claimed(self):
        with mock.patch.object(agent, "ipt_tools", lambda refresh=False: None):
            firewall = self.firewall()
            firewall.step()
        self.assertEqual(firewall.layers(), [])
        self.assertIn("ipset", agent.log.call_args_list[0][0][0])

    def test_iptables_nft_with_nft_installed_suggests_nftables(self):
        with mock.patch.object(agent, "ipt_tools", lambda refresh=False: dict(TOOLS, mode="nft")):
            self.firewall().step()
        self.assertIn('"backend": "nftables"', agent.log.call_args_list[0][0][0])


class Detect(unittest.TestCase):
    def detect(self, binaries, outputs):
        def run(args, timeout, stdin=None):
            name = os.path.basename(args[0])
            return done(stdout=outputs.get(name + " --version" if args[1:] == ["--version"] else name, ""))
        with mock.patch.object(agent.shutil, "which", lambda name: "/usr/sbin/" + name if name in binaries else None), \
                mock.patch.object(agent, "run_command", run):
            return agent.ipt_detect()

    def test_the_system_iptables_and_its_mode(self):
        tools = self.detect({"ipset", "iptables"}, {"iptables --version": "iptables v1.8.4 (nf_tables)"})
        self.assertEqual((tools["mode"], tools["4"], tools["restore6"]),
                         ("nft", ["iptables", "-w"], ["ip6tables-restore", "--noflush", "-w"]))

    def test_centos_7s_iptables_has_no_restore_lock(self):
        tools = self.detect({"ipset", "iptables"}, {"iptables --version": "iptables v1.4.21"})
        self.assertEqual((tools["mode"], tools["4"], tools["restore4"]), ("legacy", ["iptables", "-w"], ["iptables-restore", "--noflush"]))

    def test_with_both_kinds_the_one_holding_the_rules(self):
        both = {"ipset", "iptables", "iptables-legacy", "iptables-nft"}
        outputs = {"iptables --version": "iptables v1.8.7 (nf_tables)", "iptables-legacy --version": "iptables v1.8.7 (legacy)",
                   "iptables-nft --version": "iptables v1.8.7 (nf_tables)",
                   "iptables-legacy-save": "*filter\n-A INPUT -j DOCKER\n-A FORWARD -j DOCKER-USER\nCOMMIT\n",
                   "iptables-nft-save": "*filter\nCOMMIT\n"}
        self.assertEqual(self.detect(both, outputs)["4"], ["iptables-legacy", "-w"])
        outputs["iptables-nft-save"] = "*filter\n-A INPUT -j A\n-A INPUT -j B\n-A INPUT -j C\nCOMMIT\n"
        self.assertEqual(self.detect(both, outputs)["6"], ["ip6tables-nft", "-w"])
        del outputs["iptables-nft-save"], outputs["iptables-legacy-save"]
        self.assertEqual(self.detect(both, outputs)["mode"], "nft", "a tie: what `iptables` is")

    def test_no_ipset_no_iptables_backend(self):
        self.assertIsNone(self.detect({"iptables"}, {}))
        self.assertIsNone(self.detect({"ipset"}, {}))

    def test_auto(self):
        cases = [(True, 0, TOOLS, 0, "nftables"), (True, 1, TOOLS, 0, "iptables"), (False, 0, TOOLS, 0, "iptables"),
                 (False, 0, None, 0, "none"),
                 (False, 0, TOOLS, 1, "none")]  # an OpenVZ or LXC guest: the commands, not the kernel's ipset
        for installed, nft_code, tools, ipset_code, expected in cases:
            with mock.patch.object(agent, "nft_installed", lambda: installed), \
                    mock.patch.object(agent, "nft", lambda *a, stdin=None: done(nft_code)), \
                    mock.patch.object(agent, "ipt_tools", lambda refresh=False: tools), \
                    mock.patch.object(agent, "ipt", lambda family, *a: done()), \
                    mock.patch.object(agent, "ipset", lambda *a, stdin=None: done(ipset_code)):
                self.assertEqual(agent.auto_backend(), expected, (installed, nft_code, tools, ipset_code))

    def test_the_config_takes_iptables_and_auto(self):
        folder = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, folder)
        path = os.path.join(folder, "agent.json")
        for backend, expected in (("iptables", "iptables"), ("auto", "none")):
            with open(path, "w") as f:
                f.write('{"site_id": "%s", "secret": "s", "endpoint": "https://c", "backend": "%s", "state_dir": "%s"}'
                        % ("a" * 24, backend, folder))
            with mock.patch.object(agent, "CONFIG_FILE", path), mock.patch.object(agent, "auto_backend", lambda: "none"), \
                    mock.patch.object(agent, "log"):
                self.assertEqual(agent.load_config()["backend"], expected)


class ReviewFixes(KernelCase):
    def test_ip6tables_that_cant_use_mangle_leaves_ipv4_working_and_is_said_once(self):
        calls = []

        def ipt(family, *args):
            calls.append(family)
            return done(1, stderr="ip6tables v1.8.7 (legacy): can't initialize ip6tables table `mangle'")
        with mock.patch.object(agent, "ipt_families", METER_FAMILIES), mock.patch.object(agent, "ipt", ipt), \
                mock.patch.object(agent.os.path, "exists", lambda path: True), mock.patch.object(agent, "_ipt_six", []):
            self.assertEqual(agent.ipt_families(), ("4",))
            self.assertEqual(agent.ipt_families(), ("4",))
            self.assertEqual(calls, ["6"], "looked at once")
            self.assertEqual(len([c for c in agent.log.call_args_list if "IPv4 only" in c[0][0]]), 1)
            self.assertTrue(agent.ipt_apply(self.config, agent.plan(rules())))
        self.assertNotIn("ANALYTICS-FW", self.kernel.chains["6"])
        self.assertFalse([n for n in self.kernel.sets if n.endswith("6")])

    def test_a_failure_that_isnt_a_set_made_otherwise_keeps_the_bans(self):
        agent.ipt_flood_apply(self.config, agent.plan(rules()))
        self.kernel.sets["analytics-flood-ban4"]["elements"]["198.51.100.9"] = (40, 500)
        self.kernel.refuse = lambda text: "ipset v7.1: Kernel error received: Resource busy" if "create" in text else None
        self.assertIs(agent.ipt_flood_apply(self.config, agent.plan(rules(flood=dict(FLOOD, ban=300)))), False)
        self.assertEqual(self.kernel.sets["analytics-flood-ban4"]["elements"], {"198.51.100.9": (40, 500)})
        self.assertIn("ANALYTICS-FLOOD", self.kernel.chains["4"], "nothing taken out")

    def test_a_list_set_made_otherwise_is_made_again(self):
        self.kernel.sets["analytics-list-deny4"] = {"type": "hash:ip family inet", "elements": {}}
        swap = {"n": 0}

        def refuse(text):
            if "swap analytics-list-deny4-new" in text and self.kernel.sets.get("analytics-list-deny4", {}).get("type") == "hash:ip family inet":
                swap["n"] += 1
                return "ipset v7.1: The sets cannot be swapped: their type does not match"
        self.kernel.refuse = refuse
        self.assertTrue(agent.ipt_apply(self.config, agent.plan(rules())))
        self.assertEqual(swap["n"], 1)
        self.assertIn("hash:net", self.kernel.sets["analytics-list-deny4"]["type"])

    def test_the_counters_read_only_our_sets(self):
        asked = []
        with mock.patch.object(agent, "ipset", lambda *a, stdin=None: asked.append(a) or done()):
            agent.ipt_counters()
        self.assertEqual(sorted(asked), sorted(("save", agent.IPT_LIST_SET + name + family) for name in agent.LISTS for family in "46"))

    def test_a_rate_over_what_hashlimit_takes_is_logged(self):
        agent.ipt_flood_apply(self.config, agent.plan(rules(flood=dict(FLOOD, conn_rate=50000))))
        self.assertTrue([c for c in agent.log.call_args_list if "limited at 10000" in c[0][0]])

    def test_no_web_ports_is_not_a_chain_gone_every_round(self):
        agent.ipt_apply({"ports": []}, agent.plan(rules()))
        self.assertTrue(agent.ipt_present("ANALYTICS-FW", ports=False))
        self.assertFalse(agent.ipt_present("ANALYTICS-FW"))

    def test_the_seen_add_has_no_exist_which_would_reset_its_counter(self):
        rule = [r for r in agent.ipt_flood_rules(agent.plan(rules()), "4") if "--add-set analytics-flood-seen4" in r]
        self.assertEqual(rule, ["-m set ! --match-set analytics-flood-origin4 src -j SET --add-set analytics-flood-seen4 src"])


class NftFresh(unittest.TestCase):
    def test_only_a_table_declared_otherwise_is_started_over(self):
        for error, calls, result in (("Error: Could not process rule: File exists", 2, "fresh"),
                                     ("Error: Could not process rule: Device or resource busy", 1, False)):
            ran = []

            def nft(*args, stdin=None):
                ran.append(stdin)
                return done(1, stderr=error) if len(ran) == 1 else done()
            with mock.patch.object(agent, "nft", nft), mock.patch.object(agent, "log"):
                self.assertEqual(agent.flood_apply({"ports": [80, 443]}, agent.plan(rules())), result, error)
            self.assertEqual(len(ran), calls, error)
            if calls == 1:
                self.assertNotIn("delete table", ran[0])


class NginxCheckExempt(unittest.TestCase):
    def test_nginx_skips_the_private_and_loopback_ranges_as_the_other_servers_do(self):
        p = agent.plan(dict(rules(), challenge={"skip": [], "exempt": []}))
        config = dict(agent.DEFAULTS, secret="s", nginx_flood_file="/etc/nginx/analytics-flood.conf",
                      nginx_check_file="/etc/nginx/analytics-check.conf", nginx_check_log="/var/log/nginx/analytics-check.log")
        text = agent.nginx_flood_text(config, p, 20000)
        check = text[text.index("geo $sg_check_exempt"):]
        check = check[:check.index("}")]
        for net in ("10.0.0.0/8", "127.0.0.0/8", "192.168.0.0/16", "::1/128", "fc00::/7", "203.0.113.7/32", "66.249.64.0/27"):
            self.assertIn("    %s 1;" % net, check)


if __name__ == "__main__":
    unittest.main()
