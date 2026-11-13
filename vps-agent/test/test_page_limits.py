"""Page limits in the agent's nginx (sdk/protocols/firewall.md, "Page limits"):
which limits nginx gets, the text that reaches its http { } file, and what is
read back from its error log and reported.

    python3 -m unittest discover -s test
"""
import json
import os
import re
import shutil
import tempfile
import unittest
from unittest import mock

from test_flood import agent, config

REAL_DUMP = agent.nginx_dump

HERE = os.path.dirname(os.path.abspath(__file__))
with open(os.path.join(HERE, "..", "..", "protocols", "page-limits-cases.json")) as f:
    CASES = json.load(f)

LOGIN = {"id": "wp.login", "action": "block", "limit": 10, "window": 60, "methods": ["POST"],
         "path": {"exact": ["/wp-login.php"]}}
CART = {"id": "woo.add-to-cart", "action": "block", "limit": 30, "window": 60, "query": {"contains": ["add-to-cart="]}}
CHECKOUT = {"id": "checkout", "action": "block", "limit": 5, "window": 3600, "path": {"prefix": ["/checkout"]}}
# Each limit's zone, named from its id: sg_pl_L, sg_pl_C and sg_pl_K in the texts below.
ZONES = {"sg_pl_" + key: agent.nginx_page_zone(rule["id"]) for key, rule in (("L", LOGIN), ("C", CART), ("K", CHECKOUT))}


def z(text):
    for short, zone in ZONES.items():
        text = text.replace(short, zone)
    return text


def rules(limits, **extra):
    base = {"v": 1, "enabled": True, "mode": "block", "sync": 60, "allow": ["203.0.113.250"],
            "goodbots": ["192.0.2.200/29"], "flood": None, "origin": None, "challenge": None,
            "limits": {"exempt": ["198.51.100.0/24"], "rules": limits}}
    base.update(extra)
    return base


def maps(text):
    """{variable: [(key, value)]} of the file's map blocks."""
    out = {}
    for head, body in re.findall(r'^map \S+ \$(\S+) \{\n(.*?)^\}', text, re.M | re.S):
        out[head] = [tuple(line.strip().rstrip(";").rsplit(" ", 1)) for line in body.splitlines()]
    return out


def regexes(text, variable):
    """A map's regex keys as Python patterns (nginx's ~* is case-insensitive)."""
    return [re.compile(key[3:-1].replace("\\\\", "\\"), re.I) for key, _ in maps(text)[variable] if key.startswith('"~*')]


class Plan(unittest.TestCase):
    def ids(self, limits, **extra):
        p = agent.plan(rules(limits, **extra))
        return [limit["id"] for limit in (p["limits"] or {}).get("rules", [])]

    def test_the_shared_cases_that_are_ignored_are_ignored(self):
        case = [s for s in CASES["scenarios"] if s["name"].startswith("limits with nothing to match")][0]
        self.assertEqual(self.ids(case["limits"]["rules"]), [])

    def test_watched_and_per_page_limits_stay_out(self):
        self.assertEqual(self.ids([dict(LOGIN, action="monitor"), dict(LOGIN, id="each", each="path"), CART]),
                         ["woo.add-to-cart"])

    def test_limits_need_the_firewall_on(self):
        self.assertIsNone(agent.plan(rules([LOGIN], enabled=False))["limits"])
        self.assertIsNone(agent.plan(dict(rules([LOGIN]), limits=None))["limits"])

    def test_a_limit_naming_a_section_nothing_of_which_can_be_carried_is_dropped_whole(self):
        # Matching on the query alone would count every page with it, not the one asked.
        self.assertEqual(self.ids([dict(CART, id="both", path={"exact": ['/a"b']})]), [])
        self.assertEqual(self.ids([dict(LOGIN, methods=["P OST"])]), [])
        self.assertEqual(self.ids([dict(LOGIN, ua={"exact": [""]})]), [])

    def test_exempt_holds_limits_exempt_allow_goodbots_and_the_private_ranges(self):
        v4, v6 = agent.plan(rules([LOGIN]))["limits"]["exempt"]
        for net in ("198.51.100.0/24", "203.0.113.250/32", "192.0.2.200/29", "10.0.0.0/8", "127.0.0.0/8"):
            self.assertIn(net, v4)
        self.assertIn("fc00::/7", v6)

    def test_rates(self):
        self.assertEqual(agent.nginx_rate(10, 60), "10r/m")
        self.assertEqual(agent.nginx_rate(20, 1), "20r/s")
        self.assertEqual(agent.nginx_rate(10, 7), "86r/m", "rounded up, never stricter")
        self.assertEqual(agent.nginx_rate(5, 3600), "1r/m", "nginx's slowest")


class Text(unittest.TestCase):
    def setUp(self):
        self.config = config()
        self.addCleanup(shutil.rmtree, self.config["state_dir"])

    def text(self, limits, **extra):
        return agent.nginx_flood_text(self.config, agent.plan(rules(limits, **extra)), 20000)

    def test_an_exact_path_and_a_method(self):
        text = self.text([LOGIN])
        self.assertIn(z("map $request_method $sg_pl_L_method {\n    default 0;\n    POST 1;\n}"), text)
        self.assertIn(z('map $uri $sg_pl_L_path {\n    default 0;\n    "~*^/wp-login\\.php$" 1;\n}'), text)
        self.assertIn(z('map "$sg_pl_exempt$sg_flood_static$sg_pl_L_method$sg_pl_L_path" $sg_pl_L {\n'
                        '    "0011" $sg_flood_addr;\n    default "";\n}'), text)
        self.assertIn(z("limit_req_zone $sg_pl_L zone=sg_pl_L:1m rate=10r/m;"), text)
        self.assertIn(z("limit_req zone=sg_pl_L burst=9 nodelay;"), text, "exactly 10 at once")
        path = regexes(text, z("sg_pl_L_path"))
        self.assertTrue(any(r.search("/WP-Login.php") for r in path))
        self.assertFalse(any(r.search(s) for r in path for s in ("/wp-login.php/x", "/a/wp-login.php", "/wp-loginXphp")))

    def test_a_prefix_and_a_query_taken_raw_or_percent_encoded(self):
        text = self.text([CART, CHECKOUT])
        self.assertIn('    "~*^/checkout" 1;', text)
        self.assertIn(z("limit_req_zone $sg_pl_K zone=sg_pl_K:1m rate=1r/m;"), text)
        self.assertIn(z("limit_req zone=sg_pl_K burst=4 nodelay;"), text)
        self.assertIn(z('map "$sg_pl_exempt$sg_flood_static$sg_pl_C_query" $sg_pl_C {\n    "001" $sg_flood_addr;'), text)
        query = regexes(text, z("sg_pl_C_query"))
        for args in ("add-to-cart=5", "x=1&ADD-TO-CART=5", "add%2Dto%2dcart%3D5", "%61dd-to-cart="):
            self.assertTrue(any(r.search(args) for r in query), args)
        self.assertFalse(any(r.search("add-to-cart") for r in query))

    def test_the_shared_maps_and_answer_are_written_once_with_flood_on_or_off(self):
        flood = {"conn_rate": 30, "conn_max": 300, "req_rate": 20, "req_burst": 60, "ban": 600, "exempt": ["173.245.48.0/20"]}
        for text in (self.text([LOGIN]), self.text([LOGIN], flood=flood)):
            for line in ("map $uri $sg_flood_static {", "map $binary_remote_addr $sg_flood_addr {",
                         "limit_req_status 429;", "limit_req_log_level error;"):
                self.assertEqual(text.count(line), 1, line)
        with_flood = self.text([LOGIN], flood=flood)
        self.assertIn("limit_req zone=analytics_flood burst=60 nodelay;", with_flood, "flood's own limit is unchanged")
        geo = with_flood.split("geo $sg_pl_exempt {", 1)[1].split("}", 1)[0]
        self.assertIn("    173.245.48.0/20 1;", geo, "flood's exempt (Cloudflare) isn't limited per page either")
        self.assertIn("    198.51.100.0/24 1;", geo)

    def test_zones_are_named_from_the_id_not_the_place(self):
        self.assertEqual(agent.nginx_page_zone("wp.login"), agent.nginx_page_zone("wp.login"))
        self.assertNotEqual(agent.nginx_page_zone("wp.login"), agent.nginx_page_zone("wp.login2"))
        for rule in (LOGIN, CART, CHECKOUT, {"id": "a-b.c_d"}):
            self.assertRegex(agent.nginx_page_zone(rule["id"]), r"^sg_pl_[0-9a-f]{10}$", "a valid nginx variable name")
        self.assertEqual(self.text([LOGIN, CART]).split("# Page limits", 1)[1].count(z("zone=sg_pl_L:")), 1)
        before = {l for l in self.text([LOGIN, CART]).splitlines() if l.startswith("limit_req")}
        after = {l for l in self.text([CART, LOGIN]).splitlines() if l.startswith("limit_req")}
        self.assertEqual(before, after, "reordering the limits renames nothing")

    def test_a_repeated_id_is_written_once(self):
        text = self.text([LOGIN, dict(LOGIN, limit=99)])
        self.assertEqual(text.count(z("limit_req_zone $sg_pl_L ")), 1, "nginx refuses a zone written twice")
        self.assertIn(z("limit_req zone=sg_pl_L burst=9 nodelay;"), text, "the first one stands")

    def test_monitor_mode_writes_nothing(self):
        text = self.text([LOGIN], mode="monitor")
        self.assertNotIn("sg_pl", text)
        self.assertFalse([l for l in text.splitlines() if l.startswith("limit_req")])
        self.assertIn("# No page limits in monitor mode", text)

    def test_hostile_values_never_reach_the_file(self):
        hostile = ['/a"; } server { listen 81; #', "/a;b", "/a{b}", "/a$uri", "/a b", "/a\tb", "/a\nb", "/a\\b",
                   "/a'b", "/a|b", "/a^b", "/a?b", "/é", "/a%2fb", "/a#b", "/" + "a" * 200, ""]
        text = self.text([
            {"id": "evil", "action": "block", "limit": 1, "window": 60, "path": {"exact": hostile, "prefix": ["/ok"]},
             "query": {"contains": ['x"y', "x;y", "x y", "x$y", "x=%2"]}, "methods": ["POST", "GET;", 'P"']},
            {"id": "Bad Id", "action": "block", "limit": 1, "window": 60, "path": {"prefix": ["/"]}},
            {"id": 'x"; }', "action": "block", "limit": 1, "window": 60, "path": {"prefix": ["/"]}},
            {"id": "big", "action": "block", "limit": 10 ** 9, "window": 60, "path": {"prefix": ["/"]}},
        ])
        page = text[text.index("# evil"):text.index("limit_req_status")]
        evil = agent.nginx_page_zone("evil")
        self.assertEqual(maps(page)[evil + "_path"], [("default", "0"), ('"~*^/ok"', "1")])
        self.assertEqual(maps(page)[evil + "_method"], [("default", "0"), ("POST", "1")])
        self.assertEqual(len(maps(page)[evil + "_query"]), 2, "only x=%2 is carried")
        self.assertEqual(len(re.findall(r"^limit_req_zone ", text, re.M)), 1, "the other three are refused")
        for line in page.splitlines():
            # Every quoted string is closed on its line and holds no ; { } space or quote of the
            # sender's, and `$` only as the regex's own end.
            for quoted in re.findall(r'"([^"]*)"', line):
                if quoted.startswith("~*"):
                    self.assertFalse(re.search(r"[;{}\s'#]", quoted), quoted)
                    self.assertNotIn("$", quoted[:-1], quoted)
            self.assertEqual(line.count('"') % 2, 0, line)


class Agent(unittest.TestCase):
    """The agent with page limits, nginx and the reports faked."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir)
        self.config = config(self.dir)
        self.error_log = os.path.join(self.dir, "error.log")
        open(self.error_log, "w").close()
        self.sent, self.banned, self.written = [], [], []
        self.included = {self.config["nginx_flood_file"]}
        self.refuse = lambda texts: False
        self.dump = lambda config: (set(self.included), [self.error_log])
        patches = [
            mock.patch.object(agent, "report", lambda config, events: self.sent.extend(events)),
            mock.patch.object(agent, "nft_ban", lambda timeouts: self.banned.append(dict(timeouts)) or True),
            mock.patch.object(agent, "nginx_installed", lambda config: True),
            mock.patch.object(agent, "nginx_write", self.write),
            mock.patch.object(agent, "nginx_dump", lambda config: self.dump(config)),
            mock.patch.object(agent, "log"),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def write(self, config, texts, owed=False):
        self.written.append(texts)
        return not self.refuse(texts)

    def firewall(self, limits=(LOGIN, CART), **extra):
        firewall = agent.Agent(self.config)
        firewall.rules = rules(list(limits), **extra)
        firewall.p = agent.plan(firewall.rules)
        firewall.nginx_step(firewall.p, 1000)
        self.addCleanup(lambda: [tail.close() for tail in firewall.tails.values()])
        return firewall

    def limited(self, zone, address, request='"POST /wp-login.php?redirect_to=x HTTP/1.1"', times=1):
        with open(self.error_log, "a") as f:
            for _ in range(times):
                f.write('2026/11/04 21:20:25 [error] 30#30: *11 limiting requests, excess: 10.000 by zone "%s", '
                        'client: %s, server: example.com, request: %s, host: "example.com"\n' % (zone, address, request))


class Flows(Agent):
    """What nginx runs, its error log, the layer."""

    def test_a_limited_line_is_reported_as_the_limit_and_nobody_is_banned(self):
        firewall = self.firewall()
        self.assertEqual(firewall.layers(), ["nginx-limits"])
        self.limited(z("sg_pl_L"), "198.18.0.5", times=3)
        self.limited(z("sg_pl_C"), "2001:db8:0:1::42", '"GET /?add-to-cart=5 HTTP/2.0"')
        self.limited(z("sg_pl_C"), "198.18.0.9", '"GET /' + "a" * 400 + ' HTTP/1.1"')
        self.limited(z("sg_pl_K"), "198.18.0.5")  # no such limit in place
        self.limited("analytics_flood", "198.18.0.5")  # flood is off: not ours to read
        firewall.tick(1001)
        rows = sorted((e["ip"], e["rule"], e["action"], e["method"], e["path"], e["hits"]) for e in self.sent)
        self.assertEqual(rows, [
            ("198.18.0.5", "limit:wp.login", "block", "POST", "/wp-login.php", 3),
            ("198.18.0.9", "limit:woo.add-to-cart", "block", "GET", "/" + "a" * 299, 1),
            ("2001:db8:0:1::42", "limit:woo.add-to-cart", "block", "GET", "/", 1),
        ])
        firewall.tick(1001 + agent.BAN_REPORT_AFTER)
        self.assertEqual((self.banned, firewall.bans), ([], {}), "a page limit never bans")

    def test_a_line_from_before_the_limits_were_reordered_is_credited_to_its_own_limit(self):
        firewall = self.firewall(limits=(CART, LOGIN))
        self.limited(z("sg_pl_L"), "198.18.0.5")  # written while wp.login was the first limit
        self.limited(z("sg_pl_K"), "198.18.0.6")  # checkout, taken out since
        firewall.tick(1001)
        self.assertEqual([(e["ip"], e["rule"]) for e in self.sent], [("198.18.0.5", "limit:wp.login")])

    def test_a_forged_line_is_not_a_limit(self):
        firewall = self.firewall()
        with open(self.error_log, "a") as f:
            f.write('2026/11/04 21:20:25 [error] 30#30: *5 open() "/x" failed, client: 198.18.0.66, server: x, '
                    'request: "GET /x HTTP/1.1", referrer: "limiting requests, excess: 1 by zone "%s", client: 1.2.3.4,"\n' % z("sg_pl_L"))
        firewall.tick(1001)
        self.assertEqual(self.sent, [])

    def test_no_layer_or_file_lines_without_block_mode_or_the_include(self):
        firewall = self.firewall(mode="monitor")
        self.assertEqual(self.written, [], "nothing wanted, and no file there yet")
        self.assertEqual(firewall.layers(), [])
        self.assertNotIn(self.error_log, firewall.tails)
        self.included = set()
        self.assertEqual(self.firewall().layers(), [])

    def test_the_layer_header_names_it(self):
        firewall = self.firewall()
        sent = {}

        def request(config, method, path, body=None, headers=None):
            sent.update(headers or {})
            return 304, None, {}

        with mock.patch.object(agent, "request", request):
            agent.fetch_rules(self.config, "", layers=firewall.layers())
        self.assertEqual(sent["X-Firewall-Layers"], "nginx-limits")
        self.assertNotIn("User-Agent", sent, "a page limit isn't the site's request limit: still no-rate")

    def test_files_nginx_refuses_go_in_without_the_page_limits(self):
        # nginx -t refusing what the page limits wrote must not hold back the
        # rest of the file (the flood limit, the browser check and its pass).
        self.refuse = lambda texts: z("sg_pl_L") in texts[self.config["nginx_flood_file"]]
        flood = {"conn_rate": 30, "conn_max": 300, "req_rate": 20, "req_burst": 60, "ban": 600, "exempt": []}
        firewall = self.firewall(flood=flood)
        self.assertEqual(len(self.written), 2)
        self.assertNotIn("sg_pl", self.written[1][self.config["nginx_flood_file"]])
        self.assertEqual(firewall.layers(), ["nginx"])
        self.limited(z("sg_pl_L"), "198.18.0.5")
        firewall.tick(1001)
        self.assertEqual(self.sent, [])
        firewall.nginx_step(firewall.p, 1000 + agent.NGINX_DUMP_EVERY)
        self.assertEqual(len(self.written), 2, "not tried again until the rules change")



NGINX_CONF = """# configuration file /etc/nginx/nginx.conf:
user www-data;
error_log %(error_log)s;
http {
    limit_req_zone $binary_remote_addr zone=theirs:10m rate=5r/s;  # http-level lines add to ours
    limit_req zone=theirs burst=10;
    include %(flood)s;
    include conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}

# configuration file %(flood)s:
limit_req_zone $x zone=sg_pl_0123456789:1m rate=1r/s;

# configuration file /etc/nginx/conf.d/limits.conf:
limit_req zone=theirs;

# configuration file /etc/nginx/sites-enabled/shop:
%(vhost)s
"""


class TheSitesOwnLimits(unittest.TestCase):
    """A server { } or location with a limit_req of its own gets none of ours."""

    def found(self, vhost, extra=""):
        text = NGINX_CONF % {"error_log": "/var/log/nginx/error.log", "flood": "/etc/nginx/analytics-flood.conf",
                             "vhost": vhost} + extra
        return [(path, line, sorted(zones)) for path, line, zones in
                agent.parse_nginx_limit_req(text, ("/etc/nginx/analytics-flood.conf", "/etc/nginx/analytics-check.conf"))]

    def test_one_in_a_server_or_a_location(self):
        self.assertEqual(self.found("server {\n    listen 80;\n    limit_req zone=theirs burst=5;\n}"),
                         [("/etc/nginx/sites-enabled/shop", 3, ["theirs"])])
        self.assertEqual(self.found("server {\n    location /api/ {\n        if ($x) { limit_req zone=a; }\n"
                                    "        limit_req zone=b nodelay;\n    }\n}"),
                         [("/etc/nginx/sites-enabled/shop", 3, ["a"]), ("/etc/nginx/sites-enabled/shop", 4, ["b"])])

    def test_two_lines_in_one_block_are_one_block(self):
        self.assertEqual(self.found("server {\n    limit_req zone=theirs;\n    limit_req zone=analytics_flood burst=60 nodelay;\n}"),
                         [("/etc/nginx/sites-enabled/shop", 2, ["analytics_flood", "theirs"])])

    def test_what_isnt_a_limit_req(self):
        vhost = "\n".join([
            "server {",
            "    # limit_req zone=commented;",
            "    #limit_req zone=commented;",
            "    limit_req_status 429; limit_req_log_level warn; limit_req_dry_run on;",
            "    limit_req_zone $a zone=z:1m rate=1r/s;",
            '    return 200 "limit_req zone=quoted;";',
            "    add_header X-A 'x; limit_req zone=quoted';",
            '    set $v "a\\"; limit_req zone=escaped;";',
            "    location ~ ^/a{2}$ { return 204; }",
            "}",
            "stream { server { limit_req zone=nonsense; } }",
            "map $uri $m { limit_req 1; }",
        ])
        self.assertEqual(self.found(vhost), [])

    def test_a_snippet_counts_where_it_is_included(self):
        snippet = "\n# configuration file /etc/nginx/snippets/rate.conf:\nlimit_req zone=theirs;\n"
        self.assertEqual(self.found("server {\n    include snippets/rate.conf;\n}", snippet),
                         [("/etc/nginx/snippets/rate.conf", 1, ["theirs"])])
        self.assertEqual(self.found("server {\n    listen 80;\n}", snippet), [], "included by nothing: where it starts")

    def test_the_agents_own_files_are_left_out(self):
        self.assertEqual(self.found("server {\n    include /etc/nginx/analytics-flood.conf;\n}"), [])


class TheSitesOwnLimitsInTheAgent(Agent):
    """`nginx -T` read for real (from a file), and what the agent makes of it."""

    def setUp(self):
        super().setUp()
        self.dump = REAL_DUMP
        self.conf = os.path.join(self.dir, "nginx-T.txt")
        self.config["nginx_dump"] = ["cat", self.conf]

    def nginx(self, vhost):
        with open(self.conf, "w") as f:
            f.write(NGINX_CONF % {"error_log": self.error_log, "flood": self.config["nginx_flood_file"], "vhost": vhost})

    def notes(self):
        return " ".join(str(call.args[0]) for call in agent.log.call_args_list)

    def test_a_vhost_with_its_own_limit_req_turns_the_layer_off_and_says_where(self):
        self.nginx("server {\n    server_name shop;\n    location / {\n        limit_req zone=theirs;\n    }\n}")
        firewall = self.firewall()
        self.assertEqual(firewall.layers(), [])
        notes = self.notes()
        self.assertIn("/etc/nginx/sites-enabled/shop line 4", notes)
        self.assertIn(z("limit_req zone=sg_pl_L burst=9 nodelay;"), notes)
        self.assertIn(z("limit_req zone=sg_pl_C burst=29 nodelay;"), notes)
        self.assertIn("take the site's own out", notes)
        self.limited(z("sg_pl_L"), "198.18.0.5")
        firewall.tick(1001)
        self.assertEqual(len(self.sent), 1, "other blocks still limit, and are still reported")

    def test_the_flood_layer_likewise(self):
        flood = {"conn_rate": 30, "conn_max": 300, "req_rate": 20, "req_burst": 60, "ban": 600, "exempt": []}
        self.nginx("server {\n    limit_req zone=theirs;\n}")
        self.assertEqual(self.firewall(limits=(), flood=flood).layers(), [])
        self.assertIn("limit_req zone=analytics_flood burst=60 nodelay;", self.notes())
        self.assertIn("request limits", self.notes())

    def test_only_our_own_include_is_reported(self):
        self.nginx("server {\n    listen 80;\n}")
        self.assertEqual(self.firewall().layers(), ["nginx-limits"])
        self.assertNotIn("limit_req of its own", self.notes())

    def test_a_commented_out_line_is_reported(self):
        self.nginx("server {\n    # limit_req zone=theirs;\n}")
        self.assertEqual(self.firewall().layers(), ["nginx-limits"])

    def test_a_block_naming_our_zones_as_well_is_reported(self):
        self.nginx(z("server {\n    limit_req zone=theirs;\n    limit_req zone=sg_pl_L burst=9 nodelay;\n"
                     "    limit_req zone=sg_pl_C burst=29 nodelay;\n}"))
        self.assertEqual(self.firewall().layers(), ["nginx-limits"])



FLOOD = {"conn_rate": 30, "conn_max": 300, "req_rate": 20, "req_burst": 60, "ban": 600, "exempt": []}


class TheSitesOwnRefusals(Agent):
    """What the site's own limit_req zones refused: rule `nginx`, never banned,
    and counted whole however many addresses it came from."""

    def rows(self):
        return [(e["ip"], e["rule"], e["action"], e["hits"]) for e in self.sent]

    def test_counted_in_monitor_mode_with_none_of_the_agents_files(self):
        firewall = self.firewall(limits=(), flood=FLOOD, mode="monitor")
        self.assertEqual(self.written, [], "nothing of the agent's in nginx")
        self.limited("collector_browser", "198.18.0.5", times=3)
        self.limited("collector_server", "2001:db8::7")
        self.limited("analytics_flood", "198.18.0.6")  # the agent's: not in place in monitor mode
        self.limited(z("sg_pl_L"), "198.18.0.7")  # a page limit's, taken out
        firewall.tick(1001)
        self.assertEqual(self.rows(), [("198.18.0.5", "nginx", "block", 3), ("2001:db8::7", "nginx", "block", 1)])
        firewall.tick(1001 + agent.BAN_REPORT_AFTER)
        self.assertEqual((self.banned, firewall.bans), ([], {}), "the site's own limit never bans")

    def test_the_busiest_by_address_and_the_rest_as_one_row_per_family(self):
        firewall = self.firewall(limits=(), flood=FLOOD, mode="monitor")
        self.limited("theirs", "198.18.0.1", times=5)
        self.limited("theirs", "198.18.0.2", times=4)
        for n in range(3, 9):
            self.limited("theirs", "198.18.0.%d" % n)
        self.limited("theirs", "2001:db8::1", times=2)
        with mock.patch.object(agent, "ORIGIN_MAX_ROWS", 2):
            firewall.tick(1001)
        self.assertEqual(self.rows(), [("0.0.0.0/0", "nginx", "block", 6), ("::/0", "nginx", "block", 2),
                                       ("198.18.0.1", "nginx", "block", 5), ("198.18.0.2", "nginx", "block", 4)])

    def test_past_the_address_cap_only_counted(self):
        firewall = self.firewall(limits=(), flood=FLOOD, mode="monitor")
        for n in range(1, 5):
            self.limited("theirs", "198.18.0.%d" % n)
        self.limited("theirs", "198.18.0.1")
        with mock.patch.object(agent, "SITE_LIMITED_MAX", 2):
            firewall.tick(1001)
        self.assertEqual(self.rows(), [("0.0.0.0/0", "nginx", "block", 2),
                                       ("198.18.0.1", "nginx", "block", 2), ("198.18.0.2", "nginx", "block", 1)])

    def test_reported_every_flood_read(self):
        firewall = self.firewall(limits=(), flood=FLOOD, mode="monitor")
        self.limited("theirs", "198.18.0.5")
        firewall.tick(1001)
        self.limited("theirs", "198.18.0.5", times=2)
        firewall.tick(1002)
        self.assertEqual(self.rows(), [("198.18.0.5", "nginx", "block", 1)], "kept for the next report")
        firewall.tick(1001 + agent.FLOOD_READ_EVERY)
        self.assertEqual(self.rows()[1:], [("198.18.0.5", "nginx", "block", 2)])

    def test_not_without_flood_protection_or_nginx(self):
        firewall = self.firewall(limits=(), mode="monitor")
        self.limited("theirs", "198.18.0.5")
        firewall.tick(1001)
        self.assertEqual(self.sent, [])
        firewall = self.firewall(limits=(), flood=FLOOD, mode="monitor")
        with mock.patch.object(agent, "nginx_installed", lambda config: False):
            self.limited("theirs", "198.18.0.5")
            firewall.tick(1001)
        self.assertEqual(self.sent, [])

    def test_without_a_kernel_backend_too(self):
        self.config["backend"] = "none"
        firewall = self.firewall(limits=(), flood=FLOOD)
        self.limited("theirs", "198.18.0.5")
        firewall.tick(1001)
        self.assertEqual(self.rows(), [("198.18.0.5", "nginx", "block", 1)])

    def test_a_forged_line_is_not_counted(self):
        firewall = self.firewall(limits=(), flood=FLOOD, mode="monitor")
        with open(self.error_log, "a") as f:
            f.write('2026/11/04 21:20:25 [error] 30#30: *5 open() "/x" failed, client: 198.18.0.66, server: x, '
                    'request: "GET /x HTTP/1.1", referrer: "limiting requests, excess: 1 by zone "theirs", client: 1.2.3.4,"\n')
        firewall.tick(1001)
        self.assertEqual(self.sent, [])


if __name__ == "__main__":
    unittest.main()
