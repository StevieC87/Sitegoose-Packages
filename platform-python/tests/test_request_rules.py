"""The request-rule matcher (virtual patching), against the cases every client
shares: sdk/protocols/request-rules-cases.json. The Node and PHP packages run
the same file, so the matchers decide alike.

    python3 -m unittest discover -s tests
"""
import json
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analytics_platform.request_rules import compile_rules, match_request, safe_pattern  # noqa: E402

CASES = os.path.join(os.path.dirname(__file__), "..", "..", "protocols", "request-rules-cases.json")


class SharedCases(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(CASES) as handle:
            cls.cases = json.load(handle)
        cls.rules = compile_rules({"rules": cls.cases["rules"]})

    def test_every_shared_case_decides_the_same_way(self):
        for request in self.cases["requests"]:
            matched = match_request(self.rules, request["method"], request["target"], request["ua"])
            got = matched["id"] if matched else None
            self.assertEqual(got, request["expect"], "%s: %s %s" % (request["why"], request["method"], request["target"]))

    def test_a_rule_with_nothing_to_match_is_dropped(self):
        self.assertEqual(compile_rules({"rules": [{"id": "empty", "action": "block"}]}), [])

    def test_a_pattern_that_does_not_compile_is_dropped(self):
        rules = compile_rules({"rules": [
            {"id": "bad", "action": "block", "path": {"regex": "(["}},
            {"id": "good", "action": "block", "path": {"exact": ["/shell.php"]}},
        ]})
        self.assertEqual(len(rules), 1)
        self.assertEqual(match_request(rules, "GET", "/shell.php", "")["id"], "good")

    def test_no_rules_no_match(self):
        self.assertIsNone(match_request([], "GET", "/../../etc/passwd", ""))
        self.assertIsNone(match_request(compile_rules(None), "GET", "/../../etc/passwd", ""))
        self.assertIsNone(match_request(compile_rules({"rules": "nonsense"}), "GET", "/x", ""))

    def test_at_most_200_rules(self):
        many = [{"id": "r%d" % i, "action": "monitor", "path": {"exact": ["/%d" % i]}} for i in range(250)]
        self.assertEqual(len(compile_rules({"rules": many})), 200)


class PatternSafety(unittest.TestCase):
    """(a+)+ takes exponential time on input that nearly matches, and `re`
    can't be timed out: the client must refuse the pattern, not match it."""

    def test_a_pattern_that_can_blow_up_is_refused(self):
        for pattern in ("(a+)+b", "(a*)*", "(ab|cd+)+", r"(a)\1", "(?<=x)y", "unbalanced("):
            self.assertFalse(safe_pattern(pattern), pattern)

    def test_the_starter_patterns_are_allowed(self):
        for pattern in (r"/(wp-content/uploads|uploads)/[^?]*\.(php[0-9]?|phtml)$", r"(includes|inc|lib)?/?[^/]*\.php$"):
            self.assertTrue(safe_pattern(pattern), pattern)

    def test_the_shared_pattern_lists_decide_the_same_way(self):
        with open(CASES) as handle:
            patterns = json.load(handle)["patterns"]
        for pattern in patterns["refused"]:
            self.assertFalse(safe_pattern(pattern), pattern)
        for pattern in patterns["allowed"]:
            self.assertTrue(safe_pattern(pattern), pattern)

    def test_an_unsafe_rule_is_dropped_and_matching_stays_quick(self):
        rules = compile_rules({"rules": [
            {"id": "slow", "action": "block", "path": {"regex": "(a+)+b"}},
            {"id": "fine", "action": "block", "path": {"exact": ["/x"]}},
        ]})
        self.assertEqual([rule["id"] for rule in rules], ["fine"])
        started = time.time()
        self.assertIsNone(match_request(rules, "GET", "/" + "a" * 100000 + "!", ""))
        self.assertLess(time.time() - started, 1.0)


class RequestTarget(unittest.TestCase):
    """The rules match the target as sent; frameworks hand over a decoded path."""

    def test_a_decoded_path_is_encoded_again_so_it_is_decoded_once(self):
        from analytics_platform.core import request_target
        # Sent as /a%252e%252e/, which the framework decoded to /a%2e%2e/.
        self.assertEqual(request_target("/a%2e%2e/"), "/a%252e%252e/")
        rules = compile_rules({"rules": [{"id": "dots", "action": "block", "path": {"contains": ["/a../"]}}]})
        self.assertIsNone(match_request(rules, "GET", request_target("/a%2e%2e/"), ""))

    def test_the_query_string_reaches_the_rules(self):
        from analytics_platform.core import request_target
        rules = compile_rules({"rules": [{"id": "sqli", "action": "block", "query": {"contains": ["union select"]}}]})
        target = request_target("/item", "id=1%20union%20select")
        self.assertEqual(target, "/item?id=1%20union%20select")
        self.assertEqual(match_request(rules, "GET", target, "")["id"], "sqli")

    def test_the_servers_own_copy_wins(self):
        from analytics_platform.core import request_target
        self.assertEqual(request_target("/x y", "a=1", b"/x%20y?a=1"), "/x%20y?a=1")
        self.assertEqual(request_target("/x y", "a=1", b"/x%20y"), "/x%20y?a=1")
        self.assertEqual(request_target("/caf\u00e9"), "/caf%C3%A9")


if __name__ == "__main__":
    unittest.main()
