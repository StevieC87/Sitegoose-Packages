"""The security headers taken from the platform config, against the cases every
client shares: sdk/protocols/header-cases.json. Only the nine the dashboard can
produce get through, so all the packages add the same ones."""
import json
import os
import unittest

from analytics_platform.core import safe_header

CASES = os.path.join(os.path.dirname(__file__), "..", "..", "protocols", "header-cases.json")


class HeaderCases(unittest.TestCase):
    def test_shared_cases(self):
        with open(CASES, encoding="utf-8") as f:
            cases = json.load(f)["cases"]
        for case in cases:
            value = case["value"] * case.get("repeat", 1)
            with self.subTest(name=case["name"], value=case["value"][:40], repeat=case.get("repeat")):
                self.assertEqual(safe_header([case["name"], value]), case["ok"])

    def test_only_pairs_of_strings(self):
        for pair in (None, "X-Frame-Options", ["X-Frame-Options"], ["X-Frame-Options", 1], ["X-Frame-Options", "DENY", "x"]):
            self.assertFalse(safe_header(pair))


if __name__ == "__main__":
    unittest.main()
