"""The type a collector answer is served with from the site's own domain,
against the cases every client shares: sdk/protocols/proxy-answer-cases.json."""
import json
import os
import unittest

from analytics_platform.proxy import Proxy, answer_type

CASES = os.path.join(os.path.dirname(__file__), "..", "..", "protocols", "proxy-answer-cases.json")


class ProxyAnswerCases(unittest.TestCase):
    def test_shared_cases(self):
        with open(CASES, encoding="utf-8") as f:
            cases = json.load(f)["cases"]
        for case in cases:
            with self.subTest(type=case["type"]):
                self.assertEqual(answer_type(case["type"]), case["served"])

    def test_nosniff_and_only_cache_and_retry(self):
        upstream = {"Content-Type": "text/html", "Cache-Control": "no-store", "Set-Cookie": "a=b", "Refresh": "0;url=x"}
        self.assertEqual(Proxy._answer_headers(upstream), [
            ("Content-Type", "text/plain; charset=utf-8"), ("X-Content-Type-Options", "nosniff"), ("Cache-Control", "no-store")])


if __name__ == "__main__":
    unittest.main()
