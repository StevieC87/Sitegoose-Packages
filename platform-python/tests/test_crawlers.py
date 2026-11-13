"""The crawlers module: which user agents are counted as which crawler, and
how requests are aggregated (sdk/protocols/crawlers.md).

    python3 -m unittest discover -s tests
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analytics_platform.crawlers import Crawlers, detect  # noqa: E402


class FakeCore:
    """A core that keeps what would be sent instead of sending it."""

    valid = False  # no background timer in tests; flush() is called directly

    def __init__(self):
        self.sent = []
        self.on = True

    def is_on(self, _name):
        return self.on

    def log(self, *_args):
        pass

    def send(self, _module, path, body=None):
        self.sent.append((path, body))


class Detect(unittest.TestCase):
    def test_most_specific_name_wins(self):
        self.assertEqual(detect("Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)"), "GPTBot")
        self.assertEqual(detect("Mozilla/5.0 (compatible; ChatGPT-User/1.0; +https://openai.com/bot)"), "ChatGPT-User")
        self.assertEqual(detect("Mozilla/5.0 (compatible; Claude-User/1.0; +claudebot@anthropic.com)"), "Claude-User")
        self.assertEqual(detect("Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)"), "ClaudeBot")
        self.assertEqual(detect("Mozilla/5.0 (compatible; Google-InspectionTool/1.0)"), "Google-InspectionTool")
        self.assertEqual(detect("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"), "Googlebot")

    def test_an_unlisted_crawler_is_still_counted(self):
        self.assertEqual(detect("SomeNewThing-crawler/0.1"), "Other bot")
        self.assertEqual(detect("curl/8.4.0"), "Other bot")

    def test_visitors_are_not_counted(self):
        self.assertEqual(detect("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/130.0 Safari/537.36"), "")
        self.assertEqual(detect(""), "")
        self.assertEqual(detect(None), "")


class Aggregation(unittest.TestCase):
    def test_same_minute_bot_page_and_status_add_up(self):
        core = FakeCore()
        crawlers = Crawlers(core, server_name="web-1")
        crawlers.record("GPTBot", "/pricing", 200, ms=12, size=100, ip="20.0.0.1")
        crawlers.record("GPTBot", "/pricing", 200, ms=8, size=100, ip="20.0.0.1")
        crawlers.record("GPTBot", "/gone", 404, ms=2, size=50, ip="20.0.0.2")
        crawlers.flush()

        self.assertEqual(len(core.sent), 1)
        path, body = core.sent[0]
        self.assertEqual(path, "/events/crawlers")
        self.assertEqual(body["server_name"], "web-1")
        self.assertEqual(len(body["rows"]), 2)
        pricing = next(row for row in body["rows"] if row["path"] == "/pricing")
        self.assertEqual(pricing["count"], 2)
        self.assertEqual(pricing["bytes"], 200)
        self.assertEqual(pricing["sum_ms"], 20)
        self.assertEqual(body["agents"], [{"bot": "GPTBot", "ips": ["20.0.0.1", "20.0.0.2"]}])

    def test_the_query_string_is_left_off(self):
        core = FakeCore()
        crawlers = Crawlers(core)
        crawlers.record("Googlebot", "/blog/a-post?utm_source=x", 200)
        crawlers.flush()
        self.assertEqual(core.sent[0][1]["rows"][0]["path"], "/blog/a-post")

    def test_thousands_of_pages_become_one_row(self):
        core = FakeCore()
        crawlers = Crawlers(core)
        for i in range(400):
            crawlers.record("Bytespider", "/p/%d" % i, 200)
        crawlers.flush()
        rows = core.sent[0][1]["rows"]
        self.assertLessEqual(len(rows), 301)
        self.assertEqual(next(row for row in rows if row["path"] == "(other)")["count"], 100)

    def test_nothing_is_counted_with_the_module_off(self):
        core = FakeCore()
        core.on = False
        crawlers = Crawlers(core)
        crawlers.record("GPTBot", "/pricing", 200)
        crawlers.flush()
        self.assertEqual(core.sent, [])

    def test_middleware_only_counts_crawlers(self):
        core = FakeCore()
        crawlers = Crawlers(core)
        crawlers.middleware("Googlebot/2.1", "/", 200, ms=5, size="1234", ip="66.249.66.1")
        crawlers.middleware("Mozilla/5.0 Chrome/130.0 Safari/537.36", "/", 200, ms=5)
        crawlers.flush()
        rows = core.sent[0][1]["rows"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["bot"], "Googlebot")
        self.assertEqual(rows[0]["bytes"], 1234)


if __name__ == "__main__":
    unittest.main()
