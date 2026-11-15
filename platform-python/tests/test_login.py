"""login(): a successful login as a user.login audit entry, with the browser
and whether the account is staff, for unusual-login alerts.

    python3 -m unittest discover -s tests
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analytics_platform import create_platform  # noqa: E402


class Request:
    """A Flask-style request: headers and remote_addr."""

    def __init__(self, headers, remote_addr="203.0.113.9"):
        self.headers = headers
        self.remote_addr = remote_addr


def make_platform():
    return create_platform(site_id="a1b2c3d4e5f6a1b2c3d4e5f6", secret="s", endpoint="http://127.0.0.1:9",
                           firewall=False, analytics=False, flags=False, inventory=False, posture=False,
                           proxy=False, maintenance=False, crawlers=False, forms=False, resources=False,
                           headers=False, errors=False, performance=False)


class Login(unittest.TestCase):
    def test_login_sends_user_login_with_the_browser_and_staff(self):
        platform = make_platform()
        try:
            audit = platform._modules["audit"]
            audit.flush = lambda: None  # kept in the queue to read here
            platform.login("ann", staff=True, request=Request({"User-Agent": "Mozilla/5.0 " + "x" * 600}))
            platform.login("bob", user_agent="")
            platform.login("")
            entries = list(audit.queue)
            self.assertEqual([(e["action"], e["actor"], e["actor_ip"]) for e in entries],
                             [("user.login", "ann", "203.0.113.9"), ("user.login", "bob", "")])
            self.assertEqual(entries[0]["details"]["staff"], True)
            self.assertEqual(len(entries[0]["details"]["user_agent"]), 500)
            self.assertEqual(entries[1]["details"], {"staff": False})
        finally:
            platform.close()


if __name__ == "__main__":
    unittest.main()
