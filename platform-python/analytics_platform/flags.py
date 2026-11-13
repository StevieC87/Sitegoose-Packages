"""Feature flags module: turn features of your app on or off from the
dashboard (Site settings -> Server), for everyone, a share of users, or listed
user IDs. is_enabled() answers from memory; the flags come with the module
switches (core), about once a minute.
"""


def bucket(key, user):
    """FNV-1a over "key:user", 0-99: the same as the Node and PHP packages."""
    h = 0x811C9DC5
    for byte in ("%s:%s" % (key, user)).encode("utf-8"):
        h ^= byte
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h % 100


def evaluate(flag, key, user):
    if not flag.get("on"):
        return False
    uid = "" if user is None else str(user)
    if uid and uid in (flag.get("users") or []):
        return True
    rollout = int(flag.get("rollout", 100))
    if rollout >= 100:
        return True
    if rollout <= 0 or not uid:
        return False
    return bucket(key, uid) < rollout


class Flags:
    def __init__(self, core, **_):
        self.core = core

    def is_enabled(self, key, user=None, default=False):
        try:
            flag = self.core.flags().get(key) if self.core.is_on("flags") else None
            return evaluate(flag, key, user) if isinstance(flag, dict) else default
        except Exception:
            return default

    def flush(self):
        pass

    def close(self):
        pass
