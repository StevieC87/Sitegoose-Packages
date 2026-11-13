"""The options read from ANALYTICS_* when they aren't passed, as the Node and
Go packages do: ANALYTICS_SITE_ID, ANALYTICS_SITE_SECRET, ANALYTICS_ENDPOINT,
and optionally ANALYTICS_TRUST_PROXY ("cloudflare" or a number of proxies)
and ANALYTICS_SERVER_NAME. And the ANALYTICS_* lines of a .env file, for
analytics_platform.start and Django: read, never written to os.environ, so
whatever loads the app's own .env files still sets them as it would."""
import os
import re

_LINE = re.compile(r"^\s*(?:export\s+)?(ANALYTICS_[A-Z0-9_]+)\s*=\s*(.*)$")


def options_from(env):
    """{site_id, secret, endpoint, trust_proxy, server_name} found in env."""
    def read(name):
        value = env.get(name)
        return value.strip() if isinstance(value, str) and value.strip() else None

    found = {}
    for option, name in (("site_id", "ANALYTICS_SITE_ID"), ("secret", "ANALYTICS_SITE_SECRET"),
                         ("endpoint", "ANALYTICS_ENDPOINT"), ("server_name", "ANALYTICS_SERVER_NAME")):
        if read(name):
            found[option] = read(name)
    if "endpoint" not in found and read("ANALYTICS_FIREWALL_ENDPOINT"):
        found["endpoint"] = read("ANALYTICS_FIREWALL_ENDPOINT")
    trust = read("ANALYTICS_TRUST_PROXY")
    if trust:
        if trust.lower() == "cloudflare":
            found["trust_proxy"] = "cloudflare"
        elif trust.lower() == "true":
            found["trust_proxy"] = 1
        elif trust.isdigit() and int(trust) > 0:
            found["trust_proxy"] = int(trust)
    return found


def read_dotenv(path):
    """The ANALYTICS_* lines of a .env file as {name: value}; {} without one.
    Not a dotenv: no expansion, and every other line is ignored."""
    try:
        with open(path, encoding="utf-8") as handle:
            text = handle.read()
    except (OSError, UnicodeDecodeError):
        return {}
    found = {}
    for line in text.splitlines():
        match = _LINE.match(line)
        if not match:
            continue
        value = match.group(2).strip()
        quote = value[:1]
        if quote in ("'", '"') and value.find(quote, 1) > 0:
            value = value[1:value.find(quote, 1)]
        else:
            value = re.sub(r"\s+#.*$", "", value)
        found[match.group(1)] = value
    return found


def from_environment(options, dotenv=None):
    """options with what's missing filled from os.environ, then (when given)
    from a .env file's ANALYTICS_* lines."""
    filled = dict(options)
    sources = [options_from(os.environ)]
    if dotenv:
        sources.append(options_from(read_dotenv(dotenv)))
    for source in sources:
        for key, value in source.items():
            if filled.get(key) is None:
                filled[key] = value
    return filled
