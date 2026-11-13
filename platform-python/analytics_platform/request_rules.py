"""Request rules (virtual patching; protocol in sdk/protocols/firewall.md):
the firewall has always matched addresses, these match the request -- its
method, path, query string and user agent -- so an attack is turned away
before the vulnerable code runs. They arrive with the other rules and are
compiled once per fetch; matching is plain string work on text we already
have, so it costs nothing per request.

The matching is the same in every package: the shared cases are in
sdk/protocols/request-rules-cases.json, and this module is run against them by
tests/test_request_rules.py.
"""
import re
from urllib.parse import unquote_plus

MAX_RULES = 200
# How much of each part a rule may look at. Patterns come from our rules, but
# the text comes from whoever is asking, and `re` can't be timed out: a bounded
# slice keeps a bad pattern from being a hung request.
MAX_TEXT = 2000
MAX_REGEX = 200
SECTIONS = ("path", "query", "ua")
# The only kinds of group a pattern may open with "(?": non-capturing and lookahead.
GROUPS = (":", "=", "!")
# Escapes that refer to a group (\1-\9, \g, \k), and \N, which isn't in the shared subset.
_REFERENCE = re.compile(r"\\[1-9gkN]")


def _lower_list(entries, allow_empty=False):
    return [e.lower() for e in entries if isinstance(e, str) and (allow_empty or e != "")]


def safe_pattern(pattern):
    """A pattern can only come from us, but a careless one would be matched
    against text an attacker chooses, in this very request, and `re` can't be
    timed out. So the client checks the shape itself instead of trusting what it
    was handed. A repeated group that can match the same text more than one way
    takes exponential time on input that nearly matches; a group can do that
    when it holds a quantifier ("(a+)+", "(\\w\\d?)+") or an alternation
    ("(a|ab)*", "(\\w|\\d)+"), so a group followed by * + or { holds neither.
    Backreferences and lookbehind are refused too. The same check as
    backend/services/firewall/requestRules.js, free repeats included.

    Group syntax is a list of what is allowed, not of what isn't: only "(?:",
    "(?=" and "(?!". Python's `re` has more -- named groups and references
    ("(?P<x>", "(?P=x)"), conditionals ("(?(1)"), atomic groups ("(?>"),
    inline flags ("(?i)"), comments -- and none of it is in the subset every
    package shares. Escapes that refer to a group (\\1-\\9, \\g, \\k) and
    \\N are refused, and so are possessive quantifiers ("a++", "a*+") and
    PCRE's verbs ("(*FAIL)")."""
    if not isinstance(pattern, str) or not pattern or len(pattern) > MAX_REGEX:
        return False
    # Per open group: whether anything in it, nested groups too, repeats or branches.
    open_groups = []
    i = 0
    while i < len(pattern):
        char = pattern[i]
        if char == "\\":
            if _REFERENCE.match(pattern, i):
                return False
            i += 2
            continue
        if char == "[":
            # A character class: skipped whole, quantifiers inside it are literals.
            while i < len(pattern) and pattern[i] != "]":
                i += 2 if pattern[i] == "\\" else 1
            i += 1
            continue
        if char == "(":
            open_groups.append(False)
            # "(?:", "(?=", "(?!": that ? names the kind of group, it repeats nothing.
            # "(*": a PCRE verb ("(*FAIL)"), never in the shared subset.
            if pattern[i + 1:i + 2] == "*":
                return False
            if pattern[i + 1:i + 2] == "?":
                if pattern[i + 2:i + 3] not in GROUPS:
                    return False
                i += 2
        elif char in "*+?" and pattern[i + 1:i + 2] == "+" and i > 0 and pattern[i - 1] != "(":
            return False  # possessive: a++, a*+, a?+
        elif char == "}" and pattern[i + 1:i + 2] == "+" and re.search(r"\{\d*(,\d*)?\Z", pattern[:i]):
            return False  # possessive: a{2,}+
        elif char == ")":
            if not open_groups:
                return False
            ambiguous = open_groups.pop()
            nxt = pattern[i + 1:i + 2]
            if ambiguous and nxt in ("*", "+", "{"):
                return False
            if ambiguous and open_groups:
                open_groups[-1] = True
        elif open_groups and char in "|*+?{":
            open_groups[-1] = True
        i += 1
    return not open_groups and _free_repeats(pattern) <= 1


def _literal_at(pattern, i):
    if i >= len(pattern):
        return None
    char = pattern[i]
    if char == "\\":
        following = pattern[i + 1:i + 2]
        return following if following and not re.match(r"[a-z0-9]", following, re.I) else None
    return None if char in ".[](){}*+?|^$" else char


def _free_repeats(pattern):
    """Two repeats that can both take the same text multiply each other's
    work: ".*=.*=.*x" against a query of "=" that never ends in "x" is
    polynomial, and 2,000 characters is plenty for that to hang a request. A
    repeat is pinned when the character straight after it is one it can't
    match ("[^/]+/" ends at the first "/", once); any other is free, and a
    pattern may hold one free repeat."""
    free = 0
    i = 0
    while i < len(pattern):
        start = i
        char = pattern[i]
        if char == "\\":
            i += 2
        elif char == "[":
            i += 1
            while i < len(pattern) and pattern[i] != "]":
                i += 2 if pattern[i] == "\\" else 1
            i += 1
        elif char == "(":
            i += 3 if pattern[i + 1:i + 2] == "?" else 1
            continue
        elif char in "|^$":
            i += 1
            continue
        else:
            i += 1
        # A group's text can't be tried against one character.
        atom = None if char == ")" else pattern[start:i]
        quantifier = pattern[i:i + 1]
        repeats = quantifier in ("*", "+")
        if quantifier == "{":
            bounds = re.match(r"\{(\d*)(,(\d*))?\}", pattern[i:])
            if not bounds:
                continue
            # "{3}" is one length, not a choice; "{2,}" and "{2,9}" are choices.
            repeats = bounds.group(2) is not None and bounds.group(3) != bounds.group(1)
            i += len(bounds.group(0)) - 1
        elif quantifier != "?" and not repeats:
            continue
        i += 1
        if pattern[i:i + 1] == "?":
            i += 1
        if not repeats:
            continue
        nxt = _literal_at(pattern, i)
        pinned = False
        if atom and nxt is not None:
            try:
                pinned = re.fullmatch("(?:%s)" % atom, nxt, re.IGNORECASE) is None
            except re.error:
                # Not an atom on its own: free.
                pass
        if not pinned:
            free += 1
    return free


def _section(section, regex=True):
    """regex=False for a page limit: those carry no pattern (firewall.md,
    "Page limits"), so the agent's nginx can enforce the same limit."""
    if not isinstance(section, dict):
        return None
    out = {}
    for matcher in ("exact", "prefix", "suffix", "contains"):
        entries = section.get(matcher)
        if not isinstance(entries, list):
            continue
        values = _lower_list(entries, allow_empty=matcher == "exact")
        if values:
            out[matcher] = values
    pattern = section.get("regex") if regex else None
    if safe_pattern(pattern):
        try:
            out["regex"] = re.compile(pattern, re.IGNORECASE)
        except re.error:
            # A pattern we can't compile is dropped; the rule's other parts stay.
            pass
    return out or None


def compile_rules(data):
    """The rules as they will be matched; [] when there are none."""
    given = data.get("rules") if isinstance(data, dict) else None
    rules = []
    for rule in (given if isinstance(given, list) else [])[:MAX_RULES]:
        if not isinstance(rule, dict) or not isinstance(rule.get("id"), str) or not rule["id"]:
            continue
        # We are called before the body is read, so a rule that needs the body
        # is skipped whole rather than matched on the rest of it.
        if "body" in rule:
            continue
        methods = rule.get("methods")
        compiled = {
            "id": rule["id"],
            "action": "block" if rule.get("action") == "block" else "monitor",
            "ban": int(rule["ban"]) if isinstance(rule.get("ban"), (int, float)) and int(rule["ban"]) > 0 else 0,
            "methods": [m.upper() for m in methods if isinstance(m, str)] if isinstance(methods, list) else [],
        }
        sections = 0
        for name in SECTIONS:
            section = _section(rule.get(name))
            if section is not None:
                compiled[name] = section
                sections += 1
        # A rule with nothing to match would match everything.
        if not sections:
            continue
        rules.append(compiled)
    return rules


def _decode_once(text):
    """One pass only, as the protocol says: enough for %2e%2e, and no risk of
    decoding a visitor's own text into something that looks like an attack."""
    if "%" not in text and "+" not in text:
        return text
    try:
        return unquote_plus(text)
    except Exception:
        return text


def _normalize_path(path):
    return re.sub(r"/{2,}", "/", path.lower().replace("\\", "/"))


def _router_path(path):
    """The path as a router reads it: ";params" dropped from each segment
    (Tomcat, Jetty and some proxies do; "/x;y/../admin" is "/admin" to them),
    decoded once, "\\" as "/", "//" as "/", and "." and ".." resolved (never
    above the root), lower-cased."""
    text = _normalize_path(_decode_once(re.sub(r";[^/]*", "", path)))
    parts = []
    segments = text.split("/")
    for index, segment in enumerate(segments):
        if segment == "..":
            if len(parts) > 1:
                parts.pop()
        elif segment != "." and (segment or index == 0):
            parts.append(segment)
    resolved = "/".join(parts)
    if segments[-1] in ("", ".", "..") and len(segments) > 1 and not resolved.endswith("/"):
        resolved += "/"
    if text.startswith("/") and not resolved.startswith("/"):
        resolved = "/" + resolved
    return resolved


def normalize_target(target):
    """The path of a request target (no query string) as the router reads it:
    what the probes, the static-file check and the rules' path also match."""
    text = str(target or "")
    return _router_path(re.split(r"[?#]", text, 1)[0][:MAX_TEXT])[:MAX_TEXT]


def _hits(section, raw, decoded, routed=None):
    texts = [raw]
    for text in (decoded, routed):
        if text is not None and text not in texts:
            texts.append(text)
    for text in texts:
        if text in section.get("exact", ()):
            return True
        if any(text.startswith(entry) for entry in section.get("prefix", ())):
            return True
        if any(entry and text.endswith(entry) for entry in section.get("suffix", ())):
            return True
        if any(entry and entry in text for entry in section.get("contains", ())):
            return True
        regex = section.get("regex")
        if regex is not None and regex.search(text):
            return True
    return False


def prepare(method="", path="", user_agent=""):
    """The request as every rule and page limit reads it, worked out once.
    `path` is the request target as the server received it, query string and
    all. The firewall prepares a request once and hands the result to both
    match_request and match_limits, so the path is decoded and routed once."""
    target = str(path or "")
    mark = target.find("?")
    bare = (target if mark == -1 else target[:mark])[:MAX_TEXT]
    query = ("" if mark == -1 else target[mark + 1:])[:MAX_TEXT]
    return {
        "method": str(method or "").upper(),
        "raw_path": _normalize_path(bare),
        "decoded_path": _normalize_path(_decode_once(bare)[:MAX_TEXT]),
        # And as the router reads it: "/x;y/../admin" is "/admin" there, so a
        # rule on "/admin" catches it; a hit on any of the three counts.
        "routed_path": _router_path(bare)[:MAX_TEXT],
        "raw_query": query.lower(),
        # Lower-cased after decoding: %55NION decodes to "UNION", which a
        # lower-cased "union select" rule would otherwise never see.
        "decoded_query": _decode_once(query)[:MAX_TEXT].lower(),
        "ua": str(user_agent or "")[:MAX_TEXT].lower(),
    }


def _matches(rule, request):
    if rule["methods"] and request["method"] not in rule["methods"]:
        return False
    if "path" in rule and not _hits(rule["path"], request["raw_path"], request["decoded_path"], request["routed_path"]):
        return False
    if "query" in rule and not _hits(rule["query"], request["raw_query"], request["decoded_query"]):
        return False
    if "ua" in rule and not _hits(rule["ua"], request["ua"], request["ua"]):
        return False
    return True


def match_request(rules, method="", path="", user_agent="", prepared=None):
    """The first rule that matches, or None. `path` is the request target as
    the server received it, query string and all; prepared, when given, is
    prepare() of the same request and is read instead."""
    if not rules:
        return None
    request = prepared or prepare(method, path, user_agent)
    for rule in rules:
        if _matches(rule, request):
            return rule
    return None


# Page limits (firewall.md, "Page limits"): matched as a request rule is, but
# every one that matches counts, not just the first.
MAX_LIMITS = 50
LIMIT_ID = re.compile(r"[a-z][a-z0-9_.-]{1,39}\Z")


def _whole(value, low, high):
    """An integer in low..high (a JSON 10.0 counts as 10), else None."""
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value != int(value):
        return None
    value = int(value)
    return value if low <= value <= high else None


def compile_limits(data):
    """The page limits as they will be matched; [] when there are none. One
    that is malformed is left out on its own, the others stay."""
    given = data.get("rules") if isinstance(data, dict) else None
    limits = []
    for limit in given if isinstance(given, list) else []:
        if len(limits) >= MAX_LIMITS:
            break
        if not isinstance(limit, dict) or not isinstance(limit.get("id"), str) or not LIMIT_ID.match(limit["id"]):
            continue
        count, window = _whole(limit.get("limit"), 1, 100000), _whole(limit.get("window"), 1, 3600)
        if count is None or window is None:
            continue
        methods = limit.get("methods")
        compiled = {
            "id": limit["id"],
            "action": "block" if limit.get("action") == "block" else "monitor",
            "limit": count,
            "window": window,
            "methods": [m.upper() for m in methods if isinstance(m, str)] if isinstance(methods, list) else [],
            "each": limit.get("each") == "path",
        }
        for name in ("path", "query"):
            section = _section(limit.get(name), regex=False)
            if section is not None:
                compiled[name] = section
        # Neither path nor query (or a regex only, which a limit doesn't
        # read) would put every request on the site under one count.
        if "path" not in compiled and "query" not in compiled:
            continue
        limits.append(compiled)
    return limits


def match_limits(limits, method="", path="", prepared=None):
    """(every limit that matches, in the order sent; the routed path, for
    the limits counted per page). prepared, when given, is prepare() of the
    same request, as for match_request."""
    if not limits:
        return [], ""
    request = prepared or prepare(method, path)
    return [limit for limit in limits if _matches(limit, request)], request["routed_path"]
