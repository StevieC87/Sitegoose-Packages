"""The browser check (rule `challenge`, sdk/protocols/firewall.md under "Flood
protection"): a GET or HEAD that asks for a page, from an address with no
valid pass, gets a small page instead of the site. Its script sets the pass
cookie and reloads, which a script that doesn't run JavaScript never does.

The pass is <day>.<first 32 hex digits of HMAC-SHA256(key, "<day>|<who>")>,
key = HMAC-SHA256 of "sg-challenge-v1" keyed with the site secret, so any of
the site's servers accepts a pass another one handed out. It counts for its
own day and the next. sdk/protocols/challenge-cases.json holds the cases
every client runs; backend/scripts/challenge-cases.mjs is the reference.
"""
import hashlib
import hmac
import ipaddress
import json
import re
import secrets
import time

COOKIE = "__sg_pass"
MAX_AGE = 86400
_LABEL = b"sg-challenge-v1"
_PASS = re.compile(r"(\d{1,10})\.([0-9a-f]{32})")


def pass_key(secret):
    """The key every pass is signed with, from the site secret."""
    return hmac.new(str(secret or "").encode("utf-8"), _LABEL, hashlib.sha256).digest()


def who(ip):
    """What a pass is bound to: the IPv4 address (an IPv4-mapped IPv6 address
    as IPv4), or an IPv6 address's /64 as four groups of four lower-case hex
    digits. "*" for the agent's nginx (a package never accepts it); None for
    anything that isn't an address."""
    text = str(ip or "").strip()
    if text == "*":
        return "*"
    try:
        address = ipaddress.ip_address(text.split("%")[0])
    except ValueError:
        return None
    if address.version == 6 and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    if address.version == 4:
        return str(address)
    return ":".join(address.exploded.split(":")[:4])


def day_of(now=None):
    """Whole days since 1970-01-01 UTC."""
    return int((time.time() if now is None else now) // 86400)


def _sign(key, day, bound):
    return hmac.new(key, ("%d|%s" % (day, bound)).encode("ascii"), hashlib.sha256).hexdigest()[:32]


def make_pass(key, ip, now=None):
    """Today's pass for this address, or "" when it isn't one."""
    bound = who(ip)
    if bound is None:
        return ""
    day = day_of(now)
    return "%d.%s" % (day, _sign(key, day, bound))


def is_valid(key, ip, value, now=None):
    """True when value is this address's pass for today or yesterday."""
    match = _PASS.fullmatch(str(value or ""))
    bound = who(ip)
    if not match or bound is None or bound == "*":
        return False
    day = int(match.group(1))
    if day not in (day_of(now), day_of(now) - 1):
        return False
    return hmac.compare_digest(match.group(2), _sign(key, day, bound))


def cookie_values(cookie_header, name=COOKIE):
    """Every value the Cookie header carries under name (a browser can send
    two, from different paths); at most four, like the Node client. A server
    that got two Cookie headers may join them with "," (gunicorn) or ", ":
    a cookie value can't hold a comma, so it splits there too."""
    found = []
    for part in re.split(r"[;,]", str(cookie_header or "")):
        key, sep, value = part.strip().partition("=")
        if sep and key.strip() == name:
            found.append(value.strip().strip('"'))
            if len(found) == 4:
                break
    return found


def secure_compare(given, expected):
    """Equal, in time that doesn't depend on where they differ."""
    return hmac.compare_digest(str(given or "").encode("utf-8"), str(expected or "").encode("utf-8"))


def has_pass(key, ip, cookie_header, now=None):
    return any(is_valid(key, ip, value, now) for value in cookie_values(cookie_header))


def compile_skip(entries):
    """The rules' skip prefixes, lower-cased."""
    return tuple(p.lower() for p in entries or [] if isinstance(p, str) and p)[:200]


def asks_for_page(method, target, accept, skip):
    """Conditions 1 to 3: a GET or HEAD, whose Accept asks for text/html, for
    a path (lower-cased, no query string) under none of skip."""
    if str(method or "").upper() not in ("GET", "HEAD"):
        return False
    if "text/html" not in str(accept or "").lower():
        return False
    path = str(target or "").split("?", 1)[0].split("#", 1)[0].lower()
    return not (skip and path.startswith(skip))


_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex"><title>Just a moment</title>
<style nonce="{nonce}">body{{font:16px/1.5 system-ui,sans-serif;margin:0;display:flex;min-height:100vh;align-items:center;justify-content:center;color:#222;background:#fafafa}}main{{max-width:28rem;padding:2rem;text-align:center}}</style>
</head><body><main><p id="m">Checking your browser before you continue&hellip;</p>
<noscript><p>Please turn on JavaScript to continue to this site.</p></noscript></main>
<script nonce="{nonce}">{script}</script>
</body></html>
"""


def script(value):
    """The page's script: sets the pass and reloads, but only when reading the
    cookie back shows it was set (with cookies off it says so instead of
    reloading forever), and at most three times a minute, counted in
    sessionStorage (an address that changes on every request, a pool of exit
    addresses, would otherwise never get a pass that holds and reload for
    ever), or in a __sg_tries cookie lasting a minute where storage is
    blocked or full. Secure only when the browser is on https: it knows, where the
    server behind a proxy can only be told. The same script as the Node and
    PHP clients'."""
    return ('(function(){var n=' + json.dumps(COOKIE) + ',v=' + json.dumps(value) + ',m=document.getElementById("m"),'
            's=location.protocol==="https:";'
            'document.cookie=n+"="+v+"; Max-Age=' + str(MAX_AGE) + '; Path=/; SameSite=Lax"+(s?"; Secure":"");'
            'if((" "+document.cookie+";").indexOf(" "+n+"="+v+";")<0){m.textContent="Please allow cookies for this site, then reload the page.";return;}'
            'var k="__sg_tries",r=0,t;'
            'try{t=JSON.parse(sessionStorage.getItem(k)||"[]").filter(function(x){return Date.now()-x<60000;});r=t.length;if(r<3){t.push(Date.now());sessionStorage.setItem(k,JSON.stringify(t));}}'
            'catch(e){t=/(?:^|; )__sg_tries=([0-9]+)/.exec(document.cookie);r=t?+t[1]:0;if(r<3)document.cookie=k+"="+(r+1)+"; Max-Age=60; Path=/; SameSite=Lax"+(s?"; Secure":"");}'
            'if(r>=3){m.textContent="This page couldn\'t be opened because your connection\'s address keeps changing. Please try again in a minute.";return;}'
            'location.reload();})();')

def page(key, ip, method, now=None):
    """(503, headers, body) for the check page: its own Content-Security-Policy
    with a fresh nonce for its one script, and no body for a HEAD. The script
    marks the cookie Secure when the page itself is https: whatever proxies
    sit in front, that is the one answer that is never wrong."""
    nonce = secrets.token_urlsafe(18)
    headers = [
        ("Content-Type", "text/html; charset=utf-8"),
        ("Cache-Control", "no-store"),
        ("X-Robots-Tag", "noindex"),
        ("Content-Security-Policy",
         "default-src 'none'; script-src 'nonce-%s'; style-src 'nonce-%s'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'" % (nonce, nonce)),
    ]
    if str(method or "").upper() == "HEAD":
        return 503, headers, b""
    body = _PAGE.format(nonce=nonce, script=script(make_pass(key, ip, now)))
    return 503, headers, body.encode("utf-8")
