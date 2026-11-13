<?php
// The browser check (sdk/protocols/firewall.md, "Flood protection" →
// "challenge"): a page request without a pass gets a small page whose script
// sets the pass cookie and reloads, instead of the site. It stops cheap floods
// (scripts that don't run JavaScript), not a real browser.
//
// The pass is "<day>.<first 32 hex of HMAC-SHA256(key, "<day>|<who>")>", key
// = HMAC-SHA256("sg-challenge-v1", site secret), valid for its own day and the
// next. `who` is the IPv4 address, or an IPv6 address's /64, so the pass
// needs nothing stored on the server. The shared cases every client runs are
// sdk/protocols/challenge-cases.json (test/ChallengeTest.php).
//
// Used by Firewall::check() as step 8, after the rate limit.

namespace AnalyticsPlatform;

class Challenge
{
    const COOKIE = '__sg_pass';
    const CONTEXT = 'sg-challenge-v1';
    const MAX_AGE = 86400;
    const MAX_SKIP = 200;

    // The `challenge` key of the rules answer, compiled: null when absent
    // (no check), else array('skip' => lower-cased prefixes, 'exempt' =>
    // Firewall::compileList() ranges).
    public static function compile($challenge)
    {
        if (!is_array($challenge)) {
            return null;
        }
        $skip = array();
        foreach (isset($challenge['skip']) && is_array($challenge['skip']) ? $challenge['skip'] : array() as $prefix) {
            if (is_string($prefix) && $prefix !== '' && count($skip) < self::MAX_SKIP) {
                $skip[] = strtolower($prefix);
            }
        }
        return array(
            'skip' => $skip,
            'exempt' => Firewall::compileList(isset($challenge['exempt']) ? $challenge['exempt'] : array()),
        );
    }

    // Whole days since 1970-01-01 UTC.
    public static function day($now = null)
    {
        return (int) floor(($now === null ? time() : $now) / 86400);
    }

    // The address the pass is bound to: IPv4 as itself (an IPv4-mapped IPv6
    // address too), IPv6 as its first four groups, each four lower-case hex
    // digits ("2001:0db8:0000:0001"). "*" stays "*" (the agent's nginx token,
    // which a package never accepts). Null for anything that isn't an address.
    public static function who($ip)
    {
        $ip = trim((string) $ip);
        if ($ip === '*') {
            return '*';
        }
        $bin = @inet_pton($ip);
        if ($bin === false) {
            return null;
        }
        if (strlen($bin) === 16 && substr($bin, 0, 12) === str_repeat("\0", 10) . "\xff\xff") {
            $bin = substr($bin, 12);
        }
        if (strlen($bin) === 4) {
            return inet_ntop($bin);
        }
        return implode(':', str_split(bin2hex(substr($bin, 0, 8)), 4));
    }

    private static function key($secret)
    {
        return hash_hmac('sha256', self::CONTEXT, (string) $secret, true);
    }

    private static function sign($key, $day, $who)
    {
        return $day . '.' . substr(hash_hmac('sha256', $day . '|' . $who, $key), 0, 32);
    }

    // The pass this address gets today; null when the address isn't one.
    public static function token($secret, $ip, $now = null)
    {
        $who = self::who($ip);
        return $who === null ? null : self::sign(self::key($secret), self::day($now), $who);
    }

    // Whether a cookie value is a valid pass for this address: issued today or
    // yesterday, compared in constant time. Never the nginx token (who = "*").
    public static function valid($secret, $ip, $pass, $now = null)
    {
        if (!is_string($pass) || strlen($pass) > 64 || !preg_match('/^(\d{1,10})\.[0-9a-f]{32}$/D', $pass, $m)) {
            return false;
        }
        $who = self::who($ip);
        if ($who === null || $who === '*') {
            return false;
        }
        $day = (int) $m[1];
        $today = self::day($now);
        if ($day !== $today && $day !== $today - 1) {
            return false;
        }
        return hash_equals(self::sign(self::key($secret), $day, $who), $pass);
    }

    // Every pass in a raw Cookie header, at most four, like the Node and
    // Python clients: a browser sends two when a stale one is left on another
    // path, and $_COOKIE keeps only the first, which may be the stale one.
    // Split on "," as well as ";": a server that gets the cookies in two
    // Cookie headers (HTTP/2 allows it) may join them with ", ", and a pass
    // in the second must still count. A pass never holds either.
    public static function cookieValues($header)
    {
        $found = array();
        foreach (preg_split('/[;,]/', (string) $header) as $pair) {
            $parts = explode('=', $pair, 2);
            if (count($parts) === 2 && trim($parts[0]) === self::COOKIE) {
                $found[] = trim(trim($parts[1]), '"');
                if (count($found) === 4) {
                    break;
                }
            }
        }
        return $found;
    }

    // Every Cookie header of a framework's header list (name => value or
    // values, any case), as one: HeaderBag::get() returns only the first.
    public static function cookieHeaderOf(array $headers)
    {
        $parts = array();
        foreach ($headers as $name => $values) {
            if (strtolower((string) $name) === 'cookie') {
                foreach ((array) $values as $value) {
                    $parts[] = (string) $value;
                }
            }
        }
        return implode('; ', $parts);
    }

    // The first pass in a raw Cookie header ('' when there is none). Kept for
    // callers of older versions; cookieValues() is what the firewall checks.
    public static function fromCookieHeader($header)
    {
        $found = self::cookieValues($header);
        return $found ? $found[0] : '';
    }

    // Whether any of the passes (a string or a list of them) is valid.
    public static function anyValid($secret, $ip, $passes, $now = null)
    {
        foreach (array_slice(is_array($passes) ? $passes : array($passes), 0, 4) as $pass) {
            if (self::valid($secret, $ip, $pass, $now)) {
                return true;
            }
        }
        return false;
    }

    // Whether this request gets the check page. $challenge from compile();
    // $goodbots as Firewall::compileList() ranges. The site's `allow` list is
    // the firewall's step 2, so it never gets this far.
    public static function needed($challenge, $secret, $ip, $method, $path, $accept, $pass, $now = null, array $goodbots = array())
    {
        if (!is_array($challenge)) {
            return false;
        }
        $method = strtoupper((string) $method);
        if ($method !== 'GET' && $method !== 'HEAD') {
            return false;
        }
        if (strpos(strtolower((string) $accept), 'text/html') === false) {
            return false;
        }
        $path = strtolower(explode('?', (string) $path, 2)[0]);
        foreach ($challenge['skip'] as $prefix) {
            if (strpos($path, $prefix) === 0) {
                return false;
            }
        }
        $key = Firewall::ipKey($ip);
        if ($key === null || Firewall::inList($challenge['exempt'], $key) || Firewall::inList($goodbots, $key)) {
            return false;
        }
        return !self::anyValid($secret, $ip, $pass, $now);
    }

    // The check page: array('status' => 503, 'headers' => array(name => value),
    // 'body' => html; '' for a HEAD). The script sets the pass and reloads,
    // but only when the cookie reads back (cookies off: it says so instead of
    // reloading forever), and stops after three tries within 60 seconds (an
    // address that changes on every request would otherwise never settle). Secure is
    // added when the page itself is on https, which the browser knows better
    // than a server behind a proxy.
    public static function page($secret, $ip, $method = 'GET', $now = null)
    {
        $nonce = bin2hex(random_bytes(16));
        $headers = array(
            'Content-Type' => 'text/html; charset=utf-8',
            'Cache-Control' => 'no-store',
            'X-Robots-Tag' => 'noindex',
            // Its own policy, so the site's can't block the one inline script.
            'Content-Security-Policy' => "default-src 'none'; script-src 'nonce-" . $nonce . "'; style-src 'nonce-" . $nonce . "'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
        );
        if (strtoupper((string) $method) === 'HEAD') {
            return array('status' => 503, 'headers' => $headers, 'body' => '');
        }
        $token = (string) self::token($secret, $ip, $now);
        $script = '(function(){'
            . 'var c=' . json_encode(self::COOKIE . '=' . $token) . ',m=document.getElementById("m"),s=location.protocol==="https:",r=0,t=Date.now(),k="__sg_tries",l;'
            . 'document.cookie=c+"; Max-Age=' . self::MAX_AGE . '; Path=/; SameSite=Lax"+(s?"; Secure":"");'
            . 'if(("; "+document.cookie+";").indexOf("; "+c+";")<0){m.textContent="Please allow cookies for this site, then reload the page.";return;}'
            // Tries within the last 60 seconds, kept for this tab only
            // (firewall.md); where storage is blocked or full, in a cookie
            // that lasts a minute, so no browser reloads for ever.
            . 'try{l=JSON.parse(sessionStorage.getItem(k)||"[]").filter(function(x){return t-x<60000;});r=l.length;if(r<3){l.push(t);sessionStorage.setItem(k,JSON.stringify(l));}}'
            . 'catch(e){l=/(?:^|; )__sg_tries=([0-9]+)/.exec(document.cookie);r=l?+l[1]:0;if(r<3)document.cookie=k+"="+(r+1)+"; Max-Age=60; Path=/; SameSite=Lax"+(s?"; Secure":"");}'
            . 'if(r>=3){m.textContent="This page couldn\'t be opened because your connection\'s address keeps changing. Please try again in a minute.";return;}'
            . 'location.reload();'
            . '})();';
        $body = '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="robots" content="noindex">'
            . '<meta name="viewport" content="width=device-width,initial-scale=1"><title>Checking your browser</title>'
            . '<style nonce="' . $nonce . '">body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;'
            . 'font:16px/1.5 system-ui,sans-serif;color:#222;background:#fff;text-align:center;padding:0 1em}</style></head>'
            . '<body><main><p id="m">Checking your browser&hellip;</p>'
            . '<noscript><p>Please turn on JavaScript, then reload the page.</p></noscript></main>'
            . '<script nonce="' . $nonce . '">' . $script . '</script></body></html>';
        return array('status' => 503, 'headers' => $headers, 'body' => $body);
    }
}
