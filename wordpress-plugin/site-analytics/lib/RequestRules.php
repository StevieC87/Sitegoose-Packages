<?php
// Request rules (virtual patching; protocol in sdk/protocols/firewall.md):
// the firewall has always matched addresses, these match the request — its
// method, path, query string and user agent — so an attack is turned away
// before the vulnerable code runs. They arrive with the other rules and are
// compiled once per fetch into plain arrays (the Firewall keeps its rules in a
// PHP file, so nothing here may be an object).
//
// The matching is the same in every package: the shared cases are in
// sdk/protocols/request-rules-cases.json, and this class is run against them
// by test/RequestRulesTest.php.

namespace AnalyticsPlatform;

class RequestRules
{
    const MAX_RULES = 200;
    // How much of each part a rule may look at. Patterns come from our rules,
    // but the text comes from whoever is asking, and PCRE can't be timed out
    // here: a bounded slice keeps a bad pattern from being a hung request.
    const MAX_TEXT = 2000;
    const MAX_REGEX = 200;
    // A delimiter a URL pattern can't hold, so a pattern never has to be escaped.
    const DELIM = "\x01";
    private static $sections = array('path', 'query', 'ua');

    // The rules as they will be matched, or an empty array when there are none.
    public static function compile($data)
    {
        $given = isset($data['rules']) && is_array($data['rules']) ? array_slice($data['rules'], 0, self::MAX_RULES) : array();
        $rules = array();
        foreach ($given as $rule) {
            if (!is_array($rule) || empty($rule['id']) || !is_string($rule['id'])) {
                continue;
            }
            // We are called before the body is read, so a rule that needs the
            // body is skipped whole rather than matched on the rest of it.
            if (isset($rule['body'])) {
                continue;
            }
            $compiled = array(
                'id' => $rule['id'],
                'action' => isset($rule['action']) && $rule['action'] === 'block' ? 'block' : 'monitor',
                'ban' => isset($rule['ban']) && (int) $rule['ban'] > 0 ? (int) $rule['ban'] : 0,
                'methods' => array(),
            );
            if (isset($rule['methods']) && is_array($rule['methods'])) {
                foreach ($rule['methods'] as $method) {
                    if (is_string($method) && preg_match('/^[A-Za-z]{1,10}$/D', $method)) {
                        $compiled['methods'][] = strtoupper($method);
                    }
                }
            }
            $sections = 0;
            foreach (self::$sections as $name) {
                $section = self::section(isset($rule[$name]) ? $rule[$name] : null);
                if ($section !== null) {
                    $compiled[$name] = $section;
                    $sections++;
                }
            }
            // A rule with nothing to match would match everything.
            if (!$sections) {
                continue;
            }
            $rules[] = $compiled;
        }
        return $rules;
    }

    // A pattern can only come from us, but a careless one would be matched
    // against text an attacker chooses, in this very request, and PCRE can't be
    // timed out here. So the client checks the shape itself instead of trusting
    // what it was handed. A repeated group that can match the same text more
    // than one way takes exponential time on input that nearly matches: it can
    // when it holds a quantifier ("(a+)+", "(\w\d?)+") or an alternation
    // ("(a|ab)*"), so a group followed by * + or { holds neither. Backreferences
    // and lookbehind are refused too. The same check as the backend's
    // (backend/services/firewall/requestRules.js), freeRepeats included.
    //
    // Group syntax is a list of what is allowed, not of what isn't: only
    // "(?:", "(?=" and "(?!". PCRE has much more than the subset the rules
    // are written in -- recursion and subroutine calls ((?R), (?1), (?&x),
    // \g<1>), named groups and references ((?P<x>, (?<x>, \k<x>, \g{1}),
    // conditionals ((?(1)...)), atomic groups ("(?" then ">"), inline flags
    // ((?i)), comments, verbs ((*SKIP), (*UTF)) and \Q...\E quoting -- and
    // possessive quantifiers (a++, a*+, a?+, {2}+): none of them is in
    // JavaScript, and a call repeated against an alternation is the same
    // blow-up as (a+)+.
    const GROUPS = ':=!';
    // Escapes that refer to a group or change how the rest is read: \1-\9,
    // \g (call or reference), \k (named reference), \Q (quoting).
    const REFERENCE = '/^\\\\[1-9gkQ]/';

    public static function safePattern($pattern)
    {
        if (!is_string($pattern) || $pattern === '' || strlen($pattern) > self::MAX_REGEX) {
            return false;
        }
        // Per open group: whether anything in it, nested groups too, repeats or branches.
        $open = array();
        $length = strlen($pattern);
        // Whether the last thing read was a quantifier (* + ? or a {...}'s
        // closing brace): a + straight after one makes it possessive.
        $quantifier = false;
        for ($i = 0; $i < $length; $i++) {
            $char = $pattern[$i];
            $after = $quantifier;
            $quantifier = strpos('*+?}', $char) !== false;
            if ($char === '+' && $after) {
                return false;
            }
            if ($char === '\\') {
                $quantifier = false;
                if (preg_match(self::REFERENCE, substr($pattern, $i, 2))) {
                    return false;
                }
                $i++;
                continue;
            }
            if ($char === '[') {
                // A character class: skip it whole, quantifiers inside it are literals.
                while ($i < $length && $pattern[$i] !== ']') {
                    $i += $pattern[$i] === '\\' ? 2 : 1;
                }
                continue;
            }
            if ($char === '(') {
                $open[] = false;
                // A verb ((*SKIP)) or a group that starts with a quantifier.
                if (isset($pattern[$i + 1]) && $pattern[$i + 1] === '*') {
                    return false;
                }
                // "(?:", "(?=", "(?!": that ? names the kind of group, it repeats nothing.
                if (isset($pattern[$i + 1]) && $pattern[$i + 1] === '?') {
                    if (!isset($pattern[$i + 2]) || strpos(self::GROUPS, $pattern[$i + 2]) === false) {
                        return false;
                    }
                    $i += 2;
                }
            } elseif ($char === ')') {
                if (!$open) {
                    return false;
                }
                $ambiguous = array_pop($open);
                $next = isset($pattern[$i + 1]) ? $pattern[$i + 1] : '';
                if ($ambiguous && ($next === '*' || $next === '+' || $next === '{')) {
                    return false;
                }
                if ($ambiguous && $open) {
                    $open[count($open) - 1] = true;
                }
            } elseif ($open && strpos('|*+?{', $char) !== false) {
                $open[count($open) - 1] = true;
            }
        }
        return !$open && self::freeRepeats($pattern) <= 1;
    }

    private static function literalAt($pattern, $i)
    {
        if (!isset($pattern[$i])) {
            return null;
        }
        $char = $pattern[$i];
        if ($char === '\\') {
            return isset($pattern[$i + 1]) && !preg_match('/[a-z0-9]/i', $pattern[$i + 1]) ? $pattern[$i + 1] : null;
        }
        return strpos('.[](){}*+?|^$', $char) !== false ? null : $char;
    }

    // Two repeats that can both take the same text multiply each other's work:
    // ".*=.*=.*x" against a query of "=" that never ends in "x" is polynomial,
    // and MAX_TEXT is plenty for that to hang a request. A repeat is pinned
    // when the character straight after it is one it can't match ("[^/]+/"
    // ends at the first "/", once); any other is free, and a pattern may hold
    // one free repeat.
    private static function freeRepeats($pattern)
    {
        $free = 0;
        $length = strlen($pattern);
        for ($i = 0; $i < $length;) {
            $start = $i;
            $char = $pattern[$i];
            if ($char === '\\') {
                $i += 2;
            } elseif ($char === '[') {
                $i++;
                while ($i < $length && $pattern[$i] !== ']') {
                    $i += $pattern[$i] === '\\' ? 2 : 1;
                }
                $i++;
            } elseif ($char === '(') {
                $i += isset($pattern[$i + 1]) && $pattern[$i + 1] === '?' ? 3 : 1;
                continue;
            } elseif ($char === '|' || $char === '^' || $char === '$') {
                $i++;
                continue;
            } else {
                $i++;
            }
            // A group's text can't be tried against one character.
            $atom = $char === ')' ? null : substr($pattern, $start, $i - $start);
            $quantifier = isset($pattern[$i]) ? $pattern[$i] : '';
            $repeats = $quantifier === '*' || $quantifier === '+';
            if ($quantifier === '{') {
                if (!preg_match('/^\{(\d*)(,(\d*))?\}/', substr($pattern, $i), $bounds)) {
                    continue;
                }
                // "{3}" is one length, not a choice; "{2,}" and "{2,9}" are choices.
                $repeats = isset($bounds[2]) && $bounds[2] !== '' && (isset($bounds[3]) ? $bounds[3] : '') !== $bounds[1];
                $i += strlen($bounds[0]) - 1;
            } elseif ($quantifier !== '?' && !$repeats) {
                continue;
            }
            $i++;
            if (isset($pattern[$i]) && $pattern[$i] === '?') {
                $i++;
            }
            if (!$repeats) {
                continue;
            }
            $next = self::literalAt($pattern, $i);
            // Not an atom on its own (preg_match fails): free.
            if ($atom === null || $next === null || @preg_match(self::DELIM . '^(?:' . $atom . ')$' . self::DELIM . 'iD', $next) !== 0) {
                $free++;
            }
        }
        return $free;
    }

    private static function section($section)
    {
        if (!is_array($section)) {
            return null;
        }
        $out = array();
        foreach (array('exact', 'prefix', 'suffix', 'contains') as $matcher) {
            if (!isset($section[$matcher]) || !is_array($section[$matcher])) {
                continue;
            }
            $list = array();
            foreach ($section[$matcher] as $entry) {
                if (is_string($entry) && ($matcher === 'exact' || $entry !== '')) {
                    $list[] = strtolower($entry);
                }
            }
            if ($list) {
                $out[$matcher] = $list;
            }
        }
        if (isset($section['regex']) && self::safePattern($section['regex'])) {
            $pattern = self::DELIM . $section['regex'] . self::DELIM . 'i';
            // A pattern we can't compile is dropped; the rule's other parts stay.
            if (@preg_match($pattern, '') !== false) {
                $out['regex'] = $section['regex'];
            }
        }
        return $out ? $out : null;
    }

    // One pass only, as the protocol says: enough for %2e%2e, and no risk of
    // decoding a visitor's own text into something that looks like an attack.
    private static function decodeOnce($text)
    {
        if (strpos($text, '%') === false && strpos($text, '+') === false) {
            return $text;
        }
        $decoded = @rawurldecode(str_replace('+', ' ', $text));
        return is_string($decoded) ? $decoded : $text;
    }

    private static function normalizePath($path)
    {
        return preg_replace('~/{2,}~', '/', str_replace('\\', '/', strtolower($path)));
    }

    // The path as a router sees it, besides as it was sent: ";params" taken
    // off every segment (Tomcat, Jetty, Spring and others drop them), decoded
    // once, "." and ".." resolved (never above the root), lower-cased, "\"
    // as "/" and "//" as "/". "/x;y/../admin" and "/x/..%2fadmin" reach
    // "/admin", so a rule on "/admin" must see that too.
    public static function routedPath($path)
    {
        $path = preg_replace('~;[^/]*~', '', (string) $path);
        $path = self::normalizePath(self::decodeOnce($path));
        $out = array();
        $segments = explode('/', $path);
        $last = count($segments) - 1;
        foreach ($segments as $i => $segment) {
            if ($segment === '.' || $segment === '..') {
                if ($segment === '..' && count($out) > 1) {
                    array_pop($out);
                }
                // "/a/." and "/a/b/.." end in a folder.
                if ($i === $last) {
                    $out[] = '';
                }
                continue;
            }
            $out[] = $segment;
        }
        $routed = implode('/', $out);
        if ($routed === '' || $routed[0] !== '/') {
            $routed = '/' . ltrim($routed, '/');
        }
        return preg_replace('~/{2,}~', '/', $routed);
    }

    // $texts: the forms of one part (as sent, decoded, as routed); any one
    // that matches is a match.
    private static function hits(array $section, ...$texts)
    {
        foreach (array_unique($texts) as $text) {
            if (isset($section['exact']) && in_array($text, $section['exact'], true)) {
                return true;
            }
            if (isset($section['prefix'])) {
                foreach ($section['prefix'] as $entry) {
                    if (strpos($text, $entry) === 0) {
                        return true;
                    }
                }
            }
            if (isset($section['suffix'])) {
                foreach ($section['suffix'] as $entry) {
                    if ($entry !== '' && substr($text, -strlen($entry)) === $entry) {
                        return true;
                    }
                }
            }
            if (isset($section['contains'])) {
                foreach ($section['contains'] as $entry) {
                    if ($entry !== '' && strpos($text, $entry) !== false) {
                        return true;
                    }
                }
            }
            if (isset($section['regex']) && @preg_match(self::DELIM . $section['regex'] . self::DELIM . 'i', $text) === 1) {
                return true;
            }
        }
        return false;
    }

    // The first rule that matches, or null. $path is the request target as the
    // server received it, query string and all; $prepared, when given, is
    // prepare() of the same request, so the firewall decodes and routes the
    // path once for the request rules and the page limits both.
    public static function matchRequest(array $rules, $method, $path, $userAgent, ?array $prepared = null)
    {
        if (!$rules) {
            return null;
        }
        $request = $prepared !== null ? $prepared : self::prepare($method, $path, $userAgent);
        foreach ($rules as $rule) {
            if (self::matches($rule, $request)) {
                return $rule;
            }
        }
        return null;
    }

    // The request in every form a rule is matched against, worked out once
    // and shared by the request rules and the page limits.
    public static function prepare($method, $path, $userAgent)
    {
        $target = (string) $path;
        $mark = strpos($target, '?');
        $sent = substr($mark === false ? $target : substr($target, 0, $mark), 0, self::MAX_TEXT);
        $rawQuery = strtolower(substr($mark === false ? '' : substr($target, $mark + 1), 0, self::MAX_TEXT));
        return array(
            'method' => strtoupper((string) $method),
            'path' => self::normalizePath($sent),
            'decoded_path' => self::normalizePath(substr(self::decodeOnce($sent), 0, self::MAX_TEXT)),
            'routed' => substr(self::routedPath($sent), 0, self::MAX_TEXT),
            'query' => $rawQuery,
            // Lowered again after decoding: %55NION is UNION, and the patterns are lower case.
            'decoded_query' => strtolower(substr(self::decodeOnce($rawQuery), 0, self::MAX_TEXT)),
            'ua' => strtolower(substr((string) $userAgent, 0, self::MAX_TEXT)),
        );
    }

    // Whether one compiled rule (or page limit) matches a prepare()d request:
    // every section it names, any one entry within a section.
    public static function matches(array $rule, array $request)
    {
        if ($rule['methods'] && !in_array($request['method'], $rule['methods'], true)) {
            return false;
        }
        if (isset($rule['path']) && !self::hits($rule['path'], $request['path'], $request['decoded_path'], $request['routed'])) {
            return false;
        }
        if (isset($rule['query']) && !self::hits($rule['query'], $request['query'], $request['decoded_query'])) {
            return false;
        }
        if (isset($rule['ua']) && !self::hits($rule['ua'], $request['ua'], $request['ua'])) {
            return false;
        }
        return true;
    }

    // ---- Page limits ------------------------------------------------------
    // firewall.md, "Page limits": a cap on one kind of request (the login
    // form, checkout, search) on top of the site-wide rate. Matched like a
    // request rule, but on the method, path and query only and without
    // `regex`, so the server agent's nginx can carry the very same limit.

    const MAX_LIMITS = 50;
    const LIMIT_ID = '/^[a-z][a-z0-9_.-]{1,39}\z/';

    // The limits as they will be counted; an invalid one is left out, the
    // others still apply.
    public static function compileLimits($rules)
    {
        $limits = array();
        foreach (is_array($rules) ? array_slice($rules, 0, self::MAX_LIMITS) : array() as $rule) {
            if (!is_array($rule) || !isset($rule['id']) || !is_string($rule['id']) || !preg_match(self::LIMIT_ID, $rule['id'])) {
                continue;
            }
            $limit = isset($rule['limit']) ? self::whole($rule['limit']) : null;
            $window = isset($rule['window']) ? self::whole($rule['window']) : null;
            if ($limit === null || $limit < 1 || $limit > 100000 || $window === null || $window < 1 || $window > 3600) {
                continue;
            }
            // A kind of `each` this client doesn't know is skipped, not
            // counted as one: lumping every page together would refuse far
            // more than the owner asked for.
            if (isset($rule['each']) && $rule['each'] !== 'path') {
                continue;
            }
            $compiled = array(
                'id' => $rule['id'],
                'action' => isset($rule['action']) && $rule['action'] === 'block' ? 'block' : 'monitor',
                'limit' => $limit,
                'window' => $window,
                'each' => isset($rule['each']),
                'methods' => array(),
            );
            if (isset($rule['methods']) && is_array($rule['methods'])) {
                foreach ($rule['methods'] as $method) {
                    if (is_string($method) && preg_match('/^[A-Za-z]{1,10}$/D', $method)) {
                        $compiled['methods'][] = strtoupper($method);
                    }
                }
            }
            $sections = 0;
            foreach (array('path', 'query') as $name) {
                $given = isset($rule[$name]) && is_array($rule[$name]) ? $rule[$name] : null;
                // No `regex` in a limit: what is left of the section is kept,
                // and a section that was only a pattern is no section at all.
                if ($given !== null) {
                    unset($given['regex']);
                }
                $section = self::section($given);
                if ($section !== null) {
                    $compiled[$name] = $section;
                    $sections++;
                }
            }
            // Nothing to match would count every request on the site.
            if (!$sections) {
                continue;
            }
            $limits[] = $compiled;
        }
        return $limits;
    }

    // A whole number from the rules (JSON may write 60 as 60.0), else null.
    private static function whole($value)
    {
        if (is_int($value)) {
            return $value;
        }
        return is_float($value) && floor($value) === $value && abs($value) < 1e9 ? (int) $value : null;
    }
}
