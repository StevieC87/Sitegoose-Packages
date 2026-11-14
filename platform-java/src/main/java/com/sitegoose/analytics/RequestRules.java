package com.sitegoose.analytics;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

/**
 * Request rules (virtual patching; protocol in sdk/protocols/firewall.md):
 * these match the request -- its method, path, query string and user agent --
 * so an attack is turned away before the vulnerable code runs. They arrive
 * with the other rules and are compiled once per fetch.
 *
 * <p>The matching is the same in every package: the shared cases are in
 * sdk/protocols/request-rules-cases.json, run by RequestRulesTest.
 */
public final class RequestRules {
    private RequestRules() {
    }

    static final int MAX_RULES = 200;
    // How much of a part a regex looks at at once: a regex can't be timed out,
    // so a bounded window keeps a bad pattern from being a hung request. The
    // plain matchers cost one pass and read the whole part.
    static final int MAX_TEXT = 2000;
    static final int WINDOW_STEP = 1000;
    static final int MAX_REGEX = 200;
    static final String[] SECTIONS = {"path", "query", "ua"};
    private static final int FLAGS = Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE;
    // Escapes that refer to a group (\1-\9, \k<name>, \g{1}) and \N, \Q: not in the
    // subset every package's engine shares.
    private static final Pattern BACKREFERENCE = Pattern.compile("\\\\[1-9gkNQ]");
    private static final Pattern BOUNDS = Pattern.compile("\\{(\\d*)(,(\\d*))?\\}");
    private static final Pattern ALNUM = Pattern.compile("[a-z0-9]", Pattern.CASE_INSENSITIVE);
    private static final Pattern SLASHES = Pattern.compile("/{2,}");

    static final class Section {
        List<String> exact = Collections.emptyList();
        List<String> prefix = Collections.emptyList();
        List<String> suffix = Collections.emptyList();
        List<String> contains = Collections.emptyList();
        Windowed regex;
    }

    /**
     * A regex searched in windows of MAX_TEXT that start every WINDOW_STEP, to
     * the end of the part, so a match up to WINDOW_STEP long is found wherever
     * it sits. A window's edges aren't the part's: "^" is searched only in the
     * window that starts the part, "$" only in the one that ends it.
     */
    static final class Windowed {
        private static final Pattern TRAILING = Pattern.compile("\\\\*\\$\\z");
        final Pattern regex;
        private final boolean start;
        private final boolean end;

        Windowed(String pattern) {
            regex = Pattern.compile(pattern, FLAGS);
            start = pattern.startsWith("^");
            // "\$" is a dollar sign; "\\$" is a backslash, then the end.
            Matcher trailing = TRAILING.matcher(pattern);
            end = trailing.find() && (trailing.group().length() - 1) % 2 == 0;
        }

        boolean find(String text) {
            if (text.length() <= MAX_TEXT) {
                return regex.matcher(text).find();
            }
            if (start && end) {
                return false;
            }
            if (start) {
                return regex.matcher(text.substring(0, MAX_TEXT)).find();
            }
            // The first start whose window reaches the end of the part.
            int lastFrom = (text.length() - MAX_TEXT + WINDOW_STEP - 1) / WINDOW_STEP * WINDOW_STEP;
            for (int from = end ? lastFrom : 0; from <= lastFrom; from += WINDOW_STEP) {
                if (regex.matcher(text.substring(from, Math.min(text.length(), from + MAX_TEXT))).find()) {
                    return true;
                }
            }
            return false;
        }
    }

    /** A compiled rule. */
    public static final class Rule {
        public final String id;
        public final String action;
        public final long ban;
        final List<String> methods;
        final Map<String, Section> sections = new LinkedHashMap<>();

        Rule(String id, String action, long ban, List<String> methods) {
            this.id = id;
            this.action = action;
            this.ban = ban;
            this.methods = methods;
        }
    }

    /**
     * A pattern can only come from us, but a careless one would be matched
     * against text an attacker chooses, and a regex can't be timed out. So the
     * client checks the shape itself: a repeated group that holds a quantifier
     * or an alternation, backreferences and lookbehind are refused, and so is
     * more than one free repeat, and so is anything outside the regex subset every
     * package's engine shares (named groups, possessives, atomic groups, inline
     * flags, recursion, verbs, comments). The same check as
     * backend/services/firewall/requestRules.js and the Python package.
     */
    public static boolean safePattern(String pattern) {
        if (pattern == null || pattern.isEmpty() || pattern.length() > MAX_REGEX) {
            return false;
        }
        if (BACKREFERENCE.matcher(pattern).find()) {
            return false;
        }
        // Per open group: whether anything in it, nested groups too, repeats or branches.
        List<Boolean> open = new ArrayList<>();
        int i = 0;
        int n = pattern.length();
        boolean quantified = false;
        while (i < n) {
            char c = pattern.charAt(i);
            // A possessive quantifier ("a++", "a*+", "a{2}+"): PCRE, Java and Ruby only.
            if (quantified && c == '+') {
                return false;
            }
            quantified = "*+?}".indexOf(c) >= 0;
            if (c == '\\') {
                i += 2;
                quantified = false;
                continue;
            }
            if (c == '[') {
                // A character class: skipped whole, quantifiers inside it are literals.
                while (i < n && pattern.charAt(i) != ']') {
                    i += pattern.charAt(i) == '\\' ? 2 : 1;
                }
                i += 1;
                quantified = false;
                continue;
            }
            if (c == '(') {
                open.add(false);
                // Groups are a list of what is allowed: plain, "(?:", "(?=", "(?!". Named
                // groups, lookbehind, "(?P", "(?R)", "(?1)", conditionals, atomic groups,
                // inline flags, comments and "(*VERB)" are refused.
                char after = i + 1 < n ? pattern.charAt(i + 1) : 0;
                if (after == '*') {
                    return false;
                }
                if (after == '?') {
                    if (i + 2 >= n || ":=!".indexOf(pattern.charAt(i + 2)) < 0) {
                        return false;
                    }
                    i += 2;
                }
            } else if (c == ')') {
                if (open.isEmpty()) {
                    return false;
                }
                boolean ambiguous = open.remove(open.size() - 1);
                char next = i + 1 < n ? pattern.charAt(i + 1) : 0;
                if (ambiguous && (next == '*' || next == '+' || next == '{')) {
                    return false;
                }
                if (ambiguous && !open.isEmpty()) {
                    open.set(open.size() - 1, true);
                }
            } else if (!open.isEmpty() && "|*+?{".indexOf(c) >= 0) {
                open.set(open.size() - 1, true);
            }
            i += 1;
        }
        return open.isEmpty() && freeRepeats(pattern) <= 1;
    }

    private static String slice(String text, int from, int to) {
        int start = Math.min(from, text.length());
        return text.substring(start, Math.max(start, Math.min(to, text.length())));
    }

    private static String literalAt(String pattern, int i) {
        if (i >= pattern.length()) {
            return null;
        }
        char c = pattern.charAt(i);
        if (c == '\\') {
            String following = slice(pattern, i + 1, i + 2);
            return !following.isEmpty() && !ALNUM.matcher(following).lookingAt() ? following : null;
        }
        return ".[](){}*+?|^$".indexOf(c) >= 0 ? null : String.valueOf(c);
    }

    /**
     * Two repeats that can both take the same text multiply each other's
     * work. A repeat is pinned when the character straight after it is one it
     * can't match ("[^/]+/" ends at the first "/"); any other is free, and a
     * pattern may hold one free repeat.
     */
    static int freeRepeats(String pattern) {
        int free = 0;
        int i = 0;
        int n = pattern.length();
        while (i < n) {
            int start = i;
            char c = pattern.charAt(i);
            if (c == '\\') {
                i += 2;
            } else if (c == '[') {
                i += 1;
                while (i < n && pattern.charAt(i) != ']') {
                    i += pattern.charAt(i) == '\\' ? 2 : 1;
                }
                i += 1;
            } else if (c == '(') {
                i += i + 1 < n && pattern.charAt(i + 1) == '?' ? 3 : 1;
                continue;
            } else if ("|^$".indexOf(c) >= 0) {
                i += 1;
                continue;
            } else {
                i += 1;
            }
            // A group's text can't be tried against one character.
            String atom = c == ')' ? null : slice(pattern, start, i);
            String quantifier = slice(pattern, i, i + 1);
            boolean repeats = "*".equals(quantifier) || "+".equals(quantifier);
            if ("{".equals(quantifier)) {
                Matcher bounds = BOUNDS.matcher(pattern.substring(i));
                if (!bounds.lookingAt()) {
                    continue;
                }
                // "{3}" is one length, not a choice; "{2,}" and "{2,9}" are choices.
                repeats = bounds.group(2) != null && !bounds.group(3).equals(bounds.group(1));
                i += bounds.group(0).length() - 1;
            } else if (!"?".equals(quantifier) && !repeats) {
                continue;
            }
            i += 1;
            if ("?".equals(slice(pattern, i, i + 1))) {
                i += 1;
            }
            if (!repeats) {
                continue;
            }
            String next = literalAt(pattern, i);
            boolean pinned = false;
            if (atom != null && !atom.isEmpty() && next != null) {
                try {
                    pinned = !Pattern.compile("(?:" + atom + ")", FLAGS).matcher(next).matches();
                } catch (PatternSyntaxException notAnAtom) {
                    // Not an atom on its own: free.
                }
            }
            if (!pinned) {
                free += 1;
            }
        }
        return free;
    }

    private static List<String> lower(Object entries, boolean allowEmpty) {
        List<String> out = new ArrayList<>();
        for (String entry : Json.strings(entries)) {
            if (allowEmpty || !entry.isEmpty()) {
                out.add(entry.toLowerCase(Locale.ROOT));
            }
        }
        return out;
    }

    private static Section section(Object given) {
        return section(given, true);
    }

    /** A section, without its regex when regex is false (page limits carry none, so nginx can hold them too). */
    static Section section(Object given, boolean regex) {
        Map<String, Object> data = Json.map(given);
        if (data == null) {
            return null;
        }
        Section out = new Section();
        boolean any = false;
        if (data.get("exact") instanceof List) {
            out.exact = lower(data.get("exact"), true);
            any |= !out.exact.isEmpty();
        }
        if (data.get("prefix") instanceof List) {
            out.prefix = lower(data.get("prefix"), false);
            any |= !out.prefix.isEmpty();
        }
        if (data.get("suffix") instanceof List) {
            out.suffix = lower(data.get("suffix"), false);
            any |= !out.suffix.isEmpty();
        }
        if (data.get("contains") instanceof List) {
            out.contains = lower(data.get("contains"), false);
            any |= !out.contains.isEmpty();
        }
        Object pattern = regex ? data.get("regex") : null;
        if (pattern instanceof String && safePattern((String) pattern)) {
            try {
                out.regex = new Windowed((String) pattern);
                any = true;
            } catch (PatternSyntaxException error) {
                // A pattern we can't compile is dropped; the rule's other parts stay.
            }
        }
        return any ? out : null;
    }

    /** The rules as they will be matched; empty when there are none. */
    public static List<Rule> compile(Object data) {
        Map<String, Object> given = Json.map(data);
        List<Object> list = given == null ? null : Json.list(given.get("rules"));
        List<Rule> rules = new ArrayList<>();
        if (list == null) {
            return rules;
        }
        for (Object item : list.subList(0, Math.min(list.size(), MAX_RULES))) {
            Map<String, Object> rule = Json.map(item);
            if (rule == null || !(rule.get("id") instanceof String) || ((String) rule.get("id")).isEmpty()) {
                continue;
            }
            // We are called before the body is read, so a rule that needs the
            // body is skipped whole rather than matched on the rest of it.
            if (rule.containsKey("body")) {
                continue;
            }
            Object ban = rule.get("ban");
            long seconds = ban instanceof Number && !(ban instanceof Boolean) ? (long) ((Number) ban).doubleValue() : 0;
            List<String> methods = new ArrayList<>();
            for (String method : Json.strings(rule.get("methods"))) {
                methods.add(method.toUpperCase(Locale.ROOT));
            }
            Rule compiled = new Rule((String) rule.get("id"), "block".equals(rule.get("action")) ? "block" : "monitor",
                    Math.max(0, seconds), methods);
            for (String name : SECTIONS) {
                Section part = section(rule.get(name));
                if (part != null) {
                    compiled.sections.put(name, part);
                }
            }
            // A rule with nothing to match would match everything.
            if (compiled.sections.isEmpty()) {
                continue;
            }
            rules.add(compiled);
        }
        return rules;
    }

    /**
     * One pass of URL decoding only, as the protocol says (Python's
     * unquote_plus): "+" is a space, a %XX that isn't one stays as it is, and
     * bytes that aren't UTF-8 become U+FFFD.
     */
    static String decodeOnce(String text) {
        if (text.indexOf('%') < 0 && text.indexOf('+') < 0) {
            return text;
        }
        StringBuilder out = new StringBuilder(text.length());
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        int i = 0;
        while (i < text.length()) {
            char c = text.charAt(i);
            if (c == '%' && i + 2 < text.length()
                    && Ip.hex(text.charAt(i + 1)) >= 0 && Ip.hex(text.charAt(i + 2)) >= 0) {
                bytes.write(Ip.hex(text.charAt(i + 1)) * 16 + Ip.hex(text.charAt(i + 2)));
                i += 3;
                continue;
            }
            if (bytes.size() > 0) {
                out.append(new String(bytes.toByteArray(), StandardCharsets.UTF_8));
                bytes.reset();
            }
            out.append(c == '+' ? ' ' : c);
            i += 1;
        }
        if (bytes.size() > 0) {
            out.append(new String(bytes.toByteArray(), StandardCharsets.UTF_8));
        }
        return out.toString();
    }

    private static String normalizePath(String path) {
        return SLASHES.matcher(path.toLowerCase(Locale.ROOT).replace('\\', '/')).replaceAll("/");
    }

    /**
     * The path as a servlet container or router resolves it: ";..." dropped
     * from each segment (matrix parameters, ;jsessionid), "." and ".."
     * resolved. /actuator;x/env and /a/../actuator/env both reach
     * /actuator/env, so a rule for /actuator/env must see that too.
     */
    static String resolvePath(String path) {
        if (path == null || path.isEmpty()) {
            return path;
        }
        java.util.ArrayDeque<String> kept = new java.util.ArrayDeque<>();
        String[] segments = path.split("/", -1);
        for (int i = 0; i < segments.length; i++) {
            String segment = segments[i];
            int semi = segment.indexOf(';');
            if (semi >= 0) {
                segment = segment.substring(0, semi);
            }
            if (i == 0 && segment.isEmpty()) {
                continue;
            }
            if (segment.equals(".")) {
                continue;
            }
            if (segment.equals("..")) {
                kept.pollLast();
                continue;
            }
            if (segment.isEmpty() && i < segments.length - 1) {
                continue;
            }
            kept.addLast(segment);
        }
        String joined = String.join("/", kept);
        return path.startsWith("/") ? "/" + joined : joined;
    }

    private static boolean hits(Section section, String... candidates) {
        java.util.LinkedHashSet<String> texts = new java.util.LinkedHashSet<>(java.util.Arrays.asList(candidates));
        for (String text : texts) {
            if (section.exact.contains(text)) {
                return true;
            }
            for (String entry : section.prefix) {
                if (text.startsWith(entry)) {
                    return true;
                }
            }
            for (String entry : section.suffix) {
                if (!entry.isEmpty() && text.endsWith(entry)) {
                    return true;
                }
            }
            for (String entry : section.contains) {
                if (!entry.isEmpty() && text.contains(entry)) {
                    return true;
                }
            }
            if (section.regex != null && section.regex.find(text)) {
                return true;
            }
        }
        return false;
    }

    /**
     * A request as the rules see it, prepared once: the raw, decoded and
     * routed path, the raw and decoded query, the user agent. The request
     * rules and the page limits both match against it. A "#" ends the path
     * and the query: every router drops it, so "/login#1" runs /login, and
     * kept it would miss every exact and suffix rule on /login.
     */
    static final class Prepared {
        final String method;
        final String rawPath;
        final String decodedPath;
        /** What the app's router will see; also the page a limit with each "path" counts apart. */
        final String routedPath;
        final String rawQuery;
        final String decodedQuery;
        final String ua;

        Prepared(String method, String target, String userAgent) {
            String full = target == null ? "" : target;
            int hash = full.indexOf('#');
            if (hash >= 0) {
                full = full.substring(0, hash);
            }
            int mark = full.indexOf('?');
            String pathPart = mark == -1 ? full : full.substring(0, mark);
            rawPath = normalizePath(pathPart);
            String query = mark == -1 ? "" : full.substring(mark + 1);
            rawQuery = query.toLowerCase(Locale.ROOT);
            ua = (userAgent == null ? "" : userAgent).toLowerCase(Locale.ROOT);
            decodedPath = normalizePath(decodeOnce(pathPart));
            // What the app's router will see, from the whole path: a hit on any of the three counts.
            routedPath = resolvePath(decodedPath);
            // Lower-cased after decoding: %55NION decodes to "UNION".
            decodedQuery = decodeOnce(query).toLowerCase(Locale.ROOT);
            this.method = method == null ? "" : method.toUpperCase(Locale.ROOT);
        }
    }

    private static final Pattern SCHEME = Pattern.compile("^[a-zA-Z][a-zA-Z0-9+.-]*:");

    /**
     * The request target in origin form, as a server's own URL parser reads
     * one that doesn't start with "/": the scheme dropped, then, after a "//",
     * the authority; a "/" in front of what is left. "http://h/admin?x" is
     * "/admin?x", and "x:/admin" is "/admin" to Puma, gunicorn and Go, so kept
     * as it is it would miss every prefix rule. "*" stays "*".
     */
    static String originForm(String target) {
        if (target == null || target.isEmpty() || target.charAt(0) == '/' || "*".equals(target)) {
            return target;
        }
        String rest = target;
        Matcher scheme = SCHEME.matcher(rest);
        if (scheme.lookingAt()) {
            rest = rest.substring(scheme.end());
            if (rest.startsWith("//")) {
                int end = 2;
                while (end < rest.length() && "/?#".indexOf(rest.charAt(end)) < 0) {
                    end++;
                }
                rest = rest.substring(end);
            }
        }
        return rest.startsWith("/") ? rest : "/" + rest;
    }

    /** True when the request is one of the rule's methods and every section the rule names matches. */
    static boolean matches(Rule rule, Prepared request) {
        if (!rule.methods.isEmpty() && !rule.methods.contains(request.method)) {
            return false;
        }
        Section path = rule.sections.get("path");
        if (path != null && !hits(path, request.rawPath, request.decodedPath, request.routedPath)) {
            return false;
        }
        Section q = rule.sections.get("query");
        if (q != null && !hits(q, request.rawQuery, request.decodedQuery)) {
            return false;
        }
        Section u = rule.sections.get("ua");
        return u == null || hits(u, request.ua, request.ua);
    }

    /**
     * The first rule that matches, or null. target is the request target as
     * the server received it, query string and all.
     */
    public static Rule match(List<Rule> rules, String method, String target, String userAgent) {
        if (rules == null || rules.isEmpty()) {
            return null;
        }
        Prepared request = new Prepared(method, target, userAgent);
        for (Rule rule : rules) {
            if (matches(rule, request)) {
                return rule;
            }
        }
        return null;
    }
}
