package com.sitegoose.analytics;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Database queries with their values taken out (sdk/protocols/queries.md):
 * the one rule every server package applies before a query leaves the
 * server. A port of expresscollect/Analytics/queryText.js, held to
 * sdk/protocols/query-cases.json character for character, so JavaScript's
 * meaning of whitespace, digits and string length is kept on purpose.
 *
 * <pre>
 * SELECT * FROM users WHERE email = 'a@b.c' AND id IN (1, 2, 3)
 * -&gt; SELECT * FROM users WHERE email = ? AND id IN (?)
 * </pre>
 */
final class QueryText {
    private QueryText() {
    }

    static final int MAX_STATEMENT = 1000;
    static final String OTHER_STATEMENT = "(other)";
    /** The databases a row may name; anything else is "other". */
    static final Set<String> DATABASES = new HashSet<>(Arrays.asList(
            "postgresql", "mysql", "mariadb", "sqlite", "mssql", "oracle", "clickhouse", "mongodb", "redis", "other"));
    private static final int MONGO_DEPTH = 6;

    /** JavaScript's \s: Java's own leaves out no-break and other Unicode spaces. */
    private static final String SPACE = "[\\t\\n\\u000B\\f\\r \\u00A0\\u1680\\u2000-\\u200A\\u2028\\u2029\\u202F\\u205F\\u3000\\uFEFF]";
    private static final String PLACEHOLDER = "(?:\\?|\\$[0-9]+|:[A-Za-z0-9_]+|@[A-Za-z0-9_]+)";
    private static final Pattern LIST = Pattern.compile(
            "\\(" + SPACE + "*" + PLACEHOLDER + "(?:" + SPACE + "*," + SPACE + "*" + PLACEHOLDER + ")*" + SPACE + "*\\)");
    private static final Pattern ROWS = Pattern.compile("\\(\\?\\)(?:" + SPACE + "*," + SPACE + "*\\(\\?\\))+");
    /**
     * Where "..." may hold a value rather than a name: SQLite takes a
     * double-quoted string as a literal when no column has that name
     * (SQLCipher's PRAGMA key = "x'2DD2…'"), Oracle writes a password as a
     * quoted name, and an unknown database may do either. There "..." is kept
     * only when it reads as a plain name, closed: "email", never "x'2D…'",
     * "N3w P@ss" or an unclosed one.
     */
    private static final Set<String> VALUE_QUOTES = new HashSet<>(Arrays.asList("sqlite", "oracle", "other"));
    private static final Pattern NAME = Pattern.compile("\"[A-Za-z_][A-Za-z0-9_$#]{0,127}\"");
    // A password or key written as a name, on any database: Oracle's
    // ALTER USER u IDENTIFIED BY pw and SQLCipher's PRAGMA key = "passphrase".
    // What follows is "?" whether it was a word or a quoted name. JavaScript's
    // \b, as the collector's: before a letter, no ASCII word character. The
    // runs are possessive, which matches the same text here, so a long quoted
    // name doesn't recurse once per character.
    private static final String SECRET_NAME = "(\"(?:[^\"]++|\"\")*+\"?|`(?:[^`]++|``)*+`?|[^;,()" + SPACE.substring(1) + "++)";
    private static final Pattern IDENTIFIED = Pattern.compile("((?<![A-Za-z0-9_])IDENTIFIED BY )" + SECRET_NAME, Pattern.CASE_INSENSITIVE);
    private static final Pattern PRAGMA_KEY = Pattern.compile(
            "((?<![A-Za-z0-9_])PRAGMA (?:[A-Za-z_][A-Za-z0-9_]*\\.)?(?:HEX)?(?:RE)?KEY ?[=(] ?)" + SECRET_NAME, Pattern.CASE_INSENSITIVE);
    // A character no collection name has: where the filter starts.
    private static final Pattern FILTER_START = Pattern.compile("[{}\\[\\]\"']");
    private static final Pattern MONGO = Pattern.compile(
            "(" + "[^" + SPACE.substring(1) + "+)(?: ([^" + SPACE.substring(1) + "+))?(?: ([\\s\\S]*))?");

    static boolean isSpace(char c) {
        switch (c) {
            case '\t':
            case '\n':
            case '\u000B':
            case '\f':
            case '\r':
            case ' ':
            case ' ':
            case ' ':
            case ' ':
            case ' ':
            case ' ':
            case ' ':
            case '　':
            case '﻿':
                return true;
            default:
                return c >= ' ' && c <= ' ';
        }
    }

    private static boolean isDigit(char c) {
        return c >= '0' && c <= '9';
    }

    private static boolean isHex(char c) {
        return isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
    }

    private static boolean isLetter(char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
    }

    /** A digit right after one of these is part of a name or a placeholder (table2, $1, @p1, :1), not a value. */
    private static boolean isWord(char c) {
        return isLetter(c) || isDigit(c) || c == '_' || c == '$' || c == '@' || c == ':';
    }

    /** String.prototype.trim(). */
    static String trim(String text) {
        int start = 0;
        int end = text.length();
        while (start < end && isSpace(text.charAt(start))) {
            start++;
        }
        while (end > start && isSpace(text.charAt(end - 1))) {
            end--;
        }
        return text.substring(start, end);
    }

    /**
     * The end of a quoted run starting at start (the opening quote): after the
     * closing quote, or the text's length. A doubled quote escapes, and a
     * backslash too unless backslash is false.
     */
    private static int quoteEnd(String sql, int start, char quote, boolean backslash) {
        int i = start + 1;
        int n = sql.length();
        while (i < n) {
            char c = sql.charAt(i);
            if (c == '\\' && backslash) {
                i += 2;
            } else if (c == quote) {
                if (i + 1 < n && sql.charAt(i + 1) == quote) {
                    i += 2;
                } else {
                    return i + 1;
                }
            } else {
                i += 1;
            }
        }
        return n;
    }

    /** $tag$ or $$ starting at i (within 64 characters), or null. */
    private static String dollarTag(String sql, int i) {
        int limit = Math.min(sql.length(), i + 64);
        int j = i + 1;
        if (j < limit && (isLetter(sql.charAt(j)) || sql.charAt(j) == '_')) {
            j++;
            while (j < limit && (isLetter(sql.charAt(j)) || isDigit(sql.charAt(j)) || sql.charAt(j) == '_')) {
                j++;
            }
        }
        return j < limit && sql.charAt(j) == '$' ? sql.substring(i, j + 1) : null;
    }

    /** The length of the number at i (0x1F, 12, 1.5, .5, 1., 2e-3), looked for within 400 characters. */
    private static int numberLength(String sql, int i) {
        int limit = Math.min(sql.length(), i + 400);
        if (sql.charAt(i) == '0' && i + 2 < limit && (sql.charAt(i + 1) == 'x' || sql.charAt(i + 1) == 'X') && isHex(sql.charAt(i + 2))) {
            int j = i + 3;
            while (j < limit && isHex(sql.charAt(j))) {
                j++;
            }
            return j - i;
        }
        int j = i;
        if (isDigit(sql.charAt(j))) {
            while (j < limit && isDigit(sql.charAt(j))) {
                j++;
            }
            if (j < limit && sql.charAt(j) == '.') {
                j++;
            }
            while (j < limit && isDigit(sql.charAt(j))) {
                j++;
            }
        } else {
            j++;
            while (j < limit && isDigit(sql.charAt(j))) {
                j++;
            }
        }
        if (j < limit && (sql.charAt(j) == 'e' || sql.charAt(j) == 'E')) {
            int k = j + 1;
            if (k < limit && (sql.charAt(k) == '+' || sql.charAt(k) == '-')) {
                k++;
            }
            if (k < limit && isDigit(sql.charAt(k))) {
                while (k < limit && isDigit(sql.charAt(k))) {
                    k++;
                }
                j = k;
            }
        }
        return j - i;
    }

    /** A string's one-letter prefix (E'..' N'..' X'..' B'..') at the end of out, not part of a longer word. */
    private static boolean endsWithPrefix(StringBuilder out) {
        int n = out.length();
        if (n == 0 || "EeNnXxBb".indexOf(out.charAt(n - 1)) < 0) {
            return false;
        }
        if (n == 1) {
            return true;
        }
        char before = out.charAt(n - 2);
        return !(isLetter(before) || isDigit(before) || before == '_');
    }

    /** E'..' (either case) at the end of out, not part of a longer word: PostgreSQL's escaping string. */
    private static boolean endsWithEscapePrefix(StringBuilder out) {
        int n = out.length();
        if (n == 0 || (out.charAt(n - 1) != 'E' && out.charAt(n - 1) != 'e')) {
            return false;
        }
        return endsWithPrefix(out);
    }

    private static void space(StringBuilder out) {
        if (out.length() > 0 && out.charAt(out.length() - 1) != ' ') {
            out.append(' ');
        }
    }

    private static String sqlShape(String sql, String db) {
        return sqlShape(sql, db, null);
    }

    private static String sqlShape(String sql, String db, Boolean backslashLiteral) {
        boolean mysql = "mysql".equals(db) || "mariadb".equals(db);
        boolean postgres = "postgresql".equals(db);
        // Where a backslash in a string is just a character: PostgreSQL's plain
        // strings (standard_conforming_strings, on since 9.1), SQLite, SQL Server
        // and Oracle. Read as an escape there, 'C:\' ends late and lets what
        // follows out. MySQL, MariaDB, ClickHouse and unknown databases escape.
        boolean literal = backslashLiteral != null
                ? backslashLiteral
                : postgres || "sqlite".equals(db) || "mssql".equals(db) || "oracle".equals(db);
        StringBuilder out = new StringBuilder();
        int n = sql.length();
        int i = 0;
        while (i < n) {
            char c = sql.charAt(i);
            char next = i + 1 < n ? sql.charAt(i + 1) : '\0';
            boolean afterWord = i > 0 && isWord(sql.charAt(i - 1));
            if ((c == '-' && next == '-') || (c == '#' && mysql)) {
                int end = sql.indexOf('\n', i);
                i = end == -1 ? n : end;
                space(out);
            } else if (c == '/' && next == '*') {
                int end = sql.indexOf("*/", i + 2);
                i = end == -1 ? n : end + 2;
                space(out);
            } else if (c == '\'' || (c == '"' && mysql)) {
                // Only PostgreSQL's E'..' escapes with a backslash where it is literal.
                boolean escapes = !literal || (postgres && endsWithEscapePrefix(out));
                if (endsWithPrefix(out)) {
                    out.setLength(out.length() - 1);
                }
                i = quoteEnd(sql, i, c, escapes);
                out.append('?');
            } else if (c == '"' || c == '`') {
                int end = quoteEnd(sql, i, c, !literal);
                String run = sql.substring(i, end);
                out.append(c == '"' && VALUE_QUOTES.contains(db) && !NAME.matcher(run).matches() ? "?" : run);
                i = end;
            } else if (c == '$' && !afterWord && dollarTag(sql, i) != null) {
                String tag = dollarTag(sql, i);
                int end = sql.indexOf(tag, i + tag.length());
                i = end == -1 ? n : end + tag.length();
                out.append('?');
            } else if ((isDigit(c) || (c == '.' && isDigit(next))) && !afterWord) {
                i += numberLength(sql, i);
                out.append('?');
            } else if (isSpace(c)) {
                i += 1;
                space(out);
            } else {
                out.append(c);
                i += 1;
            }
        }
        String shaped = IDENTIFIED.matcher(out).replaceAll("$1?");
        shaped = PRAGMA_KEY.matcher(shaped).replaceAll("$1?");
        shaped = LIST.matcher(shaped).replaceAll("(?)");
        shaped = ROWS.matcher(shaped).replaceAll("(?)");
        return trim(shaped);
    }

    // ---- MongoDB ----

    /** A canonical array index ("0", "17"): JavaScript lists these keys first, in numeric order. */
    private static boolean arrayIndex(String key) {
        int n = key.length();
        if (n == 0 || n > 10 || (n > 1 && key.charAt(0) == '0')) {
            return false;
        }
        for (int i = 0; i < n; i++) {
            if (!isDigit(key.charAt(i))) {
                return false;
            }
        }
        return Long.parseLong(key) < 4294967295L;
    }

    /**
     * A filter or pipeline's shape: keys kept, every value "?", and an array
     * whose items all come out the same kept as one. value: maps, lists and
     * anything else (a value), as parsed JSON or a BSON document holds them.
     */
    static Object mongoShape(Object value, int depth) {
        if (depth >= MONGO_DEPTH || !(value instanceof Map || value instanceof List)) {
            return "?";
        }
        if (value instanceof List) {
            List<Object> items = new ArrayList<>();
            Set<String> seen = new HashSet<>();
            for (Object item : (List<?>) value) {
                Object shaped = mongoShape(item, depth + 1);
                items.add(shaped);
                seen.add(stringify(shaped));
            }
            if (seen.size() == 1) {
                List<Object> one = new ArrayList<>();
                one.add(items.get(0));
                return one;
            }
            return items;
        }
        // Object key order as JavaScript keeps it: array indexes first, in
        // numeric order, then the rest as written; "__proto__" isn't kept.
        Map<Long, Object[]> indexes = new TreeMap<>();
        Map<String, Object> named = new LinkedHashMap<>();
        for (Map.Entry<?, ?> entry : ((Map<?, ?>) value).entrySet()) {
            String key = String.valueOf(entry.getKey());
            if ("__proto__".equals(key)) {
                continue;
            }
            Object shaped = mongoShape(entry.getValue(), depth + 1);
            if (arrayIndex(key)) {
                indexes.put(Long.parseLong(key), new Object[] {key, shaped});
            } else {
                named.put(key, shaped);
            }
        }
        Map<String, Object> out = new LinkedHashMap<>();
        for (Object[] pair : indexes.values()) {
            out.put((String) pair[0], pair[1]);
        }
        out.putAll(named);
        return out;
    }

    /** JSON.stringify for a shape: compact, non-ASCII characters as themselves. */
    static String stringify(Object value) {
        StringBuilder out = new StringBuilder();
        stringify(out, value);
        return out.toString();
    }

    private static void stringify(StringBuilder out, Object value) {
        if (value instanceof Map) {
            out.append('{');
            boolean first = true;
            for (Map.Entry<?, ?> entry : ((Map<?, ?>) value).entrySet()) {
                if (!first) {
                    out.append(',');
                }
                first = false;
                quote(out, String.valueOf(entry.getKey()));
                out.append(':');
                stringify(out, entry.getValue());
            }
            out.append('}');
        } else if (value instanceof List) {
            out.append('[');
            boolean first = true;
            for (Object item : (List<?>) value) {
                if (!first) {
                    out.append(',');
                }
                first = false;
                stringify(out, item);
            }
            out.append(']');
        } else {
            quote(out, String.valueOf(value));
        }
    }

    private static void quote(StringBuilder out, String text) {
        out.append('"');
        int n = text.length();
        for (int i = 0; i < n; i++) {
            char c = text.charAt(i);
            switch (c) {
                case '"':
                    out.append("\\\"");
                    break;
                case '\\':
                    out.append("\\\\");
                    break;
                case '\b':
                    out.append("\\b");
                    break;
                case '\f':
                    out.append("\\f");
                    break;
                case '\n':
                    out.append("\\n");
                    break;
                case '\r':
                    out.append("\\r");
                    break;
                case '\t':
                    out.append("\\t");
                    break;
                default:
                    if (c < 0x20) {
                        out.append(String.format(Locale.ROOT, "\\u%04x", (int) c));
                    } else if (Character.isHighSurrogate(c) && i + 1 < n && Character.isLowSurrogate(text.charAt(i + 1))) {
                        out.append(c).append(text.charAt(i + 1));
                        i++;
                    } else if (Character.isSurrogate(c)) {
                        // A lone half of a pair, escaped as JSON.stringify does.
                        out.append(String.format(Locale.ROOT, "\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
            }
        }
        out.append('"');
    }

    /** "find users {...}": the command, the collection, and the filter's shape (hasFilter false: none; a null filter is JSON null). */
    static String mongoStatement(String command, String collection, Object filter, boolean hasFilter) {
        StringBuilder out = new StringBuilder();
        for (String part : new String[] {command, collection, hasFilter ? stringify(mongoShape(filter, 0)) : null}) {
            if (part != null && !part.isEmpty()) {
                if (out.length() > 0) {
                    out.append(' ');
                }
                out.append(part);
            }
        }
        return out.toString();
    }

    private static String mongoText(String text) {
        Matcher match = MONGO.matcher(trim(text));
        if (!match.matches()) {
            return "";
        }
        String collection = match.group(2);
        String rest = match.group(3);
        // A "collection" with a brace, bracket or quote in it is the filter's start.
        if (collection != null && FILTER_START.matcher(collection).find()) {
            rest = rest == null ? collection : collection + " " + rest;
            collection = null;
        }
        boolean hasFilter = false;
        Object filter = null;
        if (rest != null && !rest.isEmpty()) {
            filter = Json.parse(rest);
            // Json.parse gives null for "null" and for what isn't JSON: only the first is a filter.
            hasFilter = filter != null || "null".equals(rest.replaceAll("^[ \\t\\n\\r]+|[ \\t\\n\\r]+$", ""));
        }
        return mongoStatement(match.group(1), collection, filter, hasFilter);
    }

    // ---- Redis ----
    // The command and its first key's shape, never an argument or value
    // (queries.md, "Redis"). A key keeps each ":" segment that is only letters
    // and "_" (32 at most); every other segment is "?", so IDs, slugs, emails
    // and hashes never leave the server: user:42:cart -> user:?:cart.

    private static final Pattern REDIS_WORD = Pattern.compile("[A-Za-z][A-Za-z0-9_.|-]{0,39}");
    private static final Pattern REDIS_SEGMENT = Pattern.compile("[A-Za-z_]{1,32}");
    private static final Pattern JS_SPACES = Pattern.compile(SPACE + "+");
    // A key count as JavaScript's Number() reads it.
    private static final Pattern JS_HEX = Pattern.compile("0[xX][0-9a-fA-F]+");
    private static final Pattern JS_BINARY = Pattern.compile("0[bB][01]+");
    private static final Pattern JS_OCTAL = Pattern.compile("0[oO][0-7]+");
    private static final Pattern JS_INFINITY = Pattern.compile("[+-]?Infinity");
    private static final Pattern JS_DECIMAL = Pattern.compile("[+-]?(?:[0-9]+\\.?[0-9]*|\\.[0-9]+)(?:[eE][+-]?[0-9]+)?");
    /** Commands whose second word is a subcommand (CLIENT SETNAME, XINFO STREAM). */
    static final Set<String> REDIS_CONTAINERS = new HashSet<>(Arrays.asList("ACL", "CLIENT", "CLUSTER", "COMMAND", "CONFIG", "DEBUG",
            "FUNCTION", "LATENCY", "MEMORY", "MODULE", "OBJECT", "PUBSUB", "SCRIPT", "SLOWLOG", "XGROUP", "XINFO"));
    /** Of those, the ones with a key after the subcommand. */
    static final Set<String> REDIS_SUB_KEY = new HashSet<>(Arrays.asList("OBJECT", "MEMORY", "XGROUP", "XINFO"));
    /** No key: what follows is a password, a message, a number or nothing. */
    static final Set<String> REDIS_NO_KEY = new HashSet<>(Arrays.asList("PING", "ECHO", "INFO", "AUTH", "HELLO", "SELECT", "QUIT", "RESET",
            "MULTI", "EXEC", "DISCARD", "UNWATCH", "DBSIZE", "TIME", "FLUSHDB", "FLUSHALL", "SAVE", "BGSAVE", "BGREWRITEAOF", "LASTSAVE", "SCAN",
            "RANDOMKEY", "SWAPDB", "SHUTDOWN", "ROLE", "REPLICAOF", "SLAVEOF", "READONLY", "READWRITE", "LOLWUT", "FAILOVER", "PSYNC", "SYNC",
            "REPLCONF", "MIGRATE"));
    /** Script calls: script or name, then how many keys, then the keys. */
    static final Set<String> REDIS_SCRIPTS = new HashSet<>(Arrays.asList("EVAL", "EVALSHA", "EVAL_RO", "EVALSHA_RO", "FCALL", "FCALL_RO"));
    /** How many keys first, then the keys. */
    static final Set<String> REDIS_NUMKEYS = new HashSet<>(Arrays.asList("ZUNION", "ZINTER", "ZDIFF", "SINTERCARD", "ZINTERCARD", "LMPOP", "ZMPOP"));
    /**
     * Waiting, not working: a queue worker sits in these for seconds, so
     * timing them would put every idle worker at the top of the slow list.
     */
    static final Set<String> REDIS_WAITING = new HashSet<>(Arrays.asList("BLPOP", "BRPOP", "BRPOPLPUSH", "BLMOVE", "BLMPOP", "BZPOPMIN",
            "BZPOPMAX", "BZMPOP", "WAIT", "WAITAOF", "SUBSCRIBE", "PSUBSCRIBE", "SSUBSCRIBE", "UNSUBSCRIBE", "PUNSUBSCRIBE", "SUNSUBSCRIBE", "MONITOR"));
    private static final Set<String> REDIS_PREFIXES = new HashSet<>(Arrays.asList("PIPELINE", "MULTI"));

    /** a-z only: toUpperCase(Locale.ROOT) would turn "ß" into "SS" and "ı" into "I". */
    static String asciiUpper(String text) {
        char[] out = null;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c >= 'a' && c <= 'z') {
                if (out == null) {
                    out = text.toCharArray();
                }
                out[i] = (char) (c - 32);
            }
        }
        return out == null ? text : new String(out);
    }

    /** user:42:cart -> user:?:cart; anything not a string is "?". */
    static String redisKeyShape(Object key) {
        // An empty key is "?" too: "GET " would come back from the collector as "GET".
        if (!(key instanceof String) || ((String) key).isEmpty()) {
            return "?";
        }
        String[] parts = ((String) key).split(":", -1);
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < parts.length; i++) {
            if (i > 0) {
                out.append(':');
            }
            String part = parts[i];
            out.append(part.isEmpty() || REDIS_SEGMENT.matcher(part).matches() ? part : "?");
        }
        return out.toString();
    }

    private static boolean redisWord(Object value) {
        return value instanceof String && REDIS_WORD.matcher((String) value).matches();
    }

    /** JavaScript's Number(value) &gt; 0, for a key count. */
    static boolean jsPositive(Object value) {
        if (value instanceof Number) {
            return ((Number) value).doubleValue() > 0;
        }
        if (value instanceof Boolean) {
            return (Boolean) value;
        }
        if (!(value instanceof String)) {
            return false;
        }
        String text = trim((String) value);
        try {
            if (JS_HEX.matcher(text).matches()) {
                return new java.math.BigInteger(text.substring(2), 16).signum() > 0;
            }
            if (JS_BINARY.matcher(text).matches()) {
                return new java.math.BigInteger(text.substring(2), 2).signum() > 0;
            }
            if (JS_OCTAL.matcher(text).matches()) {
                return new java.math.BigInteger(text.substring(2), 8).signum() > 0;
            }
            if (JS_INFINITY.matcher(text).matches()) {
                return !text.startsWith("-");
            }
            if (JS_DECIMAL.matcher(text).matches()) {
                return Double.parseDouble(text) > 0;
            }
        } catch (NumberFormatException notANumber) {
            return false;
        }
        return false;
    }

    /**
     * A command as the client sends it (["GET", "user:42"]) -&gt; "GET user:?",
     * or null for one that isn't timed (blocking, or not a command).
     */
    static String redisCommand(List<?> args) {
        if (args == null || args.isEmpty() || !redisWord(args.get(0))) {
            return null;
        }
        String name = asciiUpper((String) args.get(0));
        if (REDIS_WAITING.contains(name)) {
            return null;
        }
        boolean read = "XREAD".equals(name) || "XREADGROUP".equals(name);
        String command = name;
        int key = -1;
        if (REDIS_CONTAINERS.contains(name)) {
            if (args.size() > 1 && redisWord(args.get(1))) {
                command = name + " " + asciiUpper((String) args.get(1));
                // Only after a subcommand: "OBJECT user" would read back as OBJECT USER.
                if (REDIS_SUB_KEY.contains(name)) {
                    key = 2;
                }
            }
        } else if (REDIS_SCRIPTS.contains(name)) {
            if (args.size() > 2 && jsPositive(args.get(2))) {
                key = 3;
            }
        } else if (REDIS_NUMKEYS.contains(name)) {
            if (args.size() > 1 && jsPositive(args.get(1))) {
                key = 2;
            }
        } else if ("BITOP".equals(name)) {
            key = 2;
        } else if (read) {
            // Its options, then STREAMS and the keys. XREADGROUP's group and
            // consumer come first and may be named anything, as may a stream ("block").
            for (int i = "XREADGROUP".equals(name) ? 4 : 1; i < args.size(); i++) {
                String word = args.get(i) instanceof String ? asciiUpper((String) args.get(i)) : "";
                if ("BLOCK".equals(word)) {
                    return null;
                }
                if ("STREAMS".equals(word)) {
                    key = i + 1;
                    break;
                }
            }
        } else if (!REDIS_NO_KEY.contains(name) && !REDIS_PREFIXES.contains(name)) {
            key = 1;
        }
        return key >= 0 && key < args.size() ? command + " " + redisKeyShape(args.get(key)) : command;
    }

    /** A statement a package sent: [PIPELINE|MULTI] COMMAND [SUBCOMMAND] [key]; anything else is (other). */
    private static String redisStatement(String text) {
        String trimmed = trim(text);
        if (trimmed.isEmpty()) {
            return "";
        }
        String[] words = JS_SPACES.split(trimmed);
        List<String> out = new ArrayList<>(4);
        int i = 0;
        if (REDIS_PREFIXES.contains(asciiUpper(words[0])) && words.length > 1) {
            out.add(asciiUpper(words[i++]));
        }
        if (!REDIS_WORD.matcher(words[i]).matches()) {
            return OTHER_STATEMENT;
        }
        String name = asciiUpper(words[i++]);
        if (REDIS_WAITING.contains(name)) {
            return OTHER_STATEMENT;
        }
        out.add(name);
        if (REDIS_CONTAINERS.contains(name) && i < words.length && REDIS_WORD.matcher(words[i]).matches()) {
            out.add(asciiUpper(words[i++]));
        }
        if (i < words.length - 1) {
            return OTHER_STATEMENT;
        }
        if (i < words.length) {
            out.add(redisKeyShape(words[i]));
        }
        return String.join(" ", out);
    }

    /** Cut to MAX_STATEMENT code points (a lone surrogate counts as one), trimmed again when cut. */
    static String cut(String text) {
        if (text.codePointCount(0, text.length()) <= MAX_STATEMENT) {
            return text;
        }
        return trim(text.substring(0, text.offsetByCodePoints(0, MAX_STATEMENT)));
    }

    static String databaseOf(String db) {
        String name = db == null ? "" : db.toLowerCase(Locale.ROOT);
        return DATABASES.contains(name) ? name : "other";
    }

    /** The statement to store, or "" when nothing is left of it. */
    static String normalize(String text, String db) {
        if (text == null) {
            return "";
        }
        if (OTHER_STATEMENT.equals(text)) {
            return text;
        }
        String name = databaseOf(db);
        String shaped;
        if ("mongodb".equals(name)) {
            shaped = mongoText(text);
        } else if ("redis".equals(name)) {
            shaped = redisStatement(text);
        } else if ("other".equals(name) && text.indexOf('\\') >= 0) {
            // A database we don't know may or may not take a backslash as an
            // escape, and each reading leaks what the other hides. When they
            // disagree the query keeps its timing under (other) and its text is
            // left out.
            String escaped = sqlShape(text, name, false);
            shaped = escaped.equals(sqlShape(text, name, true)) ? escaped : OTHER_STATEMENT;
        } else {
            shaped = sqlShape(text, name);
        }
        return cut(shaped);
    }

    /** The statement for a Mongo command whose filter is already in hand (a BSON document as maps and lists). */
    static String normalizeMongo(String command, String collection, Object filter, boolean hasFilter) {
        return cut(mongoStatement(command, collection, filter, hasFilter));
    }

    /** The database a driver names itself ("PostgreSQL", "Microsoft SQL Server"...), as the protocol does. */
    static String databaseOfProduct(String product) {
        String p = product == null ? "" : product.toLowerCase(Locale.ROOT);
        if (p.contains("postgres")) {
            return "postgresql";
        }
        if (p.contains("mariadb")) {
            return "mariadb";
        }
        if (p.contains("mysql")) {
            return "mysql";
        }
        if (p.contains("sqlite")) {
            return "sqlite";
        }
        if (p.contains("sql server") || p.contains("mssql")) {
            return "mssql";
        }
        if (p.contains("oracle")) {
            return "oracle";
        }
        if (p.contains("clickhouse")) {
            return "clickhouse";
        }
        return "other";
    }

    /** The database a JDBC URL names (jdbc:clickhouse:, jdbc:ch:, jdbc:postgresql:...), or "other". */
    static String databaseOfUrl(String url) {
        String u = url == null ? "" : url.toLowerCase(Locale.ROOT);
        if (u.startsWith("jdbc:clickhouse:") || u.startsWith("jdbc:ch:")) {
            return "clickhouse";
        }
        if (u.startsWith("jdbc:sqlserver:")) {
            return "mssql";
        }
        return u.startsWith("jdbc:") ? databaseOfProduct(u.substring(5, Math.max(5, u.indexOf(':', 5)))) : "other";
    }
}
