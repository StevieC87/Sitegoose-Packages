using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace SiteGoose;

/// <summary>Database queries with their values taken out (sdk/protocols/queries.md),
/// before a query is counted, so no value ever leaves the server. A port of
/// expresscollect/Analytics/queryText.js, character for character: its
/// whitespace, digits and word characters are JavaScript's, its lengths
/// are code points, and a Mongo filter comes out as JSON.stringify writes it.
///
///   SELECT * FROM users WHERE email = 'a@b.c' AND id IN (1, 2, 3)
///   -> SELECT * FROM users WHERE email = ? AND id IN (?)</summary>
internal static class QueryText
{
    public const int MaxStatement = 1000;
    public const string Other = "(other)";

    // The databases a row may name; anything else is "other".
    public static readonly HashSet<string> Databases = new(StringComparer.Ordinal)
    {
        "postgresql", "mysql", "mariadb", "sqlite", "mssql", "oracle", "clickhouse", "mongodb", "redis", "other",
    };

    // JavaScript's \s: WhiteSpace and LineTerminator.
    private const string Space = @"\u0009\u000A\u000B\u000C\u000D\u0020\u00A0\u1680\u2000-\u200A\u2028\u2029\u202F\u205F\u3000\uFEFF";
    private const string Placeholder = @"(?:\?|\$[0-9]+|:[A-Za-z0-9_]+|@[A-Za-z0-9_]+)";
    private static readonly Regex Number = new(@"^(?:0[xX][0-9a-fA-F]+|(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]+)?)", RegexOptions.CultureInvariant);
    private static readonly Regex DollarTag = new(@"^\$([A-Za-z_][A-Za-z0-9_]*)?\$", RegexOptions.CultureInvariant);
    private static readonly Regex List = new(@"\([" + Space + "]*" + Placeholder + "(?:[" + Space + "]*,[" + Space + "]*" + Placeholder + ")*[" + Space + @"]*\)", RegexOptions.CultureInvariant);
    private static readonly Regex Rows = new(@"\(\?\)(?:[" + Space + "]*,[" + Space + @"]*\(\?\))+", RegexOptions.CultureInvariant);
    // Where "..." may hold a value rather than a name: SQLite takes a
    // double-quoted string as a literal when no column has that name (SQLCipher's
    // PRAGMA key = "x'2DD2…'"), Oracle writes a password as a quoted name, and an
    // unknown database may do either. There "..." is kept only when it reads as a
    // plain name, closed: "email", never "x'2D…'", "N3w P@ss" or an unclosed one.
    private static readonly HashSet<string> ValueQuotes = new(StringComparer.Ordinal) { "sqlite", "oracle", "other" };
    private static readonly Regex Name = new(@"^""[A-Za-z_][A-Za-z0-9_$#]{0,127}""\z", RegexOptions.CultureInvariant);
    // A password or key written as a name, on any database: Oracle's
    // ALTER USER u IDENTIFIED BY pw and SQLCipher's PRAGMA key = "passphrase".
    // What follows is "?" whether it was a word or a quoted name. JavaScript's
    // \b and /i are ASCII; .NET's IgnoreCase would also take the Kelvin sign
    // for a k, so each letter is spelt out in both cases.
    private const string SecretName = @"(""(?:[^""]|"""")*""?|`(?:[^`]|``)*`?|[^" + Space + @";,()]+)";
    private const string WordStart = "(?<![A-Za-z0-9_])";
    private static readonly Regex Identified = new("(" + WordStart + AnyCase("IDENTIFIED BY ") + ")" + SecretName, RegexOptions.CultureInvariant);
    private static readonly Regex PragmaKey = new("(" + WordStart + AnyCase("PRAGMA ") + "(?:[A-Za-z_][A-Za-z0-9_]*\\.)?(?:" + AnyCase("HEX") + ")?(?:" + AnyCase("RE") + ")?"
        + AnyCase("KEY") + " ?[=(] ?)" + SecretName, RegexOptions.CultureInvariant);
    private static readonly Regex Mongo = new(@"^([^" + Space + "]+)(?: ([^" + Space + @"]+))?(?: ([\s\S]*))?\z", RegexOptions.CultureInvariant);

    private static string AnyCase(string word)
    {
        var pattern = new StringBuilder(word.Length * 4);
        foreach (var c in word)
        {
            if (c >= 'A' && c <= 'Z') pattern.Append('[').Append(c).Append((char)(c + 32)).Append(']');
            else pattern.Append(c);
        }
        return pattern.ToString();
    }

    internal static bool IsSpace(char c) => c switch
    {
        '\u0009' or '\u000A' or '\u000B' or '\u000C' or '\u000D' or '\u0020' or '\u00A0' or '\u1680' or '\u2028' or '\u2029' or '\u202F' or '\u205F' or '\u3000' or '\uFEFF' => true,
        _ => c >= '\u2000' && c <= '\u200A',
    };

    private static bool IsDigit(char c) => c >= '0' && c <= '9';

    private static bool IsLetterOrDigit(char c) => (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || IsDigit(c) || c == '_';

    // A digit right after one of these is part of a name or a placeholder
    // (table2, $1, @p1, :1), not a value. ASCII only, in every package.
    private static bool IsWord(char c) => IsLetterOrDigit(c) || c == '$' || c == '@' || c == ':';

    /// <summary>JavaScript's String.prototype.trim.</summary>
    internal static string Trim(string text)
    {
        var start = 0;
        var end = text.Length;
        while (start < end && IsSpace(text[start])) start++;
        while (end > start && IsSpace(text[end - 1])) end--;
        return start == 0 && end == text.Length ? text : text.Substring(start, end - start);
    }

    public static string DatabaseOf(string? db)
    {
        var name = (db ?? "").ToLowerInvariant();
        return Databases.Contains(name) ? name : "other";
    }

    /// <summary>The statement to store, or "" when nothing is left of it.</summary>
    public static string Normalize(string? text, string? db)
    {
        if (text == null) return "";
        if (text == Other) return text;
        var database = DatabaseOf(db);
        string shaped;
        if (database == "mongodb") shaped = MongoStatement(text);
        else if (database == "redis") shaped = RedisStatement(text);
        else if (database == "other" && text.IndexOf('\\') >= 0)
        {
            // A database we don't know may or may not take a backslash as an
            // escape, and each reading leaks what the other hides. When they
            // disagree the query keeps its timing under (other) and its text is
            // left out.
            var escaped = SqlShape(text, database, false);
            shaped = escaped == SqlShape(text, database, true) ? escaped : Other;
        }
        else shaped = SqlShape(text, database);
        return Cut(shaped);
    }

    // ---- Redis ----
    // The command and its first key's shape, never an argument or value
    // (queries.md, "Redis"). A key keeps each ":" segment that is only letters
    // and "_" (32 at most); every other segment is "?", so IDs, slugs, emails
    // and hashes never leave the server: user:42:cart -> user:?:cart.

    private static readonly Regex RedisWord = new(@"^[A-Za-z][A-Za-z0-9_.|-]{0,39}\z", RegexOptions.CultureInvariant);
    private static readonly Regex RedisSegment = new(@"^[A-Za-z_]{1,32}\z", RegexOptions.CultureInvariant);
    private static readonly Regex Spaces = new("[" + Space + "]+", RegexOptions.CultureInvariant);
    // A key count as JavaScript's Number() reads it.
    private static readonly Regex JsDecimal = new(@"^[+-]?(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]+)?\z", RegexOptions.CultureInvariant);
    private static readonly Regex JsRadix = new(@"^0(?:[xX][0-9a-fA-F]+|[bB][01]+|[oO][0-7]+)\z", RegexOptions.CultureInvariant);
    private static readonly Regex JsInfinity = new(@"^[+-]?Infinity\z", RegexOptions.CultureInvariant);
    private static readonly char[] JsNonzeroDigits = "123456789abcdefABCDEF".ToCharArray();

    // Commands whose second word is a subcommand (CLIENT SETNAME, XINFO STREAM).
    private static readonly HashSet<string> RedisContainers = new(StringComparer.Ordinal)
    {
        "ACL", "CLIENT", "CLUSTER", "COMMAND", "CONFIG", "DEBUG", "FUNCTION", "LATENCY", "MEMORY", "MODULE", "OBJECT", "PUBSUB", "SCRIPT", "SLOWLOG", "XGROUP", "XINFO",
    };
    // Of those, the ones with a key after the subcommand.
    private static readonly HashSet<string> RedisSubKey = new(StringComparer.Ordinal) { "OBJECT", "MEMORY", "XGROUP", "XINFO" };
    // No key: what follows is a password, a message, a number or nothing.
    private static readonly HashSet<string> RedisNoKey = new(StringComparer.Ordinal)
    {
        "PING", "ECHO", "INFO", "AUTH", "HELLO", "SELECT", "QUIT", "RESET", "MULTI", "EXEC", "DISCARD", "UNWATCH", "DBSIZE", "TIME", "FLUSHDB",
        "FLUSHALL", "SAVE", "BGSAVE", "BGREWRITEAOF", "LASTSAVE", "SCAN", "RANDOMKEY", "SWAPDB", "SHUTDOWN", "ROLE", "REPLICAOF", "SLAVEOF",
        "READONLY", "READWRITE", "LOLWUT", "FAILOVER", "PSYNC", "SYNC", "REPLCONF", "MIGRATE",
    };
    // Script calls: script or name, then how many keys, then the keys.
    private static readonly HashSet<string> RedisScripts = new(StringComparer.Ordinal) { "EVAL", "EVALSHA", "EVAL_RO", "EVALSHA_RO", "FCALL", "FCALL_RO" };
    // How many keys first, then the keys.
    private static readonly HashSet<string> RedisNumKeys = new(StringComparer.Ordinal) { "ZUNION", "ZINTER", "ZDIFF", "SINTERCARD", "ZINTERCARD", "LMPOP", "ZMPOP" };
    // Waiting, not working: a queue worker sits in these for seconds, so timing
    // them would put every idle worker at the top of the slow list.
    private static readonly HashSet<string> RedisWaiting = new(StringComparer.Ordinal)
    {
        "BLPOP", "BRPOP", "BRPOPLPUSH", "BLMOVE", "BLMPOP", "BZPOPMIN", "BZPOPMAX", "BZMPOP", "WAIT", "WAITAOF", "SUBSCRIBE", "PSUBSCRIBE",
        "SSUBSCRIBE", "UNSUBSCRIBE", "PUNSUBSCRIBE", "SUNSUBSCRIBE", "MONITOR",
    };
    private static readonly HashSet<string> RedisPrefixes = new(StringComparer.Ordinal) { "PIPELINE", "MULTI" };

    // a-z only: ToUpperInvariant would make "ı" an "I" and leave "ß" alone in one runtime and not another.
    internal static string AsciiUpper(string text)
    {
        char[]? output = null;
        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];
            if (c >= 'a' && c <= 'z')
            {
                output ??= text.ToCharArray();
                output[i] = (char)(c - 32);
            }
        }
        return output == null ? text : new string(output);
    }

    /// <summary>user:42:cart -> user:?:cart; anything not a string is "?".</summary>
    internal static string RedisKeyShape(object? key)
    {
        // An empty key is "?" too: "GET " would come back from the collector as "GET".
        if (key is not string text || text.Length == 0) return "?";
        var parts = text.Split(':');
        for (var i = 0; i < parts.Length; i++)
        {
            if (parts[i].Length > 0 && !RedisSegment.IsMatch(parts[i])) parts[i] = "?";
        }
        return string.Join(":", parts);
    }

    private static bool IsRedisWord(object? value) => value is string text && RedisWord.IsMatch(text);

    // JavaScript's Number(value) > 0, for a key count.
    private static bool JsPositive(object? value)
    {
        switch (value)
        {
            case bool b:
                return b;
            case string text:
                text = Trim(text);
                // 0x.., 0b.., 0o..: above zero when any digit isn't 0.
                if (JsRadix.IsMatch(text)) return text.IndexOfAny(JsNonzeroDigits, 2) >= 0;
                if (JsInfinity.IsMatch(text)) return text[0] != '-';
                return JsDecimal.IsMatch(text) && double.TryParse(text, NumberStyles.Float, CultureInfo.InvariantCulture, out var number) && number > 0;
            case null:
                return false;
            case IConvertible convertible when value is not char:
                try
                {
                    return convertible.ToDouble(CultureInfo.InvariantCulture) > 0;
                }
                catch (Exception)
                {
                    return false;
                }
            default:
                return false;
        }
    }

    /// <summary>A command as the client sends it (["GET", "user:42"]) -> "GET user:?",
    /// or null for one that isn't timed (blocking, or not a command).</summary>
    internal static string? RedisCommand(IReadOnlyList<object?>? args)
    {
        if (args == null || args.Count == 0 || !IsRedisWord(args[0])) return null;
        var name = AsciiUpper((string)args[0]!);
        if (RedisWaiting.Contains(name)) return null;
        var read = name == "XREAD" || name == "XREADGROUP";
        var command = name;
        var key = -1;
        if (RedisContainers.Contains(name))
        {
            if (args.Count > 1 && IsRedisWord(args[1]))
            {
                command = name + " " + AsciiUpper((string)args[1]!);
                // Only after a subcommand: "OBJECT user" would read back as OBJECT USER.
                if (RedisSubKey.Contains(name)) key = 2;
            }
        }
        else if (RedisScripts.Contains(name))
        {
            if (args.Count > 2 && JsPositive(args[2])) key = 3;
        }
        else if (RedisNumKeys.Contains(name))
        {
            if (args.Count > 1 && JsPositive(args[1])) key = 2;
        }
        else if (name == "BITOP") key = 2;
        else if (read)
        {
            // Its options, then STREAMS and the keys. XREADGROUP's group and consumer
            // come first and may be named anything, as may a stream ("block").
            for (var i = name == "XREADGROUP" ? 4 : 1; i < args.Count; i++)
            {
                var word = args[i] is string text ? AsciiUpper(text) : "";
                if (word == "BLOCK") return null;
                if (word == "STREAMS")
                {
                    key = i + 1;
                    break;
                }
            }
        }
        else if (!RedisNoKey.Contains(name) && !RedisPrefixes.Contains(name)) key = 1;
        return key >= 0 && key < args.Count ? command + " " + RedisKeyShape(args[key]) : command;
    }

    // A statement a package sent: [PIPELINE|MULTI] COMMAND [SUBCOMMAND] [key].
    // Anything else (an argument a package let through) is (other).
    private static string RedisStatement(string text)
    {
        var trimmed = Trim(text);
        if (trimmed.Length == 0) return "";
        var words = Spaces.Split(trimmed);
        var output = new List<string>(4);
        var i = 0;
        if (RedisPrefixes.Contains(AsciiUpper(words[0])) && words.Length > 1) output.Add(AsciiUpper(words[i++]));
        if (!RedisWord.IsMatch(words[i])) return Other;
        var name = AsciiUpper(words[i++]);
        if (RedisWaiting.Contains(name)) return Other;
        output.Add(name);
        if (RedisContainers.Contains(name) && i < words.Length && RedisWord.IsMatch(words[i])) output.Add(AsciiUpper(words[i++]));
        if (i < words.Length - 1) return Other;
        if (i < words.Length) output.Add(RedisKeyShape(words[i]));
        return string.Join(" ", output);
    }

    // Cut to MaxStatement code points (a lone surrogate is one), and trim again.
    internal static string Cut(string text)
    {
        var count = 0;
        var i = 0;
        while (i < text.Length)
        {
            if (count == MaxStatement) return Trim(text.Substring(0, i));
            i += char.IsHighSurrogate(text[i]) && i + 1 < text.Length && char.IsLowSurrogate(text[i + 1]) ? 2 : 1;
            count++;
        }
        return text;
    }

    // The end of a quoted run starting at start (the opening quote): the index
    // after the closing quote, or the text's length. A doubled quote escapes,
    // and so does a backslash when backslash is true.
    private static int QuoteEnd(string sql, int start, char quote, bool backslash = true)
    {
        var i = start + 1;
        while (i < sql.Length)
        {
            var c = sql[i];
            if (c == '\\' && backslash) i += 2;
            else if (c == quote)
            {
                if (i + 1 < sql.Length && sql[i + 1] == quote) i += 2;
                else return i + 1;
            }
            else i += 1;
        }
        return sql.Length;
    }

    private static int IndexOf(string sql, string what, int from) => sql.IndexOf(what, Math.Min(from, sql.Length), StringComparison.Ordinal);

    private static string SqlShape(string sql, string db, bool? backslashLiteral = null)
    {
        var mysql = db == "mysql" || db == "mariadb";
        var postgres = db == "postgresql";
        // Where a backslash in a string is just a character: PostgreSQL's plain
        // strings (standard_conforming_strings, on since 9.1), SQLite, SQL Server
        // and Oracle. Read as an escape there, 'C:\' ends late and lets what
        // follows out. MySQL, MariaDB, ClickHouse and unknown databases escape.
        var literal = backslashLiteral ?? (postgres || db == "sqlite" || db == "mssql" || db == "oracle");
        var output = new StringBuilder(Math.Min(sql.Length, 4096));
        void Spaced()
        {
            if (output.Length > 0 && output[output.Length - 1] != ' ') output.Append(' ');
        }
        var i = 0;
        while (i < sql.Length)
        {
            var c = sql[i];
            var hasNext = i + 1 < sql.Length;
            var next = hasNext ? sql[i + 1] : '\0';
            var afterWord = i > 0 && IsWord(sql[i - 1]);
            if ((c == '-' && hasNext && next == '-') || (c == '#' && mysql))
            {
                var end = IndexOf(sql, "\n", i);
                i = end == -1 ? sql.Length : end;
                Spaced();
            }
            else if (c == '/' && hasNext && next == '*')
            {
                var end = IndexOf(sql, "*/", i + 2);
                i = end == -1 ? sql.Length : end + 2;
                Spaced();
            }
            else if (c == '\'' || (c == '"' && mysql))
            {
                // A string's one-letter prefix: E'..' N'..' X'..' B'..'.
                var n = output.Length;
                var prefixed = n > 0 && (n == 1 || !IsLetterOrDigit(output[n - 2]));
                // Only PostgreSQL's E'..' escapes with a backslash where it is literal.
                var escapes = !literal || (postgres && prefixed && (output[n - 1] == 'E' || output[n - 1] == 'e'));
                if (prefixed && "EeNnXxBb".IndexOf(output[n - 1]) >= 0) output.Length = n - 1;
                i = QuoteEnd(sql, i, c, escapes);
                output.Append('?');
            }
            else if (c == '"' || c == '`')
            {
                var end = QuoteEnd(sql, i, c, !literal);
                if (c == '"' && ValueQuotes.Contains(db) && !Name.IsMatch(sql.Substring(i, end - i))) output.Append('?');
                else output.Append(sql, i, end - i);
                i = end;
            }
            else if (c == '$' && !afterWord && DollarTag.Match(sql.Substring(i, Math.Min(64, sql.Length - i))) is { Success: true } tag)
            {
                var end = IndexOf(sql, tag.Value, i + tag.Value.Length);
                i = end == -1 ? sql.Length : end + tag.Value.Length;
                output.Append('?');
            }
            else if ((IsDigit(c) || (c == '.' && hasNext && IsDigit(next))) && !afterWord)
            {
                i += Number.Match(sql.Substring(i, Math.Min(400, sql.Length - i))).Length;
                output.Append('?');
            }
            else if (IsSpace(c))
            {
                i += 1;
                Spaced();
            }
            else
            {
                output.Append(c);
                i += 1;
            }
        }
        var shaped = PragmaKey.Replace(Identified.Replace(output.ToString(), "$1?"), "$1?");
        return Trim(Rows.Replace(List.Replace(shaped, "(?)"), "(?)"));
    }

    // ---- MongoDB ----

    private static readonly char[] FilterStart = { '{', '}', '[', ']', '"', '\'' };

    // "find users {...}": the command, the collection, and the filter's shape.
    private static string MongoStatement(string text)
    {
        var match = Mongo.Match(Trim(text));
        if (!match.Success) return "";
        var parts = new List<string> { match.Groups[1].Value };
        var collection = match.Groups[2].Success ? match.Groups[2].Value : "";
        string? rest = match.Groups[3].Success ? match.Groups[3].Value : null;
        // A "collection" with a brace, bracket or quote in it is the filter's start.
        if (collection.IndexOfAny(FilterStart) >= 0)
        {
            rest = rest == null ? collection : collection + " " + rest;
            collection = "";
        }
        if (collection.Length > 0) parts.Add(collection);
        if (!string.IsNullOrEmpty(rest))
        {
            try
            {
                using var doc = JsonDocument.Parse(rest, new JsonDocumentOptions { MaxDepth = 100000 });
                parts.Add(Stringify(Shape(doc.RootElement, 0)));
            }
            catch (Exception)
            {
                // Not JSON: the filter is dropped.
            }
        }
        return string.Join(" ", parts);
    }

    // A filter's shape: "?" (a value), a list (an array) or a list of pairs
    // (an object, in JavaScript's own key order).
    private sealed class Pairs : List<KeyValuePair<string, object>>
    {
    }

    // Keys stay, every value is "?", and an array whose items all have the
    // same shape is kept as one.
    private static object Shape(JsonElement value, int depth)
    {
        if (depth >= 6) return "?";
        if (value.ValueKind == JsonValueKind.Array)
        {
            var items = new List<object>();
            foreach (var item in value.EnumerateArray()) items.Add(Shape(item, depth + 1));
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var item in items) seen.Add(Stringify(item));
            return seen.Count == 1 ? new List<object> { items[0] } : items;
        }
        if (value.ValueKind != JsonValueKind.Object) return "?";
        // JSON.parse: a repeated key keeps its first place and its last value.
        var keys = new List<string>();
        var values = new Dictionary<string, JsonElement>(StringComparer.Ordinal);
        foreach (var property in value.EnumerateObject())
        {
            if (!values.ContainsKey(property.Name)) keys.Add(property.Name);
            values[property.Name] = property.Value;
        }
        var output = new Pairs();
        // Integer keys first, in numeric order, then the rest as they came.
        foreach (var key in Ordered(keys))
        {
            // Assigning "__proto__" on a plain object sets its prototype: the key is gone.
            if (key == "__proto__") continue;
            output.Add(new KeyValuePair<string, object>(key, Shape(values[key], depth + 1)));
        }
        return output;
    }

    private static IEnumerable<string> Ordered(List<string> keys)
    {
        var indexes = new List<(uint Index, string Key)>();
        var rest = new List<string>();
        foreach (var key in keys)
        {
            if (ArrayIndex(key) is { } index) indexes.Add((index, key));
            else rest.Add(key);
        }
        indexes.Sort((a, b) => a.Index.CompareTo(b.Index));
        foreach (var pair in indexes) yield return pair.Key;
        foreach (var key in rest) yield return key;
    }

    // An array index as JavaScript orders object keys: "0", or no leading
    // zero, below 2^32 - 1.
    private static uint? ArrayIndex(string key)
    {
        if (key.Length == 0 || key.Length > 10) return null;
        if (key.Length > 1 && key[0] == '0') return null;
        foreach (var c in key)
        {
            if (!IsDigit(c)) return null;
        }
        var value = ulong.Parse(key, CultureInfo.InvariantCulture);
        return value < 4294967295UL ? (uint)value : null;
    }

    private static string Stringify(object shape)
    {
        var output = new StringBuilder();
        Write(output, shape);
        return output.ToString();
    }

    private static void Write(StringBuilder output, object shape)
    {
        switch (shape)
        {
            case string text:
                Quote(output, text);
                break;
            case Pairs pairs:
                output.Append('{');
                for (var i = 0; i < pairs.Count; i++)
                {
                    if (i > 0) output.Append(',');
                    Quote(output, pairs[i].Key);
                    output.Append(':');
                    Write(output, pairs[i].Value);
                }
                output.Append('}');
                break;
            case List<object> items:
                output.Append('[');
                for (var i = 0; i < items.Count; i++)
                {
                    if (i > 0) output.Append(',');
                    Write(output, items[i]);
                }
                output.Append(']');
                break;
        }
    }

    /// <summary>A string as JSON.stringify writes it: non-ASCII as itself, a
    /// lone surrogate escaped.</summary>
    internal static void Quote(StringBuilder output, string text)
    {
        output.Append('"');
        for (var i = 0; i < text.Length; i++)
        {
            var c = text[i];
            switch (c)
            {
                case '"': output.Append("\\\""); break;
                case '\\': output.Append("\\\\"); break;
                case '\b': output.Append("\\b"); break;
                case '\f': output.Append("\\f"); break;
                case '\n': output.Append("\\n"); break;
                case '\r': output.Append("\\r"); break;
                case '\t': output.Append("\\t"); break;
                default:
                    if (c < ' ')
                    {
                        output.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                    }
                    else if (char.IsHighSurrogate(c) && i + 1 < text.Length && char.IsLowSurrogate(text[i + 1]))
                    {
                        output.Append(c).Append(text[i + 1]);
                        i++;
                    }
                    else if (char.IsSurrogate(c))
                    {
                        output.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                    }
                    else output.Append(c);
                    break;
            }
        }
        output.Append('"');
    }
}
