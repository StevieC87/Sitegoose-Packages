using System;
using System.Collections.Generic;
using System.Net;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace SiteGoose;

/// <summary>A request rule as it will be matched.</summary>
internal sealed class RequestRule
{
    public string Id = "";
    public string Action = "monitor";
    public long Ban;
    public string[] Methods = Array.Empty<string>();
    public RuleSection? Path;
    public RuleSection? Query;
    public RuleSection? Ua;
}

internal sealed class RuleSection
{
    public HashSet<string>? Exact;
    public string[]? Prefix;
    public string[]? Suffix;
    public string[]? Contains;
    public Regex? Pattern;
}

/// <summary>Request rules (virtual patching; protocol in sdk/protocols/firewall.md):
/// the firewall has always matched addresses, these match the request -- its
/// method, path, query string and user agent -- so an attack is turned away
/// before the vulnerable code runs. Compiled once per fetch; matching is plain
/// string work. The matching is the same in every package: the shared cases
/// are in sdk/protocols/request-rules-cases.json.</summary>
internal static class RequestRules
{
    public const int MaxRules = 200;
    // How much of each part a rule may look at.
    public const int MaxText = 2000;
    public const int MaxRegex = 200;
    // .NET can time a regex out, which none of the other clients' languages
    // can; the shape check below still runs, so every client refuses the same
    // patterns, and this is a second guard on top of it.
    private static readonly TimeSpan MatchTimeout = TimeSpan.FromMilliseconds(50);
    private static readonly Regex Backreference = new("\\\\[1-9]", RegexOptions.CultureInvariant);
    private static readonly Regex Bounds = new("^\\{([0-9]*)(,([0-9]*))?\\}", RegexOptions.CultureInvariant);
    private static readonly Regex Slashes = new("/{2,}", RegexOptions.CultureInvariant);

    /// <summary>A pattern can only come from us, but a careless one would be
    /// matched against text an attacker chooses. A repeated group that can match
    /// the same text more than one way takes exponential time on input that
    /// nearly matches; a group can do that when it holds a quantifier or an
    /// alternation, so a group followed by * + or { holds neither.
    /// Backreferences and lookbehind are refused too. The same check as
    /// backend/services/firewall/requestRules.js, free repeats included.</summary>
    public static bool SafePattern(string? pattern)
    {
        if (string.IsNullOrEmpty(pattern) || pattern!.Length > MaxRegex) return false;
        if (Backreference.IsMatch(pattern) || pattern.Contains("(?<")) return false;
        var open = new List<bool>();
        var i = 0;
        while (i < pattern.Length)
        {
            var c = pattern[i];
            if (c == '\\')
            {
                // \k<name> and \g{1}: named and numbered backreferences, .NET's (and PCRE's) own.
                if (i + 1 < pattern.Length && (pattern[i + 1] == 'k' || pattern[i + 1] == 'g')) return false;
                i += 2;
                continue;
            }
            if (c == '[')
            {
                while (i < pattern.Length && pattern[i] != ']') i += pattern[i] == '\\' ? 2 : 1;
                i += 1;
                continue;
            }
            // A possessive quantifier ("a++", "a{2}+") is a syntax error in
            // JavaScript and Python's re before 3.11; refused so every package reads the same rules.
            if ("*+?}".IndexOf(c) >= 0 && i + 1 < pattern.Length && pattern[i + 1] == '+') return false;
            if (c == '(')
            {
                // (*FAIL), (*ACCEPT) and the other PCRE verbs.
                if (i + 1 < pattern.Length && pattern[i + 1] == '*') return false;
                open.Add(false);
                if (i + 1 < pattern.Length && pattern[i + 1] == '?')
                {
                    // Only (?: (?= (?! are in the common subset: named and
                    // balancing groups ((?<a>, (?'a', (?<a-b>), conditionals
                    // ((?( ), atomic groups, comments and inline options ((?i))
                    // are .NET's own, or read differently elsewhere.
                    var kind = i + 2 < pattern.Length ? pattern[i + 2] : '\0';
                    if (kind != ':' && kind != '=' && kind != '!') return false;
                    i += 2;
                }
            }
            else if (c == ')')
            {
                if (open.Count == 0) return false;
                var ambiguous = open[open.Count - 1];
                open.RemoveAt(open.Count - 1);
                var next = i + 1 < pattern.Length ? pattern[i + 1] : '\0';
                if (ambiguous && (next == '*' || next == '+' || next == '{')) return false;
                if (ambiguous && open.Count > 0) open[open.Count - 1] = true;
            }
            else if (open.Count > 0 && "|*+?{".IndexOf(c) >= 0)
            {
                open[open.Count - 1] = true;
            }
            i += 1;
        }
        return open.Count == 0 && FreeRepeats(pattern) <= 1;
    }

    private static string? LiteralAt(string pattern, int i)
    {
        if (i >= pattern.Length) return null;
        var c = pattern[i];
        if (c == '\\')
        {
            if (i + 1 >= pattern.Length) return null;
            var following = pattern[i + 1];
            var alnum = (following >= 'a' && following <= 'z') || (following >= 'A' && following <= 'Z') || (following >= '0' && following <= '9');
            return alnum ? null : following.ToString();
        }
        return ".[](){}*+?|^$".IndexOf(c) >= 0 ? null : c.ToString();
    }

    /// <summary>Two repeats that can both take the same text multiply each
    /// other's work. A repeat is pinned when the character straight after it is
    /// one it can't match ("[^/]+/" ends at the first "/", once); any other is
    /// free, and a pattern may hold one free repeat.</summary>
    private static int FreeRepeats(string pattern)
    {
        var free = 0;
        var i = 0;
        while (i < pattern.Length)
        {
            var start = i;
            var c = pattern[i];
            if (c == '\\')
            {
                i += 2;
            }
            else if (c == '[')
            {
                i += 1;
                while (i < pattern.Length && pattern[i] != ']') i += pattern[i] == '\\' ? 2 : 1;
                i += 1;
            }
            else if (c == '(')
            {
                i += i + 1 < pattern.Length && pattern[i + 1] == '?' ? 3 : 1;
                continue;
            }
            else if (c == '|' || c == '^' || c == '$')
            {
                i += 1;
                continue;
            }
            else
            {
                i += 1;
            }
            if (i > pattern.Length) i = pattern.Length;
            // A group's text can't be tried against one character.
            var atom = c == ')' ? null : pattern.Substring(start, i - start);
            var quantifier = i < pattern.Length ? pattern[i] : '\0';
            var repeats = quantifier == '*' || quantifier == '+';
            if (quantifier == '{')
            {
                var bounds = Bounds.Match(pattern.Substring(i));
                if (!bounds.Success) continue;
                // "{3}" is one length, not a choice; "{2,}" and "{2,9}" are choices.
                repeats = bounds.Groups[2].Success && bounds.Groups[3].Value != bounds.Groups[1].Value;
                i += bounds.Value.Length - 1;
            }
            else if (quantifier != '?' && !repeats)
            {
                continue;
            }
            i += 1;
            if (i < pattern.Length && pattern[i] == '?') i += 1;
            if (!repeats) continue;
            var next = LiteralAt(pattern, i);
            var pinned = false;
            if (atom != null && next != null)
            {
                try
                {
                    pinned = !Regex.IsMatch(next, "\\A(?:" + atom + ")\\z", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, MatchTimeout);
                }
                catch (Exception)
                {
                    // Not an atom on its own: free.
                }
            }
            if (!pinned) free += 1;
        }
        return free;
    }

    /// <summary>A rule's pattern, matched in linear time where .NET can
    /// (NonBacktracking, .NET 7 and later; not for lookahead), and always
    /// with a time limit.</summary>
    internal static Regex Compiled(string pattern)
    {
#if NET7_0_OR_GREATER
        try
        {
            return new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.NonBacktracking, MatchTimeout);
        }
        catch (NotSupportedException)
        {
        }
#endif
        return new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, MatchTimeout);
    }

    /// <summary>A section to match; without its regex when regex is false
    /// (page limits carry none, so the server agent's nginx can hold them too).</summary>
    internal static RuleSection? Section(JsonElement? data, bool regex = true)
    {
        if (data is not { ValueKind: JsonValueKind.Object }) return null;
        var section = new RuleSection();
        var any = false;
        foreach (var matcher in new[] { "exact", "prefix", "suffix", "contains" })
        {
            var entries = J.Prop(data, matcher);
            if (!J.IsArray(entries)) continue;
            var values = new List<string>();
            foreach (var entry in J.Strings(entries))
            {
                if (matcher == "exact" || entry.Length > 0) values.Add(entry.ToLowerInvariant());
            }
            if (values.Count == 0) continue;
            any = true;
            switch (matcher)
            {
                case "exact": section.Exact = new HashSet<string>(values, StringComparer.Ordinal); break;
                case "prefix": section.Prefix = values.ToArray(); break;
                case "suffix": section.Suffix = values.ToArray(); break;
                default: section.Contains = values.ToArray(); break;
            }
        }
        var pattern = regex ? J.Str(J.Prop(data, "regex")) : null;
        if (SafePattern(pattern))
        {
            try
            {
                section.Pattern = Compiled(pattern!);
                any = true;
            }
            catch (ArgumentException)
            {
                // A pattern we can't compile is dropped; the rule's other parts stay.
            }
        }
        return any ? section : null;
    }

    /// <summary>The rules as they will be matched; empty when there are none.</summary>
    public static List<RequestRule> Compile(JsonElement? data)
    {
        var rules = new List<RequestRule>();
        if (J.Prop(data, "rules") is not { ValueKind: JsonValueKind.Array } given) return rules;
        var seen = 0;
        foreach (var rule in given.EnumerateArray())
        {
            if (seen++ >= MaxRules) break;
            if (rule.ValueKind != JsonValueKind.Object) continue;
            var id = J.Str(J.Prop(rule, "id"));
            if (string.IsNullOrEmpty(id)) continue;
            // We are called before the body is read, so a rule that needs the body
            // is skipped whole rather than matched on the rest of it.
            if (rule.TryGetProperty("body", out _)) continue;
            var ban = J.Prop(rule, "ban");
            var compiled = new RequestRule
            {
                Id = id!,
                Action = J.Str(J.Prop(rule, "action")) == "block" ? "block" : "monitor",
                Ban = J.IsNumber(ban) && J.Int(ban) > 0 ? J.Int(ban) : 0,
            };
            if (J.Prop(rule, "methods") is { ValueKind: JsonValueKind.Array } methods)
            {
                var list = new List<string>();
                foreach (var method in J.Strings(methods)) list.Add(method.ToUpperInvariant());
                compiled.Methods = list.ToArray();
            }
            compiled.Path = Section(J.Prop(rule, "path"));
            compiled.Query = Section(J.Prop(rule, "query"));
            compiled.Ua = Section(J.Prop(rule, "ua"));
            // A rule with nothing to match would match everything.
            if (compiled.Path == null && compiled.Query == null && compiled.Ua == null) continue;
            rules.Add(compiled);
        }
        return rules;
    }

    /// <summary>One pass only, as the protocol says: enough for %2e%2e, and no
    /// risk of decoding a visitor's own text into something that looks like an attack.</summary>
    internal static string DecodeOnce(string text)
    {
        if (text.IndexOf('%') < 0 && text.IndexOf('+') < 0) return text;
        try
        {
            return WebUtility.UrlDecode(text) ?? text;
        }
        catch (Exception)
        {
            return text;
        }
    }

    private static string NormalizePath(string path) => Slashes.Replace(path.ToLowerInvariant().Replace('\\', '/'), "/");

    private static readonly Regex Params = new(";[^/]*", RegexOptions.CultureInvariant);

    /// <summary>The path as a router reads it: ";params" dropped from each
    /// segment (Tomcat, Jetty and some proxies do: "/x;y/../admin" is "/admin"
    /// to them), decoded once, "\" as "/", "//" as "/", and "." and ".."
    /// resolved (never above the root), lower-cased (firewall.md, 'Matching').</summary>
    internal static string RouterPath(string path)
    {
        var text = NormalizePath(DecodeOnce(Params.Replace(path, "")));
        var parts = new List<string>();
        var segments = text.Split('/');
        for (var index = 0; index < segments.Length; index++)
        {
            var segment = segments[index];
            if (segment == "..")
            {
                if (parts.Count > 1) parts.RemoveAt(parts.Count - 1);
            }
            else if (segment != "." && (segment.Length > 0 || index == 0))
            {
                parts.Add(segment);
            }
        }
        var resolved = string.Join("/", parts);
        var last = segments[segments.Length - 1];
        if ((last == "" || last == "." || last == "..") && segments.Length > 1 && !resolved.EndsWith("/", StringComparison.Ordinal)) resolved += "/";
        if (text.StartsWith("/", StringComparison.Ordinal) && !resolved.StartsWith("/", StringComparison.Ordinal)) resolved = "/" + resolved;
        return resolved;
    }

    /// <summary>A request target's path (no query string) as the router reads
    /// it: what the probes, the static-file check and the rules' path also match.</summary>
    internal static string NormalizeTarget(string? target)
    {
        var text = target ?? "";
        var cut = text.IndexOfAny(new[] { '?', '#' });
        if (cut >= 0) text = text.Substring(0, cut);
        return J.Clip(RouterPath(J.Clip(text, MaxText)), MaxText);
    }

    private static bool Hits(RuleSection section, string raw, string decoded, string? routed = null)
    {
        var texts = new List<string>(3) { raw };
        if (!texts.Contains(decoded)) texts.Add(decoded);
        if (routed != null && !texts.Contains(routed)) texts.Add(routed);
        foreach (var text in texts)
        {
            if (section.Exact != null && section.Exact.Contains(text)) return true;
            if (section.Prefix != null)
            {
                foreach (var entry in section.Prefix)
                {
                    if (text.StartsWith(entry, StringComparison.Ordinal)) return true;
                }
            }
            if (section.Suffix != null)
            {
                foreach (var entry in section.Suffix)
                {
                    if (entry.Length > 0 && text.EndsWith(entry, StringComparison.Ordinal)) return true;
                }
            }
            if (section.Contains != null)
            {
                foreach (var entry in section.Contains)
                {
                    if (entry.Length > 0 && text.IndexOf(entry, StringComparison.Ordinal) >= 0) return true;
                }
            }
            if (section.Pattern != null)
            {
                try
                {
                    if (section.Pattern.IsMatch(text)) return true;
                }
                catch (RegexMatchTimeoutException)
                {
                    // Too slow to say: not a match, and the request isn't held up.
                }
            }
        }
        return false;
    }

    /// <summary>A request as the rules see it, prepared once: the raw, decoded
    /// and routed path, the raw and decoded query, the user agent. The request
    /// rules and the page limits both match against it.</summary>
    internal sealed class Prepared
    {
        public Prepared(string? method, string? target, string? userAgent)
        {
            var t = target ?? "";
            var mark = t.IndexOf('?');
            var pathPart = mark == -1 ? t : t.Substring(0, mark);
            RawPath = NormalizePath(J.Clip(pathPart, MaxText));
            var query = J.Clip(mark == -1 ? "" : t.Substring(mark + 1), MaxText);
            RawQuery = query.ToLowerInvariant();
            Ua = J.Clip(userAgent ?? "", MaxText).ToLowerInvariant();
            DecodedPath = NormalizePath(J.Clip(DecodeOnce(J.Clip(pathPart, MaxText)), MaxText));
            RoutedPath = J.Clip(RouterPath(J.Clip(pathPart, MaxText)), MaxText);
            // Lower-cased after decoding: %55NION decodes to "UNION".
            DecodedQuery = J.Clip(DecodeOnce(query), MaxText).ToLowerInvariant();
            Method = (method ?? "").ToUpperInvariant();
        }

        public string Method { get; }
        public string RawPath { get; }
        public string DecodedPath { get; }
        /// <summary>What the router sees; also the page a limit with each "path" counts apart.</summary>
        public string RoutedPath { get; }
        public string RawQuery { get; }
        public string DecodedQuery { get; }
        public string Ua { get; }
    }

    /// <summary>True when the request is one of the rule's methods and every
    /// section the rule names matches.</summary>
    internal static bool Matches(RequestRule rule, Prepared request)
    {
        if (rule.Methods.Length > 0 && Array.IndexOf(rule.Methods, request.Method) < 0) return false;
        if (rule.Path != null && !Hits(rule.Path, request.RawPath, request.DecodedPath, request.RoutedPath)) return false;
        if (rule.Query != null && !Hits(rule.Query, request.RawQuery, request.DecodedQuery)) return false;
        return rule.Ua == null || Hits(rule.Ua, request.Ua, request.Ua);
    }

    /// <summary>The first rule that matches, or null. target is the request
    /// target as the server received it, query string and all.</summary>
    public static RequestRule? Match(List<RequestRule>? rules, string? method, string? target, string? userAgent)
    {
        if (rules == null || rules.Count == 0) return null;
        var request = new Prepared(method, target, userAgent);
        foreach (var rule in rules)
        {
            if (Matches(rule, request)) return rule;
        }
        return null;
    }
}
