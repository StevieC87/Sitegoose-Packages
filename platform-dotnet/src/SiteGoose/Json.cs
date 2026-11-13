using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text.Encodings.Web;
using System.Text.Json;

namespace SiteGoose;

/// <summary>JSON and time helpers. Values from the collector are read the way
/// the Python package reads them (int(x or default), truthiness), so the
/// clients agree on the same answer.</summary>
internal static class J
{
    // Only ever sent to the collector, never into a page.
    public static readonly JsonSerializerOptions Options = new() { Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };

    public static string Serialize(object? value) => JsonSerializer.Serialize(value, Options);

    public static JsonElement? Parse(byte[]? body)
    {
        if (body == null || body.Length == 0) return null;
        try
        {
            using var doc = JsonDocument.Parse(body);
            return doc.RootElement.Clone();
        }
        catch (Exception)
        {
            return null;
        }
    }

    public static JsonElement? Parse(string? text)
    {
        if (string.IsNullOrEmpty(text)) return null;
        try
        {
            using var doc = JsonDocument.Parse(text);
            return doc.RootElement.Clone();
        }
        catch (Exception)
        {
            return null;
        }
    }

    public static JsonElement? Prop(JsonElement? element, string name)
    {
        if (element is { ValueKind: JsonValueKind.Object } e && e.TryGetProperty(name, out var value)) return value;
        return null;
    }

    public static bool IsObject(JsonElement? element) => element is { ValueKind: JsonValueKind.Object };

    public static bool IsArray(JsonElement? element) => element is { ValueKind: JsonValueKind.Array };

    /// <summary>Python's truthiness: null, false, 0, "", [] and {} are false.</summary>
    public static bool Truthy(JsonElement? element)
    {
        if (element is not { } e) return false;
        switch (e.ValueKind)
        {
            case JsonValueKind.True: return true;
            case JsonValueKind.Number: return e.TryGetDouble(out var d) && d != 0;
            case JsonValueKind.String: return (e.GetString() ?? "").Length > 0;
            case JsonValueKind.Array: return e.GetArrayLength() > 0;
            case JsonValueKind.Object:
                foreach (var _ in e.EnumerateObject()) return true;
                return false;
            default: return false;
        }
    }

    /// <summary>int(value or fallback): a number (truncated) or a numeric string;
    /// fallback when the value is missing, falsy or not a number.</summary>
    public static long Int(JsonElement? element, long fallback = 0)
    {
        if (element is not { } e) return fallback;
        switch (e.ValueKind)
        {
            case JsonValueKind.Number:
                if (e.TryGetInt64(out var whole)) return whole == 0 ? fallback : whole;
                if (e.TryGetDouble(out var d) && !double.IsNaN(d) && !double.IsInfinity(d))
                {
                    var t = (long)Math.Truncate(Math.Max(long.MinValue, Math.Min(long.MaxValue, d)));
                    return d == 0 ? fallback : t;
                }
                return fallback;
            case JsonValueKind.String:
                var s = (e.GetString() ?? "").Trim();
                if (s.Length == 0) return fallback;
                return long.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed) ? parsed : fallback;
            case JsonValueKind.True:
                return 1;
            default:
                return fallback;
        }
    }

    public static bool IsNumber(JsonElement? element) => element is { ValueKind: JsonValueKind.Number };

    public static string? Str(JsonElement? element) => element is { ValueKind: JsonValueKind.String } e ? e.GetString() : null;

    /// <summary>The strings of an array, anything else skipped.</summary>
    public static List<string> Strings(JsonElement? element)
    {
        var list = new List<string>();
        if (element is { ValueKind: JsonValueKind.Array } e)
        {
            foreach (var item in e.EnumerateArray())
            {
                if (item.ValueKind == JsonValueKind.String) list.Add(item.GetString() ?? "");
            }
        }
        return list;
    }

    /// <summary>ISO 8601, UTC, milliseconds: 2026-10-17T12:00:00.000Z.</summary>
    public static string Iso(DateTimeOffset at) =>
        at.UtcDateTime.ToString("yyyy-MM-dd'T'HH:mm:ss.fff'Z'", CultureInfo.InvariantCulture);

    public static string IsoSeconds(long unixSeconds) => Iso(DateTimeOffset.FromUnixTimeSeconds(unixSeconds));

    public static string Now() => Iso(DateTimeOffset.UtcNow);

    /// <summary>Seconds since 1970, with milliseconds.</summary>
    public static double UnixNow() => DateTimeOffset.UtcNow.ToUnixTimeMilliseconds() / 1000.0;

    public static string Clip(string? text, int max) => text == null ? "" : text.Length <= max ? text : text.Substring(0, max);
}
