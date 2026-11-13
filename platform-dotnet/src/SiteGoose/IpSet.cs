using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;

namespace SiteGoose;

/// <summary>An address as a 128-bit number in IPv6 space: IPv4 is kept as
/// ::ffff:a.b.c.d, so one sorted list holds both and an IPv4-mapped IPv6
/// address is the IPv4 one.</summary>
internal readonly struct IpKey : IComparable<IpKey>, IEquatable<IpKey>
{
    public readonly ulong Hi;
    public readonly ulong Lo;

    public IpKey(ulong hi, ulong lo)
    {
        Hi = hi;
        Lo = lo;
    }

    public static readonly IpKey Max = new(ulong.MaxValue, ulong.MaxValue);

    public int CompareTo(IpKey other) => Hi != other.Hi ? Hi.CompareTo(other.Hi) : Lo.CompareTo(other.Lo);
    public bool Equals(IpKey other) => Hi == other.Hi && Lo == other.Lo;
    public override bool Equals(object? obj) => obj is IpKey other && Equals(other);
    public override int GetHashCode() => HashCode.Combine(Hi, Lo);
    public static bool operator <(IpKey a, IpKey b) => a.CompareTo(b) < 0;
    public static bool operator >(IpKey a, IpKey b) => a.CompareTo(b) > 0;
    public static bool operator <=(IpKey a, IpKey b) => a.CompareTo(b) <= 0;
    public static bool operator >=(IpKey a, IpKey b) => a.CompareTo(b) >= 0;
    public static bool operator ==(IpKey a, IpKey b) => a.Equals(b);
    public static bool operator !=(IpKey a, IpKey b) => !a.Equals(b);

    public IpKey Next() => Lo == ulong.MaxValue ? new IpKey(Hi + 1, 0) : new IpKey(Hi, Lo + 1);
}

internal static class Ip
{
    // ::ffff:0.0.0.0 and ::ffff:255.255.255.255.
    private const ulong Mapped = 0xFFFFUL << 32;
    public static readonly IpKey MappedStart = new(0, Mapped);
    public static readonly IpKey MappedEnd = new(0, Mapped | 0xFFFFFFFFUL);

    /// <summary>An IPv4 address in dotted form only (no "1.2", no leading zeros),
    /// as Python's ipaddress takes it.</summary>
    public static bool TryParseV4(string text, out uint value)
    {
        value = 0;
        var parts = text.Split('.');
        if (parts.Length != 4) return false;
        foreach (var part in parts)
        {
            if (part.Length == 0 || part.Length > 3) return false;
            foreach (var c in part)
            {
                if (c < '0' || c > '9') return false;
            }
            if (part.Length > 1 && part[0] == '0') return false;
            var n = int.Parse(part);
            if (n > 255) return false;
            value = (value << 8) | (uint)n;
        }
        return true;
    }

    /// <summary>A strictly parsed address (zone id dropped), or null.</summary>
    public static IPAddress? Parse(string? text)
    {
        var t = (text ?? "").Trim();
        var zone = t.IndexOf('%');
        if (zone >= 0) t = t.Substring(0, zone);
        if (t.Length == 0) return null;
        if (t.IndexOf(':') >= 0)
        {
            if (t.IndexOf('[') >= 0 || t.IndexOf(']') >= 0 || t.IndexOf('/') >= 0) return null;
            foreach (var c in t)
            {
                if (!(c == ':' || c == '.' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) return null;
            }
            if (!IPAddress.TryParse(t, out var v6) || v6.AddressFamily != AddressFamily.InterNetworkV6) return null;
            // A dotted tail (::ffff:1.2.3.4) is held to the same rules as plain IPv4.
            var colon = t.LastIndexOf(':');
            var tail = t.Substring(colon + 1);
            if (tail.IndexOf('.') >= 0 && !TryParseV4(tail, out _)) return null;
            return v6;
        }
        if (!TryParseV4(t, out var v4)) return null;
        return new IPAddress(new[] { (byte)(v4 >> 24), (byte)(v4 >> 16), (byte)(v4 >> 8), (byte)v4 });
    }

    public static IpKey KeyOf(IPAddress address)
    {
        var bytes = address.GetAddressBytes();
        if (bytes.Length == 4)
        {
            var v4 = ((ulong)bytes[0] << 24) | ((ulong)bytes[1] << 16) | ((ulong)bytes[2] << 8) | bytes[3];
            return new IpKey(0, Mapped | v4);
        }
        ulong hi = 0, lo = 0;
        for (var i = 0; i < 8; i++) hi = (hi << 8) | bytes[i];
        for (var i = 8; i < 16; i++) lo = (lo << 8) | bytes[i];
        return new IpKey(hi, lo);
    }

    /// <summary>An address as an IpKey, or null when invalid.</summary>
    public static IpKey? Key(string? text)
    {
        var address = Parse(text);
        return address == null ? null : KeyOf(address);
    }

    /// <summary>"1.2.3.0/24" -> (start, end), or null. Null too for an IPv6 range
    /// that holds all of ::ffff:0:0/96 (::/64, ::/0): with IPv4 kept as
    /// ::ffff:a.b.c.d it would match every IPv4 visitor.</summary>
    public static (IpKey Start, IpKey End)? ParseRange(string? entry)
    {
        var text = (entry ?? "").Trim();
        var slash = text.IndexOf('/');
        var addressText = slash < 0 ? text : text.Substring(0, slash);
        if (addressText.IndexOf('%') >= 0) return null;
        var address = Parse(addressText);
        if (address == null) return null;
        var v4 = address.AddressFamily == AddressFamily.InterNetwork;
        var bits = v4 ? 32 : 128;
        var prefix = bits;
        if (slash >= 0)
        {
            var p = text.Substring(slash + 1);
            if (p.Length == 0 || p.Length > 3) return null;
            foreach (var c in p)
            {
                if (c < '0' || c > '9') return null;
            }
            prefix = int.Parse(p);
            if (prefix > bits) return null;
        }
        var key = KeyOf(address);
        // Host bits of the 128-bit key: an IPv4 /n is a /(96 + n) here.
        var hostBits = bits - prefix;
        var (maskHi, maskLo) = HostMask(hostBits);
        var start = new IpKey(key.Hi & ~maskHi, key.Lo & ~maskLo);
        var end = new IpKey(start.Hi | maskHi, start.Lo | maskLo);
        if (!v4 && start <= MappedStart && end >= MappedEnd) return null;
        return (start, end);
    }

    private static (ulong Hi, ulong Lo) HostMask(int hostBits)
    {
        if (hostBits <= 0) return (0, 0);
        if (hostBits >= 128) return (ulong.MaxValue, ulong.MaxValue);
        if (hostBits >= 64) return (hostBits == 64 ? 0 : (1UL << (hostBits - 64)) - 1, ulong.MaxValue);
        return (0, (1UL << hostBits) - 1);
    }

    /// <summary>An address as a proxy may write it, without its port:
    /// "1.2.3.4:56789" (Azure Application Gateway, IIS's ARR) -> "1.2.3.4",
    /// "[2001:db8::1]:443" and "[2001:db8::1]" -> "2001:db8::1". A bare IPv6
    /// address is left alone. ForwardedHeadersMiddleware reads them the same way.</summary>
    public static string StripPort(string? text)
    {
        var t = (text ?? "").Trim();
        if (t.StartsWith("[", StringComparison.Ordinal))
        {
            var close = t.IndexOf(']');
            if (close < 0) return t;
            var rest = t.Substring(close + 1);
            if (rest.Length == 0 || (rest[0] == ':' && IsPort(rest.Substring(1)))) return t.Substring(1, close - 1);
            return t;
        }
        var colon = t.IndexOf(':');
        if (colon > 0 && colon == t.LastIndexOf(':') && t.IndexOf('.') >= 0 && IsPort(t.Substring(colon + 1))) return t.Substring(0, colon);
        return t;
    }

    private static bool IsPort(string text)
    {
        if (text.Length == 0 || text.Length > 5) return false;
        foreach (var c in text)
        {
            if (c < '0' || c > '9') return false;
        }
        return true;
    }

    /// <summary>What the rate limit, bans here and failed logins count by: an
    /// IPv4 address (an IPv4-mapped one too) as itself, an IPv6 one by its /64,
    /// since one machine is usually given a whole /64 and could otherwise pick
    /// a fresh address per request. Null when it isn't an address.</summary>
    public static string? CounterKey(string? ip)
    {
        var address = Parse(ip);
        if (address == null) return null;
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        if (address.AddressFamily == AddressFamily.InterNetwork) return address.ToString();
        var bytes = address.GetAddressBytes();
        for (var i = 8; i < 16; i++) bytes[i] = 0;
        return new IPAddress(bytes) + "/64";
    }

    /// <summary>The address as text, an IPv4-mapped IPv6 one as IPv4.</summary>
    public static string Display(IPAddress? address)
    {
        if (address == null) return "";
        if (address.IsIPv4MappedToIPv6) address = address.MapToIPv4();
        return address.ToString();
    }
}

/// <summary>Addresses and ranges, merged and sorted, looked up by binary search
/// (firewall.md: `lists` alone holds about 1,500 ranges).</summary>
internal sealed class IpSet
{
    private readonly IpKey[] starts;
    private readonly IpKey[] ends;

    public static readonly IpSet Empty = new(Array.Empty<string>());

    public IpSet(IEnumerable<string>? entries)
    {
        var ranges = new List<(IpKey Start, IpKey End)>();
        if (entries != null)
        {
            foreach (var entry in entries)
            {
                if (entry == null) continue;
                var range = Ip.ParseRange(entry);
                if (range != null) ranges.Add(range.Value);
            }
        }
        ranges.Sort((a, b) => a.Start != b.Start ? a.Start.CompareTo(b.Start) : a.End.CompareTo(b.End));
        var s = new List<IpKey>();
        var e = new List<IpKey>();
        foreach (var (start, end) in ranges)
        {
            if (e.Count > 0 && (e[e.Count - 1].Equals(IpKey.Max) || start <= e[e.Count - 1].Next()))
            {
                if (end > e[e.Count - 1]) e[e.Count - 1] = end;
            }
            else
            {
                s.Add(start);
                e.Add(end);
            }
        }
        starts = s.ToArray();
        ends = e.ToArray();
    }

    public int Count => starts.Length;

    public bool Has(IpKey key)
    {
        int lo = 0, hi = starts.Length - 1, found = -1;
        while (lo <= hi)
        {
            var mid = (lo + hi) >> 1;
            if (starts[mid] <= key)
            {
                found = mid;
                lo = mid + 1;
            }
            else
            {
                hi = mid - 1;
            }
        }
        return found >= 0 && ends[found] >= key;
    }

    public bool Has(string? ip)
    {
        var key = Ip.Key(ip);
        return key != null && Has(key.Value);
    }
}
