package com.sitegoose.analytics;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;

/**
 * Addresses as 128-bit numbers in IPv6 space, IPv4 kept as ::ffff:a.b.c.d so
 * one sorted list holds both (sdk/protocols/firewall.md). Parsed by hand:
 * InetAddress would look a host name up in DNS, on a visitor's request.
 */
public final class Ip {
    private Ip() {
    }

    /** IPv4 as ::ffff:a.b.c.d: the low 64 bits of the key. */
    static final long MAPPED = 0xFFFFL << 32;

    /** An address as a 128-bit number. */
    public static final class Key implements Comparable<Key> {
        final long hi;
        final long lo;

        Key(long hi, long lo) {
            this.hi = hi;
            this.lo = lo;
        }

        /** True for IPv4, written or mapped (::ffff:a.b.c.d). */
        boolean isV4() {
            return hi == 0 && (lo >>> 32) == 0xFFFFL;
        }

        @Override
        public int compareTo(Key other) {
            int c = Long.compareUnsigned(hi, other.hi);
            return c != 0 ? c : Long.compareUnsigned(lo, other.lo);
        }

        @Override
        public boolean equals(Object other) {
            return other instanceof Key && ((Key) other).hi == hi && ((Key) other).lo == lo;
        }

        @Override
        public int hashCode() {
            return Long.hashCode(hi) * 31 + Long.hashCode(lo);
        }
    }

    /** An address, or null when the text isn't one. A zone (%eth0) is dropped. */
    public static Key key(String text) {
        if (text == null) {
            return null;
        }
        String value = text.trim();
        int zone = value.indexOf('%');
        if (zone >= 0) {
            value = value.substring(0, zone);
        }
        if (value.indexOf(':') < 0) {
            long v4 = parseV4(value);
            return v4 < 0 ? null : new Key(0, MAPPED | v4);
        }
        long[] v6 = parseV6(value);
        return v6 == null ? null : new Key(v6[0], v6[1]);
    }

    /**
     * The address in a proxy header without a port: "203.0.113.5:54321"
     * (Azure's X-Forwarded-For), "[2001:db8::1]:443" and "[2001:db8::1]"
     * give the address; anything else is returned as it is.
     */
    public static String withoutPort(String text) {
        if (text == null) {
            return null;
        }
        String value = text.trim();
        if (value.startsWith("[")) {
            int end = value.indexOf(']');
            return end > 0 ? value.substring(1, end) : value;
        }
        int colon = value.indexOf(':');
        if (colon > 0 && colon == value.lastIndexOf(':') && value.indexOf('.') > 0 && value.indexOf('.') < colon) {
            return value.substring(0, colon);
        }
        return value;
    }

    /**
     * The key the firewall counts and bans an address under here: an IPv4
     * address as itself (::ffff:a.b.c.d is the same address), an IPv6 one by
     * its /64, which one machine usually holds whole. Null when it isn't one.
     */
    static String bucket(String ip) {
        Key key = key(withoutPort(ip));
        if (key == null) {
            return null;
        }
        if (key.isV4()) {
            return who(withoutPort(ip));
        }
        // The /64 in RFC 5952 form, as every package writes it: the last four groups are
        // zero, so the longest zero run always ends the address and the prefix's own
        // trailing zero groups join it ("2001:db8:0:1::/64", "2001::/64", "::/64").
        int[] groups = {(int) ((key.hi >>> 48) & 0xFFFF), (int) ((key.hi >>> 32) & 0xFFFF),
                (int) ((key.hi >>> 16) & 0xFFFF), (int) (key.hi & 0xFFFF)};
        int keep = 4;
        while (keep > 0 && groups[keep - 1] == 0) {
            keep--;
        }
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < keep; i++) {
            out.append(i > 0 ? ":" : "").append(Integer.toHexString(groups[i]));
        }
        return out.append("::/64").toString();
    }

    /** An ASCII hex digit's value, or -1 (Character.digit takes other scripts' digits too). */
    static int hex(char c) {
        if (c >= '0' && c <= '9') {
            return c - '0';
        }
        if (c >= 'a' && c <= 'f') {
            return c - 'a' + 10;
        }
        if (c >= 'A' && c <= 'F') {
            return c - 'A' + 10;
        }
        return -1;
    }

    /** a.b.c.d as a number, or -1. Leading zeros are refused, as Python's ipaddress does. */
    static long parseV4(String text) {
        String[] parts = text.split("\\.", -1);
        if (parts.length != 4) {
            return -1;
        }
        long out = 0;
        for (String part : parts) {
            if (part.isEmpty() || part.length() > 3 || (part.length() > 1 && part.charAt(0) == '0')) {
                return -1;
            }
            int n = 0;
            for (int i = 0; i < part.length(); i++) {
                char c = part.charAt(i);
                if (c < '0' || c > '9') {
                    return -1;
                }
                n = n * 10 + (c - '0');
            }
            if (n > 255) {
                return -1;
            }
            out = (out << 8) | n;
        }
        return out;
    }

    /** An IPv6 address as {high, low} 64 bits, or null. */
    static long[] parseV6(String text) {
        if (text.isEmpty() || text.length() > 45) {
            return null;
        }
        int[] groups = new int[8];
        String head = text;
        String tail = null;
        int gap = text.indexOf("::");
        if (gap >= 0) {
            if (text.indexOf("::", gap + 1) >= 0) {
                return null;
            }
            head = text.substring(0, gap);
            tail = text.substring(gap + 2);
        }
        List<Integer> front = new ArrayList<>();
        List<Integer> back = new ArrayList<>();
        if (!groupsOf(head, front, tail == null)) {
            return null;
        }
        if (tail != null && !groupsOf(tail, back, true)) {
            return null;
        }
        int count = front.size() + back.size();
        if (tail == null ? count != 8 : count > 7) {
            return null;
        }
        for (int i = 0; i < front.size(); i++) {
            groups[i] = front.get(i);
        }
        for (int i = 0; i < back.size(); i++) {
            groups[8 - back.size() + i] = back.get(i);
        }
        long hi = 0;
        long lo = 0;
        for (int i = 0; i < 4; i++) {
            hi = (hi << 16) | groups[i];
        }
        for (int i = 4; i < 8; i++) {
            lo = (lo << 16) | groups[i];
        }
        return new long[] {hi, lo};
    }

    /** Hex groups (and a final dotted IPv4, as two) into out; false when malformed. */
    private static boolean groupsOf(String text, List<Integer> out, boolean lastMayBeV4) {
        if (text.isEmpty()) {
            return true;
        }
        String[] parts = text.split(":", -1);
        for (int i = 0; i < parts.length; i++) {
            String part = parts[i];
            if (i == parts.length - 1 && lastMayBeV4 && part.indexOf('.') >= 0) {
                long v4 = parseV4(part);
                if (v4 < 0) {
                    return false;
                }
                out.add((int) (v4 >>> 16));
                out.add((int) (v4 & 0xFFFF));
                return true;
            }
            if (part.isEmpty() || part.length() > 4) {
                return false;
            }
            int n = 0;
            for (int j = 0; j < part.length(); j++) {
                int digit = hex(part.charAt(j));
                if (digit < 0) {
                    return false;
                }
                n = (n << 4) | digit;
            }
            out.add(n);
        }
        return true;
    }

    /**
     * "1.2.3.0/24" as {start, end}, or null. Null too for an IPv6 range that
     * holds all of ::ffff:0:0/96 (::/64, ::/0): with IPv4 kept as
     * ::ffff:a.b.c.d it would match every IPv4 visitor.
     */
    static Key[] range(String entry) {
        if (entry == null) {
            return null;
        }
        String text = entry.trim();
        int slash = text.indexOf('/');
        String address = slash < 0 ? text : text.substring(0, slash);
        boolean v4 = address.indexOf(':') < 0;
        int bits = v4 ? 32 : 128;
        int prefix = bits;
        if (slash >= 0) {
            String length = text.substring(slash + 1);
            if (length.isEmpty() || length.length() > 3 || !length.chars().allMatch(ch -> ch >= '0' && ch <= '9')) {
                return null;
            }
            prefix = Integer.parseInt(length);
            if (prefix > bits) {
                return null;
            }
        }
        if (address.indexOf('%') >= 0) {
            return null;
        }
        if (v4) {
            long value = parseV4(address);
            if (value < 0) {
                return null;
            }
            long mask = prefix == 0 ? 0 : (0xFFFFFFFFL << (32 - prefix)) & 0xFFFFFFFFL;
            long start = value & mask;
            long end = start | (~mask & 0xFFFFFFFFL);
            return new Key[] {new Key(0, MAPPED | start), new Key(0, MAPPED | end)};
        }
        long[] value = parseV6(address);
        if (value == null) {
            return null;
        }
        long hiMask = prefix >= 64 ? -1L : prefix == 0 ? 0 : -1L << (64 - prefix);
        long loMask = prefix <= 64 ? 0 : prefix == 128 ? -1L : -1L << (128 - prefix);
        Key start = new Key(value[0] & hiMask, value[1] & loMask);
        Key end = new Key(start.hi | ~hiMask, start.lo | ~loMask);
        if (start.compareTo(new Key(0, MAPPED)) <= 0 && end.compareTo(new Key(0, MAPPED | 0xFFFFFFFFL)) >= 0) {
            return null;
        }
        return new Key[] {start, end};
    }

    /** Addresses and ranges, merged and sorted, looked up by binary search. */
    public static final class Set {
        private final Key[] starts;
        private final Key[] ends;

        public Set(Collection<?> entries) {
            List<Key[]> ranges = new ArrayList<>();
            if (entries != null) {
                for (Object entry : entries) {
                    if (entry instanceof String) {
                        Key[] r = range((String) entry);
                        if (r != null) {
                            ranges.add(r);
                        }
                    }
                }
            }
            ranges.sort(Comparator.<Key[], Key>comparing(r -> r[0]).thenComparing(r -> r[1]));
            List<Key> s = new ArrayList<>();
            List<Key> e = new ArrayList<>();
            for (Key[] r : ranges) {
                if (!e.isEmpty() && adjacentOrInside(r[0], e.get(e.size() - 1))) {
                    Key last = e.get(e.size() - 1);
                    if (r[1].compareTo(last) > 0) {
                        e.set(e.size() - 1, r[1]);
                    }
                } else {
                    s.add(r[0]);
                    e.add(r[1]);
                }
            }
            starts = s.toArray(new Key[0]);
            ends = e.toArray(new Key[0]);
        }

        public static Set of(String... entries) {
            return new Set(Arrays.asList(entries));
        }

        /** start <= end + 1, without overflowing past the last address. */
        private static boolean adjacentOrInside(Key start, Key end) {
            if (start.compareTo(end) <= 0) {
                return true;
            }
            long lo = end.lo + 1;
            long hi = lo == 0 ? end.hi + 1 : end.hi;
            if (end.hi == -1L && end.lo == -1L) {
                return true;
            }
            return start.compareTo(new Key(hi, lo)) <= 0;
        }

        public boolean has(Key key) {
            if (key == null || starts.length == 0) {
                return false;
            }
            int low = 0;
            int high = starts.length - 1;
            int found = -1;
            while (low <= high) {
                int mid = (low + high) >>> 1;
                if (starts[mid].compareTo(key) <= 0) {
                    found = mid;
                    low = mid + 1;
                } else {
                    high = mid - 1;
                }
            }
            return found >= 0 && ends[found].compareTo(key) >= 0;
        }

        public boolean has(String ip) {
            return has(key(ip));
        }

        public int size() {
            return starts.length;
        }
    }

    /**
     * What a browser-check pass is bound to: the IPv4 address (an IPv4-mapped
     * IPv6 address as IPv4), or an IPv6 address's /64 as four groups of four
     * lower-case hex digits. "*" for the agent's nginx; null for anything
     * that isn't an address.
     */
    static String who(String ip) {
        String text = ip == null ? "" : ip.trim();
        if ("*".equals(text)) {
            return "*";
        }
        Key key = key(text);
        if (key == null) {
            return null;
        }
        if (key.isV4()) {
            long v4 = key.lo & 0xFFFFFFFFL;
            return (v4 >>> 24) + "." + ((v4 >>> 16) & 255) + "." + ((v4 >>> 8) & 255) + "." + (v4 & 255);
        }
        return String.format(Locale.ROOT, "%04x:%04x:%04x:%04x",
                (key.hi >>> 48) & 0xFFFF, (key.hi >>> 32) & 0xFFFF, (key.hi >>> 16) & 0xFFFF, key.hi & 0xFFFF);
    }
}
