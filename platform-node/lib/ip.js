// Addresses and ranges, with no Node built-ins so the edge runtime (Next.js
// middleware) can use it too. IPv4 is a number, IPv6 a BigInt; IPv4-mapped
// IPv6 (::ffff:1.2.3.4) is IPv4.
"use strict";

const V4 = /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const HEX = /^[0-9a-f]{1,4}$/i;

function v4(text) {
  let n = 0;
  for (const part of text.split(".")) n = n * 256 + Number(part);
  return n;
}

// The 8 groups of an IPv6 address, or null when it isn't one.
function v6Groups(text) {
  let s = text.split("%")[0];
  const cut = s.lastIndexOf(":");
  if (cut < 0) return null;
  const tail = s.slice(cut + 1);
  if (tail.includes(".")) {
    if (!V4.test(tail)) return null;
    const n = v4(tail);
    s = `${s.slice(0, cut + 1)}${Math.floor(n / 65536).toString(16)}:${(n % 65536).toString(16)}`;
  }
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  if (![...left, ...right].every((g) => HEX.test(g))) return null;
  if (halves.length === 1) return left.length === 8 ? left : null;
  const fill = 8 - left.length - right.length;
  return fill >= 1 ? [...left, ...Array(fill).fill("0"), ...right] : null;
}

function parseIp(text) {
  const s = String(text || "").trim();
  if (V4.test(s)) return { family: 4, n: v4(s) };
  const groups = v6Groups(s);
  if (!groups) return null;
  let n = 0n;
  for (const group of groups) n = (n << 16n) | BigInt(parseInt(group, 16));
  if (n >> 32n === 0xffffn) return { family: 4, n: Number(n & 0xffffffffn) };
  return { family: 6, n };
}

// "1.2.3.4", "1.2.3.0/24", "2001:db8::/32" -> { family, start, end }, or null.
function parseRange(entry) {
  const [addr, bits, extra] = String(entry || "").trim().split("/");
  if (extra !== undefined || (bits !== undefined && !/^\d{1,3}$/.test(bits))) return null;
  const ip = parseIp(addr);
  if (!ip) return null;
  const max = ip.family === 4 ? 32 : 128;
  let prefix = bits === undefined ? max : Number(bits);
  if (ip.family === 4 && addr.includes(":") && bits !== undefined) prefix -= 96;
  if (prefix < 0 || prefix > max) return null;
  if (ip.family === 4) {
    const size = 2 ** (32 - prefix);
    const start = Math.floor(ip.n / size) * size;
    return { family: 4, start, end: start + size - 1 };
  }
  const host = (1n << BigInt(128 - prefix)) - 1n;
  return { family: 6, start: ip.n & ~host, end: (ip.n & ~host) | host };
}

// Addresses and ranges, merged and sorted, looked up by binary search.
class IpSet {
  constructor(entries = []) {
    const ranges = { 4: [], 6: [] };
    for (const entry of entries) {
      const range = parseRange(entry);
      if (range) ranges[range.family].push(range);
    }
    this[4] = IpSet.merge(ranges[4], 1);
    this[6] = IpSet.merge(ranges[6], 1n);
  }

  static merge(ranges, one) {
    ranges.sort((a, b) => (a.start < b.start ? -1 : a.start > b.start ? 1 : 0));
    const merged = [];
    for (const r of ranges) {
      const last = merged[merged.length - 1];
      if (last && r.start <= last.end + one) {
        if (r.end > last.end) last.end = r.end;
      } else merged.push({ start: r.start, end: r.end });
    }
    return merged;
  }

  has(ip) {
    const list = this[ip.family];
    let lo = 0;
    let hi = list.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      if (list[mid].start > ip.n) hi = mid - 1;
      else if (list[mid].end < ip.n) lo = mid + 1;
      else return true;
    }
    return false;
  }
}

// One hop of a forwarding header as an address: "[v6]:port" and "v4:port"
// lose the port (Azure's App Service and Application Gateway send them);
// anything else is returned trimmed, for parseIp to accept or refuse.
function hop(text) {
  const s = String(text ?? "").trim();
  if (s.startsWith("[")) {
    const close = s.indexOf("]");
    return close > 0 ? s.slice(1, close) : s;
  }
  const found = /^(\d{1,3}(?:\.\d{1,3}){3}):\d{1,5}$/.exec(s);
  return found ? found[1] : s;
}

// Who the rate limit, the login count and the bans on this server are
// about: an IPv4 address ("::ffff:a.b.c.d" as a.b.c.d), or an IPv6
// address's /64, which one machine usually holds whole (and can mint
// addresses in by the billion), as the browser check binds its pass. Takes
// the text or parseIp's result; "" for anything that isn't an address.
// Written as the shared counter's key is in every package (firewall.md):
// "198.51.100.7", or the /64 as its network, compressed ("2001:db8:1:2::/64"),
// so a site mixing languages on one Redis counts a visitor once.
function counterKey(ip) {
  const address = ip && typeof ip === "object" ? ip : parseIp(ip);
  if (!address) return "";
  if (address.family === 4) {
    const n = address.n;
    return [n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
  }
  const top = address.n >> 64n;
  const groups = [48n, 32n, 16n, 0n].map((shift) => Number((top >> shift) & 0xffffn)).concat([0, 0, 0, 0]);
  return `${compressV6(groups)}/64`;
}

// Eight groups as RFC 5952 text: lower-case, no leading zeros, the longest
// run of two or more zero groups (the first of equal ones) as "::".
function compressV6(groups) {
  let best = -1;
  let bestLength = 1;
  for (let i = 0; i < 8; ) {
    if (groups[i] !== 0) { i += 1; continue; }
    let j = i;
    while (j < 8 && groups[j] === 0) j += 1;
    if (j - i > bestLength) { best = i; bestLength = j - i; }
    i = j;
  }
  const hex = groups.map((g) => g.toString(16));
  if (best < 0) return hex.join(":");
  return `${hex.slice(0, best).join(":")}::${hex.slice(best + bestLength).join(":")}`;
}

// A Map used as a bounded table: at `max` entries the oldest go (Maps keep
// insertion order), so one /64 minting new keys can't reset everyone's
// count the way clearing the whole table did.
function makeRoom(table, max) {
  while (table.size >= max) table.delete(table.keys().next().value);
}

module.exports = { parseIp, parseRange, IpSet, hop, counterKey, makeRoom };
