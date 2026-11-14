// Bot protection on the server itself: an address that floods (over the rate
// limit) or fails too many logins is banned here straight away, before the
// next rules arrive; the report that goes back bans it on the site's other
// servers too (the rules' "banned" list). Also the rules' `probes`: addresses
// of files no visitor asks for (.env, .git/...). No Node built-ins (edge-safe).
"use strict";

const { counterKey, makeRoom } = require("./ip.js");
const { routedPath, decodeOnce, MAX_TEXT } = require("./requestRules.js");

const MAX = 50000;

// One key per visitor however the address is spelled: "1.2.3.4" and
// "::ffff:1.2.3.4" (and IPv6 written two ways) are the same, and so is every
// address of one IPv6 /64.
function keyOf(ip) {
  return counterKey(ip) || String(ip);
}

function createLocalBans() {
  const bans = new Map(); // address -> when the ban ends (ms)
  const logins = new Map(); // address -> { start, count }

  function banned(address) {
    const ip = keyOf(address);
    const until = bans.get(ip);
    if (!until) return false;
    if (until > Date.now()) return true;
    bans.delete(ip);
    return false;
  }

  function ban(address, seconds) {
    if (!(seconds > 0)) return;
    const ip = keyOf(address);
    // Taken out and put back, so the table runs oldest first and a full one
    // loses the ban that was set longest ago, not every ban at once.
    const until = Math.max(bans.get(ip) || 0, Date.now() + seconds * 1000);
    bans.delete(ip);
    makeRoom(bans, MAX);
    bans.set(ip, until);
  }

  // One failed login; login: the rules' { limit, window, ban } (seconds).
  // True when it got the address banned.
  function loginFailed(address, login) {
    if (!login) return false;
    const ip = keyOf(address);
    const now = Date.now();
    let entry = logins.get(ip);
    if (!entry || now - entry.start >= login.window * 1000) {
      logins.delete(ip);
      makeRoom(logins, MAX);
      entry = { start: now, count: 0 };
      logins.set(ip, entry);
    }
    entry.count += 1;
    if (entry.count < login.limit) return false;
    ban(address, login.ban);
    logins.delete(ip);
    return true;
  }

  return { banned, ban, loginFailed };
}

// The rules' probes -> { exact: Set, prefix: [...], ban (seconds) }, or null.
function compileProbes(probes) {
  if (!probes || typeof probes !== "object") return null;
  const paths = (list) => (Array.isArray(list) ? list.filter((p) => typeof p === "string" && p).map((p) => p.toLowerCase()) : []);
  const exact = new Set(paths(probes.exact));
  const prefix = paths(probes.prefix);
  if (!exact.size && !prefix.length) return null;
  return { exact, prefix, ban: Number(probes.ban) > 0 ? Number(probes.ban) : 0 };
}

// True when the request's path (no query, lower-cased, "//" as "/") is a
// probe; or the path as the router will see it ("/x;y/../.env" is "/.env":
// requestRules.js routedPath), so a probe can't walk around the list.
function isProbe(path, probes) {
  if (!probes) return false;
  const raw = String(path || "").split(/[?#]/)[0];
  const hit = (clean) => probes.exact.has(clean) || probes.prefix.some((p) => clean.startsWith(p));
  if (hit(raw.toLowerCase().replace(/\/{2,}/g, "/"))) return true;
  return hit(routedPath(raw));
}

// Files a page load asks for by the dozen, when the app serves its own
// (express.static, Next's /_next/static/, a Vite build's /assets/): not
// counted against `rate` or the page limits, or a 40-file page would use 41
// requests of it (the agent's nginx limit leaves the same extensions out).
// Probes, request rules and the address lists still apply to them. The
// extension follows a name in the last segment, not starts it: "/login/.css"
// is no file.
const STATIC = /\/[^/.][^/]*\.(?:css|js|mjs|map|png|jpe?g|gif|webp|avif|svg|ico|bmp|woff2?|ttf|otf|eot|mp4|webm|ogg|mp3|wav|pdf|wasm)$/;
const STATIC_PREFIXES = ["/static/", "/_next/static/", "/assets/"];
// In the path decoded once: a "%xx" still there (double encoding, which a
// router that decodes again reads differently), a ";" (a path parameter to
// some servers and proxies, part of the name to others), a "\" (a "/" to
// some), a "?" or "#" that was encoded, or a control character.
const UNSURE = /%[0-9a-f]{2}|[;\\?#\x00-\x1f\x7f]/i;
// Only GET and HEAD fetch a file; a form posts to a page (Rails reads POST
// /login.css as the login action, older Spring MVC as /login). No method
// given is read as GET.
const FETCHES = new Set(["", "GET", "HEAD"]);

// Read from the target as sent, decoded once, lower case, "//" as "/". Only
// a path every router reads the same way can be a file: one with a "." or
// ".." segment, a ";", a "\", an encoded "/" or a "%xx" left after decoding
// is a page, so "/static/../login", "/static%2F..%2Flogin", "/login;x.css"
// and "/login%3Bx.css" all count (sdk/protocols/static-cases.json). A
// browser asks for its files with none of those. Nor is a path over 2,000
// characters: no asset has a name that long.
function isStatic(target, method = "") {
  if (!FETCHES.has(String(method ?? ""))) return false;
  const raw = String(target || "").split(/[?#]/)[0];
  if (raw.length > MAX_TEXT || !raw.startsWith("/") || /%2f/i.test(raw)) return false;
  const decoded = decodeOnce(raw);
  if (UNSURE.test(decoded)) return false;
  // ASCII only, as every package: "İ" is "i" lower-cased in some languages.
  const segments = decoded.replace(/[A-Z]+/g, (c) => c.toLowerCase()).split("/");
  if (segments.includes(".") || segments.includes("..")) return false;
  const parts = segments.filter(Boolean);
  // "/app.css/" isn't a file.
  const path = `/${parts.join("/")}${parts.length && segments[segments.length - 1] === "" ? "/" : ""}`;
  return STATIC_PREFIXES.some((prefix) => path.startsWith(prefix)) || STATIC.test(path);
}

// A response whose Content-Type is a file's (an image, a font, a script, a
// stylesheet, a video, a PDF, a download): what a route that serves files
// answers, e.g. express.static or res.sendFile() under "/uploads/:name".
const FILE_TYPES = /^(?:image|font|audio|video)\/|^text\/css|javascript|^application\/(?:wasm|pdf|octet-stream|vnd\.ms-fontobject|(?:x-)?font)/i;
function servesFile(contentType) {
  return FILE_TYPES.test(String(Array.isArray(contentType) ? contentType[0] : contentType || "").trim());
}

// After the response to a static-looking request (firewall.md, `rate`):
// whether the app's router sent it to a route of its own that isn't a
// file's, so it counts after all. pattern: the route matched (Express
// req.route.path, Fastify routeOptions.url, Koa _matchedRoute, Hono
// routePath; a string, an array of them, a RegExp), undefined when none
// matched (express.static, serve-static, koa-static are middleware, no
// route). A pattern that is itself a file's by the same rule
// ("/avatars/:id.png", "/static/*") is left alone, and so is a route that
// answered a file's Content-Type (a wildcard static plugin, sendFile): an
// image on a page is a request to one.
function routedToPage(pattern, contentType) {
  if (pattern === undefined || pattern === null || pattern === "" || servesFile(contentType)) return false;
  const patterns = Array.isArray(pattern) ? pattern : [pattern];
  return !patterns.every((one) => typeof one === "string" && isStatic(one));
}

// Sec-Fetch-Site says another site made the browser send the request (an
// <img>, a no-cors fetch, a link): it comes from the visitor's own address,
// so a probe, a request rule or the rate limit refuses it but bans no one
// (firewall.md, "Checking a request").
const FOREIGN = new Set(["cross-site", "same-site"]);
const sentForAnotherSite = (fetchSite) => FOREIGN.has(String(fetchSite ?? "").trim().toLowerCase());
// The rules a block report gets an address banned on the other servers for.
const bansOnReport = (rule) => rule === "probe" || rule === "rate" || String(rule).startsWith("request:");

module.exports = {
  createLocalBans, compileProbes, isProbe, isStatic, servesFile, routedToPage, keyOf, sentForAnotherSite, bansOnReport,
};
