// Maintenance mode module: while it's on (Security → Server package), visitors
// get a "back soon" page (503, so search engines know it's temporary),
// except allowed addresses and whoever opened the preview link
// (?site_preview=<code>, remembered for a day in a cookie).
"use strict";

const { parseIp, IpSet } = require("./ip.js");

const COOKIE = "site_preview";
const escape = (text) => String(text).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

function page(message) {
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Back soon</title><style>body{margin:0;min-height:100vh;display:grid;place-items:center;font:16px/1.5 system-ui,sans-serif;background:#f8fafc;color:#0f172a}
main{max-width:32rem;padding:2rem;text-align:center}h1{font-size:1.6rem;margin:0 0 .5rem}p{color:#475569;margin:0}
@media(prefers-color-scheme:dark){body{background:#0f172a;color:#e2e8f0}p{color:#94a3b8}}</style></head>
<body><main><h1>Back soon</h1><p>${escape(message || "We're doing some maintenance. Please check back in a few minutes.")}</p></main></body></html>`;
}

// ";" and ",": two Cookie headers joined by a proxy (or the Fetch API) come
// with ", " between them.
function cookieOf(cookieHeader, name) {
  const header = String(cookieHeader || "");
  for (const part of header.split(/[;,]/)) {
    const [k, ...v] = part.trim().split("=");
    if (k !== name) continue;
    // A malformed value can't be the preview code, and mustn't throw: the
    // middleware lets a request through when its check fails.
    try {
      return decodeURIComponent(v.join("="));
    } catch {
      return "";
    }
  }
  return "";
}

function queryOf(url, name) {
  try {
    return new URL(url || "/", "http://x").searchParams.get(name);
  } catch {
    return null;
  }
}

// The same text, compared in time that doesn't depend on where they differ,
// so the preview code can't be guessed a character at a time.
function sameText(a, b) {
  const x = String(a);
  const y = String(b);
  let diff = x.length ^ y.length;
  for (let i = 0; i < y.length; i += 1) diff |= (x.charCodeAt(i % (x.length || 1)) || 0) ^ y.charCodeAt(i);
  return diff === 0;
}

// Whether the request came over HTTPS: the connection itself, Express's
// req.protocol (its own "trust proxy" setting), or X-Forwarded-Proto when
// the package was told to believe the proxy in front (trustProxy).
function secureOf(req, trustProxy) {
  if (req.socket?.encrypted || req.protocol === "https") return true;
  if (!trustProxy) return false;
  const proto = String(req.headers?.["x-forwarded-proto"] || "").split(",").pop().trim().toLowerCase();
  return proto === "https";
}

// clientIp(req): the firewall's way of finding the visitor's address.
// Options: skip(req) (true lets a request through, e.g. health checks).
function createMaintenance(core, { clientIp, skip, trustProxy } = {}) {
  let allowFor = null;
  let allowSet = new IpSet([]);

  // A request, from its address, URL and Cookie header (hono.js has no
  // req), and whether it came over HTTPS (the cookie is Secure then): null
  // lets it in, a string lets it in with that Set-Cookie, and { html } is the
  // page it gets instead.
  function check(address, url, cookieHeader, secure = false) {
    const m = core.isOn("maintenance") ? core.maintenance() : null;
    if (!m?.on) return null;
    if (allowFor !== m.allow) {
      allowFor = m.allow;
      allowSet = new IpSet(m.allow || []);
    }
    const ip = parseIp(address || "");
    if (ip && allowSet.has(ip)) return null;
    if (m.bypass) {
      const given = queryOf(url, COOKIE);
      if (given !== null && sameText(given, m.bypass)) {
        return `${COOKIE}=${encodeURIComponent(m.bypass)}; Path=/; Max-Age=86400; HttpOnly; SameSite=Lax${secure ? "; Secure" : ""}`;
      }
      const kept = cookieOf(cookieHeader, COOKIE);
      if (kept && sameText(kept, m.bypass)) return null;
    }
    return { html: page(m.message) };
  }

  function middleware(req, res, next = () => {}) {
    try {
      if (!core.maintenance()?.on || skip?.(req)) return next();
      const answer = check(clientIp ? clientIp(req) : req.ip || req.socket?.remoteAddress || "", req.originalUrl || req.url, req.headers?.cookie,
        secureOf(req, trustProxy));
      if (typeof answer === "string") res.setHeader("set-cookie", answer);
      if (!answer?.html) return next();
      res.statusCode = 503;
      res.setHeader("retry-after", "600");
      res.setHeader("cache-control", "no-store");
      res.setHeader("content-type", "text/html; charset=utf-8");
      res.end(answer.html);
    } catch (error) {
      core.log("maintenance", "check failed, request passed:", error?.message);
      next();
    }
  }

  return { middleware, check };
}

module.exports = { createMaintenance, page, sameText };
