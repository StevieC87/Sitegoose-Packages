// First-party proxy: serving the tracker from the site's own domain, so ad
// blockers don't hide visitors.
//
// Blockers stop analytics by recognising the address a script comes from and
// what it is called ("track.js", "collect"). The answer is to serve both from
// the site's own domain, which until now meant writing Nginx, Cloudflare or
// Vercel rules by hand. This app is already a server on that domain, so the
// package does it itself:
//
//   <prefix>/js/<rest>   ->  <endpoint>/<rest>                  (tracker files)
//   <prefix>/api/<rest>  ->  <endpoint>/collectanalytics/<rest> (the collector)
//
// The same two rules as the hand-written ones, so one install check covers
// both. The prefix comes from the site secret: not guessable from the page,
// and the same every time, so a browser's cache and a CDN in front stay valid.
//
// It runs before every other module: a visitor's beacon is our own traffic,
// not theirs, so it shouldn't be counted as a page of the site, timed as one,
// or turned away by the firewall's rate limit.
"use strict";

// No Node built-ins required: hono.js shares the rules below on any runtime.
const { builtin } = require("./core.js");

// The tracker files, by name: anything else is refused rather than forwarded.
const FILES = new Set(["track.js", "s.js", "snapshot.js", "replay.js", "survey.js", "banner.js",
  "leadform.js", "notice.js", "editor.js", "picker.js", "feedback.js", "shield.js", "widget.js", "share.js"]);
// A pinned version never changes; /v<major>/ follows new releases, so it's
// held for an hour, the same as the collector serves it with.
const TTL_PINNED_MS = 7 * 24 * 60 * 60 * 1000;
const TTL_MAJOR_MS = 60 * 60 * 1000;
// What a collector answer may be served as from the site's own domain. Its
// type comes from the collector, so anything but these three becomes plain
// text, and nosniff stops a browser guessing: a server that is no longer ours
// still can't answer <prefix>/api/… with a page that runs as the customer's
// own site. Shared cases: sdk/protocols/proxy-answer-cases.json.
const ANSWER_TYPES = new Set(["application/json", "text/plain", "image/webp"]);
function answerType(value) {
  const type = String(value || "").split(";")[0].trim().toLowerCase();
  return ANSWER_TYPES.has(type) && /^[\x20-\x7e]*$/.test(value) ? value : "text/plain; charset=utf-8";
}
// The headers a collector answer keeps: get(name) reads one of the answer's.
function answerHeaders(get) {
  const out = { "content-type": answerType(get("content-type")), "x-content-type-options": "nosniff" };
  for (const name of ["cache-control", "retry-after"]) {
    const value = get(name);
    if (value) out[name] = value;
  }
  return out;
}
// How long one upstream call may take. Short: a visitor's page is waiting on
// the tracker file, and a beacon nobody waits for still holds a socket and
// its memory while it hangs.
const TIMEOUT_MS = 2000;
// After this many failures in a row (no answer, or a 5xx) the collector is
// left alone for BREAKER_OPEN_MS: every call is answered at once (502) rather
// than each waiting out its own timeout. Then one call tries again.
const BREAKER_FAILURES = 3;
const BREAKER_OPEN_MS = 30 * 1000;
// A tracker file that couldn't be fetched isn't asked for again for this long.
const FILE_RETRY_MS = 30 * 1000;
const MAX_FAILED = 200;
const MAX_BODY = 6 * 1024 * 1024;
// The collector reads these; everything else, cookies above all, stays here.
const PASS_HEADERS = ["content-type", "user-agent", "accept-language", "referer", "origin",
  "sec-fetch-site", "sec-ch-ua", "sec-ch-ua-mobile", "sec-ch-ua-platform"];

const isEmptyObject = (value) => value !== null && typeof value === "object" && !Buffer.isBuffer(value)
  && Object.getPrototypeOf(value) === Object.prototype && Object.keys(value).length === 0;

const sha256 = (text) => builtin("crypto").createHash("sha256").update(text).digest("hex");
const prefixFor = (secret) => sha256(`proxy|${secret}`).slice(0, 8);
// Sent as X-Proxy-Key, so the collector believes the visitor addresses this
// proxy passes on: anyone can write X-Forwarded-For. Worked out from the
// secret as the collector does (expresscollect/utils/proxyKey.js).
const keyFor = (secret) => sha256(`proxykey|${secret}`).slice(0, 32);

// The breaker, shared by this proxy and hono.js's: resting() is true while
// the collector is being left alone; worked() and failed() after each call.
// When the pause ends one call tries again; the others keep the short
// answer until it has.
function createBreaker(now = () => Date.now()) {
  let failures = 0;
  let openUntil = 0;
  return {
    resting() {
      if (failures < BREAKER_FAILURES) return false;
      if (now() < openUntil) return true;
      openUntil = now() + TIMEOUT_MS;
      return false;
    },
    worked() {
      failures = 0;
    },
    failed() {
      failures += 1;
      if (failures >= BREAKER_FAILURES) openUntil = now() + BREAKER_OPEN_MS;
    },
  };
}

// Tracker files that couldn't be fetched lately: rest -> when. Any version
// number fits the file pattern, so it is kept short.
function createFailedFiles(now = () => Date.now()) {
  const failed = new Map();
  return {
    recent: (rest) => (failed.get(rest) || -Infinity) > now() - FILE_RETRY_MS,
    remember(rest) {
      failed.delete(rest);
      while (failed.size >= MAX_FAILED) failed.delete(failed.keys().next().value);
      failed.set(rest, now());
    },
    forget: (rest) => failed.delete(rest),
  };
}

// The answer while the collector is left alone: at once, telling the
// tracker (which treats a failed beacon as lost) when to try.
const RESTING_HEADERS = { "retry-after": String(BREAKER_OPEN_MS / 1000) };

// Which of ours a URL is: null when it isn't under the prefix, kind "" when
// it is but names nothing (a 404), else "js" or "api" with the rest.
function split(prefix, url) {
  if (!url.startsWith(`/${prefix}/`)) return null;
  const [path, search = ""] = url.split("?");
  const rest = path.slice(prefix.length + 2);
  const kind = rest.startsWith("js/") ? "js" : rest.startsWith("api/") ? "api" : "";
  const tail = rest.slice(kind.length + 1);
  if (kind === "" || tail === "" || tail.includes("..") || !/^[A-Za-z0-9/_.-]{1,120}$/.test(tail)) return { kind: "", tail: "", search: "" };
  return { kind, tail, search: search ? `?${search}` : "" };
}

// A tracker file's address: { pinned } when it is one, else null.
function fileOf(rest) {
  const match = /^v(\d+(?:\.\d+\.\d+)?)\/([a-z]+\.js)$/.exec(rest);
  return match && FILES.has(match[2]) ? { pinned: match[1].includes(".") } : null;
}

// Options: prefix (default: from the secret), enabled (default true);
// guard(req) (index.js: the firewall's address rules, so a denied or banned
// address gets no tracker and no collector either).
function createProxy(core, options = {}) {
  const enabled = options.enabled !== false;
  const prefix = String(options.prefix || prefixFor(core.secret)).replace(/[^a-zA-Z0-9_-]/g, "");
  const clientIp = typeof options.clientIp === "function" ? options.clientIp : null;
  const key = core.secret ? keyFor(core.secret) : "";
  // One copy of each tracker file, so a repeat visitor costs no upstream
  // request. A handful of small files: it never grows.
  const files = new Map();
  const breaker = createBreaker();
  const failedFiles = createFailedFiles();
  const guard = typeof options.guard === "function" ? options.guard : null;

  const on = () => enabled && core.valid && prefix !== "" && core.isOn("proxy");
  const scriptUrl = (version = "1") => `/${prefix}/js/v${version}/s.js`;
  const collectUrl = () => `/${prefix}/api/e`;

  async function serveFile(rest, res) {
    const file = fileOf(rest);
    if (!file) return false;
    const { pinned } = file;
    const held = files.get(rest);
    let body = held && held.at > Date.now() - (pinned ? TTL_PINNED_MS : TTL_MAJOR_MS) ? held.body : null;
    if (body === null && !failedFiles.recent(rest) && !breaker.resting()) {
      try {
        const answer = await fetch(`${core.endpoint}/${rest}`, { signal: AbortSignal.timeout(TIMEOUT_MS) });
        if (answer.status >= 500) breaker.failed();
        else breaker.worked();
        const text = answer.ok ? await answer.text() : "";
        if (text.length > 500 && text.length <= MAX_BODY) {
          body = text;
          files.set(rest, { body, at: Date.now() });
          failedFiles.forget(rest);
        } else failedFiles.remember(rest);
      } catch (error) {
        breaker.failed();
        failedFiles.remember(rest);
        core.log("proxy", `could not fetch ${rest}: ${error?.message}`);
      }
    }
    // Upstream is unreachable: an old copy beats no tracker at all.
    if (body === null && held) body = held.body;
    if (body === null) {
      res.writeHead(502).end();
      return true;
    }
    res.writeHead(200, {
      "content-type": "application/javascript; charset=utf-8",
      "cache-control": pinned ? "public, max-age=31536000, immutable" : "public, max-age=3600",
      "x-content-type-options": "nosniff",
      "content-length": Buffer.byteLength(body),
    }).end(body);
    return true;
  }

  // The request's body, however the app is put together: straight from the
  // stream, or from whatever a body parser mounted before us already read.
  // Express 4's parsers set req.body = {} even for a type they skip (the
  // tracker's text/plain), leaving the stream unread: that empty object isn't
  // the body. req._body is how they mark one they did read.
  function readBody(req) {
    const skipped = req._body !== true && isEmptyObject(req.body);
    if (req.readableEnded || (req.body !== undefined && !skipped)) {
      const parsed = req.body;
      if (parsed === undefined || parsed === null) return Promise.resolve("");
      if (typeof parsed === "string" || Buffer.isBuffer(parsed)) return Promise.resolve(parsed);
      return Promise.resolve(JSON.stringify(parsed));
    }
    return new Promise((resolve, reject) => {
      const chunks = [];
      let size = 0;
      req.on("data", (chunk) => {
        size += chunk.length;
        if (size > MAX_BODY) {
          req.destroy();
          reject(new Error("too large"));
          return;
        }
        chunks.push(chunk);
      });
      req.on("end", () => resolve(Buffer.concat(chunks)));
      req.on("error", reject);
    });
  }

  async function serveCollector(rest, req, res, search) {
    const method = String(req.method || "GET").toUpperCase();
    if (method === "OPTIONS") {
      // Same origin as the page, so a preflight shouldn't happen; answer it
      // cheaply rather than passing it on.
      res.writeHead(204, {
        "access-control-allow-methods": "GET, POST, OPTIONS",
        "access-control-allow-headers": "Content-Type",
        "access-control-max-age": "86400",
      }).end();
      return;
    }
    if (method !== "GET" && method !== "POST") {
      res.writeHead(404, { "content-type": "text/plain" }).end("Not found");
      return;
    }
    let body;
    try {
      body = method === "POST" ? await readBody(req) : undefined;
    } catch {
      res.writeHead(413).end();
      return;
    }
    const headers = {
      // The visitor's address: the collector needs it for the country, the
      // daily visitor ID and the per-visitor rate limit.
      "x-forwarded-for": (clientIp ? clientIp(req) : req.ip) || req.socket?.remoteAddress || "",
      "x-forwarded-proto": req.socket?.encrypted ? "https" : "http",
    };
    if (key) headers["x-proxy-key"] = key;
    for (const name of PASS_HEADERS) {
      if (req.headers[name]) headers[name] = req.headers[name];
    }
    // Left alone for now: answered straight away.
    if (breaker.resting()) {
      res.writeHead(502, RESTING_HEADERS).end();
      return;
    }
    try {
      const answer = await fetch(`${core.endpoint}/collectanalytics/${rest}${search}`, {
        method,
        headers,
        body,
        signal: AbortSignal.timeout(TIMEOUT_MS),
      });
      if (answer.status >= 500) breaker.failed();
      else breaker.worked();
      const data = Buffer.from(await answer.arrayBuffer());
      res.writeHead(answer.status, answerHeaders((name) => answer.headers.get(name))).end(data);
    } catch (error) {
      // The tracker already treats a failed beacon as lost and carries on.
      breaker.failed();
      core.log("proxy", `could not reach the collector: ${error?.message}`);
      if (!res.headersSent) res.writeHead(502).end();
      else res.end();
    }
  }

  // Express / Connect / node:http middleware. Anything that isn't ours is
  // passed straight on, so the cost to every other request is one compare.
  function middleware(req, res, next = () => {}) {
    if (!on()) return next();
    const ours = split(prefix, String(req.originalUrl || req.url || ""));
    if (!ours) return next();
    const { kind, tail, search } = ours;
    if (kind === "") {
      res.writeHead(404, { "content-type": "text/plain" }).end("Not found");
      return undefined;
    }
    // Denied, banned or listed addresses get nothing from us either (in
    // block mode); the rate limit and the browser check never apply here.
    if (guard?.(req)?.action === "block") {
      res.writeHead(403, { "content-type": "text/plain; charset=utf-8" }).end("Forbidden");
      return undefined;
    }
    const done = kind === "js"
      ? serveFile(tail, res).then((served) => {
        if (!served) res.writeHead(404, { "content-type": "text/plain" }).end("Not found");
      })
      : serveCollector(tail, req, res, search);
    return done.catch((error) => {
      core.log("proxy", `failed: ${error?.message}`);
      if (!res.headersSent) res.writeHead(502).end();
    });
  }

  return { prefix, scriptUrl, collectUrl, middleware, enabled: on };
}

module.exports = {
  answerHeaders, answerType, createProxy, createBreaker, createFailedFiles, prefixFor, keyFor, split, fileOf, PASS_HEADERS, TTL_PINNED_MS, TTL_MAJOR_MS, TIMEOUT_MS,
  MAX_BODY, RESTING_HEADERS, BREAKER_FAILURES, BREAKER_OPEN_MS, FILE_RETRY_MS,
};
