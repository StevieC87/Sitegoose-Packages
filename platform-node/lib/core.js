// What every module shares: the site's credentials, sending to the
// collector, logging, and the dashboard's module switches (Site settings →
// Server, GET /events/platform/config about once a minute). A module the
// dashboard turns off stays loaded but does nothing; until the switches
// arrive, or when they can't be fetched, every loaded module stays on.
// Sending never throws into the app.
//
// That request is also this service's check-in (X-Platform-App): its
// serverName (default the machine's name, as every module sends it), process
// ID, how long it has run and its memory, so Health → All systems can say it
// is running and when it was last heard from. Left out on the edge (next.js),
// which has no process to describe and no node:os: this file needs no Node
// built-ins, so os is asked for at run time, never required.
"use strict";

const VERSION = "0.3.13";
const TIMEOUT_MS = 5000;
// At shutdown (close(), and an uncaught exception's exit) everything waiting
// gets one overall deadline, so the package never outlasts a container's or
// PM2's grace period: each send waits at most what's left, none starts after
// it, and errors not sent by then wait in their file.
const EXIT_DEADLINE_MS = 5000;
const MIN_SYNC_S = 30;
const RETRY_S = 60;

// A dashboard header is added only when it is one of the nine the dashboard
// can produce (expresscollect/Analytics/platform.js, headersOf), in any case,
// with a value of visible ASCII, spaces and tabs, so no line break, control
// character or byte a server rejects gets through. A list of what's allowed,
// not of what isn't: whoever got into our servers still couldn't make this
// app grant another site its users' data (Access-Control-Allow-*), send
// every page elsewhere (Refresh), log everyone out (Clear-Site-Data) or
// change what a response is. Shared cases: sdk/protocols/header-cases.json.
const SECURITY_HEADERS = new Set(["strict-transport-security", "x-content-type-options", "x-frame-options",
  "referrer-policy", "permissions-policy", "cross-origin-opener-policy", "content-security-policy",
  "content-security-policy-report-only", "reporting-endpoints"]);
function safeHeader(pair) {
  return Array.isArray(pair) && pair.length === 2 && typeof pair[0] === "string" && SECURITY_HEADERS.has(pair[0].toLowerCase())
    && typeof pair[1] === "string" && /^[\x20-\x7e\t]*$/.test(pair[1]) && pair[1].length <= 4000;
}

function createCore(options) {
  const siteId = String(options.siteId || "");
  const secret = String(options.secret || "");
  const endpoint = String(options.endpoint || "").replace(/\/+$/, "");
  const valid = /^[a-f0-9]{24}$/i.test(siteId) && Boolean(secret) && Boolean(endpoint);
  const debug = Boolean(options.debug);
  // options.client names the integration for the dashboard (default "node").
  const userAgent = `analytics-platform-${options.client || "node"}/${VERSION}`;
  // Form-encoded, so any name is plain ASCII in a header. The name falls back
  // as the modules' does (index.js passes serverName only when it is set).
  // Null when it can't be built: the switches still sync, without it.
  const checkIn = () => {
    if (options.checkIn === false) return null;
    try {
      const os = globalThis.process?.getBuiltinModule?.("node:os");
      const server = String(options.serverName || os?.hostname() || "").slice(0, 100);
      if (!server || typeof process.memoryUsage !== "function") return null;
      return new URLSearchParams({
        server,
        kind: "process",
        pid: String(process.pid),
        up_s: String(Math.round(process.uptime())),
        rss_mb: String(Math.round(process.memoryUsage().rss / 1048576)),
        runtime: `Node ${process.versions.node}`,
      }).toString();
    } catch {
      return null;
    }
  };

  const log = (module, ...args) => {
    if (debug) console.warn(`[analytics-platform:${module}]`, ...args);
  };

  // The shutdown deadline (ms since 1970), or 0 while running normally.
  let deadline = 0;
  // Sends from now on finish within ms (the sooner of two deadlines wins).
  function within(ms = EXIT_DEADLINE_MS) {
    const ends = Date.now() + ms;
    deadline = deadline ? Math.min(deadline, ends) : ends;
    return deadline;
  }
  // Milliseconds left before the deadline, or null when there is none.
  const timeLeft = () => (deadline ? Math.max(0, deadline - Date.now()) : null);

  // JSON to the collector. auth: "body" puts site_id and sitesecret in the
  // body (the event endpoints); "bearer" sends the secret as a header (the
  // firewall). Resolves to the Response, or null when it couldn't be sent.
  //
  // A body JSON can't carry (a BigInt, a circular object) resolves to an
  // answer with `unsendable: true` and status 0: sending it again can never
  // work, so a caller must drop it rather than keep it to retry, which a
  // network failure (null) is for.
  async function send(module, path, { method = "POST", body, auth = "body", headers = {} } = {}) {
    if (!valid) return null;
    let payload;
    try {
      payload = body === undefined ? undefined
        : JSON.stringify(auth === "body" ? { site_id: siteId, sitesecret: secret, ...body } : body);
    } catch (error) {
      log(module, `could not turn what was to be sent to ${path} into JSON, dropped:`, error?.message);
      return UNSENDABLE;
    }
    const left = timeLeft();
    if (left !== null && left < 50) return null;
    const wait = left === null ? TIMEOUT_MS : Math.min(TIMEOUT_MS, left);
    try {
      const res = await fetch(`${endpoint}${path}`, {
        method,
        headers: {
          ...(payload === undefined ? {} : { "content-type": "application/json" }),
          ...(auth === "bearer" ? { authorization: `Bearer ${secret}` } : {}),
          "user-agent": userAgent,
          ...headers,
        },
        body: payload,
        signal: typeof AbortSignal.timeout === "function" ? AbortSignal.timeout(wait) : undefined,
      });
      if (!res.ok && res.status !== 304) log(module, `collector answered ${res.status} to ${path}`);
      return res;
    } catch (error) {
      log(module, `could not reach the collector (${path}):`, error?.message);
      return null;
    }
  }

  // ---- Module switches ----
  let switches = {};
  let securityHeaders = [];
  let flags = {};
  let maintenance = { on: false };
  let etag = "";
  let timer = null;
  let loaded = [];
  let inventoryRefresh = null;
  const configListeners = new Set();

  // False only when the dashboard turned the module off.
  const isOn = (name) => switches[name] !== false;

  async function syncSwitches() {
    let wait = RETRY_S;
    try {
      const app = checkIn();
      const res = await send("core", `/events/platform/config?site_id=${encodeURIComponent(siteId)}`, {
        method: "GET", auth: "bearer",
        headers: { "x-platform-modules": loaded.join(","), ...(app ? { "x-platform-app": app } : {}), ...(etag ? { "if-none-match": etag } : {}) },
      });
      if (res?.status === 200) {
        const data = await res.json();
        if (data?.v === 1 && data.modules && typeof data.modules === "object") {
          switches = data.modules;
          inventoryRefresh = data.inventory_refresh || null;
          securityHeaders = (Array.isArray(data.headers) ? data.headers : []).filter(safeHeader);
          flags = data.flags && typeof data.flags === "object" ? data.flags : {};
          maintenance = data.maintenance && typeof data.maintenance === "object" ? data.maintenance : { on: false };
          etag = res.headers.get("etag") || "";
        }
        wait = Math.max(MIN_SYNC_S, Number(data?.sync) || RETRY_S);
      } else if (res?.status === 304) wait = RETRY_S;
    } catch (error) {
      log("core", "could not read module switches:", error?.message);
    }
    for (const listener of configListeners) {
      try { await listener({ inventory_refresh: inventoryRefresh }); }
      catch (error) { log("core", "config listener failed:", error?.message); }
    }
    if (timer !== false) {
      timer = setTimeout(syncSwitches, wait * 1000);
      timer.unref?.();
    }
  }

  // Starts fetching the switches; `names` are the modules the code loaded.
  function start(names) {
    loaded = names;
    return valid ? syncSwitches() : Promise.resolve();
  }

  function stop() {
    clearTimeout(timer);
    timer = false;
    configListeners.clear();
  }

  // The security headers picked on the dashboard, as [name, value] pairs.
  const headers = () => securityHeaders;

  return {
    siteId, secret, endpoint, valid, debug, log, send, userAgent, version: VERSION, isOn, headers, start, stop, within, timeLeft,
    onConfig(listener) { configListeners.add(listener); return () => configListeners.delete(listener); },
    flags: () => flags,
    maintenance: () => maintenance,
  };
}

// What send() answers for a body that isn't JSON (see send).
const UNSENDABLE = Object.freeze({
  ok: false, status: 0, unsendable: true, headers: { get: () => null }, text: async () => "", json: async () => null,
});

// A copy of value as JSON will carry it (a BigInt as its digits, dates as
// ISO text, functions and undefined left out), or throws for what can never
// be sent (a circular object). For what the app passes to track() and
// audit(): checked when it is called, not found out at flush time.
function jsonSafe(value) {
  const text = JSON.stringify(value, (key, item) => (typeof item === "bigint" ? item.toString() : item));
  return text === undefined ? undefined : JSON.parse(text);
}

// Errors that say the visitor went away (closed the tab, lost the network)
// while the request was answered: not the server's fault, and never a 500
// in the Errors report. body-parser's own ("request aborted") are 400s
// already; these are what a write to a closed socket throws.
const DISCONNECT_CODES = new Set(["ECONNRESET", "EPIPE", "ECONNABORTED", "ERR_STREAM_PREMATURE_CLOSE", "ERR_STREAM_DESTROYED"]);
// gone: whether this request's own connection is closed (the socket, the
// Request's signal). An ECONNRESET from the app's own call to another server
// leaves the visitor's connection open and is reported as before.
function disconnected(error, gone) {
  if (!error || typeof error !== "object") return false;
  if (error.type === "request.aborted" || error.name === "ResponseAborted") return true;
  return Boolean(gone) && (DISCONNECT_CODES.has(error.code) || error.name === "AbortError");
}

// A Node built-in where the runtime has one, or null, with no require a
// bundler follows (the edge has none: next.js, hono.js). Node before 20.16
// has no getBuiltinModule and loads it the old way.
function builtin(name) {
  try {
    return globalThis.process?.getBuiltinModule?.(`node:${name}`)
      ?? (typeof require === "function" ? require(`node:${name}`) : null);
  } catch {
    return null;
  }
}

// The browser's visit, when the page passed it on (window.analyticsSession.getId()).
const SESSION_HEADER = "x-analytics-session";
function sessionOf(req) {
  const value = req?.headers?.[SESSION_HEADER];
  return typeof value === "string" ? value : "";
}

module.exports = { safeHeader, createCore, sessionOf, builtin, jsonSafe, disconnected, VERSION, EXIT_DEADLINE_MS, UNSENDABLE };
