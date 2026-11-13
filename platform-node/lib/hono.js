// Hono, on any runtime it runs on (Node, Bun, Deno, Cloudflare Workers,
// Vercel and Netlify edge): what platform.middleware() does on Node, in one
// middleware, in the same order: the ad blocker proxy, security headers,
// crawler counts, the firewall, maintenance mode and Server speed, plus 5xx
// errors with their breadcrumbs. On the middleware: form protection, track /
// identify / lead, audit, failed logins, feature flags and job(). Everything
// but what needs the machine itself (inventory, posture, resources). No Node
// built-ins, as next.js.
//
//   import { createHonoPlatform } from "analytics-platform/hono";
//   app.use(createHonoPlatform({ siteId, secret, endpoint }));
//
// Everything is set up on the first request, not when the file loads:
// Workers allow no timers or fetches then, and their secrets only arrive
// with a request (c.env), so the options can be a function of the context.
"use strict";

const { createCore, builtin, disconnected } = require("./core.js");
const { createNextFirewall, clientIp, edgeError } = require("./next.js");
const { createPerformance, normalizeRoute, NOT_FOUND } = require("./performance.js");
const { createQueries, watchDatabase } = require("./queries.js");
const { createQueues } = require("./queues.js");
const { createCrawlers, detect } = require("./crawlers.js");
const { createMaintenance } = require("./maintenance.js");
const { createForms } = require("./forms.js");
const { createAnalytics, randomUUID } = require("./analytics.js");
const { createAudit } = require("./audit.js");
const { createFlags } = require("./flags.js");
const { routedToPage } = require("./bans.js");
const {
  answerHeaders, split, fileOf, createBreaker, createFailedFiles, PASS_HEADERS, TTL_PINNED_MS, TTL_MAJOR_MS, TIMEOUT_MS, MAX_BODY, RESTING_HEADERS,
} = require("./proxy.js");

const FLUSH_MS = 60 * 1000;
// A cold start waits this long for the dashboard's settings (maintenance
// mode, the headers), as the firewall does for its rules.
const FIRST_WAIT_MS = 1500;
const IP = Symbol("analytics.ip");
const MODULES = ["proxy", "headers", "crawlers", "firewall", "maintenance", "performance", "errors", "forms", "analytics", "audit", "flags"];
const SPAM = "Your message looks automated, so it wasn't sent. Please try again.";

// Which runtime this is, for the error's runtime and the timing rows.
function runtimeOf() {
  // Netlify's Edge Functions run on Deno, but as Workers do (below).
  if (globalThis.Netlify && globalThis.Deno) return { name: "Netlify Edge", version: String(globalThis.Deno.version?.deno || "") };
  if (globalThis.Bun) return { name: "Bun", version: String(globalThis.Bun.version || "") };
  if (globalThis.Deno) return { name: "Deno", version: String(globalThis.Deno.version?.deno || "") };
  if (globalThis.navigator?.userAgent === "Cloudflare-Workers") return { name: "Cloudflare Workers", version: "" };
  if (globalThis.EdgeRuntime) return { name: "Edge", version: "" };
  if (globalThis.process?.versions?.node) return { name: "Node", version: globalThis.process.versions.node };
  return { name: "", version: "" };
}

// The connection's own address, as each of Hono's adapters hands it over
// (what hono's getConnInfo reads): Node's request, Bun's server, Deno's
// serve info, Netlify's context. Workers have none: Cloudflare's header is
// the visitor; Vercel's edge has its x-real-ip (next.js).
function connectionIp(c, runtime) {
  if (runtime === "Cloudflare Workers") return c.req.header("cf-connecting-ip") || "";
  if (runtime === "Edge") return clientIp(c.req.raw);
  const env = c.env || {};
  return env.context?.ip
    || env.incoming?.socket?.remoteAddress
    || (typeof env.requestIP === "function" ? env.requestIP(c.req.raw)?.address : "")
    || env.remoteAddr?.hostname
    || "";
}

// The machine's name where the runtime has node:os, else "".
function hostName() {
  try {
    return String(builtin("os")?.hostname?.() || "");
  } catch {
    return "";
  }
}

// Node, Bun and Deno have no waitUntil: the process outlives the response,
// so what's sent just runs on. Netlify's is on its context (hono/netlify
// hands it over as c.env.context).
const DETACHED = { waitUntil: (promise) => promise?.catch?.(() => {}) };
const contextOf = (c) => {
  try {
    return c.executionCtx;
  } catch {
    // Hono throws when the runtime has none
    return typeof c.env?.context?.waitUntil === "function" ? c.env.context : DETACHED;
  }
};
const now = () => globalThis.performance?.now?.() ?? Date.now();

// ---- Breadcrumbs ----
// The request being handled, on runtimes with AsyncLocalStorage (Node, Bun,
// Deno, Workers with nodejs_compat): an error captured without c, and an
// outgoing request, still know which request they came from. Without it,
// outgoing requests aren't recorded, and captureException and addBreadcrumb
// need c.
const CRUMB_MAX = 15;
const storage = (() => {
  try {
    const Storage = globalThis.AsyncLocalStorage ?? builtin("async_hooks")?.AsyncLocalStorage;
    return typeof Storage === "function" ? new Storage() : null;
  } catch {
    return null;
  }
})();
// Each request's own: c -> { c, own, trail, event }.
const stores = new WeakMap();
// The collectors in use: a package's own calls aren't steps of the request.
const collectors = new Set();
const WRAPPED = Symbol.for("analytics-platform.fetch");
let watching = false;

function addCrumb(store, crumb) {
  if (!store) return;
  store.trail.push({ ...crumb, text: String(crumb.text).slice(0, 200), at: Date.now() });
  if (store.trail.length > CRUMB_MAX) store.trail.shift();
}

const isOurs = (url) => [...collectors].some((collector) => url === collector || url.startsWith(`${collector}/`));

// Outgoing requests: on Node from its diagnostics channels, as errors.js
// does (fetch and http.request, nothing patched); the other runtimes publish
// nothing there, so fetch is wrapped, once.
function watchRequests(runtime) {
  if (!storage) return;
  const channels = runtime === "Node" ? builtin("diagnostics_channel") : null;
  if (channels) {
    if (watching) return;
    watching = true;
    const outgoing = new WeakMap();
    const started = (request, address) => {
      const store = storage.getStore();
      const url = address.split(/[?#]/)[0];
      if (store && !isOurs(url)) outgoing.set(request, { store, text: `${request.method} ${url}` });
    };
    const ended = (request, status) => {
      const begun = outgoing.get(request);
      if (!begun) return;
      outgoing.delete(request);
      addCrumb(begun.store, { type: "request", text: begun.text, status });
    };
    // Cancelled by the app, as the tracker treats a cancelled fetch: not a failure.
    const failed = (request, error) => (error?.name === "AbortError" ? outgoing.delete(request) : ended(request, 0));
    // A subscriber that throws reaches the app as an uncaught exception.
    const watch = (channel, fn) => channels.subscribe(channel, (message) => {
      try {
        fn(message);
      } catch {
        // the step is left out
      }
    });
    watch("undici:request:create", ({ request }) => started(request, `${request.origin}${request.path}`));
    watch("undici:request:headers", ({ request, response }) => ended(request, response.statusCode));
    watch("undici:request:error", ({ request, error }) => failed(request, error));
    watch("http.client.request.start", ({ request }) => started(request, `${request.protocol}//${request.getHeader("host")}${request.path}`));
    watch("http.client.response.finish", ({ request, response }) => ended(request, response.statusCode));
    watch("http.client.request.error", ({ request, error }) => failed(request, error));
    return;
  }
  const original = globalThis.fetch;
  if (typeof original !== "function" || original[WRAPPED]) return;
  const wrapped = function fetch(input, init) {
    const answer = Reflect.apply(original, globalThis, [input, init]);
    const store = storage.getStore();
    if (!store) return answer;
    try {
      const url = String(typeof input === "object" && input?.url ? input.url : input).split(/[?#]/)[0];
      if (!isOurs(url)) {
        const text = `${String(init?.method || input?.method || "GET").toUpperCase()} ${url}`;
        answer.then(
          (res) => addCrumb(store, { type: "request", text, status: res.status }),
          (error) => error?.name === "AbortError" || addCrumb(store, { type: "request", text, status: 0 }),
        );
      }
    } catch {
      // the step is left out
    }
    return answer;
  };
  wrapped[WRAPPED] = true;
  globalThis.fetch = wrapped;
}

// ---- The ad blocker proxy ----
// proxy.js's two rules on a Web Request: the tracker files, held in memory,
// and the collector calls passed through with fetch.
async function sha256(text) {
  const subtle = globalThis.crypto?.subtle ?? builtin("crypto")?.webcrypto?.subtle;
  const digest = new Uint8Array(await subtle.digest("SHA-256", new TextEncoder().encode(text)));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

const timeout = () => (typeof AbortSignal.timeout === "function" ? AbortSignal.timeout(TIMEOUT_MS) : undefined);
const notFound = () => new Response("Not found", { status: 404, headers: { "content-type": "text/plain" } });

// The body, up to MAX_BODY: more throws, with what was read dropped.
async function readBody(request) {
  if (Number(request.headers.get("content-length")) > MAX_BODY) throw new Error("too large");
  if (!request.body) return undefined;
  const reader = request.body.getReader();
  const chunks = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > MAX_BODY) {
      reader.cancel().catch(() => {});
      throw new Error("too large");
    }
    chunks.push(value);
  }
  const body = new Uint8Array(size);
  let at = 0;
  for (const chunk of chunks) {
    body.set(chunk, at);
    at += chunk.byteLength;
  }
  return body;
}

async function createEdgeProxy(core, options) {
  const prefix = String(options.prefix || (await sha256(`proxy|${core.secret}`)).slice(0, 8)).replace(/[^a-zA-Z0-9_-]/g, "");
  const key = core.secret ? (await sha256(`proxykey|${core.secret}`)).slice(0, 32) : "";
  const files = new Map();
  // proxy.js's: three failures in a row and the collector is left alone for
  // a while; a file that couldn't be fetched isn't asked for again at once.
  const breaker = createBreaker();
  const failedFiles = createFailedFiles();

  async function serveFile(rest) {
    const file = fileOf(rest);
    if (!file) return notFound();
    const held = files.get(rest);
    let body = held && held.at > Date.now() - (file.pinned ? TTL_PINNED_MS : TTL_MAJOR_MS) ? held.body : null;
    if (body === null && !failedFiles.recent(rest) && !breaker.resting()) {
      try {
        const answer = await fetch(`${core.endpoint}/${rest}`, { signal: timeout() });
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
    if (body === null) return new Response(null, { status: 502 });
    return new Response(body, {
      headers: {
        "content-type": "application/javascript; charset=utf-8",
        "cache-control": file.pinned ? "public, max-age=31536000, immutable" : "public, max-age=3600",
        "x-content-type-options": "nosniff",
      },
    });
  }

  async function serveCollector(rest, request, search, ip, url) {
    const method = request.method.toUpperCase();
    if (method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "access-control-allow-methods": "GET, POST, OPTIONS",
          "access-control-allow-headers": "Content-Type",
          "access-control-max-age": "86400",
        },
      });
    }
    if (method !== "GET" && method !== "POST") return notFound();
    let body;
    try {
      body = method === "POST" ? await readBody(request) : undefined;
    } catch {
      return new Response(null, { status: 413 });
    }
    // The visitor's address, for the collector's country, daily visitor ID
    // and per-visitor rate limit; cookies stay here.
    const headers = { "x-forwarded-for": ip, "x-forwarded-proto": url.protocol === "https:" ? "https" : "http" };
    if (key) headers["x-proxy-key"] = key;
    for (const name of PASS_HEADERS) {
      const value = request.headers.get(name);
      if (value) headers[name] = value;
    }
    // Left alone for now: answered straight away.
    if (breaker.resting()) return new Response(null, { status: 502, headers: RESTING_HEADERS });
    try {
      const answer = await fetch(`${core.endpoint}/collectanalytics/${rest}${search}`, { method, headers, body, signal: timeout() });
      if (answer.status >= 500) breaker.failed();
      else breaker.worked();
      return new Response(await answer.arrayBuffer(), { status: answer.status, headers: answerHeaders((name) => answer.headers.get(name)) });
    } catch (error) {
      // The tracker already treats a failed beacon as lost and carries on.
      breaker.failed();
      core.log("proxy", `could not reach the collector: ${error?.message}`);
      return new Response(null, { status: 502 });
    }
  }

  // The answer to one of ours, or undefined for every other request.
  // guard(): the firewall's address rules (a Response when blocked).
  async function answer(request, url, ip, guard) {
    if (!prefix || !core.isOn("proxy")) return undefined;
    const ours = split(prefix, url.pathname + url.search);
    if (!ours) return undefined;
    if (ours.kind === "") return notFound();
    // Denied, banned or listed addresses get nothing from us either; never
    // the rate limit or the browser check.
    const blocked = guard?.();
    if (blocked) return blocked;
    try {
      return ours.kind === "js" ? await serveFile(ours.tail) : await serveCollector(ours.tail, request, ours.search, ip, url);
    } catch (error) {
      core.log("proxy", `failed: ${error?.message}`);
      return new Response(null, { status: 502 });
    }
  }

  return {
    answer,
    urls: {
      prefix,
      scriptUrl: (version = "1") => `/${prefix}/js/v${version}/s.js`,
      collectUrl: () => `/${prefix}/api/e`,
    },
  };
}

// The security headers the response doesn't already have: the app's own win.
function addHeaders(c, pairs) {
  let headers = c.res.headers;
  for (const [name, value] of pairs) {
    if (headers.has(name)) continue;
    try {
      headers.set(name, value);
    } catch {
      // A Response from fetch() has headers that can't change: a copy can.
      c.res = new Response(c.res.body, c.res);
      headers = c.res.headers;
      headers.set(name, value);
    }
  }
}

// The form's fields, read from a copy of the body so the route can still read
// it. Once the route has read it, from c.req's own parsers, which keep what
// they read.
async function formFields(c) {
  const type = String(c.req.header("content-type") || "").toLowerCase();
  const json = type.includes("json");
  if (!json && !type.includes("form")) return {};
  try {
    const raw = c.req.raw;
    if (raw.bodyUsed) return json ? await c.req.json() : await c.req.parseBody({ all: true });
    const copy = raw.clone();
    if (json) return await copy.json();
    const fields = {};
    for (const [name, value] of await copy.formData()) {
      fields[name] = fields[name] === undefined ? value : [].concat(fields[name], value);
    }
    return fields;
  } catch {
    return {};
  }
}

// options: { siteId, secret, endpoint, trustProxy, mode, skip, counter,
// serverName, debug }, or (c) => those, for secrets in c.env. Each module
// (MODULES) is off with false; proxy takes { prefix }, maintenance { skip(c) }.
function createHonoPlatform(options = {}) {
  let parts = null;
  // The same, once set up, for what must answer straight away (track, isEnabled).
  let current = null;
  const unwatchedQueues = [];
  // Sends still on their way, for flush().
  const pending = new Set();
  const track = (promise) => {
    pending.add(promise);
    promise.finally(() => pending.delete(promise)).catch(() => {});
    return promise;
  };
  // Errors already sent: one the app captured and threw on is sent once.
  const seen = new WeakSet();

  async function setUp(c) {
    const resolved = typeof options === "function" ? options(c) : options;
    const on = (name) => resolved[name] !== false;
    const runtime = runtimeOf();
    const { trustProxy } = resolved;
    // trustProxy: "cloudflare", a number of proxies in X-Forwarded-For, a
    // function of the context, or nothing: the connection's own address.
    // "cloudflare" believes CF-Connecting-IP only from a connection whose
    // address is Cloudflare's, or on Workers, where Cloudflare sets it.
    const ipOf = typeof trustProxy === "function" ? (ctx) => String(trustProxy(ctx) || "")
      : trustProxy === "cloudflare" ? (ctx) => clientIp(ctx.req.raw, trustProxy, connectionIp(ctx, runtime.name))
        : Number.isInteger(trustProxy) && trustProxy > 0
          ? (ctx) => clientIp(ctx.req.raw, trustProxy)
          : (ctx) => connectionIp(ctx, runtime.name);
    const core = createCore({ ...resolved, client: "hono", checkIn: false });
    const serverName = String(resolved.serverName || "");
    const runtimeName = [runtime.name, runtime.version].filter(Boolean).join(" ");
    // On Workers (and Vercel's and Netlify's edge, run the same way) an
    // instance may not live to the next minute, and its timers don't run
    // between requests: the requests themselves send, at most once a
    // minute, what they have (the collector adds a minute's rows up).
    // "Workers" below means all three.
    const workers = ["Cloudflare Workers", "Edge", "Netlify Edge"].includes(runtime.name);
    // The address is the one found above.
    const firewall = on("firewall") ? createNextFirewall({
      ...resolved,
      // Named for the Firewall tab: a process (Node, Bun, Deno) by its
      // machine, an edge instance only when serverName is given.
      serverName: serverName || (workers ? "" : hostName()),
      trustProxy: (request) => request[IP] || "",
    }) : null;
    // A process that stays up sends the firewall's events every few seconds,
    // as the Node firewall does; on Workers the next flagged request does.
    if (firewall && !workers) setInterval(() => firewall.flush(), 5000).unref?.();
    const proxy = on("proxy") && core.valid ? await createEdgeProxy(core, typeof resolved.proxy === "object" ? resolved.proxy : {}) : null;
    if (core.endpoint) collectors.add(core.endpoint);
    if (on("errors")) watchRequests(runtime.name);
    const loaded = MODULES.filter(on);
    const switches = core.start(loaded);
    const p = {
      core,
      runtime,
      serverName,
      ipOf,
      workers,
      proxy,
      firewall,
      headers: on("headers"),
      crawlers: on("crawlers") ? createCrawlers(core, { serverName, runtime: runtimeName, timer: !workers }) : null,
      maintenance: on("maintenance") ? createMaintenance(core) : null,
      skipMaintenance: resolved.maintenance?.skip,
      performance: on("performance") ? createPerformance(core, { serverName, runtime: runtimeName, timer: !workers }) : null,
      // Database queries (watchDatabase) and outgoing calls (Node's
      // diagnostics channels, where the runtime has them), on Server speed's switch.
      queries: on("performance") && (resolved.queries !== false || resolved.calls !== false)
        ? createQueries(core, { serverName, runtime: runtimeName, timer: !workers, queries: resolved.queries !== false, calls: resolved.calls !== false })
        : null,
      // Job queues (watchQueue): read every minute, so a process that stays
      // up only; Workers can't reach a Redis queue anyway.
      queues: on("performance") && resolved.queues !== false && !workers ? createQueues(core, { serverName, runtime: runtimeName }) : null,
      errors: on("errors"),
      forms: on("forms") ? createForms(core, { clientIp: (req) => req.ip }) : null,
      analytics: on("analytics") ? createAnalytics(core) : null,
      audit: on("audit") ? createAudit(core, { clientIp: (req) => req.ip }) : null,
      flags: on("flags") ? createFlags(core) : null,
      // Events and audit entries queued on Workers with no request to carry them.
      unsent: false,
      switches,
      // Until they arrive, or FIRST_WAIT_MS passes.
      settings: (on("maintenance") || on("headers") || on("flags")) && core.valid
        ? Promise.race([switches, new Promise((resolve) => setTimeout(resolve, FIRST_WAIT_MS).unref?.())])
        : null,
      lastFlush: Date.now(),
      // Errors captured outside any request on Workers (report()).
      held: [],
    };
    p.settings?.then(() => { p.settings = null; });
    return p;
  }

  // Set up once, by whichever request comes first; a set-up that failed is
  // tried again by the next.
  // With options that are a function of c, the first call needs c, or
  // anything with the env it reads ({ env }).
  function ready(c) {
    if (!parts && typeof options === "function" && !c) {
      throw new Error("[analytics-platform] the options are a function of c: pass c (or { env }) until a request has come through");
    }
    parts ||= setUp(c).then((p) => {
      // Queues handed to watchQueue() before the platform was set up.
      for (const queue of unwatchedQueues.splice(0)) p.queues?.watchQueue(queue);
      return (current = p);
    }, (error) => {
      parts = null;
      throw error;
    });
    return parts;
  }

  // fn(p), once set up; c (or the request being handled) sets up when nothing has yet.
  function run(c, fn) {
    if (current) return Promise.resolve(fn(current));
    try {
      return ready(c || storage?.getStore()?.c).then(fn);
    } catch (error) {
      return Promise.reject(error);
    }
  }
  const canRun = (c) => Boolean(current || c || storage?.getStore()?.c || typeof options !== "function");

  // The execution context to carry a send: c's, or the request being handled's.
  const eventOf = (c) => (c && contextOf(c)) || storage?.getStore()?.event || null;

  // What a queued send needs on Workers: to go now, carried by the request
  // (or by the next one); elsewhere the module's own timer batches it.
  function soon(p, c, flush) {
    if (!p.workers) return;
    const event = eventOf(c);
    if (event?.waitUntil) event.waitUntil(track(Promise.resolve(flush())));
    else p.unsent = true;
  }

  // What analytics.js and audit.js read on a Node request: the visit the
  // page passed on, and the address.
  const reqOf = (p, c) => {
    if (!c?.req) return undefined;
    let ip = "";
    try {
      ip = p.ipOf(c);
    } catch {
      // without the address
    }
    return { headers: { "x-analytics-session": c.req.header("x-analytics-session") || undefined }, ip };
  };

  function routeOf(c, own, status) {
    const matched = c.req.routePath;
    return matched && matched !== own ? matched : status === 404 ? NOT_FOUND : normalizeRoute(c.req.path);
  }

  // One error, sent now; its request's fields are read now too (the route
  // is the one running).
  function report(error, c, store, { status, kind }) {
    // The visitor went away mid-request: not a server error.
    if (disconnected(error, c?.req?.raw?.signal?.aborted)) return;
    const fields = store?.job ? { method: "JOB", path: store.job, route: store.job, session: "" } : c ? {
      method: c.req.method,
      path: c.req.path,
      route: routeOf(c, store?.own, status),
      session: c.req.header("x-analytics-session") || "",
    } : {};
    const at = Date.now();
    const trail = store?.trail.length ? { breadcrumbs: store.trail.map(({ at: when, ...crumb }) => ({ ...crumb, ms: at - when })) } : {};
    const event = store?.event || (c ? contextOf(c) : null);
    const sent = track((parts || ready(c)).then((p) => {
      if (!p.errors || !p.core.isOn("errors")) return null;
      const row = {
        ...edgeError(error, { kind, status, runtime: p.runtime.name, runtimeVersion: p.runtime.version, serverName: p.serverName, ...fields }),
        // An error the app caught has no status unless it says so, as in the main package.
        status_code: Number(status) || 0,
        ...trail,
      };
      // On Workers, with no request to wait for it, a fetch is cancelled
      // once the response is out: the next request sends it.
      if (!event && p.workers) {
        if (p.held.length < 10) p.held.push(row);
        return null;
      }
      return p.core.send("errors", "/events/server-errors", { body: { errors: [row] } });
    }));
    (event || DETACHED).waitUntil?.(sent);
  }

  function sendHeld(p) {
    const errors = p.held.splice(0);
    return errors.length ? p.core.send("errors", "/events/server-errors", { body: { errors } }) : null;
  }

  async function analyticsPlatform(c, next) {
    const p = await ready(c);
    const event = contextOf(c);
    if (p.switches) {
      event.waitUntil?.(p.switches);
      p.switches = null;
    }
    if (p.held.length) event.waitUntil?.(track(sendHeld(p)));
    if (p.workers && p.firewall?.due()) event.waitUntil?.(track(p.firewall.flush()));
    if (p.unsent) {
      p.unsent = false;
      event.waitUntil?.(track(Promise.all([p.analytics?.flush(), p.audit?.flush()])));
    }
    const request = c.req.raw;
    let ip = "";
    try {
      ip = p.ipOf(c);
      request[IP] = ip;
    } catch {
      // a frozen request: the firewall then sees no address and lets it pass
    }

    // The tracker's own addresses first: a visitor's beacon is our traffic,
    // not a page of the site, so it isn't counted, timed or rate-limited.
    const url = new URL(request.url);
    if (p.proxy) {
      const guard = p.firewall ? () => p.firewall.checkAddress(ip, { method: request.method, path: url.pathname, userAgent: c.req.header("user-agent") || "" }, event) : null;
      const answer = await p.proxy.answer(request, url, ip, guard);
      if (answer) return answer;
    }

    const arrived = now();
    const bot = p.crawlers ? detect(c.req.header("user-agent")) : "";
    // A crawler the firewall turns away is still a crawler, with the status it got.
    const counted = (response) => {
      if (bot) {
        p.crawlers.record({
          bot,
          path: url.pathname,
          status: response?.status || 200,
          bytes: Number(response?.headers.get("content-length")) || 0,
          ms: now() - arrived,
          ip,
        });
      }
    };
    const answered = (response) => {
      try {
        if (p.headers && p.core.isOn("headers")) {
          for (const [name, value] of p.core.headers()) if (!response.headers.has(name)) response.headers.set(name, value);
        }
        counted(response);
      } catch {
        // never break a response over reporting
      }
      return response;
    };

    // On a cold start the firewall's rules and the dashboard's settings are
    // waited for together.
    // late.static: a static-looking request let through, counted after the
    // response if a route took it (firewall.md, `rate`).
    const late = {};
    const checking = p.firewall?.(request, event, late);
    if (p.settings) await p.settings;
    const blocked = await checking;
    if (blocked) return answered(blocked);

    let cookie = null;
    if (p.maintenance) {
      try {
        const answer = p.skipMaintenance?.(c) ? null : p.maintenance.check(ip, url.pathname + url.search, c.req.header("cookie"), url.protocol === "https:");
        if (answer?.html) {
          return answered(new Response(answer.html, {
            status: 503,
            headers: { "retry-after": "600", "cache-control": "no-store", "content-type": "text/html; charset=utf-8" },
          }));
        }
        cookie = answer;
      } catch (error) {
        p.core.log("maintenance", "check failed, request passed:", error?.message);
      }
    }

    // Hono catches what a route throws and answers it (app.onError); the
    // error is left on c.error.
    const started = now();
    const store = { c, own: c.req.routePath, trail: [], event };
    stores.set(c, store);
    const go = () => (storage ? storage.run(store, next) : next());
    await (p.queries ? p.queries.bind(c, go) : go());

    try {
      const status = c.res?.status || 200;
      const route = routeOf(c, store.own, status);
      const method = c.req.method.toUpperCase().slice(0, 10);
      const filed = p.performance?.record({ method, route, status, ms: now() - started });
      if (filed !== undefined) p.queries?.finish(c, method, filed);
      if (p.headers && p.core.isOn("headers")) addHeaders(c, p.core.headers());
      if (cookie) c.header("set-cookie", cookie, { append: true });
      counted(c.res);
      if (late.static) {
        // The route the request ended on, when it isn't this middleware's
        // own: "/search/:q" took "/search/x.css". serveStatic answers a
        // file's Content-Type, so its files are left alone.
        const matched = c.req.routePath;
        const routed = matched !== store.own && routedToPage(matched, c.res?.headers.get("content-type"));
        const counting = track(p.firewall.countStatic(late.static, status, routed));
        event.waitUntil?.(counting);
      }

      const error = c.error;
      if (error && status >= 500 && !(typeof error === "object" && seen.has(error))) {
        if (typeof error === "object") seen.add(error);
        report(error, c, store, { status, kind: "handled" });
      }
      if (p.workers && Date.now() - p.lastFlush >= FLUSH_MS) {
        p.lastFlush = Date.now();
        event.waitUntil?.(track(Promise.all([p.performance?.flush(), p.queries?.flush(), p.crawlers?.flush()])));
      }
    } catch {
      // never break a response over reporting
    }
    return undefined;
  }

  // An error the app catches itself: c (or, where the runtime has
  // AsyncLocalStorage, the request being handled) gives its route and
  // breadcrumbs; { status } its status. Returns nothing and never throws.
  analyticsPlatform.captureException = (error, c, { status } = {}) => {
    try {
      const store = (c && stores.get(c)) || storage?.getStore() || null;
      const ctx = c || store?.c || null;
      if (!parts && !ctx) return;
      if (error && typeof error === "object") seen.add(error);
      report(error, ctx, store, { status, kind: "handled" });
    } catch {
      // never throw into the app
    }
  };

  // A step of your own in the trail sent with an error in this request.
  analyticsPlatform.addBreadcrumb = (text, c) => {
    addCrumb((c && stores.get(c)) || storage?.getStore() || null, { type: "note", text });
  };

  // Form protection (forms.js): checks the form in this request before you
  // accept it, without using up its body. Options: fields (instead of the
  // body), email, name, form. Resolves to { ok, spam, reasons, checked }.
  analyticsPlatform.checkForm = async (c, formOptions = {}) => {
    const unchecked = { ok: true, spam: false, reasons: [], checked: false };
    try {
      const p = await ready(c);
      if (!p.forms) return unchecked;
      let ip = "";
      try {
        ip = p.ipOf(c);
      } catch {
        // checked without the address
      }
      const fields = formOptions.fields || await formFields(c);
      return await p.forms.checkForm({ ip }, { ...formOptions, fields });
    } catch {
      return { ...unchecked, reasons: ["unchecked"] };
    }
  };

  // Middleware for a form's route: spam gets a 422 (or your onSpam(c,
  // result)); otherwise c.get("formCheck") holds the result and the route runs.
  analyticsPlatform.protectForm = (formOptions = {}) => async function analyticsProtectForm(c, next) {
    const result = await analyticsPlatform.checkForm(c, formOptions);
    c.set("formCheck", result);
    if (!result.spam) {
      await next();
      return undefined;
    }
    if (formOptions.onSpam) return formOptions.onSpam(c, result);
    return c.text(SPAM, 422);
  };

  // The ad blocker proxy's addresses for the page's script tag, on this
  // site's own domain; null when the proxy is off.
  analyticsPlatform.proxy = async (c) => (await run(c, (p) => p)).proxy?.urls || null;

  // Server events (analytics.js), with the same arguments as the main
  // package's, c in place of req to link them to the visit. track()
  // returns the event_uid, or "" when it can't be queued.
  analyticsPlatform.track = (name, fields = {}, { c } = {}) => {
    try {
      if (!name || typeof name !== "string" || !canRun(c)) return "";
      if (current) {
        const id = current.analytics?.track(name, fields, { req: reqOf(current, c) }) || "";
        if (id) soon(current, c, () => current.analytics.flush());
        return id;
      }
      // Not set up yet: queued once it is, under the id given now.
      const id = fields.event_uid || randomUUID();
      run(c, (p) => {
        if (p.analytics?.track(name, { ...fields, event_uid: id }, { req: reqOf(p, c) })) soon(p, c, () => p.analytics.flush());
      }).catch(() => {});
      return id;
    } catch {
      return "";
    }
  };

  // A send the caller may not wait for: on Workers it is carried by the request.
  const carried = (c, promise) => {
    eventOf(c)?.waitUntil?.(track(promise));
    return promise;
  };

  analyticsPlatform.identify = (userId, { c, session_id, traits } = {}) => carried(c,
    run(c, (p) => (p.analytics ? p.analytics.identify(userId, { req: reqOf(p, c), session_id, traits }) : false)).catch(() => false));

  analyticsPlatform.lead = (fields = {}, { c } = {}) => carried(c,
    run(c, (p) => (p.analytics ? p.analytics.lead(fields, { req: reqOf(p, c) }) : null)).catch(() => null));

  // audit("user.role_changed", { actor, target, details, c }): c adds the
  // actor's address and visit (Security → Audit log).
  analyticsPlatform.audit = (action, { c, ...entry } = {}) => {
    if (!canRun(c)) return;
    run(c, (p) => {
      if (!p.audit) return;
      p.audit.audit(action, { ...entry, req: reqOf(p, c) });
      soon(p, c, () => p.audit.flush());
    }).catch(() => {});
  };

  // A failed login (bot protection): pass c, or the address. Past the
  // site's limit the address is banned here at once, and on the other servers
  // within a minute or two.
  analyticsPlatform.loginFailed = (cOrIp) => {
    const c = typeof cOrIp === "object" && cOrIp ? cOrIp : null;
    if (!canRun(c)) return;
    run(c, (p) => {
      let ip = typeof cOrIp === "string" ? cOrIp : "";
      if (c) {
        try {
          ip = p.ipOf(c);
        } catch {
          return;
        }
      }
      p.firewall?.loginFailed(ip, eventOf(c));
    }).catch(() => {});
  };

  // Feature flags: isEnabled("new-checkout", { user }), from memory: the
  // default (false) until the dashboard's flags have arrived.
  analyticsPlatform.isEnabled = (key, flagOptions = {}) => (current?.flags
    ? current.flags.isEnabled(key, flagOptions)
    : flagOptions.default ?? false);

  // A background job (a cron trigger, a queue consumer): job("send-receipts",
  // async () => ...). Its errors are sent with the job's name as their route,
  // and each run is timed (Health → Server speed → Jobs): one that throws
  // counts as failed and is thrown on. c: the request's, or on Workers
  // { env, executionCtx } from the scheduled() or queue() handler, so the
  // options can read env and the sends are waited for.
  analyticsPlatform.job = async (name, fn, c) => {
    const route = `/(job) ${String(name || "job").slice(0, 180)}`;
    let p = null;
    try {
      p = await run(c, (x) => x);
    } catch (error) {
      console.warn("[analytics-platform] job() runs unreported:", error?.message);
    }
    if (!p) return fn();
    const event = eventOf(c);
    const store = { c: null, job: route, trail: [], event };
    const started = now();
    const holder = {};
    const timed = (status) => {
      const filed = p.performance?.record({ method: "JOB", route, status, ms: now() - started });
      // Its queries go under the route Server speed counted the run under
      // ("(other)" once a minute's routes are capped).
      if (filed !== undefined) p.queries?.finish(holder, "JOB", filed);
      // On Workers there may be no request after it to send the row.
      if (p.workers) event?.waitUntil?.(track(Promise.all([p.performance?.flush(), p.queries?.flush()])));
    };
    const go = () => (storage ? storage.run(store, fn) : fn());
    try {
      const result = await (p.queries ? p.queries.bind(holder, go) : go());
      timed(200);
      return result;
    } catch (error) {
      if (error && typeof error === "object") seen.add(error);
      report(error, null, store, { status: 500, kind: "error" });
      timed(500);
      throw error;
    }
  };

  // Times the queries run through a database object, as the main package's
  // watchDatabase(); call it at start-up, before the first request: nothing
  // is timed until that request has set the platform up. A Prisma client
  // comes back extended, to use in its place.
  analyticsPlatform.watchDatabase = (db) => watchDatabase(db, () => current?.queries?.recorder ?? null);

  // Reads a BullMQ (or Bull) queue every minute, as the main package's
  // watchQueue(); one handed over before the first request is watched once
  // that request has set the platform up. Returns it.
  analyticsPlatform.watchQueue = (queue) => {
    if (current) current.queues?.watchQueue(queue);
    else if (unwatchedQueues.length < 100) unwatchedQueues.push(queue);
    return queue;
  };

  // Sends everything waiting: before a serverless function returns, or a
  // process exits.
  analyticsPlatform.flush = async () => {
    const p = await parts?.catch(() => null);
    await Promise.all([...pending]);
    await Promise.all([p?.firewall?.flush(), p?.performance?.flush(), p?.queries?.flush(), p?.queues?.flush(), p?.crawlers?.flush(), p?.analytics?.flush(), p?.audit?.flush(), p && sendHeld(p)]);
  };
  return analyticsPlatform;
}

module.exports = { createHonoPlatform };
