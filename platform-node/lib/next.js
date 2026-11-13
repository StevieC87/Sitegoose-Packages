// Next.js (and anything else on Vercel or another edge runtime): the firewall
// in middleware.ts, and server errors from instrumentation.ts onRequestError.
// No Node built-ins, so it runs in the edge runtime. For events from route
// handlers and server actions (Node runtime), use the main package.
//
// The edge keeps no process between requests the way a server does: each
// instance keeps the rules in memory while it lives, fetches them when
// they're older than the rules' sync interval (in the background, with
// event.waitUntil), and waits up to FIRST_WAIT_MS for them on a cold start.
// It fails open: no rules, or the collector unreachable, lets requests pass.
"use strict";

const { createCore, disconnected } = require("./core.js");
const { parseIp, IpSet, hop, counterKey, makeRoom } = require("./ip.js");
const { fromCloudflare, onWorkers } = require("./cloudflare.js");
const { createLocalBans, compileProbes, isProbe, isStatic } = require("./bans.js");
const { compileRequestRules, matchRequest, prepare, compileLimits, matchLimits } = require("./requestRules.js");
const { compileChallenge, createSigner, hasPass, passFor, asksForPage, exempted, challengePage } = require("./challenge.js");

const PROTOCOL = 1;
const MIN_SYNC_S = 30;
const RETRY_S = 60;
const FIRST_WAIT_MS = 1500;
const FLUSH_MS = 5000;
const BATCH = 200;
const QUEUE_MAX = 2000;
const COUNTER_MAX = 50000;
// What a page limit answers in block mode (firewall.md, "Page limits").
const LIMIT_BODY = "Too many requests to this page. Please wait a little and try again.";

const env = (name) => (typeof process !== "undefined" && process.env ? process.env[name] : undefined);

function headerOf(request, name) {
  const headers = request.headers;
  const value = typeof headers?.get === "function" ? headers.get(name) : headers?.[name];
  return String(Array.isArray(value) ? value[0] : value || "").trim();
}

// trustProxy: "vercel" (default on Vercel: its x-real-ip), "cloudflare"
// (CF-Connecting-IP), a number of proxies in X-Forwarded-For, or a function.
// Self-hosted Next.js has no connection address in middleware: set one.
//
// "cloudflare" believes the header only where it can't be the client's own
// word: on Cloudflare Workers, where Cloudflare sets it, or when the
// connection's address (`direct`: Hono's, else request.ip or Vercel's
// x-real-ip) is one of Cloudflare's. Anywhere else it is the connection's
// address, or none, and the request passes unchecked.
//
// A hop with a port ("203.0.113.5:54321", "[2001:db8::1]:443") loses it; one
// that still isn't an address gives the connection's address where there is
// one (Hono's, request.ip), so the request is still checked.
function clientIp(request, trustProxy, direct) {
  const own = hop(direct !== undefined ? String(direct || "") : request.ip || "");
  const usable = (text, fallback = own) => {
    const address = hop(text);
    return parseIp(address) ? address : fallback;
  };
  if (typeof trustProxy === "function") return usable(trustProxy(request) || "");
  if (trustProxy === "cloudflare") {
    if (onWorkers()) return usable(headerOf(request, "cf-connecting-ip"), "");
    const from = hop(direct !== undefined ? String(direct || "")
      : request.ip || (env("VERCEL") ? headerOf(request, "x-real-ip") : ""));
    return fromCloudflare(from) && headerOf(request, "cf-connecting-ip") ? usable(headerOf(request, "cf-connecting-ip"), from) : from;
  }
  if (Number.isInteger(trustProxy) && trustProxy > 0) {
    const chain = headerOf(request, "x-forwarded-for").split(",").map((s) => s.trim()).filter(Boolean);
    return chain.length ? usable(chain[Math.max(0, chain.length - trustProxy)]) : own;
  }
  if (trustProxy === "vercel" || (trustProxy === undefined && env("VERCEL"))) {
    // Vercel writes both headers itself, whatever the visitor sent.
    return usable(request.ip || headerOf(request, "x-real-ip") || headerOf(request, "x-forwarded-for").split(",")[0], "");
  }
  return usable(request.ip || "", "");
}

function compile(data) {
  if (!data || data.v !== PROTOCOL) throw new Error(`unknown rules version ${data?.v}`);
  return {
    enabled: data.enabled === true,
    mode: data.mode === "block" ? "block" : "monitor",
    sync: Math.max(MIN_SYNC_S, Number(data.sync) || RETRY_S),
    allow: new IpSet(data.allow),
    // Crawlers the rate limit must not catch, as in the Node firewall.
    goodbots: new IpSet(data.goodbots),
    deny: new IpSet(data.deny),
    list: new IpSet(data.lists),
    shared: new IpSet(data.shared),
    rate: data.rate && Number(data.rate.limit) > 0
      ? { limit: Number(data.rate.limit), window: Math.max(1, Number(data.rate.window) || 60) }
      : null,
    banned: new IpSet(data.banned),
    ban: data.ban && Number(data.ban.seconds) > 0 ? { seconds: Number(data.ban.seconds) } : null,
    // Failed logins (loginFailed), as in the Node firewall.
    login: data.login && Number(data.login.limit) > 0
      ? { limit: Number(data.login.limit), window: Number(data.login.window) || 3600, ban: Number(data.login.ban) || 3600 }
      : null,
    probes: compileProbes(data.probes),
    // Virtual patching: rules that match the request, not the address.
    requests: compileRequestRules(data.requests),
    // Page limits: one kind of request capped on its own, never a ban.
    limits: compileLimits(data.limits),
    // The browser check (paid plans): null when off.
    challenge: compileChallenge(data.challenge),
  };
}

// Options: siteId, secret, endpoint; trustProxy (see clientIp); mode
// ("monitor" / "block": overrides the dashboard); skip(request); counter
// (async (key, ttlSeconds) => hits, shared between instances, e.g. Upstash
// Redis: each instance counts on its own otherwise); serverName (sent with
// the rules fetch; the edge has no machine name of its own); debug.
// Returns middleware(request, event): a Response when blocked, else undefined.
function createNextFirewall(options = {}) {
  const core = createCore({ ...options, client: "next", checkIn: false });
  if (!core.valid) console.warn("[analytics-platform] siteId, secret and endpoint are required; every request passes");
  let rules = null;
  let etag = "";
  let fetchedAt = 0;
  let syncing = null;
  let queue = new Map();
  // The first report goes straight away (an edge instance may not live 5 seconds), then at most every FLUSH_MS.
  let lastFlush = 0;
  const counts = new Map();
  // The page limits' own counts, capped as the rate counts are.
  const limitCounts = new Map();
  // The counts per page (`each: "path"`) apart, capped the same: one per
  // address and page, anyone can make thousands by asking for made-up paths,
  // and in the same table they would push the login limit's counts out
  // mid-window and start them again.
  const pageCounts = new Map();
  // With a shared counter: the counts this instance saw go over (their key,
  // window and all), so a static file asked for after them can be turned
  // away without adding to them (a counter can only add).
  const overNoted = new Map();
  const note = (name, over) => {
    if (over && !overNoted.has(name)) {
      makeRoom(overNoted, COUNTER_MAX);
      overNoted.set(name, true);
    }
    return over;
  };
  const local = createLocalBans();
  // The browser check's pass: WebCrypto's HMAC, no node:crypto here.
  const sign = core.valid ? createSigner(core.secret, { web: true }) : null;
  // The layers this instance runs, for the dashboard's Firewall tab; its name
  // only when given (an edge instance has none to tell).
  const serverName = String(options.serverName || "").replace(/[^\x20-\x7e]/g, "?").trim().slice(0, 100);
  const layerHeaders = { "x-firewall-layers": "app check", ...(serverName ? { "x-server-name": serverName } : {}) };

  async function sync() {
    try {
      const res = await core.send("firewall", `/events/firewall/rules?site_id=${encodeURIComponent(core.siteId)}`, {
        method: "GET", auth: "bearer", headers: { ...layerHeaders, ...(etag ? { "if-none-match": etag } : {}) },
      });
      if (res?.status === 200) {
        rules = compile(await res.json());
        etag = res.headers.get("etag") || "";
      }
    } catch (error) {
      core.log("firewall", "rules not used:", error?.message);
    }
    fetchedAt = Date.now();
  }

  function refresh(event) {
    const due = Date.now() - fetchedAt >= (rules?.sync || RETRY_S) * 1000;
    if (!core.valid || !due || syncing) return syncing;
    syncing = sync().finally(() => { syncing = null; });
    event?.waitUntil?.(syncing);
    return syncing;
  }

  async function flush() {
    if (!queue.size) return;
    const rows = [...queue.values()];
    queue = new Map();
    lastFlush = Date.now();
    for (let i = 0; i < rows.length; i += BATCH) {
      await core.send("firewall", "/events/firewall/events", { auth: "bearer", body: { site_id: core.siteId, events: rows.slice(i, i + BATCH) } });
    }
  }

  // Per address, an IPv6 address by its /64 (counterKey), as the Node
  // firewall counts. peek: only compared with the count so far, nothing
  // added (a static file).
  async function overRate(ip, rate, peek = false) {
    const window = Math.floor(Date.now() / 1000 / rate.window);
    const who = counterKey(ip) || ip;
    if (typeof options.counter === "function") {
      const name = `afw:${core.siteId}:${who}:${window}`;
      if (peek) return overNoted.has(name);
      return note(name, Number(await options.counter(name, rate.window * 2)) > rate.limit);
    }
    let entry = counts.get(who);
    if (peek) return Boolean(entry) && entry.window === window && entry.hits > rate.limit;
    if (!entry || entry.window !== window) {
      // A full table loses whoever went quiet longest ago, not everyone's count.
      counts.delete(who);
      makeRoom(counts, COUNTER_MAX);
      entry = { window, hits: 0 };
      counts.set(who, entry);
    }
    entry.hits += 1;
    return entry.hits > rate.limit;
  }

  // One fixed window of one count, now over `limit`: in the shared counter
  // when there is one and the count may go there (`shared`), else in memory
  // on this instance. peek: as overRate's.
  async function hit(table, key, seconds, shared, limit, peek) {
    const window = Math.floor(Date.now() / 1000 / seconds);
    if (shared && typeof options.counter === "function") {
      const name = `${key}:${window}`;
      if (peek) return overNoted.has(name);
      return note(name, Number(await options.counter(name, seconds * 2)) > limit);
    }
    let entry = table.get(key);
    if (peek) return Boolean(entry) && entry.window === window && entry.hits > limit;
    if (!entry || entry.window !== window) {
      table.delete(key);
      makeRoom(table, COUNTER_MAX);
      entry = { window, hits: 0 };
      table.set(key, entry);
    }
    entry.hits += 1;
    return entry.hits > limit;
  }

  // Counts the request toward every page limit it matches -> the limits now
  // over their count, in the order sent. Shared counts are keyed
  // afw:<site_id>:l:<id>:<who>:<window>; a count per page (`each: "path"`)
  // never goes in the shared counter. peek: as overRate's.
  async function overLimits(ip, limits, request, peek = false) {
    const { matched, page } = matchLimits(limits, request);
    if (!matched.length) return [];
    const who = counterKey(ip) || ip;
    const over = await Promise.all(matched.map((limit) => (limit.each
      ? hit(pageCounts, `${limit.id}|${who}|${page}`, limit.window, false, limit.limit, peek)
      : hit(limitCounts, `afw:${core.siteId}:l:${limit.id}:${who}`, limit.window, true, limit.limit, peek))));
    return matched.filter((limit, i) => over[i]);
  }

  function remember({ ip, rule, action, method, path, userAgent }, event) {
    const key = `${ip}|${rule}|${action}|${method}|${path}`;
    const row = queue.get(key);
    if (row) row.hits += 1;
    else if (queue.size < QUEUE_MAX) {
      queue.set(key, { at: new Date().toISOString(), ip, rule, action, method, path: path.slice(0, 300), user_agent: userAgent.slice(0, 300), hits: 1 });
    }
    if (queue.size >= BATCH || Date.now() - lastFlush >= FLUSH_MS) event?.waitUntil?.(flush());
  }

  // late: an object of the caller's (hono.js) given `static` when the
  // request is a static file let through, for countStatic after the
  // response. Next.js middleware never sees the response, so there nothing
  // is counted late.
  async function analyticsFirewall(request, event, late) {
    try {
      if (!core.valid || options.skip?.(request)) return undefined;
      const pending = refresh(event);
      // Cold start: wait a moment for the first rules.
      if (!rules && pending) await Promise.race([pending, new Promise((resolve) => setTimeout(resolve, FIRST_WAIT_MS))]);
      const current = rules;
      if (!current?.enabled) return undefined;
      const ip = clientIp(request, options.trustProxy);
      const address = parseIp(ip);
      if (!address || current.allow.has(address)) return undefined;
      const mode = options.mode === "block" || options.mode === "monitor" ? options.mode : current.mode;
      const action = mode === "block" ? "block" : "monitor";
      // A request rule may only watch, even when the site blocks.
      let effective = action;
      const path = request.nextUrl?.pathname || new URL(request.url).pathname;
      // The rules match the query string too, which the path alone leaves out.
      const target = (request.nextUrl?.pathname || "") + (request.nextUrl?.search || "")
        || new URL(request.url).pathname + new URL(request.url).search;
      let rule = current.deny.has(address) ? "deny"
        : current.banned.has(address) || local.banned(ip) ? "ban"
          : current.list.has(address) ? "list" : current.shared.has(address) ? "shared" : "";
      if (!rule && isProbe(path, current.probes)) {
        rule = "probe";
        if (action === "block") local.ban(ip, current.probes.ban);
      }
      // Prepared once (decoded, routed) for the request rules and the page limits both.
      const prepared = !rule && (current.requests.length || current.limits.rules.length)
        ? prepare({ method: request.method, path: target, userAgent: headerOf(request, "user-agent") }) : null;
      if (!rule) {
        const matched = matchRequest(current.requests, prepared);
        if (matched) {
          rule = `request:${matched.id}`;
          effective = action === "block" && matched.action === "block" ? "block" : "monitor";
          if (effective === "block" && matched.ban) local.ban(ip, matched.ban);
        }
      }
      // Page limits (firewall.md, step 6): never a ban, the cap lifts when the
      // window ends. One that only watches is kept aside and the check goes
      // on, so watching the login page can't let a flood past the rate limit.
      // A static file is only compared with the counts so far: an address
      // already over them is turned away for its files too.
      const fetchesFile = isStatic(path, request.method);
      let lateRate = false;
      let lateLimits = false;
      let watched = null;
      let retryAfter = 0;
      if (!rule && current.limits.rules.length && !current.goodbots.has(address)
        && !current.limits.exempt.has(address)) {
        lateLimits = fetchesFile;
        const over = await overLimits(ip, current.limits, prepared, fetchesFile);
        const blocking = action === "block" ? over.find((limit) => limit.action === "block") : null;
        if (blocking) {
          rule = `limit:${blocking.id}`;
          retryAfter = blocking.window;
        } else if (over.length) watched = over[0];
      }
      if (!rule && current.rate && !current.goodbots.has(address)) lateRate = fetchesFile;
      if (!rule && current.rate && !current.goodbots.has(address) && await overRate(ip, current.rate, fetchesFile)) {
        rule = "rate";
        retryAfter = current.rate.window;
        // Monitor mode reports what would have been banned, and bans nothing.
        if (action === "block" && current.ban) local.ban(ip, current.ban.seconds);
      }
      const said = (name, act) => ({ ip, rule: name, action: act, method: String(request.method || "").slice(0, 10), path, userAgent: headerOf(request, "user-agent") });
      if (watched) {
        // Rate decided: the watched limit is reported as well.
        if (rule) remember(said(`limit:${watched.id}`, "monitor"), event);
        else {
          rule = `limit:${watched.id}`;
          effective = "monitor";
        }
      }
      // The browser check: not a mode matter, the collector sends it only
      // for a site to be checked.
      // A match that is only watched (monitor) still gets it: firewall.md, step 8.
      if ((!rule || effective !== "block") && current.challenge && sign && asksForPage(current.challenge, request.method, headerOf(request, "accept"), path)
        && !exempted(current.challenge, address, current) && !(await hasPass(sign, ip, headerOf(request, "cookie")))) {
        const page = challengePage({ pass: await passFor(sign, ip), method: request.method });
        if (rule) remember(said(rule, effective), event);
        remember(said("challenge", "block"), event);
        return new Response(page.body || null, { status: page.status, headers: page.headers });
      }
      if ((lateRate || lateLimits) && (!rule || effective !== "block") && late && typeof late === "object") {
        late.static = { ip, rate: lateRate, request: lateLimits ? prepared : null };
      }
      if (!rule) return undefined;
      remember(said(rule, effective), event);
      if (effective !== "block") return undefined;
      // 429 with Retry-After for the rate limit and a page limit, else 403.
      const body = rule.startsWith("limit:") ? LIMIT_BODY : retryAfter ? "Too Many Requests" : "Forbidden";
      return new Response(body, {
        status: retryAfter ? 429 : 403,
        headers: {
          "content-type": "text/plain; charset=utf-8",
          "cache-control": "no-store",
          ...(retryAfter ? { "retry-after": String(retryAfter) } : {}),
        },
      });
    } catch (error) {
      core.log("firewall", "check failed, request passed:", error?.message);
      return undefined;
    }
  }
  // The rules about the address alone (deny, bans, lists, shared), for the
  // tracker's own addresses (hono.js's proxy): never the rate limit, the
  // browser check or the request rules. A Response when blocked, else
  // undefined; rules not fetched yet let it pass.
  analyticsFirewall.checkAddress = (ip, { method = "", path = "", userAgent = "" } = {}, event) => {
    try {
      const current = rules;
      if (!core.valid || !current?.enabled) return undefined;
      const address = parseIp(ip);
      if (!address || current.allow.has(address)) return undefined;
      const rule = current.deny.has(address) ? "deny"
        : current.banned.has(address) || local.banned(ip) ? "ban"
          : current.list.has(address) ? "list" : current.shared.has(address) ? "shared" : "";
      if (!rule) return undefined;
      const mode = options.mode === "block" || options.mode === "monitor" ? options.mode : current.mode;
      const action = mode === "block" ? "block" : "monitor";
      remember({ ip, rule, action, method: String(method).slice(0, 10), path: String(path).split("?")[0], userAgent: String(userAgent) }, event);
      if (action !== "block") return undefined;
      return new Response("Forbidden", { status: 403, headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" } });
    } catch (error) {
      core.log("firewall", "check failed, request passed:", error?.message);
      return undefined;
    }
  };
  // After the response to a static file the firewall let through (late.static
  // above): counted toward `rate` and the page limits it skipped when it
  // answered 400 or more or the app's router sent it to a route that isn't
  // a file's (routed, hono.js). Resolves when counted; never rejects.
  analyticsFirewall.countStatic = async (file, status, routed) => {
    try {
      const current = rules;
      // A 304 is a browser checking a file it keeps: never a page.
      if (!file || !current || !(Number(status) >= 400 || (routed && Number(status) !== 304))) return;
      await Promise.all([
        file.rate && current.rate ? overRate(file.ip, current.rate) : null,
        file.request && current.limits.rules.length ? overLimits(file.ip, current.limits, file.request) : null,
      ]);
    } catch (error) {
      core.log("firewall", "could not count a static file:", error?.message);
    }
  };
  // Sends the events waiting (hono.js, on runtimes without waitUntil).
  analyticsFirewall.flush = flush;
  // Events wait to be sent and it's time (hono.js on Workers, whose
  // requests send them, flagged or not).
  analyticsFirewall.due = () => queue.size > 0 && Date.now() - lastFlush >= FLUSH_MS;
  // A failed login from this address (hono.js): past the site's limit it is
  // banned here straight away, and reported, so it counts on the Security
  // page and is banned on the other servers too.
  analyticsFirewall.loginFailed = (ip, event) => {
    try {
      const address = parseIp(ip);
      if (!core.valid || !address || rules?.allow.has(address)) return;
      refresh(event);
      local.loginFailed(String(ip), rules?.login);
      remember({ ip: String(ip), rule: "login", action: "monitor", method: "", path: "", userAgent: "" }, event);
    } catch (error) {
      core.log("firewall", "could not count a failed login:", error?.message);
    }
  };
  return analyticsFirewall;
}

// instrumentation.ts: export const onRequestError = createOnRequestError({...}).
// Sends each server error (pages, route handlers, server actions, middleware)
// to the Errors report, unless the dashboard switched error monitoring off.
function createOnRequestError(options = {}) {
  const core = createCore({ ...options, client: "next", checkIn: false });
  let switches = { at: 0, errors: true };

  async function errorsOn() {
    if (Date.now() - switches.at < RETRY_S * 1000) return switches.errors;
    const res = await core.send("errors", `/events/platform/config?site_id=${encodeURIComponent(core.siteId)}`, {
      method: "GET", auth: "bearer", headers: { "x-platform-modules": "errors" },
    });
    const data = res?.ok ? await res.json().catch(() => null) : null;
    switches = { at: Date.now(), errors: data?.modules?.errors !== false };
    return switches.errors;
  }

  return async function onRequestError(error, request, context) {
    try {
      // Next's own word for a visitor who went away mid-response.
      if (!core.valid || disconnected(error, false) || !(await errorsOn())) return;
      const headers = request?.headers || {};
      const session = headers["x-analytics-session"];
      await core.send("errors", "/events/server-errors", {
        body: {
          errors: [edgeError(error, {
            kind: "error",
            status: 500,
            runtime: "Next.js",
            runtimeVersion: env("NEXT_RUNTIME") || "",
            serverName: env("VERCEL_REGION") || env("HOSTNAME") || "",
            method: request?.method,
            path: request?.path,
            route: context?.routePath,
            session: typeof session === "string" ? session : "",
          })],
        },
      });
    } catch {
      // never throw from the error hook
    }
  };
}

// One server error as the collector takes it, from a runtime with no Node
// built-ins (Next.js here, Hono in hono.js).
function edgeError(error, { kind, status, runtime, runtimeVersion = "", serverName = "", method, path, route, session = "" }) {
  return {
    message: String(error?.message || error || "Unknown error").slice(0, 2000),
    error_type: error?.name || "Error",
    stack: typeof error?.stack === "string" ? error.stack : "",
    kind,
    status_code: Number(status) || 500,
    runtime,
    runtime_version: runtimeVersion,
    os: "",
    server_name: serverName,
    method: String(method || ""),
    path: String(path || "").split("?")[0],
    route: String(route || ""),
    session_id: session,
  };
}

module.exports = { createNextFirewall, createOnRequestError, clientIp, edgeError };
