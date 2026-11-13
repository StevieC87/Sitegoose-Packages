// Firewall module: rules from the collector (GET /events/firewall/rules,
// protocol in sdk/protocols/firewall.md) every minute or so; every request is
// checked against them in memory, so the app never waits on the collector.
// What was blocked (or, in monitor mode, would have been) goes back in
// batches. Fails open: until rules arrive, and whenever the collector can't be
// reached, requests pass (with the last rules that arrived, if any).
"use strict";

const fs = require("node:fs");
const { parseIp, parseRange, IpSet, hop, counterKey, makeRoom } = require("./ip.js");
const { fromCloudflare } = require("./cloudflare.js");
const { createLocalBans, compileProbes, isProbe, isStatic, routedToPage } = require("./bans.js");
const { compileRequestRules, matchRequest, prepare, compileLimits, matchLimits } = require("./requestRules.js");
const {
  compileChallenge, createSigner, hasPassSync, passForSync, asksForPage, exempted, challengePage,
} = require("./challenge.js");

const PROTOCOL = 1;
const MIN_SYNC_S = 30;
const RETRY_S = 60;
const FLUSH_MS = 5000;
const BATCH = 200;
// Distinct (address, rule, path) rows waiting to be sent; more are dropped.
const QUEUE_MAX = 2000;
// Addresses the rate limit counts at once; past it the oldest go. The page
// limits keep a table of their own, as large, and the counts per page
// (`each: "path"`) a third.
const COUNTER_MAX = 100000;
// What a page limit answers in block mode (firewall.md, "Page limits").
const LIMIT_BODY = "Too many requests to this page. Please wait a little and try again.";

// ---- The client's address -------------------------------------------------

function header(req, name) {
  const value = req.headers?.[name];
  return String(Array.isArray(value) ? value[0] : value || "").trim();
}

// A public address no proxy of anyone's is: a trust setting that trusts it
// a thousand hops deep trusts every hop.
const NOBODY = "203.0.113.254";

// Whether the framework's own setting trusts every proxy hop, which makes
// its address the left-most X-Forwarded-For entry: whatever the visitor
// wrote there. Express's `trust proxy` true (or a function or range list that
// trusts anything), Fastify's trustProxy: true (the plugin marks it), Koa's
// app.proxy with no maxIpsCount (the middleware marks it).
function trustsEveryHop(req) {
  if (req[TRUSTS_ALL] !== undefined) return req[TRUSTS_ALL];
  try {
    const trust = req.app?.get?.("trust proxy fn");
    return typeof trust === "function" && Boolean(trust(NOBODY, 1000));
  } catch {
    return false;
  }
}
const TRUSTS_ALL = Symbol.for("analytics-platform.trusts-every-hop");
// The response's Content-Type where the framework writes its headers in one
// go (Fastify's writeHead), so res.getHeader() can't read it: fastify.js puts it here.
const CONTENT_TYPE = Symbol.for("analytics-platform.content-type");

// trustProxy: undefined uses the framework's own address (Express's req.ip
// under its "trust proxy" setting, Fastify's and Koa's as their plugins set
// it), else the connection's address; a number trusts that many proxies in
// X-Forwarded-For (true = 1); "cloudflare" reads CF-Connecting-IP, believed
// only when the connection comes from Cloudflare's own addresses (anyone who
// reaches the server directly can send it); a function returns the address.
//
// A framework that trusts every hop (trustsEveryHop) is read as trusting
// one, the proxy in front of the app: its own answer is whatever the visitor
// wrote first in the header. A hop with a port ("203.0.113.5:54321",
// "[2001:db8::1]:443") loses it; a hop that still isn't an address gives the
// connection's address, so the firewall checks the request rather than
// letting it through unchecked.
function clientIp(req, trustProxy) {
  const direct = hop(req.socket?.remoteAddress || "");
  const usable = (text) => {
    const address = hop(text);
    return parseIp(address) ? address : direct;
  };
  if (typeof trustProxy === "function") return usable(trustProxy(req) || "");
  if (trustProxy === "cloudflare") return fromCloudflare(direct) && header(req, "cf-connecting-ip") ? usable(header(req, "cf-connecting-ip")) : direct;
  const hops = trustProxy === true ? 1 : Number.isInteger(trustProxy) && trustProxy > 0 ? trustProxy
    : trustProxy === undefined && req.ip && trustsEveryHop(req) ? 1 : 0;
  if (hops) {
    const chain = header(req, "x-forwarded-for").split(",").map((s) => s.trim()).filter(Boolean);
    return chain.length ? usable(chain[Math.max(0, chain.length - hops)]) : direct;
  }
  return req.ip ? usable(req.ip) : direct;
}

// This machine's name for the rules fetch (X-Server-Name): printable ASCII
// only, so the header can always be sent.
function serverNameOf(options) {
  let name = options.serverName;
  if (!name) {
    try { name = require("node:os").hostname(); } catch { name = ""; }
  }
  return String(name || "").replace(/[^\x20-\x7e]/g, "?").trim().slice(0, 100);
}

// ---- The firewall ---------------------------------------------------------

// Options: trustProxy (see clientIp); mode ("monitor" or "block": overrides
// the dashboard's); skip(req) (true leaves a request unchecked);
// onBlock(req, res, decision) (send your own response; not called for the
// browser check, whose page is what lets a browser through); cacheFile (rules
// are kept there between restarts); serverName (sent with the rules fetch).
// "http://host/a?b" as "/a?b". Anything else, or a target that isn't a URL
// ("*" for OPTIONS), is kept as it is.
function originForm(target) {
  const text = String(target);
  if (text.startsWith("/")) return text;
  try {
    const url = new URL(text);
    return `${url.pathname}${url.search}`;
  } catch {
    return text;
  }
}

function createFirewall(core, options = {}) {
  const valid = core.valid;
  const log = (...args) => core.log("firewall", ...args);

  let rules = null;
  let etag = "";
  let syncTimer = null;
  let flushTimer = null;
  let closed = false;
  const counts = new Map();
  const limitCounts = new Map();
  // The counts per page (`each: "path"`) apart: one per address and page,
  // anyone can make thousands by asking for made-up paths, and in the same
  // table they would push the login limit's counts out mid-window and start
  // them again.
  const pageCounts = new Map();
  const local = createLocalBans();
  let queue = new Map();
  // The browser check's pass, signed with the site secret (node:crypto, sync).
  const sign = valid ? createSigner(core.secret) : null;
  // The layers this server runs, and its name, for the dashboard's Firewall tab.
  const layerHeaders = { "x-firewall-layers": "app check" };
  const serverName = serverNameOf(options);
  if (serverName) layerHeaders["x-server-name"] = serverName;

  function compile(data) {
    if (!data || data.v !== PROTOCOL) throw new Error(`unknown rules version ${data?.v}`);
    return {
      enabled: data.enabled === true,
      mode: data.mode === "block" ? "block" : "monitor",
      sync: Math.max(MIN_SYNC_S, Number(data.sync) || RETRY_S),
      allow: new IpSet(data.allow),
      // Crawlers the rate limit must not catch; absent from older rules, which
      // is simply an empty set.
      goodbots: new IpSet(data.goodbots),
      deny: new IpSet(data.deny),
      list: new IpSet(data.lists),
      shared: new IpSet(data.shared),
      rate: data.rate && Number(data.rate.limit) > 0
        ? { limit: Number(data.rate.limit), window: Math.max(1, Number(data.rate.window) || 60) * 1000 }
        : null,
      banned: new IpSet(data.banned),
      ban: data.ban && Number(data.ban.seconds) > 0 ? { seconds: Number(data.ban.seconds) } : null,
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

  if (options.cacheFile) {
    try {
      const cached = JSON.parse(fs.readFileSync(options.cacheFile, "utf8"));
      rules = compile(cached.rules);
      etag = cached.etag || "";
    } catch (error) {
      if (error.code !== "ENOENT") log("could not read cacheFile:", error.message);
    }
  }

  // Fixed window per address (an IPv6 address's /64: counterKey). peek:
  // only compared with the count so far, nothing added (a static file).
  function overRate(ip, rate, peek = false) {
    const key = counterKey(ip) || String(ip);
    const now = Date.now();
    let entry = counts.get(key);
    if (peek) return Boolean(entry) && now - entry.start < rate.window && entry.hits > rate.limit;
    if (!entry || now - entry.start >= rate.window) {
      // Taken out and put back, so the table runs oldest window first and a
      // full one loses whoever went quiet longest ago, not everyone's count.
      counts.delete(key);
      makeRoom(counts, COUNTER_MAX);
      entry = { start: now, hits: 0 };
      counts.set(key, entry);
    }
    entry.hits += 1;
    return entry.hits > rate.limit;
  }

  // Counts the request toward every page limit it matches (a fixed window per
  // limit and address, and per page too for `each: "path"`) -> the limits now
  // over their count, in the order sent. peek: as overRate's.
  function overLimits(ip, limits, request, peek = false) {
    const { matched, page } = matchLimits(limits, request);
    if (!matched.length) return [];
    const who = counterKey(ip) || String(ip);
    const now = Date.now();
    const over = [];
    for (const limit of matched) {
      const table = limit.each ? pageCounts : limitCounts;
      const key = `${limit.id}|${who}${limit.each ? `|${page}` : ""}`;
      let entry = table.get(key);
      if (peek) {
        if (entry && now - entry.start < limit.window * 1000 && entry.hits > limit.limit) over.push(limit);
        continue;
      }
      if (!entry || now - entry.start >= limit.window * 1000) {
        // Oldest window first, as the rate counts are kept.
        table.delete(key);
        makeRoom(table, COUNTER_MAX);
        entry = { start: now, hits: 0 };
        table.set(key, entry);
      }
      entry.hits += 1;
      if (entry.hits > limit.limit) over.push(limit);
    }
    return over;
  }

  function report(event) {
    const key = `${event.ip}|${event.rule}|${event.action}|${event.method}|${event.path}`;
    const row = queue.get(key);
    if (row) row.hits += 1;
    else if (queue.size < QUEUE_MAX) queue.set(key, { ...event, at: new Date().toISOString(), hits: 1 });
    if (queue.size >= BATCH) flush();
    else if (!flushTimer) {
      flushTimer = setTimeout(flush, FLUSH_MS);
      flushTimer.unref?.();
    }
  }

  async function flush() {
    clearTimeout(flushTimer);
    flushTimer = null;
    if (!queue.size || !valid) return;
    const rows = [...queue.values()];
    queue = new Map();
    for (let i = 0; i < rows.length; i += BATCH) {
      await core.send("firewall", "/events/firewall/events", {
        auth: "bearer",
        body: { site_id: core.siteId, events: rows.slice(i, i + BATCH) },
      });
    }
  }

  // Written beside the file and renamed over it, so a crash mid-write (or
  // two processes writing at once) never leaves half a file to read at start.
  function writeCache(text) {
    const temp = `${options.cacheFile}.${process.pid}.${Date.now()}.tmp`;
    fs.promises.writeFile(temp, text, { mode: 0o600 })
      .then(() => fs.promises.rename(temp, options.cacheFile))
      .catch((error) => {
        log("could not write cacheFile:", error.message);
        fs.promises.unlink(temp).catch(() => {});
      });
  }

  async function sync() {
    let wait = rules?.sync || RETRY_S;
    try {
      const res = await core.send("firewall", `/events/firewall/rules?site_id=${encodeURIComponent(core.siteId)}`, {
        method: "GET", auth: "bearer", headers: { ...layerHeaders, ...(etag ? { "if-none-match": etag } : {}) },
      });
      if (res?.status === 200) {
        const data = await res.json();
        rules = compile(data);
        etag = res.headers.get("etag") || "";
        wait = rules.sync;
        if (options.cacheFile) writeCache(JSON.stringify({ etag, rules: data }));
      }
    } catch (error) {
      log("could not fetch rules:", error?.message);
    }
    if (!closed) {
      syncTimer = setTimeout(sync, wait * 1000);
      syncTimer.unref?.();
    }
  }

  // { ip, method, path, userAgent, accept, cookie } -> { action: "allow" |
  // "block" | "monitor", rule, status }. Allowed addresses skip every other
  // rule. accept and cookie (the request's headers) are what the browser
  // check needs: without an Accept asking for text/html no request is checked. A checked request
  // is rule "challenge", status 503, with the page to send as headers and
  // body.
  function check({ ip, method = "", path = "", userAgent = "", accept = "", cookie = "" } = {}) {
    const allow = { action: "allow", rule: "", status: 200 };
    const current = rules;
    if (!current?.enabled) return allow;
    const address = parseIp(ip);
    if (!address || current.allow.has(address)) return allow;
    const mode = options.mode === "block" || options.mode === "monitor" ? options.mode : current.mode;
    const action = mode === "block" ? "block" : "monitor";
    // A request rule may only watch, even when the site blocks.
    let effective = action;
    let rule = current.deny.has(address) ? "deny"
      : current.banned.has(address) || local.banned(String(ip)) ? "ban"
        : current.list.has(address) ? "list"
          : current.shared.has(address) ? "shared" : "";
    if (!rule && isProbe(path, current.probes)) {
      rule = "probe";
      // Asking for a secret file: banned here in block mode; the report bans it on the other servers.
      if (action === "block") local.ban(String(ip), current.probes.ban);
    }
    // Prepared once (decoded, routed) for the request rules and the page limits both.
    const prepared = !rule && (current.requests.length || current.limits.rules.length)
      ? prepare({ method, path, userAgent }) : null;
    if (!rule) {
      const matched = matchRequest(current.requests, prepared);
      if (matched) {
        rule = `request:${matched.id}`;
        effective = action === "block" && matched.action === "block" ? "block" : "monitor";
        // Banned here straight away; the report bans it on the site's other servers.
        if (effective === "block" && matched.ban) local.ban(String(ip), matched.ban);
      }
    }
    // A static file isn't counted toward the page limits or `rate`, only
    // compared with the counts so far: an address already over them is
    // turned away for its files too. It counts after the response when the
    // app routed it to a page after all ("/search/:q" took "/search/x.css")
    // or it answered an error (countStatic, from the middleware).
    const fetchesFile = isStatic(path, method);
    let lateRate = false;
    let lateLimits = false;
    // Page limits (firewall.md, step 6). Nothing is banned: the cap lifts
    // when the window ends. One that only watches is kept aside and the check
    // goes on, so watching the login page can't let a flood past the rate limit.
    let watched = null;
    let retryAfter = 0;
    if (!rule && current.limits.rules.length && !current.goodbots.has(address)
      && !current.limits.exempt.has(address)) {
      lateLimits = fetchesFile;
      const over = overLimits(String(ip), current.limits, prepared, fetchesFile);
      const blocking = action === "block" ? over.find((limit) => limit.action === "block") : null;
      if (blocking) {
        rule = `limit:${blocking.id}`;
        retryAfter = blocking.window;
      } else if (over.length) watched = over[0];
    }
    if (!rule && current.rate && !current.goodbots.has(address)) lateRate = fetchesFile;
    if (!rule && current.rate && !current.goodbots.has(address) && overRate(String(ip), current.rate, fetchesFile)) {
      rule = "rate";
      retryAfter = Math.ceil(current.rate.window / 1000);
      // Banned here straight away in block mode, as a probe is; the report bans it on the other servers.
      if (action === "block" && current.ban) local.ban(String(ip), current.ban.seconds);
    }
    // The browser check: not a mode matter, the collector sends it only for a
    // site to be checked.
    // A match that is only watched (monitor) still gets it: firewall.md, step 8.
    const event = (name, act) => ({
      ip: String(ip),
      rule: name,
      action: act,
      method: String(method).slice(0, 10),
      path: String(path).split("?")[0].slice(0, 300),
      user_agent: String(userAgent).slice(0, 300),
    });
    if (watched) {
      // Rate decided: the watched limit is reported as well.
      if (rule) report(event(`limit:${watched.id}`, "monitor"));
      else {
        rule = `limit:${watched.id}`;
        effective = "monitor";
        retryAfter = watched.window;
      }
    }
    let page = null;
    if ((!rule || effective !== "block") && current.challenge && sign && asksForPage(current.challenge, method, accept, path)
      && !exempted(current.challenge, address, current) && !hasPassSync(sign, ip, cookie)) {
      if (rule) report(event(rule, effective));
      rule = "challenge";
      effective = "block";
      page = challengePage({ pass: passForSync(sign, ip), method });
    }
    // What countStatic needs after the response of a static file that goes on to the app.
    const late = (lateRate || lateLimits) && (!rule || effective !== "block") && !page
      ? { ip: String(ip), rate: lateRate, request: lateLimits ? prepared : null } : null;
    if (!rule) return late ? { ...allow, late } : allow;
    report(event(rule, effective));
    if (late) return { action: effective, rule, status: retryAfter ? 429 : 403, ...(retryAfter ? { retryAfter } : {}), late };
    if (page) return { action: "block", rule, status: page.status, headers: page.headers, body: page.body };
    // 429 for a limit even when it only watches: what it would have answered.
    if (retryAfter) return { action: effective, rule, status: 429, retryAfter };
    return { action: effective, rule, status: 403 };
  }

  // The rules about the address alone (deny, bans, lists, shared), for the
  // tracker's own addresses (the proxy): a denied or banned address gets
  // nothing from us either, but beacons are never rate-limited, checked or
  // matched against request rules. -> the same shape as check().
  function checkAddress({ ip, method = "", path = "", userAgent = "" } = {}) {
    const allow = { action: "allow", rule: "", status: 200 };
    const current = rules;
    if (!current?.enabled) return allow;
    const address = parseIp(ip);
    if (!address || current.allow.has(address)) return allow;
    const rule = current.deny.has(address) ? "deny"
      : current.banned.has(address) || local.banned(String(ip)) ? "ban"
        : current.list.has(address) ? "list"
          : current.shared.has(address) ? "shared" : "";
    if (!rule) return allow;
    const mode = options.mode === "block" || options.mode === "monitor" ? options.mode : current.mode;
    const action = mode === "block" ? "block" : "monitor";
    report({
      ip: String(ip), rule, action, method: String(method).slice(0, 10),
      path: String(path).split("?")[0].slice(0, 300), user_agent: String(userAgent).slice(0, 300),
    });
    return { action, rule, status: 403 };
  }

  // After the response to a static file check() let through (its
  // decision's `late`): counted toward `rate` and the page limits it skipped
  // when it answered 400 or more (a flood of made-up file names) or the
  // app's router sent it to a route that isn't a file's (routed) and it
  // wasn't a 304. In memory,
  // so nothing waits on it.
  function countStatic(late, status, routed) {
    const current = rules;
    // A 304 is a browser checking a file it keeps (a static plugin drops the
    // Content-Type on one): never a page.
    if (!late || !current || !(Number(status) >= 400 || (routed && Number(status) !== 304))) return;
    if (late.rate && current.rate) overRate(late.ip, current.rate);
    if (late.request && current.limits.rules.length) overLimits(late.ip, current.limits, late.request);
  }

  // Counts a static file once its response is out (finish, or close when the
  // visitor went away first), by the route the framework left on req
  // (Express sets req.route; the Fastify and Koa adapters copy theirs there)
  // and the response's Content-Type. Never throws.
  function countLater(req, res, late) {
    if (typeof res?.once !== "function") return;
    let done = false;
    const count = () => {
      if (done) return;
      done = true;
      try {
        const type = res.getHeader?.("content-type") ?? req[CONTENT_TYPE];
        countStatic(late, res.statusCode, routedToPage(req.route?.path, type));
      } catch (error) {
        log("could not count a static file:", error?.message);
      }
    };
    res.once("finish", count);
    res.once("close", count);
  }

  // A failed login on your site (req, or the address). Counted here: past the
  // site's limit the address is banned straight away, and reported, so it
  // counts on the Security page and gets banned on the other servers too.
  function loginFailed(reqOrIp) {
    try {
      const ip = typeof reqOrIp === "string" ? reqOrIp : clientIp(reqOrIp, options.trustProxy);
      if (!parseIp(ip) || rules?.allow.has(parseIp(ip))) return;
      local.loginFailed(String(ip), rules?.login);
      report({ ip: String(ip), rule: "login", action: "monitor", method: "", path: "", user_agent: "" });
    } catch (error) {
      log("could not count a failed login:", error?.message);
    }
  }

  // The path and query the rules compare against, as the app routes them.
  // An absolute-form request line ("GET http://host/admin") is routed by its
  // path, so it is cut to "/admin": matched as written it began "http:" and
  // missed every rule on "/admin". `options.path(req)` replaces this for an
  // app that routes a path other than its URL (a prefix it strips first).
  function pathOf(req) {
    if (options.path) {
      const own = options.path(req);
      if (typeof own === "string") return own;
    }
    return originForm(req.originalUrl || req.url || "/");
  }

  // Express / Connect / node:http middleware.
  function middleware(req, res, next = () => {}) {
    let decision;
    try {
      if (options.skip?.(req)) return next();
      decision = check({
        ip: clientIp(req, options.trustProxy),
        method: req.method,
        path: pathOf(req),
        userAgent: header(req, "user-agent"),
        accept: header(req, "accept"),
        cookie: header(req, "cookie"),
      });
    } catch (error) {
      log("check failed, request passed:", error?.message);
      return next();
    }
    if (decision.action !== "block") {
      if (decision.late) countLater(req, res, decision.late);
      return next();
    }
    if (decision.rule === "challenge") {
      res.statusCode = decision.status;
      for (const [name, value] of Object.entries(decision.headers)) res.setHeader(name, value);
      return res.end(decision.body);
    }
    if (options.onBlock) return options.onBlock(req, res, decision);
    res.statusCode = decision.status;
    if (decision.retryAfter) res.setHeader("retry-after", String(decision.retryAfter));
    res.setHeader("content-type", "text/plain; charset=utf-8");
    res.end(decision.rule.startsWith("limit:") ? LIMIT_BODY : decision.status === 429 ? "Too Many Requests" : "Forbidden");
  }

  // Stops syncing and sends what's waiting.
  function close() {
    closed = true;
    clearTimeout(syncTimer);
    return flush();
  }

  const ready = valid ? sync() : Promise.resolve();
  // checkAddress for a request: the proxy's guard (index.js).
  function guard(req) {
    try {
      return checkAddress({
        ip: clientIp(req, options.trustProxy), method: req.method, path: pathOf(req), userAgent: header(req, "user-agent"),
      });
    } catch (error) {
      log("check failed, request passed:", error?.message);
      return { action: "allow", rule: "", status: 200 };
    }
  }

  return {
    middleware, check, checkAddress, guard, loginFailed, countStatic, flush, close, ready, clientIp: (req) => clientIp(req, options.trustProxy),
  };
}

module.exports = { createFirewall, clientIp, parseIp, parseRange, IpSet, isStatic, TRUSTS_ALL, CONTENT_TYPE, originForm };
