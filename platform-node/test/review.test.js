// What the reviews of the Ruby, Java, .NET and Go ports found that this
// package shared: addresses with ports, frameworks that trust every hop,
// IPv6 rotation inside a /64, methods and rows without end, a collector that
// doesn't answer, shutdowns past their grace period, static files against the
// rate limit, joined Cookie headers, visitors who leave, payloads JSON can't
// carry, paths the router normalises, and the regex shapes every engine reads
// alike.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const http = require("node:http");
const { hop, counterKey, makeRoom } = require("../lib/ip.js");
const { createFirewall, clientIp, TRUSTS_ALL } = require("../lib/firewall.js");
const { clientIp: edgeClientIp } = require("../lib/next.js");
const { createLocalBans, isProbe, compileProbes, isStatic } = require("../lib/bans.js");
const { compileRequestRules, matchRequest, safePattern, routedPath } = require("../lib/requestRules.js");
const { cookieValues } = require("../lib/challenge.js");
const { createMaintenance } = require("../lib/maintenance.js");
const { createPerformance, HARD_MAX_KEYS } = require("../lib/performance.js");
const { createCrawlers, HARD_MAX_KEYS: CRAWLER_MAX } = require("../lib/crawlers.js");
const { createProxy, prefixFor, BREAKER_FAILURES } = require("../lib/proxy.js");
const { createErrors } = require("../lib/errors.js");
const { createAnalytics } = require("../lib/analytics.js");
const { createAudit } = require("../lib/audit.js");
const { createCore } = require("../lib/core.js");
const { createFastifyPlugin } = require("../lib/fastify.js");
const { createKoaMiddleware } = require("../lib/koa.js");
const { createPlatform } = require("../index.js");

const SITE = "a1b2c3d4e5f6a1b2c3d4e5f6";

function fakeRes() {
  const res = { statusCode: 200, headers: {}, body: "", headersSent: false };
  res.ended = new Promise((resolve) => { res.done = resolve; });
  res.setHeader = (name, value) => { res.headers[name.toLowerCase()] = value; };
  res.hasHeader = (name) => name.toLowerCase() in res.headers;
  res.writeHead = (status, headers = {}) => {
    res.statusCode = status;
    Object.assign(res.headers, headers);
    res.headersSent = true;
    return res;
  };
  res.end = (body) => {
    res.body = body === undefined ? "" : String(body);
    res.done();
    return res;
  };
  res.once = () => res;
  return res;
}

// A core whose rules fetch answers `rules` and whose events are kept.
function rulesCore(rules) {
  const events = [];
  return {
    events, valid: true, siteId: SITE, secret: "s", log: () => {}, isOn: () => true,
    send: async (module, url, { method, body } = {}) => {
      if (method === "GET") return { status: 200, json: async () => rules, headers: { get: () => "" } };
      events.push(...(body.events || []));
      return { status: 202 };
    },
  };
}

async function firewallWith(t, rules, options = {}) {
  const core = rulesCore({ v: 1, enabled: true, mode: "block", sync: 60, ...rules });
  const firewall = createFirewall(core, options);
  await firewall.ready;
  t.after(() => firewall.close());
  return { firewall, core };
}

// ---- 1. Addresses with a port, and hops that aren't addresses --------------

test("a forwarded hop with a port loses the port", () => {
  assert.equal(hop("203.0.113.5:54321"), "203.0.113.5");
  assert.equal(hop("[2001:db8::1]:443"), "2001:db8::1");
  assert.equal(hop("[2001:db8::1]"), "2001:db8::1");
  assert.equal(hop(" 2001:db8::1 "), "2001:db8::1", "a bare IPv6 address keeps its colons");
  const req = (xff) => ({ headers: { "x-forwarded-for": xff }, socket: { remoteAddress: "10.0.0.2" } });
  assert.equal(clientIp(req("198.51.100.1, 203.0.113.5:54321"), 1), "203.0.113.5");
  assert.equal(clientIp(req("[2001:db8::7]:443"), 1), "2001:db8::7");
});

test("a hop that isn't an address gives the connection's address, so the request is still checked", async (t) => {
  const req = (xff) => ({ headers: { "x-forwarded-for": xff }, socket: { remoteAddress: "198.51.100.66" } });
  assert.equal(clientIp(req("unknown"), 1), "198.51.100.66");
  assert.equal(clientIp(req("203.0.113.1, garbage"), 1), "198.51.100.66");
  assert.equal(clientIp({ headers: {}, socket: { remoteAddress: "198.51.100.66" } }, () => "not-an-ip"), "198.51.100.66");
  assert.equal(edgeClientIp(new Request("https://x.test/", { headers: { "x-forwarded-for": "203.0.113.9:80" } }), 1), "203.0.113.9");
  // The address the firewall then checks is the proxy's, which is denied here.
  const { firewall } = await firewallWith(t, { deny: ["198.51.100.66"] }, { trustProxy: 1 });
  const res = fakeRes();
  let passed = false;
  firewall.middleware({ method: "GET", url: "/", ...req("nonsense") }, res, () => { passed = true; });
  assert.equal(passed, false);
  assert.equal(res.statusCode, 403);
});

// ---- 2. Frameworks that trust every hop -------------------------------------

test("Express's trust proxy true is read as one hop; a hop count or a list is believed", () => {
  const xff = "6.6.6.6, 203.0.113.5";
  const expressReq = (trust, ip) => ({
    headers: { "x-forwarded-for": xff }, socket: { remoteAddress: "10.0.0.2" }, ip,
    app: { get: (name) => (name === "trust proxy fn" ? trust : undefined) },
  });
  // true: Express says 6.6.6.6, which the visitor wrote.
  assert.equal(clientIp(expressReq(() => true, "6.6.6.6")), "203.0.113.5");
  // 1 hop, or the proxy's own range: Express's answer is right and kept.
  assert.equal(clientIp(expressReq((a, i) => i < 1, "203.0.113.5")), "203.0.113.5");
  assert.equal(clientIp(expressReq((a) => a === "10.0.0.2", "203.0.113.5")), "203.0.113.5");
  // Express's answer with a port (an invalid hop it trusted) loses the port.
  assert.equal(clientIp(expressReq((a, i) => i < 2, "203.0.113.5:9000")), "203.0.113.5");
});

test("Fastify's trustProxy: true and Koa's app.proxy without maxIpsCount are read as one hop", async () => {
  const xff = "6.6.6.6, 203.0.113.5";
  const seen = [];
  const middleware = (req, res, next) => { seen.push(clientIp(req)); next(); };
  // Fastify keeps its options under a symbol named fastify.options.
  for (const trustProxy of [true, 1]) {
    const hooks = {};
    const fastify = { [Symbol("fastify.options")]: { trustProxy }, addHook: (name, fn) => { hooks[name] = fn; } };
    createFastifyPlugin(middleware, null)(fastify, {}, () => {});
    const raw = { headers: { "x-forwarded-for": xff }, socket: { remoteAddress: "10.0.0.2" } };
    hooks.onRequest({ raw, ip: trustProxy === true ? "6.6.6.6" : "203.0.113.5" }, { raw: fakeRes() }, () => {});
  }
  assert.deepEqual(seen, ["203.0.113.5", "203.0.113.5"]);
  seen.length = 0;
  for (const app of [{ proxy: true }, { proxy: true, maxIpsCount: 1 }, { proxy: true, proxyIpHeader: "X-Real-IP" }]) {
    const req = { headers: { "x-forwarded-for": xff, "x-real-ip": "198.51.100.4" }, socket: { remoteAddress: "10.0.0.2" } };
    const ip = app.proxyIpHeader ? "198.51.100.4" : app.maxIpsCount ? "203.0.113.5" : "6.6.6.6";
    const res = fakeRes();
    res.once = () => res;
    await createKoaMiddleware(middleware, null)({ req, res, app, ip }, async () => {});
  }
  assert.deepEqual(seen, ["203.0.113.5", "203.0.113.5", "198.51.100.4"]);
  assert.equal(TRUSTS_ALL, Symbol.for("analytics-platform.trusts-every-hop"));
});

// ---- 3. IPv6 rotation, mapped IPv4, and full tables -------------------------

test("the rate limit counts an IPv6 /64 as one visitor, and a mapped IPv4 address as IPv4", async (t) => {
  const { firewall } = await firewallWith(t, { rate: { limit: 2, window: 60 } });
  const ask = (ip) => firewall.check({ ip, method: "GET", path: "/" }).rule;
  assert.equal(ask("2001:db8:1:2::1"), "");
  assert.equal(ask("2001:db8:1:2::ffff"), "");
  assert.equal(ask("2001:db8:1:2:aaaa:bbbb:cccc:dddd"), "rate", "a third address of the same /64");
  assert.equal(ask("2001:db8:1:3::1"), "", "the next /64 is someone else");
  assert.equal(ask("203.0.113.9"), "");
  assert.equal(ask("::ffff:203.0.113.9"), "");
  assert.equal(ask("203.0.113.9"), "rate");
  assert.equal(counterKey("::ffff:203.0.113.9"), counterKey("203.0.113.9"));
});

test("a ban or failed logins hold for the whole /64", () => {
  const bans = createLocalBans();
  bans.loginFailed("2001:db8:5:6::1", { limit: 2, window: 60, ban: 60 });
  bans.loginFailed("2001:db8:5:6::2", { limit: 2, window: 60, ban: 60 });
  assert.equal(bans.banned("2001:db8:5:6:dead:beef::1"), true);
  assert.equal(bans.banned("2001:db8:5:7::1"), false);
});

test("a full table loses its oldest entries, not everyone's", () => {
  const table = new Map([["a", 1], ["b", 2], ["c", 3]]);
  makeRoom(table, 3);
  table.set("d", 4);
  assert.deepEqual([...table.keys()], ["b", "c", "d"]);
});

// ---- 4 and 17. Rows without end ---------------------------------------------

test("Server speed folds made-up methods into OTHER and keeps no more than a hard cap of rows", async () => {
  const sent = [];
  const core = { valid: false, isOn: () => true, log: () => {}, send: async (m, p, { body }) => { sent.push(...body.rows); } };
  const performance = createPerformance(core);
  for (let i = 0; i < 2000; i++) performance.record({ method: `FOO${i}`, route: `/r${i}`, status: 200 + (i % 300), ms: 1 });
  performance.record({ method: "get", route: "/", status: 200, ms: 1 });
  performance.record({ method: "JOB", route: "/(job) x", status: 200, ms: 1 });
  await performance.flush();
  assert.ok(sent.length <= HARD_MAX_KEYS);
  assert.deepEqual([...new Set(sent.map((row) => row.method))].sort(), ["OTHER"], "the cap was reached before the real ones");
  sent.length = 0;
  performance.record({ method: "get", route: "/", status: 200, ms: 1 });
  performance.record({ method: "PROPFIND", route: "/", status: 200, ms: 1 });
  await performance.flush();
  assert.deepEqual(sent.map((row) => row.method).sort(), ["GET", "OTHER"]);
});

test("crawler rows stop at a hard cap however many statuses a bot is answered with", async () => {
  const sent = [];
  const core = { valid: false, isOn: () => true, log: () => {}, send: async (m, p, { body }) => { sent.push(...body.rows); } };
  const crawlers = createCrawlers(core);
  for (let i = 0; i < 3000; i++) crawlers.record({ bot: "GPTBot", path: `/p${i}`, status: 100 + (i % 900) });
  await crawlers.flush();
  assert.ok(sent.length <= CRAWLER_MAX, `${sent.length} rows`);
});

// ---- 5. A collector that doesn't answer -------------------------------------

test("a black-holed collector trips the breaker: answered at once, the file failure remembered", async (t) => {
  const sockets = new Set();
  const hole = http.createServer(() => {});
  hole.on("connection", (socket) => sockets.add(socket));
  await new Promise((resolve) => hole.listen(0, "127.0.0.1", resolve));
  t.after(() => {
    for (const socket of sockets) socket.destroy();
    hole.close();
  });
  const core = { endpoint: `http://127.0.0.1:${hole.address().port}`, secret: "s3cret", valid: true, isOn: () => true, log: () => {} };
  const proxy = createProxy(core);
  const prefix = prefixFor("s3cret");
  const call = async (url, method = "POST") => {
    const res = fakeRes();
    const req = Object.assign(new (require("node:stream").Readable)({ read() { this.push(null); } }), {
      method, url, headers: { "content-type": "text/plain" }, socket: { remoteAddress: "203.0.113.4" },
    });
    const started = Date.now();
    await proxy.middleware(req, res, () => assert.fail("not passed on"));
    await res.ended;
    return { res, ms: Date.now() - started };
  };
  for (let i = 0; i < BREAKER_FAILURES; i++) {
    const { res, ms } = await call(`/${prefix}/api/e`);
    assert.equal(res.statusCode, 502);
    assert.ok(ms < 3500, `timed out after ${ms} ms`);
  }
  const resting = await call(`/${prefix}/api/e`);
  assert.equal(resting.res.statusCode, 502);
  assert.equal(resting.res.headers["retry-after"], "30");
  assert.ok(resting.ms < 200, `answered in ${resting.ms} ms`);
  const file = await call(`/${prefix}/js/v1/s.js`, "GET");
  assert.equal(file.res.statusCode, 502);
  assert.ok(file.ms < 200, "the tracker file isn't fetched while resting");
});

test("a denied address gets no tracker and no collector from the proxy", async (t) => {
  const asked = [];
  t.mock.method(globalThis, "fetch", async (url) => {
    asked.push(String(url));
    if (String(url).includes("/firewall/rules")) {
      return new Response(JSON.stringify({ v: 1, enabled: true, mode: "block", sync: 60, deny: ["203.0.113.66"] }), { status: 200 });
    }
    return new Response("{}", { status: 202 });
  });
  const platform = createPlatform({
    siteId: SITE, secret: "s", endpoint: "https://collector.test",
    errors: false, performance: false, crawlers: false, resources: false, inventory: false, posture: false,
  });
  t.after(() => platform.close());
  await platform.ready;
  const send = (ip) => {
    const res = fakeRes();
    const req = Object.assign(new (require("node:stream").Readable)({ read() { this.push(null); } }), {
      method: "POST", url: `${platform.proxy.collectUrl()}?x=1`, headers: { "content-type": "text/plain" }, socket: { remoteAddress: ip },
    });
    platform.middleware()(req, res, () => assert.fail("not passed on"));
    return res.ended.then(() => res);
  };
  assert.equal((await send("203.0.113.66")).statusCode, 403);
  assert.equal(asked.filter((url) => url.includes("/collectanalytics/")).length, 0);
  assert.equal((await send("203.0.113.67")).statusCode, 202);
});

// ---- 6. Shutdown within a deadline ------------------------------------------

test("close() ends within its deadline, sends no retry, and keeps what's left in the errors file", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "errors-close-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  let posts = 0;
  t.mock.method(globalThis, "fetch", async (url, init = {}) => {
    if (String(url).includes("/server-errors")) {
      posts += 1;
      // Never answers; only the deadline's abort ends it.
      return new Promise((resolve, reject) => init.signal?.addEventListener("abort", () => reject(init.signal.reason)));
    }
    return new Response("{}", { status: 200 });
  });
  const platform = createPlatform({
    siteId: SITE, secret: "s", endpoint: "https://collector.test", closeTimeoutMs: 600,
    firewall: false, performance: false, crawlers: false, resources: false, inventory: false, posture: false,
    errors: { spoolDir: dir, captureUncaught: false },
  });
  platform.captureException(new Error("lost on the way out"));
  const started = Date.now();
  await platform.close();
  const ms = Date.now() - started;
  assert.ok(ms < 1500, `close took ${ms} ms`);
  assert.equal(posts, 1, "no retry at exit");
  const kept = fs.readdirSync(dir).map((name) => fs.readFileSync(path.join(dir, name), "utf8")).join("");
  assert.match(kept, /lost on the way out/);
});

test("a resend killed half way leaves its file, and the next run sends what wasn't sent", async (t) => {
  const crypto = require("node:crypto");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "errors-orphan-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const name = `analytics-errors-${crypto.createHash("sha256").update(`${SITE}|s`).digest("hex").slice(0, 16)}.jsonl`;
  // What a process (now gone: pid 2^22 is never one) was still sending.
  fs.writeFileSync(path.join(dir, `${name}.4194304.sending`), `${JSON.stringify({ message: "orphan" })}\n`);
  fs.writeFileSync(path.join(dir, name), `${JSON.stringify({ message: "waiting" })}\n`);
  const sent = [];
  const core = {
    isOn: () => true, log: () => {}, valid: true, siteId: SITE, secret: "s", endpoint: "",
    send: async (m, p, { body }) => {
      sent.push(...body.errors.map((e) => e.message));
      return { status: 202, headers: { get: () => null } };
    },
  };
  const errors = createErrors(core, { spoolDir: dir, captureUncaught: false });
  t.after(() => errors.close());
  await errors.resend();
  assert.deepEqual(sent.sort(), ["orphan", "waiting"]);
  assert.deepEqual(fs.readdirSync(dir), [], "both files are gone once sent");
});

// ---- 7. Static files and the rate limit --------------------------------------

test("static files the app serves don't count against the rate limit", async (t) => {
  const { firewall } = await firewallWith(t, { rate: { limit: 1, window: 60 }, probes: { exact: ["/.env"], prefix: [] } });
  const ask = (p) => firewall.check({ ip: "203.0.113.20", method: "GET", path: p }).rule;
  assert.equal(ask("/"), "");
  for (const asset of ["/app.css", "/js/main.js?v=3", "/img/a.PNG", "/_next/static/chunks/x", "/assets/index-1.js", "/f.woff2"]) {
    assert.equal(ask(asset), "", asset);
  }
  assert.equal(ask("/.env"), "probe", "probes still apply");
  assert.equal(ask("/about"), "rate");
});

// Tricks that would make a page read as a static file, so a flood of them
// skips the rate and the page limits, and real assets: the cases every
// package shares (sdk/protocols/static-cases.json, firewall.md, `rate`).
const staticCases = JSON.parse(fs.readFileSync(path.join(__dirname, "../../protocols/static-cases.json"), "utf8"))
  .cases.filter((c) => !c.only || c.only.includes("node"));

test("only a path every router reads the same way is a static file", async (t) => {
  for (const { path: target, method = "GET", static: expected } of staticCases) {
    assert.equal(isStatic(target, method), expected, JSON.stringify(target.slice(0, 60)));
  }
  const { firewall: rate } = await firewallWith(t, { rate: { limit: 1, window: 60 } });
  const { firewall: limits } = await firewallWith(t, { limits: { rules: [
    { id: "all", action: "block", limit: 1, window: 60, path: { prefix: ["/"] } },
  ] } });
  staticCases.forEach(({ path: target, method = "GET", static: expected }, i) => {
    const ip = `198.51.100.${i + 1}`;
    for (const [firewall, rule] of [[rate, "rate"], [limits, "limit:all"]]) {
      firewall.check({ ip, method, path: target });
      assert.equal(firewall.check({ ip, method, path: target }).rule, expected ? "" : rule, `${rule}, ${JSON.stringify(target.slice(0, 60))}`);
    }
  });
});

// ---- 8. Cookie headers joined with a comma -----------------------------------

test("a pass or preview code in a second Cookie header joined with ', ' still counts", () => {
  assert.deepEqual(cookieValues("a=1, __sg_pass=20000.abc"), ["20000.abc"]);
  const core = { isOn: () => true, maintenance: () => ({ on: true, bypass: "letmein" }), log: () => {} };
  const { check } = createMaintenance(core);
  assert.equal(check("203.0.113.9", "/", "theme=dark, site_preview=letmein"), null);
});

// ---- 9. Visitors who go away ------------------------------------------------

test("a request the visitor abandoned isn't reported as a server error", async () => {
  const sent = [];
  const core = { isOn: () => true, log: () => {}, valid: true, siteId: SITE, secret: "s", endpoint: "", send: async (m, p, { body }) => { sent.push(...body.errors); return { status: 202, headers: { get: () => null } }; } };
  const errors = createErrors(core, { spoolDir: false, captureUncaught: false });
  const gone = { method: "GET", url: "/download", headers: {}, socket: { destroyed: true } };
  const here = { method: "GET", url: "/download", headers: {}, socket: { destroyed: false } };
  const code = (c, message = c) => Object.assign(new Error(message), { code: c });
  errors.captureException(code("ECONNRESET"), { req: gone, status: 500 });
  errors.captureException(code("EPIPE"), { req: gone, status: 500 });
  errors.captureException(code("ERR_STREAM_PREMATURE_CLOSE"), { req: gone, status: 500 });
  errors.captureException(Object.assign(new Error("request aborted"), { type: "request.aborted" }), { req: here, status: 500 });
  // The app's own call to another server reset: the visitor is still there.
  errors.captureException(code("ECONNRESET", "upstream reset"), { req: here, status: 500 });
  await errors.close();
  assert.deepEqual(sent.map((e) => e.message), ["upstream reset"]);
});

// ---- 10. Payloads JSON can't carry -------------------------------------------

test("track() and audit() turn what JSON can't carry away at the call, and the queue keeps moving", async () => {
  const bodies = [];
  const core = { isOn: () => true, log: () => {}, send: async (m, p, { body }) => { bodies.push(JSON.parse(JSON.stringify(body))); return { ok: true, status: 202 }; } };
  const analytics = createAnalytics(core);
  const circular = {};
  circular.self = circular;
  assert.equal(analytics.track("loop", { extra: circular }), "");
  assert.ok(analytics.track("big", { amount: 12345678901234567890n }));
  assert.ok(analytics.track("after", {}));
  await analytics.flush();
  const events = bodies.flatMap((body) => body.events || []);
  assert.deepEqual(events.map((e) => e.event_name), ["big", "after"]);
  assert.equal(events[0].amount, "12345678901234567890");
  const audit = createAudit(core);
  audit.audit("loop", { details: circular });
  audit.audit("fine", { details: { n: 1n } });
  await audit.flush();
  assert.deepEqual(bodies.flatMap((body) => body.entries || []).map((e) => e.action), ["fine"]);
});

test("identify() passes text, number and true/false traits through, and leaves traits off when none is left", async () => {
  const bodies = [];
  const core = { isOn: () => true, log: () => {}, send: async (m, p, { body }) => { bodies.push(body); return { ok: true, status: 200 }; } };
  const analytics = createAnalytics(core);
  assert.equal(await analytics.identify("u1", { session_id: "s1" }), true);
  assert.equal(await analytics.identify("u1", { session_id: "s1", traits: { plan: "pro", Seats: 5, trial: false, tags: ["a"], meta: { a: 1 }, gone: null, bad: NaN } }), true);
  assert.equal(await analytics.identify("u1", { session_id: "s1", traits: { tags: ["a"] } }), true);
  assert.deepEqual(bodies, [
    { user_id: "u1", session_id: "s1" },
    { user_id: "u1", session_id: "s1", traits: { plan: "pro", Seats: 5, trial: false } },
    { user_id: "u1", session_id: "s1" },
  ]);
});

test("a body that can't be JSON is told apart from a network failure", async (t) => {
  t.mock.method(globalThis, "fetch", async () => assert.fail("never sent"));
  const core = createCore({ siteId: SITE, secret: "s", endpoint: "https://collector.test" });
  const circular = {};
  circular.self = circular;
  const res = await core.send("x", "/events/x", { body: { circular } });
  assert.equal(res.unsendable, true);
  assert.equal(res.status, 0);
});

// ---- 11. Paths the router normalises ---------------------------------------

test("request rules and probes match the path as the router sees it", () => {
  assert.equal(routedPath("/x;y/../admin"), "/admin");
  assert.equal(routedPath("/public/%2e%2e/admin/"), "/admin/");
  assert.equal(routedPath("/a/./b"), "/a/b");
  const rules = compileRequestRules({ rules: [{ id: "admin", action: "block", path: { prefix: ["/admin"] } }] });
  assert.equal(matchRequest(rules, { method: "GET", path: "/x;y/../admin/users" })?.id, "admin");
  assert.equal(matchRequest(rules, { method: "GET", path: "/static;v=1/..;/admin" })?.id, "admin");
  assert.equal(matchRequest(rules, { method: "GET", path: "/admin" })?.id, "admin", "the raw path still counts");
  assert.equal(matchRequest(rules, { method: "GET", path: "/x/../help" }), null);
  const probes = compileProbes({ exact: ["/.env"], prefix: ["/.git/"] });
  assert.equal(isProbe("/static/..;/.env", probes), true);
  assert.equal(isProbe("/a/%2e%2e/.git/config", probes), true);
});

// ---- 12. Message length, the spool's size, the rules cache ------------------

test("an error's message is cut to 2,000 characters", async () => {
  const sent = [];
  const core = { isOn: () => true, log: () => {}, valid: true, siteId: SITE, secret: "s", endpoint: "", send: async (m, p, { body }) => { sent.push(...body.errors); return { status: 202, headers: { get: () => null } }; } };
  const errors = createErrors(core, { spoolDir: false, captureUncaught: false });
  errors.captureException(new Error("x".repeat(50000)));
  await errors.close();
  assert.equal(sent[0].message.length, 2000);
});

test("the errors file never grows past its size, this write included", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "errors-cap-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const core = { isOn: () => true, log: () => {}, valid: true, siteId: SITE, secret: "s", endpoint: "", send: async () => null, timeLeft: () => 0 };
  const errors = createErrors(core, { spoolDir: dir, captureUncaught: false });
  // 12 rounds of 100 errors of about 2.3 kB: some 2.8 MB offered.
  for (let round = 0; round < 12; round++) {
    for (let i = 0; i < 100; i++) errors.captureException(new Error(`${round}.${i} ${"y".repeat(1900)}`));
    errors.persist();
  }
  const [file] = fs.readdirSync(dir);
  const size = fs.statSync(path.join(dir, file)).size;
  assert.ok(size <= 1024 * 1024 && size > 1000 * 1000, `${size} bytes`);
  await errors.close();
});

test("the rules cache file is written whole: beside it first, then renamed", async (t) => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "rules-cache-"));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const cacheFile = path.join(dir, "rules.json");
  const { firewall } = await firewallWith(t, { deny: ["198.51.100.1"] }, { cacheFile });
  await new Promise((resolve) => setTimeout(resolve, 50));
  assert.deepEqual(fs.readdirSync(dir), ["rules.json"], "no temp file left over");
  assert.deepEqual(JSON.parse(fs.readFileSync(cacheFile, "utf8")).rules.deny, ["198.51.100.1"]);
  await firewall.close();
});

// ---- 13. The maintenance preview cookie --------------------------------------

test("the preview cookie is Secure over HTTPS, and only then", () => {
  const core = { isOn: () => true, maintenance: () => ({ on: true, bypass: "letmein" }), log: () => {} };
  const run = (req, options) => {
    const res = fakeRes();
    createMaintenance(core, options).middleware({ headers: {}, ...req }, res, () => {});
    return res.headers["set-cookie"];
  };
  assert.match(run({ url: "/?site_preview=letmein", socket: { encrypted: true } }), /; Secure$/);
  assert.match(run({ url: "/?site_preview=letmein", socket: {}, protocol: "https" }), /; Secure$/);
  assert.doesNotMatch(run({ url: "/?site_preview=letmein", socket: {} }), /Secure/);
  // X-Forwarded-Proto only from a proxy the package was told to believe.
  assert.doesNotMatch(run({ url: "/?site_preview=letmein", socket: {}, headers: { "x-forwarded-proto": "https" } }), /Secure/);
  assert.match(run({ url: "/?site_preview=letmein", socket: {}, headers: { "x-forwarded-proto": "https" } }, { trustProxy: 1 }), /; Secure$/);
  assert.equal(run({ url: "/?site_preview=letmeim", socket: {} }), undefined);
});

// ---- 16. Regex shapes every engine reads alike -------------------------------

test("a pattern's groups are an allow-list: (, (?:, (?= and (?! only", () => {
  for (const pattern of ["(?:a)b", "(?=x)y", "(?!x)y", "(ab)+", "a\\+(b)+", "[(?<]x", "\\\\1"]) {
    assert.equal(safePattern(pattern), true, pattern);
  }
  for (const pattern of ["(a)\\1", "(?<n>a)", "(?<=x)y", "(?P<n>a)", "(?P=n)", "\\k<n>", "(?i)a", "(?>a)", "(?R)", "(?1)",
    "(?(1)a|b)", "\\g{1}", "\\g1", "(*FAIL)", "a++", "a*+", "a?+", "a{2,}+", "(?#comment)", "(?|a)"]) {
    assert.equal(safePattern(pattern), false, pattern);
  }
});

test("the shared counter key is the same text in every package", () => {
  assert.equal(counterKey("198.51.100.7"), "198.51.100.7");
  assert.equal(counterKey("::ffff:198.51.100.7"), "198.51.100.7");
  assert.equal(counterKey("2001:db8:1:2:aa::1"), "2001:db8:1:2::/64");
  assert.equal(counterKey("2001:0:0:0:5::"), "2001::/64");
  assert.equal(counterKey("2001:db8:0:1::5"), "2001:db8:0:1::/64");
  assert.equal(counterKey("1:2:3:4::"), "1:2:3:4::/64");
});

test("dashboard headers: visible ASCII values, never a framing header", () => {
  const { safeHeader } = require("../lib/core.js");
  assert.ok(safeHeader(["X-Frame-Options", "DENY"]));
  assert.ok(safeHeader(["Content-Security-Policy", "default-src\t'self'"]));
  assert.ok(!safeHeader(["Content-Security-Policy", "default-src \u2018self\u2019"]));
  assert.ok(!safeHeader(["X-A", "a\u0001b"]));
  assert.ok(!safeHeader(["X-A", "a\nSet-Cookie: x=1"]));
  for (const name of ["Content-Length", "transfer-encoding", "Connection", "Set-Cookie", "Content-Type"]) {
    assert.ok(!safeHeader([name, "1"]), name);
  }
});
