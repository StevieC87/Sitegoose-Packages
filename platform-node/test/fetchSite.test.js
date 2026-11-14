// A request another site made the browser send is refused, never banned
// (firewall.md, "Checking a request"): any page can make a visitor's browser
// ask for /.env or a page 120 times a minute, from the visitor's own address.
// Run through every adapter that builds the check's input: Express/node:http,
// Fastify and Koa (the Node firewall), Next.js and Hono (the edge one).
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { EventEmitter } = require("node:events");
const { createFirewall } = require("../lib/firewall.js");
const { createNextFirewall } = require("../lib/next.js");
const { createFastifyPlugin } = require("../lib/fastify.js");
const { createKoaMiddleware } = require("../lib/koa.js");
const { createHonoPlatform } = require("../lib/hono.js");

const SITE = "a1b2c3d4e5f6a1b2c3d4e5f6";
const ENDPOINT = "https://collector.test";
const RULES = {
  v: 1, enabled: true, mode: "block", sync: 60, allow: [], deny: [], lists: [], shared: [], goodbots: [], banned: [],
  rate: { limit: 1, window: 60 }, ban: { seconds: 600 }, login: null, flood: null, origin: null, challenge: null,
  probes: { exact: ["/.env"], ban: 600 },
  requests: { rules: [{ id: "shell", action: "block", ban: 600, path: { exact: ["/shell.php"] } }] },
};

function rulesCore() {
  const events = [];
  return {
    events, valid: true, siteId: SITE, secret: "s", log: () => {}, isOn: () => true,
    send: async (module, url, { method, body } = {}) => {
      if (method === "GET") return { status: 200, json: async () => RULES, headers: { get: () => "" } };
      events.push(...(body.events || []));
      return { status: 202 };
    },
  };
}

function fakeRes() {
  const res = new EventEmitter();
  Object.assign(res, { statusCode: 200, headers: {} });
  res.setHeader = (name, value) => { res.headers[name.toLowerCase()] = value; };
  res.getHeader = (name) => res.headers[name.toLowerCase()];
  res.end = () => res.emit("finish");
  return res;
}

// Each adapter on the Node firewall: (url, headers, ip) -> the status, or 0 when it passed.
const NODE_ADAPTERS = {
  express: (middleware) => async (url, headers, ip) => {
    const res = fakeRes();
    let passed = false;
    middleware({ method: "GET", url, headers, socket: { remoteAddress: ip } }, res, () => { passed = true; });
    return passed ? 0 : res.statusCode;
  },
  fastify: (middleware) => {
    const hooks = {};
    createFastifyPlugin(middleware, null)({ addHook: (name, fn) => (hooks[name] = fn) }, {}, () => {});
    return async (url, headers, ip) => {
      const res = fakeRes();
      let passed = false;
      hooks.onRequest({ raw: { method: "GET", url, headers, socket: { remoteAddress: ip } }, ip }, { raw: res }, () => { passed = true; });
      return passed ? 0 : res.statusCode;
    };
  },
  koa: (middleware) => {
    const koa = createKoaMiddleware(middleware, null);
    return async (url, headers, ip) => {
      const ctx = { req: { method: "GET", url, headers, socket: { remoteAddress: ip } }, res: fakeRes(), ip, app: {}, respond: true };
      let passed = false;
      await koa(ctx, async () => { passed = true; });
      return passed ? 0 : ctx.res.statusCode;
    };
  },
};

for (const [name, adapter] of Object.entries(NODE_ADAPTERS)) {
  test(`${name}: a probe, a request rule or the rate limit another site caused is refused, reported as monitor, and bans no one`, async (t) => {
    const core = rulesCore();
    const firewall = createFirewall(core);
    await firewall.ready;
    t.after(() => firewall.close());
    const ask = adapter(firewall.middleware);
    const reported = async () => {
      await firewall.flush();
      return core.events.splice(0).map((event) => `${event.rule} ${event.action}`);
    };

    for (const [i, fetchSite] of ["cross-site", "Same-Site"].entries()) {
      const ip = `198.51.100.${10 + i}`;
      const foreign = { "sec-fetch-site": fetchSite };
      assert.equal(await ask("/.env", foreign, ip), 403);
      assert.equal(await ask("/shell.php", foreign, ip), 403);
      assert.equal(await ask("/", {}, ip), 0, "not banned for either");
      assert.deepEqual(await reported(), ["probe monitor", "request:shell monitor"]);
      assert.equal(await ask("/", foreign, ip), 429, "over the rate");
      assert.equal(await ask("/", {}, ip), 429, "still over the rate, not banned");
      assert.deepEqual(await reported(), ["rate monitor", "rate block"]);
    }

    // Same-origin, none or no header: as before.
    assert.equal(await ask("/.env", { "sec-fetch-site": "same-origin" }, "198.51.100.20"), 403);
    assert.equal(await ask("/", {}, "198.51.100.20"), 403, "banned for the probe");
    assert.equal(await ask("/shell.php", { "sec-fetch-site": "none" }, "198.51.100.21"), 403);
    assert.equal(await ask("/", {}, "198.51.100.21"), 403, "banned for the rule");
    assert.deepEqual(await reported(), ["probe block", "ban block", "request:shell block", "ban block"]);
  });
}

// The edge firewall with a stand-in collector; `ip` is read per request.
function edgeFetch(t) {
  const events = [];
  t.mock.method(globalThis, "fetch", async (url, init = {}) => {
    if (String(url).includes("/rules")) return new Response(JSON.stringify(RULES), { status: 200 });
    events.push(...JSON.parse(init.body).events);
    return new Response("{}", { status: 202 });
  });
  return events;
}

test("next: what another site caused is refused, reported as monitor, and bans no one", async (t) => {
  const events = edgeFetch(t);
  const who = { ip: "" };
  const firewall = createNextFirewall({ siteId: SITE, secret: "s", endpoint: ENDPOINT, trustProxy: () => who.ip });
  const ask = async (target, headers, ip) => {
    who.ip = ip;
    const pending = [];
    const res = await firewall(new Request(`https://site.test${target}`, { headers }), { waitUntil: (p) => pending.push(p) });
    await Promise.all(pending);
    return res ? res.status : 0;
  };
  const reported = async () => {
    await firewall.flush();
    return events.splice(0).map((event) => `${event.rule} ${event.action}`);
  };
  const foreign = { "sec-fetch-site": "cross-site" };
  assert.equal(await ask("/.env", foreign, "198.51.100.10"), 403);
  assert.equal(await ask("/shell.php", foreign, "198.51.100.10"), 403);
  assert.equal(await ask("/", {}, "198.51.100.10"), 0, "not banned for either");
  assert.equal(await ask("/", foreign, "198.51.100.10"), 429);
  assert.equal(await ask("/", {}, "198.51.100.10"), 429, "still over the rate, not banned");
  assert.deepEqual((await reported()).sort(), ["probe monitor", "rate block", "rate monitor", "request:shell monitor"]);

  assert.equal(await ask("/.env", { "sec-fetch-site": "same-origin" }, "198.51.100.20"), 403);
  assert.equal(await ask("/", {}, "198.51.100.20"), 403, "banned for the probe");
  assert.deepEqual((await reported()).sort(), ["ban block", "probe block"]);
});

test("hono: a probe another site caused gets its 403 and bans no one", async (t) => {
  const events = edgeFetch(t);
  const platform = createHonoPlatform({
    siteId: SITE, secret: "s".repeat(32), endpoint: ENDPOINT, trustProxy: 1,
    modules: { analytics: false, errors: false, performance: false, crawlers: false, headers: false, audit: false, flags: false, maintenance: false, proxy: false, forms: false },
  });
  const ask = async (path, headers) => {
    const raw = new Request(`https://site.test${path}`, { headers: { "x-forwarded-for": "198.51.100.4", ...headers } });
    const c = {
      env: {}, req: { raw, path, method: "GET", routePath: "/*", header: (n) => raw.headers.get(n) },
      get executionCtx() { throw new Error("no context"); },
      res: new Response(null), header: () => {}, set: () => {}, get: () => undefined,
    };
    let reached = false;
    const answer = await platform(c, async () => { reached = true; });
    return reached ? 0 : answer?.status;
  };
  assert.equal(await ask("/.env", { "sec-fetch-site": "cross-site" }), 403);
  assert.equal(await ask("/about", {}), 0, "not banned");
  await platform.flush();
  await new Promise((resolve) => setTimeout(resolve, 20));
  assert.deepEqual(events.map((event) => `${event.rule} ${event.action}`), ["probe monitor"]);
});
