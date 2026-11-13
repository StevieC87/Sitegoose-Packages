// A static-looking request counted after the response (firewall.md, `rate`):
// compared with the counts first (an address already over is refused its
// files), then counted toward the rate and the page limits it skipped when
// the router sent it to a route that isn't a file's ("/search/:q" took
// "/search/x.css") or it answered 400 or more. Through Express (req.route),
// the Fastify plugin, the Koa middleware and Hono, against stand-ins.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { EventEmitter } = require("node:events");
const { createFirewall } = require("../lib/firewall.js");
const { createFastifyPlugin } = require("../lib/fastify.js");
const { createKoaMiddleware } = require("../lib/koa.js");
const { createHonoPlatform } = require("../lib/hono.js");
const { routedToPage } = require("../lib/bans.js");

const SITE = "a1b2c3d4e5f6a1b2c3d4e5f6";
const IP = "198.51.100.7";
const SEARCH = { rules: [{ id: "search", action: "block", limit: 2, window: 60, path: { prefix: ["/search"] } }] };
const RULES = {
  v: 1, enabled: true, mode: "block", sync: 60, allow: [], deny: [], lists: [], shared: [], goodbots: [],
  rate: null, banned: [], ban: null, login: null, probes: null, requests: { rules: [] }, limits: SEARCH,
};

async function firewallWith(t, rules = {}) {
  const core = {
    valid: true, siteId: SITE, secret: "s", log: () => {}, isOn: () => true,
    send: async (module, url, { method } = {}) => (method === "GET"
      ? { status: 200, json: async () => ({ ...RULES, ...rules }), headers: { get: () => "" } }
      : { status: 202 }),
  };
  const firewall = createFirewall(core);
  await firewall.ready;
  t.after(() => firewall.close());
  return firewall;
}

function fakeRes() {
  const res = new EventEmitter();
  res.statusCode = 200;
  res.headers = {};
  res.setHeader = (name, value) => { res.headers[name.toLowerCase()] = value; };
  res.getHeader = (name) => res.headers[name.toLowerCase()];
  res.end = () => res.emit("finish");
  return res;
}

// One Express request: the middleware, then the app (route, status,
// Content-Type), then the response finishing. -> the status answered.
function express(firewall, url, { route, status = 200, type } = {}) {
  const req = { method: "GET", url, originalUrl: url, headers: {}, socket: { remoteAddress: IP } };
  const res = fakeRes();
  firewall.middleware(req, res, () => {
    if (route) req.route = { path: route };
    res.statusCode = status;
    if (type) res.setHeader("content-type", type);
  });
  res.emit("finish");
  res.emit("close");
  return res.statusCode;
}

const searchPage = (firewall) => firewall.check({ ip: IP, method: "GET", path: "/search" }).rule;

test("a routed /search/x.css counts toward the /search page limit after the response", async (t) => {
  const firewall = await firewallWith(t);
  assert.equal(express(firewall, "/search/x.css", { route: "/search/:q", type: "text/html" }), 200);
  assert.equal(express(firewall, "/search/y.css", { route: "/search/:q", type: "text/html" }), 200);
  assert.equal(express(firewall, "/search/z.css", { route: "/search/:q", type: "text/html" }), 200);
  assert.equal(express(firewall, "/search/w.css", { route: "/search/:q" }), 429, "over: the next one is refused before the app");
});

test("a real asset, a file's route and a file answered are not counted", async (t) => {
  const firewall = await firewallWith(t);
  for (let i = 0; i < 5; i += 1) {
    express(firewall, "/search/app.css", { type: "text/css" }); // express.static: no req.route
    express(firewall, "/search/a.png", { route: "/search/:id.png", type: "image/png" });
    express(firewall, "/search/b.css", { route: "/search/*", type: "text/css" }); // sendFile under a wildcard
    express(firewall, "/search/c.css", { route: ["/static/*", "/assets/*"] });
    express(firewall, "/search/d.css", { route: "/search/*", status: 304 }); // revalidated: no Content-Type
  }
  assert.equal(searchPage(firewall), "");
  assert.equal(searchPage(firewall), "");
  assert.equal(searchPage(firewall), "limit:search");
});

test("an error counts with no route; an address over is refused its files", async (t) => {
  const firewall = await firewallWith(t, { rate: { limit: 2, window: 60 }, ban: { seconds: 600 } });
  assert.equal(express(firewall, "/made-up.css", { status: 404 }), 404);
  assert.equal(express(firewall, "/made-up.js", { status: 404 }), 404);
  assert.equal(express(firewall, "/made-up.svg", { status: 404 }), 404);
  assert.equal(express(firewall, "/made-up.png", { status: 404 }), 429, "over the rate: refused, files and all");
  assert.equal(firewall.check({ ip: IP, method: "GET", path: "/about" }).rule, "ban", "and banned, as for a page");
});

test("peeking adds nothing: files fetched after a page don't use up the limit", async (t) => {
  const firewall = await firewallWith(t);
  assert.equal(searchPage(firewall), "");
  for (let i = 0; i < 10; i += 1) assert.equal(express(firewall, "/search/app.css", { type: "text/css" }), 200);
  assert.equal(searchPage(firewall), "");
  assert.equal(express(firewall, "/search/app.css"), 200);
  assert.equal(searchPage(firewall), "limit:search");
  assert.equal(express(firewall, "/search/app.css"), 429, "an address over the limit is refused its files too");
});

test("routedToPage: a page's route, not a file's", () => {
  assert.equal(routedToPage("/search/:q", "text/html; charset=utf-8"), true);
  assert.equal(routedToPage(/^\/s\/.*/, undefined), true);
  assert.equal(routedToPage("*", undefined), true);
  assert.equal(routedToPage(undefined, "text/html"), false);
  assert.equal(routedToPage("/avatars/:id.png", "text/html"), false);
  assert.equal(routedToPage("/static/*", undefined), false);
  assert.equal(routedToPage("/files/:name", "application/pdf"), false);
  assert.equal(routedToPage("/files/:name", ["font/woff2"]), false);
});

test("Fastify: routeOptions.url and the Content-Type onSend kept", async (t) => {
  const firewall = await firewallWith(t);
  const hooks = {};
  createFastifyPlugin(firewall.middleware, null, {}, null, true)({ addHook: (name, fn) => (hooks[name] = fn) }, {}, () => {});
  const ask = (url, route, type) => {
    const raw = { method: "GET", url, headers: {}, socket: { remoteAddress: IP } };
    const res = fakeRes();
    // Fastify's writeHead: res.getHeader() can't read what it wrote.
    res.getHeader = () => undefined;
    let passed = false;
    hooks.onRequest({ raw, ip: IP, routeOptions: { url: route } }, { raw: res }, () => (passed = true));
    if (passed) hooks.onSend({ raw }, { getHeader: () => type }, "", () => {});
    res.emit("finish");
    return passed;
  };
  for (let i = 0; i < 5; i += 1) assert.equal(ask("/search/app.css", "/search/*", "text/css"), true, "@fastify/static's wildcard");
  assert.equal(ask("/search/x.css", "/search/:q", "text/html"), true);
  assert.equal(ask("/search/y.css", "/search/:q", "text/html"), true);
  assert.equal(ask("/search/z.css", "/search/:q", "text/html"), true);
  assert.equal(ask("/search/w.css", "/search/:q", "text/html"), false);
});

test("Koa: the router's _matchedRoute, read once the app has run", async (t) => {
  const firewall = await firewallWith(t);
  const koa = createKoaMiddleware(firewall.middleware, null);
  const ask = async (url, route, type) => {
    const res = fakeRes();
    const ctx = { req: { method: "GET", url, headers: {}, socket: { remoteAddress: IP } }, res, ip: IP, app: {}, respond: true };
    let reached = false;
    await koa(ctx, async () => {
      reached = true;
      if (route) ctx._matchedRoute = route;
      if (type) res.setHeader("content-type", type);
    });
    res.emit("finish");
    return reached;
  };
  for (let i = 0; i < 5; i += 1) assert.equal(await ask("/search/app.css", undefined, "text/css"), true, "koa-static: no route");
  assert.equal(await ask("/search/x.css", "/search/:q", "text/html"), true);
  assert.equal(await ask("/search/y.css", "/search/:q", "text/html"), true);
  assert.equal(await ask("/search/z.css", "/search/:q", "text/html"), true);
  assert.equal(await ask("/search/w.css", "/search/:q", "text/html"), false);
});

test("Hono: routePath after next(), not serveStatic's file", async (t) => {
  const original = globalThis.fetch;
  globalThis.fetch = async (url, init = {}) => {
    if (String(url).includes("/events/firewall/rules")) return new Response(JSON.stringify(RULES), { status: 200 });
    return new Response(null, { status: String(url).includes("config") ? 404 : 202 });
  };
  t.after(() => { globalThis.fetch = original; });
  const platform = createHonoPlatform({ siteId: SITE, secret: "s".repeat(32), endpoint: "https://collector.example", trustProxy: 1 });
  const ask = async (path, route, type) => {
    const raw = new Request(`https://site.example${path}`, { headers: { "x-forwarded-for": IP } });
    let res;
    const c = {
      env: {},
      req: { raw, path, method: "GET", routePath: "/*", header: (name) => raw.headers.get(name) },
      get executionCtx() { throw new Error("no context"); },
      get res() { return (res ||= new Response(null)); },
      set res(value) { res = value; },
      header: () => {},
    };
    let reached = false;
    const answer = await platform(c, async () => {
      reached = true;
      c.req.routePath = route;
      c.res = new Response("", { status: 200, headers: { "content-type": type } });
    });
    await new Promise((resolve) => setTimeout(resolve, 5));
    return reached ? 200 : answer?.status;
  };
  for (let i = 0; i < 5; i += 1) assert.equal(await ask("/search/app.css", "/search/*", "text/css"), 200, "serveStatic");
  assert.equal(await ask("/search/x.css", "/search/:q", "text/html"), 200);
  assert.equal(await ask("/search/y.css", "/search/:q", "text/html"), 200);
  assert.equal(await ask("/search/z.css", "/search/:q", "text/html"), 200);
  assert.equal(await ask("/search/w.css", "/search/:q", "text/html"), 429);
  await platform.flush();
});

test("Next.js edge with a shared counter: a count seen over refuses the files; nothing counted late", async (t) => {
  const { createNextFirewall } = require("../lib/next.js");
  t.mock.method(globalThis, "fetch", async (url) => (String(url).includes("/rules")
    ? new Response(JSON.stringify(RULES), { status: 200 }) : new Response("{}", { status: 202 })));
  const shared = new Map();
  const counter = async (key) => {
    shared.set(key, (shared.get(key) || 0) + 1);
    return shared.get(key);
  };
  const firewall = createNextFirewall({ siteId: SITE, secret: "s", endpoint: "https://collector.test", trustProxy: () => IP, counter });
  const ask = async (target) => (await firewall(new Request(`https://site.test${target}`), { waitUntil: () => {} }))?.status || 200;
  assert.equal(await ask("/search/app.css"), 200);
  assert.equal(shared.size, 0, "a static file adds nothing to the shared counter");
  assert.equal(await ask("/search"), 200);
  assert.equal(await ask("/search"), 200);
  assert.equal(await ask("/search/app.css"), 200, "not over yet");
  assert.equal(await ask("/search"), 429);
  assert.equal(await ask("/search/app.css"), 429, "seen over here: refused without adding");
  assert.deepEqual([...shared.values()], [3]);
  await firewall.flush();
});
