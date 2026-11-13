// The browser check (rule `challenge`): every case in the shared file
// sdk/protocols/challenge-cases.json (tokens, valid and invalid passes, which
// requests are checked), with node:crypto's HMAC and WebCrypto's, then the
// check page as each adapter answers it: Express / node:http, Fastify, Koa,
// Next.js (edge) and Hono. A POST, an API call or a site without the check
// gets nothing new.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { EventEmitter } = require("node:events");
const {
  whoOf, dayOf, createSigner, hasPass, hasPassSync, passFor, passForSync, asksForPage, exempted, compileChallenge, cookieValues,
} = require("../lib/challenge.js");
const { createFirewall } = require("../lib/firewall.js");
const { createNextFirewall } = require("../lib/next.js");
const { createPlatform } = require("../index.js");
const { createFastifyPlugin } = require("../lib/fastify.js");
const { createHonoPlatform } = require("../lib/hono.js");
const { IpSet } = require("../lib/ip.js");

const cases = JSON.parse(fs.readFileSync(path.join(__dirname, "../../protocols/challenge-cases.json"), "utf8"));
const SECRET = cases.secret;
const SITE = "a".repeat(24);
const ENDPOINT = "https://collector.test";
const BROWSER = "text/html,application/xhtml+xml,*/*;q=0.8";
const RULES = { v: 1, enabled: true, mode: "block", sync: 60, challenge: cases.challenge };

const signers = { "node:crypto": createSigner(SECRET), WebCrypto: createSigner(SECRET, { web: true }) };

// ---- The shared cases --------------------------------------------------------

test("tokens: who each address is bound to, and its pass", async () => {
  for (const c of cases.tokens) {
    if (c.ip !== "*") assert.equal(whoOf(c.ip), c.who, c.ip);
    const day = dayOf(c.now * 1000);
    for (const [name, sign] of Object.entries(signers)) {
      const token = `${day}.${String(await sign(`${day}|${c.who}`)).slice(0, 32)}`;
      assert.equal(token, c.token, `${name} ${c.ip}`);
      if (c.ip !== "*") {
        assert.equal(await passFor(sign, c.ip, c.now * 1000), c.token, `${name} passFor ${c.ip}`);
        if (name === "node:crypto") assert.equal(passForSync(sign, c.ip, c.now * 1000), c.token);
      }
    }
  }
  assert.equal(whoOf("not an address"), "");
});

test("checks: which cookie values are a valid pass", async () => {
  for (const c of cases.checks) {
    const header = `__sg_pass=${c.cookie}`;
    for (const [name, sign] of Object.entries(signers)) {
      assert.equal(await hasPass(sign, c.ip, header, c.now * 1000), c.valid, `${name}: ${c.why}`);
    }
    assert.equal(hasPassSync(signers["node:crypto"], c.ip, header, c.now * 1000), c.valid, c.why);
  }
});

test("decisions: which requests get the check page", async () => {
  const challenge = compileChallenge(cases.challenge);
  const empty = { allow: new IpSet([]), goodbots: new IpSet([]) };
  for (const c of cases.decisions) {
    const { method, path: target, accept, ip, cookie } = c.request;
    const { parseIp } = require("../lib/ip.js");
    const checked = asksForPage(challenge, method, accept, target) && !exempted(challenge, parseIp(ip), empty)
      && !(await hasPass(signers.WebCrypto, ip, `__sg_pass=${cookie}`, c.now * 1000));
    assert.equal(checked, c.challenged, c.why);
  }
});

test("decisions, as the Node firewall's middleware answers them", async (t) => {
  for (const c of cases.decisions) {
    t.mock.method(Date, "now", () => c.now * 1000);
    const { firewall } = await nodeFirewall(t);
    const res = fakeRes();
    let passed = false;
    firewall.middleware(nodeReq(c.request), res, () => { passed = true; });
    assert.equal(!passed && res.statusCode === 503, c.challenged, c.why);
    t.mock.restoreAll();
  }
});

test("decisions, as the edge firewall answers them", async (t) => {
  for (const c of cases.decisions) {
    t.mock.method(Date, "now", () => c.now * 1000);
    const { firewall } = edgeFirewall(t, { trustProxy: () => c.request.ip });
    const answer = await firewall(new Request("https://site.test" + c.request.path, {
      method: c.request.method.toUpperCase(),
      headers: { accept: c.request.accept, cookie: `__sg_pass=${c.request.cookie}` },
    }), { waitUntil: () => {} });
    assert.equal(answer?.status === 503, c.challenged, c.why);
    t.mock.restoreAll();
  }
});

test("a browser sends several cookies, and a quoted one", () => {
  assert.deepEqual(cookieValues('a=1; __sg_pass=x; __sg_pass="y"; b=2'), ["x", "y"]);
  assert.deepEqual(cookieValues("__sg_passn=z"), []);
});

// ---- Helpers ----------------------------------------------------------------

function fakeRes() {
  const res = new EventEmitter();
  Object.assign(res, { statusCode: 200, headers: {}, body: undefined, ended: false });
  res.setHeader = (name, value) => { res.headers[name.toLowerCase()] = value; };
  res.hasHeader = (name) => name.toLowerCase() in res.headers;
  res.end = (body) => { res.body = body === undefined ? "" : String(body); res.ended = true; res.emit("finish"); };
  return res;
}

function nodeReq({ method = "GET", path: url = "/pricing", accept = BROWSER, ip = "198.51.100.9", cookie = "", headers = {}, encrypted = false } = {}) {
  return {
    method, url,
    headers: { accept, ...(cookie ? { cookie: `__sg_pass=${cookie}` } : {}), "user-agent": "Mozilla/5.0", ...headers },
    socket: { remoteAddress: ip, encrypted },
  };
}

// A core whose rules fetch answers `rules` and whose events are kept.
function fakeCore(rules) {
  const fetches = [];
  const events = [];
  return {
    fetches,
    events,
    valid: true,
    siteId: SITE,
    secret: SECRET,
    log: () => {},
    send: async (module, url, { method, headers, body } = {}) => {
      if (method === "GET") {
        fetches.push(headers);
        return { status: 200, json: async () => rules, headers: { get: () => "" } };
      }
      events.push(...body.events);
      return { status: 202 };
    },
  };
}

async function nodeFirewall(t, rules = RULES, options = {}) {
  const core = fakeCore(rules);
  const firewall = createFirewall(core, options);
  await firewall.ready;
  t.after(() => firewall.close());
  return { firewall, core };
}

// The edge firewall with a stand-in collector.
function edgeFirewall(t, options = {}, rules = RULES) {
  const fetches = [];
  const events = [];
  t.mock.method(globalThis, "fetch", async (url, init = {}) => {
    if (String(url).includes("/rules")) {
      fetches.push(init.headers);
      return new Response(JSON.stringify(rules), { status: 200 });
    }
    events.push(...JSON.parse(init.body).events);
    return new Response("{}", { status: 202 });
  });
  const firewall = createNextFirewall({ siteId: SITE, secret: SECRET, endpoint: ENDPOINT, ...options });
  return { firewall, fetches, events };
}

const nonceOf = (csp) => /'nonce-([0-9a-f]+)'/.exec(csp)?.[1];
const passIn = (body) => /v="(\d+\.[0-9a-f]{32})"/.exec(body)?.[1];

// The page as the spec has it: headers, a CSP whose nonce the script carries,
// the pass for this address, Secure left to the browser's location.
function assertPage(status, headers, body, { ip = "198.51.100.9", head = false } = {}) {
  const get = (name) => (typeof headers.get === "function" ? headers.get(name) : headers[name]);
  assert.equal(status, 503);
  assert.equal(get("content-type"), "text/html; charset=utf-8");
  assert.equal(get("cache-control"), "no-store");
  assert.equal(get("x-robots-tag"), "noindex");
  const nonce = nonceOf(get("content-security-policy"));
  assert.ok(nonce && nonce.length >= 22, "a nonce of its own");
  if (head) return assert.equal(body || "", "");
  assert.ok(body.includes(`<script nonce="${nonce}">`));
  assert.ok(body.includes("<noscript>"));
  assert.ok(body.includes("Max-Age=86400; Path=/; SameSite=Lax"));
  assert.ok(body.includes('s=location.protocol==="https:"'));
  assert.equal(passIn(body), passForSync(signers["node:crypto"], ip));
}

// ---- Express / node:http ----------------------------------------------------

test("Express: a browser's first page gets the check, and its pass then lets it in", async (t) => {
  const { firewall, core } = await nodeFirewall(t);
  const res = fakeRes();
  let passed = false;
  firewall.middleware(nodeReq(), res, () => { passed = true; });
  assert.equal(passed, false);
  assertPage(res.statusCode, res.headers, res.body);

  // Two pages carry two different nonces.
  const again = fakeRes();
  firewall.middleware(nodeReq(), again, () => {});
  assert.notEqual(nonceOf(again.headers["content-security-policy"]), nonceOf(res.headers["content-security-policy"]));

  // The reload, with the cookie the script set.
  let through = false;
  firewall.middleware(nodeReq({ cookie: passIn(res.body) }), fakeRes(), () => { through = true; });
  assert.equal(through, true);

  // Reported as rule challenge, action block, grouped.
  await firewall.flush();
  assert.deepEqual(core.events.map((e) => `${e.ip} ${e.rule} ${e.action} ${e.method} ${e.path} x${e.hits}`),
    ["198.51.100.9 challenge block GET /pricing x2"]);
});

test("Express: a POST, a JSON call, a skipped path, an allowed or good-bot address go straight through", async (t) => {
  const { firewall, core } = await nodeFirewall(t, { ...RULES, allow: ["203.0.113.50"], goodbots: ["203.0.113.60"] });
  for (const req of [
    nodeReq({ method: "POST" }),
    nodeReq({ accept: "application/json" }),
    nodeReq({ accept: "*/*" }),
    nodeReq({ path: "/api/orders" }),
    nodeReq({ path: "/wp-json/wp/v2/posts" }),
    nodeReq({ ip: "203.0.113.50" }),
    nodeReq({ ip: "203.0.113.60" }),
    nodeReq({ ip: "66.249.64.9" }),
  ]) {
    let passed = false;
    const res = fakeRes();
    firewall.middleware(req, res, () => { passed = true; });
    assert.equal(passed, true, `${req.method} ${req.url} ${req.headers.accept} ${req.socket.remoteAddress}`);
    assert.equal(res.ended, false);
  }
  await firewall.flush();
  assert.deepEqual(core.events, []);
});

test("Express: a HEAD gets the same status and headers, no body", async (t) => {
  const { firewall } = await nodeFirewall(t);
  const res = fakeRes();
  firewall.middleware(nodeReq({ method: "HEAD" }), res, () => {});
  assertPage(res.statusCode, res.headers, res.body, { head: true });
});

test("Express: `challenge: null` (or no key) changes nothing, and the check is on in monitor mode too", async (t) => {
  for (const rules of [{ ...RULES, challenge: null }, { v: 1, enabled: true, mode: "block", sync: 60 }]) {
    const { firewall } = await nodeFirewall(t, rules);
    let passed = false;
    firewall.middleware(nodeReq(), fakeRes(), () => { passed = true; });
    assert.equal(passed, true);
    assert.deepEqual(firewall.check({ ip: "198.51.100.9", method: "GET", path: "/", accept: BROWSER }), { action: "allow", rule: "", status: 200 });
  }
  const { firewall } = await nodeFirewall(t, { ...RULES, mode: "monitor" });
  const res = fakeRes();
  firewall.middleware(nodeReq(), res, () => {});
  assert.equal(res.statusCode, 503);
});

test("Express: an earlier rule wins, onBlock isn't asked for the check page, and check() without Accept checks nothing", async (t) => {
  let blocked = 0;
  const { firewall } = await nodeFirewall(t, { ...RULES, deny: ["203.0.113.66"] }, { onBlock: (req, res) => { blocked += 1; res.end("mine"); } });
  const denied = fakeRes();
  firewall.middleware(nodeReq({ ip: "203.0.113.66" }), denied, () => {});
  assert.equal(denied.body, "mine");
  const checked = fakeRes();
  firewall.middleware(nodeReq(), checked, () => {});
  assert.equal(checked.statusCode, 503);
  assert.equal(blocked, 1);
  assert.equal(firewall.check({ ip: "198.51.100.9", method: "GET", path: "/" }).action, "allow");
  const d = firewall.check({ ip: "198.51.100.9", method: "GET", path: "/", accept: BROWSER });
  assert.equal(d.rule, "challenge");
  assertPage(d.status, d.headers, d.body);
});

test("a match only watched (monitor) still gets the check, and both are reported", async (t) => {
  const { firewall, core } = await nodeFirewall(t, { ...RULES, mode: "monitor", deny: ["198.51.100.9"] });
  const res = fakeRes();
  firewall.middleware(nodeReq(), res, () => {});
  assert.equal(res.statusCode, 503);
  assert.equal(firewall.check({ ip: "198.51.100.9", method: "POST", path: "/", accept: BROWSER }).action, "monitor");
  await firewall.flush();
  assert.deepEqual(core.events.map((e) => `${e.rule} ${e.action} ${e.method}`).sort(),
    ["challenge block GET", "deny monitor GET", "deny monitor POST"]);
});

test("the rules fetch names the layers and the server", async (t) => {
  const { core } = await nodeFirewall(t, RULES, { serverName: "web-1\n" });
  assert.equal(core.fetches[0]["x-firewall-layers"], "app check");
  assert.equal(core.fetches[0]["x-server-name"], "web-1?");
  const plain = await nodeFirewall(t);
  assert.equal(plain.core.fetches[0]["x-server-name"], require("node:os").hostname().slice(0, 100));
});

// ---- Fastify and Koa (through createPlatform) --------------------------------

function platformWith(t, rules = RULES, options = {}) {
  t.mock.method(globalThis, "fetch", async (url) => (String(url).includes("/firewall/rules")
    ? new Response(JSON.stringify(rules), { status: 200 })
    : new Response(null, { status: 404 })));
  const off = { errors: false, analytics: false, performance: false, crawlers: false, forms: false, headers: false, audit: false,
    flags: false, maintenance: false, inventory: false, posture: false, resources: false, proxy: false };
  const platform = createPlatform({ siteId: SITE, secret: SECRET, endpoint: ENDPOINT, ...off, ...options });
  t.after(() => platform.close());
  return platform;
}

test("Fastify: the check page from onRequest; a POST reaches the route", async (t) => {
  const platform = platformWith(t);
  await platform.ready;
  const hooks = {};
  platform.fastify()({ addHook: (name, fn) => (hooks[name] = fn) }, {}, () => {});
  const raw = nodeReq({ ip: "10.0.0.1" });
  const reply = { raw: fakeRes() };
  let reached = false;
  hooks.onRequest({ raw, ip: "198.51.100.9" }, reply, () => { reached = true; });
  assert.equal(reached, false);
  assertPage(reply.raw.statusCode, reply.raw.headers, reply.raw.body);

  let posted = false;
  hooks.onRequest({ raw: nodeReq({ method: "POST" }), ip: "198.51.100.9" }, { raw: fakeRes() }, () => { posted = true; });
  assert.equal(posted, true);
  // The plugin alone, unchanged for a middleware that passes.
  const { hooks: plain } = (() => { const h = {}; createFastifyPlugin((req, res, next) => next(), null)({ addHook: (n, f) => (h[n] = f) }, {}, () => {}); return { hooks: h }; })();
  let ok = false;
  plain.onRequest({ raw: {}, ip: "1.2.3.4" }, { raw: {} }, () => { ok = true; });
  assert.equal(ok, true);
});

test("Koa: the check page, Koa leaves the response alone; a JSON call reaches the app", async (t) => {
  const platform = platformWith(t);
  await platform.ready;
  const koa = platform.koa();
  const ctx = { req: nodeReq({ ip: "10.0.0.1" }), res: fakeRes(), ip: "198.51.100.9", respond: true };
  let reached = false;
  await koa(ctx, async () => { reached = true; });
  assert.equal(reached, false);
  assert.equal(ctx.respond, false);
  assertPage(ctx.res.statusCode, ctx.res.headers, ctx.res.body);

  const api = { req: nodeReq({ accept: "application/json" }), res: fakeRes(), ip: "198.51.100.9", respond: true };
  await koa(api, async () => { reached = true; });
  assert.equal(reached, true);
  assert.equal(api.respond, true);
});

// ---- Next.js (edge) ----------------------------------------------------------

test("Next.js: the check page as a Response, WebCrypto's pass, reported, and the pass lets the reload in", async (t) => {
  const { firewall, fetches, events } = edgeFirewall(t, { trustProxy: 1 });
  const ask = (init = {}, url = "https://site.test/pricing?x=1") => firewall(new Request(url, {
    ...init,
    headers: { accept: BROWSER, "x-forwarded-for": "198.51.100.9", ...(init.headers || {}) },
  }), { waitUntil: () => {} });

  const page = await ask();
  assertPage(page.status, page.headers, await page.text());
  assert.equal(fetches[0]["x-firewall-layers"], "app check");
  assert.equal(fetches[0]["x-server-name"], undefined, "the edge has no machine name to give");

  const pass = passForSync(signers["node:crypto"], "198.51.100.9");
  assert.equal(await ask({ headers: { cookie: `other=1; __sg_pass=${pass}` } }), undefined);
  assert.equal(await ask({ method: "POST", body: "a=1" }), undefined);
  assert.equal(await ask({ headers: { accept: "application/json" } }), undefined);
  assert.equal(await ask({}, "https://site.test/api/orders"), undefined);

  const head = await ask({ method: "HEAD" });
  assertPage(head.status, head.headers, await head.text(), { head: true });

  await firewall.flush();
  assert.deepEqual(events.map((e) => `${e.ip} ${e.rule} ${e.action} ${e.method} ${e.path} x${e.hits}`),
    ["198.51.100.9 challenge block GET /pricing x1", "198.51.100.9 challenge block HEAD /pricing x1"]);
});

test("Next.js: `challenge: null` changes nothing, and the server name goes when it's given", async (t) => {
  const { firewall, fetches } = edgeFirewall(t, { trustProxy: () => "198.51.100.9", serverName: "edge-eu" }, { ...RULES, challenge: null });
  assert.equal(await firewall(new Request("https://site.test/pricing", { headers: { accept: BROWSER } }), { waitUntil: () => {} }), undefined);
  assert.equal(fetches[0]["x-server-name"], "edge-eu");
});

// ---- Hono ----------------------------------------------------------------------

function honoContext(url, { method = "GET", headers = {} } = {}) {
  const raw = new Request(url, { method, headers: { "cf-connecting-ip": "198.51.100.9", ...headers } });
  let res;
  const c = {
    // Node's adapter: the connection is from one of Cloudflare's addresses.
    env: { incoming: { socket: { remoteAddress: "172.64.0.1" } } },
    req: { raw, path: new URL(url).pathname, method, routePath: "/*", header: (name) => raw.headers.get(name) },
    get executionCtx() { throw new Error("no context"); },
    get res() { return (res ||= new Response(null)); },
    set res(value) { res = value; },
    header: (name, value) => c.res.headers.set(name, value),
  };
  return c;
}

test("Hono: the check page before the route; an API call reaches the route", async (t) => {
  edgeFirewall(t);
  const off = { proxy: false, headers: false, crawlers: false, maintenance: false, performance: false, errors: false,
    forms: false, analytics: false, audit: false, flags: false };
  const platform = createHonoPlatform({ siteId: SITE, secret: SECRET, endpoint: ENDPOINT, trustProxy: "cloudflare", ...off });
  let reached = false;
  const page = await platform(honoContext("http://site.test/pricing", { headers: { accept: BROWSER } }),
    async () => { reached = true; });
  assert.equal(reached, false);
  assertPage(page.status, page.headers, await page.text());

  const c = honoContext("http://site.test/pricing", { headers: { accept: "application/json" } });
  await platform(c, async () => { reached = true; });
  assert.equal(reached, true);
  await platform.flush?.();
});

// ---- The page's script, run as a browser would ---------------------------------

test("the script sets the pass and reloads only when the cookie reads back, at most three times a minute; Secure follows location.protocol", () => {
  const vm = require("node:vm");
  const { challengePage } = require("../lib/challenge.js");
  const pass = passForSync(signers["node:crypto"], "198.51.100.9");
  const code = () => /<script nonce="[0-9a-f]+">([\s\S]*?)<\/script>/.exec(challengePage({ pass }).body)[1];
  const browser = ({ cookies = true, protocol = "http:", store = new Map() } = {}) => {
    const b = { set: [], reloads: 0, message: "", jar: "" };
    vm.runInNewContext(code(), {
      document: {
        get cookie() { return b.jar; },
        set cookie(value) { b.set.push(value); if (cookies) b.jar = value.split(";")[0]; },
        getElementById: () => ({ set textContent(text) { b.message = text; } }),
      },
      location: { protocol, reload: () => { b.reloads += 1; } },
      sessionStorage: { getItem: (k) => store.get(k) ?? null, setItem: (k, v) => store.set(k, v) },
      JSON, Date,
    });
    return b;
  };
  const first = browser();
  assert.equal(first.reloads, 1);
  assert.equal(first.set[0], `__sg_pass=${pass}; Max-Age=86400; Path=/; SameSite=Lax`);
  // Secure on https, and only there: TLS ended at a proxy still means the browser is on https.
  assert.equal(browser({ protocol: "https:" }).set[0], `__sg_pass=${pass}; Max-Age=86400; Path=/; SameSite=Lax; Secure`);
  assert.equal(browser({ protocol: "http:" }).set[0].includes("Secure"), false);
  const off = browser({ cookies: false });
  assert.equal(off.reloads, 0);
  assert.match(off.message, /allow cookies/);
  const store = new Map();
  const reloads = [1, 2, 3, 4].map(() => browser({ store }).reloads);
  assert.deepEqual(reloads, [1, 1, 1, 0], "an address that keeps changing stops reloading");

  // sessionStorage blocked or full: the tries are counted in a cookie instead,
  // so a browser without storage stops too rather than reloading for ever.
  for (const storage of [
    { getItem: () => { throw new Error("blocked"); }, setItem: () => { throw new Error("blocked"); } },
    { getItem: () => null, setItem: () => { throw new Error("quota"); } },
  ]) {
    const jar = new Map();
    const load = () => {
      let reloads = 0;
      vm.runInNewContext(code(), {
        document: {
          get cookie() { return [...jar].map(([k, v]) => `${k}=${v}`).join("; "); },
          set cookie(value) { const [k, v] = value.split(";")[0].split("="); jar.set(k, v); },
          getElementById: () => ({ set textContent(text) {} }),
        },
        location: { protocol: "https:", reload: () => { reloads += 1; } },
        sessionStorage: storage, JSON, Date,
      });
      return reloads;
    };
    assert.deepEqual([1, 2, 3, 4].map(load), [1, 1, 1, 0], "no storage, still at most three");
    assert.equal(jar.get("__sg_tries"), "3");
  }
});
