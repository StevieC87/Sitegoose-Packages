// Page limits (firewall.md, "Page limits" and "Checking a request", step 6),
// against the cases every client shares: sdk/protocols/page-limits-cases.json.
// Run through both firewalls: the Node one (Express, Fastify, Koa) and the
// Next.js edge one (Hono's too), which count on their own.
//
//   npm test            (node --test test/*.test.js)
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { createFirewall } = require("../lib/firewall.js");
const { createNextFirewall } = require("../lib/next.js");
const { compileLimits, compileRequestRules, matchLimits, matchRequest, prepare } = require("../lib/requestRules.js");

const cases = JSON.parse(fs.readFileSync(path.join(__dirname, "../../protocols/page-limits-cases.json"), "utf8"));
const SITE = "a1b2c3d4e5f6a1b2c3d4e5f6";
const ENDPOINT = "https://collector.test";
const BODY = "Too many requests to this page. Please wait a little and try again.";

const rulesOf = (scenario) => ({ ...cases.base, ...(scenario.rules || {}), limits: scenario.limits });
const sorted = (list) => [...list].sort();

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

async function nodeFirewall(t, rules) {
  const core = rulesCore(rules);
  const firewall = createFirewall(core);
  await firewall.ready;
  t.after(() => firewall.close());
  return { firewall, core };
}

// The edge firewall with a stand-in collector; `ip` is read per request.
function edgeFirewall(t, rules, options = {}) {
  const events = [];
  t.mock.method(globalThis, "fetch", async (url, init = {}) => {
    if (String(url).includes("/rules")) return new Response(JSON.stringify(rules), { status: 200 });
    events.push(...JSON.parse(init.body).events);
    return new Response("{}", { status: 202 });
  });
  const who = { ip: "" };
  const firewall = createNextFirewall({ siteId: SITE, secret: "s", endpoint: ENDPOINT, trustProxy: () => who.ip, ...options });
  // Every report this request queued, sent before the next one.
  const ask = async ({ ip, method, target }) => {
    who.ip = ip;
    const pending = [];
    const res = await firewall(new Request(`https://site.test${target}`, { method }), { waitUntil: (p) => pending.push(p) });
    await Promise.all(pending);
    await firewall.flush();
    return res;
  };
  return { ask, events };
}

const label = (scenario, i, request) => `${scenario.name} #${i + 1} ${request.ip} ${request.method} ${request.target}${request.why ? ` (${request.why})` : ""}`;

test("every shared case decides the same way in the Node firewall", async (t) => {
  for (const scenario of cases.scenarios) {
    const { firewall, core } = await nodeFirewall(t, rulesOf(scenario));
    for (const [i, request] of scenario.requests.entries()) {
      const before = core.events.length;
      const decision = firewall.check({ ip: request.ip, method: request.method, path: request.target });
      await firewall.flush();
      const reported = core.events.slice(before).map((event) => event.rule);
      const name = label(scenario, i, request);
      if (request.expect === "allow") {
        assert.equal(decision.action, "allow", name);
        assert.deepEqual(reported, [], `${name}: nothing reported`);
      } else {
        assert.deepEqual({ action: decision.action, rule: decision.rule, status: decision.status }, request.expect, name);
        assert.ok(reported.includes(request.expect.rule), `${name}: reported`);
      }
      if (request.reports) assert.deepEqual(sorted(reported), sorted(request.reports), `${name}: reports`);
    }
  }
});

test("every shared case decides the same way in the Next.js edge firewall", async (t) => {
  for (const scenario of cases.scenarios) {
    await t.test(scenario.name, async (st) => {
      const { ask, events } = edgeFirewall(st, rulesOf(scenario));
      for (const [i, request] of scenario.requests.entries()) {
        const before = events.length;
        const res = await ask(request);
        const reported = events.slice(before);
        const name = label(scenario, i, request);
        if (request.expect === "allow") {
          assert.equal(res, undefined, name);
          assert.deepEqual(reported.map((event) => event.rule), [], `${name}: nothing reported`);
        } else {
          // The edge answers a Response only when it blocks; what passes is seen in the report.
          if (request.expect.action === "block") assert.equal(res?.status, request.expect.status, name);
          else assert.equal(res, undefined, name);
          assert.ok(reported.some((event) => event.rule === request.expect.rule && event.action === request.expect.action), `${name}: reported`);
        }
        if (request.reports) assert.deepEqual(sorted(reported.map((event) => event.rule)), sorted(request.reports), `${name}: reports`);
      }
    });
  }
});

const LOGIN = {
  rules: [{ id: "wp.login", action: "block", limit: 1, window: 60, methods: ["POST"], path: { exact: ["/wp-login.php"] } }],
};

function fakeRes() {
  const res = { statusCode: 200, headers: {}, body: "" };
  res.setHeader = (name, value) => { res.headers[name.toLowerCase()] = value; };
  res.end = (body) => { res.body = body === undefined ? "" : String(body); };
  return res;
}

test("Node: a window ending lifts the cap, and nothing was banned meanwhile", async (t) => {
  t.mock.timers.enable({ apis: ["Date"], now: 1_000_000_000 });
  const { firewall } = await nodeFirewall(t, rulesOf({ limits: LOGIN }));
  const login = () => firewall.check({ ip: "198.51.100.7", method: "POST", path: "/wp-login.php" });
  assert.equal(login().action, "allow");
  assert.equal(login().rule, "limit:wp.login");
  // Other pages still open: a page limit is no ban.
  assert.equal(firewall.check({ ip: "198.51.100.7", method: "GET", path: "/" }).action, "allow");
  t.mock.timers.tick(59_000);
  assert.equal(login().rule, "limit:wp.login", "still the same window");
  t.mock.timers.tick(1_000);
  assert.equal(login().action, "allow", "a new window, a new count");
  assert.equal(login().rule, "limit:wp.login");
});

test("Node: a blocking limit answers 429, Retry-After its window, and the plain-text body", async (t) => {
  const { firewall } = await nodeFirewall(t, rulesOf({ limits: { rules: [{ ...LOGIN.rules[0], window: 120 }] } }));
  const req = () => ({ method: "POST", url: "/wp-login.php", headers: {}, socket: { remoteAddress: "198.51.100.7" } });
  let passed = 0;
  firewall.middleware(req(), fakeRes(), () => { passed++; });
  const res = fakeRes();
  firewall.middleware(req(), res, () => { passed++; });
  assert.equal(passed, 1);
  assert.equal(res.statusCode, 429);
  assert.equal(res.headers["retry-after"], "120");
  assert.equal(res.headers["content-type"], "text/plain; charset=utf-8");
  assert.equal(res.body, BODY);
});

test("Next.js: a window ending lifts the cap, 429 with Retry-After and the body meanwhile", async (t) => {
  t.mock.timers.enable({ apis: ["Date"], now: 1_000_020_000 });
  const { ask } = edgeFirewall(t, rulesOf({ limits: LOGIN }));
  const login = () => ask({ ip: "198.51.100.7", method: "POST", target: "/wp-login.php" });
  assert.equal(await login(), undefined);
  const res = await login();
  assert.equal(res.status, 429);
  assert.equal(res.headers.get("retry-after"), "60");
  assert.equal(res.headers.get("content-type"), "text/plain; charset=utf-8");
  assert.equal(await res.text(), BODY);
  assert.equal(await ask({ ip: "198.51.100.7", method: "GET", target: "/" }), undefined, "no ban");
  t.mock.timers.tick(60_000);
  assert.equal(await login(), undefined, "a new window, a new count");
  assert.equal((await login())?.status, 429);
});

test("Next.js: the shared counter is keyed afw:<site>:l:<id>:<who>:<window>, a count per page never", async (t) => {
  t.mock.timers.enable({ apis: ["Date"], now: 1_000_020_000 });
  const keys = [];
  const shared = new Map();
  const counter = async (key, ttl) => {
    keys.push([key, ttl]);
    shared.set(key, (shared.get(key) || 0) + 1);
    return shared.get(key);
  };
  const limits = {
    rules: [
      LOGIN.rules[0],
      { id: "any", action: "block", limit: 5, window: 600, each: "path", path: { prefix: ["/"] } },
    ],
  };
  const { ask } = edgeFirewall(t, rulesOf({ limits }), { counter });
  assert.equal(await ask({ ip: "2001:db8:1:2::1", method: "POST", target: "/wp-login.php" }), undefined);
  assert.deepEqual(keys, [[`afw:${SITE}:l:wp.login:2001:db8:1:2::/64:${Math.floor(1_000_020_000 / 1000 / 60)}`, 120]]);
  // The same /64, counted in the shared counter: the second one is over.
  assert.equal((await ask({ ip: "2001:db8:1:2::9", method: "POST", target: "/wp-login.php" }))?.status, 429);
  assert.equal(keys.length, 2, "the per-page limit counted on this instance only");
});

test("invalid limits are left out, the rest kept; at most 50", () => {
  const good = { id: "ok", action: "block", limit: 1, window: 60, path: { prefix: ["/"] } };
  const compiled = compileLimits({
    exempt: ["198.51.100.0/24"],
    rules: [
      good,
      { ...good, id: "x" },
      { ...good, id: "big", limit: 100001 },
      { ...good, id: "long", window: 3601 },
      { ...good, id: "slow", window: 0 },
      { ...good, id: "rx", path: { regex: "^/", prefix: ["/a"] } },
      { ...good, id: "qs", path: undefined, query: { contains: ["s="] } },
    ],
  });
  assert.deepEqual(compiled.rules.map((limit) => limit.id), ["ok", "rx", "qs"]);
  assert.equal(compiled.rules[1].path.regex, undefined, "a page limit has no regex");
  assert.equal(compiled.exempt.has(require("../lib/ip.js").parseIp("198.51.100.9")), true);
  assert.deepEqual(compileLimits(null).rules, []);
  const many = Array.from({ length: 60 }, (_, i) => ({ ...good, id: `l${i}` }));
  assert.equal(compileLimits({ rules: many }).rules.length, 50);
});

// The "any one page" watcher makes a count per address and page; asking for
// made-up paths must not push the login limit's count out and start it again.
const CROWDED = {
  rules: [
    { id: "wp.login", action: "block", limit: 3, window: 600, methods: ["POST"], path: { exact: ["/wp-login.php"] } },
    { id: "any", action: "monitor", limit: 600, window: 600, each: "path", path: { prefix: ["/"] } },
  ],
};

test("Node: filling the per-page counts doesn't reset a page limit's count", async (t) => {
  const { firewall } = await nodeFirewall(t, rulesOf({ limits: CROWDED }));
  const login = () => firewall.check({ ip: "198.51.100.7", method: "POST", path: "/wp-login.php" });
  assert.equal(login().action, "allow");
  assert.equal(login().action, "allow");
  // Past the table's cap (100,000): every one a new page, from another address.
  for (let i = 0; i < 100_001; i += 1) firewall.check({ ip: "198.51.100.9", method: "GET", path: `/made-up/${i}` });
  assert.equal(login().action, "allow", "the third");
  assert.equal(login().rule, "limit:wp.login", "the fourth: still counted from the first");
});

test("Next.js edge: filling the per-page counts doesn't reset a page limit's count", async (t) => {
  const { ask } = edgeFirewall(t, rulesOf({ limits: CROWDED }));
  const login = () => ask({ ip: "198.51.100.7", method: "POST", target: "/wp-login.php" });
  assert.equal(await login(), undefined);
  assert.equal(await login(), undefined);
  // Past the edge table's cap (50,000).
  for (let i = 0; i < 50_001; i += 1) await ask({ ip: "198.51.100.9", method: "GET", target: `/made-up/${i}` });
  assert.equal(await login(), undefined, "the third");
  assert.equal((await login())?.status, 429, "the fourth: still counted from the first");
});

test("the matchers take a request as it came or already prepared, alike", () => {
  const limits = compileLimits({ rules: [{ id: "any", action: "block", limit: 1, window: 60, each: "path", path: { prefix: ["/"] } }] });
  const rules = compileRequestRules({ rules: [{ id: "dots", action: "block", path: { contains: ["/../"] } }] });
  const raw = { method: "get", path: "/a/%2e%2e/b;x=1?q=1", userAgent: "UA" };
  const prepared = prepare(raw);
  assert.deepEqual(matchLimits(limits, prepared), matchLimits(limits, raw));
  assert.equal(matchLimits(limits, prepared).page, prepared.routed);
  assert.equal(matchRequest(rules, prepared)?.id, matchRequest(rules, raw)?.id);
});

// The path a rule compares against is the one the app routes (firewall.js pathOf).
test("Node: an absolute-form request line is matched by its path, and path(req) replaces the URL", async (t) => {
  const rules = rulesOf({ limits: { rules: [{ ...LOGIN.rules[0], methods: ["GET"] }] } });
  // A limit of one: the second request from an address is held if the rule matched.
  let address = 10;
  const blocked = (firewall, url) => {
    const remoteAddress = `198.51.100.${address++}`;
    const ask = () => {
      const res = fakeRes();
      let passed = false;
      firewall.middleware({ method: "GET", url, headers: {}, socket: { remoteAddress } }, res, () => { passed = true; });
      return !passed && res.statusCode === 429;
    };
    ask();
    return ask();
  };
  const plain = createFirewall(rulesCore(rules));
  await plain.ready;
  t.after(() => plain.close());
  assert.equal(blocked(plain, "/wp-login.php"), true);
  assert.equal(blocked(plain, "http://example.com/wp-login.php?x=1"), true, "absolute-form, cut to its path");
  assert.equal(blocked(plain, "/blog/wp-login.php"), false);

  // An app that serves "/blog/<page>" as "/<page>" says so.
  const stripped = createFirewall(rulesCore(rules), { path: (req) => req.url.replace(/^\/blog(?=\/)/, "") });
  await stripped.ready;
  t.after(() => stripped.close());
  assert.equal(blocked(stripped, "/blog/wp-login.php"), true);
});
