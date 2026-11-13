// The Hono middleware, against a stand-in for Hono's context and the
// collector (it was also run in real Hono 4.13 on Node, Bun and Deno, and in
// workerd through wrangler dev): the secret can come from the context, a 5xx
// a route threw is sent with its route and breadcrumbs, the firewall's
// answer is returned, Server speed rows carry the route pattern, and the
// proxy, headers, crawler counts, maintenance mode and form checks work on
// a Web Request.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const { createHonoPlatform } = require("../lib/hono.js");
const { prefixFor, keyFor } = require("../lib/proxy.js");

const SITE = "a".repeat(24);
const SECRET = "s".repeat(32);
const ENDPOINT = "https://collector.example";

// Records what is posted; the rules make /.env a probe the firewall blocks.
// settings: the dashboard's (headers, maintenance); without them the config
// isn't found. Anything not for the collector goes out for real.
function fakeCollector(t, settings) {
  const posted = {};
  const seen = { tracker: 0, beacons: [] };
  const original = globalThis.fetch;
  globalThis.fetch = async (url, init = {}) => {
    if (!String(url).startsWith(ENDPOINT)) return original(url, init);
    const path = new URL(url).pathname;
    if (path === "/events/firewall/rules") {
      return new Response(JSON.stringify({ v: 1, enabled: true, mode: "block", probes: { exact: ["/.env"] }, login: { limit: 2, window: 60, ban: 600 } }), { status: 200 });
    }
    if (path === "/events/platform/config" && settings) {
      return new Response(JSON.stringify({ v: 1, modules: {}, ...settings }), { status: 200 });
    }
    if (path === "/v1/s.js") {
      seen.tracker += 1;
      return new Response(`/* tracker */${"x".repeat(600)}`, { status: 200 });
    }
    if (path === "/collectanalytics/e") {
      seen.beacons.push({ url, headers: init.headers, body: new TextDecoder().decode(init.body) });
      return new Response('{"ok":true}', { status: 202, headers: { "content-type": "application/json", "set-cookie": "no=1" } });
    }
    if (init.method === "POST") (posted[path] ||= []).push(JSON.parse(init.body));
    if (path === "/events/lead") return new Response(JSON.stringify({ status: "created", lead_id: "L1" }), { status: 200 });
    if (path === "/collectanalytics/shield/verify") {
      const spam = JSON.stringify(JSON.parse(init.body).fields).includes("buy now");
      return new Response(JSON.stringify({ success: !spam }), { status: 200 });
    }
    return new Response(null, { status: path.includes("config") ? 404 : 202 });
  };
  t.after(() => { globalThis.fetch = original; });
  return Object.assign(posted, { seen });
}

// handler(c): the route, returning its Response.
function fakeContext(path, { env = {}, route = path, status = 200, error, method = "GET", headers = {}, body, handler } = {}) {
  const raw = new Request(`https://site.example${path}`, {
    method, body, headers: { "cf-connecting-ip": "198.51.100.4", "x-forwarded-for": "198.51.100.4", ...headers },
  });
  const vars = new Map();
  let res;
  const c = {
    env,
    req: {
      raw, path: path.split("?")[0], method, routePath: "/*", header: (name) => raw.headers.get(name),
      json: () => raw.json(), parseBody: async () => Object.fromEntries(await raw.formData()),
    },
    get executionCtx() { throw new Error("no context"); },
    get res() { return (res ||= new Response(null)); },
    set res(value) { res = value; },
    header: (name, value, { append } = {}) => (append ? c.res.headers.append(name, value) : c.res.headers.set(name, value)),
    set: (key, value) => vars.set(key, value),
    get: (key) => vars.get(key),
    text: (text, code) => new Response(text, { status: code }),
  };
  const next = async () => {
    c.req.routePath = route;
    const answer = handler ? await handler(c) : undefined;
    c.res = answer || new Response("", { status });
    if (error) c.error = error;
  };
  return { c, next };
}

const settle = async (platform) => {
  await new Promise((resolve) => setTimeout(resolve, 20));
  await platform.flush();
  await new Promise((resolve) => setTimeout(resolve, 20));
};
const errorsOf = (posted) => (posted["/events/server-errors"] || []).flatMap((b) => b.errors);
const rowsOf = (posted) => (posted["/events/server-requests"] || []).flatMap((b) => b.rows).map((r) => `${r.method} ${r.route} ${r.status} x${r.count}`).sort();

test("the options can come from the context, and a thrown 5xx is sent with its route", async (t) => {
  const posted = fakeCollector(t);
  const platform = createHonoPlatform((c) => ({ siteId: c.env.SITE, secret: c.env.SECRET, endpoint: "https://collector.example", trustProxy: 1 }));
  const env = { SITE, SECRET: "s".repeat(32) };
  const ok = fakeContext("/users/7", { env, route: "/users/:id" });
  assert.equal(await platform(ok.c, ok.next), undefined);
  const boom = fakeContext("/boom/1", { env, route: "/boom/:id", status: 500, error: new Error("boom") });
  await platform(boom.c, boom.next);
  const bad = fakeContext("/bad", { env, status: 400, error: new Error("bad input") });
  await platform(bad.c, bad.next);
  await platform.flush();
  await new Promise((resolve) => setTimeout(resolve, 20));

  const errors = (posted["/events/server-errors"] || []).flatMap((b) => b.errors);
  assert.deepEqual(errors.map((e) => [e.message, e.status_code, e.route, e.kind]), [["boom", 500, "/boom/:id", "handled"]]);
  const rows = (posted["/events/server-requests"] || []).flatMap((b) => b.rows);
  assert.deepEqual(rows.map((r) => `${r.route} ${r.status}`).sort(), ["/bad 400", "/boom/:id 500", "/users/:id 200"]);
});

test("a probe gets the firewall's 403 and never reaches the route; a miss is one not-found route", async (t) => {
  const posted = fakeCollector(t);
  const platform = createHonoPlatform({ siteId: SITE, secret: "s".repeat(32), endpoint: "https://collector.example", trustProxy: "cloudflare" });
  // Through Cloudflare: Node's adapter hands over one of its addresses.
  const env = { incoming: { socket: { remoteAddress: "2606:4700::1" } } };
  const probe = fakeContext("/.env", { env });
  let reached = false;
  const answer = await platform(probe.c, async () => { reached = true; });
  assert.equal(answer.status, 403);
  assert.equal(reached, false);

  const miss = fakeContext("/nope/123", { env, route: "/*", status: 404 });
  await platform(miss.c, miss.next);
  await platform.flush();
  await new Promise((resolve) => setTimeout(resolve, 20));
  const events = (posted["/events/firewall/events"] || []).flatMap((b) => b.events);
  assert.deepEqual(events.map((e) => `${e.ip} ${e.rule} ${e.action}`), ["198.51.100.4 probe block"]);
  const rows = (posted["/events/server-requests"] || []).flatMap((b) => b.rows);
  assert.deepEqual(rows.map((r) => `${r.route} ${r.status}`), ["/(not found) 404"]);
});

test("the proxy serves the tracker and passes beacons on, before the firewall, uncounted and untimed", async (t) => {
  const posted = fakeCollector(t);
  const platform = createHonoPlatform({ siteId: SITE, secret: SECRET, endpoint: ENDPOINT, trustProxy: 1 });
  const prefix = prefixFor(SECRET);
  const urls = await platform.proxy(fakeContext("/").c);
  assert.deepEqual([urls.prefix, urls.scriptUrl(), urls.collectUrl()], [prefix, `/${prefix}/js/v1/s.js`, `/${prefix}/api/e`]);

  const bot = { "user-agent": "GPTBot/1.2" };
  for (let i = 0; i < 2; i++) {
    const file = fakeContext(`/${prefix}/js/v1/s.js`, { headers: bot });
    const answer = await platform(file.c, async () => assert.fail("the app must not see it"));
    assert.equal(answer.status, 200);
    assert.match(await answer.text(), /^\/\* tracker/);
  }
  assert.equal(posted.seen.tracker, 1, "the second is served from memory");

  const beacon = fakeContext(`/${prefix}/api/e?x=1`, { method: "POST", body: '{"e":1}', headers: { "content-type": "text/plain", cookie: "session=private", ...bot } });
  const answer = await platform(beacon.c, async () => assert.fail("the app must not see it"));
  assert.equal(answer.status, 202);
  assert.equal(answer.headers.get("set-cookie"), null);
  const [sent] = posted.seen.beacons;
  assert.equal(sent.url, `${ENDPOINT}/collectanalytics/e?x=1`);
  assert.equal(sent.body, '{"e":1}');
  assert.equal(sent.headers["x-forwarded-for"], "198.51.100.4");
  assert.equal(sent.headers["x-proxy-key"], keyFor(SECRET));
  assert.equal(sent.headers.cookie, undefined);

  const big = fakeContext(`/${prefix}/api/e`, { method: "POST", body: "x".repeat(6 * 1024 * 1024 + 1), headers: { "content-type": "text/plain" } });
  assert.equal((await platform(big.c, async () => {})).status, 413);
  const odd = fakeContext(`/${prefix}/js/v1/evil.js`);
  assert.equal((await platform(odd.c, async () => {})).status, 404);

  await settle(platform);
  assert.deepEqual(rowsOf(posted), []);
  assert.equal(posted["/events/crawlers"], undefined);
});

test("the dashboard's headers are added unless the app set them, on every answer", async (t) => {
  fakeCollector(t, { headers: [["x-frame-options", "DENY"], ["x-content-type-options", "nosniff"]] });
  const platform = createHonoPlatform({ siteId: SITE, secret: SECRET, endpoint: ENDPOINT, trustProxy: 1 });
  const own = fakeContext("/own", { handler: () => new Response("own", { headers: { "x-frame-options": "SAMEORIGIN" } }) });
  await platform(own.c, own.next);
  assert.equal(own.c.res.headers.get("x-frame-options"), "SAMEORIGIN");
  assert.equal(own.c.res.headers.get("x-content-type-options"), "nosniff");

  // A Response from fetch() has headers that can't change: it is copied.
  const frozen = fakeContext("/upstream", { handler: () => Response.redirect("https://elsewhere.example/", 302) });
  await platform(frozen.c, frozen.next);
  assert.equal(frozen.c.res.status, 302);
  assert.equal(frozen.c.res.headers.get("x-frame-options"), "DENY");

  const blocked = await platform(fakeContext("/.env").c, async () => {});
  assert.equal(blocked.status, 403);
  assert.equal(blocked.headers.get("x-content-type-options"), "nosniff");
});

test("crawlers are counted, the ones the firewall turned away too; visitors aren't", async (t) => {
  const posted = fakeCollector(t);
  const platform = createHonoPlatform({ siteId: SITE, secret: SECRET, endpoint: ENDPOINT, trustProxy: 1 });
  await platform(fakeContext("/.env", { headers: { "user-agent": "Mozilla/5.0 (compatible; GPTBot/1.2)" } }).c, async () => {});
  const page = fakeContext("/blog/1?utm=x", { route: "/blog/:id", headers: { "user-agent": "Googlebot/2.1", "content-length": "0" } });
  await platform(page.c, page.next);
  const human = fakeContext("/blog/2", { headers: { "user-agent": "Mozilla/5.0 Firefox/130" } });
  await platform(human.c, human.next);
  await settle(platform);
  const batches = posted["/events/crawlers"] || [];
  assert.deepEqual(batches.flatMap((b) => b.rows).map((r) => `${r.bot} ${r.path} ${r.status} x${r.count}`).sort(),
    ["GPTBot /.env 403 x1", "Googlebot /blog/1 200 x1"]);
  assert.deepEqual(batches.flatMap((b) => b.agents).flatMap((a) => a.ips), ["198.51.100.4", "198.51.100.4"]);
});

test("maintenance mode answers with its page, except allowed addresses and the preview link", async (t) => {
  const posted = fakeCollector(t, { maintenance: { on: true, bypass: "letmein", allow: ["203.0.113.7"], message: "Upgrading" } });
  const platform = createHonoPlatform({ siteId: SITE, secret: SECRET, endpoint: ENDPOINT, trustProxy: 1, maintenance: { skip: (c) => c.req.path === "/health" } });
  const visitor = fakeContext("/");
  const page = await platform(visitor.c, async () => assert.fail("the app must not run"));
  assert.equal(page.status, 503);
  assert.equal(page.headers.get("retry-after"), "600");
  assert.match(await page.text(), /Upgrading/);

  const allowed = fakeContext("/", { headers: { "x-forwarded-for": "203.0.113.7" } });
  assert.equal(await platform(allowed.c, allowed.next), undefined);
  const preview = fakeContext("/?site_preview=letmein", { route: "/" });
  assert.equal(await platform(preview.c, preview.next), undefined);
  assert.match(preview.c.res.headers.get("set-cookie"), /^site_preview=letmein;/);
  const remembered = fakeContext("/", { headers: { cookie: "site_preview=letmein" } });
  assert.equal(await platform(remembered.c, remembered.next), undefined);
  const health = fakeContext("/health");
  assert.equal(await platform(health.c, health.next), undefined);
  await settle(platform);
  assert.deepEqual(rowsOf(posted), ["GET / 200 x3", "GET /health 200 x1"], "the page itself isn't timed");
});

test("form protection checks a copy of the body: spam gets a 422, and the route still reads it", async (t) => {
  const posted = fakeCollector(t);
  const platform = createHonoPlatform({ siteId: SITE, secret: SECRET, endpoint: ENDPOINT, trustProxy: 1 });
  const form = (message) => fakeContext("/contact", { method: "POST", body: new URLSearchParams({ name: "Ann", message, password: "hunter2" }) });

  const real = form("hello");
  let read = null;
  await platform.protectForm({ form: "contact" })(real.c, async () => { read = await real.c.req.raw.formData(); });
  assert.equal(read.get("message"), "hello");
  assert.deepEqual(real.c.get("formCheck"), { ok: true, spam: false, reasons: [], checked: true });

  const spam = form("buy now");
  const answer = await platform.protectForm()(spam.c, async () => assert.fail("spam must not reach the route"));
  assert.equal(answer.status, 422);

  const json = fakeContext("/signup", { method: "POST", body: '{"name":"Bo","note":"buy now"}', headers: { "content-type": "application/json" } });
  assert.equal((await platform.checkForm(json.c, { email: "bo@example.com" })).spam, true);
  assert.equal(await json.c.req.raw.text(), '{"name":"Bo","note":"buy now"}');

  const sent = posted["/collectanalytics/shield/verify"];
  assert.equal(sent.length, 3);
  assert.equal(JSON.stringify(sent).includes("hunter2"), false, "passwords are never sent");
  assert.deepEqual([sent[0].ip, sent[0].form, sent[2].email], ["198.51.100.4", "contact", "bo@example.com"]);
});

test("errors carry the request's breadcrumbs, and captureException knows the request after an await", async (t) => {
  const posted = fakeCollector(t);
  const server = http.createServer((req, res) => res.writeHead(req.url.startsWith("/fail") ? 503 : 200).end("ok"));
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => server.close());
  const other = `http://127.0.0.1:${server.address().port}`;
  const platform = createHonoPlatform({ siteId: SITE, secret: SECRET, endpoint: ENDPOINT, trustProxy: 1 });

  const boom = fakeContext("/orders/5", { route: "/orders/:id", status: 500, error: new Error("boom") });
  boom.next = async () => {
    boom.c.req.routePath = "/orders/:id";
    platform.addBreadcrumb("charging the card");
    await fetch(`${other}/one?card=secret`);
    await fetch(`${other}/fail`);
    boom.c.res = new Response("oops", { status: 500 });
    boom.c.error = new Error("boom");
  };
  await platform(boom.c, boom.next);

  const caught = fakeContext("/sync/3", {
    route: "/sync/:id",
    handler: async () => {
      await fetch(`${other}/two`);
      await new Promise((resolve) => setTimeout(resolve, 5));
      platform.captureException(new Error("caught"));
      return new Response("fine");
    },
  });
  await platform(caught.c, caught.next);

  const twice = new Error("twice");
  const thrown = fakeContext("/twice", { status: 500, error: twice, handler: (c) => { platform.captureException(twice, c, { status: 500 }); } });
  await platform(thrown.c, thrown.next);
  await settle(platform);

  const errors = errorsOf(posted);
  assert.deepEqual(errors.map((e) => [e.message, e.status_code, e.route]), [["boom", 500, "/orders/:id"], ["caught", 0, "/sync/:id"], ["twice", 500, "/twice"]]);
  assert.deepEqual(errors[0].breadcrumbs.map((b) => `${b.type} ${b.text} ${b.status ?? ""}`.trim()),
    ["note charging the card", `request GET ${other}/one 200`, `request GET ${other}/fail 503`]);
  assert.deepEqual(errors[1].breadcrumbs.map((b) => b.text), [`GET ${other}/two`]);
});

test("a module turned off in the code does nothing", async (t) => {
  const posted = fakeCollector(t, { headers: [["x-frame-options", "DENY"]], maintenance: { on: true } });
  const platform = createHonoPlatform({ siteId: SITE, secret: SECRET, endpoint: ENDPOINT, proxy: false, headers: false, maintenance: false, crawlers: false, firewall: false });
  assert.equal(await platform.proxy(fakeContext("/").c), null);
  const page = fakeContext("/.env", { headers: { "user-agent": "GPTBot/1.2" } });
  assert.equal(await platform(page.c, page.next), undefined);
  assert.equal(page.c.res.headers.get("x-frame-options"), null);
  await settle(platform);
  assert.equal(posted["/events/crawlers"], undefined);
  assert.deepEqual(rowsOf(posted), ["GET /.env 200 x1"]);
});

test("server events, audit entries, failed logins, flags and jobs, as in the main package", async (t) => {
  const posted = fakeCollector(t, { flags: { "new-checkout": { on: true, rollout: 100 } } });
  const platform = createHonoPlatform({ siteId: SITE, secret: SECRET, endpoint: ENDPOINT, trustProxy: 1 });
  assert.equal(platform.isEnabled("new-checkout"), false, "not before the flags arrive");
  const visit = fakeContext("/checkout", { headers: { "x-analytics-session": "sess-1" } });
  await platform(visit.c, visit.next);
  assert.equal(platform.isEnabled("new-checkout"), true);
  assert.equal(platform.isEnabled("unknown", { default: true }), true);

  const id = platform.track("purchase", { value: 10 }, { c: visit.c });
  assert.match(id, /^[0-9a-f-]{36}$/);
  assert.equal(await platform.identify("user-1", { c: visit.c, traits: { plan: "pro", seats: 5 } }), true);
  assert.deepEqual(await platform.lead({ email: "ann@example.com" }, { c: visit.c }), { status: "created", lead_id: "L1" });
  platform.audit("user.role_changed", { actor: "ann", target: "bob", details: { role: "admin" }, c: visit.c });

  // Two failed logins is the limit here: the address is then banned at once.
  platform.loginFailed(visit.c);
  platform.loginFailed("198.51.100.4");
  assert.equal((await platform(fakeContext("/").c, async () => {})).status, 403);

  assert.equal(await platform.job("send-receipts", async () => {
    await new Promise((resolve) => setTimeout(resolve, 5));
    platform.captureException(new Error("one receipt failed"));
    return 7;
  }), 7);
  await assert.rejects(platform.job("nightly", async () => { throw new Error("nightly broke"); }), /nightly broke/);
  await settle(platform);

  const [event] = posted["/events/server-events"].flatMap((b) => b.events);
  assert.deepEqual([event.event_name, event.event_uid, event.session_id, event.value], ["purchase", id, "sess-1", 10]);
  assert.deepEqual([posted["/events/identify"][0].user_id, posted["/events/identify"][0].session_id], ["user-1", "sess-1"]);
  assert.deepEqual(posted["/events/identify"][0].traits, { plan: "pro", seats: 5 });
  assert.deepEqual([posted["/events/lead"][0].email, posted["/events/lead"][0].session_id], ["ann@example.com", "sess-1"]);
  const [entry] = posted["/events/audit"].flatMap((b) => b.entries);
  assert.deepEqual([entry.action, entry.actor, entry.target, entry.actor_ip, entry.session_id, entry.details.role],
    ["user.role_changed", "ann", "bob", "198.51.100.4", "sess-1", "admin"]);
  const firewall = posted["/events/firewall/events"].flatMap((b) => b.events);
  assert.equal(firewall.filter((e) => e.rule === "login").reduce((n, e) => n + e.hits, 0), 2);
  assert.ok(firewall.some((e) => e.rule === "ban" && e.action === "block"));

  const errors = errorsOf(posted);
  assert.deepEqual(errors.map((e) => [e.message, e.method, e.route, e.status_code, e.kind]), [
    ["one receipt failed", "JOB", "/(job) send-receipts", 0, "handled"],
    ["nightly broke", "JOB", "/(job) nightly", 500, "error"],
  ]);
  const jobs = rowsOf(posted).filter((r) => r.startsWith("JOB"));
  assert.deepEqual(jobs, ["JOB /(job) nightly 500 x1", "JOB /(job) send-receipts 200 x1"]);
});

test("before the first request: static options set up on their own; a function of c asks for c", async (t) => {
  const posted = fakeCollector(t);
  const early = createHonoPlatform({ siteId: SITE, secret: SECRET, endpoint: ENDPOINT });
  const id = early.track("signup");
  assert.match(id, /^[0-9a-f-]{36}$/);
  assert.equal((await early.proxy()).prefix, prefixFor(SECRET));
  await settle(early);
  assert.equal(posted["/events/server-events"][0].events[0].event_uid, id);

  const late = createHonoPlatform((c) => ({ siteId: SITE, secret: c.env.SECRET, endpoint: ENDPOINT }));
  await assert.rejects(late.proxy(), /function of c: pass c \(or \{ env \}\)/);
  assert.equal(late.track("signup"), "");
  assert.equal((await late.proxy({ env: { SECRET } })).prefix, prefixFor(SECRET));
});
