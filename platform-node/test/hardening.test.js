// Edge cases that used to slip past a check: a malformed cookie, an address
// spelled two ways, a good crawler on the edge, a second platform in one
// process, a report run by hand, and the per-minute row caps.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { spawnSync } = require("node:child_process");
const path = require("node:path");
const { createMaintenance } = require("../lib/maintenance.js");
const { createLocalBans } = require("../lib/bans.js");
const { createNextFirewall } = require("../lib/next.js");
const { createPosture } = require("../lib/posture.js");
const { createPerformance } = require("../lib/performance.js");
const { createCrawlers } = require("../lib/crawlers.js");

function fakeRes() {
  const res = { statusCode: 200, headers: {}, body: "" };
  res.setHeader = (name, value) => { res.headers[name] = value; };
  res.end = (body) => { res.body = String(body ?? ""); };
  return res;
}

test("a malformed preview cookie or URL still gets the maintenance page", () => {
  const core = { isOn: () => true, maintenance: () => ({ on: true, bypass: "letmein" }), log: () => {} };
  const { middleware } = createMaintenance(core);
  for (const req of [
    { url: "/", headers: { cookie: "site_preview=%" }, socket: { remoteAddress: "203.0.113.9" } },
    { url: "//[", headers: {}, socket: { remoteAddress: "203.0.113.9" } },
  ]) {
    const res = fakeRes();
    let passed = false;
    middleware(req, res, () => { passed = true; });
    assert.equal(passed, false);
    assert.equal(res.statusCode, 503);
  }
  const res = fakeRes();
  let passed = false;
  middleware({ url: "/", headers: { cookie: "a=%; site_preview=letmein" }, socket: {} }, res, () => { passed = true; });
  assert.equal(passed, true, "the right code still lets the visitor in");
});

test("a ban holds however the address is spelled", () => {
  const bans = createLocalBans();
  bans.ban("203.0.113.5", 60);
  assert.equal(bans.banned("::ffff:203.0.113.5"), true);
  bans.loginFailed("2001:db8::1", { limit: 1, window: 60, ban: 60 });
  assert.equal(bans.banned("2001:0db8:0:0:0:0:0:1"), true);
  assert.equal(bans.banned("203.0.113.6"), false);
});

test("the edge rate limit leaves good crawlers alone, as the Node firewall does", async (t) => {
  const rules = { v: 1, enabled: true, mode: "block", sync: 60, rate: { limit: 1, window: 60 }, goodbots: ["66.249.66.1"] };
  t.mock.method(globalThis, "fetch", async (url) => (String(url).includes("/rules")
    ? new Response(JSON.stringify(rules), { status: 200 })
    : new Response("{}", { status: 202 })));
  let ip = "";
  const firewall = createNextFirewall({ siteId: "a".repeat(24), secret: "s", endpoint: "https://collector.test", trustProxy: () => ip });
  const ask = () => firewall(new Request("https://site.test/page"), { waitUntil: () => {} });
  ip = "66.249.66.1";
  assert.equal(await ask(), undefined);
  assert.equal(await ask(), undefined);
  ip = "203.0.113.7";
  assert.equal(await ask(), undefined);
  assert.equal((await ask())?.status, 429);
});

test("two platforms in one process still exit after an uncaught exception", () => {
  const lib = JSON.stringify(path.join(__dirname, "../lib/errors.js"));
  const script = `
    const { createErrors } = require(${lib});
    const core = { isOn: () => true, log: () => {}, send: async () => ({ ok: true }) };
    createErrors(core);
    createErrors(core);
    setTimeout(() => { throw new Error("boom"); }, 0);
    setTimeout(() => { console.log("still running"); process.exit(0); }, 3000);
  `;
  const run = spawnSync(process.execPath, ["-e", script], { encoding: "utf8", timeout: 10000 });
  assert.equal(run.status, 1, run.stdout + run.stderr);
  assert.doesNotMatch(run.stdout, /still running/);
});

test("a report run by hand doesn't start a second daily chain", async (t) => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  let reports = 0;
  const core = { valid: false, siteId: "x", log: () => {}, isOn: () => (reports++, false) };
  const posture = createPosture(core, { roots: [] });
  await posture.report();
  await posture.report();
  reports = 0;
  t.mock.timers.tick(60 * 60 * 1000);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(reports, 1);
  posture.close();
});

test("the row cap is per minute, so last minute's rows don't crowd out this one's", async (t) => {
  t.mock.timers.enable({ apis: ["Date"], now: 10 * 60000 + 50000 });
  const sent = [];
  const core = { valid: false, isOn: () => true, log: () => {}, send: async (m, p, { body }) => { sent.push(...body.rows); } };
  const performance = createPerformance(core);
  const crawlers = createCrawlers(core);
  for (let i = 0; i < 300; i++) {
    performance.record({ method: "GET", route: `/a${i}`, status: 200, ms: 1 });
    crawlers.record({ bot: "GPTBot", path: `/a${i}`, status: 200 });
  }
  t.mock.timers.tick(20000); // the next minute, nothing sent yet
  performance.record({ method: "GET", route: "/fresh", status: 200, ms: 1 });
  crawlers.record({ bot: "GPTBot", path: "/fresh", status: 200 });
  await performance.flush();
  await crawlers.flush();
  assert.ok(sent.some((row) => row.route === "/fresh"));
  assert.ok(sent.some((row) => row.path === "/fresh"));
});
