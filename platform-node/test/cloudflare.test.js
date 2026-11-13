// trustProxy "cloudflare": CF-Connecting-IP is the visitor only when the
// connection is Cloudflare's (or on Workers, where Cloudflare sets it). Anyone
// who reaches the server directly can send the header, and would otherwise
// pick their own address past every allow, deny, ban and rate rule.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { CLOUDFLARE_RANGES, fromCloudflare } = require("../lib/cloudflare.js");
const { clientIp } = require("../lib/firewall.js");
const { clientIp: edgeIp, createNextFirewall } = require("../lib/next.js");
const { createHonoPlatform } = require("../lib/hono.js");

test("the ranges are the shared file's", () => {
  const shared = JSON.parse(fs.readFileSync(path.join(__dirname, "../../protocols/cloudflare-ranges.json"), "utf8"));
  assert.deepEqual([...CLOUDFLARE_RANGES], shared.ranges);
});

test("Cloudflare's addresses, however spelled, and nobody else's", () => {
  assert.equal(fromCloudflare("172.64.1.2"), true);
  assert.equal(fromCloudflare("::ffff:172.64.1.2"), true);
  assert.equal(fromCloudflare("2606:4700::6810:1"), true);
  assert.equal(fromCloudflare("203.0.113.9"), false);
  assert.equal(fromCloudflare(""), false);
  assert.equal(fromCloudflare("nonsense"), false);
});

test("Node: the header only from a Cloudflare connection", () => {
  const req = (remoteAddress) => ({ headers: { "cf-connecting-ip": "198.51.100.7" }, socket: { remoteAddress } });
  assert.equal(clientIp(req("172.64.1.2"), "cloudflare"), "198.51.100.7");
  assert.equal(clientIp(req("::ffff:162.158.0.9"), "cloudflare"), "198.51.100.7");
  // Straight to the origin: the connection's own address, whatever it claims.
  assert.equal(clientIp(req("203.0.113.9"), "cloudflare"), "203.0.113.9");
  // From Cloudflare without the header: Cloudflare's address, as before.
  assert.equal(clientIp({ headers: {}, socket: { remoteAddress: "172.64.1.2" } }, "cloudflare"), "172.64.1.2");
});

test("edge: the header from a Cloudflare connection or on Workers, else the connection's own", () => {
  const request = (ip) => Object.assign(new Request("https://site.test/", { headers: { "cf-connecting-ip": "198.51.100.7" } }), ip ? { ip } : {});
  assert.equal(edgeIp(request("172.64.1.2"), "cloudflare"), "198.51.100.7");
  assert.equal(edgeIp(request("203.0.113.9"), "cloudflare"), "203.0.113.9");
  // Self-hosted Next.js has no connection address: nothing to believe it from.
  assert.equal(edgeIp(request(), "cloudflare"), "");
  // Hono hands over its adapter's connection address.
  assert.equal(edgeIp(request(), "cloudflare", "2606:4700::1"), "198.51.100.7");
  assert.equal(edgeIp(request(), "cloudflare", "203.0.113.9"), "203.0.113.9");
  // On Workers Cloudflare itself sets the header.
  // (By hand: t.mock.property never finishes restoring Node's navigator getter.)
  const was = Object.getOwnPropertyDescriptor(globalThis, "navigator");
  Object.defineProperty(globalThis, "navigator", { value: { userAgent: "Cloudflare-Workers" }, configurable: true, writable: true });
  try {
    assert.equal(edgeIp(request(), "cloudflare"), "198.51.100.7");
  } finally {
    if (was) Object.defineProperty(globalThis, "navigator", was);
    else delete globalThis.navigator;
  }
});

test("Hono on Node: a forged header straight to the origin is not believed", async (t) => {
  const rules = { v: 1, enabled: true, mode: "block", sync: 60, deny: ["203.0.113.9"] };
  t.mock.method(globalThis, "fetch", async (url) => (String(url).includes("/rules")
    ? new Response(JSON.stringify(rules), { status: 200 })
    : new Response("{}", { status: 202 })));
  const off = { proxy: false, headers: false, crawlers: false, maintenance: false, performance: false, errors: false,
    forms: false, analytics: false, audit: false, flags: false };
  const platform = createHonoPlatform({ siteId: "a".repeat(24), secret: "s".repeat(32), endpoint: "https://collector.test", trustProxy: "cloudflare", ...off });
  const context = (remoteAddress) => {
    const raw = new Request("https://site.test/", { headers: { "cf-connecting-ip": "198.51.100.7" } });
    let res;
    const c = {
      env: { incoming: { socket: { remoteAddress } } },
      req: { raw, path: "/", method: "GET", routePath: "/*", header: (name) => raw.headers.get(name) },
      get executionCtx() { throw new Error("no context"); },
      get res() { return (res ||= new Response(null)); },
      set res(value) { res = value; },
      header: (name, value) => c.res.headers.set(name, value),
    };
    return c;
  };
  // The denied address claims to be somebody else: still denied.
  assert.equal((await platform(context("203.0.113.9"), async () => {}))?.status, 403);
  await platform.flush?.();
});

test("edge: monitor mode's rate limit bans nothing", async (t) => {
  const rules = { v: 1, enabled: true, mode: "monitor", sync: 60, rate: { limit: 1, window: 60 }, ban: { seconds: 600 } };
  const events = [];
  t.mock.method(globalThis, "fetch", async (url, init = {}) => {
    if (String(url).includes("/rules")) return new Response(JSON.stringify(rules), { status: 200 });
    events.push(...JSON.parse(init.body).events);
    return new Response("{}", { status: 202 });
  });
  const firewall = createNextFirewall({ siteId: "a".repeat(24), secret: "s", endpoint: "https://collector.test", trustProxy: () => "203.0.113.7" });
  const waits = [];
  const event = { waitUntil: (p) => waits.push(p) };
  for (let i = 0; i < 3; i++) assert.equal(await firewall(new Request("https://site.test/page"), event), undefined);
  await Promise.all(waits);
  await firewall.flush();
  // Every request past the limit is "rate"; a ban would have made the third "ban".
  assert.ok(events.length > 0);
  assert.deepEqual([...new Set(events.map((e) => `${e.rule} ${e.action}`))], ["rate monitor"]);
});
