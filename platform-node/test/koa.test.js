// The Koa middleware, against a stand-in for Koa's context (the package has
// no dependencies; it was also run in real Koa 2.16 and 3.3 with
// @koa/router): Koa's address and the router's pattern reach the modules, an
// answer from the middleware stops Koa answering too, and 5xx errors are sent
// and thrown on.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { EventEmitter } = require("node:events");
const { createKoaMiddleware } = require("../lib/koa.js");

function fakeCtx() {
  const res = new EventEmitter();
  return { req: { url: "/api/users/7" }, res, ip: "203.0.113.9", respond: true };
}

function fakeErrors() {
  const captured = [];
  return { captured, captureException: (error, context) => captured.push({ error, ...context }) };
}

test("Koa's address and the matched route reach the modules", async () => {
  let seen = null;
  const koa = createKoaMiddleware((req, res, next) => ((seen = req), next()), null);
  const ctx = fakeCtx();
  await koa(ctx, async () => { ctx._matchedRoute = "/api/users/:id"; });
  assert.equal(seen.ip, "203.0.113.9");
  assert.deepEqual(ctx.req.route, { path: "/api/users/:id" });
  assert.equal(ctx.respond, true);
});

test("a request the middleware answers never reaches the app, and Koa leaves the response alone", async () => {
  const koa = createKoaMiddleware((req, res) => res.emit("finish"), null);
  const ctx = fakeCtx();
  let reached = false;
  await koa(ctx, async () => { reached = true; });
  assert.equal(reached, false);
  assert.equal(ctx.respond, false);
});

test("5xx errors are sent and thrown on; 4xx are only thrown on", async () => {
  const errors = fakeErrors();
  const koa = createKoaMiddleware((req, res, next) => next(), errors);
  const boom = new Error("boom");
  const bad = Object.assign(new Error("bad input"), { status: 400 });
  await assert.rejects(koa(fakeCtx(), async () => { throw boom; }), boom);
  await assert.rejects(koa(fakeCtx(), async () => { throw bad; }), bad);
  assert.deepEqual(errors.captured.map((c) => [c.error.message, c.status, c.kind]), [["boom", 500, "handled"]]);
});

test("shouldCapture decides instead", async () => {
  const errors = fakeErrors();
  const koa = createKoaMiddleware((req, res, next) => next(), errors, { shouldCapture: (error) => error.status === 404 });
  const missing = Object.assign(new Error("missing"), { status: 404 });
  await assert.rejects(koa(fakeCtx(), async () => { throw missing; }));
  await assert.rejects(koa(fakeCtx(), async () => { throw new Error("boom"); }));
  assert.deepEqual(errors.captured.map((c) => c.status), [404]);
});
