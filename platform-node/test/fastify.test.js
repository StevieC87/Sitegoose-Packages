// The Fastify plugin, against a stand-in for Fastify's hooks (the package has
// no dependencies; it was also run in real Fastify 4.29 and 5.12): the raw
// request gets the address and route the modules read, an answer from the
// middleware stops the request, and errors carry the status Fastify will send.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { createFastifyPlugin } = require("../lib/fastify.js");

function install(middleware, errors, options) {
  const hooks = {};
  const plugin = createFastifyPlugin(middleware, errors, options);
  plugin({ addHook: (name, fn) => (hooks[name] = fn) }, {}, () => {});
  return { plugin, hooks };
}

function fakeErrors() {
  const captured = [];
  return { captured, bind: (req, next) => next(), captureException: (error, context) => captured.push({ error, ...context }) };
}

test("the plugin covers the whole app, as fastify-plugin would", () => {
  const { plugin } = install((req, res, next) => next(), null);
  assert.equal(plugin[Symbol.for("skip-override")], true);
  assert.equal(plugin[Symbol.for("plugin-meta")].fastify, ">=4");
});

test("the raw request gets Fastify's address and the route pattern", () => {
  let seen = null;
  const { hooks } = install((req, res, next) => ((seen = req), next()), null);
  const request = { raw: {}, ip: "203.0.113.9", routeOptions: { url: "/users/:id" } };
  let passed = false;
  hooks.onRequest(request, { raw: {} }, () => (passed = true));
  assert.equal(passed, true);
  assert.equal(seen.ip, "203.0.113.9");
  assert.deepEqual(seen.route, { path: "/users/:id" });

  // Fastify 4 before routeOptions; and no route at all (not found).
  const old = { raw: {}, ip: "1.2.3.4", routerPath: "/old/:id" };
  hooks.onRequest(old, { raw: {} }, () => {});
  assert.deepEqual(old.raw.route, { path: "/old/:id" });
  const missing = { raw: {}, ip: "1.2.3.4", routeOptions: { url: undefined } };
  hooks.onRequest(missing, { raw: {} }, () => {});
  assert.equal(missing.raw.route, undefined);
});

test("a request the middleware answers never reaches the route", () => {
  const { hooks } = install((req, res) => res.end(), null);
  let passed = false;
  hooks.onRequest({ raw: {}, ip: "1.2.3.4" }, { raw: { end() {} } }, () => (passed = true));
  assert.equal(passed, false);
});

test("onError sends 5xx with the status Fastify will answer, not 4xx", () => {
  const errors = fakeErrors();
  const { hooks } = install((req, res, next) => next(), errors);
  const request = { raw: { url: "/x" } };
  const boom = new Error("boom");
  const bad = Object.assign(new Error("bad input"), { statusCode: 400 });
  const gateway = Object.assign(new Error("upstream"), { statusCode: 502 });
  for (const error of [boom, bad, gateway]) hooks.onError(request, { statusCode: 200 }, error, () => {});
  assert.deepEqual(errors.captured.map((c) => [c.error.message, c.status, c.kind]), [["boom", 500, "handled"], ["upstream", 502, "handled"]]);
  assert.equal(errors.captured[0].req, request.raw);
});

test("shouldCapture decides instead, and no errors module adds no error hooks", () => {
  const errors = fakeErrors();
  const { hooks } = install((req, res, next) => next(), errors, { shouldCapture: (error) => error.statusCode === 404 });
  hooks.onError({ raw: {} }, { statusCode: 200 }, Object.assign(new Error("missing"), { statusCode: 404 }), () => {});
  hooks.onError({ raw: {} }, { statusCode: 200 }, new Error("boom"), () => {});
  assert.deepEqual(errors.captured.map((c) => c.status), [404]);

  const off = install((req, res, next) => next(), null);
  assert.deepEqual(Object.keys(off.hooks), ["onRequest"]);
});
