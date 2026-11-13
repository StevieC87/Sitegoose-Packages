// Fastify plugin (Fastify 4 and 5): the same middleware as Express, run on
// Fastify's raw request and response, plus Fastify's own error hook in place
// of errorHandler(). No dependency on Fastify: the plugin marks itself as
// fastify-plugin does, so its hooks cover the context it is registered in
// (the whole app, when registered on the app) rather than only itself.
//
//   await fastify.register(platform.fastify());
"use strict";

const TRUSTS_ALL = Symbol.for("analytics-platform.trusts-every-hop");
const CONTENT_TYPE = Symbol.for("analytics-platform.content-type");

// Whether the app was made with trustProxy: true (or a function that trusts
// any address): Fastify's request.ip is then the left-most X-Forwarded-For
// entry, which the visitor writes. Fastify keeps its options under a symbol
// it doesn't export, so it is found by its name; not found reads as no.
function trustsEveryHop(fastify) {
  try {
    let options = fastify?.initialConfig?.trustProxy !== undefined ? fastify.initialConfig : null;
    for (let at = fastify; !options && at; at = Object.getPrototypeOf(at)) {
      const key = Object.getOwnPropertySymbols(at).find((symbol) => symbol.description === "fastify.options");
      if (key) options = at[key];
    }
    const trust = options?.trustProxy;
    return trust === true || (typeof trust === "function" && Boolean(trust("203.0.113.254", 1000)));
  } catch {
    return false;
  }
}

// middleware: platform.middleware(); errors: the errors module, or null;
// queries: the database query timing (queries.js), or null; firewall: true
// when the firewall is on (it reads the Content-Type after the response).
function createFastifyPlugin(middleware, errors, { shouldCapture } = {}, queries = null, firewall = false) {
  function analyticsPlatform(fastify, options, done) {
    const trustsAll = trustsEveryHop(fastify);
    fastify.addHook("onRequest", (request, reply, next) => {
      const req = request.raw;
      // What the modules read on an Express request: the address (Fastify's
      // own, so its trustProxy setting applies as Express's does; with
      // trustProxy: true the package reads one hop instead, firewall.js
      // clientIp) and the route pattern Server speed and Errors name
      // requests by.
      if (req.ip === undefined) req.ip = request.ip;
      if (req[TRUSTS_ALL] === undefined) req[TRUSTS_ALL] = trustsAll;
      const route = request.routeOptions ? request.routeOptions.url : request.routerPath;
      if (!req.route && typeof route === "string") req.route = { path: route };
      // The middleware either calls next (the request goes on) or answers
      // itself (the firewall's 403/429, maintenance, the tracker's own
      // addresses) and never calls it, so Fastify never reaches the route.
      middleware(req, reply.raw, () => next());
    });

    // Fastify writes its headers in one writeHead() call, which
    // res.getHeader() can't read afterwards: the Content-Type is kept for
    // the firewall, which counts a static-looking request after the
    // response unless it answered a file (a static plugin's wildcard route).
    if (firewall) {
      fastify.addHook("onSend", (request, reply, payload, next) => {
        try {
          request.raw[CONTENT_TYPE] = reply.getHeader("content-type");
        } catch {
          // without it
        }
        next(null, payload);
      });
    }

    // Async work started by the route (await, timers, fetch) keeps the
    // request, so captureException() without req, breadcrumbs from outgoing
    // requests and database queries know which request they came from. Body
    // parsing between onRequest and here runs outside it.
    if (errors || queries) {
      fastify.addHook("preHandler", (request, reply, next) => {
        const go = queries ? () => queries.bind(request.raw, () => next()) : () => next();
        return errors ? errors.bind(request.raw, go) : go();
      });
    }

    if (errors) {
      // Runs before Fastify's error handler, so the status is the error's.
      fastify.addHook("onError", (request, reply, error, next) => {
        const code = Number(error?.statusCode || error?.status);
        const status = code >= 400 ? code : reply.statusCode >= 400 ? reply.statusCode : 500;
        const capture = shouldCapture ? shouldCapture(error, request) : status >= 500;
        if (capture) errors.captureException(error, { req: request.raw, status, kind: "handled" });
        next();
      });
    }
    done();
  }
  analyticsPlatform[Symbol.for("skip-override")] = true;
  analyticsPlatform[Symbol.for("fastify.display-name")] = "analytics-platform";
  analyticsPlatform[Symbol.for("plugin-meta")] = { name: "analytics-platform", fastify: ">=4" };
  return analyticsPlatform;
}

module.exports = { createFastifyPlugin };
