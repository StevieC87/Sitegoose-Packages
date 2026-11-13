// Koa middleware (Koa 2 and 3): the same middleware as Express, run on Koa's
// raw request and response, and 5xx errors from the middleware after it, in
// place of errorHandler().
//
//   app.use(platform.koa());   // first, before your other middleware
"use strict";

const TRUSTS_ALL = Symbol.for("analytics-platform.trusts-every-hop");

// app.proxy with no maxIpsCount makes ctx.ip the left-most X-Forwarded-For
// entry, which the visitor writes: the package then reads one hop instead
// (firewall.js clientIp). Another proxyIpHeader (X-Real-IP, set by the
// proxy) or a maxIpsCount is believed as Koa reads it.
function trustsEveryHop(app) {
  if (!app?.proxy || Number(app.maxIpsCount) > 0) return false;
  return String(app.proxyIpHeader || "X-Forwarded-For").toLowerCase() === "x-forwarded-for";
}

// middleware: platform.middleware(); errors: the errors module, or null.
function createKoaMiddleware(middleware, errors, { shouldCapture } = {}) {
  return function analyticsPlatform(ctx, next) {
    const req = ctx.req;
    // Koa's own address, so its app.proxy setting applies as Express's
    // "trust proxy" does.
    if (req.ip === undefined) req.ip = ctx.ip;
    if (req[TRUSTS_ALL] === undefined) req[TRUSTS_ALL] = trustsEveryHop(ctx.app);

    // The rest of the app, run where the middleware calls next: inside the
    // errors module's request, so a captureException() or an outgoing
    // request after an await still knows which request it came from.
    const run = async () => {
      try {
        await next();
      } catch (error) {
        const status = Number(error?.status || error?.statusCode) || 500;
        const capture = shouldCapture ? shouldCapture(error, ctx) : status >= 500;
        if (capture && errors) errors.captureException(error, { req, status, kind: "handled" });
        throw error;
      } finally {
        // The route pattern @koa/router matched (`/users/:id`), for Server
        // speed and Errors; known only once routing has run, and read when
        // the response finishes.
        if (!req.route && typeof ctx._matchedRoute === "string") req.route = { path: ctx._matchedRoute };
      }
    };

    return new Promise((resolve, reject) => {
      let passed = false;
      // Answered by the middleware itself (the firewall's 403/429,
      // maintenance, the tracker's own addresses): Koa must not answer too.
      const answered = () => {
        if (passed) return;
        ctx.respond = false;
        resolve();
      };
      ctx.res.once("finish", answered);
      ctx.res.once("close", answered);
      middleware(req, ctx.res, () => {
        passed = true;
        run().then(resolve, reject);
      });
    });
  };
}

module.exports = { createKoaMiddleware };
