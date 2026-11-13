// For analytics-platform/start: puts platform.middleware() and
// platform.errorHandler() into an Express app by itself, exactly where the
// README tells you to put them by hand. The middleware goes first, after
// Express's own setup, so req.ip already follows app.set("trust proxy"). The
// error handler goes after your routes and before your own error handler.
//
// How the app is found: Express's app.listen() and http.createServer(app)
// both go through createServer, which this wraps for node:http and
// node:https. Nothing of Express is patched. The two layers are placed when
// the server is made and checked again on each request, so routes added after
// listen() (an async setup, say) still come before the error handler. That
// check only compares the stack's length.
//
// An app that already has platform.middleware() or platform.errorHandler()
// (put in by hand) is left as it is, so nothing is counted twice.
"use strict";

const http = require("node:http");
const https = require("node:https");
const { syncBuiltinESMExports } = require("node:module");

// Express 4's own first layers. Express 5 sets the request up before its
// router runs, so it has none.
const EXPRESS_SETUP = new Set(["query", "expressInit"]);
// The names of what platform.middleware() and platform.errorHandler() return.
const BY_HAND = { middleware: "platformMiddleware", errorHandler: "analyticsErrorHandler" };

function isExpressApp(fn) {
  return typeof fn === "function" && typeof fn.handle === "function" && typeof fn.use === "function" && typeof fn.set === "function";
}

// The app's top-level layers. Express 4 keeps them on app._router once a
// route or app.use() exists; its app.router getter throws. Express 5 has
// app.router.
function stackOf(app) {
  if (Array.isArray(app._router?.stack)) return app._router.stack;
  try {
    return Array.isArray(app.router?.stack) ? app.router.stack : null;
  } catch {
    return null;
  }
}

function createExpressPlacer(platform) {
  const placed = new WeakMap();

  // Makes the app's own Layer objects for the two handlers, through its own
  // app.use(), then takes them back off the end to place them.
  function layersFor(app) {
    let state = placed.get(app);
    if (state) return state;
    const middleware = platform.middleware();
    const errorHandler = platform.errorHandler();
    app.use(middleware);
    const stack = stackOf(app);
    if (!stack) return null;
    const front = stack.pop();
    app.use(errorHandler);
    const back = stack.pop();
    if (front?.handle !== middleware || back?.handle !== errorHandler) return null;
    state = { front, back, stack, length: -1 };
    placed.set(app, state);
    return state;
  }

  function place(app) {
    const state = layersFor(app);
    if (!state) return;
    const stack = stackOf(app);
    if (stack === state.stack && stack.length === state.length) return;
    for (const layer of [state.front, state.back]) {
      const at = stack.indexOf(layer);
      if (at >= 0) stack.splice(at, 1);
    }
    const names = new Set(stack.map((layer) => layer.handle?.name));
    if (!names.has(BY_HAND.middleware)) {
      let at = 0;
      while (at < stack.length && EXPRESS_SETUP.has(stack[at].name)) at += 1;
      stack.splice(at, 0, state.front);
    }
    if (!names.has(BY_HAND.errorHandler)) {
      // Before the first error handler of your own (four arguments), so it
      // sees the error before yours answers; at the end without one.
      const at = stack.findIndex((layer) => layer !== state.front && layer.handle?.length === 4);
      stack.splice(at < 0 ? stack.length : at, 0, state.back);
    }
    state.stack = stack;
    state.length = stack.length;
  }

  return function watch(server, app) {
    // An Express we can't read never stops a request: it says so once and is
    // left alone, and the two lines by hand still work.
    let broken = false;
    const safely = () => {
      if (broken) return;
      try {
        place(app);
      } catch (error) {
        broken = true;
        console.warn("[analytics-platform] couldn't add itself to this Express app; add app.use(platform.middleware()) and app.use(platform.errorHandler()) by hand:", error?.message);
      }
    };
    safely();
    // First, before the app's own listener, so it runs before each request.
    server.prependListener("request", safely);
  };
}

// Wraps createServer once per process.
const WRAPPED = Symbol.for("analytics-platform.createServer");

function watchExpress(platform) {
  const watch = createExpressPlacer(platform);
  for (const mod of [http, https]) {
    if (mod.createServer[WRAPPED]) continue;
    const original = mod.createServer;
    const createServer = function createServer(...args) {
      const server = original.apply(this, args);
      const app = args.find(isExpressApp);
      if (app && server && typeof server.prependListener === "function") watch(server, app);
      return server;
    };
    createServer[WRAPPED] = true;
    mod.createServer = createServer;
  }
  // `import { createServer } from "node:http"` sees the wrapped one too.
  syncBuiltinESMExports();
}

module.exports = { watchExpress, createExpressPlacer, stackOf };
