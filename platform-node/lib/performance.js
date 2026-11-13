// Performance & API monitoring module: times every request (from arriving to
// the response being sent) and sends one row per minute, method, route and
// status code (how many, total and slowest time, and a count per time bucket)
// to POST /events/server-requests. Nothing about visitors is sent.
//
// The route is the framework's own pattern when there is one (Express
// "/users/:id"); otherwise numbers and IDs in the path become ":id", and
// unmatched 404s are one route, so random paths don't make thousands.
"use strict";

// No Node built-ins required, so Hono can time requests on any runtime
// (hono.js): os is asked for at run time, as core.js does. Node before 20.16
// has no getBuiltinModule and loads it the old way.
function hostname() {
  try {
    const os = globalThis.process?.getBuiltinModule?.("node:os")
      ?? (typeof require === "function" ? require(["node", "os"].join(":")) : null);
    return os?.hostname() || "";
  } catch {
    return "";
  }
}

// Keep in step with the collector (expresscollect/Analytics/serverRequests.js).
const BUCKET_EDGES_MS = [5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000];
const FLUSH_MS = 60 * 1000;
const MAX_KEYS = 300;
// Past MAX_KEYS a minute's new routes fold into "(other)"; past this nothing
// new is kept at all, whatever the requests carry.
const HARD_MAX_KEYS = 400;
const MAX_ROWS = 500;
const NOT_FOUND = "/(not found)";
// The method is the visitor's to choose ("FOO1", "FOO2"...): anything else
// is one "OTHER", so it can't make a row per request.
const METHODS = new Set(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "JOB"]);
const methodOf = (method) => {
  const name = String(method || "GET").toUpperCase();
  return METHODS.has(name) ? name : "OTHER";
};

// "/orders/123/items/9f8e..." -> "/orders/:id/items/:id"
function normalizeRoute(url) {
  const path = String(url || "/").split(/[?#]/)[0] || "/";
  const route = path.split("/").map((segment) => (
    /^\d+$/.test(segment) || /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(segment)
      || /^[0-9a-f]{16,}$/i.test(segment) || (segment.length >= 20 && /\d/.test(segment))
      ? ":id" : segment
  )).join("/");
  return (route.startsWith("/") ? route : `/${route}`).slice(0, 200);
}

function bucketOf(ms) {
  const i = BUCKET_EDGES_MS.findIndex((edge) => ms <= edge);
  return i === -1 ? BUCKET_EDGES_MS.length : i;
}

// Options: serverName (default the host name), route(req) (your own route
// name for a request, or "" to leave it out); runtime and timer: false (no
// minute timer: whoever records flushes) for hono.js.
function createPerformance(core, options = {}) {
  const log = (...args) => core.log("performance", ...args);
  const serverName = String(options.serverName ?? hostname()).slice(0, 100);
  const runtime = options.runtime || `Node ${process.versions.node}`;
  let rows = new Map();
  const keysIn = new Map(); // minute -> rows it has
  let sending = Promise.resolve();

  // Records one finished request. Returns the route it was counted under
  // ("(other)" past the cap), or undefined with Server speed off.
  function record({ method: given, route, status: code, ms }) {
    if (!core.isOn("performance")) return undefined;
    const method = methodOf(given);
    const status = Math.trunc(Number(code)) || 0;
    const minute = Math.floor(Date.now() / 60000) * 60000;
    let key = `${minute}|${method}|${route}|${status}`;
    // The cap is per minute: rows of a minute not yet sent don't count.
    const used = keysIn.get(minute) || 0;
    let shown = route;
    if (!rows.has(key) && used >= MAX_KEYS) {
      shown = "(other)";
      key = `${minute}|${method}|(other)|${status}`;
    }
    let row = rows.get(key);
    if (!row && used >= HARD_MAX_KEYS) return shown;
    if (!row) {
      row = { minute, method, route: shown, status, count: 0, sum_ms: 0, max_ms: 0, buckets: new Array(BUCKET_EDGES_MS.length + 1).fill(0) };
      rows.set(key, row);
      keysIn.set(minute, used + 1);
    }
    row.count += 1;
    row.sum_ms += ms;
    if (ms > row.max_ms) row.max_ms = ms;
    row.buckets[bucketOf(ms)] += 1;
    return shown;
  }

  // Told of each request timed, with the method and route it was counted
  // under: the queries module (queries.js) files the request's queries there.
  let finished = null;

  function routeOf(req, status) {
    const own = options.route?.(req);
    if (own) return String(own).slice(0, 200);
    if (req.route?.path && typeof req.route.path === "string") return `${req.baseUrl || ""}${req.route.path}`.slice(0, 200);
    return status === 404 ? NOT_FOUND : normalizeRoute(req.originalUrl || req.url);
  }

  // Requests in progress now, and the most at once since the resources
  // module last asked. `timed` stays false until the middleware first runs,
  // so an app that never installed it reports no peak rather than 0.
  let inflight = 0;
  let peak = 0;
  let timed = false;
  function takeInflightPeak() {
    if (!timed) return null;
    const most = peak;
    peak = inflight;
    return most;
  }

  // Express / Connect / node:http middleware.
  function middleware(req, res, next = () => {}) {
    const start = process.hrtime.bigint();
    timed = true;
    inflight += 1;
    if (inflight > peak) peak = inflight;
    // finish for an answered request, close for one the client dropped;
    // either ends it, once.
    let open = true;
    const done = () => {
      if (!open) return;
      open = false;
      inflight -= 1;
    };
    res.once("close", done);
    res.once("finish", () => {
      done();
      try {
        const ms = Number(process.hrtime.bigint() - start) / 1e6;
        const status = res.statusCode || 0;
        const route = record({ method: req.method, route: routeOf(req, status), status, ms });
        if (route !== undefined) finished?.(req, methodOf(req.method), route);
      } catch (error) {
        log("could not time a request:", error?.message);
      }
    });
    next();
  }

  // Sends the rows of finished minutes (all of them with all = true).
  function flush(all = false) {
    const current = Math.floor(Date.now() / 60000) * 60000;
    const ready = [];
    for (const [key, row] of rows) {
      if (all || row.minute < current) {
        ready.push({ ...row, minute: new Date(row.minute).toISOString(), sum_ms: Math.round(row.sum_ms * 10) / 10, max_ms: Math.round(row.max_ms * 10) / 10 });
        rows.delete(key);
      }
    }
    for (const minute of keysIn.keys()) if (all || minute < current) keysIn.delete(minute);
    for (let i = 0; i < ready.length; i += MAX_ROWS) {
      const batch = ready.slice(i, i + MAX_ROWS);
      sending = sending.then(() => core.send("performance", "/events/server-requests", { body: { server_name: serverName, runtime, rows: batch } }));
    }
    return sending;
  }

  const timer = core.valid && options.timer !== false ? setInterval(() => flush(), FLUSH_MS) : null;
  timer?.unref?.();

  return {
    middleware,
    record,
    routeOf,
    takeInflightPeak,
    afterRequest(fn) {
      finished = typeof fn === "function" ? fn : null;
    },
    flush: () => flush(true),
    close() {
      clearInterval(timer);
      return flush(true);
    },
  };
}

module.exports = { createPerformance, normalizeRoute, methodOf, bucketOf, hostname, BUCKET_EDGES_MS, NOT_FOUND, HARD_MAX_KEYS };
