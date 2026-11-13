// Sends a Node server's errors to the analytics collector (POST
// /events/server-errors), where they join the browser's errors in the Errors
// report. No dependencies; Node 18+ (global fetch).
//
// Uncaught exceptions and unhandled rejections are captured on their own and
// the process still exits as Node would. errorHandler() captures Express
// request errors (5xx only); captureException() captures errors you catch.
// Errors are sent in small batches; sending never throws into your app.
"use strict";

const os = require("node:os");

const BATCH = 10;
const QUEUE_MAX = 100;
const FLUSH_MS = 2000;
const TIMEOUT_MS = 5000;
const EXIT_FLUSH_MS = 2000;
const SESSION_HEADER = "x-analytics-session";

let config = null;
let queue = [];
let timer = null;
let sending = Promise.resolve();

function log(...args) {
  if (config?.debug) console.warn("[analytics-server-errors]", ...args);
}

// Paths relative to the app's root, so an issue keeps its identity across
// servers and deploy directories.
function relative(stack) {
  const root = config.root.replace(/\/+$/, "");
  return root ? stack.split(`file://${root}/`).join("").split(`${root}/`).join("") : stack;
}

// Fields of the request the error happened in (Express, or Node's own
// http.IncomingMessage).
function requestFields(req) {
  if (!req || typeof req !== "object") return {};
  const url = String(req.originalUrl || req.url || "");
  const route = req.route?.path && typeof req.route.path === "string" ? `${req.baseUrl || ""}${req.route.path}` : "";
  const session = req.headers?.[SESSION_HEADER];
  return {
    method: String(req.method || ""),
    path: url.split("?")[0],
    route,
    session_id: typeof session === "string" ? session : "",
  };
}

function toEvent(error, { req, status, kind = "handled" } = {}) {
  const isError = error instanceof Error;
  const message = isError ? error.message : typeof error === "string" ? error : safeString(error);
  return {
    message: message || (isError ? error.name : "Unknown error"),
    error_type: isError ? error.name || error.constructor?.name || "Error" : "Error",
    stack: isError && typeof error.stack === "string" ? relative(error.stack) : "",
    kind,
    status_code: Number(status) || 0,
    runtime: "Node",
    runtime_version: process.versions.node,
    os: process.platform,
    server_name: config.serverName,
    ...requestFields(req),
  };
}

function safeString(value) {
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function schedule() {
  if (timer || !queue.length) return;
  timer = setTimeout(() => {
    timer = null;
    flush();
  }, FLUSH_MS);
  timer.unref?.();
}

async function send(errors) {
  try {
    const res = await fetch(`${config.endpoint}/events/server-errors`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ site_id: config.siteId, sitesecret: config.secret, errors }),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
    if (!res.ok) log(`collector answered ${res.status}`, await res.text().catch(() => ""));
  } catch (error) {
    log("could not send errors:", error?.message);
  }
}

// Sends everything queued; resolves when sent (or failed).
function flush() {
  if (timer) {
    clearTimeout(timer);
    timer = null;
  }
  const batches = [];
  while (queue.length) batches.push(queue.splice(0, BATCH));
  sending = sending.then(() => Promise.all(batches.map(send)));
  return sending;
}

// Queues one error; `context` is { req, status, kind }. Returns nothing and
// never throws.
function captureException(error, context = {}) {
  if (!config) return;
  try {
    let event = toEvent(error, context);
    if (config.beforeSend) event = config.beforeSend(event, error);
    if (!event) return;
    if (queue.length >= QUEUE_MAX) {
      log("queue full, error dropped");
      return;
    }
    queue.push(event);
    if (queue.length >= BATCH) flush();
    else schedule();
  } catch (failure) {
    log("could not capture error:", failure?.message);
  }
}

// Express error middleware; use after your routes. Captures 5xx errors (4xx
// are the client's) and passes the error on unchanged.
function errorHandler({ shouldCapture } = {}) {
  return function analyticsErrorHandler(error, req, res, next) {
    const status = Number(error?.status || error?.statusCode) || 500;
    const capture = shouldCapture ? shouldCapture(error, req) : status >= 500;
    if (capture) captureException(error, { req, status, kind: "handled" });
    next(error);
  };
}

// Uncaught exceptions, and unhandled rejections (which Node turns into
// uncaught exceptions by default). When no other handler is listening, the
// error is printed and the process exits with code 1, as without the SDK,
// after up to EXIT_FLUSH_MS to send it.
function onUncaught(error, origin) {
  captureException(error, { kind: origin === "unhandledRejection" ? "rejection" : "error" });
  if (process.listenerCount("uncaughtException") > 1) return;
  console.error(error);
  const exit = setTimeout(() => process.exit(1), EXIT_FLUSH_MS);
  flush().finally(() => {
    clearTimeout(exit);
    process.exit(1);
  });
}

// siteId and secret: the site's ID and secret (site settings). endpoint: the
// collector's URL. Options: serverName (default the host name), root (paths
// in stacks are made relative to it; default process.cwd()), captureUncaught
// (default true), beforeSend(event, error) to change an event or drop it
// (return null), debug (log send failures).
function initServerErrors(options = {}) {
  const { siteId, secret, endpoint } = options;
  if (!/^[a-f0-9]{24}$/i.test(String(siteId || "")) || !secret || !endpoint) {
    console.warn("[analytics-server-errors] siteId, secret and endpoint are required; errors will not be sent");
    return;
  }
  const first = !config;
  config = {
    siteId: String(siteId),
    secret: String(secret),
    endpoint: String(endpoint).replace(/\/+$/, ""),
    serverName: String(options.serverName ?? os.hostname()).slice(0, 100),
    root: String(options.root ?? process.cwd()),
    beforeSend: typeof options.beforeSend === "function" ? options.beforeSend : null,
    debug: Boolean(options.debug),
  };
  if (first && options.captureUncaught !== false) process.on("uncaughtException", onUncaught);
}

module.exports = { initServerErrors, captureException, errorHandler, flush };
