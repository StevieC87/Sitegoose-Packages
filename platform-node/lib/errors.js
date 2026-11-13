// Error monitoring module: the server's errors go to the collector (POST
// /events/server-errors), where they join the browser's errors in the Errors
// report. Uncaught exceptions and unhandled rejections are captured on their
// own and the process still exits as Node would. errorHandler() captures
// Express request errors (5xx only); captureException() captures errors you
// catch; captureConsole sends the errors your code logs with console.error.
// An error is sent once however many of those see it. Errors are sent in
// small batches, a batch the collector couldn't take is tried once more, and
// sending never throws into your app. What still can't be sent (the collector
// is away, or the process is crashing) waits in a file and is sent once it
// can be, after a restart too; each error carries when it happened.
// job(name, fn) names the errors of a background job as its route.
// Each error carries the trail of its request: the outgoing requests it made
// (seen on Node's diagnostics channels, so nothing of Express or fetch is
// patched) and what you add with addBreadcrumb().
"use strict";

const os = require("node:os");
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const { AsyncLocalStorage } = require("node:async_hooks");
const channels = require("node:diagnostics_channel");
const { sessionOf, disconnected } = require("./core.js");
const { normalizeRoute } = require("./performance.js");

const BATCH = 10;
const QUEUE_MAX = 100;
const FLUSH_MS = 2000;
const EXIT_FLUSH_MS = 2000;
// A batch the collector couldn't take (unreachable, 429, 5xx) is sent once
// more after its Retry-After, capped, or this.
const RETRY_MS = 2000;
const RETRY_MAX_MS = 5000;
// The file of errors waiting to be sent: tried again this often, and kept
// under this size (past it, new ones are dropped rather than filling a disk).
const RESEND_MS = 60 * 1000;
const SPOOL_BYTES = 1024 * 1024;
// A message longer than this is cut: a whole response body or SQL dump in
// an exception's message would otherwise fill the batch (and the file).
const MAX_MESSAGE = 2000;
// A file being sent by a process that is gone (killed while sending) is
// picked up again after this, even when its process ID is in use again.
const ORPHAN_MS = 10 * 60 * 1000;
// The request being handled, from platform.middleware(): an error captured
// without one (logged, or caught deep in your code) still gets its route.
const requests = new AsyncLocalStorage();
// Marks the context job() runs in; a Symbol, so an app's own req.job is never
// taken for one.
const JOB = Symbol("analytics job");
// The trail of each request or job: the last CRUMB_MAX steps, oldest first.
const CRUMB_MAX = 15;
const trails = new WeakMap();
// An outgoing request still waiting for its answer -> its address and the
// request or job that made it. A step is added once the answer is known.
const outgoing = new WeakMap();
// The collectors in use: a package's own calls aren't steps of the request.
const collectors = new Set();
let watching = false;
// Every instance's uncaught-exception handler, with its flush: two platforms in
// one process are still "no other handler", and the exit waits for both.
const handlers = new Map();
let exiting = false;

function addCrumb(context, crumb) {
  if (!context) return;
  const trail = trails.get(context) || [];
  trail.push({ ...crumb, text: String(crumb.text).slice(0, 200), at: Date.now() });
  if (trail.length > CRUMB_MAX) trail.shift();
  trails.set(context, trail);
}

// Starts with a request's context, ends with an answer arriving on whichever
// socket it arrives on, so the two are joined by the request object.
function requestStarted(request, address) {
  const context = requests.getStore();
  const url = address.split(/[?#]/)[0];
  // The collector's own address and what's under it: not a server on the
  // same host whose port merely starts with the same digits.
  if (!context || [...collectors].some((collector) => url === collector || url.startsWith(`${collector}/`))) return;
  outgoing.set(request, { context, text: `${request.method} ${url}` });
}

function requestEnded(request, status) {
  const started = outgoing.get(request);
  if (!started) return;
  outgoing.delete(request);
  addCrumb(started.context, { type: "request", text: started.text, status });
}

function requestFailed(request, error) {
  // Cancelled by the app, as the tracker treats a cancelled fetch: not a failure.
  if (error?.name === "AbortError") outgoing.delete(request);
  else requestEnded(request, 0);
}

// One subscription however many instances, for the life of the process: with
// no request in progress a step has nowhere to go, so it costs nothing.
function watchRequests() {
  if (watching) return;
  watching = true;
  // A subscriber that throws reaches the app as an uncaught exception.
  const watch = (channel, fn) => channels.subscribe(channel, (message) => {
    try {
      fn(message);
    } catch {
      // the step is left out
    }
  });
  // fetch()
  watch("undici:request:create", ({ request }) => requestStarted(request, `${request.origin}${request.path}`));
  watch("undici:request:headers", ({ request, response }) => requestEnded(request, response.statusCode));
  watch("undici:request:error", ({ request, error }) => requestFailed(request, error));
  // http.request() and what's built on it (axios, got)
  watch("http.client.request.start", ({ request }) => requestStarted(request, `${request.protocol}//${request.getHeader("host")}${request.path}`));
  watch("http.client.response.finish", ({ request, response }) => requestEnded(request, response.statusCode));
  watch("http.client.request.error", ({ request, error }) => requestFailed(request, error));
}

// Options: serverName (default the host name), root (paths in stacks are
// made relative to it; default process.cwd()), release (which build this is,
// for "introduced in" in the Errors report; defaults to ANALYTICS_RELEASE in
// the environment), captureUncaught (default true), captureConsole (default
// false: errors passed to console.error are sent too), beforeSend(event,
// error) to change an event or drop it (return null), spoolDir (where errors
// that couldn't be sent wait; default the system's temp folder, false to keep
// none).
function createErrors(core, options = {}) {
  const config = {
    serverName: String(options.serverName ?? os.hostname()).slice(0, 100),
    root: String(options.root ?? process.cwd()),
    // Letters, numbers and .-_+ only, as the collector stores it.
    release: String(options.release ?? process.env.ANALYTICS_RELEASE ?? "")
      .trim().replace(/[^\w.+-]/g, "").slice(0, 64),
    beforeSend: typeof options.beforeSend === "function" ? options.beforeSend : null,
  };
  let queue = [];
  let timer = null;
  let sending = Promise.resolve();
  // Errors already captured: the error handler, your own handler logging it
  // and the uncaught handler can all see one error. While its event still
  // waits to be sent, a later capture can fill it in (pending).
  const seen = new WeakSet();
  const pending = new WeakMap();
  // Server speed's own naming (performance's routeOf, set by the platform),
  // so an error and the request's timings name a route the same way.
  let routeOf = null;
  const log = (...args) => core.log("errors", ...args);
  if (core.endpoint) collectors.add(core.endpoint);
  try {
    watchRequests();
  } catch (failure) {
    log("could not watch outgoing requests:", failure?.message);
  }
  // Named after the site and its secret, not the site id alone, so the
  // folder's listing tells nobody which site it is.
  const spoolFile = options.spoolDir === false || !core.valid ? null : path.join(String(options.spoolDir || os.tmpdir()),
    `analytics-errors-${crypto.createHash("sha256").update(`${core.siteId}|${core.secret}`).digest("hex").slice(0, 16)}.jsonl`);
  // Batches being sent: written to the file if the process exits first.
  const inFlight = new Set();
  let lastResend = 0;

  // Paths relative to the app's root, so an issue keeps its identity across
  // servers and deploy directories.
  function relative(stack) {
    const root = config.root.replace(/\/+$/, "");
    return root ? stack.split(`file://${root}/`).join("").split(`${root}/`).join("") : stack;
  }

  // Fields of the request the error happened in (Express, or Node's own
  // http.IncomingMessage).
  function requestFields(req, status) {
    if (!req || typeof req !== "object") return {};
    if (req[JOB]) return { method: "JOB", path: req[JOB], route: req[JOB], session_id: "" };
    const url = String(req.originalUrl || req.url || "");
    let route = "";
    try {
      route = routeOf ? String(routeOf(req, status) || "")
        : req.route?.path && typeof req.route.path === "string" ? `${req.baseUrl || ""}${req.route.path}` : normalizeRoute(url);
    } catch {
      // a custom route() that throws leaves the route out
    }
    return {
      method: String(req.method || ""),
      path: url.split("?")[0],
      route,
      session_id: sessionOf(req),
    };
  }

  // What happened in the request before now, as the tracker sends it.
  function breadcrumbs(req) {
    const now = Date.now();
    const trail = (req && trails.get(req)) || [];
    return trail.length ? { breadcrumbs: trail.map(({ at, ...crumb }) => ({ ...crumb, ms: now - at })) } : {};
  }

  function toEvent(error, { req, status, kind = "handled" } = {}) {
    const isError = error instanceof Error;
    const message = isError ? error.message : typeof error === "string" ? error : safeString(error);
    return {
      message: String(message || (isError ? error.name : "Unknown error")).slice(0, MAX_MESSAGE),
      error_type: isError ? error.name || error.constructor?.name || "Error" : "Error",
      stack: isError && typeof error.stack === "string" ? relative(error.stack) : "",
      kind,
      status_code: Number(status) || 0,
      runtime: "Node",
      runtime_version: process.versions.node,
      os: process.platform,
      server_name: config.serverName,
      release: config.release,
      // When it happened: a crash sent after a restart keeps its own time.
      at: new Date().toISOString(),
      ...requestFields(req, status),
      ...breadcrumbs(req),
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

  // Not taken, and worth keeping to send later: no answer, 429, 5xx. A batch
  // that can't be JSON (unsendable) never will be, and is dropped.
  const failed = (res) => !res || res.status === 429 || res.status >= 500;
  const post = (errors) => core.send("errors", "/events/server-errors", { body: { errors } });
  async function send(errors) {
    // Written to the file by an exit while it waited its turn: not sent too.
    if (!inFlight.has(errors)) return null;
    try {
      let res = await post(errors);
      // Tried once more a little later, but not when the process is ending
      // (a deadline is set): what's left waits in the file instead.
      if (failed(res) && core.timeLeft?.() == null) {
        const after = Number(res?.headers?.get?.("retry-after")) * 1000;
        const wait = Math.min(after > 0 ? after : RETRY_MS, RETRY_MAX_MS);
        // Not unref'd: a script that awaits flush() and ends must not exit
        // during the wait, with the batch neither sent nor kept.
        await new Promise((resolve) => setTimeout(resolve, wait));
        res = await post(errors);
      }
      if (!inFlight.has(errors)) return res; // already written by an exit
      inFlight.delete(errors);
      if (failed(res)) spool(errors);
      else if (Date.now() - lastResend >= RESEND_MS) resend();
      return res;
    } finally {
      inFlight.delete(errors);
    }
  }

  // Appends events to the file (synchronously: an exit can follow at once).
  // Credentials are added when sent, never written down. What fits, oldest
  // first: the file never grows past SPOOL_BYTES, this write included.
  function spool(events) {
    if (!spoolFile || !events.length) return;
    try {
      const lines = [];
      for (const event of events) {
        try {
          lines.push(`${JSON.stringify(event)}\n`);
        } catch {
          // not JSON: it can never be sent
        }
      }
      let room = SPOOL_BYTES - (fs.existsSync(spoolFile) ? fs.statSync(spoolFile).size : 0);
      const kept = [];
      for (const line of lines) {
        room -= Buffer.byteLength(line);
        if (room < 0) break;
        kept.push(line);
      }
      if (kept.length < lines.length) log(`waiting errors file is full, ${lines.length - kept.length} errors dropped`);
      if (kept.length) fs.appendFileSync(spoolFile, kept.join(""), { mode: 0o600 });
    } catch (failure) {
      log("could not keep errors to send later:", failure?.message);
    }
  }

  // Everything not yet sent, to the file: the process is about to exit.
  function persist() {
    if (timer) {
      clearTimeout(timer);
      timer = null;
    }
    const waiting = [...inFlight].flat().concat(queue);
    inFlight.clear();
    queue = [];
    spool(waiting);
    // A resend under way: what it hasn't sent goes back in the spool file
    // too (a SIGKILL instead leaves the taken file, for the next start).
    const taken = sendingFile;
    sendingFile = null;
    if (taken) {
      try {
        const left = fs.readFileSync(taken, "utf8").split("\n").filter(Boolean).map((line) => {
          try {
            return JSON.parse(line);
          } catch {
            return null;
          }
        }).filter((event) => event && typeof event === "object");
        spool(left);
        fs.unlinkSync(taken);
      } catch {
        // gone already
      }
    }
  }

  // Sends what earlier attempts (or an earlier run) couldn't. Taken by
  // renaming the file first, so two processes never send the same errors.
  // The taken file stays until its errors are sent (rewritten with what's
  // left after each batch), so a process killed while sending loses none:
  // the next run finds it (orphans) and sends it.
  let resending = null;
  // The taken file being sent right now, or null.
  let sendingFile = null;
  const takenName = (pid) => `${spoolFile}.${pid}.sending`;
  const alive = (pid) => {
    try {
      process.kill(pid, 0);
      return true;
    } catch (failure) {
      return failure?.code === "EPERM";
    }
  };
  // Files a killed process left: another process's once that process is
  // gone (or the file is old), this process ID's always (no resend of ours
  // is running when this is called, so it's an earlier run's).
  async function orphans() {
    const dir = path.dirname(spoolFile);
    const base = `${path.basename(spoolFile)}.`;
    let names = [];
    try {
      names = await fs.promises.readdir(dir);
    } catch {
      return [];
    }
    const found = [];
    for (const name of names) {
      const match = name.startsWith(base) ? /^(\d+)\.sending(?:\.[0-9a-f]+)?$/.exec(name.slice(base.length)) : null;
      if (!match) continue;
      const pid = Number(match[1]);
      const file = path.join(dir, name);
      let old = false;
      try {
        old = Date.now() - (await fs.promises.stat(file)).mtimeMs > ORPHAN_MS;
      } catch {
        continue;
      }
      if (pid === process.pid || old || !alive(pid)) found.push(file);
    }
    return found;
  }
  const readEvents = async (file) => (await fs.promises.readFile(file, "utf8")).split("\n").filter(Boolean).map((line) => {
    try {
      return JSON.parse(line);
    } catch {
      return null;
    }
  }).filter((event) => event && typeof event === "object");
  // Sends one taken file; false when the collector stopped taking them (what's
  // left goes back in the spool file, for the next try).
  async function sendTaken(taken) {
    let events = [];
    try {
      events = await readEvents(taken);
    } catch {
      return true;
    }
    sendingFile = taken;
    while (events.length) {
      const res = await post(events.slice(0, BATCH));
      // An exit wrote what's left back to the spool file (persist): stop here.
      if (sendingFile !== taken) return false;
      if (failed(res) && !res?.unsendable) {
        sendingFile = null;
        spool(events);
        await fs.promises.unlink(taken).catch(() => {});
        return false;
      }
      events = events.slice(BATCH);
      try {
        if (events.length) fs.writeFileSync(taken, events.map((event) => JSON.stringify(event)).join("\n") + "\n", { mode: 0o600 });
      } catch {
        // sent again after a crash, at worst
      }
    }
    sendingFile = null;
    await fs.promises.unlink(taken).catch(() => {});
    return true;
  }
  function resend() {
    if (!spoolFile || resending) return resending;
    lastResend = Date.now();
    resending = (async () => {
      const files = [];
      for (const orphan of await orphans()) {
        // Claimed by renaming, as the spool file is: one process gets it.
        const claimed = `${takenName(process.pid)}.${crypto.randomBytes(6).toString("hex")}`;
        try {
          await fs.promises.rename(orphan, claimed);
          files.push(claimed);
        } catch {
          // another process took it
        }
      }
      try {
        await fs.promises.rename(spoolFile, takenName(process.pid));
        files.push(takenName(process.pid));
      } catch {
        // nothing waiting
      }
      for (const file of files) {
        if (!(await sendTaken(file))) {
          // The collector is away: the rest go back in the spool unsent.
          for (const rest of files.slice(files.indexOf(file) + 1)) {
            try {
              spool(await readEvents(rest));
            } finally {
              await fs.promises.unlink(rest).catch(() => {});
            }
          }
          return;
        }
      }
    })().catch((failure) => log("could not send waiting errors:", failure?.message)).finally(() => {
      resending = null;
    });
    return resending;
  }
  const resendTimer = spoolFile ? setInterval(() => {
    if (fs.existsSync(spoolFile)) resend();
  }, RESEND_MS) : null;
  resendTimer?.unref?.();
  // What an earlier run left, soon after start.
  if (spoolFile) setTimeout(() => resend(), 5000).unref?.();

  // Sends everything queued; resolves when sent (or failed).
  function flush() {
    if (timer) {
      clearTimeout(timer);
      timer = null;
    }
    const batches = [];
    while (queue.length) batches.push(queue.splice(0, BATCH));
    // In flight from now, not from when the send before them ends: an exit
    // meanwhile writes them to the file (persist) instead of losing them.
    for (const batch of batches) inFlight.add(batch);
    sending = sending.then(() => Promise.all(batches.map(send)));
    return sending;
  }

  // Queues one error; `context` is { req, status, kind }. Returns nothing and
  // never throws.
  function captureException(error, context = {}) {
    if (!core.isOn("errors")) return;
    try {
      // A Fastify request (what a NestJS filter gets on Fastify) stands for
      // its raw request, which the plugin gave the route and the trail.
      const given = context.req?.raw?.headers && context.req.raw !== context.req ? context.req.raw : context.req;
      const req = given || requests.getStore();
      // The visitor went away mid-request (ECONNRESET, EPIPE, an aborted
      // request): not a server error.
      const gone = req && !req[JOB] && (req.aborted || req.socket?.destroyed || (req.res?.destroyed && !req.res?.writableFinished));
      if (disconnected(error, gone)) return;
      const tracked = error && typeof error === "object";
      if (tracked && seen.has(error)) {
        upgrade(error, toEvent(error, { ...context, req }));
        return;
      }
      if (tracked) seen.add(error);
      let event = toEvent(error, { ...context, req });
      if (config.beforeSend) event = config.beforeSend(event, error);
      if (!event) return;
      if (queue.length >= QUEUE_MAX) {
        log("queue full, error dropped");
        return;
      }
      queue.push(event);
      if (tracked) pending.set(error, event);
      if (queue.length >= BATCH) flush();
      else schedule();
    } catch (failure) {
      log("could not capture error:", failure?.message);
    }
  }

  // An error logged and then thrown on is captured first as "logged", with no
  // status; the error handler's capture that follows knows the status, the
  // kind and the request. Filled in while the event still waits to be sent.
  function upgrade(error, fresh) {
    const waiting = pending.get(error);
    const index = waiting ? queue.indexOf(waiting) : -1;
    if (index === -1 || fresh.kind === "logged") return;
    let event = {
      ...waiting,
      kind: waiting.kind === "logged" ? fresh.kind : waiting.kind,
      status_code: waiting.status_code || fresh.status_code,
    };
    for (const key of ["method", "path", "route", "session_id"]) {
      if (!event[key] && fresh[key]) event[key] = fresh[key];
    }
    if (config.beforeSend) event = config.beforeSend(event, error);
    if (event) {
      queue[index] = event;
      pending.set(error, event);
    } else {
      queue.splice(index, 1);
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
    if (exiting || process.listeners("uncaughtException").some((listener) => !handlers.has(listener))) return;
    exiting = true;
    console.error(error);
    // After the other instances' handlers (called right after this one) have
    // queued the error too.
    // What isn't sent by then waits in the file for the next start.
    process.nextTick(() => {
      // No retry waits, and no send outlasting the exit.
      for (const handler of handlers.values()) handler.core?.within?.(EXIT_FLUSH_MS);
      const keepAll = () => [...handlers.values()].forEach((handler) => handler.persist());
      const exit = setTimeout(() => {
        keepAll();
        process.exit(1);
      }, EXIT_FLUSH_MS);
      Promise.allSettled([...handlers.values()].map((handler) => handler.flush())).finally(() => {
        clearTimeout(exit);
        keepAll();
        process.exit(1);
      });
    });
  }

  if (options.captureUncaught !== false) {
    handlers.set(onUncaught, { flush, persist, core });
    process.on("uncaughtException", onUncaught);
  }

  // console.error(..., error, ...) still prints as before; the first Error
  // among its arguments is sent as "logged". Plain text isn't: it has no
  // stack to group it by.
  let restoreConsole = () => {};
  if (options.captureConsole) {
    const original = console.error;
    let inside = false;
    const wrapped = function analyticsConsoleError(...args) {
      original.apply(this, args);
      const error = args.find((arg) => arg instanceof Error);
      if (!error || inside) return;
      inside = true;
      try {
        captureException(error, { kind: "logged" });
      } finally {
        inside = false;
      }
    };
    console.error = wrapped;
    restoreConsole = () => {
      if (console.error === wrapped) console.error = original;
    };
  }

  return {
    captureException,
    errorHandler,
    flush,
    // A step of your own in the current request or job's trail.
    addBreadcrumb: (text) => addCrumb(requests.getStore(), { type: "note", text }),
    // Runs `next` (the rest of the request) with req as the current request.
    bind: (req, next) => requests.run(req, next),
    // Names routes as Server speed does: (req, status) -> route.
    useRoutes(fn) {
      routeOf = typeof fn === "function" ? fn : null;
    },
    // Runs a background job with its name as the route of the errors it
    // captures; an error it throws is sent (status 500) and thrown on.
    async job(route, fn) {
      const context = { [JOB]: route };
      return requests.run(context, async () => {
        try {
          return await fn();
        } catch (error) {
          captureException(error, { req: context, status: 500, kind: "error" });
          throw error;
        }
      });
    },
    // Sends what's waiting in the file now (resolves when done).
    resend: () => resend() || Promise.resolve(),
    // Everything not yet sent, to the file, now (the platform's close()
    // calls it once its deadline has passed).
    persist,
    close() {
      process.off("uncaughtException", onUncaught);
      handlers.delete(onUncaught);
      if (resendTimer) clearInterval(resendTimer);
      restoreConsole();
      return flush();
    },
  };
}

module.exports = { createErrors };
