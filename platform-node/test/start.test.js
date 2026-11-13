// analytics-platform/start: the platform from the environment or .env, and
// the middleware and error handler placed in an Express app by themselves.
// Express isn't a dependency of the package: these use the one in
// EXPRESS_PATH, else one this folder or the backend next to it resolves, and
// skip without one. Run them on Express 4 and 5.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { spawn } = require("node:child_process");
const { createExpressPlacer } = require("../lib/auto.js");
const { createPlatform } = require("../index.js");

function findExpress() {
  const places = [process.env.EXPRESS_PATH, __dirname, path.join(__dirname, "../../../backend")].filter(Boolean);
  for (const place of places) {
    try {
      return require.resolve("express", { paths: [place] });
    } catch {}
  }
  return null;
}
const EXPRESS = findExpress();
const skip = EXPRESS ? false : "Express isn't installed here";

// A stand-in platform: what its two handlers saw.
function fakePlatform() {
  const seen = { requests: [], errors: [] };
  return {
    seen,
    middleware: () => function platformMiddleware(req, res, next) {
      seen.requests.push({ path: req.url, ip: req.ip });
      req.platformSaw = true;
      next();
    },
    errorHandler: () => function analyticsErrorHandler(error, req, res, next) {
      seen.errors.push(error.message);
      next(error);
    },
  };
}

async function listen(app) {
  const server = http.createServer(app);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { server, url: `http://127.0.0.1:${server.address().port}` };
}

test("Express: first before the routes, the error handler before yours, routes added after listen() included", { skip }, async (t) => {
  const express = require(EXPRESS);
  const platform = fakePlatform();
  const app = express();
  app.set("trust proxy", 1);
  app.use(express.json());
  app.get("/ok", (req, res) => res.send(req.platformSaw ? "seen" : "not seen"));
  app.get("/boom", () => {
    throw new Error("boom");
  });

  const server = http.createServer(app);
  t.after(() => server.close());
  createExpressPlacer(platform)(server, app);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const url = `http://127.0.0.1:${server.address().port}`;
  // An async setup: more routes and your own error handler after listen().
  app.get("/late", () => {
    throw new Error("late");
  });
  app.use((error, req, res, next) => res.status(500).send(`mine: ${error.message}`));

  assert.equal(await fetch(`${url}/ok`, { headers: { "x-forwarded-for": "203.0.113.9" } }).then((r) => r.text()), "seen");
  assert.equal(platform.seen.requests[0].ip, "203.0.113.9", "after Express's own setup, so req.ip follows trust proxy");
  assert.equal(await fetch(`${url}/boom`).then((r) => r.text()), "mine: boom", "your error handler still answers");
  assert.equal(await fetch(`${url}/late`).then((r) => r.text()), "mine: late");
  assert.deepEqual(platform.seen.errors, ["boom", "late"]);
});

test("Express: an app with the two lines by hand gets nothing added", { skip }, async (t) => {
  const express = require(EXPRESS);
  const platform = fakePlatform();
  const byHand = fakePlatform();
  const app = express();
  app.use(byHand.middleware());
  app.get("/boom", () => {
    throw new Error("boom");
  });
  app.use(byHand.errorHandler());
  const { server, url } = await listen(app);
  t.after(() => server.close());
  createExpressPlacer(platform)(server, app);
  await fetch(`${url}/boom`).then((r) => r.text());
  assert.equal(platform.seen.requests.length, 0);
  assert.deepEqual(platform.seen.errors, []);
  assert.deepEqual(byHand.seen.errors, ["boom"]);
});

test("Express: no error handler of your own, Express's answers after it", { skip }, async (t) => {
  const express = require(EXPRESS);
  const platform = fakePlatform();
  const app = express();
  app.get("/boom", () => {
    throw new Error("boom");
  });
  const server = http.createServer(app);
  t.after(() => server.close());
  app.set("env", "test"); // Express's own handler prints nothing
  createExpressPlacer(platform)(server, app);
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const res = await fetch(`http://127.0.0.1:${server.address().port}/boom`);
  await res.text();
  assert.equal(res.status, 500);
  assert.deepEqual(platform.seen.errors, ["boom"]);
});

test("createPlatform() reads its keys from the environment", () => {
  const saved = { ...process.env };
  const warnings = [];
  const warn = console.warn;
  console.warn = (...args) => warnings.push(args.join(" "));
  const off = Object.fromEntries(["firewall", "errors", "analytics", "performance", "crawlers", "forms", "headers", "audit", "flags",
    "maintenance", "inventory", "posture", "resources", "proxy"].map((name) => [name, false]));
  try {
    Object.assign(process.env, { ANALYTICS_SITE_ID: "d".repeat(24), ANALYTICS_SITE_SECRET: "s", ANALYTICS_ENDPOINT: "http://127.0.0.1:9" });
    createPlatform({ ...off, checkIn: false }).close();
    assert.equal(warnings.length, 0);
    delete process.env.ANALYTICS_SITE_SECRET;
    createPlatform({ ...off, checkIn: false }).close();
    assert.match(warnings[0], /ANALYTICS_SITE_SECRET/);
  } finally {
    console.warn = warn;
    for (const key of Object.keys(process.env)) if (!(key in saved)) delete process.env[key];
    Object.assign(process.env, saved);
  }
});

// The whole thing as a customer runs it: keys in .env, one import, an Express
// app, a route that throws, then a deploy's SIGTERM.
test("start: from .env, an Express error reaches the collector, and SIGTERM sends it and exits", { skip }, async () => {
  const received = [];
  const collector = http.createServer((req, res) => {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => {
      if (req.url === "/events/server-errors") received.push({ auth: req.headers.authorization, body });
      res.statusCode = req.url === "/events/server-errors" ? 202 : 404;
      res.end();
    });
  });
  await new Promise((resolve) => collector.listen(0, "127.0.0.1", resolve));
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "analytics-start-"));
  fs.writeFileSync(path.join(dir, ".env"), [
    "DATABASE_URL=left-alone",
    `ANALYTICS_SITE_ID="${"e".repeat(24)}"`,
    "ANALYTICS_SITE_SECRET=from-dotenv # a comment",
    `export ANALYTICS_ENDPOINT=http://127.0.0.1:${collector.address().port}`,
  ].join("\n"));
  fs.writeFileSync(path.join(dir, "app.js"), `
    const platform = require(${JSON.stringify(path.join(__dirname, "../start.js"))});
    const express = require(${JSON.stringify(EXPRESS)});
    const app = express();
    app.get("/boom", () => { throw new Error("boom from start"); });
    const server = app.listen(0, "127.0.0.1", () => {
      console.log(JSON.stringify({ port: server.address().port, dotenvLeft: process.env.DATABASE_URL === undefined, envUntouched: process.env.ANALYTICS_SITE_SECRET === undefined, same: platform === require(${JSON.stringify(path.join(__dirname, "../start.js"))}) }));
    });
  `);
  const child = spawn(process.execPath, ["app.js"], { cwd: dir, env: { PATH: process.env.PATH }, stdio: ["ignore", "pipe", "pipe"] });
  let stderr = "";
  child.stderr.on("data", (chunk) => (stderr += chunk));
  const first = await new Promise((resolve, reject) => {
    child.stdout.once("data", (chunk) => resolve(JSON.parse(String(chunk))));
    child.once("exit", () => reject(new Error(`exited early: ${stderr}`)));
  });
  assert.equal(first.dotenvLeft, true, "only ANALYTICS_* lines are read from .env");
  assert.equal(first.envUntouched, true, "and they're never written into process.env");
  assert.equal(first.same, true);
  const res = await fetch(`http://127.0.0.1:${first.port}/boom`);
  await res.text();
  assert.equal(res.status, 500);
  const exited = new Promise((resolve) => child.once("exit", (code, signal) => resolve({ code, signal })));
  child.kill("SIGTERM");
  const { signal } = await exited;
  collector.close();
  fs.rmSync(dir, { recursive: true, force: true });
  assert.equal(signal, "SIGTERM", "exits as Node would on SIGTERM");
  assert.doesNotMatch(stderr, /are required/);
  assert.equal(received.length, 1, `the error was sent before exiting: ${stderr}`);
  const sent = JSON.parse(received[0].body);
  assert.equal(sent.site_id, "e".repeat(24));
  assert.equal(sent.sitesecret, "from-dotenv", "quotes and a trailing comment are taken off");
  assert.match(received[0].body, /boom from start/);
});
