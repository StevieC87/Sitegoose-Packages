// The errors module: an error is sent once however many handlers see it,
// errors logged with console.error are sent when asked, a request's route
// follows errors captured without it, and a failed batch is tried once more.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { createErrors } = require("../lib/errors.js");

function fakeCore(answers = []) {
  const sent = [];
  return {
    sent,
    isOn: () => true,
    log: () => {},
    async send(module, path, { body }) {
      sent.push(body.errors);
      const status = answers.length ? answers.shift() : 202;
      return status === null ? null : { status, headers: { get: (name) => (name === "retry-after" ? "0.01" : null) } };
    },
  };
}

test("one error seen by the error handler and by captureException is sent once", async () => {
  const core = fakeCore();
  const errors = createErrors(core, { captureUncaught: false });
  const error = new Error("payment failed");
  errors.errorHandler()(error, { method: "POST", url: "/pay" }, {}, () => {});
  errors.captureException(error);
  errors.captureException(new Error("payment failed"));
  await errors.close();
  assert.equal(core.sent.flat().length, 2, "the same object once, a second error with the same message again");
});

test("captureConsole sends the Error passed to console.error, and only when on", async () => {
  const core = fakeCore();
  const printed = [];
  const original = console.error;
  console.error = (...args) => printed.push(args);
  try {
    const off = createErrors(core, { captureUncaught: false });
    console.error("not sent", new Error("off"));
    await off.close();
    assert.equal(core.sent.length, 0);

    const on = createErrors(core, { captureUncaught: false, captureConsole: true });
    console.error("charge failed:", new Error("card declined"));
    console.error("plain text is not sent");
    await on.close();
    assert.notEqual(console.error.name, "analyticsConsoleError", "close() puts console.error back");
    const events = core.sent.flat();
    assert.equal(events.length, 1);
    assert.equal(events[0].message, "card declined");
    assert.equal(events[0].kind, "logged");
    assert.equal(printed.length, 3, "everything is still printed");
  } finally {
    console.error = original;
  }
});

test("an error captured inside bind() gets that request's route", async () => {
  const core = fakeCore();
  const errors = createErrors(core, { captureUncaught: false });
  const req = { method: "POST", originalUrl: "/orders/12?x=1", baseUrl: "/orders", route: { path: "/:id" } };
  await errors.bind(req, async () => {
    await new Promise((resolve) => setImmediate(resolve));
    errors.captureException(new Error("deep inside"));
  });
  errors.captureException(new Error("outside"));
  await errors.close();
  const [inside, outside] = core.sent.flat();
  assert.equal(inside.route, "/orders/:id");
  assert.equal(inside.path, "/orders/12");
  assert.equal(inside.method, "POST");
  assert.equal(outside.route, undefined);
});

test("a Fastify request passed in (a NestJS filter on Fastify) stands for its raw request", async () => {
  const core = fakeCore();
  const errors = createErrors(core, { captureUncaught: false });
  const raw = { method: "GET", url: "/users/boom", headers: {}, route: { path: "/users/:id" } };
  await errors.bind(raw, async () => {
    errors.addBreadcrumb("looked the user up");
    errors.captureException(new Error("boom"), { req: { raw, url: "/users/boom", headers: {} }, status: 500 });
  });
  await errors.close();
  const [event] = core.sent.flat();
  assert.equal(event.route, "/users/:id");
  assert.deepEqual(event.breadcrumbs.map((crumb) => crumb.text), ["looked the user up"]);
});

test("a batch the collector couldn't take is sent once more, and only once", async () => {
  const core = fakeCore([503, 503]);
  const errors = createErrors(core, { captureUncaught: false });
  errors.captureException(new Error("a"));
  await errors.flush();
  assert.equal(core.sent.length, 2);

  const unreachable = fakeCore([null, 202]);
  const second = createErrors(unreachable, { captureUncaught: false });
  second.captureException(new Error("b"));
  await second.flush();
  assert.equal(unreachable.sent.length, 2);

  const rejected = fakeCore([400]);
  const third = createErrors(rejected, { captureUncaught: false });
  third.captureException(new Error("c"));
  await third.flush();
  assert.equal(rejected.sent.length, 1, "a 4xx is not tried again");
});

test("an error logged and then thrown on keeps the error handler's status, kind and request", async () => {
  const core = fakeCore();
  const printed = console.error;
  console.error = () => {};
  try {
    const errors = createErrors(core, { captureUncaught: false, captureConsole: true });
    const error = new Error("charge failed");
    console.error(error);
    errors.errorHandler()(error, { method: "POST", originalUrl: "/pay", baseUrl: "", route: { path: "/pay" } }, {}, () => {});
    await errors.close();
    const events = core.sent.flat();
    assert.equal(events.length, 1);
    assert.equal(events[0].kind, "handled");
    assert.equal(events[0].status_code, 500);
    assert.equal(events[0].route, "/pay");
  } finally {
    console.error = printed;
  }
});

test("without a matched route, an error is named as Server speed names the request", async () => {
  const core = fakeCore();
  const errors = createErrors(core, { captureUncaught: false });
  errors.captureException(new Error("in middleware"), { req: { method: "GET", url: "/orders/123/items" }, status: 500 });
  errors.useRoutes((req) => `custom:${req.url}`);
  errors.captureException(new Error("named by the custom route option"), { req: { method: "GET", url: "/x" }, status: 500 });
  await errors.close();
  const [plain, custom] = core.sent.flat();
  assert.equal(plain.route, "/orders/:id/items");
  assert.equal(custom.route, "custom:/x");
});

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

function spoolCore(answers) {
  return Object.assign(fakeCore(answers), { valid: true, siteId: "a1b2c3d4e5f6a1b2c3d4e5f6", secret: "s" });
}

test("errors the collector couldn't take wait in a file, without credentials, and are sent later", async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "errors-spool-"));
  try {
    const core = spoolCore([503, 503]);
    const errors = createErrors(core, { captureUncaught: false, spoolDir: dir });
    errors.captureException(new Error("collector away"));
    await errors.flush();
    const [file] = fs.readdirSync(dir);
    assert.ok(file, "kept in a file");
    const kept = fs.readFileSync(path.join(dir, file), "utf8");
    assert.match(kept, /collector away/);
    assert.doesNotMatch(kept, /a1b2c3d4e5f6a1b2c3d4e5f6/, "the file is named and filled without the site's id");
    assert.match(JSON.parse(kept.trim()).at, /^\d{4}-\d\d-\d\dT/, "with when it happened");

    core.sent.length = 0;
    await errors.resend();
    assert.equal(core.sent.flat()[0].message, "collector away");
    assert.deepEqual(fs.readdirSync(dir), [], "and gone once sent");
    await errors.close();
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("job() names its errors after the job, sends the one it throws and throws it on", async () => {
  const core = fakeCore();
  const errors = createErrors(core, { captureUncaught: false });
  await assert.rejects(errors.job("/(job) receipts", async () => {
    errors.captureException(new Error("one receipt failed"));
    throw new Error("the job failed");
  }), /the job failed/);
  await errors.close();
  const [inside, thrown] = core.sent.flat();
  assert.equal(inside.route, "/(job) receipts");
  assert.equal(inside.method, "JOB");
  assert.equal(thrown.status_code, 500);
});

test("a crash while the collector is away is kept for the next start", () => {
  const { spawnSync } = require("node:child_process");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "errors-crash-"));
  try {
    const script = `
      const { createPlatform } = require(${JSON.stringify(path.join(__dirname, "..", "index.js"))});
      createPlatform({ siteId: "a1b2c3d4e5f6a1b2c3d4e5f6", secret: "s", endpoint: "http://127.0.0.1:9",
        firewall: false, performance: false, crawlers: false, analytics: false, flags: false, maintenance: false,
        inventory: false, posture: false, resources: false, proxy: false, audit: false, forms: false, headers: false,
        errors: { spoolDir: ${JSON.stringify(dir)} } });
      setTimeout(() => { throw new Error("worker crashed"); }, 10);`;
    const run = spawnSync(process.execPath, ["-e", script], { encoding: "utf8", timeout: 15000 });
    assert.equal(run.status, 1, "it still exits as Node would");
    const files = fs.readdirSync(dir);
    assert.equal(files.length, 1);
    assert.match(fs.readFileSync(path.join(dir, files[0]), "utf8"), /worker crashed/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("an app's own req.job is not taken for a background job", async () => {
  const core = fakeCore();
  const errors = createErrors(core, { captureUncaught: false });
  errors.captureException(new Error("x"), { req: { method: "POST", url: "/jobs/5", job: { id: 5 } }, status: 500 });
  await errors.close();
  const [event] = core.sent.flat();
  assert.equal(event.method, "POST");
  assert.equal(event.route, "/jobs/:id");
});

test("a script that ends while a batch waits to be tried again still sends it", () => {
  const { spawnSync } = require("node:child_process");
  const script = `
    const { createErrors } = require(${JSON.stringify(path.join(__dirname, "..", "lib", "errors.js"))});
    const answers = [503, 202];
    const core = { isOn: () => true, log: () => {}, valid: false,
      async send() { const status = answers.shift(); console.log("sent", status); return { status, headers: { get: () => "1" } }; } };
    const errors = createErrors(core, { captureUncaught: false });
    errors.captureException(new Error("from a cron script"));
    errors.flush();`;
  const run = spawnSync(process.execPath, ["-e", script], { encoding: "utf8", timeout: 15000 });
  assert.equal(run.stdout.trim(), "sent 503\nsent 202");
});

test("an error carries its own request's outgoing calls and steps, not its neighbour's", async () => {
  const http = require("node:http");
  const server = http.createServer((req, res) => {
    res.statusCode = req.url.startsWith("/bad") ? 502 : 200;
    setTimeout(() => res.end("ok"), 5);
  });
  await new Promise((resolve) => server.listen(0, resolve));
  const { port } = server.address();
  const closed = http.createServer();
  await new Promise((resolve) => closed.listen(0, resolve));
  const deadPort = closed.address().port;
  await new Promise((resolve) => closed.close(resolve));
  const base = `http://127.0.0.1:${port}`;
  const get = (url) => new Promise((resolve, reject) => http.get(url, (res) => res.resume().on("end", resolve)).on("error", reject));

  const core = { ...fakeCore(), endpoint: `${base}/collector` };
  const errors = createErrors(core, { captureUncaught: false });
  const handle = (req, work) => errors.bind(req, work);
  const a = { method: "POST", url: "/a" };
  const b = { method: "GET", url: "/b" };
  try {
    await Promise.all([
      handle(a, async () => {
        await (await fetch(`${base}/ok?token=secret#frag`)).text();
        errors.addBreadcrumb("Order saved");
        await get(`${base}/bad?token=secret`);
        await fetch(`http://127.0.0.1:${deadPort}/gone`).catch(() => {});
        await get(`http://127.0.0.1:${deadPort}/gone-too`).catch(() => {});
        await fetch(`${base}/collector/events`).then((res) => res.text()); // the package's own traffic
        const cancel = new AbortController();
        const cancelled = fetch(`${base}/slow`, { signal: cancel.signal }).catch(() => {});
        cancel.abort();
        await cancelled;
        errors.captureException(new Error("from a"));
      }),
      handle(b, async () => {
        await (await fetch(`${base}/other`)).text();
        errors.captureException(new Error("from b"));
      }),
    ]);
    errors.captureException(new Error("outside a request"));
    await errors.close();
  } finally {
    server.closeAllConnections();
    server.close();
  }

  const sent = core.sent.flat();
  const of = (message) => sent.find((event) => event.message === message);
  const steps = of("from a").breadcrumbs.map(({ type, text, status }) => [type, text, status]);
  assert.deepEqual(steps, [
    ["request", `GET ${base}/ok`, 200],
    ["note", "Order saved", undefined],
    ["request", `GET ${base}/bad`, 502],
    ["request", `GET http://127.0.0.1:${deadPort}/gone`, 0],
    ["request", `GET http://127.0.0.1:${deadPort}/gone-too`, 0],
  ]);
  assert.ok(of("from a").breadcrumbs.every((crumb) => crumb.ms >= 0 && !("at" in crumb)));
  assert.deepEqual(of("from b").breadcrumbs.map((crumb) => crumb.text), [`GET ${base}/other`]);
  assert.ok(!("breadcrumbs" in of("outside a request")));
});

test("a server on the collector's host, on a port that starts with the collector's, is a step", async () => {
  const http = require("node:http");
  const server = http.createServer((req, res) => res.end("ok"));
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  // The collector on the port with one digit fewer: 127.0.0.1:4123 against 127.0.0.1:41234.
  const core = { ...fakeCore(), endpoint: `http://127.0.0.1:${String(port).slice(0, -1)}` };
  const errors = createErrors(core, { captureUncaught: false });
  try {
    await errors.bind({ method: "GET", url: "/x" }, async () => {
      await (await fetch(`http://127.0.0.1:${port}/neighbour`)).text();
      errors.captureException(new Error("next door"));
    });
    await errors.close();
  } finally {
    server.closeAllConnections();
    server.close();
  }
  assert.deepEqual(core.sent.flat()[0].breadcrumbs.map((crumb) => crumb.text), [`GET http://127.0.0.1:${port}/neighbour`]);
});

test("the trail keeps the last steps, and a job has one too", async () => {
  const core = fakeCore();
  const errors = createErrors(core, { captureUncaught: false });
  errors.addBreadcrumb("outside any request, kept nowhere");
  await errors.job("send-receipts", async () => {
    for (let i = 0; i < 20; i += 1) errors.addBreadcrumb(`step ${i}`);
    errors.captureException(new Error("in a job"));
  });
  await errors.close();
  const crumbs = core.sent.flat()[0].breadcrumbs;
  assert.equal(crumbs.length, 15);
  assert.equal(crumbs[0].text, "step 5");
  assert.equal(crumbs.at(-1).text, "step 19");
});

test("a crash inside a request keeps that request's trail", () => {
  const { spawnSync } = require("node:child_process");
  for (const crash of ["setTimeout(() => { throw new Error('boom'); }, 5)", "Promise.reject(new Error('boom'))"]) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "errors-trail-"));
    try {
      // The collector never answers, so the crash waits in the file.
      const script = `
        const { createErrors } = require(${JSON.stringify(path.join(__dirname, "..", "lib", "errors.js"))});
        const core = { isOn: () => true, log: () => {}, valid: true, siteId: "a1b2c3d4e5f6a1b2c3d4e5f6", secret: "s", send: () => new Promise(() => {}) };
        const errors = createErrors(core, { spoolDir: ${JSON.stringify(dir)} });
        errors.bind({ method: "POST", url: "/pay" }, () => {
          errors.addBreadcrumb("Order saved");
          ${crash};
        });`;
      const run = spawnSync(process.execPath, ["-e", script], { encoding: "utf8", timeout: 15000 });
      assert.equal(run.status, 1);
      const kept = fs.readdirSync(dir).map((file) => fs.readFileSync(path.join(dir, file), "utf8")).join("");
      assert.equal(JSON.parse(kept).breadcrumbs[0].text, "Order saved");
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }
});

test("errors being resent when the process crashes go back in the file", () => {
  const { spawnSync } = require("node:child_process");
  const crypto = require("node:crypto");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "errors-resend-"));
  try {
    const file = path.join(dir, `analytics-errors-${crypto.createHash("sha256").update("a1b2c3d4e5f6a1b2c3d4e5f6|s").digest("hex").slice(0, 16)}.jsonl`);
    fs.writeFileSync(file, Array.from({ length: 12 }, (_, i) => JSON.stringify({ message: `e${i}` })).join("\n") + "\n");
    // The first batch is taken; during the second the process crashes.
    const script = `
      const { createErrors } = require(${JSON.stringify(path.join(__dirname, "..", "lib", "errors.js"))});
      let calls = 0;
      const core = { isOn: () => true, log: () => {}, valid: true, siteId: "a1b2c3d4e5f6a1b2c3d4e5f6", secret: "s",
        send() {
          calls += 1;
          if (calls === 1) return Promise.resolve({ status: 202, headers: { get: () => null } });
          if (calls === 2) setTimeout(() => { throw new Error("crashed mid-resend"); }, 10);
          return new Promise(() => {});
        } };
      createErrors(core, { spoolDir: ${JSON.stringify(dir)} }).resend();`;
    const run = spawnSync(process.execPath, ["-e", script], { encoding: "utf8", timeout: 15000 });
    assert.equal(run.status, 1);
    const kept = fs.readFileSync(file, "utf8");
    assert.match(kept, /"e10"/);
    assert.match(kept, /"e11"/);
    assert.match(kept, /crashed mid-resend/);
    assert.doesNotMatch(kept, /"e0"/, "what was sent is not kept again");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
