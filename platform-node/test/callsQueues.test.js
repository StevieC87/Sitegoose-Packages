// Outgoing calls (sdk/protocols/calls.md), ClickHouse queries and job queues
// (queues.md): calls timed from Node's own diagnostics channels against a
// real local server, filed under their request by host only; a
// @clickhouse/client-shaped client timed until its result is read; and
// BullMQ/Bull-shaped queues read once a minute, credentials never sent.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const { EventEmitter } = require("node:events");
const { createQueries, hostOfUrl } = require("../lib/queries.js");
const { createQueues, brokerOf } = require("../lib/queues.js");
const { createPlatform } = require("../index.js");

function setUp({ on = true, endpoint = "", ...options } = {}) {
  const sent = [];
  const core = {
    valid: false, siteId: "a".repeat(24), endpoint, isOn: (name) => name === "performance" && on, log: () => {},
    send: async (module, url, opts) => { sent.push({ module, url, ...opts }); return null; },
  };
  const queries = createQueries(core, { serverName: "web-1", ...options });
  const rows = async (url) => {
    await queries.flush();
    return sent.splice(0).filter((call) => !url || call.url === url).flatMap((call) => call.body.rows);
  };
  return { core, queries, sent, rows };
}

// A local server answering each path with the status in it: /200, /404, /503.
async function server() {
  const srv = http.createServer((req, res) => {
    const status = Number(req.url.slice(1).split("/")[0]) || 200;
    setTimeout(() => res.writeHead(status).end("ok"), 5);
  });
  await new Promise((resolve) => srv.listen(0, "127.0.0.1", resolve));
  return { srv, base: `http://127.0.0.1:${srv.address().port}` };
}

const get = (url) => new Promise((resolve, reject) => {
  http.get(url, (res) => {
    res.resume();
    res.on("end", resolve);
  }).on("error", reject);
});

// ---- Calls ----

test("a request's fetch and http calls are filed under its route, by host only", async (t) => {
  const { srv, base } = await server();
  t.after(() => srv.close());
  const { queries, rows } = setUp();
  t.after(() => queries.close());
  const req = {};
  await queries.bind(req, async () => {
    await (await fetch(`${base}/200/v1/customers/cus_123?key=secret`, { method: "POST" })).text();
    await (await fetch(`${base}/503`)).text();
    await (await fetch(`${base}/404`)).text();
    await get(`${base}/200/other`);
  });
  queries.finish(req, "POST", "/checkout");
  const sent = await rows("/events/server-calls");
  const host = `127.0.0.1:${srv.address().port}`;
  const byMethod = Object.fromEntries(sent.map((row) => [row.call_method, row]));
  assert.deepEqual(Object.keys(byMethod).sort(), ["GET", "POST"]);
  assert.equal(byMethod.POST.host, host);
  assert.equal(byMethod.POST.route, "/checkout");
  assert.equal(byMethod.POST.method, "POST");
  assert.equal(byMethod.POST.count, 1);
  assert.equal(byMethod.GET.count, 3);
  // The 503 failed; the 404 is the other side's answer.
  assert.equal(byMethod.GET.errors, 1);
  assert.ok(byMethod.GET.sum_ms > 0);
  assert.ok(!JSON.stringify(sent).includes("cus_123"));
  assert.ok(!JSON.stringify(sent).includes("secret"));
});

test("a call nobody answered is a failure; one outside a request is (background)", async (t) => {
  const { queries, rows } = setUp();
  t.after(() => queries.close());
  // A port nothing listens on any more (fetch refuses a "bad port" like 1 outright).
  const { srv, base } = await server();
  await new Promise((resolve) => srv.close(resolve));
  await fetch(`${base}/nothing`).catch(() => {});
  const [row] = await rows("/events/server-calls");
  assert.equal(row.route, "(background)");
  assert.equal(row.method, "JOB");
  assert.equal(row.errors, 1);
});

test("the package's own calls to the collector aren't counted, and calls: false or Server speed off counts none", async (t) => {
  const { srv, base } = await server();
  t.after(() => srv.close());
  const own = setUp({ endpoint: base });
  t.after(() => own.queries.close());
  await (await fetch(`${base}/200/events/server-queries`)).text();
  assert.deepEqual(await own.rows("/events/server-calls"), []);
  own.queries.close();
  const off = setUp({ calls: false });
  t.after(() => off.queries.close());
  await (await fetch(`${base}/200`)).text();
  assert.deepEqual(await off.rows("/events/server-calls"), []);
  off.queries.close();
  const dark = setUp({ on: false });
  t.after(() => dark.queries.close());
  await (await fetch(`${base}/200`)).text();
  assert.deepEqual(await dark.rows(), []);
});

test("a call's host keeps its port only when it isn't the scheme's own", () => {
  assert.equal(hostOfUrl("https://API.Stripe.com/v1/charges"), "api.stripe.com");
  assert.equal(hostOfUrl("https://api.stripe.com:443/v1"), "api.stripe.com");
  assert.equal(hostOfUrl("http://localhost:8080/x"), "localhost:8080");
  assert.equal(hostOfUrl("http://[::1]:3000/"), "[::1]:3000");
  assert.equal(hostOfUrl("https://user:pass@example.com/"), "example.com");
  assert.equal(hostOfUrl("not a url"), "");
});

test("end to end: an Express-style request's calls arrive at /events/server-calls with the bearer secret", async (t) => {
  const { srv, base } = await server();
  t.after(() => srv.close());
  const posts = [];
  const collector = http.createServer((req, res) => {
    let body = "";
    req.on("data", (chunk) => { body += chunk; });
    req.on("end", () => {
      posts.push({ url: req.url, auth: req.headers.authorization, body: body ? JSON.parse(body) : null });
      res.writeHead(req.url.startsWith("/events/platform/config") ? 200 : 202, { "content-type": "application/json" }).end("{}");
    });
  });
  await new Promise((resolve) => collector.listen(0, "127.0.0.1", resolve));
  t.after(() => collector.close());
  const endpoint = `http://127.0.0.1:${collector.address().port}`;
  const platform = createPlatform({ siteId: "b".repeat(24), secret: "s3cret", endpoint, firewall: false, errors: false,
    crawlers: false, analytics: false, forms: false, headers: false, audit: false, flags: false, maintenance: false,
    inventory: false, posture: false, resources: false, proxy: false });
  await platform.ready;
  const app = http.createServer((req, res) => platform.middleware()(req, res, async () => {
    await (await fetch(`${base}/200/pay`)).text();
    res.end("done");
  }));
  await new Promise((resolve) => app.listen(0, "127.0.0.1", resolve));
  t.after(() => app.close());
  await get(`http://127.0.0.1:${app.address().port}/checkout`);
  await platform.flush();
  await platform.close();
  const calls = posts.find((post) => post.url === "/events/server-calls");
  assert.ok(calls, "calls were sent");
  assert.equal(calls.auth, "Bearer s3cret");
  const [row] = calls.body.rows;
  assert.equal(row.route, "/checkout");
  assert.equal(row.host, `127.0.0.1:${srv.address().port}`);
  // The package's own posts to the collector are not among them.
  assert.ok(!calls.body.rows.some((r) => r.host === `127.0.0.1:${collector.address().port}`));
});

// ---- ClickHouse ----

// @clickhouse/client's shape: query() answers a result set to read;
// insert(), command() and exec() answer when done.
function fakeClickHouse({ fail = false } = {}) {
  const calls = [];
  const later = (value) => new Promise((resolve, reject) => setTimeout(() => (fail ? reject(new Error("Code: 60")) : resolve(value)), 2));
  const client = {
    async query(params) {
      calls.push(params);
      await later();
      let closed = false;
      return { json: () => later([{ n: 1 }]), text: () => later("1"), close: () => { closed = true; return closed; } };
    },
    insert: (params) => (calls.push(params), later({ executed: true })),
    command: (params) => (calls.push(params), later({ query_id: "1" })),
    exec: (params) => (calls.push(params), later({ stream: null })),
    ping: async () => ({ success: true }),
    close: async () => {},
  };
  return { client, calls };
}

test("ClickHouse: queries are timed until their result is read, inserts and commands until they answer", async () => {
  const { queries, rows } = setUp();
  const { client, calls } = fakeClickHouse();
  const same = queries.watchDatabase(client);
  assert.equal(same, client);
  const req = {};
  await queries.bind(req, async () => {
    const result = await client.query({ query: "SELECT count() FROM events WHERE site_id = {site:String} AND day = '2026-11-04'", format: "JSONEachRow" });
    assert.deepEqual(await result.json(), [{ n: 1 }]);
    await client.insert({ table: "events", values: [{ secret: "x" }], format: "JSONEachRow" });
    await client.command({ query: "OPTIMIZE TABLE events" });
    // Read never: not counted.
    await client.query({ query: "SELECT 2" });
  });
  queries.finish(req, "GET", "/report");
  const sent = await rows("/events/server-queries");
  assert.deepEqual(sent.map((row) => [row.db, row.statement]).sort(), [
    ["clickhouse", "INSERT INTO events FORMAT JSONEachRow"],
    ["clickhouse", "OPTIMIZE TABLE events"],
    ["clickhouse", "SELECT count() FROM events WHERE site_id = {site:String} AND day = ?"],
  ]);
  assert.ok(sent.every((row) => row.route === "/report"));
  assert.ok(!JSON.stringify(sent).includes("secret"));
  assert.equal(calls.length, 4);
  queries.close();
});

test("ClickHouse: a failed query counts as failed and still throws; watching twice counts once", async () => {
  const { queries, rows } = setUp();
  const { client } = fakeClickHouse({ fail: true });
  queries.watchDatabase(client);
  queries.watchDatabase(client);
  await assert.rejects(client.command({ query: "DROP TABLE x" }), /Code: 60/);
  const [row] = await rows("/events/server-queries");
  assert.equal(row.count, 1);
  assert.equal(row.errors, 1);
  queries.close();
});

test("ClickHouse: the client's own HTTP requests are its queries, not outgoing calls", async (t) => {
  const { srv, base } = await server();
  t.after(() => srv.close());
  const { queries, rows } = setUp();
  t.after(() => queries.close());
  // As @clickhouse/client sends every query: over http.request.
  const client = {
    async query(params) {
      await get(`${base}/200/?query=${encodeURIComponent(params.query)}`);
      return { json: async () => [{ n: 1 }], text: async () => "1", close: () => {} };
    },
    insert: async () => get(`${base}/200/insert`),
    command: async () => get(`${base}/200/command`),
    exec: async () => get(`${base}/200/exec`),
    ping: async () => ({ success: true }),
  };
  queries.watchDatabase(client);
  const req = {};
  await queries.bind(req, async () => {
    await (await client.query({ query: "SELECT 1" })).json();
    // The app's own call, after the query, is still one.
    await (await fetch(`${base}/200/api`)).text();
  });
  queries.finish(req, "GET", "/r");
  const sent = await rows();
  assert.deepEqual(sent.filter((row) => row.db).map((row) => row.statement), ["SELECT ?"]);
  assert.deepEqual(sent.filter((row) => row.host).map((row) => [row.route, row.count]), [["/r", 1]]);
});

test("the collector's address written with capitals or its default port is still its own", async (t) => {
  const { srv } = await server();
  t.after(() => srv.close());
  const own = setUp({ endpoint: `http://LOCALHOST:${srv.address().port}` });
  t.after(() => own.queries.close());
  await (await fetch(`http://localhost:${srv.address().port}/200/events/server-queries`)).text();
  assert.deepEqual(await own.rows("/events/server-calls"), []);
});

// ---- Queues ----

// BullMQ's shapes: a Queue (add, getJobCounts, getJobs, its "waiting" event)
// and a Worker (getNextJob, "completed"/"failed" events).
function fakeQueue({ name = "emails", counts = { waiting: 5, prioritized: 1, active: 2, delayed: 3, failed: 4, completed: 9 }, oldestAgo = 90000, connection = { host: "cache", port: 6380, db: 2, password: "hunter2", username: "app" } } = {}) {
  const queue = new EventEmitter();
  Object.assign(queue, {
    name, opts: { connection, prefix: "bull" },
    add: async () => ({}),
    addBulk: async (jobs) => jobs.map(() => ({})),
    getJobCounts: async () => counts,
    getJobs: async () => [{ timestamp: Date.now() - oldestAgo, data: { secret: "x" } }],
  });
  return queue;
}
function fakeWorker({ name = "emails", connection = { host: "cache", port: 6380, db: 2 } } = {}) {
  const worker = new EventEmitter();
  Object.assign(worker, { name, opts: { connection }, getNextJob: async () => null, run: async () => {}, close: async () => {} });
  return worker;
}

function setUpQueues({ on = true } = {}) {
  const sent = [];
  const core = {
    valid: false, siteId: "a".repeat(24), isOn: (name) => name === "performance" && on, log: () => {},
    send: async (module, url, opts) => { sent.push({ url, ...opts }); return null; },
  };
  return { queues: createQueues(core, { serverName: "worker-1", timer: false }), sent };
}

test("a BullMQ queue and worker make one row: the backlog, the oldest wait, and this process's adds and finishes", async () => {
  const { queues, sent } = setUpQueues();
  const queue = queues.watchQueue(fakeQueue());
  const worker = queues.watchQueue(fakeWorker());
  queue.emit("waiting", {});
  queue.emit("waiting", {});
  // BullMQ's addBulk sends no "waiting".
  await queue.addBulk([{ name: "a" }, { name: "b" }, { name: "c" }]);
  worker.emit("completed", {});
  // An attempt that will be retried isn't finished; the last one is.
  worker.emit("failed", { attemptsMade: 1 }, new Error("x"));
  worker.emit("failed", { attemptsMade: 3, finishedOn: Date.now() }, new Error("x"));
  worker.emit("completed", {});
  await queues.sample();
  assert.equal(sent.length, 1);
  assert.equal(sent[0].url, "/events/server-queues");
  assert.equal(sent[0].auth, "bearer");
  const [row] = sent[0].body.rows;
  assert.equal(row.system, "bullmq");
  assert.equal(row.broker, "cache:6380/2");
  assert.equal(row.queue, "emails");
  assert.equal(row.waiting, 6);
  assert.equal(row.running, 2);
  assert.equal(row.delayed, 3);
  assert.equal(row.failed, 4);
  assert.ok(row.oldest_s >= 89 && row.oldest_s <= 91);
  assert.equal(row.added, 5);
  assert.equal(row.finished, 3);
  assert.equal(row.shared, false);
  assert.ok(!JSON.stringify(sent).includes("hunter2"));
  assert.ok(!JSON.stringify(sent).includes("secret"));
  // The counters start again for the next minute.
  await queues.sample();
  assert.equal(sent[1].body.rows[0].added, 0);
});

test("a queue whose Redis fails gives no gauges, not zeros; a worker alone sends only what it finished", async () => {
  const { queues, sent } = setUpQueues();
  const broken = fakeQueue({ name: "broken" });
  broken.getJobCounts = async () => { throw new Error("ECONNREFUSED"); };
  queues.watchQueue(broken);
  queues.watchQueue(fakeWorker({ name: "only-worker" }));
  await queues.sample();
  const byQueue = Object.fromEntries(sent[0].body.rows.map((row) => [row.queue, row]));
  assert.equal(byQueue.broken.waiting, null);
  assert.equal(byQueue.broken.added, 0);
  assert.equal(byQueue["only-worker"].waiting, null);
  assert.equal(byQueue["only-worker"].added, null);
  assert.equal(byQueue["only-worker"].finished, 0);
});

test("an empty queue's oldest wait is 0; Bull is told from BullMQ; other objects are handed back", async () => {
  const { queues, sent } = setUpQueues();
  const bull = fakeQueue({ name: "bull-q", counts: { waiting: 0, active: 0, delayed: 0, failed: 0 } });
  bull.process = () => {};
  queues.watchQueue(bull);
  bull.emit("completed", {});
  const thing = { name: "nope" };
  assert.equal(queues.watchQueue(thing), thing);
  await queues.sample();
  const [row] = sent[0].body.rows;
  assert.equal(row.system, "bull");
  assert.equal(row.oldest_s, 0);
  assert.equal(row.finished, 1);
});

test("a paused queue's oldest wait is unknown, and a delayed job waits from when its delay ended", async () => {
  const { queues, sent } = setUpQueues();
  queues.watchQueue(fakeQueue({ name: "paused", counts: { waiting: 0, paused: 7, active: 0, delayed: 0, failed: 0 } }));
  const delayed = fakeQueue({ name: "was-delayed" });
  delayed.getJobs = async () => [{ timestamp: Date.now() - 600000, delay: 540000 }];
  queues.watchQueue(delayed);
  await queues.sample();
  const byQueue = Object.fromEntries(sent[0].body.rows.map((row) => [row.queue, row]));
  assert.equal(byQueue.paused.waiting, 7);
  assert.equal(byQueue.paused.oldest_s, null);
  assert.ok(byQueue["was-delayed"].oldest_s >= 59 && byQueue["was-delayed"].oldest_s <= 61);
});

test("with Server speed off nothing is read or sent", async () => {
  const { queues, sent } = setUpQueues({ on: false });
  queues.watchQueue(fakeQueue());
  await queues.sample();
  assert.equal(sent.length, 0);
});

test("a broker names host, port and database, never credentials", () => {
  assert.equal(brokerOf({ opts: { connection: { host: "redis.internal", port: 6379, password: "p", username: "u" } } }), "redis.internal:6379/0");
  assert.equal(brokerOf({ opts: { connection: { options: { host: "x", port: 7000, db: 3 } } } }), "x:7000/3");
  assert.equal(brokerOf({ opts: { connection: { path: "/var/run/redis/redis.sock", db: 1 } } }), "redis.sock/1");
  assert.equal(brokerOf({ opts: {} }), "localhost:6379/0");
});

test("the platform hands watchQueue's queue back, and queues: false leaves them out", () => {
  const platform = createPlatform({ siteId: "c".repeat(24), secret: "s", endpoint: "http://127.0.0.1:1", queues: false,
    firewall: false, inventory: false, posture: false, resources: false });
  const queue = fakeQueue();
  assert.equal(platform.watchQueue(queue), queue);
  assert.equal(queue.listenerCount("waiting"), 0);
  return platform.close();
});
