// Database query timings (sdk/protocols/queries.md): the shared normalizing
// cases, filing each query under its request, the caps, what is sent, and
// each library's hook against a stand-in with that library's shape (the
// package has no dependencies).
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const http = require("node:http");
const { EventEmitter } = require("node:events");
const { normalizeStatement } = require("../lib/queryText.js");
const { createQueries, mongoText, MAX_PER_REQUEST, MAX_KEYS, HARD_MAX_KEYS } = require("../lib/queries.js");
const { createPlatform } = require("../index.js");

const cases = JSON.parse(fs.readFileSync(path.join(__dirname, "../../protocols/query-cases.json"), "utf8"));

function setUp({ on = true } = {}) {
  const sent = [];
  const core = {
    valid: false, siteId: "a".repeat(24), isOn: (name) => name === "performance" && on, log: () => {},
    send: async (module, url, options) => { sent.push({ url, ...options }); return null; },
  };
  const queries = createQueries(core, { serverName: "web-1" });
  // The rows sent since the last call.
  const rows = async () => {
    await queries.flush();
    return sent.splice(0).flatMap((call) => call.body.rows);
  };
  return { queries, sent, rows };
}

const tick = () => new Promise((resolve) => setImmediate(resolve));

// ---- Stand-ins, shaped as each library's objects are ----

// pg: Pool.query takes a client with this.connect() synchronously and runs
// client.query on it; connect() also lends clients to the app.
function fakePg({ fail = false } = {}) {
  class Client {
    constructor() {
      this.connectionParameters = { host: "db" };
      this.ran = [];
    }
    query(text, values, callback) {
      if (typeof values === "function") [callback, values] = [values, undefined];
      this.ran.push(typeof text === "string" ? text : text.text);
      const answer = new Promise((resolve, reject) => setImmediate(() => (fail ? reject(new Error("boom")) : resolve({ rows: [] }))));
      if (callback) return void answer.then((res) => callback(null, res), (error) => callback(error));
      return answer;
    }
  }
  class Pool extends EventEmitter {
    constructor() {
      super();
      this.client = new Client();
    }
    get totalCount() { return 1; }
    get idleCount() { return 1; }
    connect(callback) {
      if (callback) return void setImmediate(() => callback(null, this.client, () => {}));
      return Promise.resolve(this.client);
    }
    query(text, values) {
      return new Promise((resolve, reject) => {
        this.connect((error, client) => client.query(text, values).then(resolve, reject));
      });
    }
  }
  return { Pool, Client };
}

// mysql2: a core pool (callbacks; query() returns a command object whose
// then() throws) and the promise pool around it.
function fakeMysql() {
  class Query extends EventEmitter {
    then() {
      throw new Error("You have tried to call .then() on a query that is not a promise");
    }
  }
  class Connection extends EventEmitter {
    constructor() {
      super();
      this.config = {};
    }
    query(sql, values, callback) {
      if (typeof values === "function") [callback, values] = [values, undefined];
      const command = new Query();
      setImmediate(() => {
        callback?.(null, []);
        command.emit("end");
      });
      return command;
    }
    execute(sql, values, callback) {
      setImmediate(() => callback?.(null, []));
    }
  }
  class Pool extends EventEmitter {
    constructor() {
      super();
      this.connection = new Connection();
    }
    getConnection(callback) {
      setImmediate(() => callback(null, this.connection));
    }
    query(sql, values, callback) {
      const command = new Query();
      this.getConnection((error, connection) => connection.query(sql, values, callback).once("end", () => command.emit("end")));
      return command;
    }
    execute(sql, values, callback) {
      this.getConnection((error, connection) => connection.execute(sql, values, callback));
    }
    promise() {
      const core = this;
      return {
        pool: core,
        getConnection: () => new Promise((resolve) => core.getConnection((error, c) => resolve({ connection: c, query: (sql, v) => new Promise((ok) => c.query(sql, v, (e, r) => ok([r]))), execute: (sql, v) => new Promise((ok) => c.execute(sql, v, (e, r) => ok([r]))) }))),
        query: (sql, v) => new Promise((ok, no) => core.query(sql, v, (e, r) => (e ? no(e) : ok([r])))),
        execute: (sql, v) => new Promise((ok, no) => core.execute(sql, v, (e, r) => (e ? no(e) : ok([r])))),
      };
    }
  }
  return { Pool, Connection };
}

// ---- Normalizing ----

test("every shared case normalizes character for character", () => {
  assert.ok(cases.cases.length > 20);
  for (const { statement, db, expected } of cases.cases) {
    assert.equal(normalizeStatement(statement, db), expected, `${db}: ${statement.slice(0, 80)}`);
  }
});

test("Mongo statements are command, collection and the filter the spec names", () => {
  assert.equal(normalizeStatement(mongoText("find", { find: "users", filter: { email: "a@b.c" }, limit: 1 }), "mongodb"), 'find users {"email":"?"}');
  assert.equal(normalizeStatement(mongoText("delete", { delete: "users", deletes: [{ q: { _id: 5 }, limit: 1 }] }), "mongodb"), 'delete users {"_id":"?"}');
  assert.equal(normalizeStatement(mongoText("insert", { insert: "users", documents: [{ secret: "x" }] }), "mongodb"), "insert users");
  assert.equal(normalizeStatement(mongoText("find", { find: "users", filter: { n: 10n } }), "mongodb"), "find users");
});

// ---- Filing ----

test("a request's queries are added up and filed under its method and route when it finishes", async () => {
  const { queries, rows } = setUp();
  const { recorder } = queries;
  const req = {};
  const run = (text, ms, failed = false) => {
    const timing = recorder.begin();
    recorder.end(timing, "postgresql", text, failed, ms);
  };
  queries.bind(req, () => {
    run("SELECT * FROM users WHERE id = 1", 3);
    run("SELECT * FROM users WHERE id = 2", 40);
    run("UPDATE users SET a = 'x'", 2, true);
  });
  assert.deepEqual(await rows(), [], "nothing is filed before the request finishes");
  queries.finish(req, "get", "/users/:id");
  // A query the request didn't wait for, after it finished: still its row.
  queries.bind(req, () => run("SELECT * FROM users WHERE id = 3", 1));
  // And one with no request around it.
  run("DELETE FROM sessions WHERE expires < 5", 7);
  const sent = await rows();
  const select = sent.filter((row) => row.statement === "SELECT * FROM users WHERE id = ?");
  assert.equal(select.length, 1);
  assert.deepEqual({ ...select[0], minute: undefined }, {
    minute: undefined, method: "GET", route: "/users/:id", db: "postgresql", statement: "SELECT * FROM users WHERE id = ?",
    count: 3, errors: 0, sum_ms: 44, max_ms: 40, buckets: [2, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0],
  });
  assert.deepEqual(sent.find((row) => row.statement.startsWith("UPDATE")), {
    ...sent.find((row) => row.statement.startsWith("UPDATE")), method: "GET", route: "/users/:id", count: 1, errors: 1,
  });
  const background = sent.find((row) => row.statement.startsWith("DELETE"));
  assert.equal(background.method, "JOB");
  assert.equal(background.route, "(background)");
  assert.match(sent[0].minute, /^\d{4}-\d\d-\d\dT\d\d:\d\d:00\.000Z$/);
});

test("a job's queries are filed under the job's route", async () => {
  const { queries, rows } = setUp();
  const holder = {};
  await queries.bind(holder, async () => {
    await tick();
    queries.recorder.end(queries.recorder.begin(), "mysql", "SELECT 1", false, 1);
  });
  queries.finish(holder, "JOB", "/(job) send-receipts");
  assert.deepEqual((await rows()).map(({ method, route, statement }) => ({ method, route, statement })),
    [{ method: "JOB", route: "/(job) send-receipts", statement: "SELECT ?" }]);
});

test("with Server speed off nothing is timed", async () => {
  const { queries, rows } = setUp({ on: false });
  assert.equal(queries.recorder.begin(), null);
  const pool = queries.watchDatabase(new (fakePg().Pool)());
  await pool.query("SELECT 1");
  assert.deepEqual(await rows(), []);
});

// ---- Caps ----

test("past 50 queries in a request new ones are (other); past 200 a minute (other); past 300 nothing", async () => {
  const { queries, rows } = setUp();
  const { recorder } = queries;
  const req = {};
  queries.bind(req, () => {
    for (let i = 0; i < 80; i++) recorder.end(recorder.begin(), "postgresql", `SELECT * FROM t${i}`, false, 1);
  });
  queries.finish(req, "GET", "/a");
  let sent = await rows();
  assert.equal(sent.length, MAX_PER_REQUEST + 1);
  assert.equal(sent.find((row) => row.statement === "(other)").count, 30);

  // (other) is per method, route and database: 100 routes fill the 200,
  // the next 100 get an (other) each, and the rest nothing.
  const fresh = setUp();
  for (let r = 0; r < 250; r++) {
    const one = {};
    fresh.queries.bind(one, () => {
      for (let i = 0; i < 2; i++) fresh.queries.recorder.end(fresh.queries.recorder.begin(), "postgresql", `SELECT * FROM t${i}`, false, 1);
    });
    fresh.queries.finish(one, "GET", `/route${r}`);
  }
  sent = await fresh.rows();
  assert.equal(sent.length, HARD_MAX_KEYS);
  assert.equal(sent.filter((row) => row.statement === "(other)").length, HARD_MAX_KEYS - MAX_KEYS);
  assert.equal(sent.find((row) => row.statement === "(other)").count, 2);
  assert.ok(!sent.some((row) => row.route === "/route200"));
});

// ---- What is sent ----

test("rows go to /events/server-queries with the site in the body and the secret as a bearer token", async () => {
  const { queries, sent } = setUp();
  for (let i = 0; i < 120; i++) {
    for (let r = 0; r < 5; r++) {
      const req = {};
      queries.bind(req, () => queries.recorder.end(queries.recorder.begin(), "postgresql", `SELECT 1.234 FROM t${i}`, false, 1.26));
      queries.finish(req, "POST", `/r${r}/${i}`);
    }
  }
  // 600 keys in one minute: the hard cap keeps 300, in one request.
  await queries.flush();
  assert.equal(sent.length, 1);
  assert.equal(sent[0].url, "/events/server-queries");
  assert.equal(sent[0].auth, "bearer");
  assert.equal(sent[0].body.site_id, "a".repeat(24));
  assert.equal(sent[0].body.server_name, "web-1");
  assert.match(sent[0].body.runtime, /^Node /);
  assert.equal(sent[0].body.rows[0].sum_ms, 1.3);
});

test("end to end: an Express-style request's queries arrive under its route, with the bearer secret", async () => {
  const received = [];
  const collector = http.createServer((req, res) => {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => {
      if (req.url === "/events/server-queries") received.push({ auth: req.headers.authorization, body: JSON.parse(body) });
      res.statusCode = req.url.startsWith("/events/platform/config") ? 404 : 202;
      res.end();
    });
  });
  await new Promise((resolve) => collector.listen(0, "127.0.0.1", resolve));
  const off = Object.fromEntries(["firewall", "errors", "analytics", "crawlers", "forms", "headers", "audit", "flags", "maintenance",
    "inventory", "posture", "resources", "proxy"].map((name) => [name, false]));
  const platform = createPlatform({ siteId: "b".repeat(24), secret: "s3cret", endpoint: `http://127.0.0.1:${collector.address().port}`, ...off });
  const pool = platform.watchDatabase(new (fakePg().Pool)());
  const middleware = platform.middleware();
  const app = http.createServer((req, res) => middleware(req, res, async () => {
    req.route = { path: "/orders/:id" };
    await pool.query("SELECT * FROM orders WHERE id = $1", [7]);
    await pool.query("SELECT * FROM orders WHERE id = $1", [8]);
    res.end("ok");
  }));
  await new Promise((resolve) => app.listen(0, "127.0.0.1", resolve));
  await fetch(`http://127.0.0.1:${app.address().port}/orders/7`).then((res) => res.text());
  await platform.job("nightly", () => pool.query("VACUUM"));
  await platform.close();
  app.close();
  collector.close();
  const rows = received.flatMap((call) => call.body.rows);
  assert.equal(received[0].auth, "Bearer s3cret");
  assert.equal(received[0].body.site_id, "b".repeat(24));
  assert.deepEqual(rows.map(({ method, route, statement, count }) => ({ method, route, statement, count })), [
    { method: "GET", route: "/orders/:id", statement: "SELECT * FROM orders WHERE id = $1", count: 2 },
    { method: "JOB", route: "/(job) nightly", statement: "VACUUM", count: 1 },
  ]);
});

test("a job Server speed counted under (other), past its cap, has its queries there too", async () => {
  const received = [];
  const collector = http.createServer((req, res) => {
    let body = "";
    req.on("data", (chunk) => (body += chunk));
    req.on("end", () => {
      if (req.url === "/events/server-queries") received.push(JSON.parse(body));
      res.statusCode = req.url.startsWith("/events/platform/config") ? 404 : 202;
      res.end();
    });
  });
  await new Promise((resolve) => collector.listen(0, "127.0.0.1", resolve));
  const off = Object.fromEntries(["firewall", "errors", "analytics", "crawlers", "forms", "headers", "audit", "flags", "maintenance",
    "inventory", "posture", "resources", "proxy"].map((name) => [name, false]));
  const platform = createPlatform({ siteId: "b".repeat(24), secret: "s3cret", endpoint: `http://127.0.0.1:${collector.address().port}`, ...off });
  const pool = platform.watchDatabase(new (fakePg().Pool)());
  for (let i = 0; i < 300; i += 1) await platform.job(`job-${i}`, () => null);
  await platform.job("late", () => pool.query("VACUUM"));
  await platform.close();
  collector.close();
  const rows = received.flatMap((body) => body.rows);
  assert.deepEqual(rows.map(({ method, route, statement }) => ({ method, route, statement })),
    [{ method: "JOB", route: "(other)", statement: "VACUUM" }]);
});

test("queries: false leaves them out and watchDatabase hands the object back untouched", () => {
  const platform = createPlatform({ queries: false, firewall: false, inventory: false, posture: false, resources: false, errors: false });
  const pool = new (fakePg().Pool)();
  const query = pool.query;
  assert.equal(platform.watchDatabase(pool), pool);
  assert.equal(pool.query, query);
  platform.close();
});

// ---- Each library ----

test("pg: a Pool's own queries count once, and so do a checked-out client's; the prototype is left alone", async () => {
  const { Pool, Client } = fakePg();
  const { queries, rows } = setUp();
  const pool = new Pool();
  assert.equal(queries.watchDatabase(pool), pool);
  queries.watchDatabase(pool); // twice is still once
  await pool.query("SELECT 1");
  await pool.query({ text: "SELECT 2" });
  const client = await pool.connect();
  await client.query("SELECT 3");
  await new Promise((resolve) => pool.connect((error, c) => c.query("SELECT 4", () => resolve())));
  await pool.query("SELECT 5"); // the same client, back in the pool's own hands
  assert.ok(!Object.prototype.hasOwnProperty.call(Pool.prototype.query, Symbol.for("analytics-platform.queries")));
  assert.equal(Client.prototype.query.name, "query");
  const sent = await rows();
  assert.equal(sent.length, 1);
  assert.equal(sent[0].statement, "SELECT ?");
  assert.equal(sent[0].count, 5);

  const failing = new (fakePg({ fail: true }).Client)();
  queries.watchDatabase(failing);
  await assert.rejects(failing.query("SELECT * FROM x"));
  await new Promise((resolve) => failing.query("SELECT * FROM x", () => resolve()));
  const [row] = await rows();
  assert.deepEqual([row.count, row.errors, row.db], [2, 2, "postgresql"]);
});

test("mysql2: pool and connection, callback, event and promise forms, each counted once", async () => {
  const { Pool, Connection } = fakeMysql();
  const { queries, rows } = setUp();
  const pool = queries.watchDatabase(new Pool());
  await new Promise((resolve) => pool.query("SELECT 1", [], () => resolve()));
  await new Promise((resolve) => pool.query("SELECT 1").once("end", resolve));
  await new Promise((resolve) => pool.execute("SELECT 1", [], () => resolve()));
  await new Promise((resolve) => pool.getConnection((error, c) => c.query("SELECT 1", () => resolve())));
  const promisePool = queries.watchDatabase(pool.promise());
  await promisePool.query("SELECT 2"); // through the core pool, once
  const lent = await promisePool.getConnection();
  await lent.execute("SELECT 3");
  const connection = queries.watchDatabase(new Connection());
  await new Promise((resolve) => connection.query("SELECT 4", resolve));
  const [row] = await rows();
  assert.deepEqual([row.db, row.statement, row.count], ["mysql", "SELECT ?", 7]);
});

test("mongodb: command events are timed, chatter and getMore are not", async () => {
  const { queries, rows } = setUp();
  const client = Object.assign(new EventEmitter(), { monitorCommands: false, db() {} });
  assert.equal(queries.watchDatabase(client), client);
  assert.equal(client.monitorCommands, true);
  const command = (name, body, requestId, failed = false) => {
    client.emit("commandStarted", { commandName: name, command: { [name]: "users", ...body }, requestId, connectionId: 1 });
    client.emit(failed ? "commandFailed" : "commandSucceeded", { commandName: name, requestId, connectionId: 1, duration: 12 });
  };
  const req = {};
  queries.bind(req, () => {
    command("find", { filter: { email: "a@b.c" } }, 1);
    command("find", { filter: { email: "z@b.c" } }, 2, true);
    command("hello", {}, 3);
    command("getMore", {}, 4);
  });
  queries.finish(req, "GET", "/users");
  // Mongoose's connection gives the client.
  queries.watchDatabase({ getClient: () => client });
  const sent = await rows();
  assert.deepEqual(sent.map(({ db, statement, count, errors, sum_ms }) => ({ db, statement, count, errors, sum_ms })),
    [{ db: "mongodb", statement: 'find users {"email":"?"}', count: 2, errors: 1, sum_ms: 24 }]);
});

test("knex: query events are timed, and a watched driver underneath leaves them to knex", async () => {
  const { queries, rows } = setUp();
  const driver = queries.watchDatabase(new (fakePg().Client)());
  const knex = Object.assign(function knex() {}, EventEmitter.prototype, { client: { dialect: "postgresql" } });
  EventEmitter.call(knex);
  queries.watchDatabase(knex);
  const req = {};
  await queries.bind(req, async () => {
    knex.emit("query", { __knexQueryUid: "q1", sql: "select * from users where id = ?", bindings: [1] });
    await driver.query("select * from users where id = $1"); // knex's own connection, if it were watched
    knex.emit("query-response", [], { __knexQueryUid: "q1" });
    knex.emit("query", { __knexQueryUid: "q2", sql: "insert into logs values (?)" });
    knex.emit("query-error", new Error("x"), { __knexQueryUid: "q2" });
    await driver.query("select 1"); // after knex is done: the driver's own
  });
  queries.finish(req, "POST", "/users");
  const sent = await rows();
  assert.deepEqual(sent.map(({ db, statement, count, errors }) => ({ db, statement, count, errors })), [
    { db: "postgresql", statement: "select * from users where id = ?", count: 1, errors: 0 },
    { db: "postgresql", statement: "insert into logs values (?)", count: 1, errors: 1 },
    { db: "postgresql", statement: "select ?", count: 1, errors: 0 },
  ]);
});

test("Prisma: model calls through a query extension, the driver under it skipped, the extended client returned", async () => {
  const { queries, rows } = setUp();
  const driver = queries.watchDatabase(new (fakePg().Pool)());
  let extension = null;
  const prisma = {
    _activeProvider: "postgresql",
    $extends(given) {
      extension = given;
      return { extended: true };
    },
  };
  const extended = queries.watchDatabase(prisma);
  assert.deepEqual(extended, { extended: true });
  const operation = extension.query.$allOperations;
  const req = {};
  await queries.bind(req, async () => {
    await operation({ model: "User", operation: "findMany", args: {}, query: () => driver.query("SELECT * FROM \"User\"") });
    await assert.rejects(operation({ model: "User", operation: "create", args: {}, query: async () => { throw new Error("unique"); } }));
    await operation({ model: undefined, operation: "$queryRaw", args: [], query: async () => [] });
  });
  queries.finish(req, "GET", "/users");
  const sent = await rows();
  assert.deepEqual(sent.map(({ db, statement, count, errors }) => ({ db, statement, count, errors })), [
    { db: "postgresql", statement: "User.findMany", count: 1, errors: 0 },
    { db: "postgresql", statement: "User.create", count: 1, errors: 1 },
    { db: "postgresql", statement: "$queryRaw", count: 1, errors: 0 },
  ]);
});

test("something that isn't a database object is handed back as it is", () => {
  const { queries } = setUp();
  const thing = { query: 1 };
  assert.equal(queries.watchDatabase(thing), thing);
  assert.equal(queries.watchDatabase(null), null);
});
