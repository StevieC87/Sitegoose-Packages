// Redis command timings (sdk/protocols/queries.md, "Redis"): the shared
// redisCommand cases, and the ioredis and node-redis hooks against stand-ins
// shaped as each library's objects are (the package has no dependencies).
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { EventEmitter } = require("node:events");
const { redisCommand } = require("../lib/queryText.js");
const { createQueries } = require("../lib/queries.js");
const { createQueues } = require("../lib/queues.js");

const cases = JSON.parse(fs.readFileSync(path.join(__dirname, "../../protocols/query-cases.json"), "utf8"));

function setUp() {
  const sent = [];
  const logged = [];
  const core = {
    valid: false, siteId: "a".repeat(24), isOn: (name) => name === "performance", log: (...args) => logged.push(args.join(" ")),
    send: async (module, url, options) => { sent.push({ url, ...options }); return null; },
  };
  const queries = createQueries(core, { serverName: "web-1" });
  // With routes: each row's route too.
  const rows = async (routes = false) => {
    await queries.flush();
    return sent.splice(0).filter((call) => call.url === "/events/server-queries").flatMap((call) => call.body.rows)
      .map(({ db, statement, count, errors, route }) => (routes ? { db, statement, count, errors, route } : { db, statement, count, errors }))
      .sort((a, b) => a.statement.localeCompare(b.statement));
  };
  return { queries, rows, logged, core };
}

const tick = () => new Promise((resolve) => setImmediate(resolve));

// What the stand-in servers answer: nil for "missing", an error reply for "text".
function replyTo(name, args) {
  if (String(args[0]) === "missing") return null;
  if (String(args[0]) === "text") return new Error("WRONGTYPE Operation against a key holding the wrong kind of value");
  return name.toLowerCase() === "get" ? "v" : "OK";
}

// ---- ioredis: Command objects with their own resolve/reject, sendCommand,
// and Pipelines that queue commands and send them through the client's
// sendCommand marked as a pipeline's ----

class IoCommand {
  constructor(name, args, callback) {
    Object.assign(this, { name, args, callback });
    this.promise = new Promise((resolve, reject) => {
      this.resolve = resolve;
      this.reject = reject;
    });
    if (callback) this.promise.then((value) => callback(null, value), (error) => callback(error));
  }
}

class IoPipeline {
  constructor(redis, multi, commands) {
    Object.assign(this, { redis, multi, queue: [] });
    if (multi) this.sendCommand(new IoCommand("multi", []));
    for (const [name, ...args] of commands || []) this.sendCommand(new IoCommand(name, args));
  }
  sendCommand(command) {
    this.queue.push(command);
    return this;
  }
  get(key) { return this.sendCommand(new IoCommand("get", [key])); }
  set(key, value) { return this.sendCommand(new IoCommand("set", [key, value])); }
  incr(key) { return this.sendCommand(new IoCommand("incr", [key])); }
  exec(callback) {
    if (this.multi) this.sendCommand(new IoCommand("exec", []));
    const stream = { isPipeline: true };
    for (const command of this.queue) this.redis.sendCommand(command, stream);
    const answer = new Promise((resolve) => setImmediate(() => resolve(this.queue.map((command) => {
      const reply = replyTo(command.name, command.args);
      return reply instanceof Error ? [reply, null] : [null, reply];
    }))));
    if (callback) answer.then((value) => callback(null, value));
    return answer;
  }
}

class Ioredis extends EventEmitter {
  constructor() {
    super();
    this.status = "ready";
    this.offline = [];
    this.wire = [];
  }
  defineCommand() {}
  sendCommand(command, stream) {
    if (stream?.isPipeline) return command.promise;
    // Its handshake is written while connecting; the app's commands wait.
    if (this.status !== "ready" && this.status !== "connect") {
      this.offline.push(command);
      return command.promise;
    }
    this.wire.push(command.name);
    setImmediate(() => {
      const reply = replyTo(command.name, command.args);
      if (reply instanceof Error) command.reject(reply);
      else command.resolve(reply);
    });
    return command.promise;
  }
  ready() {
    this.status = "ready";
    for (const command of this.offline.splice(0)) this.sendCommand(command);
  }
  get(key, callback) { return this.sendCommand(new IoCommand("get", [key], callback)); }
  incr(key) { return this.sendCommand(new IoCommand("incr", [key])); }
  blpop(...args) { return this.sendCommand(new IoCommand("blpop", args)); }
  call(name, ...args) { return this.sendCommand(new IoCommand(name, args)); }
  pipeline(commands) { return new IoPipeline(this, false, commands); }
  multi(commands, options) {
    if (options?.pipeline === false) return this.call("multi");
    return new IoPipeline(this, true, commands);
  }
}

test("every shared redisCommand case, character for character", () => {
  assert.ok(cases.redis_commands.length > 20);
  for (const { args, expected } of cases.redis_commands) assert.equal(redisCommand(args), expected, JSON.stringify(args));
});

test("ioredis: each command timed to its reply, errors counted, nil not, blocking ones and the prototype left alone", async () => {
  const { queries, rows } = setUp();
  const original = Ioredis.prototype.sendCommand;
  const redis = queries.watchDatabase(new Ioredis());
  assert.ok(redis instanceof Ioredis);
  assert.equal(await redis.get("user:42:cart"), "v");
  assert.equal(await redis.get("missing"), null);
  await assert.rejects(redis.incr("text"), /WRONGTYPE/);
  await new Promise((resolve) => redis.get("user:7:cart", resolve));
  assert.equal(await redis.call("GET", Buffer.from("user:9:cart")), "v");
  await redis.blpop("jobs", 0);
  assert.equal(Ioredis.prototype.sendCommand, original);
  assert.deepEqual(await rows(), [
    { db: "redis", statement: "GET missing", count: 1, errors: 0 },
    { db: "redis", statement: "GET user:?:cart", count: 3, errors: 0 },
    { db: "redis", statement: "INCR text", count: 1, errors: 1 },
  ]);
});

test("ioredis: a command waiting for the connection counts once, and the handshake not at all", async () => {
  const { queries, rows } = setUp();
  const redis = queries.watchDatabase(new Ioredis());
  redis.status = "connect";
  redis.call("auth", "hunter2");
  redis.status = "connecting";
  const answer = redis.get("user:1");
  redis.ready();
  await answer;
  assert.deepEqual(await rows(), [{ db: "redis", statement: "GET user:?", count: 1, errors: 0 }]);
});

test("ioredis: a pipeline or transaction is one call named by its first command; its commands aren't counted again", async () => {
  const { queries, rows } = setUp();
  const redis = queries.watchDatabase(new Ioredis());
  const replies = await redis.pipeline().get("user:1").incr("text").exec();
  assert.equal(replies.length, 2);
  await redis.multi().set("cart:9", "x").get("cart:9").exec();
  await redis.pipeline([["set", "session:abc123", "x"]]).exec();
  await new Promise((resolve) => redis.pipeline().get("user:2").exec(resolve));
  // An empty one isn't a call.
  await redis.pipeline().exec();
  assert.deepEqual(await rows(), [
    { db: "redis", statement: "MULTI SET cart:?", count: 1, errors: 0 },
    { db: "redis", statement: "PIPELINE GET user:?", count: 2, errors: 1 },
    { db: "redis", statement: "PIPELINE SET session:?", count: 1, errors: 0 },
  ]);
});

// As ioredis's enableAutoPipelining: separate commands, from any request,
// gathered into one pipeline the client makes and runs on the next turn.
class AutoIoredis extends Ioredis {
  options = { enableAutoPipelining: true };
  auto = null;
  get(key) {
    if (!this.auto) {
      this.auto = this.pipeline();
      setImmediate(() => {
        const pipeline = this.auto;
        this.auto = null;
        pipeline.exec();
        for (const queued of pipeline.queue) {
          const reply = replyTo(queued.name, queued.args);
          if (reply instanceof Error) queued.reject(reply);
          else queued.resolve(reply);
        }
      });
    }
    const command = new IoCommand("get", [key]);
    this.auto.sendCommand(command);
    return command.promise;
  }
}

test("ioredis: commands auto-pipelined are each timed alone, in the request that sent them", async () => {
  const { queries, rows } = setUp();
  const redis = queries.watchDatabase(new AutoIoredis());
  const one = {};
  const two = {};
  const answers = Promise.allSettled([queries.bind(one, () => redis.get("user:1")), queries.bind(two, () => redis.get("missing")), redis.get("text")]);
  assert.deepEqual((await answers).map((answer) => (answer.status === "fulfilled" ? answer.value : answer.reason.message.slice(0, 9))), ["v", null, "WRONGTYPE"]);
  queries.finish(one, "GET", "/one");
  queries.finish(two, "GET", "/two");
  assert.deepEqual(await rows(true), [
    { db: "redis", statement: "GET missing", count: 1, errors: 0, route: "/two" },
    { db: "redis", statement: "GET text", count: 1, errors: 1, route: "(background)" },
    { db: "redis", statement: "GET user:?", count: 1, errors: 0, route: "/one" },
  ]);
});

test("ioredis: the package's own queue reads on the same client aren't timed", async () => {
  const { queries, rows, core } = setUp();
  const redis = queries.watchDatabase(new Ioredis());
  const queues = createQueues(core, { timer: false });
  const queue = new EventEmitter();
  Object.assign(queue, {
    name: "emails", opts: { connection: redis }, add: async () => ({}),
    // As BullMQ's: waits for its client, then runs its script on it.
    getJobCounts: async () => {
      await tick();
      await redis.call("evalsha", "abc", "1", "bull:emails:wait");
      return { waiting: 0 };
    },
    getJobs: async () => [],
  });
  queues.watchQueue(queue);
  await Promise.all([queues.sample(), redis.get("user:3")]);
  assert.deepEqual(await rows(), [{ db: "redis", statement: "GET user:?", count: 1, errors: 0 }]);
});

// ---- node-redis 5: typed commands through _self._executeCommand, then the
// client's sendCommand; multi() batches ----

class NodeMulti {
  constructor(executeMulti, executePipeline) {
    this.queue = [];
    this.executeMulti = executeMulti;
    this.executePipeline = executePipeline;
  }
  addCommand(args) {
    this.queue.push(args);
    return this;
  }
  get(key) { return this.addCommand(["GET", key]); }
  set(key, value) { return this.addCommand(["SET", key, value]); }
  async exec(execAsPipeline = false) {
    if (execAsPipeline) return this.execAsPipeline();
    return this.executeMulti(this.queue);
  }
  EXEC = this.exec;
  async execAsPipeline() {
    return this.executePipeline(this.queue);
  }
}

class NodeRedis extends EventEmitter {
  _self = this;
  multi = this.MULTI;
  async _executeCommand(args) {
    return this.sendCommand(args);
  }
  sendCommand(args) {
    return new Promise((resolve, reject) => setImmediate(() => {
      const reply = replyTo(args[0], args.slice(1));
      if (reply instanceof Error) reject(reply);
      else resolve(reply);
    }));
  }
  get(key) { return this._self._executeCommand(["GET", key]); }
  incr(key) { return this._self._executeCommand(["INCR", key]); }
  blPop(key) { return this._self._executeCommand(["BLPOP", key, "0"]); }
  withTypeMapping() { return Object.create(this._self); }
  MULTI() {
    const run = async (commands) => {
      await tick();
      const replies = commands.map((args) => replyTo(args[0], args.slice(1)));
      if (replies.some((reply) => reply instanceof Error)) throw new Error("MultiErrorReply");
      return replies;
    };
    return new NodeMulti(run, run);
  }
}

test("node-redis 5: typed and raw commands, a proxy's too; errors rejected to the app as before", async () => {
  const { queries, rows } = setUp();
  const client = queries.watchDatabase(new NodeRedis());
  assert.equal(await client.get("user:42"), "v");
  await assert.rejects(client.incr("text"), /WRONGTYPE/);
  assert.equal(await client.withTypeMapping({}).get("user:43"), "v");
  await client.sendCommand(["HSET", Buffer.from("profile:bob@x.com"), "name", "Bob"]);
  await client.blPop("jobs");
  assert.deepEqual(await rows(), [
    { db: "redis", statement: "GET user:?", count: 2, errors: 0 },
    { db: "redis", statement: "HSET profile:?", count: 1, errors: 0 },
    { db: "redis", statement: "INCR text", count: 1, errors: 1 },
  ]);
});

test("node-redis 5: multi().exec() is MULTI, exec(true) and execAsPipeline() PIPELINE, each once", async () => {
  const { queries, rows } = setUp();
  const client = queries.watchDatabase(new NodeRedis());
  await client.multi().set("cart:1", "x").get("cart:1").exec();
  await client.multi().get("user:1").exec(true);
  await client.MULTI().get("user:2").execAsPipeline();
  await assert.rejects(client.multi().get("user:3").addCommand(["INCR", "text"]).EXEC(), /MultiErrorReply/);
  assert.deepEqual(await rows(), [
    { db: "redis", statement: "MULTI GET user:?", count: 1, errors: 1 },
    { db: "redis", statement: "MULTI SET cart:?", count: 1, errors: 0 },
    { db: "redis", statement: "PIPELINE GET user:?", count: 2, errors: 0 },
  ]);
});

// ---- node-redis 4: typed commands on the prototype, both spellings, run
// through a private sendCommand the public one doesn't see ----

function nodeRedis4() {
  const sendPrivately = (args) => new Promise((resolve, reject) => setImmediate(() => {
    const reply = replyTo(args[0], args.slice(1));
    if (reply instanceof Error) reject(reply);
    else resolve(reply);
  }));
  class RedisClient extends EventEmitter {
    constructor() {
      super();
      this.multi = this.MULTI;
    }
    get options() { return {}; }
    commandsExecutor() {}
    multiExecutor() {}
    sendCommand(args) { return sendPrivately(args); }
    MULTI() {
      const run = async (commands) => commands.map((args) => replyTo(args[0], args.slice(1)));
      return new NodeMulti(run, run);
    }
  }
  const commands = {
    GET: (key) => ["GET", key], INCR: (key) => ["INCR", key], BLPOP: (key) => ["BLPOP", key, "0"],
    CLIENT_SETNAME: (name) => ["CLIENT", "SETNAME", name], XREAD: () => ["XREAD", "BLOCK", "0", "STREAMS", "s", "$"],
    ZRANGE_WITHSCORES: (key) => ["ZRANGE", key, "0", "-1", "WITHSCORES"],
  };
  const camel = { GET: "get", INCR: "incr", BLPOP: "blPop", CLIENT_SETNAME: "clientSetName", XREAD: "xRead", ZRANGE_WITHSCORES: "zRangeWithScores" };
  for (const [name, toArgs] of Object.entries(commands)) {
    RedisClient.prototype[name] = RedisClient.prototype[camel[name]] = function (...args) {
      if (args[0] && typeof args[0] === "object" && Object.getOwnPropertySymbols(args[0]).length) args.shift();
      return sendPrivately(toArgs(...args));
    };
  }
  return new RedisClient();
}

test("node-redis 4: typed commands in either spelling, with command options, blocking ones left out", async () => {
  const { queries, rows } = setUp();
  const client = queries.watchDatabase(nodeRedis4());
  assert.equal(await client.get("user:42"), "v");
  assert.equal(await client.GET({ [Symbol("Command Options")]: true, isolated: true }, "user:43"), "v");
  await assert.rejects(client.incr("text"), /WRONGTYPE/);
  await client.clientSetName("web");
  await client.zRangeWithScores("board:7", 0, -1);
  await client.blPop("jobs", 0);
  await client.xRead({ key: "s", id: "$" }, { BLOCK: 0 });
  await client.sendCommand(["SET", "session:abc123", "x"]);
  await client.multi().get("user:1").exec();
  assert.deepEqual(await rows(), [
    { db: "redis", statement: "CLIENT SETNAME", count: 1, errors: 0 },
    { db: "redis", statement: "GET user:?", count: 2, errors: 0 },
    { db: "redis", statement: "INCR text", count: 1, errors: 1 },
    { db: "redis", statement: "MULTI GET user:?", count: 1, errors: 0 },
    { db: "redis", statement: "SET session:?", count: 1, errors: 0 },
    { db: "redis", statement: "ZRANGE board:?", count: 1, errors: 0 },
  ]);
});

test("a node-redis cluster or pool is handed back untouched, with a word in the log", () => {
  const { queries, logged } = setUp();
  const cluster = { nodeClient() {}, getMasters() {}, sendCommand() {}, MULTI() {} };
  const before = cluster.sendCommand;
  assert.equal(queries.watchDatabase(cluster), cluster);
  assert.equal(cluster.sendCommand, before);
  assert.match(logged.join("\n"), /cluster, pool/);
});

test("an object that throws on being looked at, and a client used after close(), leave the app alone", async () => {
  const { queries, rows, logged } = setUp();
  const hostile = new Proxy({}, { get() { throw new Error("no peeking"); } });
  assert.equal(queries.watchDatabase(hostile), hostile);
  assert.match(logged.join("\n"), /could not watch it/);
  const redis = queries.watchDatabase(new Ioredis());
  await queries.close();
  // Nothing sends rows after close(): none are kept, and the command still answers.
  assert.equal(await redis.get("user:1"), "v");
  assert.deepEqual(await rows(), []);
});
