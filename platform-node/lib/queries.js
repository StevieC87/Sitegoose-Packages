// Database queries (sdk/protocols/queries.md): the half of Server speed that
// says why a route is slow. platform.watchDatabase(db) times the queries run
// through one database object the app made, with the values in each taken
// out first (queryText.js), adds them up per request, and when the request
// finishes files them under the method and route Server speed counted it
// under. One row per minute, method, route, database and query goes to POST
// /events/server-queries. Bound parameters are never read.
//
// Only the object passed is changed (its own query function, or its public
// events): never a library's prototype or private code. Rides on the
// performance module's switch; queries: false leaves them out.
//
// The same requests' outgoing HTTP calls (sdk/protocols/calls.md) are filed
// alongside, by call method and host, from Node's public diagnostics
// channels, and go to POST /events/server-calls; calls: false leaves them out.
"use strict";

// No Node built-ins required, as performance.js: AsyncLocalStorage is asked
// for at run time, so Hono can load this on any runtime.
const { builtin } = require("./core.js");
const { BUCKET_EDGES_MS, bucketOf, hostname, methodOf } = require("./performance.js");
const { normalizeStatement, redisCommand, OTHER_STATEMENT, REDIS_CONTAINERS } = require("./queryText.js");

const FLUSH_MS = 60 * 1000;
// Distinct queries kept per request; past it new ones are one "(other)".
const MAX_PER_REQUEST = 50;
// Past MAX_KEYS a minute's new queries fold into "(other)" (same method,
// route and database); past HARD_MAX_KEYS nothing new is kept.
const MAX_KEYS = 200;
const HARD_MAX_KEYS = 300;
const MAX_ROWS = 500;
// Queries no request or job is waiting on.
const BACKGROUND = { method: "JOB", route: "(background)" };
// Marks a query function already timed, so watching an object twice counts once.
const WRAPPED = Symbol.for("analytics-platform.queries");
// On a pooled connection: false while its pool runs a query of its own on it
// (pool.query(), timed as the pool's), true while the app holds it.
const LENT = Symbol.for("analytics-platform.lent");
// Mongo commands that are the driver's own talk, not the app's queries.
const CHATTER = new Set(["hello", "isMaster", "ismaster", "ping", "buildInfo", "saslStart", "saslContinue", "getMore",
  "endSessions", "killCursors", "getLastError"]);
// Queries started and not yet answered (Mongo, knex), by their ID: a driver
// that never answers can't grow it past this.
const PENDING_MAX = 1000;
// Normalized SQL by its text: an app runs the same few queries over and over.
const CACHE_MAX = 500;
const CACHE_TEXT_MAX = 2000;

const clock = () => globalThis.performance?.now?.() ?? Date.now();
const emptyBuckets = () => new Array(BUCKET_EDGES_MS.length + 1).fill(0);

// The database a library's name for it is: pg, mysql2, knex's dialects, Prisma's providers.
function databaseNamed(name) {
  const text = String(name || "").toLowerCase();
  if (["pg", "postgres", "postgresql", "pgnative", "pg-native"].includes(text)) return "postgresql";
  if (text.startsWith("mysql")) return "mysql";
  if (text.startsWith("maria")) return "mariadb";
  if (text.startsWith("sqlite") || text === "better-sqlite3") return "sqlite";
  if (["mssql", "sqlserver", "tedious"].includes(text)) return "mssql";
  if (text.startsWith("oracle")) return "oracle";
  if (text === "clickhouse") return "clickhouse";
  if (text === "mongodb") return "mongodb";
  return "other";
}

// The SQL in a query call's first argument: text, pg's { text } or mysql2's { sql }.
function sqlOf(arg) {
  if (typeof arg === "string") return arg;
  if (typeof arg?.text === "string") return arg.text;
  return typeof arg?.sql === "string" ? arg.sql : "";
}

// "find users {...}": what the normalizer turns into the statement (values
// out), from a Mongo command as the driver's commandStarted event has it.
function mongoText(name, command) {
  const collection = command?.[name];
  let filter;
  if (name === "find") filter = command.filter;
  else if (name === "aggregate") filter = command.pipeline;
  else if (["count", "distinct", "findAndModify"].includes(name)) filter = command.query;
  else if (name === "delete") filter = command.deletes?.[0]?.q;
  else if (name === "update") filter = command.updates?.[0]?.q;
  const named = !(collection === undefined || collection === null || typeof collection === "object" || collection === "");
  let text = named ? `${name} ${collection}` : name;
  // With no collection the filter would be read as one, values and all.
  if (filter !== undefined && named) {
    try {
      const json = JSON.stringify(filter);
      if (json) text += ` ${json}`;
    } catch {
      // a filter JSON can't carry (a BigInt) is left out
    }
  }
  return text;
}

// ---- Watching ----
// get() is the recorder now (null when there is none yet, as on Hono before
// its first request); every hook asks it, so nothing is timed until it exists.

// Times target[name], a query function, on this one object. Callback,
// promise and event-emitter answers alike; a call made while its pool uses
// the connection for its own query() is left to the pool's.
function wrapQuery(target, name, db, get) {
  const original = target[name];
  if (typeof original !== "function" || original[WRAPPED]) return;
  function timedQuery(...args) {
    const recorder = this?.[LENT] === false ? null : get();
    const timing = recorder?.begin();
    const text = timing ? sqlOf(args[0]) : "";
    if (!text) return original.apply(this, args);
    const done = (failed) => {
      if (timing.done) return;
      timing.done = true;
      recorder.end(timing, db, text, failed);
    };
    const last = args.length - 1;
    if (typeof args[last] === "function") {
      const callback = args[last];
      args[last] = function queryAnswered(error, ...rest) {
        done(Boolean(error));
        return callback.call(this, error, ...rest);
      };
      return original.apply(this, args);
    }
    let result;
    try {
      result = original.apply(this, args);
    } catch (error) {
      done(true);
      throw error;
    }
    try {
      // mysql2's query objects have a then() that throws, so events first. An
      // 'error' listener would swallow an error the app may not handle: a
      // query streamed this way that fails isn't counted.
      if (typeof result?.once === "function") result.once("end", () => done(false));
      // The promise handed back is the one timed, so a rejection the app
      // doesn't handle is still unhandled, as without the hook.
      else if (typeof result?.then === "function") {
        return result.then((value) => (done(false), value), (error) => {
          done(true);
          throw error;
        });
      }
    } catch {
      // not timed
    }
    return result;
  }
  timedQuery[WRAPPED] = true;
  target[name] = timedQuery;
}

// A pool: its own query functions are timed, and so are those of the
// connections the app checks out (pg's connect(), mysql2's getConnection());
// the connection the pool takes for its own query() is not, or that query
// would count twice. Both pools take it synchronously inside query().
function watchPool(pool, db, methods, checkout, get) {
  let busy = 0;
  for (const name of methods) {
    const query = pool[name];
    if (typeof query !== "function" || query[WRAPPED]) continue;
    pool[name] = function poolQuery(...args) {
      busy += 1;
      try {
        return query.apply(this, args);
      } finally {
        busy -= 1;
      }
    };
    wrapQuery(pool, name, db, get);
  }
  const original = pool[checkout];
  if (typeof original !== "function" || original[WRAPPED]) return;
  function checkedOut(...args) {
    const own = busy === 0;
    const lend = (connection) => {
      if (connection && typeof connection === "object") {
        if (own) for (const name of methods) wrapQuery(connection, name, db, get);
        connection[LENT] = own;
      }
      return connection;
    };
    const last = args.length - 1;
    if (typeof args[last] === "function") {
      const callback = args[last];
      args[last] = function connected(error, connection, ...rest) {
        if (!error) lend(connection);
        return callback.call(this, error, connection, ...rest);
      };
      return original.apply(this, args);
    }
    const result = original.apply(this, args);
    return typeof result?.then === "function" ? result.then(lend) : result;
  }
  checkedOut[WRAPPED] = true;
  pool[checkout] = checkedOut;
}

// MongoClient: the driver's own command events (public, on the client).
// Connections opened before monitorCommands was set send none, so watch the
// client before it connects.
function watchMongo(client, get) {
  if (client[WRAPPED]) return;
  client[WRAPPED] = true;
  client.monitorCommands = true;
  const pending = new Map();
  const keyOf = (event) => `${event.connectionId}|${event.requestId}`;
  client.on("commandStarted", (event) => {
    try {
      if (CHATTER.has(event.commandName) || pending.size >= PENDING_MAX) return;
      const recorder = get();
      // Never under knex or Prisma, so a knex query running beside it in
      // the same request doesn't make it skip.
      const timing = recorder?.begin(true);
      if (timing) pending.set(keyOf(event), { recorder, timing, text: mongoText(event.commandName, event.command) });
    } catch {
      // not timed
    }
  });
  const ended = (failed) => (event) => {
    const started = pending.get(keyOf(event));
    if (!started) return;
    pending.delete(keyOf(event));
    started.recorder.end(started.timing, "mongodb", started.text, failed, Number(event.duration));
  };
  client.on("commandSucceeded", ended(false));
  client.on("commandFailed", ended(true));
}

// knex: its query events (public, on the instance; a transaction's are
// passed on to it). A query knex runs marks its request, so the driver
// underneath, when watched too, leaves it to knex.
function watchKnex(knex, get) {
  if (knex[WRAPPED]) return;
  knex[WRAPPED] = true;
  const db = databaseNamed(knex.client?.dialect || knex.client?.config?.client);
  const pending = new Map();
  knex.on("query", (data) => {
    try {
      const id = data?.__knexQueryUid;
      if (!id || typeof data.sql !== "string" || pending.size >= PENDING_MAX) return;
      const recorder = get();
      const timing = recorder?.begin(true);
      if (!timing) return;
      if (timing.store) timing.store.outer += 1;
      pending.set(id, { recorder, timing, text: data.sql });
    } catch {
      // not timed
    }
  });
  const ended = (data, failed) => {
    const started = pending.get(data?.__knexQueryUid);
    if (!started) return;
    pending.delete(data.__knexQueryUid);
    if (started.timing.store) started.timing.store.outer -= 1;
    started.recorder.end(started.timing, db, started.text, failed);
  };
  knex.on("query-response", (response, data) => ended(data, false));
  knex.on("query-error", (error, data) => ended(data, true));
}

// Prisma: a query extension, so the client returned is the one to use. Model
// calls ("User.findMany"), not SQL; a driver underneath, when watched too
// (a pg pool given to @prisma/adapter-pg), leaves them to Prisma.
function watchPrisma(prisma, get) {
  let db = "other";
  try {
    db = databaseNamed(prisma._activeProvider ?? prisma._engineConfig?.activeProvider);
  } catch {
    // "other"
  }
  return prisma.$extends({
    name: "analytics-platform",
    query: {
      async $allOperations({ model, operation, args, query }) {
        const recorder = get();
        const timing = recorder?.begin(true);
        if (!timing) return query(args);
        const text = model ? `${model}.${operation}` : String(operation);
        try {
          const result = await recorder.outer(() => query(args));
          recorder.end(timing, db, text, false);
          return result;
        } catch (error) {
          recorder.end(timing, db, text, true);
          throw error;
        }
      },
    },
  });
}

// @clickhouse/client: the client's own query, insert, command and exec. A
// query answers once its result starts arriving, so it is timed until the
// result is read (json(), text(), the stream ending, or close()); one never
// read isn't counted. An insert or command is timed until it answers.
const CLICKHOUSE_METHODS = ["query", "insert", "command", "exec"];

function clickhouseText(name, params) {
  if (name !== "insert") return typeof params?.query === "string" ? params.query : "";
  const table = typeof params?.table === "string" ? params.table : "";
  return table ? `INSERT INTO ${table} FORMAT ${params.format || "JSONCompactEachRow"}` : "";
}

// Ends timing once the app has read the result set (or given up on it).
function timeResult(result, done) {
  for (const name of ["json", "text"]) {
    const read = result[name];
    if (typeof read !== "function") continue;
    result[name] = function readTimed(...args) {
      try {
        const value = read.apply(this, args);
        if (typeof value?.then === "function") value.then(() => done(false), () => done(true));
        else done(false);
        return value;
      } catch (error) {
        done(true);
        throw error;
      }
    };
  }
  const stream = result.stream;
  if (typeof stream === "function") {
    result.stream = function streamTimed(...args) {
      const out = stream.apply(this, args);
      if (typeof out?.once === "function") {
        out.once("error", () => done(true));
        out.once("end", () => done(false));
        out.once("close", () => done(false));
      }
      return out;
    };
  }
  const close = result.close;
  if (typeof close === "function") {
    result.close = function closeTimed(...args) {
      done(false);
      return close.apply(this, args);
    };
  }
  return result;
}

function watchClickHouse(client, get) {
  for (const name of CLICKHOUSE_METHODS) {
    const original = client[name];
    if (typeof original !== "function" || original[WRAPPED]) continue;
    const timed = function clickhouseTimed(params, ...rest) {
      const recorder = get();
      // Its HTTP requests are this query, not outgoing calls.
      return recorder ? recorder.database(() => run.call(this, recorder, params, rest)) : original.call(this, params, ...rest);
    };
    const run = function clickhouseRun(recorder, params, rest) {
      const timing = recorder.begin();
      const text = timing ? clickhouseText(name, params) : "";
      if (!text) return original.call(this, params, ...rest);
      const done = (failed) => {
        if (timing.done) return;
        timing.done = true;
        recorder.end(timing, "clickhouse", text, failed);
      };
      let answer;
      try {
        answer = original.call(this, params, ...rest);
      } catch (error) {
        done(true);
        throw error;
      }
      if (typeof answer?.then !== "function") return answer;
      return answer.then((result) => {
        if (name === "query" && result && typeof result === "object") return timeResult(result, done);
        done(false);
        return result;
      }, (error) => {
        done(true);
        throw error;
      });
    };
    timed[WRAPPED] = true;
    client[name] = timed;
  }
}

// ---- Redis (queries.md, "Redis") ----
// Each command is one query under db "redis": its name and first key's shape
// (redisCommand), never an argument. A pipeline or transaction is one, timed
// as a whole: "PIPELINE " or "MULTI " and its first command. A blocking
// command (BLPOP, XREAD BLOCK) isn't timed. An error reply or no answer is a
// failure; a nil reply isn't.

// The package's own Redis reads (queues.js, reading BullMQ queue depths) run
// inside ownRedis(), so a watched client they share is left out of them.
let ownStore = null;
function ownRedis(fn) {
  if (ownStore === null) {
    try {
      const Storage = globalThis.AsyncLocalStorage ?? builtin("async_hooks")?.AsyncLocalStorage;
      ownStore = typeof Storage === "function" ? new Storage() : false;
    } catch {
      ownStore = false;
    }
  }
  return ownStore ? ownStore.run(true, fn) : fn();
}
const ownRedisCall = () => (ownStore ? ownStore.getStore() === true : false);

const decoder = typeof TextDecoder === "function" ? new TextDecoder() : null;
// Bytes (a Buffer) as text, as a key is read; a long one isn't a key worth
// decoding. Anything else is handed on (a number makes "?").
function redisArg(arg) {
  if (typeof arg === "string" || !(arg instanceof Uint8Array)) return arg;
  return decoder && arg.length <= 1024 ? decoder.decode(arg) : null;
}

// The command as redisCommand reads it: its name (or name words), then args
// from `from` on. The key is at most the third argument, so only the first few
// are taken, except for XREAD, whose STREAMS can come anywhere.
function redisList(head, args, from = 0) {
  const list = Array.isArray(head) ? head.map(redisArg) : [redisArg(head)];
  const name = typeof list[0] === "string" && list[0].length < 12 ? list[0].toUpperCase() : "";
  const all = name === "XREAD" || name === "XREADGROUP";
  const end = all ? args.length : Math.min(args.length, from + Math.max(0, 4 - list.length));
  for (let i = from; i < end; i += 1) list.push(redisArg(args[i]));
  return list;
}

// What a batch adds: its first command that is timed, framing left out.
const FRAMING = new Set(["MULTI", "EXEC", "DISCARD"]);
function firstOf(batch, list) {
  if (batch.first) return;
  const statement = redisCommand(list);
  if (statement && !FRAMING.has(statement)) batch.first = statement;
}

// A command starting now: build(a, b, c) is the list redisCommand reads
// (redisList or named4), only made once it is timed; with no build, a is a
// batch's statement, its prefix included. done(failed) files it. null when
// it isn't timed.
function redisStart(get, build, a, b, c) {
  if (ownRedisCall()) return null;
  const recorder = get();
  // Never skipped for an ORM's query running beside it (begin(true)).
  const timing = recorder?.begin(true);
  if (!timing) return null;
  const statement = build ? redisCommand(build(a, b, c)) : a;
  if (!statement) return null;
  return (failed) => {
    if (timing.done) return;
    timing.done = true;
    recorder.end(timing, "redis", statement, failed);
  };
}

// A batch's answer: an error reply in it is a failure (ioredis hands back
// [error, reply] pairs; node-redis ErrorReply objects).
const batchFailed = (replies) => Array.isArray(replies)
  && replies.some((reply) => reply instanceof Error || (Array.isArray(reply) && reply[0] instanceof Error));

// Times call(), a promise: the one handed back is the one timed, so a
// rejection the app doesn't handle is still unhandled, as without the hook.
// keep: the app's answer comes by callback, so nobody holds the promise:
// it is watched and handed back unchanged.
function timeRedis(done, call, batch = false, keep = false) {
  if (!done) return call();
  let result;
  try {
    result = call();
  } catch (error) {
    done(true);
    throw error;
  }
  if (typeof result?.then !== "function") {
    done(false);
    return result;
  }
  const answered = (value) => done(batch && batchFailed(value));
  // node-redis's WatchError: EXEC answered nil, the transaction a WATCH
  // called off. A nil reply isn't a failure.
  const failed = (error) => done(!(batch && error?.constructor?.name === "WatchError"));
  if (keep) {
    result.then(answered, failed);
    return result;
  }
  return result.then((value) => (answered(value), value), (error) => {
    failed(error);
    throw error;
  });
}

// ioredis (Redis or Cluster): every command goes through the instance's
// sendCommand, timed from there to its reply by the command's own resolve and
// reject (so callbacks and promises alike, and the promise the app holds is
// unchanged). A pipeline's commands come through it too, marked as a
// pipeline's: those are left to the pipeline, timed by its exec().
const seenCommands = new WeakSet();
function watchIoredis(client, get) {
  if (client[WRAPPED]) return;
  client[WRAPPED] = true;
  const send = client.sendCommand;
  client.sendCommand = function redisTimed(command, stream) {
    try {
      timeIoredisCommand(this, command, stream, get);
    } catch {
      // not timed
    }
    return send.apply(this, arguments);
  };
  for (const name of ["pipeline", "multi"]) {
    const make = client[name];
    if (typeof make !== "function") continue;
    client[name] = function redisBatch(...args) {
      const batch = make.apply(this, args);
      try {
        // With enableAutoPipelining, ioredis gathers the app's separate
        // commands (from any request) into pipelines of its own, made here:
        // each of those commands is timed on its own, from where the app sent it.
        if (name === "pipeline" && args.length === 0 && this.options?.enableAutoPipelining) watchIoredisSingles(batch, get);
        // multi({ pipeline: false }) sends MULTI at once and hands back a
        // promise: its commands are then timed one by one.
        else if (batch && typeof batch.exec === "function") watchIoredisBatch(batch, name === "multi" ? "MULTI" : "PIPELINE", args[0], get);
      } catch {
        // not timed
      }
      return batch;
    };
  }
}

function timeIoredisCommand(client, command, stream, get) {
  if (!command || typeof command !== "object" || stream?.isPipeline || seenCommands.has(command)) return;
  // Its handshake (AUTH, HELLO, SELECT, INFO). A command the app sends now
  // waits in the offline queue and comes back through here once it's ready.
  if (client.status === "connect") return;
  // Sent again from the offline queue, or after a redirection: timed once.
  seenCommands.add(command);
  timeIoredisReply(command, get);
}

// Times one ioredis Command from now to its reply, by its own resolve and reject.
function timeIoredisReply(command, get) {
  const { resolve, reject } = command;
  if (typeof resolve !== "function" || typeof reject !== "function" || !Array.isArray(command.args)) return;
  const done = redisStart(get, redisList, command.name, command.args);
  if (!done) return;
  command.resolve = function resolved(...args) {
    done(false);
    return resolve.apply(this, args);
  };
  command.reject = function rejected(...args) {
    done(true);
    return reject.apply(this, args);
  };
}

// A pipeline whose commands are each timed alone, as queued.
function watchIoredisSingles(pipeline, get) {
  const queue = pipeline?.sendCommand;
  if (typeof queue !== "function") return;
  pipeline.sendCommand = function queuedAlone(command) {
    try {
      if (command && typeof command === "object") timeIoredisReply(command, get);
    } catch {
      // not timed
    }
    return queue.apply(this, arguments);
  };
}

// ioredis's Pipeline: the commands it queues (its own sendCommand, or the
// list it was made with) name it; exec() times it.
function watchIoredisBatch(pipeline, prefix, initial, get) {
  const batch = { first: "", timed: false };
  if (Array.isArray(initial)) {
    for (const item of initial) if (Array.isArray(item)) firstOf(batch, redisList([item[0]], item, 1));
  }
  const queue = pipeline.sendCommand;
  if (typeof queue === "function") {
    pipeline.sendCommand = function queued(command) {
      try {
        if (!batch.first && Array.isArray(command?.args)) firstOf(batch, redisList([command.name], command.args));
      } catch {
        // not named by it
      }
      return queue.apply(this, arguments);
    };
  }
  const exec = pipeline.exec;
  pipeline.exec = function execTimed(...args) {
    // Once: a retry calls exec() again.
    if (batch.timed || !batch.first) return exec.apply(this, args);
    batch.timed = true;
    const done = redisStart(get, null, `${prefix} ${batch.first}`);
    return timeRedis(done, () => exec.apply(this, args), true, typeof args[args.length - 1] === "function");
  };
}

// node-redis 5 and later: every command reaches the client's sendCommand
// (client.sendCommand, or a typed command through it); multi() hands back a
// batch whose addCommand names it and whose exec() or execAsPipeline() times it.
function watchNodeRedis(client, get) {
  if (client[WRAPPED]) return;
  client[WRAPPED] = true;
  watchNodeRedisSend(client, get);
  watchNodeRedisMulti(client, get);
}

// node-redis's client.sendCommand(["SET", key, value]).
function watchNodeRedisSend(client, get) {
  const send = client.sendCommand;
  if (typeof send !== "function") return;
  client.sendCommand = function redisTimed(args) {
    let done = null;
    try {
      if (Array.isArray(args)) done = redisStart(get, redisList, args[0], args, 1);
    } catch {
      // not timed
    }
    return timeRedis(done, () => send.apply(this, arguments));
  };
}

// node-redis 4: typed commands (client.get()) skip the public sendCommand,
// so each is timed where the app calls it, on this client alone. Their
// arguments are the app's, not yet the command's: what the rule needs (the
// name and first key) is in the same place for nearly all of them.
function watchNodeRedis4(client, get) {
  if (client[WRAPPED]) return;
  client[WRAPPED] = true;
  const methods = new Map();
  for (let proto = client; proto && proto !== Object.prototype; proto = Object.getPrototypeOf(proto)) {
    for (const name of Object.getOwnPropertyNames(proto)) {
      if (methods.has(name)) continue;
      const value = Object.getOwnPropertyDescriptor(proto, name)?.value;
      if (typeof value === "function") methods.set(name, value);
    }
  }
  // GET and get, CLIENT_SETNAME and clientSetName: one command, its words.
  const commands = new Map();
  for (const name of methods.keys()) {
    if (/^[A-Z][A-Z0-9_]*$/.test(name) && name !== "MULTI") commands.set(name.replace(/_/g, ""), wordsOf4(name));
  }
  for (const [name, original] of methods) {
    if (name === "sendCommand" || name === "multi" || name === "MULTI") continue;
    const words = commands.get(name.toUpperCase());
    if (!words) continue;
    client[name] = function redisCommandTimed(...args) {
      let done = null;
      try {
        done = redisStart(get, named4, words, args);
      } catch {
        // not timed
      }
      return timeRedis(done, () => original.apply(this, args));
    };
  }
  watchNodeRedisSend(client, get);
  watchNodeRedisMulti(client, get);
}

// node-redis 4's method name as the command's words: CLIENT_SETNAME is
// CLIENT SETNAME, EVAL_RO is itself, ZRANGE_WITHSCORES is ZRANGE.
function wordsOf4(name) {
  const words = name.split("_");
  if (words.length === 1) return words;
  if (REDIS_CONTAINERS.has(words[0])) return [words[0], words.slice(1).join("-")];
  return [words[1] === "RO" ? `${words[0]}_RO` : words[0]];
}

function named4(words, args) {
  let from = 0;
  // commandOptions({ isolated: true }) first: marked with a symbol.
  const first = args[0];
  if (first && typeof first === "object" && !Array.isArray(first) && !(first instanceof Uint8Array) && Object.getOwnPropertySymbols(first).length) from = 1;
  // xRead(streams, { BLOCK }): waiting, so not timed.
  if ((words[0] === "XREAD" || words[0] === "XREADGROUP") && args.some((arg) => arg && typeof arg === "object" && "BLOCK" in arg)) return null;
  return redisList(words, args, from);
}

// node-redis's multi(): one batch, named by the commands added to it and
// timed by exec() (MULTI, or PIPELINE with exec(true)) or execAsPipeline().
function watchNodeRedisMulti(client, get) {
  for (const name of ["multi", "MULTI"]) {
    const make = client[name];
    if (typeof make !== "function") continue;
    client[name] = function redisMulti(...args) {
      const multi = make.apply(this, args);
      try {
        if (multi && typeof multi.exec === "function") watchNodeRedisBatch(multi, get);
      } catch {
        // not timed
      }
      return multi;
    };
  }
}

function watchNodeRedisBatch(multi, get) {
  const batch = { first: "", running: false };
  for (const name of ["addCommand", "sendCommand"]) {
    const add = multi[name];
    if (typeof add !== "function") continue;
    multi[name] = function added(args) {
      try {
        if (!batch.first && Array.isArray(args)) firstOf(batch, redisList([args[0]], args, 1));
      } catch {
        // not named by it
      }
      return add.apply(this, arguments);
    };
  }
  const timed = (original, prefixOf) => function execTimed(...args) {
    // exec(true) runs execAsPipeline(): timed once, as the pipeline.
    if (batch.running || !batch.first) return original.apply(this, args);
    const done = redisStart(get, null, `${prefixOf(args)} ${batch.first}`);
    batch.running = true;
    try {
      return timeRedis(done, () => original.apply(this, args), true);
    } finally {
      batch.running = false;
    }
  };
  const exec = multi.exec;
  const multiPrefix = (args) => (args[0] === true ? "PIPELINE" : "MULTI");
  multi.exec = timed(exec, multiPrefix);
  if (typeof multi.EXEC === "function") multi.EXEC = timed(multi.EXEC, multiPrefix);
  if (typeof multi.execAsPipeline === "function") multi.execAsPipeline = timed(multi.execAsPipeline, () => "PIPELINE");
}

// node-redis 5's client itself, under a proxy its withTypeMapping() or
// withCommandOptions() made over it: watched there, the proxy is too.
const selfOf = (db) => (db._self && typeof db._self === "object" ? db._self : db);

// What kind of database object db is, by the shape of each library's.
function kindOf(db) {
  if (!db || (typeof db !== "object" && typeof db !== "function")) return "";
  if (typeof db.$extends === "function") return "prisma";
  if (typeof db.sendCommand === "function" && typeof db.pipeline === "function" && typeof db.defineCommand === "function") return "ioredis";
  // node-redis: a client; a cluster, pool or sentinel runs its commands on
  // clients of its own, which aren't the app's to hand over.
  if (typeof db.nodeClient === "function" && typeof db.getMasters === "function") return "redis-other";
  const self = selfOf(db);
  if (typeof self.MULTI === "function" && typeof self.sendCommand === "function") {
    if (typeof self._executeCommand === "function") return "node-redis";
    if (typeof self.commandsExecutor === "function" && typeof self.multiExecutor === "function") return self.options?.legacyMode ? "redis-other" : "node-redis-4";
    if (typeof self.execute === "function" || typeof self._execute === "function") return "redis-other";
  }
  if (typeof db === "function" && db.client && typeof db.on === "function") return "knex";
  if (typeof db.db === "function" && "monitorCommands" in db && typeof db.on === "function") return "mongodb";
  if (typeof db.getClient === "function" && typeof db.getClient()?.db === "function") return "mongoose";
  if (typeof db.query !== "function") return "";
  if (CLICKHOUSE_METHODS.every((name) => typeof db[name] === "function") && typeof db.ping === "function") return "clickhouse";
  // pg first: a pg Client's own connection has query() and execute() too.
  if (typeof db.connect === "function" && "totalCount" in db && "idleCount" in db) return "pg-pool";
  if (db.connectionParameters && typeof db.connectionParameters === "object") return "pg";
  // mysql2's promise pool and connection run on the callback ones they hold:
  // those are watched, so the promise ones' queries count once.
  if (typeof db.pool?.getConnection === "function" && typeof db.pool.query === "function") return "mysql-promise-pool";
  if (typeof db.connection?.query === "function" && typeof db.connection.execute === "function") return "mysql-promise";
  if (typeof db.getConnection === "function") return "mysql-pool";
  if (typeof db.execute === "function") return "mysql";
  return "";
}

// Returns db (a Prisma client: the extended one, to use in its place).
function watchDatabase(db, get, log = () => {}) {
  try {
    // Inside the try: a getter or proxy that throws on being looked at is
    // left alone, not thrown into the app.
    const kind = kindOf(db);
    if (kind === "prisma") return watchPrisma(db, get);
    if (kind === "knex") watchKnex(db, get);
    else if (kind === "mongodb") watchMongo(db, get);
    else if (kind === "mongoose") watchMongo(db.getClient(), get);
    else if (kind === "mysql-pool") watchPool(db, "mysql", ["query", "execute"], "getConnection", get);
    else if (kind === "mysql-promise-pool") watchPool(db.pool, "mysql", ["query", "execute"], "getConnection", get);
    else if (kind === "mysql-promise") ["query", "execute"].forEach((name) => wrapQuery(db.connection, name, "mysql", get));
    else if (kind === "mysql") ["query", "execute"].forEach((name) => wrapQuery(db, name, "mysql", get));
    else if (kind === "pg-pool") watchPool(db, "postgresql", ["query"], "connect", get);
    else if (kind === "pg") wrapQuery(db, "query", "postgresql", get);
    else if (kind === "clickhouse") watchClickHouse(db, get);
    else if (kind === "ioredis") watchIoredis(db, get);
    else if (kind === "node-redis") watchNodeRedis(selfOf(db), get);
    else if (kind === "node-redis-4") watchNodeRedis4(db, get);
    else if (kind === "redis-other") log("watchDatabase: a node-redis cluster, pool, sentinel or legacy-mode client isn't timed; watch a single createClient() client");
    else log("watchDatabase: not a pg, mysql2, mongodb, knex, Prisma, ClickHouse or Redis object; its queries aren't timed");
  } catch (error) {
    log("watchDatabase: could not watch it:", error?.message);
  }
  return db;
}

// ---- Recording ----

function addTo(entry, ms, failed) {
  entry.count += 1;
  if (failed) entry.errors += 1;
  entry.sum_ms += ms;
  if (ms > entry.max_ms) entry.max_ms = ms;
  entry.buckets[bucketOf(ms)] += 1;
  return entry;
}

const measures = () => ({ count: 0, errors: 0, sum_ms: 0, max_ms: 0, buckets: emptyBuckets() });

// The two kinds of timing filed per request and then per minute: queries
// (sdk/protocols/queries.md) by database and statement, and outgoing calls
// (calls.md) by call method and host. Each names its two key fields, the
// (other) entry a capped key folds into, and where its rows go.
const KINDS = {
  queries: { path: "/events/server-queries", fields: ["db", "statement"], other: (e) => ({ db: e.db, statement: OTHER_STATEMENT }) },
  calls: { path: "/events/server-calls", fields: ["call_method", "host"], other: (e) => ({ call_method: e.call_method, host: OTHER_HOST }) },
};
const OTHER_HOST = "(other)";
const keyOf = (kind, entry) => KINDS[kind].fields.map((field) => entry[field]).join("\n");

// The host of an outgoing call as calls.md stores it: lower case, the port
// only when it isn't the scheme's own (URL drops those). "" when it isn't one.
function normalAddress(url) {
  try {
    const parsed = new URL(url);
    return `${parsed.origin}${parsed.pathname.replace(/\/+$/, "")}`;
  } catch {
    return "";
  }
}

function hostOfUrl(url) {
  try {
    const host = new URL(url).host.toLowerCase();
    return /^[a-z0-9._\-[\]:]{1,255}$/.test(host) ? host : "";
  } catch {
    return "";
  }
}

// Options: serverName (default the host name); queries and calls (false
// leaves one out); runtime and timer: false (no minute timer: whoever
// records flushes) for hono.js.
function createQueries(core, options = {}) {
  const log = (...args) => core.log("queries", ...args);
  const serverName = String(options.serverName ?? hostname()).slice(0, 100);
  const runtime = options.runtime || `Node ${globalThis.process?.versions?.node || ""}`;
  const kinds = Object.keys(KINDS).filter((kind) => options[kind] !== false);
  // The request or job a query or call runs in: { holder, outer }, where
  // holder is the request object (or the job's) and outer counts the
  // queries an ORM above the driver is timing (the driver skips them).
  const storage = (() => {
    try {
      const Storage = globalThis.AsyncLocalStorage ?? builtin("async_hooks")?.AsyncLocalStorage;
      return typeof Storage === "function" ? new Storage() : null;
    } catch {
      return null;
    }
  })();
  // holder -> { queries: Map, calls: Map } (key -> entry) while it runs,
  // then { done, method, route } once finished: a query or call it didn't
  // wait for still has a row.
  const requests = new WeakMap();
  const cache = new Map();
  // kind -> { rows: key -> row, keysIn: minute -> rows it has }
  const minutes = Object.fromEntries(kinds.map((kind) => [kind, { rows: new Map(), keysIn: new Map() }]));
  let sending = Promise.resolve();
  let closed = false;

  const on = () => core.isOn("performance");

  function shape(text, db) {
    if (db === "mongodb" || text.length > CACHE_TEXT_MAX) return normalizeStatement(text, db);
    const key = `${db}\n${text}`;
    let statement = cache.get(key);
    if (statement === undefined) {
      if (cache.size >= CACHE_MAX) cache.clear();
      statement = normalizeStatement(text, db);
      cache.set(key, statement);
    }
    return statement;
  }

  // Adds entry (one query or call, or a request's sum of one) to its minute's row.
  function addToMinute(kind, method, route, entry) {
    const { rows, keysIn } = minutes[kind];
    const minute = Math.floor(Date.now() / 60000) * 60000;
    let fields = entry;
    let key = `${minute}|${method}|${route}|${keyOf(kind, fields)}`;
    // The cap is per minute: rows of a minute not yet sent don't count.
    const used = keysIn.get(minute) || 0;
    if (!rows.has(key) && used >= MAX_KEYS) {
      fields = KINDS[kind].other(entry);
      key = `${minute}|${method}|${route}|${keyOf(kind, fields)}`;
    }
    let row = rows.get(key);
    if (!row && used >= HARD_MAX_KEYS) return;
    if (!row) {
      const [a, b] = KINDS[kind].fields;
      row = { minute, method, route, [a]: fields[a], [b]: fields[b], ...measures() };
      rows.set(key, row);
      keysIn.set(minute, used + 1);
    }
    row.count += entry.count;
    row.errors += entry.errors;
    row.sum_ms += entry.sum_ms;
    if (entry.max_ms > row.max_ms) row.max_ms = entry.max_ms;
    entry.buckets.forEach((n, i) => { row.buckets[i] += n; });
  }

  // One query or call that ran (fields: its two key fields), in store's
  // request (or none).
  function add(kind, store, fields, ms, failed) {
    const holder = store?.holder;
    let request = holder ? requests.get(holder) : null;
    if (holder && !request?.done) {
      if (!request) {
        request = {};
        requests.set(holder, request);
      }
      const map = (request[kind] ||= new Map());
      let filed = fields;
      let entry = map.get(keyOf(kind, filed));
      if (!entry && map.size >= MAX_PER_REQUEST) {
        filed = KINDS[kind].other(fields);
        entry = map.get(keyOf(kind, filed));
      }
      if (!entry) {
        entry = { ...filed, ...measures() };
        map.set(keyOf(kind, filed), entry);
      }
      addTo(entry, ms, failed);
      return;
    }
    const { method, route } = request?.done ? request : BACKGROUND;
    addToMinute(kind, method, route, addTo({ ...fields, ...measures() }, ms, failed));
  }

  // The recorder the database watchers use.
  const recorder = {
    // A query starting now: what end() needs, or null when it isn't timed
    // (Server speed off, queries: false; or a driver's query an ORM above
    // it is timing, unless this is that ORM: outerLayer).
    begin(outerLayer = false) {
      // After close(): nothing sends the rows any more, so none are kept.
      if (closed || !minutes.queries || !on()) return null;
      const store = storage?.getStore() ?? null;
      if (!outerLayer && store?.outer > 0) return null;
      return { store, started: clock(), done: false };
    },
    end(timing, db, text, failed, ms) {
      try {
        const statement = shape(text, db);
        if (!statement) return;
        add("queries", timing.store, { db, statement }, Number.isFinite(ms) && ms >= 0 ? ms : clock() - timing.started, failed);
      } catch (error) {
        log("could not count a query:", error?.message);
      }
    },
    // Runs fn as an ORM's query: the driver's hooks inside it skip it.
    outer(fn) {
      return storage ? storage.run({ holder: storage.getStore()?.holder ?? null, outer: 1 }, fn) : fn();
    },
    // Runs fn as a database client's own work: the HTTP requests it makes
    // (ClickHouse's) aren't counted as outgoing calls.
    database(fn) {
      return storage ? storage.run({ holder: null, outer: 0, ...storage.getStore(), database: true }, fn) : fn();
    },
  };

  // ---- Outgoing calls ----
  // Node's diagnostics channels (public, for the life of the process): fetch()
  // through undici's, and http.request() and what's built on it (axios, got,
  // node-fetch) through http's. A call is timed from being sent to its
  // response's headers. The package's own calls to the collector aren't.
  const pendingCalls = new WeakMap(); // the library's request object -> started
  const subscribed = [];
  // As the libraries write an address: lower case, no default port.
  const ownAddress = normalAddress(core.endpoint);
  function callStarted(request, url) {
    if (!on() || storage?.getStore()?.database) return;
    const address = String(url).split(/[?#]/)[0];
    const normal = ownAddress && normalAddress(address);
    if (ownAddress && (normal === ownAddress || normal.startsWith(`${ownAddress}/`))) return;
    const host = hostOfUrl(address);
    const callMethod = String(request?.method || "GET").toUpperCase();
    if (!host || !/^[A-Z]{1,10}$/.test(callMethod)) return;
    pendingCalls.set(request, { store: storage?.getStore() ?? null, started: clock(), fields: { call_method: callMethod, host } });
  }
  function callEnded(request, status) {
    const started = pendingCalls.get(request);
    if (!started) return;
    pendingCalls.delete(request);
    try {
      add("calls", started.store, started.fields, clock() - started.started, !(status > 0 && status < 500));
    } catch (error) {
      log("could not count a call:", error?.message);
    }
  }
  function callFailed(request, error) {
    // Cancelled by the app: not a failure of the other side, and not a wait.
    if (error?.name === "AbortError") pendingCalls.delete(request);
    else callEnded(request, 0);
  }
  if (minutes.calls) {
    const channels = builtin("diagnostics_channel");
    const watch = (name, fn) => {
      if (typeof channels?.subscribe !== "function") return;
      // A subscriber that throws reaches the app as an uncaught exception.
      const listener = (message) => {
        try {
          fn(message);
        } catch {
          // the call is left out
        }
      };
      channels.subscribe(name, listener);
      subscribed.push(() => channels.unsubscribe(name, listener));
    };
    watch("undici:request:create", ({ request }) => callStarted(request, `${request.origin}${request.path}`));
    watch("undici:request:headers", ({ request, response }) => callEnded(request, response.statusCode));
    watch("undici:request:error", ({ request, error }) => callFailed(request, error));
    watch("http.client.request.start", ({ request }) => callStarted(request,
      `${request.protocol}//${request.getHeader?.("host") || request.host}${request.path}`));
    watch("http.client.response.finish", ({ request, response }) => callEnded(request, response.statusCode));
    watch("http.client.request.error", ({ request, error }) => callFailed(request, error));
  }

  // Runs next (the rest of the request) with holder as the request its
  // queries and calls belong to. Again for the same request (Fastify's
  // preHandler, after body parsing lost it) adds to the same one.
  function bind(holder, next) {
    return storage ? storage.run({ holder, outer: 0 }, next) : next();
  }

  // The request finished, counted by Server speed under method and route:
  // its queries and calls go into that minute's rows.
  function finish(holder, method, route) {
    if (!holder || (typeof holder !== "object" && typeof holder !== "function")) return;
    const request = requests.get(holder);
    const given = methodOf(method);
    requests.set(holder, { done: true, method: given, route });
    if (!request || request.done || !on()) return;
    for (const kind of kinds) {
      for (const entry of request[kind]?.values() || []) addToMinute(kind, given, route, entry);
    }
  }

  // Sends the rows of finished minutes (all of them with all = true).
  function flush(all = false) {
    const current = Math.floor(Date.now() / 60000) * 60000;
    for (const kind of kinds) {
      const { rows, keysIn } = minutes[kind];
      const ready = [];
      for (const [key, row] of rows) {
        if (all || row.minute < current) {
          ready.push({ ...row, minute: new Date(row.minute).toISOString(), sum_ms: Math.round(row.sum_ms * 10) / 10, max_ms: Math.round(row.max_ms * 10) / 10 });
          rows.delete(key);
        }
      }
      for (const minute of keysIn.keys()) if (all || minute < current) keysIn.delete(minute);
      for (let i = 0; i < ready.length; i += MAX_ROWS) {
        const body = { site_id: core.siteId, server_name: serverName, runtime, rows: ready.slice(i, i + MAX_ROWS) };
        sending = sending.then(() => core.send(kind, KINDS[kind].path, { auth: "bearer", body }));
      }
    }
    return sending;
  }

  const timer = core.valid && options.timer !== false ? setInterval(() => flush(), FLUSH_MS) : null;
  timer?.unref?.();

  return {
    watchDatabase: (db) => (minutes.queries ? watchDatabase(db, () => recorder, log) : db),
    recorder,
    bind,
    finish,
    flush: () => flush(true),
    close() {
      closed = true;
      clearInterval(timer);
      for (const stop of subscribed.splice(0)) stop();
      return flush(true);
    },
  };
}

module.exports = { createQueries, watchDatabase, ownRedis, mongoText, hostOfUrl, MAX_PER_REQUEST, MAX_KEYS, HARD_MAX_KEYS };
