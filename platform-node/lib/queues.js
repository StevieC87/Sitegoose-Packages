// Job queues (sdk/protocols/queues.md): platform.watchQueue(queue) reads a
// BullMQ (or Bull) queue once a minute — how many jobs wait, run, are delayed
// or kept as failed, and how long the oldest waiting one has waited — and
// counts the jobs this process added to it and, given a Worker, finished.
// One row per queue a minute to POST /events/server-queues, for Health →
// Server speed → Jobs. Rides on the performance module's switch; queues:
// false leaves them out.
//
// Only the queue's public API and events are used (getJobCounts, getJobs,
// "waiting", "completed", "failed"); BullMQ's addBulk, which sends no
// "waiting", is wrapped on the watched queue alone, never on its class. Jobs a
// FlowProducer adds aren't counted. Every
// process watching one queue reads the same gauges, and the dashboard takes
// the largest, so watching it in each web server and worker is fine.
"use strict";

const { randomBytes } = require("node:crypto");
const { hostname } = require("./performance.js");
// Our reads of a queue go through its Redis connection, which the app may
// also have handed to watchDatabase(): run inside ownRedis, they aren't timed.
const { ownRedis } = require("./queries.js");

const SAMPLE_MS = 60 * 1000;
// A queue whose Redis doesn't answer is skipped for that minute.
const READ_TIMEOUT_MS = 5000;
const MAX_QUEUES = 100;
const MAX_ROWS = 500;
const WATCHED = Symbol.for("analytics-platform.queue");

const count = (value) => (Number.isFinite(Number(value)) ? Math.max(0, Math.round(Number(value))) : 0);

// Bull's Queue runs its own jobs (process()); BullMQ's leaves that to a Worker.
const isQueue = (x) => typeof x?.getJobCounts === "function" && typeof x?.add === "function" && typeof x?.name === "string";
// getNextJob: a Worker's, which QueueEvents (every worker's jobs, not this one's) lacks.
const isWorker = (x) => !isQueue(x) && typeof x?.on === "function" && typeof x?.getNextJob === "function" && typeof x?.name === "string";
const systemOf = (x) => (typeof x.process === "function" && typeof x.getJobCounts === "function" ? "bull" : "bullmq");

// Where the queue lives: host, port and Redis database (or a socket's name),
// never the password or user in the connection options.
function brokerOf(x) {
  const connection = x.opts?.connection ?? x.client ?? x.clients?.[0];
  const options = connection?.options ?? connection ?? {};
  const db = Number(options.db) || 0;
  if (typeof options.path === "string" && options.path) return `${options.path.split("/").pop().slice(0, 80)}/${db}`;
  const host = String(options.host || "localhost").replace(/[@\s/]/g, "").slice(0, 120) || "localhost";
  return `${host}:${Number(options.port) || 6379}/${db}`;
}

// The queue's name, with its key prefix when it isn't the default.
function nameOf(x) {
  const prefix = x.opts?.prefix ?? x.keyPrefix;
  const name = String(x.name).slice(0, 150);
  return prefix && prefix !== "bull" ? `${String(prefix).slice(0, 40)}:${name}` : name;
}

function within(promise, ms) {
  let timer;
  return Promise.race([
    promise,
    new Promise((resolve, reject) => {
      timer = setTimeout(() => reject(new Error("timed out")), ms);
      timer.unref?.();
    }),
  ]).finally(() => clearTimeout(timer));
}

// Options: serverName (default the host name); timer: false (sample() is
// called by hand, for tests).
function createQueues(core, options = {}) {
  const log = (...args) => core.log("queues", ...args);
  const serverName = String(options.serverName ?? hostname()).slice(0, 100);
  const runtime = options.runtime || `Node ${globalThis.process?.versions?.node || ""}`;
  // This process, so the collector can tell a reading resent after a failed
  // answer from another process's on the same machine with the same counts.
  const sender = randomBytes(8).toString("hex");
  // system|broker|queue -> { system, broker, queue, readers: [Queue], added, finished }
  const watched = new Map();
  let sending = Promise.resolve();

  const on = () => core.isOn("performance");

  function entryFor(x) {
    const system = systemOf(x);
    const broker = brokerOf(x);
    const queue = nameOf(x);
    const key = `${system}|${broker}|${queue}`;
    let entry = watched.get(key);
    if (!entry) {
      if (watched.size >= MAX_QUEUES) return null;
      entry = { system, broker, queue, readers: [], added: 0, finished: 0, counted: { added: false, finished: false } };
      watched.set(key, entry);
    }
    return entry;
  }

  // Returns x. A Queue is read every minute and its adds counted; a Worker
  // (BullMQ) has the jobs it finishes counted. Bull's Queue is both.
  function watchQueue(x) {
    try {
      if ((!isQueue(x) && !isWorker(x)) || x[WATCHED]) {
        if (!x?.[WATCHED]) log("watchQueue: not a BullMQ Queue or Worker, or a Bull queue; not watched");
        return x;
      }
      const entry = entryFor(x);
      if (!entry) {
        log(`watchQueue: already watching ${MAX_QUEUES} queues; this one isn't`);
        return x;
      }
      x[WATCHED] = true;
      const finished = () => {
        if (on()) entry.finished += 1;
      };
      // "failed" comes on every attempt; only the last sets finishedOn (a
      // retried job goes back to wait or delayed).
      const failed = (job) => {
        if (job?.finishedOn) finished();
      };
      if (isQueue(x)) {
        entry.readers.push(x);
        entry.counted.added = true;
        x.on?.("waiting", () => {
          if (on()) entry.added += 1;
        });
        const addBulk = x.addBulk;
        if (systemOf(x) === "bullmq" && typeof addBulk === "function") {
          x.addBulk = function addBulkCounted(...args) {
            const added = addBulk.apply(this, args);
            Promise.resolve(added).then((jobs) => {
              if (on() && Array.isArray(jobs)) entry.added += jobs.length;
            }, () => {});
            return added;
          };
        }
      }
      // A BullMQ Worker's, or Bull's queue running its own jobs.
      if (isWorker(x) || systemOf(x) === "bull") {
        entry.counted.finished = true;
        x.on?.("completed", finished);
        x.on?.("failed", failed);
      }
    } catch (error) {
      log("watchQueue: could not watch it:", error?.message);
    }
    return x;
  }

  // The gauges of one queue now, or null when its Redis didn't answer.
  async function read(reader) {
    const counts = await within(ownRedis(() => reader.getJobCounts()), READ_TIMEOUT_MS);
    const waiting = count(counts.waiting ?? counts.wait) + count(counts.prioritized) + count(counts.paused);
    // The oldest is read from the waiting list alone: prioritized jobs are
    // kept in priority order and a paused queue's in another list, so with
    // only those it is unknown, not 0.
    let oldest = waiting ? null : 0;
    if (count(counts.waiting ?? counts.wait)) {
      try {
        const [job] = await within(ownRedis(() => reader.getJobs(["waiting"], 0, 0, true)), READ_TIMEOUT_MS);
        // A delayed job waits from when its delay ended, not from when it was added.
        const at = Number(job?.timestamp) + (Number(job?.delay ?? job?.opts?.delay) || 0);
        if (Number.isFinite(at) && at > 0) oldest = Math.max(0, Math.round((Date.now() - at) / 1000));
      } catch {
        // unknown, not zero
      }
    }
    return { waiting, running: count(counts.active), delayed: count(counts.delayed), failed: count(counts.failed), oldest_s: oldest };
  }

  // One reading of every queue watched: a row each, sent at once.
  async function sample() {
    if (!watched.size || !on()) return null;
    const minute = new Date(Math.floor(Date.now() / 60000) * 60000).toISOString();
    const rows = [];
    for (const entry of watched.values()) {
      let gauges = null;
      for (const reader of entry.readers) {
        try {
          gauges = await read(reader);
          break;
        } catch (error) {
          log(`could not read queue ${entry.queue}:`, error?.message);
        }
      }
      const row = {
        minute, system: entry.system, broker: entry.broker, queue: entry.queue,
        waiting: null, running: null, delayed: null, failed: null, oldest_s: null,
        ...(gauges || {}),
        added: entry.counted.added ? entry.added : null,
        finished: entry.counted.finished ? entry.finished : null,
        shared: false,
      };
      entry.added = 0;
      entry.finished = 0;
      if (gauges || row.added !== null || row.finished !== null) rows.push(row);
    }
    for (let i = 0; i < rows.length; i += MAX_ROWS) {
      const body = { site_id: core.siteId, server_name: serverName, runtime, sender, rows: rows.slice(i, i + MAX_ROWS) };
      sending = sending.then(() => core.send("queues", "/events/server-queues", { auth: "bearer", body }));
    }
    return sending;
  }

  let busy = false;
  const tick = () => {
    if (busy) return;
    busy = true;
    sample().catch((error) => log("queue reading failed:", error?.message)).finally(() => {
      busy = false;
    });
  };
  const timer = core.valid && options.timer !== false ? setInterval(tick, SAMPLE_MS) : null;
  timer?.unref?.();

  return {
    watchQueue,
    sample,
    flush: () => sending,
    close() {
      clearInterval(timer);
      return sending;
    },
  };
}

module.exports = { createQueues, brokerOf, nameOf };
