// One package for a site's Node server, run from the analytics dashboard.
// Each module (lib/) is separate: only the ones turned on are loaded, and one
// failing never stops the others; the firewall in particular never waits on
// reporting. Every module shares the core's credentials and sending.
//
//   const platform = createPlatform({ siteId, secret, endpoint });
//   app.use(platform.middleware());   // before your routes
//   ...routes...
//   app.use(platform.errorHandler()); // after your routes
//
// A module is on with `true` (or its options as an object) and off with
// `false`; one that's loaded can also be switched off in the dashboard (Site
// settings → Server). No dependencies; Node 18+ (global fetch).
"use strict";

const { createCore, EXIT_DEADLINE_MS } = require("./lib/core.js");
const { clientIp } = require("./lib/firewall.js");

// Module name -> [loader, on by default].
const MODULES = {
  firewall: [(core, opts) => require("./lib/firewall.js").createFirewall(core, opts), true],
  errors: [(core, opts) => require("./lib/errors.js").createErrors(core, opts), true],
  analytics: [(core) => require("./lib/analytics.js").createAnalytics(core), true],
  performance: [(core, opts) => require("./lib/performance.js").createPerformance(core, opts), true],
  crawlers: [(core, opts) => require("./lib/crawlers.js").createCrawlers(core, opts), true],
  forms: [(core, opts) => require("./lib/forms.js").createForms(core, opts), true],
  headers: [(core) => require("./lib/headers.js").createHeaders(core), true],
  audit: [(core, opts) => require("./lib/audit.js").createAudit(core, opts), true],
  flags: [(core) => require("./lib/flags.js").createFlags(core), true],
  maintenance: [(core, opts) => require("./lib/maintenance.js").createMaintenance(core, opts), true],
  inventory: [(core, opts) => require("./lib/inventory.js").createInventory(core, opts), true],
  posture: [(core, opts) => require("./lib/posture.js").createPosture(core, opts), true],
  resources: [(core, opts) => require("./lib/resources.js").createResources(core, opts), true],
  proxy: [(core, opts) => require("./lib/proxy.js").createProxy(core, opts), true],
};

// Options left out are read from ANALYTICS_* (lib/env.js).
const { fromEnvironment } = require("./lib/env.js");

// Set by analytics-platform/start once it has made the process's platform.
const STARTED = Symbol.for("analytics-platform.started");

// Options: siteId, secret (site settings; keep it on the server), endpoint
// (the collector's URL); trustProxy (how to find the visitor's address, for
// every module that needs it: see README); debug (log send problems); and
// per module, true / false / { options }. Each of the first five left out is
// read from the environment (fromEnvironment above).
function createPlatform(given = {}) {
  if (globalThis[STARTED]) {
    console.warn("[analytics-platform] analytics-platform/start has already made this process's platform; a second one sends everything twice. Use `import platform from \"analytics-platform/start\"` instead of createPlatform().");
  }
  const options = fromEnvironment(given);
  const core = createCore(options);
  if (!core.valid) console.warn("[analytics-platform] siteId, secret and endpoint are required (or ANALYTICS_SITE_ID, ANALYTICS_SITE_SECRET and ANALYTICS_ENDPOINT in the environment); nothing is sent and every request passes");

  const modules = {};
  for (const [name, [load, onByDefault]] of Object.entries(MODULES)) {
    const setting = options[name] === undefined ? onByDefault : options[name];
    if (setting === false) continue;
    // serverName names this service for every module that sends one, so its
    // errors, timings and resources can be told apart from other services'.
    // Inventory and posture call it host, and are stored one per site and
    // host: without it two services on one machine overwrite each other's.
    const opts = {
      trustProxy: options.trustProxy,
      ...(options.serverName ? { serverName: options.serverName } : {}),
      ...(options.serverName && ["inventory", "posture"].includes(name) ? { host: options.serverName } : {}),
      ...(setting && typeof setting === "object" ? setting : {}),
    };
    // These find the visitor's address the way the firewall does, with the
    // same trustProxy, whether or not the firewall itself is on.
    if (["forms", "audit", "maintenance", "crawlers", "proxy"].includes(name)) {
      opts.clientIp = modules.firewall?.clientIp || ((req) => clientIp(req, options.trustProxy));
    }
    // A denied or banned address gets no tracker and no collector either.
    if (name === "proxy" && modules.firewall && opts.guard === undefined) opts.guard = modules.firewall.guard;
    try {
      modules[name] = load(core, opts);
    } catch (error) {
      console.warn(`[analytics-platform] the ${name} module could not start and is off:`, error?.message);
    }
  }

  // Errors name a request's route as Server speed does, so the two match.
  if (modules.errors && modules.performance) modules.errors.useRoutes(modules.performance.routeOf);
  // Resources report the most requests in progress at once, as timed there.
  if (modules.resources && modules.performance) modules.resources.useInflight(modules.performance.takeInflightPeak);

  // Database queries (watchDatabase) and outgoing calls, on Server speed's
  // switch: filed under the method and route Server speed counts each
  // request under. Not modules of their own; queries: false and calls:
  // false leave them out.
  let queries = null;
  if (modules.performance && (options.queries !== false || options.calls !== false)) {
    try {
      queries = require("./lib/queries.js").createQueries(core, {
        ...(options.serverName ? { serverName: options.serverName } : {}),
        queries: options.queries !== false,
        calls: options.calls !== false,
      });
      modules.performance.afterRequest(queries.finish);
    } catch (error) {
      console.warn("[analytics-platform] database query and call timing could not start and is off:", error?.message);
    }
  }
  // Job queues (watchQueue), on Server speed's switch too; queues: false leaves them out.
  let queues = null;
  if (modules.performance && options.queues !== false) {
    try {
      queues = require("./lib/queues.js").createQueues(core, options.serverName ? { serverName: options.serverName } : {});
    } catch (error) {
      console.warn("[analytics-platform] queue readings could not start and are off:", error?.message);
    }
  }

  const switches = core.start(Object.keys(modules));
  const off = (name) => () => core.log(name, "module is off");
  const { firewall, errors, analytics, performance, crawlers, forms, headers, audit, flags, maintenance, proxy } = modules;

  // Express / Connect / node:http middleware, before your routes: the
  // tracker's own addresses are answered first (a visitor's beacon is our
  // traffic, not a page of the site: it shouldn't be counted, timed or
  // rate-limited), then crawlers are counted (a crawler the firewall turns
  // away is still a crawler), then the firewall, then timing (blocked
  // requests aren't timed).
  function middleware() {
    // A request's database queries are its own from here on.
    const timing = (req, res, next) => performance.middleware(req, res, next);
    const timed = (req, res, next) => {
      if (!performance) return next();
      return queries ? queries.bind(req, () => timing(req, res, next)) : timing(req, res, next);
    };
    const open = (req, res, next) => (maintenance ? maintenance.middleware(req, res, () => timed(req, res, next)) : timed(req, res, next));
    const guarded = (req, res, next) => (firewall ? firewall.middleware(req, res, () => open(req, res, next)) : open(req, res, next));
    const counted = (req, res, next) => (crawlers ? crawlers.middleware(req, res, () => guarded(req, res, next)) : guarded(req, res, next));
    const withHeaders = (req, res, next) => (headers ? headers.middleware(req, res, () => counted(req, res, next)) : counted(req, res, next));
    const all = (req, res, next) => (proxy ? proxy.middleware(req, res, () => withHeaders(req, res, next)) : withHeaders(req, res, next));
    // Errors captured later in the request (logged, or caught without
    // passing req) still know which request they came from.
    return function platformMiddleware(req, res, next = () => {}) {
      return errors ? errors.bind(req, () => all(req, res, next)) : all(req, res, next);
    };
  }

  return {
    // The modules that are on, by name.
    modules: Object.keys(modules),
    firewall: firewall || null,
    // record({ bot, path, status, bytes, ms, ip }) and detect(userAgent), for
    // frameworks that aren't Express.
    crawlers: crawlers || null,
    // The first-party proxy: scriptUrl(major) and collectUrl() are the two
    // addresses the page's script tag needs, on this site's own domain.
    proxy: proxy || null,

    middleware,

    // Fastify 4 and 5, in place of middleware() and errorHandler():
    // await fastify.register(platform.fastify()). Captures 5xx errors.
    fastify(handlerOptions) {
      return require("./lib/fastify.js").createFastifyPlugin(middleware(), errors || null, handlerOptions, queries, Boolean(firewall));
    },

    // Koa 2 and 3, in place of middleware() and errorHandler():
    // app.use(platform.koa()), first. Captures 5xx errors.
    koa(handlerOptions) {
      return require("./lib/koa.js").createKoaMiddleware(middleware(), errors || null, handlerOptions);
    },

    // Express error middleware, after your routes. Captures 5xx errors.
    errorHandler(handlerOptions) {
      return errors ? errors.errorHandler(handlerOptions) : (error, req, res, next) => next(error);
    },

    captureException: errors ? errors.captureException : off("errors"),
    // A step of your own in the trail shown before an error in this request.
    addBreadcrumb: errors ? errors.addBreadcrumb : off("errors"),
    // A background job (a queue consumer, a cron task): job("send-receipts", async () => ...).
    // Its errors are sent with the job's name as their route, and each run is
    // timed (Health → Server speed → Jobs): a run that throws counts as failed.
    // Its database queries are filed under the route Server speed counted
    // the run under ("(other)" once a minute's routes are capped).
    async job(name, fn) {
      const route = `/(job) ${String(name || "job").slice(0, 180)}`;
      const started = process.hrtime.bigint();
      const holder = {};
      const timed = (status) => {
        const filed = performance?.record({ method: "JOB", route, status, ms: Number(process.hrtime.bigint() - started) / 1e6 });
        if (filed !== undefined) queries?.finish(holder, "JOB", filed);
      };
      const run = () => (errors ? errors.job(route, fn) : fn());
      try {
        const result = queries ? await queries.bind(holder, run) : await run();
        timed(200);
        return result;
      } catch (error) {
        timed(500);
        throw error;
      }
    },
    // Times the queries run through a database object (sdk/protocols/queries.md):
    // a pg Pool or Client, a mysql2 pool or connection, a MongoClient
    // (Mongoose: mongoose.connection.getClient()), knex, a Prisma client, a
    // @clickhouse/client client, or Redis (ioredis, node-redis createClient()).
    // Returns it; a Prisma client comes back extended, to use in its place.
    watchDatabase: (db) => (queries ? queries.watchDatabase(db) : db),
    // Reads a job queue once a minute (sdk/protocols/queues.md): a BullMQ
    // Queue (waiting, running, delayed, failed, the oldest job's wait, and
    // the jobs this process added), a BullMQ Worker (the jobs it finished),
    // or a Bull queue (both). Returns it.
    watchQueue: (queue) => (queues ? queues.watchQueue(queue) : queue),
    // A failed login (bot protection): pass the request, or the address.
    loginFailed: firewall ? firewall.loginFailed : off("firewall"),
    // Form protection: check a form before accepting it, or protect a route.
    checkForm: forms ? forms.checkForm : async () => ({ ok: true, spam: false, reasons: [], checked: false }),
    protectForm: forms ? forms.protectForm : () => (req, res, next) => next(),
    // Feature flags: isEnabled("new-checkout", { user }) (false until known).
    isEnabled: flags ? flags.isEnabled : (key, { default: fallback = false } = {}) => fallback,
    // Audit log: audit("user.role_changed", { actor, target, details, req }).
    audit: audit ? audit.audit : off("audit"),
    track: analytics ? analytics.track : () => (off("analytics")(), ""),
    identify: analytics ? analytics.identify : async () => (off("analytics")(), false),
    lead: analytics ? analytics.lead : async () => (off("analytics")(), null),

    // Resolves once each module that fetches something has tried once.
    ready: Promise.all([switches, ...Object.values(modules).map((m) => m.ready).filter(Boolean)]).then(() => undefined),

    // Sends everything waiting.
    flush: () => Promise.all([...Object.values(modules), queries, queues].map((m) => m?.flush?.())).then(() => undefined),

    // Stops background work and sends what's waiting (for a clean shutdown),
    // within one overall deadline (5 s; options.closeTimeoutMs): sends past
    // it aren't started, a failed error batch isn't retried, and the errors
    // still waiting then go to their file for the next start.
    close: () => {
      core.stop();
      const ms = Number(options.closeTimeoutMs) > 0 ? Number(options.closeTimeoutMs) : EXIT_DEADLINE_MS;
      core.within(ms);
      let timer = null;
      const late = new Promise((resolve) => {
        timer = setTimeout(resolve, ms + 100);
      });
      const all = Promise.all([...Object.values(modules), queries, queues].map((m) => Promise.resolve(m?.close?.()).catch(() => {})));
      return Promise.race([all, late]).then(() => {
        clearTimeout(timer);
        errors?.persist();
      });
    },
  };
}

module.exports = { createPlatform };
