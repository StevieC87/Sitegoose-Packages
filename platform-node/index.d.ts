import type { IncomingMessage, ServerResponse } from "node:http";

export type TrustProxy = boolean | number | "cloudflare" | ((req: IncomingMessage) => string);

export interface FirewallDecision {
  action: "allow" | "block" | "monitor";
  /** Empty when allowed. */
  rule: "deny" | "ban" | "list" | "shared" | "probe" | "rate" | "challenge" | `request:${string}` | `limit:${string}` | "";
  /** 403, 429 for the rate limit and a page limit, 503 for the browser check. */
  status: number;
  /** With a 429: the seconds to send as Retry-After (the limit's window). */
  retryAfter?: number;
  /** The browser check's page (rule "challenge"): send these headers and body as they are. */
  headers?: Record<string, string>;
  body?: string;
}

export interface FirewallOptions {
  /** Overrides the platform's trustProxy. */
  trustProxy?: TrustProxy;
  /** Overrides the mode set in the dashboard. */
  mode?: "monitor" | "block";
  /** Return true to leave a request unchecked. */
  skip?: (req: IncomingMessage) => boolean;
  /** The path and query your router sees, when it isn't the URL (a prefix stripped first). Defaults to the URL, an absolute-form one cut to its path. */
  path?: (req: IncomingMessage) => string;
  /** Send your own response for blocked requests (not for the browser check, whose page lets a browser through). */
  onBlock?: (req: IncomingMessage, res: ServerResponse, decision: FirewallDecision) => void;
  /** Keeps the last rules on disk, so they apply straight after a restart. */
  cacheFile?: string;
}

export interface ErrorsOptions {
  /** Default: the host name. */
  serverName?: string;
  /** Paths in stacks are made relative to it. Default: process.cwd(). */
  root?: string;
  /** Capture uncaught exceptions and unhandled rejections. Default true. */
  captureUncaught?: boolean;
  /** Also send errors your code logs: the first Error passed to console.error. Default false. */
  captureConsole?: boolean;
  /** Where errors that couldn't be sent wait until they can be (after a restart too). Default: the temp folder; false keeps none. */
  spoolDir?: string | false;
  /** Change an error before it's sent, or return null to drop it. */
  beforeSend?: (event: Record<string, unknown>, error: unknown) => Record<string, unknown> | null;
}

export interface PlatformOptions {
  /** Default: ANALYTICS_SITE_ID. */
  siteId?: string;
  /** The site secret (site settings). Keep it on the server. Default: ANALYTICS_SITE_SECRET. */
  secret?: string;
  /** The collector's URL. Default: ANALYTICS_ENDPOINT. */
  endpoint?: string;
  /**
   * How to find the visitor's address. Default: Express's req.ip (Fastify's,
   * Koa's), else the connection's address; a framework setting that trusts
   * every hop is read as one. A number trusts that many proxies in
   * X-Forwarded-For (true = 1); "cloudflare" reads CF-Connecting-IP, only from Cloudflare's own addresses.
   * Default: ANALYTICS_TRUST_PROXY ("cloudflare", "true" or a number).
   */
  trustProxy?: TrustProxy;
  /** Names this service (backend, worker…) on its errors, timings, resources, packages and setup. Default: ANALYTICS_SERVER_NAME, else the host name. */
  serverName?: string;
  /** How long close() may take in all, in milliseconds. Default 5000. */
  closeTimeoutMs?: number;
  /** Logs send problems. */
  debug?: boolean;
  /** On by default. */
  firewall?: boolean | FirewallOptions;
  /** On by default. */
  errors?: boolean | ErrorsOptions;
  /** On by default. */
  analytics?: boolean;
  /** Security headers picked on the dashboard. On by default (adds none until you pick some). */
  headers?: boolean;
  /** Feature flags. On by default. */
  flags?: boolean;
  /** Maintenance mode. On by default (does nothing until you turn it on in the dashboard). */
  maintenance?: boolean | { skip?: (req: IncomingMessage) => boolean };
  /** Audit log. On by default. */
  audit?: boolean;
  /** Form protection. On by default. */
  forms?: boolean;
  /**
   * Software inventory: your production packages (from npm-shrinkwrap.json,
   * package-lock.json, pnpm-lock.yaml, yarn.lock or bun.lock) and Node
   * version, sent once a day for the Security check. On by default.
   */
  inventory?: boolean | {
    /** The folder with the lock file and package.json. Default: the working directory. */
    dir?: string;
    /** The server's name. Default: the host name. */
    host?: string;
  };
  /**
   * How the server is set up, sent once a day for the Security check: whether
   * the app runs in production and as root, code anyone on the machine can
   * write, and files in the folders you serve to the web that shouldn't be
   * public (a dump, a .env, a backup copy). Reads only; no file's contents are
   * sent. On by default; with no served folder, only the settings are reported.
   */
  posture?: boolean | {
    /** The folders the web serves. Default: ./public and ./static when they exist. */
    roots?: (string | { dir: string; prefix?: string })[];
    /** The server's name. Default: the host name. */
    host?: string;
    /** More checks of your own: { id, state: "pass" | "fail" | "unknown", value? }. */
    checks?: () => Promise<{ id: string; state: string; value?: string }[]> | { id: string; state: string; value?: string }[];
  };
  /**
   * First-party proxy: serve the tracker and take visits under this site's
   * own domain, so ad blockers have no address or filename of ours to
   * recognise. On by default; the page's script tag uses proxy.scriptUrl()
   * and proxy.collectUrl().
   */
  proxy?: boolean | {
    /** The path it answers on. Default: eight characters from the secret. */
    prefix?: string;
  };
  /** Performance & API monitoring. On by default. */
  performance?: boolean | {
    serverName?: string;
    /** Your own route name for a request ("" to use the default). */
    route?: (req: IncomingMessage) => string;
  };
  /** Database query timings from watchDatabase(), on Server speed's switch. false leaves them out. On by default. */
  queries?: boolean;
  /** Outgoing HTTP call timings by host (fetch, http, https and what's built on them), on Server speed's switch. false leaves them out. On by default. */
  calls?: boolean;
  /** Job queue readings from watchQueue(), on Server speed's switch. false leaves them out. On by default. */
  queues?: boolean;
  /** Search engines and AI bots that fetch your pages (Off-site → Crawlers). On by default. */
  crawlers?: boolean | { serverName?: string };
  /** The machine's CPU, load, memory and disks, and this app's limits: its container's caps, open files, heap and requests in progress. On by default, in every app. */
  resources?: boolean | { serverName?: string };
}

export interface EventFields {
  value?: string;
  numeric_value?: string | number;
  currency?: string;
  url?: string;
  event_label?: string;
  variant?: string;
  id?: string;
  session_id?: string;
  timestamp?: string;
  /** One occurrence: reuse it when sending the same occurrence again. */
  event_uid?: string;
  [key: string]: unknown;
}

/** User properties for identify(): name -> text, number or true/false. */
export type Traits = Record<string, string | number | boolean>;

export interface WithRequest {
  /** The request, to link to the visit (x-analytics-session header). */
  req?: IncomingMessage;
}

export interface Platform {
  /** The modules that are on. */
  modules: string[];
  /** The firewall module, for check() in frameworks without middleware. */
  firewall: {
    /**
     * accept and cookie are the request's headers: the browser check needs
     * them, and checks nothing without an Accept that asks for text/html.
     */
    check(input: { ip: string; method?: string; path?: string; userAgent?: string; accept?: string; cookie?: string }): FirewallDecision;
    clientIp(req: IncomingMessage): string;
  } | null;
  /**
   * The first-party proxy's two addresses, on this site's own domain, for the
   * script tag: <script src={scriptUrl()} data-collect={collectUrl()} ...>.
   */
  proxy: {
    /** The path it answers on. */
    prefix: string;
    /** The tracker's address, e.g. "/3f9a2c1b/js/v1/s.js". */
    scriptUrl(version?: string): string;
    /** Where visits are sent, e.g. "/3f9a2c1b/api/e". */
    collectUrl(): string;
    /** Whether it is on (it can also be switched off in the dashboard). */
    enabled(): boolean;
  } | null;
  /** Before your routes. */
  middleware(): (req: IncomingMessage, res: ServerResponse, next?: (err?: unknown) => void) => void;
  /** After your routes. Captures 5xx errors and passes them on. */
  errorHandler(options?: { shouldCapture?: (error: unknown, req: IncomingMessage) => boolean }):
    (error: unknown, req: IncomingMessage, res: ServerResponse, next: (err?: unknown) => void) => void;
  /**
   * Fastify 4 and 5, in place of middleware() and errorHandler():
   * `await fastify.register(platform.fastify())`. Captures 5xx errors;
   * shouldCapture gets Fastify's request.
   */
  fastify(options?: { shouldCapture?: (error: unknown, request: any) => boolean }):
    (instance: any, options: any, done: (err?: Error) => void) => void;
  /**
   * Koa 2 and 3, in place of middleware() and errorHandler(): `app.use(platform.koa())`,
   * first. Captures 5xx errors; shouldCapture gets Koa's ctx.
   */
  koa(options?: { shouldCapture?: (error: unknown, ctx: any) => boolean }):
    (ctx: any, next: () => Promise<unknown>) => Promise<void>;
  /** Checks a form before you accept it (form protection). Spam goes to Leads → Spam. */
  checkForm(req: IncomingMessage | null, options?: { fields?: Record<string, unknown>; email?: string; name?: string; form?: string }):
    Promise<{ ok: boolean; spam: boolean; reasons: string[]; checked: boolean }>;
  /** Express middleware for a form route (after your body parser): spam gets a 422. */
  protectForm(options?: { email?: string; name?: string; form?: string; onSpam?: (req: IncomingMessage, res: ServerResponse, result: { reasons: string[] }) => void }):
    (req: IncomingMessage, res: ServerResponse, next?: (err?: unknown) => void) => void;
  /** A feature flag from the dashboard. user: for rollouts and user lists; default: until it's known (false). */
  isEnabled(key: string, options?: { user?: string | number; default?: boolean }): boolean;
  /** Records who did what (Security → Audit log). action: e.g. "user.role_changed". */
  audit(action: string, options?: { actor?: string; target?: string; details?: unknown; req?: IncomingMessage }): void;
  /** A failed login on your site (bot protection): the request, or the address. */
  loginFailed(reqOrIp: IncomingMessage | string): void;
  /** Runs a background job: its errors are sent with the job's name as their route, and each run is timed. */
  job<T>(name: string, fn: () => T | Promise<T>): Promise<T>;
  /**
   * Times the queries run through a database object (Health → Server speed → Queries): a pg Pool or
   * Client, a mysql2 pool or connection, a MongoClient (Mongoose: mongoose.connection.getClient()),
   * knex, a Prisma client, a @clickhouse/client client, or a Redis client (ioredis Redis or Cluster,
   * node-redis createClient()). Returns it; a Prisma client comes back extended, to use in its place.
   */
  watchDatabase<T>(db: T): T;
  /**
   * Reads a job queue every minute (Health → Server speed → Jobs): a BullMQ Queue (its backlog, the
   * oldest job's wait and the jobs this process added), a BullMQ Worker (the jobs it finished), or a
   * Bull queue (both). Returns it.
   */
  watchQueue<T>(queue: T): T;
  captureException(error: unknown, context?: { req?: IncomingMessage; status?: number; kind?: "handled" | "error" | "rejection" | "logged" }): void;
  /** A step of your own in the trail shown before an error in this request or job. */
  addBreadcrumb(text: string): void;
  /** Returns the event's event_uid ("" when not queued). */
  track(name: string, fields?: EventFields, options?: WithRequest): string;
  /**
   * Links the visit to your user ID. traits: what you know about the user (plan, seats...);
   * values other than text, numbers and true/false are left out.
   */
  identify(userId: string, options?: WithRequest & { session_id?: string; traits?: Traits }): Promise<boolean>;
  /** Adds or updates a lead. */
  lead(fields: Record<string, unknown>, options?: WithRequest): Promise<{ status: string; lead_id: string } | null>;
  /** Resolves once each module that fetches something has tried once. */
  ready: Promise<void>;
  /** Sends everything waiting (serverless: before returning). */
  flush(): Promise<void>;
  /** Stops background work and sends what's waiting. */
  close(): Promise<void>;
}

/** Every option left out of siteId, secret, endpoint, trustProxy and serverName is read from the environment (ANALYTICS_*). */
export function createPlatform(options?: PlatformOptions): Platform;
