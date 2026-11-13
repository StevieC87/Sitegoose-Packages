export interface HonoPlatformOptions {
  siteId: string;
  /** The site secret (site settings). Keep it in an environment variable or a Workers secret. */
  secret: string;
  /** The collector's URL. */
  endpoint: string;
  /**
   * How to find the visitor's address. Default: the connection's own address
   * (Node, Bun, Deno) or CF-Connecting-IP (Cloudflare Workers). Behind a proxy:
   * the number of proxies in X-Forwarded-For, "cloudflare", or a function of the context.
   */
  trustProxy?: "cloudflare" | number | ((c: any) => string);
  /** Overrides the firewall mode set in the dashboard. */
  mode?: "monitor" | "block";
  /** Return true to leave a request unchecked by the firewall. */
  skip?: (request: Request) => boolean;
  /** A rate-limit counter shared between instances (e.g. Upstash Redis): returns the hits so far. */
  counter?: (key: string, ttlSeconds: number) => Promise<number> | number;
  /** Names this service in Errors, Server speed and Crawlers. */
  serverName?: string;
  debug?: boolean;
  /** The ad blocker proxy: false turns it off; prefix picks its path (default: from the secret). */
  proxy?: boolean | { prefix?: string };
  /** The security headers picked on the dashboard. */
  headers?: boolean;
  /** Counts search engines and AI bots (Off-site → Crawlers). */
  crawlers?: boolean;
  firewall?: boolean;
  /** The "back soon" page while maintenance mode is on; skip(c) returning true lets a request through. */
  maintenance?: boolean | { skip?: (c: any) => boolean };
  /** Server speed. */
  performance?: boolean;
  /** Database query timings from watchDatabase(), on Server speed's switch. */
  queries?: boolean;
  /** Outgoing HTTP call timings by host, where the runtime has Node's diagnostics channels, on Server speed's switch. */
  calls?: boolean;
  /** Job queue readings from watchQueue(), in a process that stays up, on Server speed's switch. */
  queues?: boolean;
  errors?: boolean;
  /** checkForm() and protectForm(). */
  forms?: boolean;
  /** track(), identify() and lead(). */
  analytics?: boolean;
  audit?: boolean;
  /** isEnabled(). */
  flags?: boolean;
}

/** A Hono context, or anything with the env the options read: { env, executionCtx } in a Workers scheduled() handler. */
export type HonoContextLike = any;

export interface FormCheckOptions {
  /** The form's fields, instead of the request's body. */
  fields?: Record<string, unknown>;
  email?: string;
  name?: string;
  /** The form's name in the spam folder. */
  form?: string;
}

export interface FormCheckResult {
  ok: boolean;
  spam: boolean;
  reasons: string[];
  /** false when the check couldn't be made: the form is accepted. */
  checked: boolean;
}

export interface HonoProxyUrls {
  prefix: string;
  /** The tracker's address on this site's own domain, for the script tag's src. */
  scriptUrl(version?: string): string;
  /** The beacons' address on this site's own domain, for data-collect. */
  collectUrl(): string;
}

/**
 * Hono middleware, first: the ad blocker proxy, security headers, crawler
 * counts, the firewall, maintenance mode, Server speed and 5xx errors, on any runtime.
 * Pass a function of the context when the secret is in c.env (Cloudflare Workers).
 */
export function createHonoPlatform(options: HonoPlatformOptions | ((c: any) => HonoPlatformOptions)):
  ((c: any, next: () => Promise<void>) => Promise<Response | undefined>) & {
    /**
     * An error you caught yourself. Pass c, or leave it out where the runtime has
     * AsyncLocalStorage (Node, Bun, Deno, Workers with nodejs_compat).
     */
    captureException(error: unknown, c?: any, context?: { status?: number }): void;
    /** A step of your own in the trail sent with an error in this request. */
    addBreadcrumb(text: string, c?: any): void;
    /** Checks the form in this request before you accept it, leaving its body for the route. */
    checkForm(c: any, options?: FormCheckOptions): Promise<FormCheckResult>;
    /** Middleware for a form's route: spam gets a 422 (or onSpam); c.get("formCheck") holds the result. */
    protectForm(options?: FormCheckOptions & { onSpam?: (c: any, result: FormCheckResult) => Response | Promise<Response> }):
      (c: any, next: () => Promise<void>) => Promise<Response | undefined>;
    /**
     * The ad blocker proxy's addresses for the page's script tag; null when it's off.
     * With options that are a function of c, pass c (or { env }) until a request has come through.
     */
    proxy(c?: HonoContextLike): Promise<HonoProxyUrls | null>;
    /** A server event (value, numeric_value, currency, url, event_label, variant, id, session_id, timestamp, event_uid). Returns its event_uid ("" when not queued). */
    track(name: string, fields?: Record<string, unknown>, options?: { c?: any }): string;
    /** Links the visit (c's x-analytics-session, or session_id) to your user ID, with optional traits ({ plan: "pro", seats: 5 }). */
    identify(userId: string, options?: { c?: any; session_id?: string; traits?: Record<string, string | number | boolean> }): Promise<boolean>;
    /** Adds or updates a lead. */
    lead(fields: Record<string, unknown>, options?: { c?: any }): Promise<{ status: string; lead_id: string } | null>;
    /** Records who did what (Security → Audit log); c adds the actor's address and visit. */
    audit(action: string, options?: { actor?: string; target?: string; details?: unknown; c?: any }): void;
    /** A failed login (bot protection): c, or the address. */
    loginFailed(cOrIp: any): void;
    /** A feature flag from the dashboard. user: for rollouts and user lists; default: until it's known (false). */
    isEnabled(key: string, options?: { user?: string | number; default?: boolean }): boolean;
    /**
     * Runs a background job: its errors are sent with the job's name as their route, and each run is timed.
     * c: the request's, or { env, executionCtx } in a Workers scheduled() or queue() handler.
     */
    job<T>(name: string, fn: () => T | Promise<T>, c?: HonoContextLike): Promise<T>;
    /**
     * Times the queries run through a database object (pg, mysql2, MongoClient, knex, Prisma, ClickHouse, ioredis, node-redis),
     * from the first request on. Returns it; a Prisma client comes back extended, to use in its place.
     */
    watchDatabase<T>(db: T): T;
    /** Reads a BullMQ (or Bull) queue every minute, from the first request on. Returns it. */
    watchQueue<T>(queue: T): T;
    /** Sends everything waiting: before a serverless function returns, or a process exits. */
    flush(): Promise<void>;
  };
