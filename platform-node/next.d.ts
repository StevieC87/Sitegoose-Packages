export interface NextFirewallOptions {
  siteId: string;
  /** The site secret (site settings). Keep it in an environment variable. */
  secret: string;
  /** The collector's URL. */
  endpoint: string;
  /**
   * How to find the visitor's address. Default on Vercel: "vercel". Self-hosted
   * Next.js has no connection address in middleware: set the number of proxies
   * in X-Forwarded-For, "cloudflare", or a function.
   */
  trustProxy?: "vercel" | "cloudflare" | number | ((request: Request) => string);
  /** Overrides the mode set in the dashboard. */
  mode?: "monitor" | "block";
  /** Return true to leave a request unchecked. */
  skip?: (request: Request) => boolean;
  /** A counter shared between instances (e.g. Upstash Redis) for the rate limit and page limits: returns the hits so far. */
  counter?: (key: string, ttlSeconds: number) => Promise<number> | number;
  /** Names this deployment on the dashboard's Firewall tab (an edge instance has no machine name of its own). */
  serverName?: string;
  debug?: boolean;
}

/** Next.js middleware: returns a Response when blocked, else undefined (the request goes on). */
export function createNextFirewall(options: NextFirewallOptions):
  ((request: Request, event?: { waitUntil(promise: Promise<unknown>): void }) => Promise<Response | undefined>) & {
    /** A failed login from this address (bot protection): past the site's limit it is banned here and reported. */
    loginFailed(ip: string, event?: { waitUntil(promise: Promise<unknown>): void }): void;
    /** Sends the events waiting. */
    flush(): Promise<void>;
  };

export interface OnRequestErrorOptions {
  siteId: string;
  secret: string;
  endpoint: string;
  debug?: boolean;
}

/** For instrumentation.ts: export const onRequestError = createOnRequestError({...}). */
export function createOnRequestError(options: OnRequestErrorOptions):
  (error: unknown, request: { path: string; method: string; headers: Record<string, string | string[] | undefined> },
   context: { routePath?: string; routerKind?: string; routeType?: string }) => Promise<void>;
