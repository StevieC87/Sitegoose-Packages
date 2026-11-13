# analytics-platform

One package for your Node server, run from your analytics dashboard: a
**firewall**, **error monitoring** and **server analytics** (payments,
sign-ups, leads). Turn modules on or off; the ones you turn off aren't loaded.
No dependencies; Node 18 or later.

```bash
npm install analytics-platform
```

### The quick way: one line

Put your keys in `.env` (site settings has all three, ready to copy):

```bash
ANALYTICS_SITE_ID=YOUR_SITE_ID
ANALYTICS_SITE_SECRET=YOUR_SITE_SECRET
ANALYTICS_ENDPOINT=https://YOUR_COLLECTOR_URL
```

Then add this line at the top of the file that starts your server:

```js
import platform from "analytics-platform/start";   // CommonJS: require("analytics-platform/start")
```

**For Express, that's all.** It adds its middleware before your routes and
its error handler after them, in the same places the manual setup below puts
them. Routes you add after `listen()` are covered too, and your own error
handler still answers.

You can also leave your code alone and start Node with the line instead:
`node --import analytics-platform/start app.js` (or `--require`).
In PM2, Docker or a host's settings, set
`NODE_OPTIONS="--import analytics-platform/start"`.

- **No `.env` to load first.** It reads the three keys from the environment, or
  else from the `.env` in the folder the server starts in. It reads only the
  `ANALYTICS_*` lines and never writes them into `process.env`, so it doesn't
  matter where your own `dotenv` runs, or which `.env` files it loads.
- **Use `platform` anywhere.** Import the same line in your route files for
  `platform.track()`, `lead()`, `watchDatabase()` and the rest. It's one
  platform for the whole process, however many files import it.
- **Behind Nginx or a load balancer**, `app.set("trust proxy", 1)` is all it
  needs, as with the manual setup. **Behind Cloudflare**, add
  `ANALYTICS_TRUST_PROXY=cloudflare`. **Several services** sending to one
  site? Give each one `ANALYTICS_SERVER_NAME=api` (or `worker` and so on).
- **Deploys:** on `SIGTERM` it sends what's waiting before the process exits.
  If your app handles `SIGTERM` itself, your handler still decides when to exit.
- **Fastify, Koa, NestJS:** the same line, plus your framework's one line:
  `await fastify.register(platform.fastify())`, or `app.use(platform.koa())`
  first. NestJS needs only its error filter ([NestJS](#nestjs)); the
  middleware is added by itself.
- **Next.js** doesn't use this: see [Next.js and Vercel](#nextjs-and-vercel).
- Want module options in code (`errors: { captureConsole: true }`,
  `firewall: { mode: "monitor" }` and so on)? Use the manual setup below. Use
  one setup or the other: an app that has the two lines below gets nothing
  added a second time.

### Setting it up in code instead

In the file that creates your Express app (the one with `const app = express()`,
usually `app.js`, `index.js` or `server.js`). Create the platform **once**, at the
top level of that file: not inside a route, a route file or a request handler.
Then add it twice: first thing after `express()`, and last thing after your routes.

```js
// app.js
import express from "express";
import { createPlatform } from "analytics-platform";
import apiRoutes from "./routes/api.js";

const platform = createPlatform({
  siteId: "YOUR_SITE_ID",
  secret: process.env.ANALYTICS_SITE_SECRET, // site settings; keep it on the server
  endpoint: "https://YOUR_COLLECTOR_URL",
  // trustProxy: 1,            // behind Nginx or a load balancer
  // trustProxy: "cloudflare", // every request through Cloudflare
});

const app = express();

app.use(platform.middleware());   // 1. first, before body parsers, static files and routes

app.use(express.json());
app.use(express.static("public"));
app.use("/api", apiRoutes);
// ...your other routes...

app.use(platform.errorHandler()); // 2. last, after every route, before your own error handler

app.listen(3000);
```

- **Load your `.env` before `createPlatform()` runs.** It reads the secret
  the moment it runs, so a `dotenv.config()` below it is too late: the package
  prints `siteId, secret and endpoint are required`, sends nothing and lets
  every request through. Put `import "dotenv/config";` first in `app.js`, or
  start with `node --env-file=.env`. With `listen()` in `bin/www`, load it
  there *before* `import app from "../app.js"`: imports run before the rest of
  the file.
- **CommonJS (no `"type": "module"` in your package.json)?** Use
  `const { createPlatform } = require("analytics-platform");` instead of the
  `import`. Everything else is the same.
- **App in `app.js`, `listen()` in `server.js` or `bin/www`** (the
  express-generator layout): all of this goes in `app.js`, the file with
  `express()`. Leave `server.js` alone.
- **Using `platform.track()`, `lead()` or `audit()` in your route files?**
  Export it from a small module, `platform.js` (`export default createPlatform({...})`),
  and `import platform from "./platform.js"` in `app.js` and in the routes. A second
  `createPlatform()` would fetch the rules and send everything twice.
- **More than one app** (microservices, a worker, a separate API): install it
  in each, one site for all of them; see [Several apps](#several-apps-microservices-workers-a-separate-api).
- **Next.js** has no `app.js`: see [Next.js and Vercel](#nextjs-and-vercel).
  **NestJS** goes in `main.ts`, and its errors need a filter: see [NestJS](#nestjs).
  **Fastify**: `await fastify.register(platform.fastify())`, see [Fastify](#fastify).
  **Koa**: `app.use(platform.koa())`, see [Koa](#koa).
  **Hono, Bun, Deno, Cloudflare Workers**: see [Hono](#hono-bun-deno-cloudflare-workers).

## Modules

| Module | What it does | Default |
|---|---|---|
| `firewall` | Blocks addresses, known criminal networks, shared blocks and floods (Security → Firewall) | on |
| `firewall`'s attack patterns | Rules that match the *request* (its path, query string and user agent), not just the address, so an attack is turned away before your code runs — a package with a known hole stays safe until you update it. They come with the firewall's rules and are managed on the Security page (Firewall → Attack patterns); a pattern a real visitor might trip only watches until you promote it. Nothing to configure (protocol: `sdk/protocols/firewall.md`) | with the firewall |
| `proxy` | Serves the tracker and takes visits under your own domain, so ad blockers can't hide those visitors | on |
| `errors` | Sends your server's errors to the Errors report | on |
| `analytics` | `track()`, `identify()` and `lead()` from your server | on |
| `performance` | Response times and errors of every route (Health → Server speed) | on |
| `queries` | Database query timings per route from `platform.watchDatabase(db)` ([Database queries](#database-queries)); needs `performance` | on |
| `calls` | Time each route spends waiting on other services' APIs, by host, from `fetch`, `http` and `https` ([Outgoing calls](#outgoing-calls)); needs `performance` | on |
| `queues` | Job backlog from `platform.watchQueue(queue)`, BullMQ or Bull ([Job queues](#job-queues)); needs `performance` | on |
| `crawlers` | Which search engines and AI bots fetch your pages (Off-site → Crawlers). Your tracker can't see them: crawlers don't run JavaScript | on |
| `audit` | `platform.audit("user.role_changed", { actor, target, details, req })` (Security → Audit log) | on |
| `flags` | `platform.isEnabled("new-checkout", { user: user.id })`: features on or off from the dashboard | on |
| `maintenance` | A "back soon" page while maintenance mode is on in the dashboard | on |
| `headers` | Adds the security headers you pick on the Security page; your own headers win | on |
| `forms` | Checks forms before you accept them: `platform.protectForm()` / `platform.checkForm(req)` | on |
| `inventory` | Your production packages and Node version, once a day, so the Security check can flag known security holes. Read from `npm-shrinkwrap.json`, `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock` or `bun.lock`, the first of those it finds; `yarn.lock` also needs `package.json` beside it (and each workspace's), to tell production packages from development ones, and bun's older binary `bun.lockb` isn't read (`bun install --save-text-lockfile` writes `bun.lock`). `{ dir }`: the folder with the lock file | on |
| `posture` | How the server is set up, once a day, for the Security check: `NODE_ENV`, whether the app runs as root, code anyone on the machine can write, and files in the folders you serve to the web that shouldn't be public (a dump, a `.env`, a `.bak`). The dashboard then asks your site for each of those files and tells you whether it really is downloadable. Reads only, and sends no file's contents. `{ roots: ["public", { dir: "uploads", prefix: "files" }] }` (default: `./public` and `./static` when they exist; `prefix` is where the web serves the folder), `{ checks }` for checks of your own (protocol: `sdk/protocols/posture.md`) | on |

Each takes `true`, `false` or its options:

```js
createPlatform({
  siteId, secret, endpoint,
  firewall: { mode: "monitor", cacheFile: "./firewall-rules.json" },
  errors: { captureUncaught: false },
  analytics: false,
});
```

**Switch modules off in the dashboard** (Security → Server package) without a
deploy: the package checks about once a minute. A module turned off in your
code isn't loaded at all, so the dashboard can't turn it on.

Modules are independent: one failing to start, or the collector being down,
never stops the others, and never slows your requests. The firewall checks
requests against rules it keeps in memory; everything is sent in the
background, in batches.

## Firewall

Rules, monitor or block mode and reports are in the dashboard (Security →
Firewall). New sites start in monitor mode: nothing is blocked until you switch.

| Option | |
|---|---|
| `mode` | `"monitor"` or `"block"`; overrides the dashboard |
| `skip(req)` | return `true` to leave a request unchecked (health checks) |
| `path(req)` | the path and query your router really sees, when it isn't the URL: an app that strips a prefix (`/api/users` routed as `/users`) returns the stripped one, so a rule on `/users` still applies |
| `onBlock(req, res, decision)` | send your own response |
| `cacheFile` | keep the last rules between restarts |
| `trustProxy` | overrides the platform's |

**The visitor's address:** behind a proxy, every request comes from the proxy
unless you set `trustProxy`:

| Setup | Option |
|---|---|
| Express with `app.set("trust proxy", ...)` | nothing (uses `req.ip`) |
| One proxy (Nginx, a load balancer) | `trustProxy: 1` |
| Cloudflare → load balancer | `trustProxy: 2` |
| Every request through Cloudflare | `trustProxy: "cloudflare"` |

`"cloudflare"` believes `CF-Connecting-IP` only when the connection comes from
Cloudflare's own addresses (anyone who reaches your server directly can send
the header); from anywhere else the visitor is the connection's address.

- **A setting that trusts every proxy** makes the framework's address the
  first `X-Forwarded-For` entry, which is whatever the visitor typed there.
  The package reads one hop instead (the address your proxy added) when it
  sees one: Express's `trust proxy` `true` (or a function or list that trusts
  any address), Fastify's `trustProxy: true`, Koa's `proxy: true` without
  `maxIpsCount`. Behind two proxies set the count (`trust proxy` `2`,
  `trustProxy: 2`, `maxIpsCount: 2`), or `trustProxy: 2` here.
- **A hop with a port** (`203.0.113.5:54321`, `[2001:db8::1]:443`, as Azure
  App Service and Application Gateway send them) is read without it. A hop
  that still isn't an address (`unknown`, a name) gives the connection's
  address, so the request is still checked.
- **Something that rewrites the header before the app** (Apache's
  `mod_remoteip` in front of a Node app removes the entries it consumed):
  count only the proxies after it, or pass a function that returns the
  address it found.

**What's counted per visitor:** the rate limit, failed logins and the bans
here count an IPv6 address by its /64 (one machine usually holds the whole
/64, and can rotate through it), and `::ffff:1.2.3.4` as `1.2.3.4`. Static
files your app serves itself (`.css`, `.js`, images, fonts, `/_next/static/`,
`/assets/`…) don't count against the rate limit, so a page with 40 of them
uses one request of it; probes, request rules and the address lists still
apply to them. Request rules and probes match the path as your router will
see it as well as the raw one: `/x;y/../admin` is `/admin`.

**Bot protection:** call `platform.loginFailed(req)` when a login fails. Past
the site's limit the address is banned here straight away and on your other
servers within a minute or two. Floods (over the rate limit) are banned the
same way, and the dashboard can ban visits the tracker scores high risk.

**Page limits:** the dashboard can cap one kind of request on its own (a
login form posted ten times a minute, a checkout tried five times). Over the
cap, in block mode, the visitor gets a 429 with `Retry-After` until the window
ends; nothing is banned. The same /64 and static-file rules apply, and the
site's trusted addresses are never counted.

Other frameworks (Fastify, Koa and Hono have their own: see [Fastify](#fastify),
[Koa](#koa), [Hono](#hono-bun-deno-cloudflare-workers)):
`platform.firewall.check({ ip, method, path, userAgent })` returns the decision.

```js
const d = platform.firewall.check({ ip, method: req.method, path: req.url, userAgent: req.headers["user-agent"] });
if (d.action === "block") return send(d.status, "Forbidden"); // your framework's way to answer
```


**Probes.** Requests for files no visitor ever asks for (`/.env`, `/.git/…`,
backups: the list comes with the rules) are rule `probe`; in block mode the
address is also banned on this server, and the collector bans it on the
site's other servers.

**The browser check** (paid plans; switched on in Security → Firewall). A
visitor's first page of the day gets a small "Checking your browser" page
instead (status 503, never cached or indexed). Its script sets a cookie and
reloads, and from then on the site opens as usual. Only a `GET` or `HEAD` that
asks for a page (`Accept: text/html`) is checked: a `POST` (forms, webhooks,
payment callbacks), `fetch()` and API calls, feed readers, the paths the
dashboard skips (`/api/`, `/wp-json/`, …), your allowed addresses and the
search and AI crawlers go straight through. It works the same in every
adapter here (Express, Fastify, Koa, Next.js, Hono), in monitor mode too.

- **What it stops:** cheap floods, scripts that hammer your pages without
  running JavaScript.
- **What it doesn't:** a real browser, or a script driving one, gets through,
  as does a script that doesn't ask for `text/html`. It's a speed bump for
  floods, not a bot wall: keep the rate limit on.
- **A speed bump, not a lock:** it stops scripts that don't run JavaScript. A
  bot written for this product can read the pass from the page, which is why
  the pass is bound to the visitor's address and the day.
- **The cookie** is `__sg_pass`, set for a day (`Path=/; SameSite=Lax`, and
  `Secure` on https). It holds no personal data, only a signature of the
  visitor's address and the day, and exists only to keep the site reachable
  under attack: a strictly necessary security cookie.
- The page brings its own `Content-Security-Policy` so your site's policy
  can't block its script. Without cookies it says so instead of reloading.
  `onBlock` isn't called for it. The cookie is `Secure` whenever the
  browser itself is on https, so no proxy setting is needed for it.
- With `firewall.check()`, pass `accept` and `cookie` too; a
  decision with rule `"challenge"` carries the page as `headers` and `body`.

## Error monitoring

Uncaught exceptions and unhandled rejections are sent on their own; your
process still exits as it would. `errorHandler()` sends 5xx errors from your
routes. Errors you catch:

```js
try {
  await chargeCard(order);
} catch (error) {
  platform.captureException(error, { req, status: 502 });
  throw error;
}
```

Errors your code only logs: `errors: { captureConsole: true }` sends the
first `Error` passed to `console.error` (it is still printed). An error is
sent once however many of these see it, and one logged inside a request keeps
that request's route when `platform.middleware()` runs before your routes.
A batch the collector couldn't take is tried once more a few seconds later.

What still can't be sent waits in a file in the temp folder and is sent when
it can be, after a restart too, including the crash that took the process
down; each error keeps the time it happened. A message is cut to 2,000
characters. A visitor who goes away mid-request (`ECONNRESET`, `EPIPE`, an
aborted request) isn't a server error and isn't sent.

**Shutting down:** `await platform.close()` on `SIGTERM` sends what's waiting
within 5 seconds (`closeTimeoutMs`), well inside a container's or PM2's grace
period: no send starts after that, a failed error batch isn't retried, and the
errors not sent by then wait in the file for the next start.

An error in a request or job also shows what happened before it. Outgoing
requests are recorded on their own, from `fetch`, `http.request` and what's
built on them, with their address (no query string) and status. Add your own
steps with `platform.addBreadcrumb("Order saved")`. This needs
`platform.middleware()` in front of your routes, or `platform.job()`. Database
calls that don't go over HTTP aren't recorded. To send none, delete
`event.breadcrumbs` in `beforeSend`.

Background jobs (queue consumers, cron tasks):

```js
await platform.job("send-receipts", async () => { /* ... */ });
```

Their errors carry the job's name as the route, a job that throws is sent
(status 500) and thrown on, and each run is timed (Server speed → Jobs).
Several services on one site: give each `createPlatform({ serverName: "worker", ... })`
(see [Several apps](#several-apps-microservices-workers-a-separate-api)).

Options: `serverName`, `root` (stack paths relative to it), `captureUncaught`,
`captureConsole`, `spoolDir` (where unsent errors wait; `false` for none),
`beforeSend(event, error)` (change an error, or return `null` to drop it).

## Server analytics

For what only your server knows for sure. Not pageviews: the tracker counts
those.

```js
// A payment
platform.track("purchase", { numeric_value: "49.90", currency: "EUR", event_uid: `order-${order.id}` }, { req });

// Link the visit to your user, with what you know about them (optional)
await platform.identify(user.id, { req, traits: { plan: "pro", seats: 5, trial: false } });

// Add or update a lead
await platform.lead({ email: "ana@example.com", name: "Ana", status: "qualified" });
```

Fields are turned into JSON when you call `track()` (a `BigInt` becomes its
digits); an event whose fields can't be (a circular object) is dropped there
and `track()` returns `""`, so it never holds up the events after it.
`audit()` does the same with `details`.

**User traits:** `identify()` takes an optional `traits` object of name to
text, number or `true`/`false`. Lists, objects and other values are left out
(and `traits` is left off when nothing is left). The collector does the rest:
names are lowercased with spaces and dashes as `_` (up to 40 letters, digits
and `_`), text is cut at 200 characters, values that look like an email
address are dropped, and at most 20 are kept.

**Link to the visit:** send the tracker's session ID with your site's requests,
and pass `{ req }`:

```js
fetch("/api/orders", { headers: { "x-analytics-session": window.analyticsSession?.getId() || "" }, ... });
```

## Next.js and Vercel

The firewall in Next.js's proxy (`proxy.ts`, or `middleware.ts` before Next.js
16), which runs on the edge too, and server errors from `instrumentation.ts`:

```ts
// proxy.ts
import { createNextFirewall } from "analytics-platform/next";
export const proxy = createNextFirewall({ siteId, secret: process.env.ANALYTICS_SITE_SECRET!, endpoint });
export const config = { matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"] };

// instrumentation.ts
import { createOnRequestError } from "analytics-platform/next";
export const onRequestError = createOnRequestError({ siteId, secret: process.env.ANALYTICS_SITE_SECRET!, endpoint });
```

On Vercel the visitor's address is found for you; elsewhere set `trustProxy`.
`"cloudflare"` works on Cloudflare (Workers), and on Vercel behind Cloudflare;
self-hosted Next.js has no connection address in middleware to check the
header against, so pass a function there.
Each instance keeps the rules in memory and counts the rate limit on its own:
pass `counter: async (key, ttl) => hits` (e.g. Upstash Redis) for one count.
For events from route handlers and server actions, use `createPlatform` there.

## Fastify

Fastify 4 and 5. One plugin in place of `middleware()` and `errorHandler()`:

```js
import Fastify from "fastify";
import { createPlatform } from "analytics-platform";

const platform = createPlatform({ siteId, secret: process.env.ANALYTICS_SITE_SECRET, endpoint });

const app = Fastify({ trustProxy: 1 });   // behind Nginx or a load balancer
await app.register(platform.fastify());   // before your routes

app.get("/users/:id", async (request) => findUser(request.params.id));

await app.listen({ port: 3000 });
```

- **Everything `middleware()` does** runs in Fastify's `onRequest` hook, before
  the body is parsed: the firewall, crawlers, Server speed, maintenance and the
  [ad blocker proxy](#ad-blockers).
- **Errors** are sent from Fastify's `onError` hook, 5xx only, with the status
  Fastify answers with; your `setErrorHandler()` still sends the response.
  `platform.fastify({ shouldCapture: (error, request) => ... })` decides
  instead.
- **The visitor's address** is Fastify's `request.ip`, so Fastify's own
  `trustProxy` is all it needs, as `trust proxy` is in Express. Behind
  Cloudflare, pass `trustProxy: "cloudflare"` to `createPlatform()` too.
- **Route names** are Fastify's (`/users/:id`), and a `captureException()` or
  outgoing request in a route knows which request it came from, as in
  Express.
- **Register it on the app itself**, not inside one of your own plugins
  (`app.register(async (child) => ...)`): there it covers only that plugin's
  routes.

## Koa

Koa 2 and 3. One middleware in place of `middleware()` and `errorHandler()`,
first, before your body parser and router:

```js
import Koa from "koa";
import Router from "@koa/router";
import { createPlatform } from "analytics-platform";

const platform = createPlatform({ siteId, secret: process.env.ANALYTICS_SITE_SECRET, endpoint });

const app = new Koa({ proxy: true });   // behind Nginx or a load balancer
app.use(platform.koa());                // first

const router = new Router();
router.get("/users/:id", async (ctx) => { ctx.body = await findUser(ctx.params.id); });
app.use(router.routes());

app.listen(3000);
```

- **Errors** a route throws are sent (5xx only) and thrown on, so Koa, or
  your own error middleware after this one, still answers.
  `platform.koa({ shouldCapture: (error, ctx) => ... })` decides instead.
- **The visitor's address** is Koa's `ctx.ip`, so Koa's own `proxy` setting is
  all it needs. Behind Cloudflare, pass `trustProxy: "cloudflare"` to
  `createPlatform()` too.
- **Route names** are `@koa/router`'s (`/users/:id`, with the router's
  prefix); without it, numbers and IDs in the path become `:id`.

## Hono, Bun, Deno, Cloudflare Workers

Hono on any runtime: Node, Bun, Deno, Cloudflare Workers, Vercel or Netlify's
edge. One middleware, first, does what `middleware()` does, in the same
order: the [ad blocker proxy](#ad-blockers), security headers, crawler
counts, the firewall, maintenance mode and Server speed, plus 5xx errors
with their breadcrumbs. Everything else is on `platform` with the same
arguments as the main package's, `c` in place of `req`.

```js
import { Hono } from "hono";
import { createHonoPlatform } from "analytics-platform/hono";

const platform = createHonoPlatform({ siteId, secret: process.env.ANALYTICS_SITE_SECRET, endpoint });

const app = new Hono();
app.use(platform);   // first

app.get("/users/:id", (c) => c.json(findUser(c.req.param("id"))));

export default app;
```

On Cloudflare Workers the secret is in `c.env`, so pass a function:

```js
const platform = createHonoPlatform((c) => ({ siteId, secret: c.env.ANALYTICS_SITE_SECRET, endpoint }));
```

- **Errors** a route throws are sent (5xx only) from what Hono leaves on
  `c.error`; your `app.onError()` still answers. For one you catch yourself:
  `platform.captureException(error, c)`, and `{ status }` as a third
  argument if it has one. Each carries the request's trail: its outgoing
  `fetch` calls (on Node, `http.request` too), and your own steps with
  `platform.addBreadcrumb("charged the card", c)`.
- **Without `c`** works where the runtime has `AsyncLocalStorage`: Node, Bun,
  Deno, Netlify's edge and Workers with `nodejs_compat` (recent compatibility
  dates have it without the flag). Elsewhere (Vercel's edge-runtime, older
  Workers) outgoing calls aren't recorded, and an error captured without `c`
  has no route.
- **Server events and the rest:** `platform.track("purchase", { value }, { c })`,
  `await platform.identify(user.id, { c })`, `await platform.lead({ email }, { c })`,
  `platform.audit("user.role_changed", { actor, target, c })`,
  `platform.loginFailed(c)` (or the address) and
  `platform.isEnabled("new-checkout", { user })`. `c` links them to the
  visit (the page's `x-analytics-session` header) and, on Workers, keeps the
  request alive until they're sent. Flags are `false` (or your `default`)
  until the first request has fetched them.
- **Background jobs:** `await platform.job("send-receipts", async () => ...)`,
  as in the main package (Health → Server speed → Jobs). In a Workers
  `scheduled()` or `queue()` handler there is no `c`: pass
  `{ env, executionCtx: ctx }` as the third argument, so the options can read
  `env` and the job's rows and errors are sent before the handler ends.
- **Database queries:** `platform.watchDatabase(db)` as in the main package
  ([Database queries](#database-queries)); nothing is timed until the first
  request has set the platform up, and filing a query under its request needs
  AsyncLocalStorage (Node, Bun, Deno, Workers with `nodejs_compat`).
- **Outgoing calls:** as in the main package ([Outgoing calls](#outgoing-calls))
  on Node. Bun and Deno have the diagnostics channels but their own `fetch`
  may not report to them; Workers and the edge have none.
- **Job queues:** `platform.watchQueue(queue)` as in the main package
  ([Job queues](#job-queues)), in a process that stays up; read from the first
  request on.
- **Forms:** `app.post("/contact", platform.protectForm(), handler)` gives spam
  a 422 (or your `onSpam(c, result)`) and leaves the result in
  `c.get("formCheck")`; or `await platform.checkForm(c, { email })` in the
  route. Either reads a copy of the body, so the route still reads it.
- **Ad blockers:** `const { scriptUrl, collectUrl } = await platform.proxy(c)`
  gives the two addresses for your page's script tag (`null` with
  `proxy: false`). When the options are a function of `c`, the first call
  needs `c` or `{ env }`; without either it throws, saying so.
- **Maintenance mode** answers with its page before your routes;
  `maintenance: { skip: (c) => c.req.path === "/health" }` lets a request
  through.
- **Turn a module off** with `false`: `proxy`, `headers`, `crawlers`,
  `firewall`, `maintenance`, `performance`, `errors`, `forms`, `analytics`
  (track, identify, lead), `audit`, `flags`.
- **The visitor's address** is the connection's own on Node, Bun and Deno,
  Netlify's on its edge, `CF-Connecting-IP` on Workers, and `x-real-ip` on
  Vercel's edge. Behind a proxy: `trustProxy: 1` (the
  number of proxies), `"cloudflare"`, or `(c) => address`.
- **Server speed and crawler counts** are sent once a minute; on Workers and
  Vercel's and Netlify's edge, by the requests themselves (an instance has
  no timer between requests). Workers' clock only moves while waiting on
  I/O, so their times are I/O time.
- **The dashboard's settings** (maintenance mode, the headers, flags) are
  fetched on the first request, which waits up to 1.5 seconds for them, as
  for the firewall's rules.
- **Not on Hono:** what needs the machine itself (its packages, set-up and
  resources: `inventory`, `posture`, `resources`); run `createPlatform()` on
  Node for those.
- **Serverless** (Lambda, Vercel functions): `await platform.flush()` before
  returning.
- Each instance counts toward the rate limit on its own: pass
  `counter: async (key, ttl) => hits` (e.g. Upstash Redis) for one count.

## NestJS

**With the one line** (`import platform from "analytics-platform/start"`
first in `main.ts`, or `node --import analytics-platform/start dist/main.js`),
the middleware is added to Nest's Express app by itself: you don't need
`platform.ts` or `app.use()` below. Only the error filter is still needed,
with `import platform from "analytics-platform/start"` in place of
`./platform`.

Nest runs on Express by default, so `middleware()` is the same as in an
Express app. `errorHandler()` is not: Nest's exception filters answer every
error first, so an Express error handler never sees one. A global filter sends
them instead.

```ts
// platform.ts: created once, imported wherever you track events
import { createPlatform } from "analytics-platform";

export default createPlatform({ siteId, secret: process.env.ANALYTICS_SITE_SECRET!, endpoint });
```

```ts
// platform.filter.ts
import { ArgumentsHost, Catch, HttpException } from "@nestjs/common";
import { BaseExceptionFilter } from "@nestjs/core";
import platform from "./platform";

@Catch()
export class PlatformFilter extends BaseExceptionFilter {
  catch(exception: unknown, host: ArgumentsHost) {
    const status = exception instanceof HttpException ? exception.getStatus() : 500;
    if (status >= 500) platform.captureException(exception, { req: host.switchToHttp().getRequest(), status, kind: "handled" });
    super.catch(exception, host); // Nest still answers as before
  }
}
```

```ts
// main.ts
import "dotenv/config"; // first: before anything imports platform.ts
import { HttpAdapterHost, NestFactory } from "@nestjs/core";
import { NestExpressApplication } from "@nestjs/platform-express";
import { AppModule } from "./app.module";
import platform from "./platform";
import { PlatformFilter } from "./platform.filter";

async function bootstrap() {
  const app = await NestFactory.create<NestExpressApplication>(AppModule);
  app.set("trust proxy", 1);        // behind Nginx or a load balancer
  app.use(platform.middleware());   // before Nest's body parsers and your routes
  app.useGlobalFilters(new PlatformFilter(app.get(HttpAdapterHost).httpAdapter));
  await app.listen(process.env.PORT ?? 3000);
}
bootstrap();
```

- **`ConfigModule` loads `.env` too late** for `platform.ts`, which reads the
  secret as soon as it is imported. Keep `import "dotenv/config";` as the first
  line of `main.ts`, or start with `node --env-file=.env dist/main.js`.
- **Already have a catch-all filter?** Add the `captureException` line to it
  instead. A filter with `@Catch(SomeError)` answers only that error and
  doesn't pass it on, so a 5xx it handles needs the line too.
- **Route names** in Server speed and Errors are Nest's own (`/users/:id`,
  with the global prefix: `/api/users/:id`), because Nest registers its routes
  on Express (or Fastify).
- **`platform.track()` and the rest** in a service: `import platform from "./platform"`.
  A second `createPlatform()` would fetch the rules and send everything twice.
  A `platform.captureException(error)` there, even after an `await`, still
  knows which request it came from.
- **4xx are not sent**: an `HttpException` below 500 (`BadRequestException`,
  `NotFoundException`, a body that isn't valid JSON) is the client's.
- **On Fastify** (`@nestjs/platform-fastify`): `await app.register(platform.fastify())`
  in place of `app.use()`, and keep the same filter: Nest answers errors
  before Fastify's error hook sees them. The visitor's address is Fastify's,
  so set its `trustProxy` on the adapter:

  ```ts
  const app = await NestFactory.create<NestFastifyApplication>(AppModule, new FastifyAdapter({ trustProxy: 1 }));
  await app.register(platform.fastify());   // before listen()
  app.useGlobalFilters(new PlatformFilter(app.get(HttpAdapterHost).httpAdapter));
  ```
- **Microservices and WebSocket gateways** don't use the global HTTP filter:
  call `platform.captureException(error)` in theirs, or run the handler in
  `platform.job("name", ...)`.

**Shutting down.** Server speed and crawler counts are sent once a minute, so
a deploy or restart (SIGTERM) loses the last minute unless the app closes the
platform. Let Nest do it, on either adapter:

```ts
// platform.shutdown.ts
import { Injectable, OnApplicationShutdown } from "@nestjs/common";
import platform from "./platform";

@Injectable()
export class PlatformShutdown implements OnApplicationShutdown {
  async onApplicationShutdown() {
    await platform.close(); // sends what's waiting
  }
}
```

Add `PlatformShutdown` to your `AppModule`'s `providers`, and
`app.enableShutdownHooks();` in `main.ts` before `listen()`. Nest then stops
taking requests, calls it, and exits. `onApplicationShutdown` runs once the
HTTP server has closed, so requests still being answered are counted;
`beforeApplicationShutdown` runs before that and would leave them out.

## Crawlers and AI bots

`platform.middleware()` counts every request from a crawler — `GPTBot`,
`ClaudeBot`, `ChatGPT-User`, `PerplexityBot`, `Googlebot`, `bingbot`, the SEO
tools, the link previews — and sends one small summary a minute per bot, page
and status. See it under Off-site → Crawlers.

Your browser tracker cannot see any of this: crawlers don't run JavaScript. So
this is the only place you learn that an AI fetched a page because someone
asked it about you, that Googlebot has been asking for a page you deleted, or
that something calling itself Googlebot isn't.

Nothing about your visitors is counted or sent: a request is counted only when
its user agent names a crawler. Requests the firewall turned away are counted
too, with the status the crawler got.

```js
createPlatform({
  siteId, secret, endpoint,
  crawlers: { serverName: "web-1" },  // or false to leave them uncounted
});
```

Crawler addresses go with each batch so the collector can check a crawler is
itself (Google, Bing, Yandex, Baidu and Apple publish a reverse-DNS
convention; for the rest the network is shown). No address is stored. The
protocol is `sdk/protocols/crawlers.md`.

Other frameworks: `platform.crawlers.record({ bot, path, status, bytes, ms, ip })`,
with `platform.crawlers.detect(userAgent)` for the bot's name (`""` when the
request isn't from one).

## Performance & API monitoring

`platform.middleware()` times every request it lets through and sends one
small summary a minute per route (Express route patterns like `/users/:id`;
elsewhere numbers and IDs in the path become `:id`). See it under Health →
Server speed. Name routes yourself with `performance: { route: (req) => "..." }`.

### Database queries

Hand your database object to `watchDatabase()` once, where you create it, and
Health → Server speed → Queries shows each route's queries: how many ran, how
many failed and how long they took. Every value in a query is replaced by `?`
before it is counted, and bound parameters are never read, so no data leaves
your server.

```js
const pool = platform.watchDatabase(new pg.Pool());              // pg Pool or Client
const db = platform.watchDatabase(mysql.createPool(config));      // mysql2, callback or promise
platform.watchDatabase(mongoClient);                              // before mongoClient.connect()
platform.watchDatabase(mongoose.connection.getClient());          // Mongoose
platform.watchDatabase(knex);
const prisma = platform.watchDatabase(new PrismaClient());        // use the client it returns
platform.watchDatabase(clickhouse);                               // @clickhouse/client's createClient()
platform.watchDatabase(redis);                                    // ioredis (Redis or Cluster), or node-redis createClient()
```

- Only the object you pass is changed (its own `query`, or its events); the
  library itself is left alone. For a pool, connections you check out
  (`pool.connect()`, `getConnection()`) are timed too.
- Prisma reports model calls (`User.findMany`), not SQL. When Prisma or knex
  run on a pool you also watch, each query is counted once, by Prisma or knex.
- Mongo: watch the client before it connects (the driver sends command
  events only on connections opened after that).
- ClickHouse: `query()` is timed until you read its result (`json()`,
  `text()`, the stream ending, or `close()`): a query answers as soon as its
  result starts arriving, which isn't when it's done. A result you never read
  isn't counted. `insert()`, `command()` and `exec()` are timed until they answer.
- Redis: each command is counted by its name and the shape of its key
  (`GET user:?:cart`); no other argument or value is read. A pipeline or
  `multi()` is one call (`PIPELINE GET user:?`), timed as a whole; with
  ioredis's `enableAutoPipelining` each automatic batch is one. Commands that
  wait (`BLPOP`, `XREAD BLOCK`, subscribing) aren't timed, and nor are this
  package's own reads of your BullMQ queues. A node-redis cluster or pool
  isn't timed: watch a single client. node-redis 4 reads the key from the
  arguments you pass, so a script's (`eval()`) isn't shown.
- Queries are filed under the request they ran in, by Server speed's method
  and route; inside `platform.job()` under the job; anywhere else as
  `JOB (background)`.
- They ride on Server speed's switch; `queries: false` leaves them out.

### Outgoing calls

Nothing to set up: Health → Server speed → Calls shows how long each route
waited on other services — a payment provider, an email API, your own
microservices — by the host it called (`api.stripe.com`), with how many calls
failed. Read from Node's own diagnostics channels, so `fetch()`, `http`,
`https` and what's built on them (axios, got, node-fetch) are all seen and
none of them is changed.

- **Only the host is sent.** A call's path, query string, headers and body
  never leave your server: paths carry IDs and keys.
- A call is timed from being sent to its response's headers arriving. A
  call that got no answer, or a 5xx, is a failed one; a 4xx is the other
  side's answer, not a failure. A call your code cancels isn't counted.
- Calls are filed as queries are: under the request, the `platform.job()`, or
  `JOB (background)`. The package's own calls to us are left out.
- They ride on Server speed's switch; `calls: false` leaves them out.

### Job queues

Health → Server speed → Jobs shows each queue's backlog once a minute: jobs
waiting, running, delayed and failed, how long the oldest has waited, and jobs
added against jobs finished — so a queue falling behind shows before the
emails go out an hour late. BullMQ and Bull:

```js
const emails = platform.watchQueue(new Queue("emails", { connection }));   // where jobs are added
platform.watchQueue(new Worker("emails", process, { connection }));        // where they run
```

- Watch the Queue wherever you have one: it reads the backlog and counts the
  jobs that process adds. Watch the Worker to count the jobs it finishes.
  Bull's queue does both. Watching one queue in several processes is fine:
  the dashboard takes the largest reading, never the sum.
- Only the queue's public API and events are used (`getJobCounts()`, one
  `getJobs()` for the oldest job, `waiting`, `completed`, `failed`). Its Redis
  is named by host, port and database; never a password.
- A reading that fails is a gap, not a zero.
- Time each job too with `platform.job("send-email", fn)` inside your processor.
- They ride on Server speed's switch; `queues: false` leaves them out.

## Ad blockers

Many visitors use an ad blocker, and most blockers stop analytics. They
recognise **the address a script comes from** and **what it is called**, so a
tracker loaded from us is simply never counted.

This package already runs on your own domain, so it serves the tracker and
takes the visits itself. Nothing to set up: use the two addresses it gives you
in your page's script tag.

```js
app.use(platform.middleware());        // the proxy answers before anything else

// in your template
`<script async src="${platform.proxy.scriptUrl()}"
         data-siteid="${siteId}" data-domain="example.com"
         data-collect="${platform.proxy.collectUrl()}"></script>`
```

- The path comes from your secret (`/3f9a2c1b/...`), so it isn't in the page
  and isn't a name any blocker lists. Pick your own with `proxy: { prefix }`.
- Tracker files are fetched once and then served from memory; if we can't be
  reached, the copy already held is served rather than nothing. A file that
  couldn't be fetched isn't asked for again for 30 seconds.
- Each call to us waits at most 2 seconds. After 3 failures in a row we're
  left alone for 30 seconds: beacons are answered `502` at once (the tracker
  treats a lost beacon as lost and carries on) instead of each waiting out a
  timeout, then one call tries again.
- The visitor's address goes on as `X-Forwarded-For` (your collector needs it
  for the country, the daily visitor ID and the rate limit) and cookies never
  leave your server.
- Beacons are answered before the firewall, the crawler count and the timing,
  so your own analytics traffic doesn't appear as pages of your site. Only the
  firewall's address rules apply to them (a denied or banned address gets
  `403` in block mode); never the rate limit or the browser check.
- Switch it off with `proxy: false`, or in the dashboard (Site settings →
  Server). Then load the tracker from us as before.

## Several apps: microservices, workers, a separate API

One site can have any number of apps behind it: an API, a queue worker, a
service in another repo, a Python service next to a Node one. Install the
package in each, with the **same** `siteId`, `secret` and `endpoint`, and give
each its own `serverName`:

```js
// api/platform.js
export default createPlatform({ siteId, secret, endpoint, serverName: "api" });

// worker/platform.js
export default createPlatform({ siteId, secret, endpoint, serverName: "worker" });
```

Everything then lands on the one site, told apart by that name: the Errors
report and Server speed can be narrowed to one app, Crawlers lists each, and
Health → Updates keeps each app's own packages. A purchase tracked by the
worker and a sign-up from the API count in the same reports.

Health → All systems lists each app with a light: the package checks in about
once a minute (its process ID, how long it has run, its memory), so an app
that stops reads "Stopped" within ten minutes, even if it never serves a
request. An app you retire on purpose has a Remove button there
(`sdk/protocols/checkin.md`).

Without `serverName`, each app is named after its machine. That's fine when
every app has a machine to itself. Two apps on one machine (two PM2 processes,
two containers on one host) are then reported as one, and the Security check
keeps only the package list of whichever app sent last.

What each kind of app needs:

- **The app your visitors reach** (the website, or the gateway in front of
  your services): set up as in [Where it goes](#where-it-goes).
- **A service only your other apps call**: `middleware()` and `errorHandler()`
  as usual, with `firewall: false, proxy: false, maintenance: false`. Its
  requests come from your own apps, so the firewall's rate limit would count
  all your traffic as one visitor and start answering 429. The app in front
  already checks the visitor. Maintenance mode is shown by that app too, not
  by an API it calls.
- **A background app with no routes** (a queue consumer, a cron runner):
  `createPlatform()` alone sends uncaught errors, packages and set-up. Wrap
  the work in `platform.job()`, and set `errors: { captureConsole: true }` if
  it logs the errors it catches instead of throwing them. If it has a health
  or metrics server, add `middleware()` and `errorHandler()` there as well.
- **Several apps on one machine**: leave `resources` on in all of them. The
  machine's CPU, memory and disks are shown once (the dashboard sees the names
  are one machine), and each app adds what is its own: its container's
  memory and CPU caps, how often the cap throttled it, open files against the
  limit, its heap, garbage collection, and the most requests in progress at
  once. Cluster workers under one name are told apart, so their heaps aren't
  mixed up.

To link a server event to a visit, the app that does the work needs the
visitor's session ID. If the request reached another app first, pass on the
`x-analytics-session` header when that app calls yours, then use `{ req }` as
usual.

Still one `createPlatform()` per process: an app that imports it from several
files shares one `platform.js` (see [Where it goes](#where-it-goes)).

## Shutting down and serverless

`await platform.flush()` sends everything waiting (on Vercel or Lambda, before
returning). `await platform.close()` also stops fetching rules.
