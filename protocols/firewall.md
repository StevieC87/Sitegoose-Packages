# Firewall protocol (v1)

What every firewall client implements. Clients: Node, Next.js (edge) and Python
(`sdk/platform-node` incl. `lib/next.js`, and `sdk/platform-python`), Ruby, Java, .NET and Go
(`sdk/platform-ruby`, `sdk/platform-java`, `sdk/platform-dotnet`, `sdk/platform-go`), PHP and Laravel (`sdk/platform-php`), WordPress
(`sdk/wordpress-plugin`, built on the PHP one) and Cloudflare (pushed by the
backend, `backend/services/firewall/cloudflare.js`) and the server agent
(`sdk/vps-agent`, nftables, iptables + ipset or nginx; it reports ranges as the `ip`, e.g. `1.2.3.0/24`). The collector side is `expresscollect/Analytics/firewall.js`.

## Authentication

Both endpoints take the site's ID and its secret (site settings):
`Authorization: Bearer <secret>`. The secret never goes to a browser.

## GET /events/firewall/rules?site_id=<id>

Send `If-None-Match` with the last `ETag`; `304` means nothing changed.
Send a `User-Agent` naming the client and its version (`analytics-platform-node/0.1.0`,
`analytics-firewall-wordpress/0.1.0`): the dashboard shows it as the connected client. Append ` (no-rate)` when the client can't
count requests (PHP without APCu or another shared counter): the dashboard then
warns that the rate limit isn't working.

```json
{
  "v": 1,
  "enabled": true,
  "mode": "monitor",
  "sync": 60,
  "allow": ["203.0.113.7", "10.0.0.0/8"],
  "deny": ["198.51.100.0/24", "2001:db8::/32"],
  "lists": ["1.10.16.0/20"],
  "shared": ["192.0.2.44"],
  "rate": { "limit": 120, "window": 60 },
  "goodbots": ["23.98.142.176/28", "2a05:d014:f2f:4600::/56"]
}
```

- `v`: protocol version. Ignore rules with a version you don't know (keep the old ones).
- `enabled`: false → every request passes.
- `mode`: `"block"` refuses matched requests; `"monitor"` lets them through and reports them.
- `sync`: seconds until the next fetch (at least 30).
- `allow`, `deny`, `lists` (Spamhaus DROP), `shared` (reported by other sites):
  IPv4/IPv6 addresses and CIDR ranges. Treat IPv4-mapped IPv6 (`::ffff:1.2.3.4`) as IPv4.
  A client that keeps IPv4 in IPv6 space as `::ffff:a.b.c.d` drops, from every
  list, an IPv6 range that holds all of `::ffff:0:0/96` (`::/64`, `::/0`): it
  would match every IPv4 visitor. The collector bans and shares a reported
  IPv6 /64 only inside global unicast (`2000::/3`).
  An address is `shared` once three accounts whose sites have a proven domain
  (backend/docs/DOMAIN_PROOF.md), on three different domains, banned it within
  an hour; a site without a proven domain is no witness.
- `rate`: null, or at most `limit` requests per address per `window` seconds.
  A request for a static file doesn't count: an app serving its own files
  would otherwise spend 41 hits on a page with 40 assets. It is still checked
  against everything else (address lists, probes, request rules). A path is a
  static file only when every router reads it the same way, so the rule is
  strict, not "as routed":
  - Only a `GET` or `HEAD` request (as sent, upper case) can be a file. A
    form posts to a page, and some routers take a file's name for one: Rails
    reads `POST /login.css` as the login action (format `css`), Spring MVC
    before 5.3 as `/login` (suffix pattern matching), Django's
    `re_path(r"^login")` and ASP.NET's default `{controller}/{action}/{id?}`
    route (`/Account/Login/x.css`) too, and WooCommerce takes a login posted
    to any address.
  - Cut at the first `?` or `#`; what is left must start with `/` and be at
    most 2,000 characters (a longer one is no file: no asset has a name that
    long).
  - An encoded slash (`%2F`, any case) in it → not static.
  - Decoded once; a `%xx` still there (double encoding), a `;` (a path
    parameter to some servers, part of the name to others), a `\`, an
    encoded `?` or `#`, or a control character → not static.
  - Lower-cased (`A`–`Z` only: some languages read `İ` as `i`) and split on `/`: a `.` or `..` segment → not static
    (`/static/../login`, `/static/%2e%2e/login`). Empty segments drop (`//`
    reads as `/`); a trailing slash stays (`/app.css/` is no file).
  - Then static when it starts with an asset folder, `/static/`,
    `/_next/static/` or `/assets/` (Ruby also `/packs/` and `/vite/`), or its
    last segment is a name followed by one of `.css`, `.js`, `.mjs`, `.map`,
    `.png`, `.jpg`, `.jpeg`, `.gif`, `.webp`, `.avif`, `.svg`, `.ico`, `.bmp`,
    `.woff`, `.woff2`, `.ttf`, `.otf`, `.eot`, `.mp4`, `.webm`, `.ogg`, `.mp3`,
    `.wav`, `.pdf` or `.wasm` at its very end (the agent's nginx list;
    `/login/.css` and `/a.css%0A` are no files).
  - PHP also reads a script with a path after it as the script:
    `/wp-login.php/x.css` runs `wp-login.php` (`.phtml` and `.phar` too).

  A browser asks for its files with none of those tricks.
  [static-cases.json](static-cases.json) holds the cases every package's tests
  run (`only` marks the Ruby and PHP extras); a new trick goes there, not into
  one package's tests.

  Counted after the response, in every package. A static request is
  compared with the counts so far without adding to them, so an address
  already over the rate or a page limit that matches is refused its files
  too. With a shared counter, which can only add, a package remembers which
  counts it saw go over (Node's edge firewall, Go, .NET, Python, Ruby and
  Java in the process; PHP in APCu, so PHP without APCu can't, and an
  address over a shared count still gets its files there). Once the
  response is out, it counts toward `rate` and the page limits it skipped
  when it answered 400 or more (a flood of made-up `/x.css` that each boot
  the app), or when the router sent it to a route of the app's own that
  isn't a file's. A route is a file's when its pattern is a static file by
  this same rule (`/avatars/{id}.png`, `/static/{**path}`; all but Ruby),
  or, in Node, Go, .NET, Python and PHP, when the answer's `Content-Type`
  is a file's
  (`image/`, `font/`, `audio/`, `video/`, `text/css`, JavaScript, WASM, PDF,
  `application/octet-stream`): a wildcard file server or `sendFile()` under
  `/uploads/:name`, so an image on a page is never counted; those five
  never count a routed 304 either (a browser checking a file it keeps,
  which a file server answers with no `Content-Type`). Per package:
  - **Node**: Express `req.route` (set by the router;
    `express.static`/`serve-static` are middleware and set none), Fastify
    `request.routeOptions.url` (a static plugin's wildcard is left alone by
    its `Content-Type`, which the plugin keeps from `onSend`), Koa
    `ctx._matchedRoute` (@koa/router; koa-static sets none), read on the
    response's `finish`. Hono: `c.req.routePath` after `next()`, when it
    isn't the middleware's own (`serveStatic` answers a file's type). Next.js
    middleware never sees the route or the response, so there only the
    comparison applies: nothing is counted late.
  - **Go**: the pattern ServeMux matched (`r.Pattern`, Go 1.23+; ServeMux
    sets it on the request the middleware handed it, so a middleware
    between the two that copies the request hides it; before 1.23 the
    ServeMux the middleware wraps is asked), or the one an adapter gives:
    gin `c.FullPath()`, chi `RoutePattern()`, echo `c.Path()`. Read once the
    handler returned; a shared counter is called in a goroutine, at most 64
    at once (past them, on the request, as a page's count is).
  - **.NET**: the endpoint routing matched (`HttpContext.GetEndpoint()`, a
    `RouteEndpoint`: Razor Pages, MVC, minimal APIs), read in
    `Response.OnCompleted`. The static files middleware serves a file only
    when no endpoint matched. A visitor who went away (the package's 499) is
    no error: the status the app set stands.
  - **Python**: Django `request.resolver_match` (not `django.views.static`'s
    or staticfiles' `serve`; whitenoise answers before the resolver),
    counted from the response's closers once the body is sent. Flask
    `request.url_rule` (not the `static` endpoint, nor a blueprint's),
    counted when the server closes the WSGI response. Starlette and FastAPI
    `scope["route"]`, or the endpoint Starlette's router left in the scope
    (a `StaticFiles` mount is left alone; a visitor gone before any answer
    is no error). Plain WSGI has no router to ask: an error only. A WSGI
    answer already known not to count is handed back as the app gave it, so
    the server's file wrapper (sendfile) stays.
  - **PHP**: Laravel `$request->route()` in the middleware's `terminate()`
    (not a route whose URI is a file's, nor `storage/` and Livewire's
    `livewire/` routes), counted there by the response's status, so Octane
    counts too. WordPress: any static-looking request WordPress's
    own router took (its main query ran, the `wp` action): the web server
    serves the files that exist, so one reaching WordPress had none. Not
    a path starting with `/wp-content/` or `/wp-includes/` (or the site's
    own content and includes folders: a plugin serving uploads through
    PHP), nor the site's favicon; only at the start, as
    `/search/a/wp-content/b.css` is a search. Symfony: the request's
    `_route` in `kernel.terminate` (not a route whose path is a file's, nor
    LiipImagine's), counted there, so a worker (RoadRunner, FrankenPHP)
    counts too. Plain PHP: an error only (`countStatic()`, at shutdown).
  - **Ruby**: Rails' router sent it to a controller action (the env's
    `action_dispatch.request.path_parameters` has a `:controller`, other
    than Active Storage's and Action Text's, which serve files: an image on
    a page is a request to one); Rails reads `GET /search.css` as the search
    action with format `css`.
  - **Java**: Spring MVC sent it to a controller method
    (`HandlerMapping`'s `bestMatchingHandler` is a `HandlerMethod`): `/search`
    took `/search.css` (suffix pattern matching), `/search/{q}` took
    `/search/x.css`. JAX-RS and other servlet routers: an error only.
- `goodbots`: addresses and ranges the rate limit must **not** apply to, as the
  vendors publish them: the AI crawlers that bring visits and citations, which
  is `ai_user` and `ai_search` in `crawlers.md`. Checked **only** at the rate
  step, so a good bot is still subject to `deny`, `banned`, `lists`, `shared`,
  `probes` and the request rules. Bulk collection (`ai_train`, e.g. `GPTBot`)
  is deliberately not here: that is the kind that floods, and it earns no
  citation. A client that doesn't know this key ignores it and keeps rate
  limiting these crawlers as it did before, so no client has to be upgraded.
- `banned`: temporary bans (bot protection), checked right after `deny` as rule `ban`.
- `ban`: null, or `{ "seconds": 600 }`: in block mode, an address over the rate
  limit is banned on this server straight away for that long (rule `ban` while
  it lasts). In monitor mode it is only reported, as a probe is.
- `login`: null, or `{ "limit": 10, "window": 3600, "ban": 3600 }`: failed
  logins (the client's `loginFailed()`) from one address within `window` seconds
  that get it banned on this server for `ban` seconds. Report each failed login as
  an event with rule `login`, action `monitor` and empty method and path.
- **Who is counted.** The rate limit, the failed-login count and the bans on
  this server are per IPv4 address (an IPv4-mapped IPv6 address as IPv4) or per
  IPv6 **/64**, which one machine usually holds whole and can mint addresses
  in by the billion: counted per address, rotating through it would earn a
  fresh count on every request. The address lists still match the full
  address. A table of counters that is full drops its oldest entries, never
  all of them at once (one /64 could otherwise reset everyone's count and
  ban). A shared counter (Redis and the like) is keyed
  `afw:<site_id>:<who>:<window>`, with `<window>` the whole number of
  `window`-second periods since 1970 and `<who>` written the same way by
  every package, so a site whose servers run different languages on one
  Redis counts a visitor once: `198.51.100.7`, or the /64 as its network in
  RFC 5952 text, lower-case and compressed (`2001:db8:1:2::/64`).
- `probes`: null, or `{ "exact": ["/.env", ...], "prefix": ["/.git/", ...], "ban": 3600 }`:
  addresses of files no visitor ever asks for (secrets, backups, version
  control). A request whose path (no query string, lower-cased, `//` as `/`)
  is in `exact` or starts with an entry of `prefix` is rule `probe`; in block
  mode the address is also banned on this server for `ban` seconds (rule
  `ban` while it lasts). The collector bans it on the site's other servers too,
  and so with a `rate` event: only for events whose action is `block`, so a
  site in monitor mode bans nobody. Failed logins are counted in either mode,
  but ban and count toward `shared` only when the site's mode is `block`. The
  site's trusted addresses (Security settings) are never banned or shared by
  the collector, whatever they trip.

## Request rules (virtual patching)

Besides addresses, the answer carries `requests`: rules that match the
**request itself**, so an attack is turned away before the vulnerable code
runs. This is what keeps a site with a known hole in a plugin safe until it
updates.

```json
"requests": {
  "rules": [
    { "id": "traversal", "action": "block", "ban": 3600,
      "path": { "contains": ["../", "..%2f"] } },
    { "id": "empty.ua.post", "action": "monitor",
      "methods": ["POST"], "ua": { "exact": [""] } }
  ]
}
```

- `requests` is **additive**: a client that doesn't know the key ignores it and
  keeps checking addresses only. The answer stays `v: 1` for that reason — a
  version bump would make older clients throw the whole answer away and keep
  stale rules.
- `id`: `[a-z][a-z0-9_.-]{1,39}`, reported back as the rule `request:<id>`.
- Which rules a client gets depends on who it says it is: a rule stored with
  `platforms` (e.g. `["wordpress"]`) goes only to a client whose
  `User-Agent` names one of them (`analytics-platform-<name>/…`: `wordpress`,
  `php`, `laravel`, `node`, `next`, `python`, `django`, `ruby`, `java`,
  `dotnet`, `go`), and a client the collector can't name gets every rule. The
  Ruby, Java, .NET and Go packages name their language, never their framework,
  so a rule can be aimed at Ruby but not at Rails alone.
- `action`: `block` or `monitor`. **`monitor` beats nothing**: a rule only
  blocks when the site's `mode` is `block` *and* the rule's action is `block`.
  Rules a real visitor might trip arrive as `monitor` so the owner can see
  what they would have stopped first.
- `methods`: upper-case; any method when absent.
- `path`, `query`, `ua`, `body`: the parts to match, each with any of
  `exact`, `prefix`, `suffix`, `contains` (lists, already lower-cased) and
  `regex` (one pattern, case-insensitive).
- `ban`: seconds to ban the address as well, as the rate limit does. Only when
  the rule blocks.
- At most 200 rules, 60 entries per matcher and 200 characters per pattern.
  `exact`, `prefix`, `suffix` and `contains` run over the **whole** part, however
  long: they cost one pass, and a part cut short would let 2,000 characters of
  filler carry an attack past every rule (`?pad=xxx…&file=../../wp-config.php`).
  Only a `regex` is held to 2,000 characters at a time, since a backtracking
  engine's cost grows faster than the text: it is searched in the first 2,000
  characters, then in every further window of 2,000 that starts 1,000 later,
  to the end of the part, so a match up to 1,000 characters long is found
  wherever it sits. A window's edges are not the part's: a pattern that
  begins with `^` is searched only in the first window, and one that ends with
  `$` (not `\$`) only in the last of those windows (the first one to reach the
  end of the part, so between 1,000 and 2,000 characters long), so neither
  matches in the middle of a long path. Prefer plain matchers, or a `regex` whose match stays short
  (bounded repeats): a match spanning more than 1,000 characters is found only
  inside the first 2,000.
- A `regex` stays in the common subset of JavaScript, PCRE, Python, Ruby,
  Java and .NET: no
  backreferences, no lookbehind, and **no quantifier on a group that itself
  repeats** (`(a+)+`). Groups are a list of what is allowed, not of what
  isn't: plain `(`, `(?:`, `(?=` and `(?!` only, so named groups, lookbehind,
  `(?P…)`, `(?R)`, `(?1)`, conditionals, atomic groups, inline flags,
  comments and `(*VERB)` are all refused; so are escapes that refer to a
  group or aren't shared (`\1`–`\9`, `\k`, `\g`, `\N`, `\Q`) and possessive
  quantifiers (`a++`, `a*+`, `a{2}+`). `patterns` in
  `request-rules-cases.json` lists both sides. None of these languages can time a regex out, so such a
  pattern is one request away from a hung server; the collector refuses to hand
  one out, and a client that sees one may ignore it. Go's RE2 runs in linear
  time but has no lookahead either: the Go package drops a pattern it can't
  compile and keeps the rule's other parts, so prefer the plain matchers.

### Matching

A rule matches when **every section it names** matches and, within a section,
**any one entry** does. For each request, prepare:

- The **target**: the path and query as the request line carries them, in
  origin form. A target that doesn't start with `/` (absolute form, or
  anything else a server accepts) is read the way the server's own URL parser
  reads it: a leading scheme (`[a-z][a-z0-9+.-]*:`) dropped, then, after a
  `//`, the authority up to the next `/`, `?` or `#`; what is left gets a `/`
  in front when it has none. So `http://h/admin?x` is `/admin?x`, and
  `x:/admin` and `http:/admin` are `/admin`: Puma, gunicorn and Go's
  `net/http` all route those as `/admin`, and a firewall that kept `x:/admin`
  would let it past every prefix rule. `*` (`OPTIONS *`) stays as it is.
  `targets` in `request-rules-cases.json` holds the cases.
- `method`: upper-case.
- `path`: before the first `?` or `#`, lower-cased, `\` as `/`, repeated `/`
  collapsed. Browsers never send a `#`, but a raw client can, and Express,
  Koa, Fastify, gunicorn and nginx all drop it before routing: `POST /login#1`
  runs the login, so a `/login` kept as `/login#1` would miss every exact and
  suffix rule and every page limit.
- `query`: after the first `?`, up to a `#` (empty when there is none), lower-cased.
  The target is cut at its first `#` before either is taken, so in `/a#x?y` the
  `?y` is part of the fragment and the query is empty.
- `ua`: the user agent, lower-cased; the empty string when it is missing.
- Each of those **URL-decoded once** as well: a section matches if either the
  raw or the decoded text matches, so `%2e%2e%2f` is caught like `../`.
- The `path` also **as a router reads it**: `;params` dropped from each
  segment, decoded once, `\` as `/`, repeated `/` collapsed, `.` and `..`
  segments resolved (never above the root), lower-cased, from the **whole**
  path, never a cut one: `/./././…/login` is `/login` to Kestrel, Tomcat and
  nginx however many `./` it carries. A rule matches if any
  of the three forms does, so `/x/..;/actuator/env`, `/a/./b` and
  `/a;jsessionid=1/b` don't slip past a prefix rule for `/actuator/` or an
  exact one for `/a/b`. `probes` match the raw or the routed path too.

Then: `exact` is equality, `prefix`/`suffix`/`contains` are what they say, and
`regex` is a case-insensitive search. A rule with no section at all is ignored
(it would match everything).

- A client that **cannot read the body** (every one of ours in a middleware
  that runs before body parsing) **ignores any rule with a `body` section**
  rather than matching on the rest of it.
- A rule whose `regex` doesn't compile is ignored; the other rules still apply.
- The **server agent gets no request rules**: nftables and nginx see packets
  and addresses, never a path, and the collector hands it an empty list.

## Page limits

The site-wide `rate` treats every page alike. `limits` caps one kind of
request on its own: a login form posted ten times a minute, a checkout tried
five times, a search hammered. Why it looks the way it does:
`backend/docs/PAGE_LIMITS.md`.

```json
"limits": {
  "exempt": ["203.0.113.7", "198.51.100.0/24"],
  "rules": [
    { "id": "wp.login", "action": "monitor", "limit": 10, "window": 60,
      "methods": ["POST"], "path": { "exact": ["/wp-login.php"] } },
    { "id": "woo.add-to-cart", "action": "block", "limit": 30, "window": 60,
      "query": { "contains": ["add-to-cart="] } },
    { "id": "any", "action": "monitor", "limit": 600, "window": 600,
      "each": "path", "path": { "prefix": ["/"] } }
  ]
}
```

- `limits` is **additive**, like `requests`: a client that doesn't know the key
  ignores it, and the answer stays `v: 1`. Absent or `null` means no limits.
- `exempt`: addresses and ranges where many people share one address: the
  site's trusted addresses (an office, a team's VPN), Cloudflare's ranges for
  a site behind it, the private and loopback ranges listed under `flood`, our
  uptime checker and the search engines' published ranges — the same list as
  `flood.exempt`. Never counted against any page limit.
  `allow` (step 2 below) skips them as well, and so does `goodbots`.
- `id`: `[a-z][a-z0-9_.-]{1,39}`, reported back as the rule `limit:<id>`.
- `action`: `block` or `monitor`, as for a request rule: a limit only blocks
  when the site's `mode` is `block` *and* its action is `block`.
- `limit` (1–100,000) requests per `window` seconds (1–3,600), per address
  (an IPv6 address by its /64, as `rate`). A fixed window per limit, each
  limit its own count: one request can count toward several.
- `methods`, `path`, `query`: matched as a request rule's are (same
  preparation, the raw, decoded and routed path, any entry within a
  section, every named section), with `exact`, `prefix`, `suffix` and
  `contains` only — **no `regex`**, so the server agent's nginx can carry the
  same limit. A limit with neither `path` nor `query` is ignored.
- `each`: absent, or `"path"`: a separate count for every page (the routed
  path), not one for all the pages the limit matches. This is how one rule
  watches "any one page asked for far too often". Those counts stay on this
  server (never in a shared counter).
- A static file (the rule under `rate`) never counts toward a page limit as it
  is asked for, only after the response, as `rate` says.
- A shared counter, where the client has one, is keyed
  `afw:<site_id>:l:<id>:<who>:<window>`, `<who>` and `<window>` as for `rate`.
- Over its limit: in block mode with action `block`, answer **429** with
  `Retry-After: <window>` and a short plain-text body (`Too many requests to
  this page. Please wait a little and try again.`). Nothing is banned: a
  shopper who refreshes checkout too often is a customer, and the cap lifts
  when the window ends. Report it as rule `limit:<id>`; while the address
  stays over, every further request it makes there is reported too (grouped,
  as every event is).
- At most 50 limits. `sdk/protocols/page-limits-cases.json` holds the shared
  cases; every client's tests run them.
- **The server agent** gets the limits whose action is `block`, and enforces
  them in nginx only (block mode only, as its `flood` request limit: see
  there). The Windows agent gets none: IIS can't limit per page.

## Checking a request

All in memory, no network call:

1. Rules off or none yet → pass.
2. Address in `allow` → pass (skips everything below).
3. In `deny` → rule `deny`; else in `banned` or banned on this server → `ban`;
   else in `lists` → `list`; else in `shared` → `shared`. The first-party
   proxy's own paths (the tracker and its beacons, served from the site) get
   this step only: a denied or banned address gets nothing from us either,
   but beacons are never rate-limited, checked or matched against request
   rules.
4. Else a probe (`probes` above) → `probe`.
5. Else the first matching request rule (above) → `request:<id>`; in block mode
   and with the rule's action `block`, ban the address for its `ban` seconds
   too, as the rate limit does.
6. Else, unless the address is in `goodbots` or `limits.exempt` or the
   request is for a static file (`rate` above: it is compared with the
   counts so far instead, and counted after the response): count it toward every page limit that
   matches (above). The first limit, in the order sent, now over its count
   and blocking (block mode, action `block`) → `limit:<id>`, status 429.
   A limit over its count that only watches is reported as `limit:<id>`,
   action `monitor`, and the check **goes on** to step 7: watching the
   login page must not let a flood through it untouched by `rate`.
7. Else over the rate limit, and **not** in `goodbots` → `rate`. (A watched
   page limit from step 6 is reported as well.)
8. Else — and also when what matched in 3–7 is only watched (action
   `monitor`) — the browser check (`challenge`, under "Flood protection"
   below) is on and the request needs it → answer the check page, rule
   `challenge`, action `block`, reporting the watched match as well. Not a mode
   matter: the collector only sends `challenge` when the site is to be checked,
   and an address a site in monitor mode only watches must not skip a check
   every clean visitor gets.
9. Matched: in block mode answer 403 (429 with `Retry-After` for `rate` and
   `limit:<id>`); in monitor mode pass. A request rule whose action is `monitor` passes even in
   block mode. Either way, report it.

**A request another site made the browser send is refused, never banned.**
Any page can make a visitor's browser ask a site for `/.env` (an `<img>`, a
`no-cors` fetch, a redirect, a link) or ask for a page 120 times a minute, and
the request comes from the visitor's own address. So when `Sec-Fetch-Site` is
`cross-site` or `same-site` (any case), a probe, a request rule or the rate
limit still answers as above, but **bans no one** on this server, and the
event is reported with action `monitor`, so the collector bans nobody on the
site's other servers and counts nothing toward `shared` either. `same-origin`,
`none` or no header at all (every scanner and script) is treated as before.
A client that forges the header only gives up the ban: it is still refused
every time it trips a rule, and still over the rate while it floods.

Use a sorted range lookup (binary search) or a trie, not a list scan:
`lists` alone holds about 1,500 ranges.

Step 2 is why `allow` comes first and why the dashboard's own security check
has to be in it. That check asks the site for `/.env`, `/wp-config.php.bak`,
`/wp-json/wp/v2/users` and the rest, which is exactly what `probes` and the
`wp.config` request rule are for — so without the allowance the site blocks
its owner's own check and bans it for an hour, and the check, seeing a 403 at
every address, reports the site as clean. The collector puts the addresses in
`SCANNER_IPS` at the front of `allow` for every site; operators of a
self-hosted install have to set it to whatever addresses their backend makes
those requests from. The check also counts the refusals it got and says the
result is incomplete when most of them were refused, so a missing
`SCANNER_IPS` shows up as a finding rather than as a clean bill of health.

## Flood protection

Paid plans only (`floodProtection` in the backend's `Billing/plans.js`): for
any other site the three keys below are `null`. All three are additive, like
`requests`, so the answer stays `v: 1`. Why it is built this way:
`backend/docs/FLOOD_PROTECTION.md`.

```json
"flood": {
  "conn_rate": 30, "conn_max": 300,
  "req_rate": 20, "req_burst": 60,
  "ban": 600,
  "exempt": ["173.245.48.0/20", "66.249.64.0/27"]
},
"origin": { "only": ["173.245.48.0/20", "2400:cb00::/32"] },
"challenge": { "skip": ["/api/", "/wp-json/"], "exempt": ["66.249.64.0/27"] }
```

### `flood`: limits per address (the server agent only)

The packages ignore it: they have `rate`. The agent enforces it on the web
ports (`"ports"`), TCP and UDP:

- `conn_rate`: new connections per second from one address (burst twice that);
  `conn_max`: connections open at once from one address. Over either, the
  address goes into a ban set for `ban` seconds and, in block mode, every
  packet from it is dropped in the kernel. In monitor mode it is only counted.
- `req_rate` / `req_burst`: requests per second from one address in nginx, when
  nginx is there and its file is included (the agent's README says how). Static
  files (by extension) don't count: one page load asks for dozens. Over the
  limit, nginx answers 429, and the agent, reading nginx's error log (only
  lines that start with nginx's own date, level and connection prefix: the
  Referer and Host it copies into its lines are the sender's text), puts the
  address in the same ban set. In monitor mode nginx limits nothing: its
  `limit_req_dry_run` can't be scoped to one zone and would make the site's
  own `limit_req` log-only too, so `rate` is reported only in block mode.
- An **IPv6 address is counted and banned by its /64**: one machine usually
  holds the whole /64, so a per-address limit would never trip.
- Never counted or banned: `allow`, `goodbots`, `exempt`, and the private,
  loopback and shared ranges (`10/8`, `172.16/12`, `192.168/16`, `127/8`,
  `100.64/10`, `169.254/16`, `::1`, `fc00::/7`, `fe80::/10`), and anything
  arriving over loopback (the server's own requests to its public address go
  that way, with that address as the source). `exempt` holds
  Cloudflare's ranges (left out once the backend has seen, within the hour,
  that the site's domain doesn't resolve to Cloudflare: there they are just
  more of the internet), the private and loopback ranges above, and the
  search engines' published ones. That rule is
  what keeps a site behind Cloudflare or a load balancer online: all its
  traffic arrives from a handful of the proxy's addresses, and limiting those
  would cut off every visitor at once.
- Report each banned address once per ban as rule `flood` (the kernel limits)
  or `rate` (nginx's), with the packets or requests counted as `hits`, the
  address or /64 as `ip`, empty method and path. The agent reports a ban a few
  seconds after it starts, so `hits` is what the ban caught by then, not over
  its whole length.
- A ban outlives a change of the rules: the agent keeps the ban set out of the
  table it rewrites on every change of the lists.
- **The site's own nginx limits.** With `flood` in the rules, in either mode
  and whether or not the agent's own nginx file is in place, the agent also
  reads nginx's error logs for "limiting requests" lines of any zone that
  isn't its own (`analytics_flood`, the page limits' `sg_pl_…`), anchored to
  nginx's prefix as above. Every
  FLOOD_READ_EVERY (15 s) it reports what they refused as rule `nginx`,
  action `block` (nginx did refuse them), empty method and path, `hits` the
  requests: the busiest 500 addresses one row each, and all the others as one
  row per family, `ip` `0.0.0.0/0` and `::/0`, first in the report. Without
  those two a flood spread over thousands of addresses would arrive as 500 of
  them. Nothing bans on `nginx`, neither the agent nor the collector, and a
  `/0` row is never listed as an address: the site's own limit answered 429,
  which is all it asked for. The backend's flood watch counts `nginx` with
  `rate` and `ban`.

### `origin`: only Cloudflare reaches the site (the server agent only)

When present, the web ports accept traffic only from `origin.only` and
`allow` (and the private and loopback ranges listed under `flood`, which don't
come from the internet: a load balancer, Docker, a health check); everything
else is dropped in block mode, counted in monitor mode, and reported as rule
`origin` (per source, an IPv6 one by its /64, empty method and path). An
`origin` whose `only` holds no valid range is ignored: locking out everyone
but `allow` is never what it means. Likewise per family: IPv6 is locked only
when `only` holds an IPv6 range, IPv4 only when it holds an IPv4 one. The
agent applies all of this to traffic addressed to the server itself, never to
traffic it only routes (to a VM, a VPN client, a container's own address). This is
what stops an attacker who found the server's own address from going around
Cloudflare. The backend sends it only after checking that the site's domain
resolves to Cloudflare, and stops sending it when that changes.

### `challenge`: the browser check (the packages and the agent's nginx)

When present, a request gets a small page that sets a pass cookie with
JavaScript and reloads, instead of the site, when **all** of these hold:

1. The method is `GET` or `HEAD`. Never a `POST`: webhooks, forms and payment
   callbacks must keep working.
2. The `Accept` header (lower-cased) contains `text/html`. curl's default,
   `fetch()`, API clients and feed readers don't ask for it.
3. The path (lower-cased) starts with none of `skip`.
4. The address is in none of `allow`, `goodbots` and `exempt` (which holds
   the private and loopback ranges listed under `flood`, and Cloudflare's as
   `flood.exempt` does), and isn't one of the server's own: the server agent
   adds the machine's public addresses, since its requests to its own public
   address carry them (a cron job, WordPress's loopback, server rendering).
   The agent's own probe of the check (header `X-Analytics-Probe: 1`) gets
   the check from an exempt address too.
5. It has no valid pass.

The pass, per client:

- `key` = HMAC-SHA256 of `sg-challenge-v1`, keyed with the site secret.
- `day` = whole days since 1970-01-01 UTC; `who` = the IPv4 address (an
  IPv4-mapped IPv6 address as IPv4), or the first four groups of an IPv6
  address, each written as four lower-case hex digits (`2001:0db8:0000:0001`).
- The pass is `<day>.<first 32 hex digits of HMAC-SHA256(key, "<day>|<who>")>`,
  in the cookie `__sg_pass`. Valid for its own day and the next, compared in
  constant time. A browser can send the cookie more than once (a stale one
  on another path): read the raw `Cookie` header and accept any of the first
  four. Split it on `,` as well as `;`: a server that gets two `Cookie`
  headers joins them with a comma (gunicorn with none, others with ", "),
  and a pass in the second one still counts. nginx can't compute it per address, so the agent's nginx
  uses `who` = `*` and the cookie `__sg_passn`; a package never accepts that
  one.
- `sdk/protocols/challenge-cases.json` holds the shared cases (tokens, valid
  and invalid passes, which requests are checked); every client's tests run
  them.

The page: status `503`, `Content-Type: text/html; charset=utf-8`,
`Cache-Control: no-store`, `X-Robots-Tag: noindex`, and its own
`Content-Security-Policy` with a fresh nonce for its one inline script (a
site's own policy must not block it). The script sets the cookie
(`Max-Age=86400; Path=/; SameSite=Lax`, plus `Secure` when
`location.protocol` is `https:` — the browser's word, never the server's: a
proxy wrongly saying https would make the cookie impossible to set) and
reloads, but only when reading the cookie back shows it was set: with cookies
off it says so instead of reloading forever. It also stops after 3 reloads
within 60 seconds (counted in `sessionStorage`, or, where it is blocked or
full, in a `__sg_tries` cookie with `Max-Age=60`) and says the connection's
address keeps changing: the pass is bound to the address, so a visitor whose
address changes on every request would otherwise reload for ever. A
`<noscript>` line asks for JavaScript.
Report each checked request as rule `challenge`, action `block`. A `HEAD`
gets the same status and headers without the body.

It stops cheap floods (scripts that don't run JavaScript), not a real browser.
Say so wherever the dashboard offers it.

## Which layers a server has

Send `X-Firewall-Layers` on every rules fetch: the layers this server is
running, space-separated, from `kernel` (address lists in nftables, or in
iptables + ipset where there is no nftables; `flood` and `origin` likewise),
`nginx-lists` (address lists as nginx allow/deny lines, the agent's nginx backend,
in block mode and once nginx is shown to include the file),
`flood` (the kernel limits), `origin`, `nginx` (nginx's request limits),
`nginx-limits` (the page limits in nginx: block mode, at least one limit, and
the agent's http file shown included; `nginx` and `nginx-limits` are left out
while a `server` or `location` sets a `limit_req` of its own without the
agent's zones, since nginx then inherits none of ours there), `nginx-check` (nginx's browser check), `logs` (the request limit counted
from the web server's access logs by the server agent, any server: over the
limit an address is banned in the kernel as `rate`, or only reported in
monitor mode), `apache-check` (the browser check in Apache 2.4),
`litespeed-check` (in LiteSpeed Enterprise or OpenLiteSpeed), `caddy-check`
(in Caddy 2), `haproxy-check` (in HAProxy 2.2+), `app` (a package's firewall)
and `check` (a package's browser check). A `*-check` layer is sent only once
the server is shown to use the agent's file; `logs` only once a log has been
read. Either `nginx` or `logs` means requests are counted, so the agent's
`User-Agent` drops "no-rate". Send `X-Server-Name` with the host name
(100 characters at most). The dashboard shows them per server.

**Windows Server (IIS).** `sdk/windows-agent` (User-Agent
`analytics-platform-agent-windows/<version>`, "; no-rate" unless `logs` or `iis`
runs) puts the same rules in place with Windows Firewall and IIS. Its layers:
`windows-firewall` (address lists as inbound block rules on the web ports, group
`AnalyticsAgent`; in monitor mode no rules, the lists are watched in the IIS logs
and reported as `monitor`), `origin` (the complement of `origin.only` + `allow` +
private ranges, both families), `iis` (Dynamic IP Restrictions at server level
from `flood`, block mode only, exempt IPv4 ranges as `ipSecurity` allow entries;
off on a server with a public IPv6 address), `logs` (the request limit from IIS's
W3C logs, `c-ip` only) and `iis-check`. `conn_rate` has no Windows counterpart
and is ignored. In block mode, drops by Windows Firewall are not reported (it
keeps no per-rule counts). Like the Linux agent it is handed no request rules.

**The browser check in IIS** (`iis-check`) is server-level: the `__sg_passn`
cookie with `who = *`, as nginx. URL Rewrite answers a checked request with 503
and a private sub-status (default 71). An `httpErrors` entry for 503.<sub> only
serves the static check page, so real 503s are unaffected. The page carries the
day's pass in `data-pass`, and its policy allows its one script and style by
`sha256` hash, since a static page can't carry a nonce. IPv6 visitors are never
checked by IIS. The check is on only for sites whose error pages are shown as
configured.

## POST /events/firewall/events

```json
{
  "site_id": "<id>",
  "events": [
    { "at": "2026-10-17T12:00:00.000Z", "ip": "198.51.100.9", "rule": "deny", "action": "block",
      "method": "GET", "path": "/wp-login.php", "user_agent": "...", "hits": 14 }
  ]
}
```

`rule` is one of the names above, `request:<id>` for a request rule or
`limit:<id>` for a page limit.
Group identical (ip, rule, action, method, path) into one row with `hits`,
send every few seconds, at most 200 rows per request. `path` without the query
string, 300 characters at most.

## Must

- **Fail open:** a failed fetch keeps the last rules; no rules means every request passes.
- **Never block the request on the network:** fetches and reports run in the background.
- **Trusted address only:** read forwarding headers only from proxies the site
  owner says they run.
  - A hop in `X-Forwarded-For` may carry a port, `203.0.113.5:54321` or
    `[2001:db8::1]:443` (Azure App Service and Application Gateway send
    them): strip it. A hop that still isn't an address means the
    connection's own address, never a request that skips the checks.
  - Don't count a hop twice. Some servers resolve the address themselves
    and **take the entries they used out of the header** (Apache
    `mod_remoteip`, ASP.NET Core's forwarded headers, Tomcat's
    `RemoteIpValve`): counting the client's hops again past them reads an
    entry the visitor wrote. Where the package can see that a framework has
    resolved the address with a bounded trust (Express or Fastify with a hop
    count or a subnet list, Laravel's or Symfony's trusted proxies, werkzeug's
    `ProxyFix`), it uses that. A framework setting that trusts **every** hop
    (Express `trust proxy` `true`, Fastify `trustProxy: true`, Koa
    `app.proxy` without `maxIpsCount`, Uvicorn `--forwarded-allow-ips='*'`)
    takes the leftmost entry, which the visitor writes, and is read as one
    hop instead.
- Drop reports rather than queue without end (2,000 rows is plenty).
- **Security headers** from the dashboard (`headers` in the platform config)
  are added only when the name is one of the nine the dashboard can produce
  (`Strict-Transport-Security`, `X-Content-Type-Options`, `X-Frame-Options`,
  `Referrer-Policy`, `Permissions-Policy`, `Cross-Origin-Opener-Policy`,
  `Content-Security-Policy`, `Content-Security-Policy-Report-Only`,
  `Reporting-Endpoints`), in any case, and the value is visible ASCII, spaces
  and tabs (no line break, control character or byte past `~`), at most
  4,000 characters. A list of what's allowed, not of what isn't, so even a
  config from a server that is no longer ours can't make the app grant
  another site its users' data (`Access-Control-Allow-*`), send every page
  elsewhere (`Refresh`), log everyone out (`Clear-Site-Data`) or change what
  a response is. The backend refuses anything else when it is saved and the
  collector drops it when it is handed out; the package checks again. Every
  client runs `header-cases.json`; a new header on the dashboard needs a
  release of every package before it is added anywhere.
- **The maintenance bypass code** is compared in constant time, and its
  cookie carries `Secure` when the request came over HTTPS.
