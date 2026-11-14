# SiteGoose (Java)

One package for your Java server, run from your analytics dashboard: a
**firewall**, **error monitoring** and **server analytics** (payments,
sign-ups, leads). Spring Boot 3, and any servlet container: Tomcat, Jetty,
Undertow, WildFly, Payara. Nothing at runtime but the JDK; Java 11 or later
(the Spring Boot starter needs 17, as Spring Boot 3 does).

Maven:

```xml
<dependency>
  <groupId>com.sitegoose</groupId>
  <artifactId>sitegoose</artifactId>
  <version>0.3.4</version>
</dependency>
```

Gradle:

```kotlin
implementation("com.sitegoose:sitegoose:0.3.4")
```

## Spring Boot 3

Add the dependency and three properties; nothing else to write.

```properties
# application.properties
analytics.site-id=YOUR_SITE_ID
analytics.site-secret=${ANALYTICS_SITE_SECRET}
analytics.endpoint=https://collect.example.com
```

Behind a proxy or load balancer, the visitor's address is usually Spring
Boot's business already: with `server.forward-headers-strategy=native`, or on
a cloud platform where Spring Boot turns it on by itself (Kubernetes, Cloud
Foundry, Heroku, Azure App Service), the starter uses the address the server
works out and **ignores `analytics.trust-proxy`** (with a warning), because
what's left in `X-Forwarded-For` then is whatever the visitor wrote. With
`framework`, Spring's `ForwardedHeaderFilter` believes the leftmost
`X-Forwarded-For` or `Forwarded` entry, which is the visitor's own writing, so
the filter reads the request from under it and counts from the right instead:
one proxy, or as many as `analytics.trust-proxy` says. Set
`analytics.trust-proxy=1` when Spring Boot doesn't read the proxy headers
itself (see "The visitor's address").

(Or only environment variables: `ANALYTICS_SITE_ID`, `ANALYTICS_SITE_SECRET`,
`ANALYTICS_ENDPOINT`, `ANALYTICS_TRUST_PROXY`.)

The starter:

- puts the filter in front of every other filter, Spring Security's too, so
  turned-away requests cost your app nothing;
- reports exceptions your app doesn't handle, and also the ones Spring
  handles itself when the answer is still a 500 (an `@ExceptionHandler`
  returning 500, Spring Boot's error page);
- names each request by its route pattern (`/orders/{id}`), in Server speed
  and in Errors;
- times the `RestTemplate`, `RestClient` and `WebClient` calls made through
  Spring's builders (Health → Server speed → Calls, below) and turns them into
  breadcrumbs (steps before an error);
- with Spring Security: failed logins count for bot protection, and logins
  and logouts go in the audit log (`user.login`, `user.logout`);
- with `analytics.errors.capture-logging=true`: exceptions logged at `ERROR`
  through Logback (`log.error("...", e)`) are sent too;
- checks the settings that leave a Spring site open (actuator endpoints
  exposed, stack traces on error pages, the H2 console, session cookie
  flags) and the folders Spring serves as static files (posture);
- times the database queries run through every `DataSource` bean (JDBC,
  JPA/Hibernate, jOOQ, MyBatis: all of them go through it), Spring Boot's
  `MongoClient` and Spring Data Redis's Lettuce client (Health → Server
  speed → Queries, below).

The `Platform` is a bean: inject it for `track()`, `isEnabled()`, `audit()`
and the rest. Spring closes it with the context, after its last request.

Every option is a property: `analytics.server-name`, `analytics.debug`,
`analytics.<module>.enabled=false` for any module below,
`analytics.firewall.mode`, `analytics.firewall.cache-file`,
`analytics.errors.release`, `analytics.errors.capture-uncaught`,
`analytics.errors.capture-logging`, `analytics.errors.spool-dir`,
`analytics.queries.enabled=false`, `analytics.calls.enabled=false`,
`analytics.proxy.prefix`, `analytics.inventory.sbom`,
`analytics.posture.root`. To set options the properties can't express (a
shared rate-limit counter, `beforeSend`), declare your own `Platform` bean:
the starter uses it.

Spring Boot 2 (javax): use the javax filter below, registered as a
`FilterRegistrationBean` with `Ordered.HIGHEST_PRECEDENCE` and
`setAsyncSupported(true)`.

**WebFlux** isn't supported yet: there is no servlet filter to put in front,
so in a reactive (or non-web) app the starter turns off the modules that work
on requests (firewall, proxy, maintenance page, security headers, Server
speed, crawlers), and says so in the log. Errors, `track()`, the audit log,
flags, inventory, posture and resources still work.

## Any servlet app

`com.sitegoose.analytics.jakarta.PlatformFilter` (Servlet 5+: Tomcat 10+,
Jetty 11+, Undertow 2.2+, WildFly 27+) or
`com.sitegoose.analytics.javax.PlatformFilter` (Servlet 3.1/4: Tomcat 8.5/9,
Jetty 9/10). Map it first, to `/*`:

```xml
<!-- web.xml -->
<filter>
  <filter-name>analytics</filter-name>
  <filter-class>com.sitegoose.analytics.jakarta.PlatformFilter</filter-class>
  <async-supported>true</async-supported>
</filter>
<filter-mapping>
  <filter-name>analytics</filter-name>
  <url-pattern>/*</url-pattern>
</filter-mapping>
```

It reads `ANALYTICS_SITE_ID`, `ANALYTICS_SITE_SECRET`, `ANALYTICS_ENDPOINT`,
`ANALYTICS_TRUST_PROXY` and `ANALYTICS_SERVER_NAME` from the environment, or
init-params `site-id`, `secret`, `endpoint`, `trust-proxy`, `server-name`.

For options in code, create the platform yourself and hand it over:

```java
Platform platform = Platform.create(new PlatformOptions()
    .siteId("YOUR_SITE_ID")
    .secret(System.getenv("ANALYTICS_SITE_SECRET"))
    .endpoint("https://collect.example.com")
    .trustProxy("1")
    .firewall(f -> f.cacheFile("/var/tmp/firewall-rules.json")));

// embedded Jetty/Tomcat, or ServletContext.addFilter(...) in a listener:
FilterRegistration.Dynamic filter = context.addFilter("analytics", new PlatformFilter(platform));
filter.setAsyncSupported(true); // or every async servlet behind it fails
filter.addMappingForUrlPatterns(null, false, "/*");
// or: servletContext.setAttribute(PlatformFilter.CONTEXT_ATTRIBUTE, platform) and the web.xml above
```

Name your routes for Server speed and Errors (Spring does it for you): set
the request attribute `Platform.ROUTE_ATTRIBUTE` to the pattern
(`"/orders/{id}"`). Without one, ids in the path are folded (`/orders/:id`).

### Quarkus, Micronaut, Helidon

- **Quarkus** with `quarkus-undertow` (servlet) takes the jakarta filter: list
  it in `src/main/webapp/WEB-INF/web.xml` as above, or create the `Platform`
  as an `@ApplicationScoped` producer. On RESTEasy Reactive without
  servlets there's no filter to hang it on yet: call `platform.blocked(...)`
  from a `@ServerRequestFilter` and `platform.captureException(...)` from an
  `ExceptionMapper`.
- **Micronaut** on its servlet runtime (`micronaut-servlet-jetty`/`-tomcat`)
  takes the jakarta filter; on Netty, the same two calls from an
  `@ServerFilter` and an `ExceptionHandler`.
- **Helidon MP 4** (Jakarta EE): the jakarta filter.

Everything the filters do is public on `Platform` (`proxyResponse`,
`blocked`, `maintenanceResponse`, `securityHeaders`, `enterRequest`,
`timeRequest`, `recordCrawler`, `captureException`), so another framework's
adapter is about forty lines; see `PlatformFilter`.

## Background jobs

```java
platform.job("send-receipts", () -> sendReceipts());           // runs it now, timed, errors named after the job
executor.submit(platform.wrapJob("nightly-export", this::export)); // the same, for an executor or a scheduler
```

A run that throws counts as failed (Health → Server speed → Jobs), its error
is sent with the job's name as its route, and the exception is thrown on.

## Database queries

Which queries each route runs, how often, how long they take and how many
fail (Health → Server speed → Queries; protocol: `sdk/protocols/queries.md`).
Every value in a query is replaced by `?` before it is counted, bound
parameters are never read, and nothing about them leaves your server. The
Spring Boot starter does it all; otherwise one line per database:

```java
DataSource dataSource = platform.wrap(new HikariDataSource(config));   // plain JDBC: use what wrap() returns

MongoClient mongo = MongoClients.create(MongoClientSettings.builder()
    .applyConnectionString(new ConnectionString(uri))
    .addCommandListener(platform.mongoListener())                     // the MongoDB driver
    .build());

RedisClient redis = RedisClient.create(uri);
redis.addListener(platform.redisListener());                          // Lettuce 6.1+, before it connects
```

Queries are counted under the request (or `platform.job`) they ran in, by
the route Server speed names it with; queries outside both count as
`JOB (background)`. With the reactive MongoDB driver, commands start on the
driver's own threads, so they count as background. They ride on the
`performance` module: switch it off, or `new PlatformOptions().queries(false)`,
and nothing is timed. A `DataSource` wrapped twice (a routing data source in
front of a wrapped pool) counts each query once.

**Redis**: each Lettuce command is counted as its name and its first key's
shape (`GET user:?:cart`), never a value; blocking reads (`BLPOP`, `XREAD
BLOCK`) aren't timed. The starter adds the listener to Spring Data Redis's
Lettuce client. A pipeline or `MULTI`/`EXEC` reaches Lettuce's listener one
command at a time, so each command is counted on its own. Jedis has no hook
to time its commands through, so its commands aren't counted.

**ClickHouse**: its JDBC driver (`com.clickhouse:clickhouse-jdbc`, URLs
`jdbc:clickhouse:` and `jdbc:ch:`) goes through `wrap()` like any other, and
its queries are labelled ClickHouse. The newer `client-v2`
(`com.clickhouse.client.api.Client`) has no public hook to time queries
through, so its queries aren't counted.

## Outgoing calls

How long each route waited on other services (a payment provider, an email
API, your own microservices) by the host it called (`api.stripe.com`), and how
many calls failed (Health → Server speed → Calls; protocol:
`sdk/protocols/calls.md`). The Spring Boot starter times `RestTemplate`,
`RestClient` and `WebClient` through Spring's own customizers; otherwise one
line per HTTP client:

```java
OkHttpClient client = new OkHttpClient.Builder()
    .addInterceptor(platform.okHttpInterceptor())                    // OkHttp
    .build();

HttpResponse<String> res = platform.send(httpClient, request, BodyHandlers.ofString());  // java.net.http, in place of httpClient.send(...)
platform.sendAsync(httpClient, request, BodyHandlers.ofString());                        // and sendAsync(...)

platform.recordCall("POST", url, startedNanos, status);              // any other client: status 0 when no answer came
```

- **Only the host is sent.** A call's path, query string, headers and body
  never leave your server: paths carry IDs and keys.
- A call is timed from being sent to its response's headers arriving; a body
  read afterwards isn't counted. No answer (refused, timed out, reset) or a
  5xx is a failed call; a 4xx is the other side's answer, not a failure. A
  call your code cancels isn't counted (OkHttp's own `callTimeout` is a
  timeout, and counts as failed).
- A call two hooks see (a `RestTemplate` on OkHttp whose client has the
  interceptor too) is counted once, by the outer one.
- Calls are filed as queries are: under the request, the `platform.job()`, or
  `JOB (background)`. OkHttp's `enqueue()` runs on OkHttp's own threads, so
  those calls are background; `WebClient` calls belong to the thread that
  subscribed (a `block()` in a controller). The package's own calls to us are
  left out.
- Each call is also a step in the error trail.
- They ride on the `performance` module; `new PlatformOptions().calls(false)`
  leaves them out and keeps Server speed.

There is no job-queue reader for Java (no queue library is common enough to
hook): time each job with `platform.job("send-email", work)` instead.

## Modules

| Module | What it does | Default |
|---|---|---|
| `firewall` | Blocks addresses, known criminal networks, shared blocks and floods (Security → Firewall); with its attack patterns, rules that match the request's path, query and user agent (protocol: `sdk/protocols/firewall.md`) | on |
| `proxy` | Serves the tracker and takes visits under your own domain, so ad blockers can't hide those visitors | on |
| `errors` | Sends your server's errors to the Errors report | on |
| `analytics` | `track()`, `identify()` and `lead()` from your server | on |
| `audit` | `platform.audit("user.role_changed", actor, target, details)`; Spring Security logins and logouts on their own | on |
| `flags` | `platform.isEnabled("new-checkout", user.getId())`: features on or off from the dashboard | on |
| `maintenance` | A "back soon" page while maintenance mode is on in the dashboard | on |
| `headers` | Adds the security headers you pick on the Security page; your own headers win | on |
| `forms` | Checks forms before you accept them: `platform.checkForm(request)` | on |
| `performance` | Response times and errors of every route (Health → Server speed). Server-sent event streams (`text/event-stream`) are left out: they stay open on purpose | on |
| `crawlers` | Which search engines and AI bots fetch your pages (Off-site → Crawlers); the filter counts them | on |
| `inventory` | The libraries on the classpath (Maven `group:artifact`, read from each jar's `pom.properties`, also inside a Spring Boot fat jar or a war; or a CycloneDX SBOM) and the Java version, once a day, so the Security check can flag known security holes | on |
| `posture` | How the server is set up, once a day: whether it runs as root, code anyone on the machine can write, files in the folders you serve that shouldn't be public (a dump, a `.env`, a `.bak`), and Spring Boot's settings. Reads only, and sends no file's contents. `posture(p -> p.root("/srv/www", "/"))`, `p.checks(supplier)` for checks of your own (protocol: `sdk/protocols/posture.md`) | on |
| `resources` | The machine's CPU, load, memory and disks, every minute (Health → Server resources; protocol: `sdk/protocols/resources.md`). `/proc` on Linux; elsewhere the JVM's own figures. Also how close the app is to a wall (below) | on |

Each module takes `true`, `false` or its options:

```java
new PlatformOptions()
    .firewall(f -> f.mode("monitor").cacheFile("/tmp/firewall-rules.json"))
    .errors(e -> e.captureUncaught(false).release("1.4.2"))
    .analytics(false);
```

**How close it is to a wall** (`resources`): each row also carries the
container's own memory and CPU caps (cgroup v1 or v2) with its working set,
how often the cap throttled it and processes killed for memory, the machine's
waiting time (`/proc/pressure`), connections refused before the app accepted
them, the connection-tracking table, open files against the limit, the JVM's
heap against `-Xmx`, milliseconds the app was paused for garbage collection
(a concurrent collector's work beside the app isn't counted), and the most
requests in progress at once (counted by the filter). A figure this machine
doesn't give is left out, never sent as 0: a bare machine has no caps to
report, and off Linux only the heap, garbage collection, the JVM's uptime and
the requests in progress are sent. Several
JVMs under one `server-name` are told apart, so their heaps aren't mixed up.
The JVM's own kill for memory can't be reported by the JVM: a restart shows as
its uptime starting again.

**Switch modules off in the dashboard** (Security → Server package) without a
deploy: the package checks about once a minute. Modules are independent: one
failing to start, or the collector being down, never stops the others, and
never slows your requests. Sending happens on four daemon threads; queues are
bounded, and what's waiting is sent at shutdown (a JVM shutdown hook, or
`platform.close()`).

## Firewall

Rules, monitor or block mode and reports are in the dashboard (Security →
Firewall). New sites start in monitor mode.

Options: `mode` (`"monitor"` or `"block"`, overrides the dashboard),
`cacheFile` (keep rules between restarts), `trustProxy`, `counter`.

**The visitor's address:** behind a proxy every request comes from the proxy
unless you set `trustProxy`: `"1"` for one proxy or load balancer, `"2"` for
Cloudflare in front of a load balancer, `"cloudflare"` when every request
comes through Cloudflare (`CF-Connecting-IP` is believed only from
Cloudflare's own addresses). A port after the address (`203.0.113.5:54321`,
as Azure sends it) is dropped; a hop that isn't an address is ignored and the
connection's address used.

**If the container already reads those headers, leave `trustProxy` unset.**
Tomcat's `RemoteIpValve` or `RemoteIpFilter`, Jetty's
`ForwardedRequestCustomizer`, Undertow's `proxy-address-forwarding`, WildFly's
`proxy-address-forwarding="true"`, Spring Boot's
`server.forward-headers-strategy`: they put the visitor's address in
`getRemoteAddr()` and leave in `X-Forwarded-For` only what the visitor wrote,
so `trustProxy` would believe a forged address (and let anyone get someone
else banned). The filter notices Tomcat's valve and filter (they mark the
request) and the Spring Boot starter its own settings, and use the
container's address then; it can't tell for Jetty, Undertow or WildFly.
Spring's `ForwardedHeaderFilter` is the exception: the filter reads the
request from under it, so there `trustProxy` applies as usual.

**Rate limit with several instances:** each JVM counts on its own. For one
count, pass a shared counter:

```java
.firewall(f -> f.counter((key, ttl) -> {
    long hits = redis.incr(key);
    if (hits == 1) redis.expire(key, ttl);
    return hits;
}))
```

**Page limits** (set in the dashboard): one kind of request capped on its own,
say ten login posts a minute per address. Over a limit that blocks, the
visitor gets a 429 with `Retry-After` and a one-line note; nothing is banned,
and the cap lifts when the window ends. The shared counter above counts them
too, except a limit that counts every page apart, which stays in this JVM.

**Bot protection:** Spring Security's failed logins are counted on their
own; elsewhere call `platform.loginFailed(request)` when a login fails.

**Probes** (`/.env`, `/.git/…`, backups) are rule `probe`; in block mode the
address is also banned here.

Attack patterns and probes are matched against the path as sent, decoded
once, and as the container will route it (`/actuator;x/env` and
`/a/../actuator/env` are `/actuator/env`): a hit on any of them counts. The
rate limit and the page limits leave the app's own static files alone, which
come a dozen to a page: a path, as the container routes it, ending in `.css`,
`.js`, an image, a font, audio or video, `.pdf` or `.wasm`, or under
`/static/`, `/_next/static/` or `/assets/` (so `/admin;x.css` is `/admin`,
and counts). Everything else still applies to them. A denied or banned address is also
refused the tracker's own addresses (the proxy); the rate limit and the browser
check never apply to those.

**Browser check** (paid plans, switched on in the dashboard). A visitor's
first page of the day is a short "checking your browser" page that sets a
cookie with JavaScript and reloads. Only a `GET` or `HEAD` asking for a web
page is checked: forms, webhooks, API calls (`Accept: application/json`), the
paths you exclude, your allowed addresses, search engines and AI crawlers
never see it. The cookie, `__sg_pass`, holds a signed day bound to the
visitor's address; it is strictly necessary and needs no consent.

## Error monitoring

The filter reports what your app throws (and, with Spring, the 500s it
handles), with the request's method, path, route, visit and the steps before
it. Elsewhere:

```java
try { ... } catch (PaymentException e) { platform.captureException(e); }
platform.addBreadcrumb("charged the card");
```

Exceptions on threads nobody catches (`Thread.setDefaultUncaughtExceptionHandler`)
are sent too (`captureUncaught(false)` to leave them alone) — except in a war
inside a container that runs several apps (Tomcat, WildFly, WebLogic…): the
JVM's handler is shared by all of them there, so it's left alone, and only
the requests' errors are reported. A visitor who hangs up mid-answer (broken
pipe, `ClientAbortException`) is not an error.
`captureLogging(true)` sends `java.util.logging` records at `SEVERE` with an
exception; for Logback outside Spring Boot,
`com.sitegoose.analytics.logback.PlatformAppender.attach(platform)`.
Container wrappers (`ServletException`, `InvocationTargetException`, …) are
taken off, so errors group by what went wrong. Errors the collector couldn't
take wait in a file (`spoolDir`, default the temp folder) and are sent once
the collector answers, after a restart too; the file is only removed once
what it holds was taken. `beforeSend((event, error) -> ...)` edits or drops an event.

## Server analytics

```java
platform.track("order.paid", Map.of("value", 49.0, "currency", "EUR"));
platform.identify(user.getId());
platform.identify(user.getId(), null, Map.of("plan", "pro", "seats", 5, "trial", false)); // with traits
platform.lead(Map.of("email", form.getEmail(), "source", "contact"));
```

They join the visit through the `X-Analytics-Session` header the tracker
sends, read from the request in progress (or the session ID you pass;
`null` for the request's).

`identify()`'s optional traits are name to text, a number or a boolean; other
values are left out (and so is `traits` when nothing is left). The collector
does the rest: names are lowercased with spaces and dashes as `_` (up to 40
letters, digits and `_`), text is cut at 200 characters, values that look
like an email address are dropped, and at most 20 are kept.

## Ad blockers

`platform.proxy().scriptUrl()` is the tracker's address on your own domain
(`/3f9a2c1b/js/v1/s.js`): put it in the page's script tag. The filter
answers those addresses before anything else.

## Shutting down and serverless

`platform.flush()` sends what's waiting (before a function returns);
`platform.close()` stops the background work and sends it, all of it within
8 seconds: a stop or redeploy never waits on a collector that doesn't answer
(errors not sent by then wait in their file for the next start). Its threads
end with it (on Java 21 the HTTP client's too), so a redeployed war leaves
nothing running. A shutdown hook does it for you unless `shutdownHook(false)`;
Spring and the filter (when it created the platform) close it themselves.

## Tests

The shared cases are read from `sdk/protocols`, beside this folder, so mount
the whole `sdk` folder, not only this one:

```sh
cd sdk
docker run --rm -v "$PWD:/src" -w /src/platform-java maven:3.9-eclipse-temurin-21 mvn -B test
```

With only this folder mounted, add `-v "$PWD/../protocols:/protocols:ro"` and
`-Dprotocols.dir=/protocols`.
