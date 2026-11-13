# Calls protocol (v1)

What a server package reports about **the outgoing HTTP calls the site's own
code makes**: per minute, per route and per host it called, how many calls,
how many failed, their total and slowest time and a count per time bucket.
The other half of why a route is slow, beside its database queries
(`queries.md`): `/checkout` takes 900 ms, and 700 of them are waiting on the
payment provider.

The dashboard shows it in Health → Server speed → Calls
(`backend/Sections/Analytics/health/serverCalls.js`). The collector side is
`expresscollect/Analytics/serverCalls.js`; the table is `analytics.server_calls`
(`clickhouse_worker/migrations/20261104_server_calls.sql`). OpenTelemetry
senders get the same rows from their HTTP client spans
(`expresscollect/Analytics/otlp/traces.js`).

**Only the host is kept.** A call's path, query string, headers and body never
leave the customer's server: paths carry IDs and tokens (`/v1/customers/cus_8x…`,
`?key=…`), and a host says who the time went to, which is the question.

## Endpoint

`POST /events/server-calls`, `Authorization: Bearer <secret>`, a `User-Agent`
naming the client and its version, like queries:

```json
{
  "site_id": "<24 hex>",
  "server_name": "web-1",
  "runtime": "Node 26.13.0",
  "rows": [
    {
      "minute": "2026-11-04T10:15:00.000Z",
      "method": "POST",
      "route": "/checkout",
      "host": "api.stripe.com",
      "call_method": "POST",
      "count": 12,
      "errors": 0,
      "sum_ms": 4310.4,
      "max_ms": 812.2,
      "buckets": [0, 0, 0, 0, 0, 3, 8, 1, 0, 0, 0, 0]
    }
  ]
}
```

- `server_name`, `runtime`, `minute`, `method`, `route`, `buckets`, `sum_ms`,
  `max_ms`: exactly as in `queries.md`, so a route's calls join its requests.
  A call outside any request or job is `JOB` `(background)`.
- `host`: the host called, lower case, with its port when it isn't the
  scheme's default (`localhost:8080`, `[::1]:3000`). At most 255 characters
  of `a-z 0-9 . - : [ ] _`; anything else is refused.
- `call_method`: the call's own HTTP method (`GET`, `POST`...).
- `errors`: calls that got no answer (refused, timed out, reset) or a 5xx. A
  4xx is the other side's answer, not a failure of the call.

At most 500 rows a request. Answers as `queries.md`: `202` stored
(`enabled: false` when Server speed is off), `400`/`401` refused, `429`/`503`
with `Retry-After`.

## Turning it on

Calls ride on the **performance** module switch, like queries. Each package
takes a `calls: false` option that keeps Server speed and leaves calls out.

## Recording

As `queries.md` "Recording", with the host and call method in place of the
database and statement:

1. Time each call through the HTTP library's public hook. Never patch a
   library's private code.
2. Leave out the package's own calls to the collector (its endpoint's host).
3. Add it to the request it ran in, keyed by `call_method` + `host`. Past
   **50** distinct hosts in one request, new ones go under host `(other)`.
4. When the request finishes, add its map into the minute's rows, keyed by
   `minute | method | route | call_method | host`. Past **200** keys in a
   minute, new hosts go under `(other)`; past **300** nothing new is kept.
5. Flush finished minutes every 60 seconds, and everything on shutdown.

A call is timed from the request being sent to the response's headers
arriving: what the code waited for before it could go on. A body streamed
afterwards isn't counted.

## Hooks per package

| Package | Caught by | Setup |
| --- | --- | --- |
| Node | `diagnostics_channel`: `undici:request:*` (`fetch`) and `http.client.request.*` / `http.client.response.finish` (`http`, `https`, and the libraries on them: axios, got, node-fetch) | automatic |
| Python | `requests`: each adapter the `Session` has mounted, wrapped in a delegating `BaseAdapter`. `httpx`: `event_hooks` on `Client`/`AsyncClient` (answered calls only), or a wrapped transport passed as `transport=` (calls with no answer too; both on one client count once). `urllib3` and `urllib.request` have no public hook and aren't counted | `platform.watch_http(session_or_client)` |
| PHP (Laravel) | the `Http` client's events: `RequestSending` → `ResponseReceived` / `ConnectionFailed` (Laravel fires the answer after the body is read, so the time includes it) | automatic |
| PHP (Symfony) | `HttpClientBreadcrumbs`, a decorator of the app's `HttpClient`, to the first chunk | services.yaml |
| PHP (Guzzle) | `$platform->guzzleMiddleware()`, to `on_headers` | one line |
| WordPress | `pre_http_request` (last, value unchanged) → `http_api_debug`; the time includes the body; non-blocking calls are left out | automatic |
| Ruby | a Faraday middleware registered in Faraday's own registry (`f.request :sitegoose`); the time includes the body, which Faraday hands back whole. `SiteGoose.time_call(host) { }` for anything else. No `Net::HTTP` hook: it has none that isn't patching | one line per connection |
| Java | Spring Boot: `RestTemplateCustomizer` / `RestClientCustomizer` (an interceptor) and `WebClientCustomizer` (an `ExchangeFilterFunction`). OkHttp: `platform.okHttpInterceptor()`. `java.net.http`: `platform.send(client, request, handler)` / `sendAsync(...)`, timed when the body handler is handed the headers. Anything else: `platform.recordCall(method, url, startedNanos, status)` | automatic (Spring), or one line |
| .NET | `HttpClient`'s `HttpHandlerDiagnosticListener` (`System.Net.Http.HttpRequestOut.Start` / `.Stop`): every `HttpClient`, `IHttpClientFactory`'s, and the SDKs built on them. A ClickHouse client's requests are its queries, not calls | automatic |
| Go | `p.Transport(base)`: an `http.RoundTripper` around the app's own transport (the one breadcrumbs use). Nothing global is replaced | `&http.Client{Transport: p.Transport(nil)}` |
