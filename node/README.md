# analytics-server-errors

Sends your Node server's errors to the analytics **Errors** report, next to the
errors your visitors hit in the browser. No dependencies; Node 18 or later.

```bash
npm install analytics-server-errors
```

```js
import { initServerErrors, errorHandler, captureException } from "analytics-server-errors";

initServerErrors({
  siteId: "YOUR_SITE_ID",
  secret: process.env.ANALYTICS_SITE_SECRET, // site settings; keep it on the server
  endpoint: "https://YOUR_COLLECTOR_URL",
});

// Express: after your routes. Captures 5xx errors and passes them on.
app.use(errorHandler());

// Errors you catch yourself:
try {
  await chargeCard(order);
} catch (error) {
  captureException(error, { req, status: 502 });
  throw error;
}
```

- **Uncaught exceptions and unhandled rejections** are captured on their own.
  The process still prints the error and exits with code 1, as it would without
  the SDK (after up to 2 seconds to send it). If your app has its own
  `uncaughtException` handler, that handler decides instead.
- **Batches:** errors are sent every 2 seconds or 10 at a time. At most 100
  wait to be sent; more are dropped. Sending never throws into your app.
- **Limits:** up to 10 errors per request and 300 requests a minute per site.
  The collector stores up to 1,000 occurrences of one issue per day (50,000
  per site). Past that, occurrences are counted, not stored,
  so the counts stay right.

## Link errors to visits

Send the browser tracker's session ID with your site's requests, and the SDK
reads it from the request. The error then links to the visit's replay and
counts in "What errors cost":

```js
fetch("/api/orders", {
  method: "POST",
  headers: { "x-analytics-session": window.analyticsSession?.getId() || "" },
  body,
});
```

## Options

| Option | Default | |
| --- | --- | --- |
| `serverName` | the host name | Shown per occurrence. |
| `root` | `process.cwd()` | Stack paths are made relative to it, so issues stay the same across servers and deploy folders. |
| `captureUncaught` | `true` | `false` to capture only through `errorHandler` and `captureException`. |
| `beforeSend(event, error)` | | Change an event, or return `null` to drop it. |
| `debug` | `false` | Logs send failures. |

`errorHandler({ shouldCapture(error, req) })` overrides the 5xx rule.
`flush()` sends what is queued, for example before a serverless function returns.

Messages, stacks and paths are masked again by the collector (emails, tokens,
long numbers, query strings). Still, don't put personal data in error messages.

## Other languages: the HTTP API

`POST {endpoint}/events/server-errors` with JSON:

```json
{
  "site_id": "YOUR_SITE_ID",
  "sitesecret": "YOUR_SITE_SECRET",
  "errors": [{
    "message": "Cannot read properties of undefined (reading 'id')",
    "error_type": "TypeError",
    "stack": "TypeError: ...\n    at getOrder (src/orders.js:42:7)",
    "kind": "handled",
    "method": "GET",
    "path": "/orders/123",
    "route": "/orders/:id",
    "status_code": 500,
    "session_id": "the tracker's session ID, if known",
    "server_name": "web-1",
    "runtime": "Node",
    "runtime_version": "20.11.0",
    "os": "linux"
  }]
}
```

Only `message` is required. Up to 10 errors per request. `kind` is `error`
(uncaught), `rejection` (unhandled promise rejection) or `handled`. Issues are
grouped by error type, message (numbers and IDs ignored) and the top stack frame
outside `node_modules`; frames are read in the `at fn (file:line:col)` form.

Responses: `202` accepted, `400` invalid data, `401` wrong site ID or secret,
`429` too many requests and `503` unavailable (both: try again after
`Retry-After` seconds).
