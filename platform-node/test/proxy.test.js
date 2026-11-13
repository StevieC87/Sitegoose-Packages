// The first-party proxy: which addresses it answers, what it refuses, and
// what it passes on to the collector. A real collector stands in for ours, so
// the forwarding itself is checked and not just the gate.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const { Readable } = require("node:stream");
const { createProxy, prefixFor, keyFor } = require("../lib/proxy.js");

const TRACKER = `// a tracker${"x".repeat(600)}`;

// Stands in for the collector, and records what reached it.
function upstream() {
  const seen = [];
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => {
      seen.push({ url: req.url, method: req.method, headers: req.headers, body: Buffer.concat(chunks).toString() });
      if (req.url.endsWith(".js")) {
        res.writeHead(200, { "content-type": "application/javascript" }).end(TRACKER);
      } else {
        res.writeHead(202, { "content-type": "application/json" }).end('{"ok":true}');
      }
    });
  });
  return new Promise((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve({ seen, server, port: server.address().port }));
  });
}

// Closes the stand-in collector however the test ends, so a failure doesn't
// leave the run hanging on an open socket.
async function withUpstream(run) {
  const up = await upstream();
  try {
    await run(up);
  } finally {
    up.server.close();
  }
}

function fakeCore(endpoint) {
  return { endpoint, secret: "s3cret", valid: true, isOn: () => true, log: () => {} };
}

// Collects what the middleware answered, the way node:http would.
function fakeRes() {
  const res = { statusCode: 0, headers: {}, body: "", headersSent: false };
  res.ended = new Promise((resolve) => { res.done = resolve; });
  res.writeHead = (status, headers) => {
    res.statusCode = status;
    res.headers = headers || {};
    res.headersSent = true;
    return res;
  };
  res.end = (body) => {
    res.body = body === undefined ? "" : String(body);
    res.done(res);
    return res;
  };
  return res;
}

const fakeReq = (url, { method = "GET", headers = {}, body = null } = {}) => {
  const req = { url, method, headers, socket: { remoteAddress: "203.0.113.9" }, readableEnded: body === null, body: body === null ? undefined : body };
  return req;
};

// The same vector is pinned in the collector, the backend and the other packages.
test("the proxy key is worked out as the collector does", () => {
  assert.equal(keyFor("0123456789abcdef01234567"), "8fc74dbbd4f088449862841cd29fcaee");
});

test("the address comes from the secret and never from the site id", () => {
  assert.equal(prefixFor("s3cret"), prefixFor("s3cret"));
  assert.notEqual(prefixFor("s3cret"), prefixFor("other"));
  assert.match(prefixFor("s3cret"), /^[a-f0-9]{8}$/);
});

test("anything that isn't ours is passed straight on", () => {
  const proxy = createProxy(fakeCore("http://127.0.0.1:1"));
  let passed = 0;
  for (const url of ["/", "/about", "/wp-admin", `/${proxy.prefix}x/js/v1/s.js`]) {
    proxy.middleware(fakeReq(url), fakeRes(), () => { passed += 1; });
  }
  assert.equal(passed, 4);
});

test("only the tracker files we know, and never a way out of them", async () => {
  const proxy = createProxy(fakeCore("http://127.0.0.1:1"));
  for (const path of ["js/", "js/v1/evil.js", "js/v1/../../../etc/passwd", "js/v1/s.php",
    "other/v1/s.js", "api/", "api/../../secret"]) {
    const res = fakeRes();
    await proxy.middleware(fakeReq(`/${proxy.prefix}/${path}`), res, () => assert.fail(`passed on ${path}`));
    await res.ended;
    assert.equal(res.statusCode, 404, path);
  }
});

test("the tracker is fetched once and then served from memory", async () => withUpstream(async ({ seen, port }) => {
  const proxy = createProxy(fakeCore(`http://127.0.0.1:${port}`));
  for (let i = 0; i < 3; i += 1) {
    const res = fakeRes();
    proxy.middleware(fakeReq(`/${proxy.prefix}/js/v1/s.js`), res, () => assert.fail("passed on"));
    await res.ended;
    assert.equal(res.statusCode, 200);
    assert.equal(res.body, TRACKER);
    assert.match(res.headers["content-type"], /javascript/);
  }
  assert.equal(seen.length, 1, "asked the collector once for three requests");
  assert.equal(seen[0].url, "/v1/s.js");
}));

test("a pinned version is held for a year, a major version for an hour", async () => withUpstream(async ({ port }) => {
  const proxy = createProxy(fakeCore(`http://127.0.0.1:${port}`));
  const held = async (path) => {
    const res = fakeRes();
    proxy.middleware(fakeReq(`/${proxy.prefix}/js/${path}`), res, () => {});
    await res.ended;
    return res.headers["cache-control"];
  };
  assert.match(await held("v1.2.3/track.js"), /immutable/);
  assert.match(await held("v1/s.js"), /max-age=3600/);
}));

test("visits reach the collector with the visitor's address and no cookies", async () => withUpstream(async ({ seen, port }) => {
  const proxy = createProxy(fakeCore(`http://127.0.0.1:${port}`), { clientIp: () => "198.51.100.4" });
  const res = fakeRes();
  proxy.middleware(fakeReq(`/${proxy.prefix}/api/e?v=1`, {
    method: "POST",
    headers: { "content-type": "text/plain", cookie: "wordpress_logged_in=secret", "user-agent": "Mozilla/5.0" },
    body: '{"event":"pageview"}',
  }), res, () => assert.fail("passed on"));
  await res.ended;
  assert.equal(res.statusCode, 202);
  assert.equal(res.body, '{"ok":true}');
  const [got] = seen;
  assert.equal(got.url, "/collectanalytics/e?v=1");
  assert.equal(got.body, '{"event":"pageview"}');
  assert.equal(got.headers["x-forwarded-for"], "198.51.100.4");
  assert.equal(got.headers["x-proxy-key"], keyFor("s3cret"), "so the collector believes the address");
  assert.equal(got.headers["user-agent"], "Mozilla/5.0");
  assert.equal(got.headers.cookie, undefined, "the site's own cookies stay on the site");
}));

test("an empty {} left by Express 4's body parser isn't taken for the beacon", async () => withUpstream(async ({ seen, port }) => {
  const proxy = createProxy(fakeCore(`http://127.0.0.1:${port}`));
  // express.json() skipped the text/plain body: req.body = {}, stream unread.
  const req = Object.assign(Readable.from([Buffer.from('{"event":"pageview"}')]), {
    url: `/${proxy.prefix}/api/e`,
    method: "POST",
    headers: { "content-type": "text/plain" },
    socket: { remoteAddress: "127.0.0.1" },
    ip: "198.51.100.8",
    body: {},
  });
  const res = fakeRes();
  proxy.middleware(req, res, () => assert.fail("passed on"));
  await res.ended;
  const [got] = seen;
  assert.equal(got.body, '{"event":"pageview"}');
  assert.equal(got.headers["x-forwarded-for"], "198.51.100.8", "Express's req.ip, not the proxy in front");
}));

test("methods the tracker never uses are not forwarded", async () => withUpstream(async ({ seen, port }) => {
  const proxy = createProxy(fakeCore(`http://127.0.0.1:${port}`));
  const res = fakeRes();
  await proxy.middleware(fakeReq(`/${proxy.prefix}/api/e`, { method: "PUT" }), res, () => assert.fail("passed on"));
  await res.ended;
  assert.equal(res.statusCode, 404);
  assert.equal(seen.length, 0);
}));

test("switched off, it does nothing at all", () => {
  const proxy = createProxy(fakeCore("http://127.0.0.1:1"), { enabled: false });
  let passed = 0;
  proxy.middleware(fakeReq(`/${proxy.prefix}/js/v1/s.js`), fakeRes(), () => { passed += 1; });
  assert.equal(passed, 1);
});
