// The check-in on the switches request (X-Platform-App): what names this
// service on Health → All systems.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { createCore } = require("../lib/core.js");

test("the switches request says which service is asking, and that it runs", async (t) => {
  const seen = [];
  t.mock.method(globalThis, "fetch", async (url, init) => {
    seen.push(init.headers);
    return new Response(null, { status: 304 });
  });
  const core = createCore({ siteId: "a".repeat(24), secret: "s", endpoint: "http://collector", serverName: "api wörker" });
  await core.start(["errors"]);
  core.stop();
  const app = new URLSearchParams(seen[0]["x-platform-app"]);
  assert.equal(app.get("server"), "api wörker");
  assert.equal(app.get("kind"), "process");
  assert.equal(app.get("pid"), String(process.pid));
  assert.match(app.get("runtime"), /^Node \d+/);
  assert.ok(Number(app.get("rss_mb")) > 0);
  // Any name is plain ASCII in the header.
  assert.match(seen[0]["x-platform-app"], /^[\x20-\x7e]+$/);
});
