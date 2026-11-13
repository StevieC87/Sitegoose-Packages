// The type a collector answer is served with from the site's own domain,
// against the cases every client shares: sdk/protocols/proxy-answer-cases.json.
// hono.js serves its answers through the same answerHeaders.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { answerHeaders, answerType } = require("../lib/proxy.js");

const { cases } = JSON.parse(fs.readFileSync(path.join(__dirname, "../../protocols/proxy-answer-cases.json"), "utf8"));

for (const c of cases) {
  test(`${JSON.stringify(c.type)} is served as ${c.served}`, () => {
    assert.equal(answerType(c.type), c.served);
  });
}

test("an answer always carries nosniff, and keeps only its cache and retry headers", () => {
  const upstream = { "content-type": "text/html", "cache-control": "no-store", "set-cookie": "a=b", refresh: "0;url=x" };
  assert.deepEqual(answerHeaders((name) => upstream[name] ?? null), {
    "content-type": "text/plain; charset=utf-8", "x-content-type-options": "nosniff", "cache-control": "no-store",
  });
});
