// The security headers taken from the platform config, against the cases every
// client shares: sdk/protocols/header-cases.json. Only the nine the dashboard
// can produce get through, so all the packages add the same ones.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { safeHeader } = require("../lib/core.js");

const { cases } = JSON.parse(fs.readFileSync(path.join(__dirname, "../../protocols/header-cases.json"), "utf8"));

for (const c of cases) {
  const value = c.value.repeat(c.repeat || 1);
  test(`${JSON.stringify(c.name)}: ${JSON.stringify(c.value.slice(0, 40))}${c.repeat ? ` x${c.repeat}` : ""} -> ${c.ok}`, () => {
    assert.equal(safeHeader([c.name, value]), c.ok);
  });
}

test("anything but a [name, value] pair of strings is dropped", () => {
  for (const pair of [null, "X-Frame-Options", ["X-Frame-Options"], ["X-Frame-Options", 1], ["X-Frame-Options", "DENY", "x"]]) {
    assert.equal(safeHeader(pair), false);
  }
});
