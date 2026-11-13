// The request-rule matcher (virtual patching), against the cases every client
// shares: sdk/protocols/request-rules-cases.json. The same file is run by the
// PHP and Python packages, so the four matchers decide alike — this one covers
// the Next.js edge middleware too, which uses the same module.
//
//   npm test            (node --test test/*.test.js)
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { compileRequestRules, matchRequest, safePattern } = require("../lib/requestRules.js");

const cases = JSON.parse(fs.readFileSync(path.join(__dirname, "../../protocols/request-rules-cases.json"), "utf8"));

test("every shared case decides the same way here", () => {
  const rules = compileRequestRules({ rules: cases.rules });
  for (const request of cases.requests) {
    const matched = matchRequest(rules, { method: request.method, path: request.target, userAgent: request.ua });
    assert.equal(matched?.id ?? null, request.expect, `${request.why}: ${request.method} ${request.target}`);
  }
});

test("a rule with nothing to match is dropped, not applied to everything", () => {
  assert.deepEqual(compileRequestRules({ rules: [{ id: "empty", action: "block" }] }), []);
  assert.equal(matchRequest(compileRequestRules({ rules: [{ id: "empty", action: "block" }] }), { path: "/" }), null);
});

test("a pattern that doesn't compile is dropped, and the rest of the rules still work", () => {
  const rules = compileRequestRules({ rules: [
    { id: "bad", action: "block", path: { regex: "([" } },
    { id: "good", action: "block", path: { exact: ["/shell.php"] } },
  ] });
  assert.equal(rules.length, 1);
  assert.equal(matchRequest(rules, { path: "/shell.php" })?.id, "good");
});

test("no rules, no match, whatever the request", () => {
  assert.equal(matchRequest([], { path: "/../../etc/passwd" }), null);
  assert.equal(matchRequest(compileRequestRules(null), { path: "/../../etc/passwd" }), null);
  assert.equal(matchRequest(compileRequestRules({ rules: "nonsense" }), { path: "/x" }), null);
});

test("the regex guard refuses and allows the shared lists", () => {
  // The same lists the backend and collector check before a rule is stored or handed out.
  for (const pattern of cases.patterns.refused) assert.equal(safePattern(pattern), false, pattern);
  for (const pattern of cases.patterns.allowed) assert.equal(safePattern(pattern), true, pattern);
});

test("at most 200 rules are compiled", () => {
  const many = Array.from({ length: 250 }, (_, i) => ({ id: `r${i}`, action: "monitor", path: { exact: [`/${i}`] } }));
  assert.equal(compileRequestRules({ rules: many }).length, 200);
});

test("a pattern that can blow up is refused, so a request can't hang the server", () => {
  // (a+)+ takes exponential time on input that nearly matches, and no engine we
  // ship to can be timed out: the client must not compile it at all.
  assert.equal(safePattern("(a+)+b"), false);
  assert.equal(safePattern("(a*)*"), false);
  assert.equal(safePattern("(ab|cd+)+"), false);
  assert.equal(safePattern("(a)\\1"), false, "a backreference isn't in every engine we ship to");
  assert.equal(safePattern("(?<=x)y"), false, "nor is lookbehind");
  // The starter rules' own patterns stay allowed.
  assert.equal(safePattern("/(wp-content/uploads|uploads)/[^?]*\\.(php[0-9]?|phtml)$"), true);
  assert.equal(safePattern("(includes|inc|lib)?/?[^/]*\\.php$"), true);
  const rules = compileRequestRules({ rules: [
    { id: "slow", action: "block", path: { regex: "(a+)+b" } },
    { id: "fine", action: "block", path: { exact: ["/x"] } },
  ] });
  assert.deepEqual(rules.map((rule) => rule.id), ["fine"]);
  const started = Date.now();
  assert.equal(matchRequest(rules, { method: "GET", path: "/" + "a".repeat(100000) + "!", userAgent: "" }), null);
  assert.ok(Date.now() - started < 1000, "matching must stay quick on a long path");
});

test("the cap is the first 2,000 characters of a part", () => {
  const rules = compileRequestRules({ rules: [{ id: "deep", action: "block", path: { contains: ["/needle"] } }] });
  assert.equal(matchRequest(rules, { path: "/a".repeat(100) + "/needle" })?.id, "deep");
  assert.equal(matchRequest(rules, { path: "/" + "a".repeat(2100) + "/needle" }), null);
});

test("a stray % elsewhere doesn't stop the rest being decoded", () => {
  const rules = compileRequestRules({ rules: [
    { id: "up", action: "block", path: { contains: ["../"] } },
    { id: "q", action: "block", query: { contains: ["../"] } },
  ] });
  assert.equal(matchRequest(rules, { path: "/%2e%2e/%2e%2e/etc/passwd%" })?.id, "up");
  assert.equal(matchRequest(rules, { path: "/x?a=%&f=%2e%2e/%2e%2e/etc" })?.id, "q");
  // A run that isn't valid UTF-8 still has its ASCII escapes decoded.
  assert.equal(matchRequest(rules, { path: "/%ff%2e%2e/etc" })?.id, "up");
});
