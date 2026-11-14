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
const { originForm } = require("../lib/firewall.js");

const cases = JSON.parse(fs.readFileSync(path.join(__dirname, "../../protocols/request-rules-cases.json"), "utf8"));

test("every shared case decides the same way here", () => {
  const rules = compileRequestRules({ rules: cases.rules });
  for (const request of cases.requests) {
    const matched = matchRequest(rules, { method: request.method, path: request.target, userAgent: request.ua });
    assert.equal(matched?.id ?? null, request.expect, `${request.why}: ${request.method} ${request.target}`);
  }
});

test("every shared request target is read in origin form, as the server's URL parser reads it", () => {
  for (const { target, origin } of cases.targets) assert.equal(originForm(target), origin, target);
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

test("the plain matchers read the whole part, however long", () => {
  const rules = compileRequestRules({ rules: [
    { id: "deep", action: "block", path: { contains: ["/needle"] } },
    { id: "jndi", action: "block", ua: { contains: ["${jndi:"] } },
    { id: "end", action: "block", query: { suffix: ["&x=1"] } },
  ] });
  assert.equal(matchRequest(rules, { path: "/a".repeat(100) + "/needle" })?.id, "deep");
  assert.equal(matchRequest(rules, { path: "/" + "a".repeat(2100) + "/needle" })?.id, "deep");
  assert.equal(matchRequest(rules, { path: "/", userAgent: "x".repeat(5000) + "${jndi:ldap://x/a}" })?.id, "jndi");
  assert.equal(matchRequest(rules, { path: `/?pad=${"x".repeat(5000)}&x=1` })?.id, "end");
});

test("a regex is searched in windows of 2,000, and its anchors only at the part's own edges", () => {
  const rule = (id, regex) => ({ id, action: "block", path: { regex } });
  const pad = "/" + "a".repeat(4500);
  // A match straddling 2,000 is in the window that starts at 1,000.
  const across = "/" + "a".repeat(1990) + "/evil.php";
  assert.equal(matchRequest(compileRequestRules({ rules: [rule("r", "/evil\\.php")] }), { path: across })?.id, "r");
  assert.equal(matchRequest(compileRequestRules({ rules: [rule("r", "/evil\\.php$")] }), { path: `${pad}/evil.php` })?.id, "r");
  // "$" isn't the end of a window in the middle: only of the part.
  const middle = "/" + "a".repeat(2990) + "/evil.php" + "b".repeat(2000);
  assert.equal(matchRequest(compileRequestRules({ rules: [rule("r", "/evil\\.php$")] }), { path: middle }), null);
  assert.equal(matchRequest(compileRequestRules({ rules: [rule("r", "/evil\\.php")] }), { path: middle })?.id, "r");
  // "\$" is a dollar sign, searched everywhere.
  assert.equal(matchRequest(compileRequestRules({ rules: [rule("r", "/\\$x")] }), { path: `${pad}/$x${pad}` })?.id, "r");
  // "^" only in the window that starts the part.
  assert.equal(matchRequest(compileRequestRules({ rules: [rule("r", "^/admin")] }), { path: `/admin${pad}` })?.id, "r");
  assert.equal(matchRequest(compileRequestRules({ rules: [rule("r", "^/admin")] }), { path: `${pad.slice(0, 1000)}/admin${pad}` }), null);
  // Both: only a part that fits one window.
  assert.equal(matchRequest(compileRequestRules({ rules: [rule("r", "^/a+$")] }), { path: "/" + "a".repeat(1500) })?.id, "r");
  assert.equal(matchRequest(compileRequestRules({ rules: [rule("r", "^/a+$")] }), { path: pad }), null);
});

test("a # ends the path and the query", () => {
  const rules = compileRequestRules({ rules: [
    { id: "login", action: "block", path: { exact: ["/login"] } },
    { id: "q", action: "block", query: { suffix: ["=1"] } },
  ] });
  assert.equal(matchRequest(rules, { method: "POST", path: "/login#1" })?.id, "login");
  assert.equal(matchRequest(rules, { path: "/login#x?y=2" })?.id, "login");
  assert.equal(matchRequest(rules, { path: "/x?a=1#b" })?.id, "q");
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
