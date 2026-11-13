// Runs the template's sandboxed code against fake GTM APIs that behave as the
// documented ones do, plus the template's own ___TESTS___ scenarios through a
// small stand-in for GTM's test runner. GTM itself is the last word: import the
// template and run its Tests tab before a release (README.md).
import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";

const file = new URL("../template.tpl", import.meta.url);
const source = readFileSync(file, "utf8");
const sections = {};
const parts = source.split(/^___([A-Z_]+)___$/m);
for (let i = 1; i < parts.length; i += 2) sections[parts[i]] = parts[i + 1].trim();

const code = sections.SANDBOXED_JS_FOR_WEB_TEMPLATE;
const params = JSON.parse(sections.TEMPLATE_PARAMETERS);
const permissions = JSON.parse(sections.WEB_PERMISSIONS);
const info = JSON.parse(sections.INFO);

const METHODS = ["track", "identify", "consent", "reset", "captureException"];
const SITE = "0123456789abcdef01234567";

// A page's window and the GTM APIs the template may require.
function gtm(window = {}, { loadFails = false } = {}) {
  const injected = [];
  const logs = [];
  const get = (path) => path.split(".").reduce((node, key) => node?.[key], window);
  const api = {
    callInWindow(path, ...args) {
      const fn = get(path);
      if (typeof fn !== "function") throw new Error(`${path} is not a function`);
      return fn(...args);
    },
    copyFromWindow: get,
    // Creates the array if missing, and returns a push into it.
    createQueue(path) {
      if (!Array.isArray(get(path))) api.setInWindow(path, [], true);
      const queue = get(path);
      return (value) => queue.push(value);
    },
    getType: (value) => (Array.isArray(value) ? "array" : value === null ? "null" : typeof value),
    injectScript(url, onSuccess, onFailure, cacheToken) {
      injected.push({ url, cacheToken });
      (loadFails ? onFailure : onSuccess)();
    },
    logToConsole: (...args) => logs.push(args.join(" ")),
    makeNumber: (value) => Number(value),
    makeString: (value) => String(value),
    makeTableMap: (rows, key, value) => Object.fromEntries(rows.map((row) => [row[key], row[value]])),
    // Strict about the parent existing, so the template can't rely on GTM
    // creating window.analytics for it.
    setInWindow(path, value, overrideExisting) {
      const keys = path.split(".");
      const last = keys.pop();
      const parent = keys.reduce((node, key) => node?.[key], window);
      if (parent === null || typeof parent !== "object" && typeof parent !== "function") {
        throw new Error(`no parent for ${path}`);
      }
      if (!overrideExisting && parent[last] !== undefined) return false;
      parent[last] = value;
      return true;
    },
  };
  return { window, api, injected, logs };
}

// `mocks` stand in for APIs the way GTM's mock() does.
function requireFor(env, mocks = {}) {
  return (name) => {
    if (!(name in env.api)) throw new Error(`unknown API ${name}`);
    return (...args) => (mocks[name] || env.api[name])(...args);
  };
}

function run(env, data, mocks) {
  const outcome = { success: 0, failure: 0 };
  new Function("require", "data", code)(requireFor(env, mocks), {
    ...data,
    gtmOnSuccess: () => outcome.success++,
    gtmOnFailure: () => outcome.failure++,
  });
  return outcome;
}

// What the tracker does when it loads (track.js): keeps window.analytics,
// replaces the methods with its own, and replays the queue after its first
// pageview.
function loadTracker(window) {
  const calls = [];
  window.analytics = window.analytics || {};
  for (const method of METHODS) window.analytics[method] = (...args) => calls.push([method, args]);
  return {
    calls,
    flush() {
      const queued = window.analytics.q || [];
      window.analytics.q = [];
      for (const [method, args] of queued) window.analytics[method](...(args || []));
    },
  };
}

test("track pages sets only what differs from the defaults, then loads the tracker once", () => {
  const env = gtm();
  const outcome = run(env, { tagType: "page", siteId: SITE, performance: true, outboundLinks: true, fileDownloads: false, consentDetect: true, consentMode: true });
  assert.deepEqual(outcome, { success: 1, failure: 0 });
  assert.deepEqual(env.window.analyticsConfig, { siteid: SITE, performance: "true", "file-downloads": "false" });
  assert.deepEqual(env.injected, [{ url: "https://t.sitegoose.com/v1/track.js", cacheToken: "sitegoose-tracker" }]);
});

test("a tag saved before a setting existed keeps the tracker's default", () => {
  const env = gtm();
  run(env, { tagType: "page", siteId: SITE });
  assert.deepEqual(env.window.analyticsConfig, { siteid: SITE });
});

test("every advanced setting reaches the tracker under its attribute's name", () => {
  const env = gtm();
  run(env, {
    tagType: "page", siteId: SITE, domain: "example.com", release: "2.4.1",
    consentDetect: false, consentMode: false, webVitalsWaitMs: 5000,
  });
  assert.deepEqual(env.window.analyticsConfig, {
    siteid: SITE, domain: "example.com", release: "2.4.1",
    "consent-detect": "false", "consent-mode": "false", "web-vitals-wait-ms": "5000",
  });
});

test("a tracker that can't load fails the tag", () => {
  const env = gtm({}, { loadFails: true });
  assert.deepEqual(run(env, { tagType: "page", siteId: SITE }), { success: 0, failure: 1 });
});

test("an event before the tracker has loaded is sent once it has", () => {
  const env = gtm();
  run(env, { tagType: "page", siteId: SITE });
  const outcome = run(env, {
    tagType: "event", eventName: "purchase", amount: "59.80", currency: "EUR", transactionId: 1042,
    properties: [{ name: "coupon", value: "SUMMER10" }, { name: "items", value: [{ sku: "MUG-B", quantity: 2 }] }],
  });
  assert.deepEqual(outcome, { success: 1, failure: 0 });
  const tracker = loadTracker(env.window);
  assert.deepEqual(tracker.calls, []);
  tracker.flush();
  assert.deepEqual(tracker.calls, [["track", ["purchase", {
    coupon: "SUMMER10", items: [{ sku: "MUG-B", quantity: 2 }], amount: 59.8, currency: "EUR", transaction_id: "1042",
  }]]]);
});

test("an event before the page tag has fired at all still waits for the tracker", () => {
  const env = gtm();
  run(env, { tagType: "event", eventName: "signup", properties: [] });
  const tracker = loadTracker(env.window);
  tracker.flush();
  assert.deepEqual(tracker.calls, [["track", ["signup", {}]]]);
});

test("an event after the tracker has loaded goes straight to it", () => {
  const env = gtm();
  const tracker = loadTracker(env.window);
  run(env, { tagType: "event", eventName: "add_to_cart", amount: 29.9, currency: "EUR" });
  assert.deepEqual(tracker.calls, [["track", ["add_to_cart", { amount: 29.9, currency: "EUR" }]]]);
  assert.deepEqual(env.window.analytics.q, []);
});

test("the page tag firing again never puts placeholders over the tracker", () => {
  const env = gtm();
  run(env, { tagType: "page", siteId: SITE });
  const tracker = loadTracker(env.window);
  run(env, { tagType: "page", siteId: SITE });
  env.window.analytics.track("late");
  assert.deepEqual(tracker.calls, [["track", ["late"]]]);
});

test("the site's own code can call window.analytics before the tracker arrives", () => {
  const env = gtm();
  run(env, { tagType: "page", siteId: SITE });
  for (const method of METHODS) assert.equal(typeof env.window.analytics[method], "function");
  env.window.analytics.consent({ analytics: true });
  env.window.analytics.track("add_to_cart", { item: "Blue shirt" });
  const tracker = loadTracker(env.window);
  tracker.flush();
  assert.deepEqual(tracker.calls, [
    ["consent", [{ analytics: true }, undefined]],
    ["track", ["add_to_cart", { item: "Blue shirt" }]],
  ]);
});

test("an existing window.analytics object is kept", () => {
  const env = gtm({ analytics: { q: [["track", ["early", {}]]], hasConsent: "kept" } });
  run(env, { tagType: "event", eventName: "later" });
  assert.equal(env.window.analytics.hasConsent, "kept");
  assert.deepEqual(env.window.analytics.q.map(([, args]) => args[0]), ["early", "later"]);
});

test("a window.analytics another tool made (Segment's is an array) is never replaced", () => {
  const segment = [];
  const env = gtm({ analytics: segment });
  run(env, { tagType: "page", siteId: SITE });
  assert.equal(env.window.analytics, segment);
});

test("an amount that isn't a number is left out and said in the console", () => {
  const env = gtm();
  run(env, { tagType: "event", eventName: "signup", amount: "free" });
  assert.deepEqual(env.window.analytics.q, [["track", ["signup", {}]]]);
  assert.match(env.logs.join("\n"), /"free" is not a number/);
});

test("an amount of 0 is kept", () => {
  const env = gtm();
  run(env, { tagType: "event", eventName: "purchase", amount: 0, currency: "EUR" });
  assert.deepEqual(env.window.analytics.q[0][1][1], { amount: 0, currency: "EUR" });
});

test("an event with no name fails the tag and sends nothing", () => {
  const env = gtm();
  assert.deepEqual(run(env, { tagType: "event", eventName: "" }), { success: 0, failure: 1 });
  assert.equal(env.window.analytics, undefined);
});

test("identify sends a user ID with properties, or properties alone", () => {
  const env = gtm();
  run(env, { tagType: "identify", userId: 4821, traits: [{ name: "plan", value: "pro" }] });
  run(env, { tagType: "identify", userId: "", traits: [{ name: "plan", value: "free" }] });
  run(env, { tagType: "identify", userId: "user_9", traits: [] });
  const tracker = loadTracker(env.window);
  tracker.flush();
  assert.deepEqual(tracker.calls, [
    ["identify", ["4821", { plan: "pro" }]],
    ["identify", [{ plan: "free" }, undefined]],
    ["identify", ["user_9", undefined]],
  ]);
});

test("identify with neither a user ID nor a property fails the tag", () => {
  const env = gtm();
  assert.deepEqual(run(env, { tagType: "identify", userId: "", traits: [] }), { success: 0, failure: 1 });
});

test("forget the signed-in user calls reset", () => {
  const env = gtm();
  assert.deepEqual(run(env, { tagType: "reset" }), { success: 1, failure: 0 });
  const tracker = loadTracker(env.window);
  tracker.flush();
  assert.deepEqual(tracker.calls, [["reset", [undefined, undefined]]]);
});

// ---- the file itself ----

test("the code keeps to what GTM's sandbox runs", () => {
  const body = code.replace(/^\s*\/\/.*$/gm, "");
  for (const [what, pattern] of [
    ["arrow functions", /=>/], ["this", /\bthis\b/], ["new", /\bnew\s/], ["arguments", /\barguments\b/],
    ["classes", /\bclass\b/], ["spread", /\.\.\./], ["template literals", /`/], ["for loops", /\bfor\s*\(/],
  ]) assert.doesNotMatch(body, pattern, `the sandbox has no ${what}`);
});

test("every field the code reads is in the form, and every field in the form is read", () => {
  const names = [];
  const walk = (list) => list.forEach((param) => { names.push(param.name); if (param.subParams) walk(param.subParams); });
  walk(params);
  const fields = names.filter((name) => !["advanced", "revenue"].includes(name));
  const read = [...new Set([...code.matchAll(/\bdata\.(\w+)/g)].map((m) => m[1]))]
    .filter((name) => !["gtmOnSuccess", "gtmOnFailure"].includes(name));
  assert.deepEqual(read.sort(), fields.sort());
});

test("the permissions are exactly what the code uses", () => {
  const byId = Object.fromEntries(permissions.map((p) => [p.instance.key.publicId, p.instance.param]));
  assert.deepEqual(Object.keys(byId).sort(), ["access_globals", "inject_script", "logging"]);
  const globals = byId.access_globals[0].value.listItem.map((item) => {
    const values = item.mapValue.map((v) => v.string ?? v.boolean);
    return `${values[0]} ${values[1] ? "r" : "-"}${values[2] ? "w" : "-"}${values[3] ? "x" : "-"}`;
  });
  assert.deepEqual(globals, [
    "analyticsConfig rw-", "analytics rw-", "analytics.q rw-",
    ...METHODS.map((m) => `analytics.${m} rwx`),
  ]);
  const urls = byId.inject_script[0].value.listItem.map((item) => item.string);
  assert.deepEqual(urls, ["https://t.sitegoose.com/v1/"]);
  assert.match(code, /const TRACKER_URL = 'https:\/\/t\.sitegoose\.com\/v1\/track\.js';/);
  assert.equal(byId.logging[0].value.string, "debug");
});

test("the gallery's info block is complete", () => {
  assert.equal(info.type, "TAG");
  assert.deepEqual(info.containerContexts, ["WEB"]);
  assert.match(info.brand.thumbnail, /^data:image\/png;base64,[A-Za-z0-9+/=]+$/);
  assert.ok(info.description.length <= 200);
  const metadata = readFileSync(new URL("../metadata.yaml", import.meta.url), "utf8");
  assert.match(metadata, /^homepage: /m);
  assert.match(metadata, /^documentation: /m);
  assert.match(metadata, /- sha: /);
});

test("the dashboard offers this exact file for download", () => {
  const copy = new URL("../../../frontend/public/downloads/sitegoose-gtm-template.tpl", import.meta.url);
  assert.ok(existsSync(copy), "copy template.tpl to frontend/public/downloads/sitegoose-gtm-template.tpl");
  assert.equal(readFileSync(copy, "utf8"), source, "the dashboard's copy differs: copy template.tpl over it");
});

// ---- the template's own ___TESTS___, through a stand-in for GTM's runner ----

function gtmScenarios() {
  // The YAML here is always the same shape: "- name:", then a "code: |-"
  // block indented four spaces, and a "setup: |-" block indented two.
  const text = sections.TESTS;
  const scenarios = [...text.matchAll(/^- name: (.+)\n {2}code: \|-\n((?: {4}.*\n?)+)/gm)]
    .map((m) => ({ name: m[1], code: m[2].replace(/^ {4}/gm, "") }));
  const setup = (text.match(/^setup: \|-\n((?: {2}.*\n?)+)/m)?.[1] || "").replace(/^ {2}/gm, "");
  return { scenarios, setup };
}

const { scenarios, setup } = gtmScenarios();

test("the template has GTM test scenarios", () => {
  assert.ok(scenarios.length >= 8);
});

for (const scenario of scenarios) {
  test(`GTM scenario: ${scenario.name}`, () => {
    const env = gtm();
    const mocks = {};
    const calls = { gtmOnSuccess: 0, gtmOnFailure: 0 };
    const runner = {
      mock: (name, fn) => { mocks[name] = fn; },
      runCode: (data) => {
        const outcome = run(env, data, mocks);
        calls.gtmOnSuccess += outcome.success;
        calls.gtmOnFailure += outcome.failure;
      },
      assertApi: (name) => ({
        wasCalled: () => assert.ok(calls[name] > 0, `${name} was not called`),
        wasNotCalled: () => assert.equal(calls[name], 0, `${name} was called`),
      }),
      assertThat: (actual) => ({ isEqualTo: (expected) => assert.deepEqual(actual, expected) }),
    };
    new Function("require", ...Object.keys(runner), `${setup}\n${scenario.code}`)(requireFor(env, mocks), ...Object.values(runner));
  });
}
