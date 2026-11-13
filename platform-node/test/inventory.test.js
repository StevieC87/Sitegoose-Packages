// The inventory module: which packages a lock file yields, and `direct` —
// the mark that separates the few dozen packages the app asks for from the
// hundreds underneath them (sdk/protocols/inventory.md).
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { lockPackages, directNames } = require("../lib/inventory.js");

const LOCK_V3 = {
  lockfileVersion: 3,
  packages: {
    "": { name: "shop", dependencies: { express: "^4.18.2" } },
    "node_modules/express": { version: "4.18.2" },
    "node_modules/body-parser": { version: "1.20.1" },
    "node_modules/jest": { version: "29.7.0", dev: true },
    "node_modules/express/node_modules/qs": { version: "6.11.0" },
    "node_modules/ui": { link: true, resolved: "packages/ui" },
    "packages/ui": { version: "1.0.0" },
  },
};

test("takes the production packages, with the name from the last node_modules", () => {
  const names = lockPackages(LOCK_V3).map((p) => p.name).sort();
  assert.deepEqual(names, ["body-parser", "express", "qs"]);
});

test("every package is npm, with the version as the lock file gives it", () => {
  const express = lockPackages(LOCK_V3).find((p) => p.name === "express");
  assert.deepEqual(express, { ecosystem: "npm", name: "express", version: "4.18.2" });
});

test("marks only what package.json asks for by name", () => {
  const direct = directNames({ dependencies: { express: "^4.18.2" }, devDependencies: { jest: "^29" } });
  const rows = lockPackages(LOCK_V3, direct);
  assert.equal(rows.find((p) => p.name === "express").direct, true);
  // A dependency of a dependency is not the owner's choice, so it is unmarked.
  assert.equal(rows.find((p) => p.name === "qs").direct, undefined);
});

test("marks only the copy package.json gets, not one nested under another package", () => {
  // `npm install cookie@2` leaves express holding its own 0.7.2. That copy
  // can't be moved from here, so it mustn't read as the owner's to update.
  const rows = lockPackages({
    lockfileVersion: 3,
    packages: {
      "node_modules/cookie": { version: "2.0.1" },
      "node_modules/express": { version: "5.3.0" },
      "node_modules/express/node_modules/cookie": { version: "0.7.2" },
    },
  }, directNames({ dependencies: { cookie: "^2.0.1", express: "^5" } }));
  assert.equal(rows.find((p) => p.version === "2.0.1").direct, true);
  assert.equal(rows.find((p) => p.version === "0.7.2").direct, undefined);
});

test("a nested copy of the same version doesn't unmark the chosen one", () => {
  const rows = lockPackages({
    lockfileVersion: 3,
    packages: {
      "node_modules/cookie": { version: "2.0.1" },
      "node_modules/express/node_modules/cookie": { version: "2.0.1" },
    },
  }, directNames({ dependencies: { cookie: "^2.0.1" } }));
  assert.deepEqual(rows, [{ ecosystem: "npm", name: "cookie", version: "2.0.1", direct: true }]);
});

test("marks only the top of a v1 lock file's tree", () => {
  const rows = lockPackages({
    lockfileVersion: 1,
    dependencies: {
      cookie: { version: "2.0.1" },
      express: { version: "4.18.2", dependencies: { cookie: { version: "0.7.2" } } },
    },
  }, directNames({ dependencies: { cookie: "^2.0.1" } }));
  assert.equal(rows.find((p) => p.version === "2.0.1").direct, true);
  assert.equal(rows.find((p) => p.version === "0.7.2").direct, undefined);
});

test("counts optional dependencies as chosen, and dev ones not at all", () => {
  const direct = directNames({
    dependencies: { express: "1" },
    optionalDependencies: { fsevents: "1" },
    devDependencies: { jest: "1" },
  });
  assert.deepEqual([...direct].sort(), ["express", "fsevents"]);
});

test("without a package.json nothing is marked, and the list still goes up", () => {
  const rows = lockPackages(LOCK_V3);
  assert.equal(rows.length, 3);
  assert.ok(rows.every((p) => p.direct === undefined));
});

test("reads a v1 lock file's tree, dev packages left out", () => {
  const rows = lockPackages({
    lockfileVersion: 1,
    dependencies: {
      express: { version: "4.18.2", dependencies: { qs: { version: "6.11.0" } } },
      jest: { version: "29.7.0", dev: true },
    },
  }, directNames({ dependencies: { express: "^4" } }));
  assert.deepEqual(rows.map((p) => p.name).sort(), ["express", "qs"]);
  assert.equal(rows.find((p) => p.name === "express").direct, true);
});

test("leaves out versions that aren't releases", () => {
  const rows = lockPackages({
    lockfileVersion: 3,
    packages: {
      "node_modules/local": { version: "file:../local" },
      "node_modules/fromgit": { version: "git+https://example.com/a.git#abc" },
      "node_modules/real": { version: "2.0.0" },
    },
  });
  assert.deepEqual(rows.map((p) => p.name), ["real"]);
});

// Inventory and posture are stored one per site and host, so two services on
// one machine overwrite each other's unless serverName names them.
test("serverName names the package list and the set-up report, unless the module names its own", async () => {
  const inventory = require("../lib/inventory.js");
  const posture = require("../lib/posture.js");
  const seen = {};
  const real = { inventory: inventory.createInventory, posture: posture.createPosture };
  inventory.createInventory = (core, opts) => ((seen.inventory = opts.host), { close() {} });
  posture.createPosture = (core, opts) => ((seen.posture = opts.host), { close() {} });
  try {
    const { createPlatform } = require("../index.js");
    const off = { firewall: false, errors: false, analytics: false, performance: false, crawlers: false, forms: false,
      headers: false, audit: false, flags: false, maintenance: false, resources: false, proxy: false };
    const platform = createPlatform({ siteId: "a1b2c3d4e5f6a1b2c3d4e5f6", secret: "s", endpoint: "http://127.0.0.1:9",
      serverName: "worker", ...off, posture: { host: "own" } });
    await platform.close();
    assert.deepEqual(seen, { inventory: "worker", posture: "own" });
  } finally {
    inventory.createInventory = real.inventory;
    posture.createPosture = real.posture;
  }
});

test("manual refresh rereads the lockfile, acknowledges once, and retries failed sends", async () => {
  const fs = require("node:fs");
  const os = require("node:os");
  const path = require("node:path");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "inventory-refresh-"));
  let listener;
  let succeeds = false;
  const sent = [];
  const core = { valid: false, siteId: "site", isOn: () => true, log() {},
    onConfig(fn) { listener = fn; return () => { listener = null; }; },
    async send(module, url, options) { sent.push(options.body); return { ok: succeeds, json: async () => ({ enabled: true }) }; } };
  const inventory = require("../lib/inventory.js").createInventory(core, { dir });
  try {
    const request = { inventory_refresh: { id: "a".repeat(24), at: new Date().toISOString() } };
    fs.writeFileSync(path.join(dir, "package-lock.json"), JSON.stringify(LOCK_V3));
    await listener(request);
    succeeds = true;
    const updated = structuredClone(LOCK_V3);
    updated.packages["node_modules/express"].version = "5.0.0";
    fs.writeFileSync(path.join(dir, "package-lock.json"), JSON.stringify(updated));
    await listener(request);
    await listener(request);
    assert.equal(sent.length, 2);
    assert.equal(sent[1].packages.find(p => p.name === "express").version, "5.0.0");
    assert.equal(sent[1].refresh_id, request.inventory_refresh.id);
    await listener({ inventory_refresh: { id: "b".repeat(24), at: new Date(Date.now() - 180000).toISOString() } });
    assert.equal(sent.length, 2);
  } finally { inventory.close(); fs.rmSync(dir, { recursive: true, force: true }); }
  assert.equal(listener, null);
});

// pnpm, yarn and bun projects. These are small; the full fixtures, and the
// check that this copy and sdk/report-packages' agree on every format, are in
// sdk/report-packages/test.
const { parseLock } = require("../lib/inventory.js");

test("reads pnpm-lock.yaml 9.0: production packages walked from the project, peers taken off the version", () => {
  const text = [
    "lockfileVersion: '9.0'", "", "importers:", "", "  .:", "    dependencies:",
    "      next:", "        specifier: 15.1.0", "        version: 15.1.0(react@19.0.0)",
    "      react:", "        specifier: ^19.0.0", "        version: 19.0.0",
    "    devDependencies:", "      typescript:", "        specifier: ^5", "        version: 5.7.2",
    "", "snapshots:", "", "  next@15.1.0(react@19.0.0):", "    dependencies:", "      '@next/env': 15.1.0", "      react: 19.0.0",
    "", "  '@next/env@15.1.0': {}", "", "  react@19.0.0: {}", "", "  typescript@5.7.2: {}",
  ].join("\n");
  const rows = parseLock("pnpm-lock.yaml", text, { dependencies: { next: "15.1.0", react: "^19.0.0" } });
  assert.deepEqual(rows.map((p) => `${p.name}@${p.version}${p.direct ? "*" : ""}`).sort(), ["@next/env@15.1.0", "next@15.1.0*", "react@19.0.0*"]);
});

test("reads pnpm-lock.yaml 5.x and 6.0 by their dev flags", () => {
  const v5 = "lockfileVersion: 5.4\ndependencies:\n  react: 18.2.0\npackages:\n  /react/18.2.0:\n    dev: false\n  /jest/29.7.0:\n    dev: true\n  /loose-envify/1.4.0:\n    dependencies:\n      js-tokens: 4.0.0\n";
  const v6 = "lockfileVersion: '6.0'\ndependencies:\n  react:\n    specifier: ^18\n    version: 18.2.0\npackages:\n  /react@18.2.0:\n    dev: false\n  /jest@29.7.0:\n    dev: true\n  /loose-envify@1.4.0:\n    dev: false\n";
  for (const text of [v5, v6]) {
    const rows = parseLock("pnpm-lock.yaml", text, { dependencies: { react: "^18" } });
    assert.deepEqual(rows.map((p) => `${p.name}@${p.version}${p.direct ? "*" : ""}`).sort(), ["loose-envify@1.4.0", "react@18.2.0*"]);
  }
});

test("reads yarn.lock, 1 and 2+, from package.json's production dependencies", () => {
  const classic = 'react@^19.0.0:\n  version "19.0.0"\n  dependencies:\n    scheduler "^0.25.0"\n\nscheduler@^0.25.0:\n  version "0.25.0"\n\njest@^29:\n  version "29.7.0"\n';
  const berry = '__metadata:\n  version: 8\n\n"react@npm:^19.0.0":\n  version: 19.0.0\n  resolution: "react@npm:19.0.0"\n  dependencies:\n    scheduler: "npm:^0.25.0"\n  linkType: hard\n\n"scheduler@npm:^0.25.0":\n  version: 0.25.0\n  resolution: "scheduler@npm:0.25.0"\n  linkType: hard\n\n"jest@npm:^29":\n  version: 29.7.0\n  resolution: "jest@npm:29.7.0"\n  linkType: hard\n';
  const manifest = { dependencies: { react: "^19.0.0" }, devDependencies: { jest: "^29" } };
  for (const text of [classic, berry]) {
    const rows = parseLock("yarn.lock", text, manifest);
    assert.deepEqual(rows.map((p) => `${p.name}@${p.version}${p.direct ? "*" : ""}`).sort(), ["react@19.0.0*", "scheduler@0.25.0"]);
  }
});

test("reads bun.lock, trailing commas and all", () => {
  const text = '{\n  "lockfileVersion": 1,\n  "workspaces": {\n    "": {\n      "dependencies": {\n        "react": "^19.0.0",\n      },\n      "devDependencies": {\n        "jest": "^29",\n      },\n    },\n  },\n  "packages": {\n    "jest": ["jest@29.7.0", "", {}, "sha512-a"],\n    "react": ["react@19.0.0", "", { "dependencies": { "scheduler": "^0.25.0" } }, "sha512-b"],\n    "scheduler": ["scheduler@0.25.0", "", {}, "sha512-c"],\n  }\n}\n';
  const rows = parseLock("bun.lock", text, { dependencies: { react: "^19.0.0" } });
  assert.deepEqual(rows.map((p) => `${p.name}@${p.version}${p.direct ? "*" : ""}`).sort(), ["react@19.0.0*", "scheduler@0.25.0"]);
});

test("the inventory reads whichever lock file the project has, and says when it can only find bun.lockb", async () => {
  const fs = require("node:fs");
  const os = require("node:os");
  const path = require("node:path");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "inventory-managers-"));
  let listener;
  const sent = [];
  const logged = [];
  const core = { valid: false, siteId: "site", isOn: () => true, log: (...args) => logged.push(args.join(" ")),
    onConfig(fn) { listener = fn; return () => { listener = null; }; },
    async send(module, url, options) { sent.push(options.body); return { ok: false }; } };
  const inventory = require("../lib/inventory.js").createInventory(core, { dir });
  const refresh = (id) => listener({ inventory_refresh: { id: id.repeat(24), at: new Date().toISOString() } });
  try {
    fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ dependencies: { react: "^19.0.0" } }));
    fs.writeFileSync(path.join(dir, "bun.lockb"), "\u0000binary");
    await refresh("a");
    assert.deepEqual(sent[0].packages, []);
    assert.ok(logged.some((line) => line.includes("bun install --save-text-lockfile")));
    fs.writeFileSync(path.join(dir, "yarn.lock"), 'react@^19.0.0:\n  version "19.0.0"\n');
    await refresh("b");
    assert.deepEqual(sent[1].packages, [{ ecosystem: "npm", name: "react", version: "19.0.0", direct: true }]);
    // A broken file is logged and the next one tried, as a broken
    // package-lock.json always was.
    fs.writeFileSync(path.join(dir, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\n\tbroken\n");
    await refresh("c");
    assert.ok(logged.some((line) => line.includes("could not read pnpm-lock.yaml:")));
    assert.equal(sent[2].packages[0].name, "react");
  } finally { inventory.close(); fs.rmSync(dir, { recursive: true, force: true }); }
});

test("the inventory reads a yarn monorepo's workspaces, through byte order marks, and prefers npm-shrinkwrap.json", async () => {
  const fs = require("node:fs");
  const os = require("node:os");
  const path = require("node:path");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "inventory-workspaces-"));
  let listener;
  const sent = [];
  const core = { valid: false, siteId: "site", isOn: () => true, log() {},
    onConfig(fn) { listener = fn; return () => { listener = null; }; },
    async send(module, url, options) { sent.push(options.body); return { ok: false }; } };
  const inventory = require("../lib/inventory.js").createInventory(core, { dir });
  const refresh = (id) => listener({ inventory_refresh: { id: id.repeat(24), at: new Date().toISOString() } });
  const write = (file, value) => {
    fs.mkdirSync(path.dirname(path.join(dir, file)), { recursive: true });
    fs.writeFileSync(path.join(dir, file), `﻿${typeof value === "string" ? value : JSON.stringify(value)}`);
  };
  try {
    write("package.json", { private: true, workspaces: ["apps/*"], devDependencies: { turbo: "^2" } });
    write("apps/web/package.json", { dependencies: { react: "^19.0.0" } });
    write("yarn.lock", 'react@^19.0.0:\n  version "19.0.0"\nturbo@^2:\n  version "2.3.0"\n');
    await refresh("a");
    // react is the web app's, not the project root's, so it isn't marked.
    assert.deepEqual(sent[0].packages, [{ ecosystem: "npm", name: "react", version: "19.0.0" }]);
    write("package-lock.json", LOCK_V3);
    write("npm-shrinkwrap.json", { lockfileVersion: 3, packages: { "node_modules/express": { version: "4.0.0" } } });
    await refresh("b");
    assert.deepEqual(sent[1].packages, [{ ecosystem: "npm", name: "express", version: "4.0.0" }]);
  } finally { inventory.close(); fs.rmSync(dir, { recursive: true, force: true }); }
});
