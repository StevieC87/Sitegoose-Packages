// This package parses lock files itself so it can be installed on its own,
// which means there are two copies of those rules in the tree. This test is
// what stops them drifting: both are run over the same lock files and must
// agree exactly, package for package and flag for flag.
//
// If this fails, one of the two was changed and the other wasn't:
//   sdk/report-packages/lib/lockfile.js
//   sdk/platform-node/lib/inventory.js
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const here = require("../lib/lockfile.js");

// The Node package sits beside this one in the tree, but is not a dependency:
// published on its own, it isn't there, and this check is then skipped rather
// than failed.
const SIBLING = path.join(__dirname, "../../platform-node/lib/inventory.js");
const sibling = fs.existsSync(SIBLING) ? require(SIBLING) : null;

const LOCKS = {
  "v3 with workspaces, dev packages and a nested copy": {
    lockfileVersion: 3,
    packages: {
      "": { name: "app", dependencies: { express: "^4.18.2", react: "^19.0.0" }, devDependencies: { vite: "^6" } },
      "node_modules/express": { version: "4.18.2" },
      "node_modules/react": { version: "19.0.0" },
      "node_modules/vite": { version: "6.0.1", dev: true },
      "node_modules/express/node_modules/qs": { version: "6.11.0" },
      "node_modules/aliased": { name: "real-name", version: "1.2.3" },
      "node_modules/ui": { link: true, resolved: "packages/ui" },
      "packages/ui": { version: "1.0.0" },
    },
  },
  "v1 tree": {
    lockfileVersion: 1,
    dependencies: {
      express: { version: "4.18.2", dependencies: { qs: { version: "6.11.0" } } },
      jest: { version: "29.7.0", dev: true },
    },
  },
  "versions that aren't releases": {
    lockfileVersion: 3,
    packages: {
      "node_modules/local": { version: "file:../local" },
      "node_modules/fromgit": { version: "git+https://example.com/a.git#abc" },
      "node_modules/tarball": { version: "https://example.com/a.tgz" },
      "node_modules/real": { version: "2.0.0" },
      "node_modules/prefixed": { version: "v3.1.0" },
    },
  },
  "empty": { lockfileVersion: 3, packages: {} },
  "same package at two versions": {
    lockfileVersion: 3,
    packages: {
      "node_modules/qs": { version: "6.11.0" },
      "node_modules/a/node_modules/qs": { version: "6.9.0" },
      "node_modules/a": { version: "1.0.0" },
    },
  },
};

const MANIFESTS = {
  none: undefined,
  "two direct, one dev": { dependencies: { express: "^4.18.2", react: "^19.0.0" }, devDependencies: { vite: "^6" } },
  "an optional one": { optionalDependencies: { qs: "^6" } },
  "nothing declared": {},
};

const sorted = (rows) => [...rows].sort((a, b) => `${a.name}@${a.version}`.localeCompare(`${b.name}@${b.version}`));

test("both copies read every lock file the same way", { skip: sibling ? false : "platform-node is not in this tree" }, () => {
  for (const [lockName, lock] of Object.entries(LOCKS)) {
    for (const [manifestName, manifest] of Object.entries(MANIFESTS)) {
      const mine = sorted(here.lockPackages(lock, here.directNames(manifest)));
      const theirs = sorted(sibling.lockPackages(lock, sibling.directNames(manifest)));
      assert.deepEqual(mine, theirs, `${lockName} / ${manifestName}`);
    }
  }
});

// pnpm, yarn and bun lock files, read from their text. The fixtures are one
// project written by each tool (fixtures/package.json); the rest are the
// corners: aliases, git and local packages, and files that are broken.
const FIXTURES = path.join(__dirname, "fixtures");
const fixture = (name) => fs.readFileSync(path.join(FIXTURES, name), "utf8");
const PROJECT = JSON.parse(fixture("package.json"));

const TEXT_LOCKS = {
  "pnpm lockfile 5.4": ["pnpm-lock.yaml", fixture("pnpm-v5.yaml")],
  "pnpm lockfile 6.0": ["pnpm-lock.yaml", fixture("pnpm-v6.yaml")],
  "pnpm lockfile 9.0": ["pnpm-lock.yaml", fixture("pnpm-v9.yaml")],
  "yarn 1": ["yarn.lock", fixture("yarn-v1.lock")],
  "yarn 2+": ["yarn.lock", fixture("yarn-berry.lock")],
  "bun.lock": ["bun.lock", fixture("bun.lock")],
  "pnpm 9 alias": ["pnpm-lock.yaml", [
    "lockfileVersion: '9.0'", "importers:", "  .:", "    dependencies:",
    "      lodash-alias:", "        specifier: npm:lodash@^4", "        version: lodash@4.17.21",
    "      '@scope/x':", "        specifier: ^1", "        version: 1.0.0",
    "snapshots:", "  lodash@4.17.21: {}", "  '@scope/x@1.0.0':", "    dependencies:", "      inner: '@real/inner@2.0.0'",
    "  '@real/inner@2.0.0': {}",
  ].join("\n")],
  "pnpm 6 alias": ["pnpm-lock.yaml", [
    "lockfileVersion: '6.0'", "dependencies:", "  lodash-alias:", "    specifier: npm:lodash@^4", "    version: /lodash@4.17.21",
    "packages:", "  /lodash@4.17.21:", "    resolution: {integrity: sha512-x}", "    dev: false",
    "  github.com/a/b/1abc:", "    name: b", "    version: 1.0.0", "    dev: false",
  ].join("\n")],
  "yarn 1 alias, git and GitHub": ["yarn.lock", [
    '"lodash-alias@npm:lodash@^4":', '  version "4.17.21"',
    '"fromgit@git+https://example.com/a.git#abc":', '  version "1.0.0"', "  dependencies:", '    real "^2.0.0"',
    'gh@user/repo:', '  version "3.0.0"',
    'real@^2.0.0:', '  version "v2.0.0"',
  ].join("\n")],
  "yarn 2+ alias and git": ["yarn.lock", [
    "__metadata:", "  version: 6", "",
    '"lodash-alias@npm:lodash@^4":', "  version: 4.17.21", '  resolution: "lodash@npm:4.17.21"', "  linkType: hard",
    '"fromgit@git+https://example.com/a.git#abc":', "  version: 1.0.0", '  resolution: "fromgit@git+https://example.com/a.git#commit=abc"',
    "  dependencies:", "    real: ^2.0.0", "  linkType: hard",
    '"real@npm:^2.0.0":', "  version: 2.0.0", '  resolution: "real@npm:2.0.0"', "  linkType: hard",
  ].join("\n")],
  "bun alias and git": ["bun.lock", JSON.stringify({
    lockfileVersion: 1,
    workspaces: { "": { dependencies: { "lodash-alias": "npm:lodash@^4", fromgit: "github:a/b" } } },
    packages: {
      "lodash-alias": ["lodash@4.17.21", "", {}, "sha512-x"],
      fromgit: ["fromgit@github:a/b#abc", { dependencies: { real: "^2" } }, "abc"],
      real: ["real@2.0.0", "", {}, "sha512-y"],
    },
  })],
  "npm 3 from git, folders and tarballs": ["package-lock.json", JSON.stringify({ lockfileVersion: 3, packages: {
    "node_modules/registry": { version: "1.0.0", resolved: "https://registry.npmjs.org/registry/-/registry-1.0.0.tgz" },
    "node_modules/ghpkg": { version: "1.0.0", resolved: "https://npm.pkg.github.com/download/@o/ghpkg/1.0.0/abc" },
    "node_modules/fromgit": { version: "1.0.0", resolved: "git+ssh://git@github.com/a/b.git#abc" },
    "node_modules/tarball": { version: "1.0.0", resolved: "https://example.com/tarball.tgz" },
    "node_modules/folder": { version: "1.0.0", resolved: "file:../folder" },
    "node_modules/lodash-alias": { name: "lodash", version: "4.17.21" },
  } })],
  "npm 1 alias and git": ["package-lock.json", JSON.stringify({ lockfileVersion: 1, dependencies: {
    "lodash-alias": { version: "npm:lodash@4.17.21" },
    fromgit: { version: "1.0.0", resolved: "github:a/b#abc", dependencies: { inner: { version: "2.0.0" } } },
  } })],
  "pnpm with a key too long for one line": ["pnpm-lock.yaml", [
    "lockfileVersion: '9.0'", "importers:", "  .:", "    dependencies:",
    "      next:", "        specifier: 15.1.0", `        version: 15.1.0${"(x@1.0.0)".repeat(130)}`,
    "snapshots:", `  ? next@15.1.0${"(x@1.0.0)".repeat(130)}`, "  : dependencies:", "      '@next/env': 15.1.0",
    "  '@next/env@15.1.0': {}",
  ].join("\n")],
  "pnpm with a byte order mark": ["pnpm-lock.yaml", `\ufeff${fixture("pnpm-v9.yaml")}`],
  "yarn 2+ with a byte order mark": ["yarn.lock", `\ufeff${fixture("yarn-berry.lock")}`],
  "bun with a byte order mark": ["bun.lock", `\ufeff${fixture("bun.lock")}`],
  "npm with a byte order mark": ["package-lock.json", `\ufeff${JSON.stringify(LOCKS["v1 tree"])}`],
  "yarn 1 workspaces": ["yarn.lock", 'react@^19.0.0:\n  version "19.0.0"\nturbo@^2:\n  version "2.3.0"\n',
    { "apps/web": { dependencies: { react: "^19.0.0" }, devDependencies: { turbo: "^2" } } }],
  "yarn 2+ workspaces": ["yarn.lock", [
    "__metadata:", "  version: 8", "",
    '"react@npm:^19.0.0":', "  version: 19.0.0", '  resolution: "react@npm:19.0.0"', "  linkType: hard",
    '"web@workspace:apps/web":', "  version: 0.0.0-use.local", '  resolution: "web@workspace:apps/web"',
    "  dependencies:", '    react: "npm:^19.0.0"', "  linkType: soft",
  ].join("\n"), { "apps/web": { dependencies: { react: "^19.0.0" } } }],
  "pnpm with a tab": ["pnpm-lock.yaml", "lockfileVersion: '9.0'\n\tbad: tab\n"],
  "pnpm without a version": ["pnpm-lock.yaml", "packages: {}\n"],
  "yarn that isn't": ["yarn.lock", "not a lock file\n"],
  "bun that isn't JSON": ["bun.lock", "{ nope"],
};

const TEXT_MANIFESTS = {
  ...MANIFESTS,
  "the fixtures' project": PROJECT,
  "the aliases": { dependencies: { "lodash-alias": "npm:lodash@^4", "@scope/x": "^1", fromgit: "git+https://example.com/a.git#abc", gh: "user/repo" } },
  "yarn 1 workspaces": { workspaces: ["apps/*"], devDependencies: { turbo: "^2" } },
};

// The same rows, or the same error.
const outcome = (copy, file, text, manifest, workspaces) => {
  try {
    return { rows: sorted(copy.parseLock(file, text, manifest, workspaces)), patterns: copy.workspacePatterns(file, text, manifest) };
  } catch (error) {
    return { error: error.message };
  }
};

test("both copies read every pnpm, yarn and bun lock file the same way", { skip: sibling ? false : "platform-node is not in this tree" }, () => {
  for (const [lockName, [file, text, workspaces]] of Object.entries(TEXT_LOCKS)) {
    for (const [manifestName, manifest] of Object.entries(TEXT_MANIFESTS)) {
      const mine = outcome(here, file, text, manifest, workspaces);
      assert.deepEqual(mine, outcome(sibling, file, text, manifest, workspaces), `${lockName} / ${manifestName}`);
    }
  }
});

test("both copies read npm's lock files through parseLock the same way", { skip: sibling ? false : "platform-node is not in this tree" }, () => {
  for (const [lockName, lock] of Object.entries(LOCKS)) {
    for (const [manifestName, manifest] of Object.entries(MANIFESTS)) {
      const text = JSON.stringify(lock);
      assert.deepEqual(outcome(here, "package-lock.json", text, manifest), outcome(sibling, "package-lock.json", text, manifest), `${lockName} / ${manifestName}`);
    }
  }
});

test("both copies read yarn workspace patterns the same way", { skip: sibling ? false : "platform-node is not in this tree" }, () => {
  for (const pattern of ["apps/*", "./packages/ui/", "*", "!apps/old", "!apps/*", "packages/**", "", "a/b/*"]) {
    assert.deepEqual(here.workspaceGlob(pattern), sibling.workspaceGlob(pattern), pattern);
  }
});

test("both copies try the same lock files in the same order", { skip: sibling ? false : "platform-node is not in this tree" }, () => {
  assert.deepEqual(here.LOCK_FILES, sibling.LOCK_FILES);
});

test("both copies agree on what package.json declares", { skip: sibling ? false : "platform-node is not in this tree" }, () => {
  for (const [name, manifest] of Object.entries(MANIFESTS)) {
    assert.deepEqual([...here.directNames(manifest)].sort(), [...sibling.directNames(manifest)].sort(), name);
  }
});
