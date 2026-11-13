// Reading the project: which packages a lock file yields, and which of them
// package.json asks for by name.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { collect, parseLock, lockPackages, directNames } = require("../lib/lockfile.js");

const LOCK_V3 = {
  lockfileVersion: 3,
  packages: {
    "": { name: "shop", dependencies: { react: "^19.0.0" } },
    "node_modules/react": { version: "19.0.0" },
    "node_modules/scheduler": { version: "0.25.0" },
    "node_modules/vite": { version: "6.0.1", dev: true },
    "node_modules/react/node_modules/loose-envify": { version: "1.4.0" },
    "node_modules/ui": { link: true, resolved: "packages/ui" },
    "packages/ui": { version: "1.0.0" },
  },
};

function inTempDir(files, run) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "report-packages-"));
  try {
    for (const [name, contents] of Object.entries(files)) {
      fs.writeFileSync(path.join(dir, name), typeof contents === "string" ? contents : JSON.stringify(contents));
    }
    return run(dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

test("takes the production packages, dev ones and links left out", () => {
  const names = lockPackages(LOCK_V3).map((p) => p.name).sort();
  assert.deepEqual(names, ["loose-envify", "react", "scheduler"]);
});

test("marks what package.json asks for, and nothing underneath it", () => {
  const rows = lockPackages(LOCK_V3, directNames({ dependencies: { react: "^19.0.0" } }));
  assert.equal(rows.find((p) => p.name === "react").direct, true);
  assert.equal(rows.find((p) => p.name === "scheduler").direct, undefined);
});

test("a bundled frontend's own libraries are in the lock file, which is the point", () => {
  // A static Vite + React build has no server, but React is still a package
  // it ships. This is what the build step is for.
  const rows = lockPackages(LOCK_V3, directNames({ dependencies: { react: "^19.0.0" } }));
  assert.ok(rows.some((p) => p.name === "react" && p.version === "19.0.0" && p.direct));
});

test("reads a real folder, saying which files it found", () => {
  inTempDir({ "package-lock.json": LOCK_V3, "package.json": { dependencies: { react: "^19.0.0" } } }, (dir) => {
    const found = collect(dir);
    assert.equal(found.manifest, true);
    assert.equal(path.basename(found.lockFile), "package-lock.json");
    assert.equal(found.packages.filter((p) => p.direct).length, 1);
  });
});

test("falls back to npm-shrinkwrap.json", () => {
  inTempDir({ "npm-shrinkwrap.json": LOCK_V3 }, (dir) => {
    assert.equal(path.basename(collect(dir).lockFile), "npm-shrinkwrap.json");
  });
});

test("no lock file is not a crash, it is nothing to report", () => {
  inTempDir({ "package.json": { dependencies: { react: "1" } } }, (dir) => {
    const found = collect(dir);
    assert.equal(found.lockFile, null);
    assert.deepEqual(found.packages, []);
  });
});

test("no package.json leaves everything unmarked, and still reports", () => {
  inTempDir({ "package-lock.json": LOCK_V3 }, (dir) => {
    const found = collect(dir);
    assert.equal(found.manifest, false);
    assert.equal(found.packages.length, 3);
    assert.ok(found.packages.every((p) => p.direct === undefined));
  });
});

test("a lock file that isn't JSON says which file is wrong", () => {
  inTempDir({ "package-lock.json": "{ not json" }, (dir) => {
    const found = collect(dir);
    assert.equal(found.lockFile, null);
    assert.equal(path.basename(found.failed[0].file), "package-lock.json");
  });
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

// pnpm, yarn and bun. The fixtures are one project, written by each tool:
// react and next asked for, @scope/opt optional, a local package (left out,
// but what it needs kept), a workspace, and typescript and vitest for
// development, vitest sharing js-tokens with a production package.
const FIXTURES = path.join(__dirname, "fixtures");
const fixture = (name) => fs.readFileSync(path.join(FIXTURES, name), "utf8");
const PROJECT = JSON.parse(fixture("package.json"));
const EXPECTED = [
  "@next/env@15.1.0",
  "@next/swc-linux-x64-gnu@15.1.0",
  "@scope/opt@1.2.0 direct",
  "client-only@0.0.1",
  "js-tokens@4.0.0",
  "left-pad@1.3.0",
  "next@15.1.0 direct",
  // A different react that @scope/opt pulls in is not the project's own.
  "react@18.3.1",
  "react@19.0.0 direct",
  "styled-jsx@5.1.6",
];
const summary = (rows) => rows
  .map((p) => {
    assert.equal(p.ecosystem, "npm");
    return `${p.name}@${p.version}${p.direct ? " direct" : ""}`;
  })
  .sort();

for (const [label, source, file] of [
  ["pnpm lockfile 5.4", "pnpm-v5.yaml", "pnpm-lock.yaml"],
  ["pnpm lockfile 6.0", "pnpm-v6.yaml", "pnpm-lock.yaml"],
  ["pnpm lockfile 9.0, after pnpm 10's own document", "pnpm-v9.yaml", "pnpm-lock.yaml"],
  ["yarn 1", "yarn-v1.lock", "yarn.lock"],
  ["yarn 2+", "yarn-berry.lock", "yarn.lock"],
  ["bun.lock", "bun.lock", "bun.lock"],
]) {
  test(`${label}: production packages, the project's own marked`, () => {
    inTempDir({ [file]: fixture(source), "package.json": PROJECT }, (dir) => {
      const found = collect(dir);
      assert.equal(path.basename(found.lockFile), file);
      assert.deepEqual(summary(found.packages), EXPECTED);
    });
  });
}

test("pnpm and bun still report without package.json, unmarked; yarn can't tell, so reports nothing", () => {
  for (const [source, file] of [["pnpm-v9.yaml", "pnpm-lock.yaml"], ["pnpm-v5.yaml", "pnpm-lock.yaml"], ["bun.lock", "bun.lock"]]) {
    const rows = parseLock(file, fixture(source), null);
    assert.equal(rows.length, EXPECTED.length, source);
    assert.ok(rows.every((p) => p.direct === undefined), source);
  }
  assert.deepEqual(parseLock("yarn.lock", fixture("yarn-v1.lock"), null), []);
  assert.deepEqual(parseLock("yarn.lock", fixture("yarn-berry.lock"), null), []);
});

test("an alias is reported under the package it really installs, and marked as the project's", () => {
  const manifest = { dependencies: { "lodash-alias": "npm:lodash@^4" } };
  const pnpm = "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      lodash-alias:\n"
    + "        specifier: npm:lodash@^4\n        version: lodash@4.17.21\nsnapshots:\n  lodash@4.17.21: {}\n";
  const yarn = '"lodash-alias@npm:lodash@^4":\n  version "4.17.21"\n';
  const bun = JSON.stringify({ workspaces: { "": { dependencies: { "lodash-alias": "npm:lodash@^4" } } },
    packages: { "lodash-alias": ["lodash@4.17.21", "", {}, "sha512-x"] } });
  for (const [file, text] of [["pnpm-lock.yaml", pnpm], ["yarn.lock", yarn], ["bun.lock", bun]]) {
    assert.deepEqual(parseLock(file, text, manifest), [{ ecosystem: "npm", name: "lodash", version: "4.17.21", direct: true }], file);
  }
  // npm: lockfile 3 names the real package in the entry; lockfile 1 writes
  // the alias into the version.
  const v3 = { lockfileVersion: 3, packages: { "node_modules/lodash-alias": { name: "lodash", version: "4.17.21" } } };
  const v1 = { lockfileVersion: 1, dependencies: { "lodash-alias": { version: "npm:lodash@4.17.21" } } };
  for (const lock of [v3, v1]) {
    assert.deepEqual(parseLock("package-lock.json", JSON.stringify(lock), manifest), [{ ecosystem: "npm", name: "lodash", version: "4.17.21", direct: true }]);
  }
});

test("git, GitHub and local packages are left out, and what they need is kept", () => {
  const yarn = [
    '"fromgit@git+https://example.com/a.git#abc":', '  version "1.0.0"', "  dependencies:", '    real "^2.0.0"',
    "gh@user/repo:", '  version "3.0.0"',
    "real@^2.0.0:", '  version "v2.0.0"',
  ].join("\n");
  const manifest = { dependencies: { fromgit: "git+https://example.com/a.git#abc", gh: "user/repo" } };
  assert.deepEqual(parseLock("yarn.lock", yarn, manifest), [{ ecosystem: "npm", name: "real", version: "2.0.0" }]);
});

test("pnpm, yarn, bun: the order lock files are tried in", () => {
  const pnpm = fixture("pnpm-v9.yaml");
  const yarn = fixture("yarn-v1.lock");
  const bun = fixture("bun.lock");
  inTempDir({ "package-lock.json": LOCK_V3, "pnpm-lock.yaml": pnpm, "yarn.lock": yarn }, (dir) => {
    assert.equal(path.basename(collect(dir).lockFile), "package-lock.json");
  });
  inTempDir({ "pnpm-lock.yaml": pnpm, "yarn.lock": yarn, "bun.lock": bun }, (dir) => {
    assert.equal(path.basename(collect(dir).lockFile), "pnpm-lock.yaml");
  });
  inTempDir({ "yarn.lock": yarn, "bun.lock": bun }, (dir) => {
    assert.equal(path.basename(collect(dir).lockFile), "yarn.lock");
  });
});

test("a broken pnpm, yarn or bun lock file says which file is wrong", () => {
  for (const [file, text] of [["pnpm-lock.yaml", "lockfileVersion: '9.0'\n\tbad: tab\n"], ["pnpm-lock.yaml", "packages: {}\n"],
    ["yarn.lock", "not a lock file\n"], ["bun.lock", "{ nope"]]) {
    inTempDir({ [file]: text }, (dir) => {
      const found = collect(dir);
      assert.equal(found.lockFile, null, file);
      assert.equal(path.basename(found.failed[0].file), file);
    });
  }
});

test("a lock file that won't parse is passed over for the next one", () => {
  inTempDir({ "package-lock.json": "{ broken", "yarn.lock": fixture("yarn-v1.lock"), "package.json": PROJECT }, (dir) => {
    const found = collect(dir);
    assert.equal(path.basename(found.lockFile), "yarn.lock");
    assert.equal(path.basename(found.failed[0].file), "package-lock.json");
    assert.equal(found.packages.length, EXPECTED.length);
  });
});

test("a broken package.json is a warning, and the packages still go up unmarked", () => {
  inTempDir({ "package-lock.json": LOCK_V3, "package.json": "{ broken" }, (dir) => {
    const found = collect(dir);
    assert.equal(found.manifest, false);
    assert.match(found.warnings[0], /package\.json.*none of the packages are marked/);
    assert.equal(found.packages.length, 3);
  });
});

test("npm-shrinkwrap.json wins over package-lock.json, as it does for npm", () => {
  const shrinkwrap = { lockfileVersion: 3, packages: { "node_modules/react": { version: "18.0.0" } } };
  inTempDir({ "package-lock.json": LOCK_V3, "npm-shrinkwrap.json": shrinkwrap }, (dir) => {
    const found = collect(dir);
    assert.equal(path.basename(found.lockFile), "npm-shrinkwrap.json");
    assert.deepEqual(found.packages.map((p) => p.version), ["18.0.0"]);
  });
});

test("npm: packages from git, a folder or a tarball that isn't a registry's are left out", () => {
  const lock = {
    lockfileVersion: 3,
    packages: {
      "node_modules/registry": { version: "1.0.0", resolved: "https://registry.npmjs.org/registry/-/registry-1.0.0.tgz" },
      "node_modules/@s/scoped": { version: "1.0.0", resolved: "https://npm.example.com/@s/scoped/-/scoped-1.0.0.tgz?x=1" },
      "node_modules/ghpkg": { version: "1.0.0", resolved: "https://npm.pkg.github.com/download/@o/ghpkg/1.0.0/abc" },
      "node_modules/bundled": { version: "1.0.0" },
      "node_modules/fromgit": { version: "1.0.0", resolved: "git+ssh://git@github.com/a/b.git#abc" },
      "node_modules/github": { version: "1.0.0", resolved: "github:a/b#abc" },
      "node_modules/tarball": { version: "1.0.0", resolved: "https://example.com/files/tarball.tgz" },
      "node_modules/folder": { version: "1.0.0", resolved: "file:../folder" },
    },
  };
  assert.deepEqual(lockPackages(lock).map((p) => p.name).sort(), ["@s/scoped", "bundled", "ghpkg", "registry"]);
  const v1 = { lockfileVersion: 1, dependencies: {
    kept: { version: "1.0.0", resolved: "https://registry.npmjs.org/kept/-/kept-1.0.0.tgz" },
    fromgit: { version: "1.0.0", resolved: "git+https://github.com/a/b.git#abc", dependencies: { inner: { version: "2.0.0" } } },
  } };
  assert.deepEqual(lockPackages(v1).map((p) => p.name).sort(), ["inner", "kept"]);
});

test("a byte order mark at the start of a file is not part of it", () => {
  const bom = "\ufeff";
  for (const [source, file] of [["pnpm-v9.yaml", "pnpm-lock.yaml"], ["yarn-berry.lock", "yarn.lock"], ["bun.lock", "bun.lock"]]) {
    inTempDir({ [file]: bom + fixture(source), "package.json": bom + JSON.stringify(PROJECT) }, (dir) => {
      assert.deepEqual(summary(collect(dir).packages), EXPECTED, source);
    });
  }
  inTempDir({ "package-lock.json": bom + JSON.stringify(LOCK_V3) }, (dir) => assert.equal(collect(dir).packages.length, 3));
});

test("pnpm: a key too long for one line, written as \"? key\" and \": value\"", () => {
  const peers = "(x@1.0.0)".repeat(130);
  const text = [
    "lockfileVersion: '9.0'", "importers:", "  .:", "    dependencies:",
    "      next:", "        specifier: 15.1.0", `        version: 15.1.0${peers}`,
    "snapshots:",
    `  ? next@15.1.0${peers}`, "  : dependencies:", "      '@next/env': 15.1.0", "    optionalDependencies:", "      sharp: 0.33.0",
    `  ? other@1.0.0${peers}`, "  : {}",
    "  '@next/env@15.1.0': {}", "  sharp@0.33.0: {}",
  ].join("\n");
  const rows = parseLock("pnpm-lock.yaml", text, { dependencies: { next: "15.1.0" } });
  assert.deepEqual(summary(rows), ["@next/env@15.1.0", "next@15.1.0 direct", "sharp@0.33.0"]);
});

// A Turborepo-style yarn monorepo: the root asks for nothing but tools, and
// the apps under apps/ ask for what ships.
test("yarn workspaces: each one's production packages, none of them marked as the project's", () => {
  const root = { private: true, workspaces: ["apps/*", "packages/ui", "!apps/old"], devDependencies: { turbo: "^2" } };
  const web = { name: "web", dependencies: { react: "^19.0.0", ui: "*" }, devDependencies: { vitest: "^2" } };
  const ui = { name: "ui", dependencies: { "client-only": "0.0.1" } };
  const classic = [
    "react@^19.0.0:", '  version "19.0.0"', "client-only@0.0.1:", '  version "0.0.1"',
    "vitest@^2:", '  version "2.1.8"', "turbo@^2:", '  version "2.3.0"',
  ].join("\n");
  const berry = [
    "__metadata:", "  version: 8", "",
    '"react@npm:^19.0.0":', "  version: 19.0.0", '  resolution: "react@npm:19.0.0"', "  linkType: hard",
    '"client-only@npm:0.0.1":', "  version: 0.0.1", '  resolution: "client-only@npm:0.0.1"', "  linkType: hard",
    '"vitest@npm:^2":', "  version: 2.1.8", '  resolution: "vitest@npm:2.1.8"', "  linkType: hard",
    '"turbo@npm:^2":', "  version: 2.3.0", '  resolution: "turbo@npm:2.3.0"', "  linkType: hard",
    '"mono@workspace:.":', "  version: 0.0.0-use.local", '  resolution: "mono@workspace:."',
    "  dependencies:", '    turbo: "npm:^2"', "  linkType: soft",
    '"web@workspace:apps/web":', "  version: 0.0.0-use.local", '  resolution: "web@workspace:apps/web"',
    "  dependencies:", '    react: "npm:^19.0.0"', '    ui: "workspace:*"', '    vitest: "npm:^2"', "  linkType: soft",
    '"ui@workspace:*, ui@workspace:packages/ui":', "  version: 0.0.0-use.local", '  resolution: "ui@workspace:packages/ui"',
    "  dependencies:", '    client-only: "npm:0.0.1"', "  linkType: soft",
  ].join("\n");
  for (const text of [classic, berry]) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "report-packages-ws-"));
    try {
      for (const [folder, manifest] of [["", root], ["apps/web", web], ["apps/old", { dependencies: { turbo: "^2" } }], ["packages/ui", ui]]) {
        fs.mkdirSync(path.join(dir, folder), { recursive: true });
        fs.writeFileSync(path.join(dir, folder, "package.json"), JSON.stringify(manifest));
      }
      fs.writeFileSync(path.join(dir, "yarn.lock"), text);
      assert.deepEqual(summary(collect(dir).packages), ["client-only@0.0.1", "react@19.0.0"]);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }
});

test("yarn workspace patterns: a folder and the folders in one, nothing fancier", () => {
  const { workspaceGlob, workspacePatterns } = require("../lib/lockfile.js");
  assert.deepEqual(workspaceGlob("apps/*"), { folder: "apps", children: true, exclude: false });
  assert.deepEqual(workspaceGlob("./packages/ui/"), { folder: "packages/ui", children: false, exclude: false });
  assert.deepEqual(workspaceGlob("*"), { folder: "", children: true, exclude: false });
  assert.deepEqual(workspaceGlob("!apps/old"), { folder: "apps/old", children: false, exclude: true });
  assert.equal(workspaceGlob("packages/**"), null);
  assert.equal(workspaceGlob("!apps/*"), null);
  assert.deepEqual(workspacePatterns("yarn.lock", "a@^1:\n  version \"1.0.0\"\n", { workspaces: { packages: ["apps/*"] } }), ["apps/*"]);
  assert.deepEqual(workspacePatterns("pnpm-lock.yaml", "", { workspaces: ["apps/*"] }), []);
});

test("bun's binary lock file is noticed but not read", () => {
  inTempDir({ "bun.lockb": "\u0000binary" }, (dir) => {
    const found = collect(dir);
    assert.equal(found.lockFile, null);
    assert.equal(path.basename(found.binaryLock), "bun.lockb");
    assert.deepEqual(found.packages, []);
  });
});

test("bun.lock's trailing commas and comments are not part of the data", () => {
  const text = '{\n  // bun writes none, but JSONC allows them\n  "workspaces": { "": { "dependencies": { "a": "1", }, }, },\n'
    + '  /* a "quoted, }" string stays */ "packages": { "a": ["a@1.0.0", "", { "note": "x, ]" }, "sha",], },\n}\n';
  assert.deepEqual(parseLock("bun.lock", text, { dependencies: { a: "1" } }), [{ ecosystem: "npm", name: "a", version: "1.0.0", direct: true }]);
});
