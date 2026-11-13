// The command itself: what it sends, and the rule the whole thing rests on —
// it never fails the build, whatever goes wrong, unless asked to with --strict.
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const { main, parse } = require("../bin/report-packages.js");

const SITE = "0123456789abcdef01234567";
const ENV = { ANALYTICS_SITE_ID: SITE, ANALYTICS_SECRET: "test-secret", ANALYTICS_ENDPOINT: "https://collect.example/" };

const LOCK = {
  lockfileVersion: 3,
  packages: {
    "": { name: "site", dependencies: { react: "^19.0.0" } },
    "node_modules/react": { version: "19.0.0" },
    "node_modules/scheduler": { version: "0.25.0" },
  },
};

function project(files = { "package-lock.json": LOCK, "package.json": { dependencies: { react: "^19.0.0" } } }) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "report-cli-"));
  for (const [name, contents] of Object.entries(files)) {
    fs.writeFileSync(path.join(dir, name), typeof contents === "string" ? contents : JSON.stringify(contents));
  }
  return dir;
}

// Runs the command with the network and the console replaced.
async function run(argv, env = ENV, responder = async () => new Response(JSON.stringify({ v: 1, enabled: true }), { status: 200 })) {
  const calls = [];
  const out = [];
  const realFetch = globalThis.fetch;
  const realLog = console.log;
  const realWarn = console.warn;
  globalThis.fetch = async (url, init) => {
    calls.push({ url, init });
    return responder(url, init);
  };
  console.log = (...args) => out.push(args.join(" "));
  console.warn = (...args) => out.push(args.join(" "));
  try {
    const code = await main(argv, env);
    return { code, calls, out: out.join("\n") };
  } finally {
    globalThis.fetch = realFetch;
    console.log = realLog;
    console.warn = realWarn;
  }
}

test("sends the packages, marked, as a build report", async () => {
  const dir = project();
  try {
    const { code, calls } = await run(["--dir", dir]);
    assert.equal(code, 0);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, "https://collect.example/events/inventory");
    assert.equal(calls[0].init.headers.authorization, "Bearer test-secret");
    assert.match(calls[0].init.headers["user-agent"], /^analytics-report-packages\//);
    const body = JSON.parse(calls[0].init.body);
    assert.equal(body.site_id, SITE);
    assert.equal(body.host, "build");
    assert.equal(body.source, "build");
    assert.equal(body.truncated, false);
    assert.equal(body.packages.length, 2);
    assert.equal(body.packages.find((p) => p.name === "react").direct, true);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("never sends a runtime: CI's Node is not the site's", async () => {
  const dir = project();
  try {
    const { calls } = await run(["--dir", dir]);
    assert.equal("runtime" in JSON.parse(calls[0].init.body), false);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("a name for the report can be given", async () => {
  const dir = project();
  try {
    const { calls } = await run(["--dir", dir, "--host", "netlify"]);
    assert.equal(JSON.parse(calls[0].init.body).host, "netlify");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("--dry-run sends nothing", async () => {
  const dir = project();
  try {
    const { code, calls, out } = await run(["--dir", dir, "--dry-run"]);
    assert.equal(code, 0);
    assert.equal(calls.length, 0);
    assert.match(out, /would report 2 packages/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

// The rule: none of these may break somebody's deploy.
const FAILURES = [
  ["no site id", ["--dir", "."], { ...ENV, ANALYTICS_SITE_ID: "" }, /no site ID/],
  ["a site id that isn't one", ["--dir", "."], { ...ENV, ANALYTICS_SITE_ID: "nope" }, /no site ID/],
  ["no secret", ["--dir", "."], { ...ENV, ANALYTICS_SECRET: "" }, /no site secret/],
  ["no endpoint", ["--dir", "."], { ...ENV, ANALYTICS_ENDPOINT: "" }, /no collector address/],
  ["an endpoint that isn't a URL", ["--dir", "."], { ...ENV, ANALYTICS_ENDPOINT: "collect.example" }, /no collector address/],
  ["a host name that isn't usable", ["--dir", ".", "--host", "a build!"], ENV, /isn't a usable name/],
  ["an option it doesn't know", ["--wat"], ENV, /don't know what to do/],
  ["an option missing its value", ["--dir"], ENV, /don't know what to do/],
];

for (const [name, argv, env, message] of FAILURES) {
  test(`${name}: says so and exits 0`, async () => {
    const { code, out } = await run(argv, env);
    assert.equal(code, 0);
    assert.match(out, message);
  });

  test(`${name}: exits 1 under --strict`, async () => {
    const { code } = await run([...argv, "--strict"], env);
    assert.equal(code, 1);
  });
}

test("no lock file: says where it looked, exits 0", async () => {
  const dir = project({ "package.json": { dependencies: { react: "1" } } });
  try {
    const { code, calls, out } = await run(["--dir", dir]);
    assert.equal(code, 0);
    assert.equal(calls.length, 0);
    assert.match(out, /no npm-shrinkwrap\.json, package-lock\.json/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("only bun's binary lock file: says how to get a readable one, exits 0", async () => {
  const dir = project({ "bun.lockb": "\u0000binary", "package.json": { dependencies: { react: "1" } } });
  try {
    const { code, calls, out } = await run(["--dir", dir]);
    assert.equal(code, 0);
    assert.equal(calls.length, 0);
    assert.match(out, /bun install --save-text-lockfile/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("yarn.lock without package.json: reports nothing rather than an empty list", async () => {
  const dir = project({ "yarn.lock": "react@^19.0.0:\n  version \"19.0.0\"\n" });
  try {
    const { code, calls, out } = await run(["--dir", dir]);
    assert.equal(code, 0);
    assert.equal(calls.length, 0);
    assert.match(out, /package\.json isn't/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("a pnpm project is reported like an npm one", async () => {
  const dir = project({
    "pnpm-lock.yaml": "lockfileVersion: '9.0'\n\nimporters:\n\n  .:\n    dependencies:\n      react:\n        specifier: ^19.0.0\n        version: 19.0.0\n\nsnapshots:\n\n  react@19.0.0: {}\n",
    "package.json": { dependencies: { react: "^19.0.0" } },
  });
  try {
    const { code, calls } = await run(["--dir", dir]);
    assert.equal(code, 0);
    assert.deepEqual(JSON.parse(calls[0].init.body).packages, [{ ecosystem: "npm", name: "react", version: "19.0.0", direct: true }]);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("a broken pnpm, yarn or bun lock file: exits 0, and 1 with --strict", async () => {
  for (const [name, text] of [["pnpm-lock.yaml", "lockfileVersion: '9.0'\n\tbad: tab\n"], ["yarn.lock", "not a lock file\n"], ["bun.lock", "{ nope"]]) {
    const dir = project({ [name]: text, "package.json": { dependencies: {} } });
    try {
      const lenient = await run(["--dir", dir]);
      assert.equal(lenient.code, 0, name);
      assert.match(lenient.out, new RegExp(`couldn't read the lock file: .*${name.replace(".", "\\.")}`), name);
      assert.equal((await run(["--dir", dir, "--strict"])).code, 1, name);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  }
});

test("a broken package.json: warns, and still reports the packages unmarked", async () => {
  const dir = project({ "package-lock.json": LOCK, "package.json": "{ broken" });
  try {
    const { code, calls, out } = await run(["--dir", dir]);
    assert.equal(code, 0);
    assert.equal(calls.length, 1);
    assert.match(out, /couldn't read .*package\.json/);
    assert.ok(JSON.parse(calls[0].init.body).packages.every((p) => p.direct === undefined));
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("a broken lock file beside a good one: warns, and reports from the good one", async () => {
  const dir = project({
    "package-lock.json": "{ broken",
    "yarn.lock": 'react@^19.0.0:\n  version "19.0.0"\n',
    "package.json": { dependencies: { react: "^19.0.0" } },
  });
  try {
    const { code, calls, out } = await run(["--dir", dir]);
    assert.equal(code, 0);
    assert.deepEqual(JSON.parse(calls[0].init.body).packages, [{ ecosystem: "npm", name: "react", version: "19.0.0", direct: true }]);
    assert.match(out, /package-lock\.json.*used .*yarn\.lock instead/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("a lock file that isn't JSON: exits 0", async () => {
  const dir = project({ "package-lock.json": "{ broken" });
  try {
    const { code, out } = await run(["--dir", dir]);
    assert.equal(code, 0);
    assert.match(out, /couldn't read the lock file/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("the collector unreachable: exits 0 and says the build is fine", async () => {
  const dir = project();
  try {
    const { code, out } = await run(["--dir", dir], ENV, async () => { throw new Error("getaddrinfo ENOTFOUND"); });
    assert.equal(code, 0);
    assert.match(out, /couldn't reach https:\/\/collect\.example/);
    assert.match(out, /the build is fine/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("credentials refused: says to check them, exits 0", async () => {
  const dir = project();
  try {
    const { code, out } = await run(["--dir", dir], ENV, async () => new Response("{}", { status: 401 }));
    assert.equal(code, 0);
    assert.match(out, /refused/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("the collector erroring: exits 0", async () => {
  const dir = project();
  try {
    const { code, out } = await run(["--dir", dir], ENV, async () => new Response("{}", { status: 503 }));
    assert.equal(code, 0);
    assert.match(out, /answered 503/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("the module switched off: says so without complaining", async () => {
  const dir = project();
  try {
    const { code, out } = await run(["--dir", dir], ENV, async () => new Response(JSON.stringify({ v: 1, enabled: false }), { status: 200 }));
    assert.equal(code, 0);
    assert.match(out, /switched off/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("--quiet says nothing when it worked", async () => {
  const dir = project();
  try {
    const { out } = await run(["--dir", dir, "--quiet"]);
    assert.equal(out, "");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("--help prints the usage and sends nothing", async () => {
  const { code, calls, out } = await run(["--help"]);
  assert.equal(code, 0);
  assert.equal(calls.length, 0);
  assert.match(out, /npx analytics-report-packages/);
});

test("a secret on the command line works, but the help says not to", async () => {
  const dir = project();
  try {
    const { calls } = await run(["--dir", dir, "--site", SITE, "--secret", "flag-secret", "--endpoint", "https://c.example"], {});
    assert.equal(calls[0].init.headers.authorization, "Bearer flag-secret");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("options can be written with an equals sign", () => {
  assert.deepEqual(parse(["--dir=/tmp/x", "--strict"]).flags, { dir: "/tmp/x", strict: true });
});

// A self-hosted build keeps its values in .env, which only the framework
// reads; this runs after it as its own process.
test("reads its three values from the project's .env files", async () => {
  const dir = project({
    "package-lock.json": LOCK,
    "package.json": { dependencies: { react: "^19.0.0" } },
    ".env": `ANALYTICS_SITE_ID=${SITE}\nANALYTICS_SECRET=from-env\nOTHER=ignored\n`,
    ".env.local": "# comment\nexport ANALYTICS_SECRET=\"from-local\"\nANALYTICS_ENDPOINT=https://collect.example # trailing\n",
  });
  try {
    const { code, calls, out } = await run(["--dir", dir], {});
    assert.equal(code, 0);
    assert.equal(calls.length, 1);
    assert.equal(calls[0].url, "https://collect.example/events/inventory");
    assert.equal(calls[0].init.headers.authorization, "Bearer from-local");
    assert.equal(JSON.parse(calls[0].init.body).site_id, SITE);
    assert.match(out, /read ANALYTICS_SITE_ID, ANALYTICS_SECRET, ANALYTICS_ENDPOINT from/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("a real environment variable beats a .env file", async () => {
  const dir = project({
    "package-lock.json": LOCK,
    ".env": "ANALYTICS_SECRET=from-file\nANALYTICS_HOST=dashboard\n",
  });
  try {
    const { calls } = await run(["--dir", dir], ENV);
    assert.equal(calls[0].init.headers.authorization, "Bearer test-secret");
    assert.equal(JSON.parse(calls[0].init.body).host, "dashboard");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("takes the server packages' ANALYTICS_SITE_SECRET too", async () => {
  const dir = project({ "package-lock.json": LOCK, ".env.local": "ANALYTICS_SITE_SECRET=shared-name\n" });
  try {
    const { calls } = await run(["--dir", dir], { ANALYTICS_SITE_ID: SITE, ANALYTICS_ENDPOINT: "https://collect.example" });
    assert.equal(calls[0].init.headers.authorization, "Bearer shared-name");
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
