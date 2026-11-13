#!/usr/bin/env node
// Reports a project's packages once, from its build (protocol in
// sdk/protocols/inventory.md, `source: "build"`). For sites with nothing
// running server-side to report by itself (a static build, Next.js on
// Vercel or Netlify) and for a separate front end whose lock file no server
// package of ours reads.
//
// One line on the end of the build:
//   "build": "vite build && npx analytics-report-packages"
//
// Two rules this holds to:
//   It never fails the build. No network, wrong key, our collector down: it
//   says so on one line and exits 0. Nobody's deploy breaks because our
//   reporting had a bad day. --strict is there for people who want the
//   opposite, and it is off by default.
//   It never sends the build machine's Node version as the site's runtime.
//   A static site runs no Node at all, and CI's version is not the site's —
//   reporting it would have the dashboard calling an unsupported Node a
//   problem on a site that doesn't use Node.
"use strict";

const fs = require("node:fs");
const path = require("node:path");
const { collect } = require("../lib/lockfile.js");

const VERSION = require("../package.json").version;
const MAX_PACKAGES = 5000;
const TIMEOUT_MS = 10000;
const HOST_SHAPE = /^[A-Za-z0-9._-]{1,100}$/;
// ANALYTICS_SITE_SECRET is the name the server packages read, so a project
// that has one already set up needs no second copy of the secret.
const KEYS = ["ANALYTICS_SITE_ID", "ANALYTICS_SECRET", "ANALYTICS_SITE_SECRET", "ANALYTICS_ENDPOINT", "ANALYTICS_HOST"];
// Lowest first, as Next.js, Vite and Nuxt rank them: a later file wins, and a
// real environment variable beats every file.
const ENV_FILES = [".env", ".env.production", ".env.local", ".env.production.local"];

// A build that keeps its values in .env reads them through its framework, but
// this runs as its own process after the build and would otherwise see none
// of them. Only our own four keys are taken; nothing else in the file is
// read into anything. Unreadable or odd lines are skipped, never fatal.
function fromEnvFiles(dirs) {
  const found = {};
  const files = [];
  for (const dir of [...new Set(dirs)]) {
    for (const name of ENV_FILES) {
      let text;
      try {
        text = fs.readFileSync(path.join(dir, name), "utf8");
      } catch {
        continue;
      }
      let used = false;
      for (const line of text.split(/\r?\n/)) {
        const match = /^\s*(?:export\s+)?([A-Z_]+)\s*=\s*(.*?)\s*$/.exec(line);
        if (!match || !KEYS.includes(match[1])) continue;
        let value = match[2];
        const quoted = /^(["'])(.*)\1$/.exec(value);
        value = quoted ? quoted[2] : value.replace(/\s+#.*$/, "");
        found[match[1]] = value;
        used = true;
      }
      if (used) files.push(path.relative(process.cwd(), path.join(dir, name)) || name);
    }
  }
  return { found, files };
}

const USAGE = `analytics-report-packages ${VERSION}

Reports this project's packages to your analytics dashboard, once, from the build.

  npx analytics-report-packages [options]

Options
  --site <id>        Site ID        (or ANALYTICS_SITE_ID)
  --secret <secret>  Site secret    (or ANALYTICS_SECRET, or ANALYTICS_SITE_SECRET)
  --endpoint <url>   Collector URL  (or ANALYTICS_ENDPOINT)
                     The three can also sit in .env, .env.production, .env.local or
                     .env.production.local; a real environment variable wins.
  --dir <path>       Where the lock file is (default: this folder): npm-shrinkwrap.json,
                     package-lock.json, pnpm-lock.yaml, yarn.lock or bun.lock
  --host <name>      What to call this report in the dashboard (default: build,
                     or ANALYTICS_HOST). Give each front end its own name.
  --dry-run          Print what would be sent, send nothing
  --strict           Exit non-zero on failure (default: never fail the build)
  --quiet            Say nothing unless something is wrong
  --help

Put the secret in your CI's secret store or a .env file git ignores, never in the repo.`;

function parse(argv) {
  const out = { flags: {}, bad: [] };
  const takesValue = new Set(["site", "secret", "endpoint", "dir", "host"]);
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg.startsWith("--")) {
      out.bad.push(arg);
      continue;
    }
    const [name, inline] = arg.slice(2).split(/=(.*)/s);
    if (takesValue.has(name)) {
      // The next word, unless it is itself an option: "--dir --strict" is a
      // missing value, not a folder called --strict. Use --dir=--odd for the
      // vanishingly unlikely value that really does start with a dash.
      const next = argv[i + 1];
      const value = inline !== undefined ? inline : (next !== undefined && !next.startsWith("--") ? argv[++i] : undefined);
      if (value === undefined) out.bad.push(arg);
      else out.flags[name] = value;
    } else if (["dry-run", "strict", "quiet", "help"].includes(name)) {
      out.flags[name] = true;
    } else {
      out.bad.push(arg);
    }
  }
  return out;
}

async function main(argv, env) {
  const { flags, bad } = parse(argv);
  if (flags.help) {
    console.log(USAGE);
    return 0;
  }
  const strict = flags.strict === true;
  const say = (message) => { if (!flags.quiet) console.log(`analytics: ${message}`); };
  // Everything below this point is "report nothing, say why, don't break the
  // build" — so the one exit code that matters is decided here.
  const give_up = (message) => {
    console.warn(`analytics: ${message}`);
    return strict ? 1 : 0;
  };

  if (bad.length) return give_up(`don't know what to do with ${bad.join(" ")}. Try --help.`);

  const dir = path.resolve(flags.dir || env.ANALYTICS_DIR || process.cwd());
  const files = fromEnvFiles([process.cwd(), dir]);
  const fromFiles = Object.keys(files.found).filter((key) => !env[key]);
  env = { ...files.found, ...env };
  if (fromFiles.length) say(`read ${fromFiles.join(", ")} from ${files.files.join(", ")}.`);

  const siteId = String(flags.site || env.ANALYTICS_SITE_ID || "").trim();
  const secret = String(flags.secret || env.ANALYTICS_SECRET || env.ANALYTICS_SITE_SECRET || "").trim();
  const endpoint = String(flags.endpoint || env.ANALYTICS_ENDPOINT || "").trim().replace(/\/+$/, "");
  const host = String(flags.host || env.ANALYTICS_HOST || "build").trim();

  if (!/^[a-f0-9]{24}$/i.test(siteId)) return give_up("no site ID (ANALYTICS_SITE_ID), so nothing was reported.");
  if (!secret) return give_up("no site secret (ANALYTICS_SECRET), so nothing was reported.");
  if (!/^https?:\/\/[^\s/]+/.test(endpoint)) return give_up("no collector address (ANALYTICS_ENDPOINT), so nothing was reported.");
  if (!HOST_SHAPE.test(host)) return give_up(`"${host}" isn't a usable name for this report (letters, numbers, dot, dash, underscore).`);

  let found;
  try {
    found = collect(dir);
  } catch (error) {
    // collect() catches what it expects; this is for what it doesn't.
    return give_up(`couldn't read the project: ${error.message}`);
  }
  // Something wrong, but not enough to stop: these print even with --quiet.
  for (const warning of found.warnings) console.warn(`analytics: ${warning}`);
  const failures = found.failed.map((failure) => `${failure.file}: ${failure.message}`).join("; ");
  if (!found.lockFile && failures) return give_up(`couldn't read the lock file: ${failures}`);
  if (found.lockFile && failures) console.warn(`analytics: couldn't read ${failures}; used ${found.lockFile} instead.`);
  if (!found.lockFile && found.binaryLock) {
    return give_up(`only bun.lockb in ${dir}, which is binary and can't be read. Run \`bun install --save-text-lockfile\` once to write bun.lock beside it (bun 1.2 and later write it by default).`);
  }
  if (!found.lockFile) {
    return give_up(`no npm-shrinkwrap.json, package-lock.json, pnpm-lock.yaml, yarn.lock or bun.lock in ${dir}, so there are no packages to report. Use --dir if it's somewhere else.`);
  }
  // yarn.lock doesn't say which packages are for development only, so the
  // production ones are found from package.json; without it there are none,
  // and an empty report would wrongly say the site has no packages.
  if (path.basename(found.lockFile) === "yarn.lock" && !found.manifest && !found.packages.length) {
    return give_up(`yarn.lock is in ${dir} but package.json isn't, and yarn.lock alone can't tell production packages from development ones. Nothing was reported.`);
  }

  const packages = found.packages.slice(0, MAX_PACKAGES);
  const body = {
    site_id: siteId,
    host,
    at: new Date().toISOString(),
    // Reported from a build, not from something running: the dashboard keeps
    // these however long it is between deploys, because a site that hasn't
    // been rebuilt is still running exactly these packages.
    source: "build",
    packages,
    truncated: found.packages.length > MAX_PACKAGES,
  };
  const chosen = packages.filter((p) => p.direct).length;
  const summary = `${packages.length} packages${found.manifest ? `, ${chosen} of them yours` : " (no package.json, so none marked as yours)"}`;

  if (flags["dry-run"]) {
    console.log(`analytics: would report ${summary} from ${found.lockFile}`);
    console.log(JSON.stringify({ ...body, packages: packages.slice(0, 5) }, null, 2));
    if (packages.length > 5) console.log(`  … and ${packages.length - 5} more`);
    return 0;
  }

  let response;
  try {
    response = await fetch(`${endpoint}/events/inventory`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        authorization: `Bearer ${secret}`,
        "user-agent": `analytics-report-packages/${VERSION}`,
      },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(TIMEOUT_MS),
    });
  } catch (error) {
    return give_up(`couldn't reach ${endpoint}: ${error.message}. Nothing was reported; the build is fine.`);
  }
  if (response.status === 401) return give_up("the site ID and secret were refused. Check them in the dashboard.");
  if (!response.ok) return give_up(`the collector answered ${response.status}. Nothing was reported; the build is fine.`);

  const answer = await response.json().catch(() => null);
  if (answer && answer.enabled === false) {
    say("software inventory is switched off for this site, so nothing was kept.");
    return 0;
  }
  say(`reported ${summary}.`);
  return 0;
}

module.exports = { main, parse };

if (require.main === module) {
  main(process.argv.slice(2), process.env)
    .then((code) => process.exit(code))
    .catch((error) => {
      // Nothing above should throw, but a crash here must still not be the
      // reason somebody's deploy failed.
      console.warn(`analytics: ${error?.message || error}`);
      process.exit(process.argv.includes("--strict") ? 1 : 0);
    });
}
