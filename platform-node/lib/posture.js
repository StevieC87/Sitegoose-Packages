// How the server is set up (protocol in sdk/protocols/posture.md): the app
// settings that leave it open, whether it runs as root, and the files in the
// folders it serves to the web that should never be public. Sent to
// POST /events/posture a few minutes after start and then once a day (the
// collector's `every`), so Security → Security check can say what to change.
//
// It only reads: nothing here changes a setting, a permission or a file, and
// no file's contents are sent — paths, sizes, times and short values only.
// The walk is bounded and runs in the background, never in a request; with no
// folder served to the web there is nothing to walk and only the settings are
// reported.
"use strict";

const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");

const FIRST_MS = 3 * 60 * 1000;
const RETRY_S = 60 * 60;
const EVERY_S = 24 * 60 * 60;
const MAX_CHECKS = 200;
const MAX_EXPOSURE = 50;
const MAX_ENTRIES = 20000;
const MAX_DEPTH = 6;
const MAX_PERM_CHECKS = 3000;
// Folders that are conventionally served to the web, when the app has them.
const STATIC_DIRS = ["public", "static"];
const SKIP_DIRS = new Set([".git", ".svn", ".hg", "node_modules", "vendor", "cache", ".cache", ".next", ".history"]);
const CODE_FILE = /\.(js|cjs|mjs|jsx|tsx?|php[0-9]?|phtml|py|rb|pl|sh)$/i;
// Files that shouldn't be downloadable, by name; first match wins.
const EXPOSURE = [
  ["database_dump", /\.sql(\.(gz|bz2|xz|zip))?$/i],
  ["private_key", /^(id_rsa|id_dsa|id_ecdsa|id_ed25519)$|\.(pem|key|p12|pfx|jks)$/i],
  ["env", /^\.env($|\.)|^env\.(ini|txt)$/i],
  ["archive", /\.(zip|tar|tgz|tar\.gz|tar\.bz2|rar|7z)$/i],
  ["backup", /\.(bak|old|orig|save|swp|copy|backup)$|~$|\.(js|json|conf|config|ini|ya?ml)\.(bak|old|orig|save|txt)$/i],
  ["info", /^(phpinfo|info|adminer)\.php$/i],
  ["log", /^(debug|error|access)[-_.]?log$|\.log$/i],
];

const kindOf = (name) => (EXPOSURE.find(([, pattern]) => pattern.test(name)) || [null])[0];

// Each root as { dir, prefix }: `prefix` is where the web serves it, so the
// path we report is the one the dashboard can ask the site for.
// A folder inside another folder on the list is already covered: without this,
// every file under it would be reported twice.
function withoutNested(roots) {
  const seen = new Map(roots.map((root) => [root.dir, root]));
  return [...seen.values()].filter((root, _, all) =>
    !all.some((other) => other.dir !== root.dir && `${root.dir}/`.startsWith(`${other.dir}/`)));
}

function rootsOf(given, cwd) {
  const list = [];
  for (const entry of Array.isArray(given) ? given : []) {
    const dir = typeof entry === "string" ? entry : entry?.dir;
    if (!dir) continue;
    const prefix = String((typeof entry === "object" && entry.prefix) || "").replace(/^\/+|\/+$/g, "");
    list.push({ dir: path.resolve(cwd, String(dir)), prefix });
  }
  if (list.length) return withoutNested(list);
  // Not told: the conventional folders, when they're there (Express static,
  // Next.js public).
  return withoutNested(STATIC_DIRS
    .map((name) => ({ dir: path.join(cwd, name), prefix: "" }))
    .filter(({ dir }) => { try { return fs.statSync(dir).isDirectory(); } catch { return false; } }));
}

// One bounded walk per root: files that shouldn't be public, and code any
// account on the machine can write.
async function walk(roots) {
  const exposure = [];
  const examples = [];
  let writable = 0;
  let checked = 0;
  let entries = 0;
  for (const root of roots) {
    const queue = [[root.dir, 0]];
    while (queue.length) {
      const [dir, depth] = queue.shift();
      let names;
      try {
        names = await fs.promises.readdir(dir, { withFileTypes: true });
      } catch {
        continue;
      }
      for (const item of names) {
        if (++entries > MAX_ENTRIES) return { exposure, writable: checked ? writable : null, examples, truncated: true };
        if (item.isSymbolicLink()) continue;
        const full = path.join(dir, item.name);
        const relative = [root.prefix, path.relative(root.dir, full).split(path.sep).join("/")].filter(Boolean).join("/");
        if (item.isDirectory()) {
          if (/^\.(git|svn|hg|bzr)$/.test(item.name)) {
            if (exposure.length < MAX_EXPOSURE) exposure.push({ path: `${relative}/config`, kind: "vcs" });
            continue;
          }
          if (depth + 1 <= MAX_DEPTH && !SKIP_DIRS.has(item.name)) queue.push([full, depth + 1]);
          continue;
        }
        if (!item.isFile()) continue;
        const kind = kindOf(item.name);
        if (kind && exposure.length < MAX_EXPOSURE) {
          const file = { path: relative, kind };
          try {
            const info = await fs.promises.stat(full);
            file.size = info.size;
            file.mtime = new Date(info.mtimeMs).toISOString();
          } catch {
            // reported without its size
          }
          exposure.push(file);
        }
        if (checked < MAX_PERM_CHECKS && CODE_FILE.test(item.name)) {
          checked++;
          try {
            // The "others may write" bit: any account on the machine can rewrite it.
            if ((await fs.promises.stat(full)).mode & 0o002) {
              writable++;
              if (examples.length < 3) examples.push(relative);
            }
          } catch {
            // left out
          }
        }
      }
    }
  }
  return { exposure, writable: checked ? writable : null, examples, truncated: false };
}

// What the app itself can say about how it's set up.
function appChecks() {
  const checks = [];
  const add = (id, failed, value) => {
    if (failed === null) return checks.push({ id, state: "unknown" });
    checks.push({ id, state: failed ? "fail" : "pass", ...(value ? { value } : {}) });
  };
  add("app.node_env", process.env.NODE_ENV !== "production", process.env.NODE_ENV ? `NODE_ENV=${process.env.NODE_ENV}` : "NODE_ENV is not set");
  // Running the web app as root turns any hole in it into the whole machine.
  if (typeof process.getuid === "function") {
    add("server.runs_as_root", process.getuid() === 0);
  }
  return checks;
}

// Options: roots (the folders the web serves, as "public" or
// { dir, prefix: "static" }; default: ./public and ./static when they exist),
// host (the server's name; default the host name), checks (a function
// returning more checks of your own).
function createPosture(core, options = {}) {
  const log = (...args) => core.log("posture", ...args);
  const cwd = String(options.cwd || process.cwd());
  const roots = rootsOf(options.roots, cwd);
  const host = String(options.host ?? os.hostname()).replace(/[^A-Za-z0-9._-]/g, "-").slice(0, 100) || "server";
  let timer = null;
  let closed = false;

  async function report() {
    let wait = RETRY_S;
    try {
      // The set-up checks ride the software inventory switch.
      if (core.isOn("inventory")) {
        const { exposure, writable, examples, truncated } = await walk(roots);
        const checks = appChecks();
        if (writable !== null) {
          checks.push({
            id: "server.code_writable",
            state: writable ? "fail" : "pass",
            ...(writable ? { value: `${writable} files, e.g. ${examples.join(", ")}` } : {}),
          });
        }
        for (const check of typeof options.checks === "function" ? await options.checks() : []) {
          if (check?.id && ["pass", "fail", "unknown"].includes(check.state) && checks.length < MAX_CHECKS) {
            checks.push({ id: String(check.id).toLowerCase().slice(0, 60), state: check.state, ...(check.value ? { value: String(check.value).slice(0, 200) } : {}) });
          }
        }
        const res = await core.send("posture", "/events/posture", {
          auth: "bearer",
          body: {
            site_id: core.siteId,
            host,
            at: new Date().toISOString(),
            checks: checks.slice(0, MAX_CHECKS),
            facts: {
              agent: `node/${process.versions.node}`,
              ...(roots.length ? { webroot: roots[0].dir } : {}),
            },
            // Left out when there's no folder to walk: the dashboard then says
            // this wasn't checked, instead of taking an empty walk for a clean one.
            ...(roots.length ? { exposure: exposure.slice(0, MAX_EXPOSURE) } : {}),
            ...(truncated ? { truncated: true } : {}),
          },
        });
        if (res?.ok) {
          const data = await res.json().catch(() => null);
          wait = Number(data?.every) > 0 ? Math.max(RETRY_S, Number(data.every)) : EVERY_S;
        }
      }
    } catch (error) {
      log("could not send the set-up checks:", error?.message);
    }
    schedule(wait * 1000);
  }

  function schedule(ms) {
    if (closed) return;
    // A report called by hand restarts the wait rather than starting a second chain.
    clearTimeout(timer);
    timer = setTimeout(report, ms);
    timer.unref?.();
  }

  if (core.valid) schedule(FIRST_MS);

  return {
    // What would be reported now (for your own checks and tests).
    report,
    roots,
    close() {
      closed = true;
      clearTimeout(timer);
    },
  };
}

module.exports = { createPosture, rootsOf, withoutNested, walk, appChecks, kindOf };
