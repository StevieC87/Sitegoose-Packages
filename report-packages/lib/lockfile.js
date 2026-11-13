// Reading a project's packages at build time, from whichever lock file it
// has: npm's, pnpm's, yarn's or bun's. The same rules as the Node package's
// inventory module (sdk/platform-node/lib/inventory.js): production packages
// only, releases only, and `direct` for the ones package.json asks for by
// name, on the copy the project itself resolves.
//
// This is a second implementation of that parsing rather than a shared one,
// because this package has to stay dependency-free and installable on its own
// (`npx analytics-report-packages` on a machine that has nothing else of ours
// on it). test/parity.test.js holds the two together: it runs both over the
// same lock files and fails if they ever disagree. Change one, change both.
"use strict";

const fs = require("node:fs");
const path = require("node:path");

// The lock files read, in this order when a project has more than one: the
// first found is the one used. npm-shrinkwrap.json comes first because npm
// itself installs from it over package-lock.json when both are there.
// bun.lockb, bun's binary lock file before 1.2, is not among them (see
// bunPackages).
const LOCK_FILES = ["npm-shrinkwrap.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock"];

// The packages the project asks for itself, from package.json. Production
// only, to match the lock file: devDependencies never reach a visitor.
function directNames(manifest) {
  const names = new Set();
  for (const key of ["dependencies", "optionalDependencies"]) {
    const deps = manifest?.[key];
    if (!deps || typeof deps !== "object") continue;
    for (const [name, range] of Object.entries(deps)) {
      names.add(name);
      // An alias ("my-react": "npm:react@^18") installs react, and every lock
      // file reports it as react, so that is the name to mark.
      const real = aliasOf(range);
      if (real) names.add(real.name);
    }
  }
  return names;
}

// A lock file -> [{ ecosystem, name, version, direct? }]: lockfile v2/v3
// "packages", else v1 "dependencies". Dev packages, links and versions that
// aren't releases (file:, git, tarballs) are left out. `direct` goes only on
// the copy at the top of node_modules: a copy nested under another package is
// that package's own, and installing the name doesn't move it.
function lockPackages(lock, direct = new Set()) {
  const { add, rows } = rowSet(direct);
  if (lock?.packages && typeof lock.packages === "object") {
    for (const [key, entry] of Object.entries(lock.packages)) {
      const at = key.lastIndexOf("node_modules/");
      // "" is the project itself; paths without node_modules/ are workspaces.
      if (at === -1 || !entry || entry.dev || entry.link || !npmRegistry(entry.resolved)) continue;
      add(entry.name || key.slice(at + "node_modules/".length), entry.version, at === 0);
    }
  } else if (lock?.dependencies && typeof lock.dependencies === "object") {
    const walk = (deps, top) => {
      for (const [name, entry] of Object.entries(deps)) {
        if (!entry || entry.dev) continue;
        if (npmRegistry(entry.resolved)) {
          // Lockfile 1 writes an alias's version as "npm:react@18.2.0".
          const real = aliasOf(entry.version);
          add(real ? real.name : name, real ? real.range : entry.version, top);
        }
        if (entry.dependencies && typeof entry.dependencies === "object") walk(entry.dependencies, false);
      }
    };
    walk(lock.dependencies, true);
  }
  return rows();
}

// pnpm, yarn and bun. None of these files is JSON, and this package can't
// depend on a YAML parser, so each is read by a small parser of its own that
// knows only what that tool writes. The rules they come down to are npm's:
// production packages only, versions that are releases, and `direct` on the
// copy the project itself resolves.

const PROD = ["dependencies", "optionalDependencies"];
const isMap = (value) => Boolean(value) && typeof value === "object" && !Array.isArray(value);
const entriesOf = (value) => (isMap(value) ? Object.entries(value) : []);
// A real package can be called "constructor", so lookups by package name
// mustn't reach the object's prototype.
const own = (map, key) => (isMap(map) && Object.hasOwn(map, key) ? map[key] : undefined);
// Editors on Windows can save a file with a byte order mark, which JSON.parse
// rejects and which would read as indentation in YAML.
const stripBom = (text) => (String(text).charCodeAt(0) === 0xfeff ? String(text).slice(1) : String(text));

// "npm:real@1.2.3" -> { name: "real", range: "1.2.3" }, else null. "npm:^1"
// on its own is yarn 2+'s protocol for a plain range, not an alias.
function aliasOf(range) {
  if (typeof range !== "string" || !range.startsWith("npm:")) return null;
  const inner = range.slice(4);
  return inner.indexOf("@", 1) > 0 ? descriptorParts(inner) : null;
}

// Where npm fetched a package from. A lock entry's `version` is the
// package's own even when it came from git, a tarball URL or a folder, so
// `resolved` is what says whether it is a published release: a registry
// tarball has the "/-/name-1.2.3.tgz" shape, GitHub Packages' "/download/"
// links are the one registry without it, and no `resolved` at all is a
// release too (npm leaves it out of bundled and some older entries).
function npmRegistry(resolved) {
  if (typeof resolved !== "string" || !resolved) return true;
  if (!/^https?:\/\//i.test(resolved)) return false;
  const url = resolved.replace(/[?#].*$/, "");
  return /\/-\/[^/]+\.tgz$/i.test(url) || /^https:\/\/npm\.pkg\.github\.com\/download\//i.test(url);
}

// The rows every lock file comes down to: one per name@version, and when the
// same release turns up both where the project resolves it and deeper down,
// the row keeps `direct`.
function rowSet(direct) {
  const found = new Map();
  const add = (name, version, top) => {
    if (typeof name !== "string" || !name || typeof version !== "string") return;
    const clean = version.replace(/^v/, "");
    // file:, link:, workspace:, git and tarball versions aren't releases.
    if (!/^\d/.test(clean)) return;
    const row = { ecosystem: "npm", name, version: clean };
    if (top && direct.has(name)) row.direct = true;
    const key = `${name}@${clean}`;
    if (!found.get(key)?.direct) found.set(key, row);
  };
  return { add, rows: () => [...found.values()] };
}

// "name@range" -> its two halves; the first character is skipped because a
// scoped name starts with "@".
function descriptorParts(descriptor) {
  const text = String(descriptor);
  const at = text.indexOf("@", 1);
  return at === -1 ? { name: text, range: "" } : { name: text.slice(0, at), range: text.slice(at + 1) };
}

// A quoted string starting at s[start]: 'single', where '' is a quote, or
// "double" with JSON's escapes. Returns [text, the index after it].
function quoted(s, start, where) {
  if (s[start] === "'") {
    let out = "";
    for (let i = start + 1; ;) {
      const close = s.indexOf("'", i);
      if (close === -1) throw new Error(`${where}: a quote that isn't closed`);
      out += s.slice(i, close);
      if (s[close + 1] !== "'") return [out, close + 1];
      out += "'";
      i = close + 2;
    }
  }
  for (let i = start + 1; i < s.length; i++) {
    if (s[i] === "\\") i++;
    else if (s[i] === '"') {
      const raw = s.slice(start, i + 1);
      try {
        return [JSON.parse(raw), i + 1];
      } catch {
        return [raw.slice(1, -1), i + 1];
      }
    }
  }
  throw new Error(`${where}: a quote that isn't closed`);
}

// Inline {…} and […]. The only ones that matter here are empty ({} is a
// package with no dependencies); the rest are integrity hashes, engines and
// platforms, which nothing reads, so one this doesn't follow stays as text
// rather than failing the whole file.
function flow(s) {
  let i = 0;
  const space = () => { while (s[i] === " ") i++; };
  const item = (stops) => {
    space();
    if (s[i] === "{" || s[i] === "[") return collection();
    if (s[i] === "'" || s[i] === '"') {
      const [text, end] = quoted(s, i, "an inline value");
      i = end;
      return text;
    }
    const start = i;
    while (i < s.length && !stops.includes(s[i])) i++;
    return s.slice(start, i).trim();
  };
  const collection = () => {
    const open = s[i++];
    const close = open === "{" ? "}" : "]";
    const out = open === "{" ? Object.create(null) : [];
    space();
    while (s[i] !== close) {
      if (i >= s.length) throw new Error("not closed");
      if (open === "{") {
        const key = item([":", ",", "}"]);
        space();
        let value = null;
        if (s[i] === ":") {
          i++;
          value = item([",", "}"]);
        }
        out[key] = value;
      } else {
        out.push(item([",", "]"]));
      }
      space();
      if (s[i] === ",") i++;
      else if (s[i] !== close) throw new Error("expected a comma");
      space();
    }
    i++;
    return out;
  };
  try {
    const out = collection();
    space();
    return i === s.length ? out : s;
  } catch {
    return s;
  }
}

// The part of YAML that pnpm-lock.yaml and yarn 2+'s yarn.lock are written
// in: maps nested by indentation, quoted or plain keys and values, inline
// {…} and […], and "- item" lists. Both are generated files that use nothing
// else, so this is not a YAML parser; a line outside that shape (a tab in the
// indentation, a key with no colon) is an error rather than a guess. Numbers
// stay strings, which keeps "5.10" and "1.0" what they say.
function parseYaml(text) {
  const lines = [];
  String(text).split(/\r?\n/).forEach((raw, index) => {
    const body = raw.trimStart();
    if (!body || body.startsWith("#")) return;
    const indent = raw.length - body.length;
    if (raw.slice(0, indent).includes("\t")) throw new Error(`line ${index + 1}: a tab in the indentation`);
    lines.push({ indent, text: body.trimEnd(), where: `line ${index + 1}` });
  });
  let at = 0;
  const isItem = (s) => s === "-" || s.startsWith("- ");

  const scalar = (s, where) => {
    if (s[0] === "'" || s[0] === '"') {
      const [text, end] = quoted(s, 0, where);
      const after = s.slice(end).trim();
      if (after && !after.startsWith("#")) throw new Error(`${where}: text after a quoted value`);
      return text;
    }
    if (s[0] === "{" || s[0] === "[") return flow(s);
    if (s === "true") return true;
    if (s === "false") return false;
    if (s === "null" || s === "~") return null;
    return s;
  };

  const splitKey = ({ text: s, where }) => {
    let key;
    let end;
    if (s[0] === "'" || s[0] === '"') {
      [key, end] = quoted(s, 0, where);
      if (s[end] !== ":") throw new Error(`${where}: expected a colon after the key`);
      end++;
    } else {
      const colon = s.search(/:( |$)/);
      if (colon === -1) throw new Error(`${where}: expected "key: value"`);
      key = s.slice(0, colon);
      end = colon + 1;
    }
    if (end < s.length && s[end] !== " ") throw new Error(`${where}: expected a space after the colon`);
    return { key, rest: s.slice(end).trim() };
  };

  const value = (rest, indent, where) => {
    if (rest === "") {
      if (at < lines.length && lines[at].indent > indent) return block(lines[at].indent);
      if (at < lines.length && lines[at].indent === indent && isItem(lines[at].text)) return list(indent);
      return null;
    }
    // A block scalar ("|" or ">"): the lines under it are text, not keys.
    if (/^[|>][-+1-9]*$/.test(rest)) {
      const parts = [];
      while (at < lines.length && lines[at].indent > indent) parts.push(lines[at++].text);
      return parts.join("\n");
    }
    return scalar(rest, where);
  };

  const strayIndent = (indent) => {
    if (at < lines.length && lines[at].indent > indent) throw new Error(`${lines[at].where}: unexpected indentation`);
  };

  // Whether text is the start of a map entry ("key: …") or a list item,
  // rather than a value on its own ("{}", "'text'").
  const startsEntry = (s) => {
    if (isItem(s)) return true;
    if (s[0] === "{" || s[0] === "[") return false;
    if (s[0] === "'" || s[0] === '"') {
      try {
        return s[quoted(s, 0, "")[1]] === ":";
      } catch {
        return false;
      }
    }
    return /:( |$)/.test(s);
  };

  // js-yaml, which pnpm writes with, puts a key over 1024 characters (a long
  // peer suffix in a big monorepo) on a "? " line of its own, and the value
  // on a ": " line after it, compactly: a map's first key on that line and
  // the rest two deeper.
  const explicit = (line, indent) => {
    const key = scalar(line.text.slice(1).trim(), line.where);
    const next = lines[at];
    if (!next || next.indent !== indent || !(next.text === ":" || next.text.startsWith(": "))) {
      throw new Error(`${line.where}: a "? " key without its ": " value`);
    }
    const rest = next.text.slice(1).trim();
    if (rest && startsEntry(rest)) {
      lines[at] = { indent: indent + 2, text: rest, where: next.where };
      return [key, block(indent + 2)];
    }
    at++;
    return [key, value(rest, indent, next.where)];
  };

  function map(indent) {
    const out = Object.create(null);
    while (at < lines.length && lines[at].indent === indent && !isItem(lines[at].text)) {
      const line = lines[at++];
      if (line.text === "?" || line.text.startsWith("? ")) {
        const [key, item] = explicit(line, indent);
        out[String(key)] = item;
        continue;
      }
      const { key, rest } = splitKey(line);
      out[key] = value(rest, indent, line.where);
    }
    strayIndent(indent);
    return out;
  }

  function list(indent) {
    const out = [];
    while (at < lines.length && lines[at].indent === indent && isItem(lines[at].text)) {
      const line = lines[at++];
      out.push(value(line.text.slice(1).trim(), indent, line.where));
    }
    strayIndent(indent);
    return out;
  }

  function block(indent) {
    return isItem(lines[at].text) ? list(indent) : map(indent);
  }

  if (!lines.length) return Object.create(null);
  const out = block(lines[0].indent);
  if (at < lines.length) throw new Error(`${lines[at].where}: less indented than the start of the file`);
  return out;
}

// pnpm writes the peers a package was installed against onto its version:
// "15.1.0(react@19.0.0)" since lockfile 6, "15.1.0_react@19.0.0" before.
// Neither is part of the release.
const withoutPeers = (version) => (typeof version === "string" ? version.replace(/[(_].*$/, "") : version);

// A pnpm package key -> name and version: "/name/1.2.3_peer" (lockfile 5),
// "/name@1.2.3(peer)" (6), "name@1.2.3(peer)" (9).
function pnpmKey(key, major) {
  const id = key.replace(/^\//, "");
  if (major < 6) {
    const parts = id.split("/");
    const width = parts[0].startsWith("@") ? 2 : 1;
    return { name: parts.slice(0, width).join("/"), version: withoutPeers(parts.slice(width).join("/")) };
  }
  const { name, range } = descriptorParts(id);
  return { name, version: withoutPeers(range) };
}

// pnpm-lock.yaml: lockfile 5.x (pnpm 7 and before), 6.0 (pnpm 8) and 9.0
// (pnpm 9 and 10).
function pnpmPackages(text, manifest) {
  // pnpm 10 can write the lock file of its own configuration dependencies
  // first, as a YAML document of its own. The project's is the last one.
  const documents = String(text).split(/^---[ \t]*$/m).filter((part) => part.trim());
  const lock = parseYaml(documents[documents.length - 1] || "");
  if (!isMap(lock) || lock.lockfileVersion == null) throw new Error("no lockfileVersion, so this isn't a pnpm lock file");
  const major = parseInt(String(lock.lockfileVersion), 10);
  const rows = rowSet(directNames(manifest));
  // A workspace lists each folder under importers, the project itself as
  // "."; a single project before lockfile 9 keeps its dependencies at the top.
  const importers = isMap(lock.importers) ? lock.importers : { ".": lock };

  // What a dependency points at: a version ("1.2.3(peer@1)") of the package
  // with the dependency's own name, or for an alias the real package
  // ("real@1.2.3" in 9, "/real@1.2.3" in 6, "/real/1.2.3" in 5). link: is a
  // workspace folder, read as an importer of its own.
  const target = (name, entry) => {
    const ref = isMap(entry) ? entry.version : entry;
    if (typeof ref !== "string" || !ref || ref.startsWith("link:")) return null;
    if (major >= 9) {
      const alias = !/^\d[^@(]*(\(|$)/.test(ref) && /^(@[^/@:]+\/)?[^/@:]+@/.test(ref);
      const key = alias ? ref : `${name}@${ref}`;
      return { key, ...pnpmKey(key, major) };
    }
    if (ref.startsWith("/")) return { key: ref, ...pnpmKey(ref, major) };
    return { key: null, name, version: withoutPeers(ref) };
  };

  // What the project itself resolves, for `direct`: the root importer's
  // production dependencies.
  const tops = new Set();
  const root = own(importers, ".");
  for (const field of PROD) {
    for (const [name, entry] of entriesOf(root?.[field])) {
      const found = target(name, entry);
      if (found) tops.add(`${found.name}@${found.version}`);
    }
  }
  const add = ({ name, version }) => rows.add(name, version, tops.has(`${name}@${version}`));

  if (major >= 9) {
    // Lockfile 9 has no dev flag, so the production packages are the ones
    // reachable from an importer's dependencies or optionalDependencies,
    // through each package's snapshot.
    const seen = new Set();
    const queue = [];
    const visit = (name, entry) => {
      const found = target(name, entry);
      if (found && !seen.has(found.key)) {
        seen.add(found.key);
        queue.push(found);
      }
    };
    for (const importer of Object.values(importers)) {
      for (const field of PROD) for (const [name, entry] of entriesOf(importer?.[field])) visit(name, entry);
    }
    while (queue.length) {
      const found = queue.pop();
      add(found);
      const snapshot = own(lock.snapshots, found.key);
      // A snapshot lists the peers it was resolved against among its
      // dependencies. A required peer is needed at run time, but an optional
      // one is only there because something else installed it (typescript
      // for a package that merely supports it, put there by devDependencies),
      // so it doesn't make that package production.
      const meta = own(own(lock.packages, found.key.replace(/\(.*$/, "")), "peerDependenciesMeta");
      for (const field of PROD) {
        for (const [name, entry] of entriesOf(snapshot?.[field])) if (own(meta, name)?.optional !== true) visit(name, entry);
      }
    }
  } else {
    // Before 9, a package only devDependencies reach says dev: true (false,
    // or no flag when both kinds reach it). Keys without the leading "/" are
    // git, tarball and local packages, which aren't releases.
    for (const [key, entry] of entriesOf(lock.packages)) {
      if (!key.startsWith("/") || entry?.dev === true) continue;
      add(pnpmKey(key, major));
    }
  }
  return rows.rows();
}

// Whether a yarn 1 range names a published release. Semver ranges and tags
// never hold "/" or ":", while file:, link:, git, tarball URLs and GitHub's
// "user/repo" all do; "npm:" is an alias, judged by the range inside it.
function yarnRelease(range) {
  const inner = range.startsWith("npm:") ? range.slice(4) : range;
  const aliased = /^(@[^/@]+\/)?[^/@]+@/.test(inner) ? descriptorParts(inner).range : inner;
  return !/[/:]/.test(aliased);
}

// yarn 1's own format: unindented headings listing every "name@range" that
// resolved to the entry, then `key "value"` lines, and dependencies under
// a `dependencies:` line.
function classicEntries(text) {
  const list = [];
  let entry = null;
  let section = null;
  // A "quoted" token or a run of characters up to one of `stops`.
  const token = (s, i, stops, where) => {
    if (s[i] === '"') return quoted(s, i, where);
    let end = i;
    while (end < s.length && !stops.includes(s[end])) end++;
    return [s.slice(i, end), end];
  };
  String(text).split(/\r?\n/).forEach((raw, index) => {
    const body = raw.trim();
    if (!body || body.startsWith("#")) return;
    const indent = raw.length - raw.trimStart().length;
    const where = `line ${index + 1}`;
    if (indent === 0) {
      if (!body.endsWith(":")) throw new Error(`${where}: expected a package heading ending in a colon`);
      const heading = body.slice(0, -1);
      const descriptors = [];
      for (let i = 0; i < heading.length;) {
        while (heading[i] === " ") i++;
        const [descriptor, end] = token(heading, i, [","], where);
        if (descriptor.trim()) descriptors.push(descriptor.trim());
        i = end;
        while (heading[i] === " ") i++;
        if (i < heading.length && heading[i] !== ",") throw new Error(`${where}: expected a comma between ranges`);
        i++;
      }
      entry = { descriptors, fields: Object.create(null), sections: Object.create(null) };
      section = null;
      list.push(entry);
      return;
    }
    if (!entry) throw new Error(`${where}: indented text before the first package`);
    const [key, end] = token(body, 0, [" "], where);
    const rest = body.slice(end).trim();
    if (indent <= 2) {
      if (!rest && key.endsWith(":")) {
        section = key.slice(0, -1);
        entry.sections[section] = Object.create(null);
      } else {
        entry.fields[key] = rest[0] === '"' ? quoted(rest, 0, where)[0] : rest;
        section = null;
      }
    } else {
      if (!section) throw new Error(`${where}: an indented line outside a section`);
      entry.sections[section][key] = rest[0] === '"' ? quoted(rest, 0, where)[0] : rest;
    }
  });
  return list.map(({ descriptors, fields, sections }) => {
    const first = descriptorParts(descriptors[0] || "");
    const aliased = first.range.startsWith("npm:") && /^(@[^/@]+\/)?[^/@]+@/.test(first.range.slice(4));
    return {
      descriptors,
      name: aliased ? descriptorParts(first.range.slice(4)).name : first.name,
      version: fields.version,
      release: yarnRelease(first.range),
      soft: false,
      dependencies: sections.dependencies,
      optionalDependencies: sections.optionalDependencies,
    };
  });
}

// yarn 2 and later: YAML, one key per entry listing its descriptors, each
// with the resolution yarn settled on.
function berryEntries(text) {
  const list = [];
  for (const [key, value] of entriesOf(parseYaml(text))) {
    if (key === "__metadata" || !isMap(value)) continue;
    const descriptors = key.split(",").map((part) => part.trim()).filter(Boolean);
    const resolution = typeof value.resolution === "string" ? value.resolution : "";
    const from = descriptorParts(resolution || descriptors[0] || "");
    list.push({
      descriptors,
      resolution,
      name: from.name,
      version: value.version,
      // The resolution says how the package was fetched. Only npm: is a
      // published release, and patch: of one, which is how yarn ships its
      // built-in fixes to a few packages (typescript, fsevents, resolve).
      release: from.range.startsWith("npm:") || (from.range.startsWith("patch:") && from.range.includes("@npm%3A")),
      // A soft link is a folder on disk (a workspace, portal: or link:), not
      // an installed package; a workspace's dependencies here also mix in its
      // devDependencies, so they aren't followed.
      soft: value.linkType === "soft",
      dependencies: value.dependencies,
      optionalDependencies: value.optionalDependencies,
    });
  }
  return list;
}

// yarn.lock, both yarn 1's format and the YAML yarn 2 and later write (any
// __metadata version). Neither says which packages are only for
// development, so the production ones are found by walking from
// package.json's dependencies and optionalDependencies through each entry's
// own: the project's, and each workspace's (`workspaces` maps a folder, as
// workspacePatterns gives it, to that folder's package.json, read by the
// caller). Without any package.json there is nowhere to start, and nothing
// is reported rather than counting development tools as production.
function yarnPackages(text, manifest, workspaces = {}) {
  const berry = /^__metadata:/m.test(String(text));
  const list = berry ? berryEntries(text) : classicEntries(text);
  const byDescriptor = new Map();
  for (const entry of list) {
    for (const descriptor of entry.descriptors) {
      byDescriptor.set(descriptor, entry);
      // yarn 2+ ties a file: dependency to the workspace that asked for it
      // ("::locator=…"); the dependency itself is written without that.
      const bare = descriptor.split("::")[0];
      if (!byDescriptor.has(bare)) byDescriptor.set(bare, entry);
    }
  }
  // yarn 2+ adds the protocol to every key ("react@npm:^19.0.0") even where
  // package.json, or an older yarn's dependency lines, leave it out.
  const find = (name, range) => (typeof range === "string"
    ? byDescriptor.get(`${name}@${range}`) || byDescriptor.get(`${name}@npm:${range}`)
    : undefined);

  const rows = rowSet(directNames(manifest));
  // yarn 2+ also records an entry for each workspace, the project's own as
  // ".", with each dependency in the form yarn settled on: the surest key for
  // what that workspace resolves.
  const recorded = new Map();
  for (const entry of berry ? list : []) {
    const found = /@workspace:(.+)$/.exec(entry.resolution);
    if (found) recorded.set(found[1], entry);
  }
  const tops = new Set();
  const seen = new Set();
  const queue = [];
  const visit = (entry) => {
    if (entry && !seen.has(entry)) {
      seen.add(entry);
      queue.push(entry);
    }
  };
  // `direct` is the project's own choice, so only its package.json's
  // dependencies count as tops; a workspace's start a walk and no more.
  const seed = (declared, entryOf, top) => {
    for (const field of PROD) {
      for (const [name, range] of entriesOf(declared?.[field])) {
        const entry = find(name, own(entryOf?.dependencies, name)) || find(name, range);
        if (entry && top) tops.add(entry);
        visit(entry);
      }
    }
  };
  seed(manifest, recorded.get("."), true);
  for (const [where, declared] of entriesOf(workspaces)) if (where !== ".") seed(declared, recorded.get(where), false);
  while (queue.length) {
    const entry = queue.pop();
    if (entry.soft) continue;
    if (entry.release) rows.add(entry.name, entry.version, tops.has(entry));
    for (const field of PROD) for (const [name, range] of entriesOf(entry[field])) visit(find(name, range));
  }
  return rows.rows();
}

// bun.lock is JSON except that bun leaves trailing commas in, and JSONC
// allows comments; both are taken out (outside strings) before parsing.
function withoutJsoncExtras(text) {
  const s = String(text);
  const out = [];
  let from = 0;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === '"') {
      for (i++; i < s.length && s[i] !== '"'; i++) if (s[i] === "\\") i++;
    } else if (c === "/" && (s[i + 1] === "/" || s[i + 1] === "*")) {
      out.push(s.slice(from, i));
      const end = s[i + 1] === "/" ? s.indexOf("\n", i) : s.indexOf("*/", i + 2) + 1;
      i = end <= 0 ? s.length : end;
      from = s[i] === "\n" ? i : i + 1;
    } else if (c === ",") {
      let next = i + 1;
      while (next < s.length && /\s/.test(s[next])) next++;
      if (s[next] === "}" || s[next] === "]") {
        out.push(s.slice(from, i));
        from = i + 1;
      }
    }
  }
  out.push(s.slice(from));
  return out.join("");
}

// bun.lock, the text lock file bun 1.2 and later write. bun.lockb, the
// binary one earlier versions wrote, is not read: its layout is bun's
// internal one and changes between releases. `bun install
// --save-text-lockfile` writes bun.lock beside it.
function bunPackages(text, manifest) {
  const lock = JSON.parse(withoutJsoncExtras(text));
  if (!isMap(lock?.packages)) throw new Error("no packages, so this isn't a bun lock file");
  const { packages } = lock;
  const rows = rowSet(directNames(manifest));
  // Keys are install paths, like npm's node_modules ("next/@swc/helpers" is
  // a copy under next), split into package names.
  const pathOf = (key) => {
    const parts = key.split("/");
    const out = [];
    for (let i = 0; i < parts.length; i++) out.push(parts[i].startsWith("@") && i + 1 < parts.length ? `${parts[i]}/${parts[++i]}` : parts[i]);
    return out;
  };
  // Where a dependency of the package at `from` was installed: the same
  // search Node makes, from that package's own folder up to the top.
  const resolve = (from, name) => {
    for (let n = from.length; n >= 0; n--) {
      const key = [...from.slice(0, n), name].join("/");
      if (Object.hasOwn(packages, key)) return key;
    }
    return null;
  };
  // Each entry is an array: "name@version" first, then for a package from
  // the registry its registry, its dependencies object and its hash. The
  // other kinds (git, file:, workspace:) put that object elsewhere or leave
  // it out, so it is found by type.
  const ident = (key) => {
    const entry = packages[key];
    return Array.isArray(entry) && typeof entry[0] === "string" ? descriptorParts(entry[0]) : { name: null, range: null };
  };
  const info = (key) => (Array.isArray(packages[key]) ? packages[key].find(isMap) : null);

  const tops = new Set();
  const seen = new Set();
  const queue = [];
  const visit = (from, name) => {
    const key = resolve(from, name);
    if (key && !seen.has(key)) {
      seen.add(key);
      queue.push(key);
    }
    return key;
  };
  // workspaces[""] is the project itself; other workspaces' own copies sit
  // under their package name.
  for (const [where, workspace] of entriesOf(lock.workspaces)) {
    const from = where === "" || typeof workspace?.name !== "string" ? [] : [workspace.name];
    for (const field of PROD) {
      for (const [name] of entriesOf(workspace?.[field])) {
        const key = visit(from, name);
        if (where === "" && key) tops.add(key);
      }
    }
  }
  while (queue.length) {
    const key = queue.pop();
    const { name, range } = ident(key);
    rows.add(name, range, tops.has(key));
    const meta = info(key);
    for (const field of PROD) for (const [name] of entriesOf(meta?.[field])) visit(pathOf(key), name);
    // bun installs peers too, so a required one is followed like a
    // dependency; an optional one (optionalPeers) is only there because
    // something else installed it, as with pnpm.
    const optional = new Set(Array.isArray(meta?.optionalPeers) ? meta.optionalPeers : []);
    for (const [name] of entriesOf(meta?.peerDependencies)) if (!optional.has(name)) visit(pathOf(key), name);
  }
  return rows.rows();
}

// The workspace folders a yarn project has, for the caller to read each
// one's package.json before parseLock, which reads no files itself. yarn 2+
// lists them in the lock file; yarn 1 doesn't, so they are package.json's
// `workspaces` patterns (a list, or { packages: [...] }). The other lock
// files list every workspace's dependencies themselves.
function workspacePatterns(file, text, manifest) {
  if (path.basename(String(file)) !== "yarn.lock") return [];
  const body = stripBom(text);
  if (/^__metadata:/m.test(body)) {
    const found = new Set();
    for (const match of body.matchAll(/^\s+resolution: "?(?:@[^@\s"]+\/)?[^@\s"]+@workspace:([^"\r\n]+)"?\s*$/gm)) {
      if (match[1] !== ".") found.add(match[1]);
    }
    return [...found];
  }
  const declared = Array.isArray(manifest?.workspaces) ? manifest.workspaces : manifest?.workspaces?.packages;
  return Array.isArray(declared) ? declared.filter((pattern) => typeof pattern === "string") : [];
}

// A workspace pattern -> the folder it names, whether it means the folders
// directly inside it, and whether it takes that folder out ("!apps/old").
// Only the shapes nearly every project uses are followed, "apps/web",
// "apps/*" and "!apps/old"; anything else ("packages/**") is left out rather
// than pulling in a glob library.
function workspaceGlob(pattern) {
  const negated = String(pattern).startsWith("!");
  const clean = String(pattern).slice(negated ? 1 : 0).replace(/^\.\//, "").replace(/\/+$/, "");
  const glob = /[*?[\]{}!]/;
  if (!clean) return null;
  if (negated) return glob.test(clean) ? null : { folder: clean, children: false, exclude: true };
  if (clean === "*") return { folder: "", children: true, exclude: false };
  if (clean.endsWith("/*") && !glob.test(clean.slice(0, -2))) return { folder: clean.slice(0, -2), children: true, exclude: false };
  return glob.test(clean) ? null : { folder: clean, children: false, exclude: false };
}

// One lock file's text -> rows, by which lock file it is. `workspaces` is
// only for yarn.lock (see workspacePatterns).
function parseLock(file, text, manifest, workspaces = {}) {
  const body = stripBom(text);
  switch (path.basename(String(file))) {
    case "pnpm-lock.yaml":
      return pnpmPackages(body, manifest);
    case "yarn.lock":
      return yarnPackages(body, manifest, workspaces);
    case "bun.lock":
      return bunPackages(body, manifest);
    default:
      return lockPackages(JSON.parse(body), directNames(manifest));
  }
}

// A package.json, or null when it is missing or can't be read. Unreadable is
// a warning, not a failure: the report still goes up, only with less in it,
// which `consequence` says.
function readManifest(file, warnings, consequence) {
  try {
    return JSON.parse(stripBom(fs.readFileSync(file, "utf8")));
  } catch (error) {
    if (error.code !== "ENOENT") warnings.push(`couldn't read ${file} (${error.message}), so ${consequence}.`);
    return null;
  }
}

// The package.json of each workspace folder the patterns name, by folder.
function readWorkspaces(dir, patterns, warnings) {
  const found = Object.create(null);
  const globs = patterns.map(workspaceGlob).filter(Boolean);
  const excluded = new Set(globs.filter((glob) => glob.exclude).map((glob) => glob.folder));
  for (const glob of globs) {
    if (glob.exclude) continue;
    let folders = [glob.folder];
    if (glob.children) {
      try {
        folders = fs.readdirSync(path.join(dir, glob.folder), { withFileTypes: true })
          .filter((item) => item.isDirectory() && item.name !== "node_modules" && !item.name.startsWith("."))
          .map((item) => (glob.folder ? `${glob.folder}/${item.name}` : item.name));
      } catch {
        folders = [];
      }
    }
    for (const folder of folders) {
      if (Object.hasOwn(found, folder) || excluded.has(folder)) continue;
      const manifest = readManifest(path.join(dir, folder, "package.json"), warnings, `the packages only ${folder} uses are left out`);
      if (manifest) found[folder] = manifest;
    }
  }
  return found;
}

// What `dir` holds: its packages, and which files they came from. Nothing
// here throws, the way the Node package's daily read doesn't: a package.json
// that is missing or broken leaves the packages unmarked (and a yarn.lock,
// which can't tell production from development without one, empty), and a
// lock file that won't parse is passed over for the next, so the build is
// only given up on when none can be read. `failed` says which didn't and
// why, `warnings` anything else worth a line, and `binaryLock` is a
// bun.lockb found with nothing readable beside it.
function collect(dir) {
  const warnings = [];
  const failed = [];
  const manifest = readManifest(path.join(dir, "package.json"), warnings, "none of the packages are marked as yours");
  for (const name of LOCK_FILES) {
    const file = path.join(dir, name);
    try {
      const text = fs.readFileSync(file, "utf8");
      const workspaces = readWorkspaces(dir, workspacePatterns(name, text, manifest), warnings);
      const packages = parseLock(name, text, manifest, workspaces);
      return { packages, lockFile: file, manifest: Boolean(manifest), warnings, failed, binaryLock: null };
    } catch (error) {
      if (error.code !== "ENOENT") failed.push({ file, message: error.message });
    }
  }
  const binary = path.join(dir, "bun.lockb");
  return {
    packages: [], lockFile: null, manifest: Boolean(manifest), warnings, failed,
    binaryLock: fs.existsSync(binary) ? binary : null,
  };
}

module.exports = {
  collect, parseLock, workspacePatterns, workspaceGlob, lockPackages, pnpmPackages, yarnPackages, bunPackages,
  directNames, LOCK_FILES,
};
