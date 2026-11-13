// Request rules (virtual patching; protocol in sdk/protocols/firewall.md):
// the firewall has always matched addresses, these match the request — its
// method, path, query string and user agent — so an attack is turned away
// before the vulnerable code runs. The rules come with the others, from the
// collector, and are compiled once per fetch; matching is plain string work on
// text we already have, so it costs nothing per request.
//
// Shared by the Express/node:http middleware and the Next.js edge one, so
// both decide the same way: nothing here touches the filesystem or the
// network, which is what the edge runtime allows.
"use strict";

const { IpSet } = require("./ip.js");

const MAX_RULES = 200;
// How much of each part a rule may look at. Patterns come from our rules, but
// the text comes from whoever is asking, and no regex engine we ship to can be
// timed out: a bounded slice keeps a bad pattern from being a hung request.
const MAX_TEXT = 2000;
const MAX_REGEX = 200;

const lower = (value) => String(value ?? "").slice(0, MAX_TEXT).toLowerCase();
// One pass only, as the protocol says: enough for %2e%2e, and no risk of
// decoding a visitor's own text into something that looks like an attack.
// Each run of escapes is decoded on its own, so a stray "%" elsewhere can't
// leave the whole text undecoded; a run that isn't valid UTF-8 still has its
// ASCII escapes (%2e, %2f) decoded.
function decodeRun(run) {
  try {
    return decodeURIComponent(run);
  } catch {
    return run.replace(/%([0-7][0-9a-f])/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)));
  }
}
function decodeOnce(text) {
  if (!text.includes("%") && !text.includes("+")) return text;
  return text.replace(/\+/g, " ").replace(/(?:%[0-9a-f]{2})+/gi, decodeRun);
}
const normalizePath = (path) => lower(path).replace(/\\/g, "/").replace(/\/{2,}/g, "/");

// The path as a router will see it: ";params" dropped from each segment
// (Tomcat, Jetty and others ignore them), decoded once, "\\" as "/", "." and
// ".." resolved (never above the root), lower-cased. "/x;y/../admin" is
// "/admin" here, which a rule on the raw text would miss. Takes the path
// without its query string.
function routedPath(path) {
  const text = String(path ?? "").slice(0, MAX_TEXT);
  const unparamed = text.includes(";") ? text.split("/").map((segment) => segment.split(";")[0]).join("/") : text;
  const decoded = decodeOnce(unparamed).replace(/\\/g, "/");
  const out = [];
  const segments = decoded.split("/");
  for (const segment of segments) {
    if (segment === "" || segment === ".") continue;
    if (segment === "..") out.pop();
    else out.push(segment);
  }
  const last = segments[segments.length - 1];
  const trailing = out.length && (last === "" || last === "." || last === "..");
  return `/${out.join("/")}${trailing ? "/" : ""}`.toLowerCase();
}

// A pattern can only come from us, but a careless one would be matched against
// text an attacker chooses, in this very request, and JavaScript cannot time a
// regex out. So the client checks the shape itself instead of trusting what it
// was handed: a repeated group that can match the same text more than one way
// takes exponential time on input that nearly matches. A group can do that when
// it holds a quantifier ("(a+)+", "(\w\d?)+") or an alternation ("(a|ab)*"),
// so a group followed by * + or { holds neither. Backreferences and lookbehind
// are refused for the same reason (and they aren't in every engine we ship to).
// The same check as backend/services/firewall/requestRules.js, freeRepeats
// included; sdk/protocols/request-rules-cases.json holds the shared lists.
//
// What a group may be is an allow-list, not a list of what's refused: "(",
// "(?:", "(?=" and "(?!" only. Everything else each engine adds — named
// groups and their backreferences (JavaScript's \k<name>, Python's
// (?P<name> and (?P=name)), lookbehind, PCRE's recursion ((?R), (?1)),
// \g{...}, (*VERB)s, conditionals, atomic groups and inline flags — means a
// different thing, or nothing, in another of the engines a rule goes to.
// Possessive quantifiers ("a++") likewise.
function safePattern(pattern) {
  if (typeof pattern !== "string" || !pattern || pattern.length > MAX_REGEX) return false;
  if (/\\[1-9kg]/i.test(pattern.replace(/\\\\/g, ""))) return false;
  if (!groupsAllowed(pattern)) return false;
  // Per open group: whether anything in it, nested groups too, repeats or branches.
  const open = [];
  for (let i = 0; i < pattern.length; i++) {
    const char = pattern[i];
    if (char === "\\") {
      i++;
      continue;
    }
    if (char === "[") {
      // A character class: skip it whole, quantifiers inside it are literals.
      while (i < pattern.length && pattern[i] !== "]") i += pattern[i] === "\\" ? 2 : 1;
      continue;
    }
    if (char === "(") {
      open.push(false);
      // "(?:", "(?=", "(?!": that ? names the kind of group, it repeats nothing.
      if (pattern[i + 1] === "?") i += 2;
    } else if (char === ")") {
      if (!open.length) return false;
      const ambiguous = open.pop();
      const next = pattern[i + 1];
      if (ambiguous && (next === "*" || next === "+" || next === "{")) return false;
      if (ambiguous && open.length) open[open.length - 1] = true;
    } else if (open.length && "|*+?{".includes(char)) {
      open[open.length - 1] = true;
    }
  }
  return open.length === 0 && freeRepeats(pattern) <= 1;
}

// Every group opens as "(", "(?:", "(?=" or "(?!", and no quantifier is
// possessive. Escapes and character classes are skipped, as safePattern does.
function groupsAllowed(pattern) {
  for (let i = 0; i < pattern.length; i++) {
    const char = pattern[i];
    if (char === "\\") {
      i++;
      continue;
    }
    if (char === "[") {
      while (i < pattern.length && pattern[i] !== "]") i += pattern[i] === "\\" ? 2 : 1;
      continue;
    }
    if (char === "(") {
      if (pattern[i + 1] === "*") return false;
      if (pattern[i + 1] === "?") {
        if (!":=!".includes(pattern[i + 2] || "x")) return false;
        i += 2;
      }
      continue;
    }
    if ("*+?}".includes(char) && pattern[i + 1] === "+") return false;
  }
  return true;
}

// Two repeats that can both take the same text multiply each other's work:
// ".*=.*=.*x" against a query of "=" that never ends in "x" is polynomial,
// and the 2000 characters the clients match at most is plenty for that to
// hang a request. A repeat is pinned when the character straight after it is
// one it can't match ("[^/]+/" ends at the first "/", once); any other is
// free, and a pattern may hold one free repeat.
const literalAt = (pattern, i) => {
  const char = pattern[i];
  if (char === undefined) return null;
  if (char === "\\") return pattern[i + 1] && !/[a-z0-9]/i.test(pattern[i + 1]) ? pattern[i + 1] : null;
  return ".[](){}*+?|^$".includes(char) ? null : char;
};
function freeRepeats(pattern) {
  let free = 0;
  for (let i = 0; i < pattern.length;) {
    const start = i;
    const char = pattern[i];
    if (char === "\\") i += 2;
    else if (char === "[") {
      i++;
      while (i < pattern.length && pattern[i] !== "]") i += pattern[i] === "\\" ? 2 : 1;
      i++;
    } else if (char === "(") {
      i += pattern[i + 1] === "?" ? 3 : 1;
      continue;
    } else if (char === "|" || char === "^" || char === "$") {
      i++;
      continue;
    } else i++;
    // A group's text can't be tried against one character.
    const atom = char === ")" ? null : pattern.slice(start, i);
    const quantifier = pattern[i];
    let repeats = quantifier === "*" || quantifier === "+";
    if (quantifier === "{") {
      const bounds = /^\{(\d*)(,(\d*))?\}/.exec(pattern.slice(i));
      if (!bounds) continue;
      // "{3}" is one length, not a choice; "{2,}" and "{2,9}" are choices.
      repeats = bounds[2] !== undefined && bounds[3] !== bounds[1];
      i += bounds[0].length - 1;
    } else if (quantifier !== "?" && !repeats) continue;
    i++;
    if (pattern[i] === "?") i++;
    if (!repeats) continue;
    const next = literalAt(pattern, i);
    let pinned = false;
    if (atom && next !== null) {
      try {
        pinned = !new RegExp(`^(?:${atom})$`, "i").test(next);
      } catch {
        // not an atom on its own: free
      }
    }
    if (!pinned) free++;
  }
  return free;
}

// regex: false for a page limit, which takes the plain matchers only (so the
// server agent's nginx can carry the same limit); its pattern is dropped.
function compileSection(section, { regex = true } = {}) {
  if (!section || typeof section !== "object") return null;
  const out = {};
  for (const matcher of ["exact", "prefix", "suffix", "contains"]) {
    const list = Array.isArray(section[matcher]) ? section[matcher].filter((s) => typeof s === "string").map(lower) : [];
    if (list.length) out[matcher] = list;
  }
  if (regex && safePattern(section.regex)) {
    try {
      out.regex = new RegExp(section.regex, "i");
    } catch {
      // A pattern we can't compile is dropped; the rule's other parts stay.
    }
  }
  return Object.keys(out).length ? out : null;
}

function compileRequestRules(data) {
  const given = Array.isArray(data?.rules) ? data.rules.slice(0, MAX_RULES) : [];
  const rules = [];
  for (const rule of given) {
    if (!rule || typeof rule.id !== "string" || !rule.id) continue;
    // The middleware runs before the body is parsed, so we never see it: a
    // rule that needs the body is skipped whole, not matched on the rest.
    if (rule.body) continue;
    const compiled = {
      id: rule.id,
      action: rule.action === "block" ? "block" : "monitor",
      ban: Number(rule.ban) > 0 ? Number(rule.ban) : 0,
      methods: Array.isArray(rule.methods) && rule.methods.length
        ? new Set(rule.methods.map((method) => String(method).toUpperCase())) : null,
      path: compileSection(rule.path),
      query: compileSection(rule.query),
      ua: compileSection(rule.ua),
    };
    // A rule with nothing to match would match everything.
    if (!compiled.path && !compiled.query && !compiled.ua) continue;
    rules.push(compiled);
  }
  return rules;
}

// Any one entry of the section, against the text as it came, decoded once,
// and (for the path) as the router will see it.
function sectionHits(section, raw, decoded, routed = decoded) {
  const texts = [...new Set([raw, decoded, routed])];
  for (const text of texts) {
    if (section.exact?.includes(text)) return true;
    if (section.prefix?.some((entry) => text.startsWith(entry))) return true;
    if (section.suffix?.some((entry) => text.endsWith(entry))) return true;
    if (section.contains?.some((entry) => text.includes(entry))) return true;
    if (section.regex?.test(text)) return true;
  }
  return false;
}

// Marks a request already prepared, so the matchers take it as it is.
const PREPARED = Symbol("prepared");

// The request as every rule reads it, worked out once. `path` is the full
// target as the server received it, query string and all. The firewall
// prepares a request once and hands the result to both the request rules and
// the page limits, so the path is decoded and routed once, not twice.
function prepare({ method = "", path = "", userAgent = "" } = {}) {
  const target = String(path ?? "");
  const mark = target.indexOf("?");
  const pathPart = mark === -1 ? target : target.slice(0, mark);
  const rawQuery = lower(mark === -1 ? "" : target.slice(mark + 1));
  return {
    [PREPARED]: true,
    method: String(method ?? "").toUpperCase(),
    rawPath: normalizePath(pathPart),
    decodedPath: normalizePath(decodeOnce(pathPart)),
    routed: routedPath(pathPart),
    rawQuery,
    // Lowered again after decoding: %55NION is UNION, and the patterns are lower case.
    decodedQuery: decodeOnce(rawQuery).toLowerCase(),
    ua: lower(userAgent),
  };
}

// A request as it came ({ method, path, userAgent }) or prepare()'s result.
const asPrepared = (request) => (request?.[PREPARED] ? request : prepare(request));

// Every section the rule names matches (a request rule or a page limit).
function hits(rule, request) {
  if (rule.methods && !rule.methods.has(request.method)) return false;
  if (rule.path && !sectionHits(rule.path, request.rawPath, request.decodedPath, request.routed)) return false;
  if (rule.query && !sectionHits(rule.query, request.rawQuery, request.decodedQuery)) return false;
  if (rule.ua && !sectionHits(rule.ua, request.ua, request.ua)) return false;
  return true;
}

// The first rule that matches, or null. `path` is the full target as the
// server received it, query string and all; a request already prepared
// (prepare()) is taken as it is.
function matchRequest(rules, request = {}) {
  if (!rules || !rules.length) return null;
  const prepared = asPrepared(request);
  for (const rule of rules) {
    if (hits(rule, prepared)) return rule;
  }
  return null;
}

// ---- Page limits (firewall.md, "Page limits") ------------------------------
//
// One kind of request capped on its own: a login form posted ten times a
// minute, a checkout tried five times. Matched as a request rule is, with the
// plain matchers only; counting is the firewall's (in memory here, or in the
// edge's shared counter), so this only says which limits a request counts
// toward.

const MAX_LIMITS = 50;
const LIMIT_ID = /^[a-z][a-z0-9_.-]{1,39}$/;
const inRange = (value, low, high) => Number.isInteger(value) && value >= low && value <= high;

// -> { exempt: IpSet, rules }. A limit that isn't valid is left out, the rest
// still apply; absent or null limits are none at all.
function compileLimits(data) {
  const given = Array.isArray(data?.rules) ? data.rules.slice(0, MAX_LIMITS) : [];
  const rules = [];
  for (const limit of given) {
    if (!limit || typeof limit.id !== "string" || !LIMIT_ID.test(limit.id)) continue;
    if (!inRange(limit.limit, 1, 100000) || !inRange(limit.window, 1, 3600)) continue;
    const compiled = {
      id: limit.id,
      action: limit.action === "block" ? "block" : "monitor",
      limit: limit.limit,
      window: limit.window,
      methods: Array.isArray(limit.methods) && limit.methods.length
        ? new Set(limit.methods.map((method) => String(method).toUpperCase())) : null,
      path: compileSection(limit.path, { regex: false }),
      query: compileSection(limit.query, { regex: false }),
      // A count for every page apart, by the routed path.
      each: limit.each === "path" ? "path" : null,
    };
    // Nothing left to match (no section, or a regex only) would count every request.
    if (!compiled.path && !compiled.query) continue;
    rules.push(compiled);
  }
  return { exempt: new IpSet(Array.isArray(data?.exempt) ? data.exempt : []), rules };
}

// Every limit the request counts toward, in the order sent, with the routed
// path an `each: "path"` limit counts by. Takes the request as it came or
// already prepared, as matchRequest does.
function matchLimits(limits, request = {}) {
  if (!limits?.rules?.length) return { matched: [], page: "" };
  const prepared = asPrepared(request);
  return { matched: limits.rules.filter((limit) => hits(limit, prepared)), page: prepared.routed };
}

module.exports = {
  compileRequestRules, matchRequest, prepare, safePattern, routedPath, decodeOnce, compileLimits, matchLimits, MAX_RULES, MAX_TEXT, MAX_LIMITS,
};
