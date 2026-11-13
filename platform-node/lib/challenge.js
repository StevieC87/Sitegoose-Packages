// The browser check (rule `challenge`, sdk/protocols/firewall.md under "Flood
// protection"): a GET or HEAD that asks for a page, from an address with no
// valid pass, gets a small page instead of the site. Its script sets the pass
// cookie and reloads, which a script that doesn't run JavaScript never does.
// It stops cheap floods, not a real browser.
//
// The pass is <day>.<first 32 hex digits of HMAC-SHA256(key, "<day>|<who>")>,
// key = HMAC-SHA256 of "sg-challenge-v1" keyed with the site secret, so any of
// the site's servers accepts a pass another one handed out. It counts for its
// own day and the next. sdk/protocols/challenge-cases.json holds the cases
// every client runs; backend/scripts/challenge-cases.mjs is the reference.
//
// Framework-neutral and with no Node built-ins required up front, so the
// Node firewall (firewall.js, a sync HMAC from node:crypto) and the edge
// (next.js and hono.js, WebCrypto) share it.
"use strict";

const { parseIp, IpSet } = require("./ip.js");
const { builtin } = require("./core.js");

const COOKIE = "__sg_pass";
const LABEL = "sg-challenge-v1";
const MAX_AGE = 86400;
const DAY_MS = 86400 * 1000;
const PASS = /^(\d{1,10})\.([0-9a-f]{32})$/;
// Cookie values looked at per request: a browser can send a few, from different paths.
const MAX_VALUES = 4;
const MAX_SKIP = 200;

// The rules' `challenge`: null (no check), or { skip, exempt }.
function compileChallenge(data) {
  if (!data || typeof data !== "object" || Array.isArray(data)) return null;
  const skip = (Array.isArray(data.skip) ? data.skip : [])
    .filter((entry) => typeof entry === "string" && entry)
    .slice(0, MAX_SKIP)
    .map((entry) => entry.toLowerCase());
  return { skip, exempt: new IpSet(Array.isArray(data.exempt) ? data.exempt : []) };
}

// What a pass is bound to: the IPv4 address (an IPv4-mapped IPv6 address as
// IPv4), or an IPv6 address's /64 as four groups of four lower-case hex
// digits. "" for anything that isn't an address. Takes the text or parseIp's
// result.
function whoOf(ip) {
  const address = ip && typeof ip === "object" ? ip : parseIp(ip);
  if (!address) return "";
  if (address.family === 4) {
    const n = address.n;
    return [Math.floor(n / 16777216), Math.floor(n / 65536) % 256, Math.floor(n / 256) % 256, n % 256].join(".");
  }
  const top = address.n >> 64n;
  const groups = [];
  for (let shift = 48n; shift >= 0n; shift -= 16n) groups.push(((top >> shift) & 0xffffn).toString(16).padStart(4, "0"));
  return groups.join(":");
}

// Whole days since 1970-01-01 UTC.
const dayOf = (nowMs = Date.now()) => Math.floor(nowMs / DAY_MS);

// sign(message) -> the HMAC's hex digest: a string from node:crypto (sync, the
// Node firewall) or a Promise from WebCrypto (the edge). web: true goes
// straight to WebCrypto. Null when the runtime has neither: no check then.
function createSigner(secret, { web = false } = {}) {
  const text = String(secret || "");
  if (!web) {
    const crypto = builtin("crypto");
    if (crypto?.createHmac) {
      const key = crypto.createHmac("sha256", text).update(LABEL).digest();
      return (message) => crypto.createHmac("sha256", key).update(message).digest("hex");
    }
  }
  // Node 18 has WebCrypto only on node:crypto; the edge always has it global.
  const subtle = globalThis.crypto?.subtle || builtin("crypto")?.webcrypto?.subtle;
  if (!subtle) return null;
  const encoder = new TextEncoder();
  const hmac = { name: "HMAC", hash: "SHA-256" };
  let key = null;
  const keyOf = () => (key ||= (async () => {
    const outer = await subtle.importKey("raw", encoder.encode(text), hmac, false, ["sign"]);
    const derived = await subtle.sign("HMAC", outer, encoder.encode(LABEL));
    return subtle.importKey("raw", derived, hmac, false, ["sign"]);
  })().catch((error) => {
    key = null;
    throw error;
  }));
  return async (message) => {
    const digest = new Uint8Array(await subtle.sign("HMAC", await keyOf(), encoder.encode(message)));
    let hex = "";
    for (const byte of digest) hex += byte.toString(16).padStart(2, "0");
    return hex;
  };
}

const messageOf = (day, who) => `${day}|${who}`;
const formatPass = (day, hex) => `${day}.${String(hex).slice(0, 32)}`;

// Equal strings, in time that doesn't depend on where they differ.
function sameText(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

// Every value the Cookie header carries under the pass's name. Split on ","
// as well as ";": a server or proxy that gets two Cookie headers can join
// them with ", " (the Fetch API's Headers do), and a pass in the second must
// still count. No pass, and no cookie value worth one, holds a comma.
function cookieValues(cookieHeader, name = COOKIE) {
  const found = [];
  for (const part of String(cookieHeader || "").split(/[;,]/)) {
    const cut = part.indexOf("=");
    if (cut < 0 || part.slice(0, cut).trim() !== name) continue;
    found.push(part.slice(cut + 1).trim().replace(/^"(.*)"$/, "$1"));
    if (found.length >= MAX_VALUES) break;
  }
  return found;
}

// The cookie values worth an HMAC: well formed, for today or yesterday, and
// for an address (never the agent's nginx pass, who = "*").
function candidates(ip, cookieHeader, nowMs) {
  const who = whoOf(ip);
  if (!who || who === "*") return [];
  const today = dayOf(nowMs);
  const out = [];
  for (const value of cookieValues(cookieHeader)) {
    const match = PASS.exec(value);
    if (!match) continue;
    const day = Number(match[1]);
    if (day !== today && day !== today - 1) continue;
    out.push({ message: messageOf(day, who), mac: match[2] });
  }
  return out;
}

// Whether the Cookie header holds this address's pass, with a sync signer.
function hasPassSync(sign, ip, cookieHeader, nowMs = Date.now()) {
  return candidates(ip, cookieHeader, nowMs).some((c) => sameText(String(sign(c.message)).slice(0, 32), c.mac));
}

// The same with any signer (WebCrypto's is async).
async function hasPass(sign, ip, cookieHeader, nowMs = Date.now()) {
  for (const c of candidates(ip, cookieHeader, nowMs)) {
    if (sameText(String(await sign(c.message)).slice(0, 32), c.mac)) return true;
  }
  return false;
}

// Today's pass for this address ("" when it isn't one), with a sync signer.
function passForSync(sign, ip, nowMs = Date.now()) {
  const who = whoOf(ip);
  if (!who) return "";
  const day = dayOf(nowMs);
  return formatPass(day, sign(messageOf(day, who)));
}

async function passFor(sign, ip, nowMs = Date.now()) {
  const who = whoOf(ip);
  if (!who) return "";
  const day = dayOf(nowMs);
  return formatPass(day, await sign(messageOf(day, who)));
}

// Conditions 1 to 3: a GET or HEAD, whose Accept asks for text/html, for a
// path (lower-cased, no query string) under none of the skip prefixes.
function asksForPage(challenge, method, accept, path) {
  if (!challenge) return false;
  const m = String(method || "").toUpperCase();
  if (m !== "GET" && m !== "HEAD") return false;
  if (!String(accept || "").toLowerCase().includes("text/html")) return false;
  const p = String(path || "").split("?")[0].split("#")[0].toLowerCase();
  return !challenge.skip.some((prefix) => p.startsWith(prefix));
}

// Condition 4: the address is in none of allow, goodbots and exempt. address
// is parseIp's result; lists holds the rules' compiled allow and goodbots.
function exempted(challenge, address, { allow, goodbots } = {}) {
  if (!address) return true;
  return Boolean(allow?.has(address) || goodbots?.has(address) || challenge.exempt.has(address));
}

// A fresh nonce for the page's Content-Security-Policy.
function nonce() {
  const bytes = new Uint8Array(16);
  if (globalThis.crypto?.getRandomValues) globalThis.crypto.getRandomValues(bytes);
  else {
    const random = builtin("crypto")?.randomBytes?.(16);
    if (!random) throw new Error("no random source for the check page's nonce");
    bytes.set(random);
  }
  let hex = "";
  for (const byte of bytes) hex += byte.toString(16).padStart(2, "0");
  return hex;
}

// The script: sets the pass and reloads, but only when reading the cookie
// back shows it was set (with cookies off it says so instead of reloading
// forever), and at most three times a minute (an address that changes on
// every request, a pool of exit addresses, would otherwise never get a pass
// that holds and reload for ever). The tries are counted in sessionStorage,
// or, where storage is blocked or full, in a __sg_tries cookie that lasts a
// minute (cookies work: the pass just read back), so a browser without
// storage can't reload for ever either. Secure only when the browser is on
// https: it knows, where the server behind a proxy can only be told. The same
// script as the PHP and Python clients'.
function script(pass) {
  return `(function(){var n=${JSON.stringify(COOKIE)},v=${JSON.stringify(pass)},m=document.getElementById("m"),`
    + `s=location.protocol==="https:";`
    + `document.cookie=n+"="+v+"; Max-Age=${MAX_AGE}; Path=/; SameSite=Lax"+(s?"; Secure":"");`
    + `if((" "+document.cookie+";").indexOf(" "+n+"="+v+";")<0){m.textContent="Please allow cookies for this site, then reload the page.";return;}`
    + `var k="__sg_tries",r=0,t;`
    + `try{t=JSON.parse(sessionStorage.getItem(k)||"[]").filter(function(x){return Date.now()-x<60000;});r=t.length;if(r<3){t.push(Date.now());sessionStorage.setItem(k,JSON.stringify(t));}}`
    + `catch(e){t=/(?:^|; )__sg_tries=([0-9]+)/.exec(document.cookie);r=t?+t[1]:0;if(r<3)document.cookie=k+"="+(r+1)+"; Max-Age=60; Path=/; SameSite=Lax"+(s?"; Secure":"");}`
    + `if(r>=3){m.textContent="This page couldn't be opened because your connection's address keeps changing. Please try again in a minute.";return;}`
    + `location.reload();})();`;
}

// The check page: { status: 503, headers, body } ("" for a HEAD).
function challengePage({ pass, method = "GET" }) {
  const n = nonce();
  const headers = {
    "content-type": "text/html; charset=utf-8",
    "cache-control": "no-store",
    "x-robots-tag": "noindex",
    "content-security-policy": `default-src 'none'; script-src 'nonce-${n}'; style-src 'nonce-${n}'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'`,
  };
  if (String(method || "").toUpperCase() === "HEAD") return { status: 503, headers, body: "" };
  const body = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex"><title>Just a moment</title>
<style nonce="${n}">body{margin:0;min-height:100vh;display:grid;place-items:center;font:16px/1.5 system-ui,sans-serif;background:#f8fafc;color:#0f172a}main{max-width:32rem;padding:2rem;text-align:center}@media(prefers-color-scheme:dark){body{background:#0f172a;color:#e2e8f0}}</style>
</head><body><main><p id="m">Checking your browser before you continue&hellip;</p>
<noscript><p>Please turn on JavaScript to continue to this site.</p></noscript></main>
<script nonce="${n}">${script(pass)}</script>
</body></html>`;
  return { status: 503, headers, body };
}

module.exports = {
  COOKIE,
  MAX_AGE,
  compileChallenge,
  whoOf,
  dayOf,
  createSigner,
  hasPass,
  hasPassSync,
  passFor,
  passForSync,
  asksForPage,
  exempted,
  challengePage,
  cookieValues,
  sameText,
};
