// The options read from ANALYTICS_* when they aren't passed, as the Go
// package does: ANALYTICS_SITE_ID, ANALYTICS_SITE_SECRET, ANALYTICS_ENDPOINT,
// and optionally ANALYTICS_TRUST_PROXY ("cloudflare", "true" or a number of
// proxies) and ANALYTICS_SERVER_NAME. And the ANALYTICS_* lines of a .env
// file, for analytics-platform/start: read, never written to process.env, so
// whatever loads the app's own .env files later still sets them as it would.
"use strict";

const fs = require("node:fs");

function fromEnvironment(options = {}, env = process.env) {
  const read = (name) => (typeof env[name] === "string" && env[name].trim()) || undefined;
  const trust = read("ANALYTICS_TRUST_PROXY");
  const trustProxy = trust === undefined ? undefined
    : trust.toLowerCase() === "cloudflare" ? "cloudflare"
      : trust.toLowerCase() === "true" ? true
        : /^\d+$/.test(trust) && Number(trust) > 0 ? Number(trust) : undefined;
  const filled = { ...options };
  if (filled.siteId === undefined) filled.siteId = read("ANALYTICS_SITE_ID");
  if (filled.secret === undefined) filled.secret = read("ANALYTICS_SITE_SECRET");
  if (filled.endpoint === undefined) filled.endpoint = read("ANALYTICS_ENDPOINT");
  if (filled.trustProxy === undefined && trustProxy !== undefined) filled.trustProxy = trustProxy;
  if (filled.serverName === undefined && read("ANALYTICS_SERVER_NAME")) filled.serverName = read("ANALYTICS_SERVER_NAME");
  return filled;
}

// The ANALYTICS_* lines of a .env file, as { name: value }; {} without one.
// Not a dotenv: no expansion, and every other line is ignored.
function readDotEnv(file) {
  let text;
  try {
    text = fs.readFileSync(file, "utf8");
  } catch {
    return {};
  }
  const found = {};
  for (const line of text.split(/\r?\n/)) {
    const match = /^\s*(?:export\s+)?(ANALYTICS_[A-Z0-9_]+)\s*=\s*(.*)$/.exec(line);
    if (!match) continue;
    let value = match[2].trim();
    const quote = value[0];
    if ((quote === '"' || quote === "'" || quote === "`") && value.indexOf(quote, 1) > 0) {
      value = value.slice(1, value.indexOf(quote, 1));
    } else {
      value = value.replace(/\s+#.*$/, "");
    }
    found[match[1]] = value;
  }
  return found;
}

module.exports = { fromEnvironment, readDotEnv };
