// Cloudflare's published ranges (cloudflare.com/ips), the same list as
// sdk/protocols/cloudflare-ranges.json (test/cloudflare.test.js compares
// them): CF-Connecting-IP is believed only from a connection in these, since
// anyone who reaches the origin directly can send the header. No Node
// built-ins, so the edge runtime can use it too.
"use strict";

const { parseIp, IpSet } = require("./ip.js");

const CLOUDFLARE_RANGES = Object.freeze([
  "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "141.101.64.0/18",
  "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22", "198.41.128.0/17",
  "162.158.0.0/15", "104.16.0.0/13", "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
  "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32", "2405:b500::/32", "2405:8100::/32",
  "2a06:98c0::/29", "2c0f:f248::/32",
]);

let set = null;

// Whether a connection's address is one of Cloudflare's.
function fromCloudflare(ip) {
  const address = parseIp(ip);
  if (!address) return false;
  set ||= new IpSet(CLOUDFLARE_RANGES);
  return set.has(address);
}

// Running as a Cloudflare Worker: there is no connection address, and
// Cloudflare itself sets CF-Connecting-IP on every request, overwriting
// whatever the client sent.
const onWorkers = () => globalThis.navigator?.userAgent === "Cloudflare-Workers";

module.exports = { CLOUDFLARE_RANGES, fromCloudflare, onWorkers };
