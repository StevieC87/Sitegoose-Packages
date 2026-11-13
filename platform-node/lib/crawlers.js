// Crawlers module: counts the search engines and AI bots that fetch the site
// and sends one row a minute per bot, path and status to POST /events/crawlers
// (the protocol is sdk/protocols/crawlers.md). This traffic is invisible to
// the browser tracker, because crawlers don't run JavaScript: the server is
// the only place it can be counted.
//
// Only requests whose user agent names a known crawler are counted, so
// visitors are never counted twice. Requests the firewall turned away count
// too, with the status the crawler got. Nothing about a visitor is sent; bot
// addresses go with the batch only so the collector can check a crawler is
// itself (reverse DNS), and are not stored.
"use strict";

// No Node built-ins required, so Hono can count crawlers on any runtime
// (hono.js), as performance.js does.
const { builtin } = require("./core.js");

const FLUSH_MS = 60 * 1000;
const MAX_KEYS = 300;
// Past MAX_KEYS a minute's new paths fold into "(other)"; past this nothing
// new is kept at all (bots by status can still add rows after the fold).
const HARD_MAX_KEYS = 400;
const MAX_ROWS = 500;
const MAX_IPS_PER_BOT = 5;
const MAX_PATH = 400;
const OTHER = "(other)";

// The catalogue of the protocol, most specific first: "ChatGPT-User" must be
// tried before "GPTBot", "Claude-User" before "ClaudeBot". Keep in step with
// the collector (expresscollect/Analytics/crawlers.js CATALOGUE).
const BOTS = [
  // Fetched because a person asked an AI about the page.
  ["ChatGPT-User", /ChatGPT-User/i],
  ["OAI-SearchBot", /OAI-SearchBot/i],
  ["Perplexity-User", /Perplexity-User/i],
  ["Claude-User", /Claude-User/i],
  ["Claude-SearchBot", /Claude-SearchBot/i],
  ["MistralAI-User", /MistralAI-User/i],
  ["MistralAI-SearchBot", /MistralAI-SearchBot/i],
  ["Meta-ExternalFetcher", /meta-externalfetcher/i],
  // Bulk collection, for training or a dataset.
  ["GPTBot", /GPTBot/i],
  ["ClaudeBot", /ClaudeBot|Claude-Web/i],
  ["anthropic-ai", /anthropic-ai/i],
  ["CCBot", /CCBot/i],
  ["Bytespider", /Bytespider/i],
  ["Meta-ExternalAgent", /meta-externalagent|facebookbot/i],
  ["Amazonbot", /Amazonbot/i],
  ["Diffbot", /Diffbot/i],
  ["omgili", /omgili/i],
  ["AI2Bot", /AI2Bot/i],
  ["Timpibot", /Timpibot/i],
  ["Webzio-Extended", /Webzio-Extended/i],
  ["PerplexityBot", /PerplexityBot/i],
  ["DuckAssistBot", /DuckAssistBot/i],
  ["YouBot", /YouBot/i],
  // Search engines. Google's tools before Googlebot itself.
  ["Google-InspectionTool", /Google-InspectionTool/i],
  ["Storebot-Google", /Storebot-Google/i],
  ["AdsBot-Google", /AdsBot-Google/i],
  ["Googlebot", /Googlebot|Google-Site-Verification/i],
  ["bingbot", /bingbot|BingPreview|adidxbot/i],
  ["YandexBot", /Yandex(Bot|Mobile|Images|Webmaster)?/i],
  ["Baiduspider", /Baiduspider/i],
  ["DuckDuckBot", /DuckDuckBot|DuckDuckGo-Favicons/i],
  ["Applebot", /Applebot/i],
  ["PetalBot", /PetalBot|AspiegelBot/i],
  ["SeznamBot", /SeznamBot/i],
  ["Yeti", /Yeti\//i],
  ["MojeekBot", /MojeekBot/i],
  ["Qwantbot", /Qwantbot|Qwantify/i],
  // SEO and backlink tools.
  ["AhrefsBot", /AhrefsBot|AhrefsSiteAudit/i],
  ["SemrushBot", /SemrushBot|SiteAuditBot/i],
  ["DotBot", /DotBot/i],
  ["MJ12bot", /MJ12bot/i],
  ["BLEXBot", /BLEXBot/i],
  ["DataForSeoBot", /DataForSeoBot/i],
  ["Barkrowler", /Barkrowler/i],
  ["ScreamingFrog", /Screaming\s?Frog/i],
  ["ZoominfoBot", /ZoominfoBot/i],
  // Link previews.
  ["facebookexternalhit", /facebookexternalhit/i],
  ["Twitterbot", /Twitterbot/i],
  ["LinkedInBot", /LinkedInBot/i],
  ["Slackbot", /Slackbot|Slack-ImgProxy/i],
  ["Discordbot", /Discordbot/i],
  ["TelegramBot", /TelegramBot/i],
  ["WhatsApp", /WhatsApp/i],
  ["Pinterestbot", /Pinterest(bot)?\//i],
  ["redditbot", /redditbot/i],
  // Uptime and speed checks.
  ["UptimeRobot", /UptimeRobot/i],
  ["Pingdom", /Pingdom/i],
  ["BetterUptime", /Better\s?Uptime|betteruptime/i],
  ["Lighthouse", /Chrome-Lighthouse|Google Page Speed/i],
  ["GTmetrix", /GTmetrix/i],
  // Archives.
  ["ia_archiver", /ia_archiver/i],
  ["archive.org_bot", /archive\.org_bot|Wayback/i],
];

// Anything else that names itself a bot: counted as "Other bot", so a new
// crawler shows up as traffic instead of disappearing.
const GENERIC = /bot\b|crawler|crawling|spider|scrapy|curl\/|wget\/|python-requests|headlesschrome|http-client|okhttp|java\/|go-http-client/i;

// The crawler's catalogue name, or "" when the user agent isn't one.
function detect(userAgent) {
  const ua = String(userAgent || "");
  if (!ua) return "";
  for (const [name, pattern] of BOTS) if (pattern.test(ua)) return name;
  return GENERIC.test(ua) ? "Other bot" : "";
}

// Options: serverName (default the host name), clientIp(req) (the firewall's,
// so the address is found the same way behind a proxy); runtime and timer:
// false (no minute timer: whoever records flushes) for hono.js.
function createCrawlers(core, options = {}) {
  const log = (...args) => core.log("crawlers", ...args);
  const serverName = String(options.serverName ?? builtin("os")?.hostname() ?? "").slice(0, 100);
  const runtime = options.runtime || `Node ${process.versions.node}`;
  const addressOf = typeof options.clientIp === "function"
    ? options.clientIp
    : (req) => req.ip || req.socket?.remoteAddress || "";
  let rows = new Map();
  const keysIn = new Map(); // minute -> rows it has
  let agents = new Map();
  let sending = Promise.resolve();

  // Records one finished request from a crawler.
  function record({ bot, path, status, bytes = 0, ms = 0, ip = "" }) {
    if (!bot || !core.isOn("crawlers")) return;
    const minute = Math.floor(Date.now() / 60000) * 60000;
    const clean = String(path || "/").split(/[?#]/)[0].slice(0, MAX_PATH) || "/";
    const code = Math.trunc(Number(status)) || 0;
    let key = `${minute}|${bot}|${clean}|${code}`;
    // Past MAX_KEYS a crawler asking for thousands of URLs becomes one row.
    // The cap is per minute: rows of a minute not yet sent don't count.
    const used = keysIn.get(minute) || 0;
    let shown = clean;
    if (!rows.has(key) && used >= MAX_KEYS) {
      shown = OTHER;
      key = `${minute}|${bot}|${OTHER}|${code}`;
    }
    let row = rows.get(key);
    if (!row && used >= HARD_MAX_KEYS) return;
    if (!row) {
      row = { minute, bot, path: shown, status: code, count: 0, bytes: 0, sum_ms: 0 };
      rows.set(key, row);
      keysIn.set(minute, used + 1);
    }
    row.count += 1;
    row.bytes += Math.max(0, Number(bytes) || 0);
    row.sum_ms += Math.max(0, Number(ms) || 0);
    if (ip) {
      let seen = agents.get(bot);
      if (!seen) agents.set(bot, (seen = new Set()));
      if (seen.size < MAX_IPS_PER_BOT) seen.add(ip);
    }
  }

  // Express / Connect / node:http middleware. Runs before the firewall, so a
  // crawler that was turned away is still counted, with the status it got.
  function middleware(req, res, next = () => {}) {
    const bot = detect(req.headers?.["user-agent"]);
    if (!bot) return next();
    const start = process.hrtime.bigint();
    res.once("finish", () => {
      try {
        const length = Number(res.getHeader?.("content-length")) || 0;
        record({
          bot,
          path: req.originalUrl || req.url || "/",
          status: res.statusCode || 0,
          bytes: length,
          ms: Number(process.hrtime.bigint() - start) / 1e6,
          ip: addressOf(req),
        });
      } catch (error) {
        log("could not count a crawler request:", error?.message);
      }
    });
    return next();
  }

  // Sends the rows of finished minutes (all of them with all = true).
  function flush(all = false) {
    const current = Math.floor(Date.now() / 60000) * 60000;
    const ready = [];
    for (const [key, row] of rows) {
      if (all || row.minute < current) {
        ready.push({ ...row, minute: new Date(row.minute).toISOString(), sum_ms: Math.round(row.sum_ms) });
        rows.delete(key);
      }
    }
    for (const minute of keysIn.keys()) if (all || minute < current) keysIn.delete(minute);
    if (!ready.length) return sending;
    const sent = new Set(ready.map((row) => row.bot));
    const batchAgents = [...agents].filter(([bot]) => sent.has(bot)).map(([bot, ips]) => ({ bot, ips: [...ips] }));
    // A bot with rows still waiting (this minute isn't over) keeps its
    // addresses, so the next batch can be checked as well.
    const waiting = new Set([...rows.values()].map((row) => row.bot));
    agents = new Map([...agents].filter(([bot]) => waiting.has(bot)));
    for (let i = 0; i < ready.length; i += MAX_ROWS) {
      const batch = ready.slice(i, i + MAX_ROWS);
      sending = sending.then(() => core.send("crawlers", "/events/crawlers", {
        body: { server_name: serverName, runtime, rows: batch, agents: i === 0 ? batchAgents : [] },
      }));
    }
    return sending;
  }

  const timer = core.valid && options.timer !== false ? setInterval(() => flush(), FLUSH_MS) : null;
  timer?.unref?.();

  return {
    middleware,
    record,
    detect,
    flush: () => flush(true),
    close() {
      clearInterval(timer);
      return flush(true);
    },
  };
}

module.exports = { createCrawlers, detect, BOTS, HARD_MAX_KEYS };
