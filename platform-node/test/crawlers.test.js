// The crawlers module: which user agents are counted as which crawler, how
// requests are aggregated per minute, and what is sent (sdk/protocols/crawlers.md).
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { createCrawlers, detect } = require("../lib/crawlers.js");

// A core that records what would be sent instead of sending it.
function fakeCore() {
  const sent = [];
  return {
    sent,
    valid: false, // no background timer in tests; flush() is called directly
    isOn: () => true,
    log: () => {},
    send: async (module, path, options) => {
      sent.push({ path, body: options.body });
      return { ok: true, status: 202 };
    },
  };
}

test("names the crawler behind a user agent, most specific first", () => {
  assert.equal(detect("Mozilla/5.0 AppleWebKit (compatible; GPTBot/1.2; +https://openai.com/gptbot)"), "GPTBot");
  // ChatGPT-User must win over GPTBot, and Claude-User over ClaudeBot.
  assert.equal(detect("Mozilla/5.0 (compatible; ChatGPT-User/1.0; +https://openai.com/bot)"), "ChatGPT-User");
  assert.equal(detect("Mozilla/5.0 (compatible; Claude-User/1.0; +claudebot@anthropic.com)"), "Claude-User");
  assert.equal(detect("Mozilla/5.0 (compatible; ClaudeBot/1.0; +claudebot@anthropic.com)"), "ClaudeBot");
  // Google's tools are their own, not Googlebot.
  assert.equal(detect("Mozilla/5.0 (compatible; Google-InspectionTool/1.0)"), "Google-InspectionTool");
  assert.equal(detect("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"), "Googlebot");
  assert.equal(detect("Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"), "bingbot");
  assert.equal(detect("Mozilla/5.0 (compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)"), "PerplexityBot");
});

test("a crawler nobody has listed is still counted, as Other bot", () => {
  assert.equal(detect("SomeNewThing-crawler/0.1 (+https://example.com)"), "Other bot");
  assert.equal(detect("curl/8.4.0"), "Other bot");
});

test("real browsers are not counted: visitors are the tracker's job", () => {
  assert.equal(detect("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"), "");
  assert.equal(detect("Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Version/17.0 Mobile/15E148 Safari/604.1"), "");
  assert.equal(detect(""), "");
  assert.equal(detect(undefined), "");
});

test("adds up requests for the same minute, bot, page and status", async () => {
  const core = fakeCore();
  const crawlers = createCrawlers(core, { serverName: "web-1" });
  crawlers.record({ bot: "GPTBot", path: "/pricing", status: 200, bytes: 100, ms: 12, ip: "20.0.0.1" });
  crawlers.record({ bot: "GPTBot", path: "/pricing", status: 200, bytes: 100, ms: 8, ip: "20.0.0.1" });
  crawlers.record({ bot: "GPTBot", path: "/gone", status: 404, bytes: 50, ms: 2, ip: "20.0.0.2" });
  await crawlers.flush();

  assert.equal(core.sent.length, 1);
  const { path, body } = core.sent[0];
  assert.equal(path, "/events/crawlers");
  assert.equal(body.server_name, "web-1");
  assert.equal(body.rows.length, 2);
  const pricing = body.rows.find((row) => row.path === "/pricing");
  assert.equal(pricing.count, 2);
  assert.equal(pricing.bytes, 200);
  assert.equal(pricing.sum_ms, 20);
  assert.equal(pricing.bot, "GPTBot");
  assert.match(pricing.minute, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:00\.000Z$/);
  assert.equal(body.rows.find((row) => row.status === 404).count, 1);
  // Up to five addresses per bot go with the batch, for verification only.
  assert.deepEqual(body.agents, [{ bot: "GPTBot", ips: ["20.0.0.1", "20.0.0.2"] }]);
});

test("the query string is left off and the page is kept", async () => {
  const core = fakeCore();
  const crawlers = createCrawlers(core, {});
  crawlers.record({ bot: "Googlebot", path: "/blog/a-post?utm_source=x#top", status: 200 });
  await crawlers.flush();
  assert.equal(core.sent[0].body.rows[0].path, "/blog/a-post");
});

test("a crawler asking for thousands of pages becomes one row", async () => {
  const core = fakeCore();
  const crawlers = createCrawlers(core, {});
  for (let i = 0; i < 400; i++) crawlers.record({ bot: "Bytespider", path: `/p/${i}`, status: 200 });
  await crawlers.flush();
  const rows = core.sent[0].body.rows;
  assert.ok(rows.length <= 301, `expected at most 301 rows, got ${rows.length}`);
  const other = rows.find((row) => row.path === "(other)");
  assert.equal(other.count, 100);
});

test("nothing is counted while the dashboard has the module off", async () => {
  const core = fakeCore();
  core.isOn = () => false;
  const crawlers = createCrawlers(core, {});
  crawlers.record({ bot: "GPTBot", path: "/pricing", status: 200 });
  await crawlers.flush();
  assert.equal(core.sent.length, 0);
});

test("the middleware counts a crawler when the response is done, and passes everything through", async () => {
  const core = fakeCore();
  const crawlers = createCrawlers(core, { clientIp: () => "66.249.66.1" });
  const finish = [];
  const res = { statusCode: 200, getHeader: () => "1234", once: (name, fn) => finish.push([name, fn]) };
  let passed = false;
  crawlers.middleware({ headers: { "user-agent": "Googlebot/2.1" }, url: "/", originalUrl: "/" }, res, () => { passed = true; });
  assert.equal(passed, true);
  assert.equal(finish[0][0], "finish");
  finish[0][1]();
  await crawlers.flush();
  const row = core.sent[0].body.rows[0];
  assert.equal(row.bot, "Googlebot");
  assert.equal(row.bytes, 1234);
  assert.deepEqual(core.sent[0].body.agents, [{ bot: "Googlebot", ips: ["66.249.66.1"] }]);

  // A visitor is not counted, and nothing is hooked onto their response.
  const visitor = { statusCode: 200, once: () => assert.fail("a visitor's response was hooked") };
  let wentOn = false;
  crawlers.middleware({ headers: { "user-agent": "Mozilla/5.0 Chrome/130.0 Safari/537.36" }, url: "/" }, visitor, () => { wentOn = true; });
  assert.equal(wentOn, true);
});

test("a bot with rows still waiting keeps its addresses for the next batch", async (t) => {
  // Rows are bucketed by wall-clock minute, but the timer runs 60 seconds from
  // when the module started: starting half way through a minute means a flush
  // lands with the next minute's rows already waiting, which is the ordinary
  // case for a site with steady traffic.
  t.mock.timers.enable({ apis: ["Date", "setInterval", "setTimeout"], now: 1800000030000 });
  const core = fakeCore();
  core.valid = true; // the periodic flush only runs for a configured site
  const crawlers = createCrawlers(core, {});

  crawlers.record({ bot: "GPTBot", path: "/a", status: 200, ip: "20.0.0.1" });
  t.mock.timers.tick(31000); // into the next minute, before the timer fires
  // This request's address wasn't recorded (no firewall module, say).
  crawlers.record({ bot: "GPTBot", path: "/b", status: 200 });
  t.mock.timers.tick(30000); // the timer fires: the first minute goes, /b waits
  await crawlers.flush();

  assert.equal(core.sent.length, 2);
  assert.equal(core.sent[0].body.rows[0].path, "/a");
  assert.deepEqual(core.sent[0].body.agents, [{ bot: "GPTBot", ips: ["20.0.0.1"] }]);
  // The waiting row's batch still says which addresses this crawler used, so
  // the collector can tell it is itself.
  assert.equal(core.sent[1].body.rows[0].path, "/b");
  assert.deepEqual(core.sent[1].body.agents, [{ bot: "GPTBot", ips: ["20.0.0.1"] }]);

  // With nothing left waiting, the addresses are let go rather than kept for ever.
  crawlers.record({ bot: "Googlebot", path: "/c", status: 200 });
  await crawlers.flush();
  assert.deepEqual(core.sent[2].body.agents, []);
});
