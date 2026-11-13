# Crawler analytics protocol (v1)

What each server package reports about the **crawlers and AI bots** that fetch
the site, so the dashboard can show what search engines and AI systems read,
how often, and which of them only claim to be who they say.

The browser tracker cannot see any of this: crawlers don't run JavaScript. The
collector's own AI classification (`expresscollect/Analytics/collectAnalytics.js`)
only ever saw a bot that executed the tracker, which is why AI crawler
collection is switched off there. The server packages are the only place the
traffic is visible.

Clients: the Node package (`sdk/platform-node`), the Python package
(`sdk/platform-python`), the PHP package (`sdk/platform-php`), the WordPress
plugin (`sdk/wordpress-plugin`) and the Ruby, Java, .NET and Go packages
(`sdk/platform-ruby`, `sdk/platform-java`, `sdk/platform-dotnet`,
`sdk/platform-go`), whose `runtime` reads `Ruby 3.3.6`, `Java 21.0.12.1`,
`.NET 8.0.11`, `Go 1.23.4`. The collector side is
`expresscollect/Analytics/crawlers.js`; the report is
`backend/Sections/Analytics/health/crawlerReport.js` (Off-site → Crawlers).

## Authentication

Like server speed (`/events/server-requests`): the site's ID and its secret in
the body, and a `User-Agent` naming the client and its version.

## When

One row set per minute, sent at most once a minute, in the background, after
the response has gone out. Never in a visitor's request; never slow the site.
A client that cannot send keeps at most `MAX_ROWS` rows and drops the rest.

## What to count

Every request whose `User-Agent` matches the catalogue below, including the ones
the firewall blocked (a blocked crawler is still a crawler: send the status the
visitor got). Requests with no match are **not** counted: humans are the
tracker's job, and counting them here would double-count.

Aggregate in memory by `(minute, bot, path, status)`:

| field | |
|---|---|
| `minute` | the minute the request arrived, ISO 8601, UTC |
| `bot` | the catalogue name, exactly as spelled below |
| `path` | the request path, no query string, at most 400 characters |
| `status` | the response status the bot got |
| `count` | how many such requests |
| `bytes` | response bytes, summed, when the client knows them (0 otherwise) |
| `sum_ms` | time to answer, summed, in milliseconds |

At most `MAX_ROWS` (500) rows per minute. Past 300 distinct keys, put the rest
under `path: "(other)"` so a crawler asking for thousands of URLs cannot turn
into thousands of rows. Past 400 rows a client keeps no more that minute,
whatever their keys: the fold bounds paths, not every part of a key.

Server speed (`/events/server-requests`) rows are bounded the same way (300
keys, then `(other)`, 400 rows at most), and their `method` is one of `GET`,
`HEAD`, `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS` and `JOB` (a background
job), anything else `OTHER`: the method is the visitor's to choose, so taken
as sent it would be a new row per made-up word.

**Addresses.** Alongside the rows, send `agents`: per bot name, up to 5 distinct
client addresses seen that minute, so the collector can tell a real crawler from
something wearing its name. Nothing else about the request is sent, and no
address is stored.

## The catalogue

Both sides keep this list in step, like `BUCKET_EDGES_MS` for server speed. The
`kind` is what the dashboard groups by; `ai_train`, `ai_search` and `ai_user`
together are "AI".

| kind | meaning | names |
|---|---|---|
| `ai_train` | bulk collection, for training or a dataset | `GPTBot`, `ClaudeBot`, `anthropic-ai`, `CCBot`, `Bytespider`, `Meta-ExternalAgent`, `Amazonbot`, `Diffbot`, `omgili`, `AI2Bot`, `Timpibot`, `Webzio-Extended` |
| `ai_search` | indexing for an answer engine | `OAI-SearchBot`, `PerplexityBot`, `Claude-SearchBot`, `DuckAssistBot`, `YouBot`, `MistralAI-SearchBot` |
| `ai_user` | fetched because a person asked an AI about the page | `ChatGPT-User`, `Perplexity-User`, `Claude-User`, `MistralAI-User`, `Meta-ExternalFetcher` |
| `search` | search engines | `Googlebot`, `Google-InspectionTool`, `Storebot-Google`, `AdsBot-Google`, `bingbot`, `YandexBot`, `Baiduspider`, `DuckDuckBot`, `Applebot`, `PetalBot`, `SeznamBot`, `Yeti`, `MojeekBot`, `Qwantbot` |
| `seo` | SEO and backlink tools | `AhrefsBot`, `SemrushBot`, `DotBot`, `MJ12bot`, `BLEXBot`, `DataForSeoBot`, `Barkrowler`, `ScreamingFrog`, `ZoominfoBot` |
| `chat` | a chat app previewing a link someone just pasted | `Slackbot`, `Discordbot`, `TelegramBot`, `WhatsApp` |
| `social` | a social network's card preview | `facebookexternalhit`, `Twitterbot`, `LinkedInBot`, `Pinterestbot`, `redditbot` |
| `monitor` | uptime and speed checks | `UptimeRobot`, `Pingdom`, `BetterUptime`, `Lighthouse`, `GTmetrix` |
| `archive` | archives | `ia_archiver`, `archive.org_bot` |
| `other` | a user agent naming itself a bot, crawler or spider that none of the above match | `Other bot` |

Google crawls for AI Overviews and Gemini grounding as `Googlebot`, so that
traffic cannot be told apart from search: `Google-Extended` and
`Applebot-Extended` are robots.txt tokens, not crawlers, and never appear as a
user agent. The dashboard says so rather than guessing.

`chat` is set apart because each of its fetches follows a person pasting the
address into a conversation, so the dashboard counts them as pastes (Widgets →
Share buttons). The networks in `social` also refresh their cards on their own
schedule, so theirs are not. iMessage and Messenger preview under
`facebookexternalhit` and stay in `social`. The kind is the collector's
alone — clients send only the name — and rows stored before `chat` existed
(2026-10-25) are split by name when read
(`backend/Sections/Analytics/health/crawlerKinds.js`).

A name the collector does not know is stored as `Other bot`, so a client can
ship a longer catalogue than the collector without losing the counts.

## POST /events/crawlers

```json
{
  "site_id": "<id>",
  "sitesecret": "<secret>",
  "server_name": "web-1",
  "runtime": "Node 22.11.0",
  "rows": [
    { "minute": "2026-10-18T12:00:00.000Z", "bot": "GPTBot", "path": "/pricing", "status": 200, "count": 3, "bytes": 42310, "sum_ms": 84 },
    { "minute": "2026-10-18T12:00:00.000Z", "bot": "Googlebot", "path": "/blog/post", "status": 404, "count": 1, "bytes": 512, "sum_ms": 9 }
  ],
  "agents": [
    { "bot": "GPTBot", "ips": ["20.171.207.1"] },
    { "bot": "Googlebot", "ips": ["66.249.66.1"] }
  ]
}
```

The answer (`202`): `{ "status": "accepted", "stored": 2 }`. `400` for a body
with no valid row, `401` for bad credentials, `429` over the rate limit, `503`
with `Retry-After` when ClickHouse cannot take the rows (the client keeps them
and tries again).

## Verification (collector side)

A crawler can be proved to be itself two ways, and the collector uses both.

**The address list it publishes.** Most crawlers, including every AI crawler
that can be checked at all, publish the addresses they crawl from as
`{ "prefixes": [{ "ipv4Prefix": … } | { "ipv6Prefix": … }] }`. The collector
reads them once a day in the background (`crawlerRanges.js`) and keeps the last
good copy when a fetch fails, so a list it cannot read today never turns a real
crawler into a fake one. The sources, each checked against the live endpoint on
2026-10-18:

| crawler | list |
|---|---|
| `GPTBot` | `openai.com/gptbot.json` |
| `OAI-SearchBot` | `openai.com/searchbot.json` |
| `ChatGPT-User` | `openai.com/chatgpt-user.json` |
| `PerplexityBot` | `perplexity.com/perplexitybot.json` |
| `Perplexity-User` | `perplexity.com/perplexity-user.json` |
| `DuckAssistBot` | `duckduckgo.com/duckassistbot.json` |
| `bingbot` | `bing.com/toolbox/bingbot.json` |
| `Googlebot`, `Google-InspectionTool`, `Storebot-Google`, `AdsBot-Google` | Google's `googlebot.json`, `special-crawlers.json` and `user-triggered-fetchers-google.json`, as one list |

Google splits its addresses over three files and may move a crawler between
them, so every Google name is checked against all three together. That still
catches anything outside Google using the name, and cannot call a real Google
crawler fake.

**The name it publishes.** Five crawlers document a reverse-DNS convention: the
collector looks up the address's name and resolves that name back, and both
must agree.

| bot | names |
|---|---|
| `Googlebot`, `Google-InspectionTool`, `Storebot-Google`, `AdsBot-Google` | `.googlebot.com`, `.google.com`, `.googleusercontent.com` |
| `bingbot` | `.search.msn.com` |
| `YandexBot` | `.yandex.ru`, `.yandex.net`, `.yandex.com` |
| `Baiduspider` | `.baidu.com`, `.baidu.jp` |
| `Applebot` | `.applebot.apple.com` |

The list is tried first, because it costs nothing. An address the list doesn't
have is **not** called fake while the crawler also documents a name — a list
can lag a new range, so reverse DNS decides those.

- `verified` — the published list has the address, or its name resolved back to it.
- `fake` — the crawler publishes a way to check and the address failed it.
  Someone is using the crawler's name; the dashboard offers a firewall rule.
- `unknown` — the crawler publishes neither. Anthropic publishes no address
  list, so `ClaudeBot`, `Claude-User` and `Claude-SearchBot` land here, as do
  `CCBot`, `Bytespider` and the SEO tools. The collector records the network
  the address belongs to instead (`asn`, `asn_org`, from the GeoLite2-ASN
  database it already has), so "ClaudeBot, from Amazon AWS" can be told from
  "ClaudeBot, from a home connection".

Verdicts are cached in Redis for a day (`botver:<bot>:<ip>`), so a crawl costs a
handful of lookups a day, not one per request. A verdict that is only `unknown`
because no list has been read yet is kept for a minute instead.

## Storage

`analytics.crawler_requests`, inserted directly by the collector (no queue: one
row per minute, bot, path and status is a small, already aggregated write — the
same shape as `server_requests`). See
`clickhouse_worker/migrations/20261018_crawler_requests.sql`.

## What reads it

- **Off-site → Crawlers** (`backend/Sections/Analytics/health/crawlerReport.js`,
  `frontend/.../analytics/crawlers/CrawlersView.jsx`): the whole picture, plus
  the robots.txt check, which compares the pages crawlers actually fetched
  against the site's own rules for that crawler.
- **AI visibility** (`backend/services/aiVisibility/insights.js`): the AI
  crawler card, and when an AI crawler last read each page an answer cited.
  Citations say what AI answers with; these rows say what it read.

## Must

- Paths, statuses and counts only: never a visitor, a cookie, a header or a body.
- Addresses only for the bots in `agents`, only to verify them, and never stored.
- The module is `crawlers` in `/events/platform/config`, so the dashboard can
  switch it off (Security → Server package).
- Off never breaks anything: a client that cannot reach the collector drops its
  rows and carries on.
