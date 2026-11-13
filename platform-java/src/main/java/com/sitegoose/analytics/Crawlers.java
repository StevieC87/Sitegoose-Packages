package com.sitegoose.analytics;

import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;

/**
 * Crawlers module: counts the search engines and AI bots that fetch the site
 * and sends one row a minute per bot, page and status to POST /events/crawlers
 * (sdk/protocols/crawlers.md). Crawlers don't run JavaScript, so the server
 * is the only place this traffic can be counted. Only requests whose user
 * agent names a known crawler are counted; bot addresses go with the batch
 * only so the collector can check a crawler is itself, and are not stored.
 */
final class Crawlers {
    static final double FLUSH_EVERY = 60;
    static final int MAX_KEYS = 300;
    static final int MAX_ROWS = 500;
    static final int MAX_IPS_PER_BOT = 5;
    static final int MAX_PATH = 400;

    /**
     * The catalogue of the protocol, most specific first: "ChatGPT-User" must
     * be tried before "GPTBot", "Claude-User" before "ClaudeBot". Keep in step
     * with the collector (expresscollect/Analytics/crawlers.js CATALOGUE).
     */
    static final String[][] BOTS = {
        // Fetched because a person asked an AI about the page.
        {"ChatGPT-User", "ChatGPT-User"},
        {"OAI-SearchBot", "OAI-SearchBot"},
        {"Perplexity-User", "Perplexity-User"},
        {"Claude-User", "Claude-User"},
        {"Claude-SearchBot", "Claude-SearchBot"},
        {"MistralAI-User", "MistralAI-User"},
        {"MistralAI-SearchBot", "MistralAI-SearchBot"},
        {"Meta-ExternalFetcher", "meta-externalfetcher"},
        // Bulk collection, for training or a dataset.
        {"GPTBot", "GPTBot"},
        {"ClaudeBot", "ClaudeBot|Claude-Web"},
        {"anthropic-ai", "anthropic-ai"},
        {"CCBot", "CCBot"},
        {"Bytespider", "Bytespider"},
        {"Meta-ExternalAgent", "meta-externalagent|facebookbot"},
        {"Amazonbot", "Amazonbot"},
        {"Diffbot", "Diffbot"},
        {"omgili", "omgili"},
        {"AI2Bot", "AI2Bot"},
        {"Timpibot", "Timpibot"},
        {"Webzio-Extended", "Webzio-Extended"},
        {"PerplexityBot", "PerplexityBot"},
        {"DuckAssistBot", "DuckAssistBot"},
        {"YouBot", "YouBot"},
        // Search engines. Google's tools before Googlebot itself.
        {"Google-InspectionTool", "Google-InspectionTool"},
        {"Storebot-Google", "Storebot-Google"},
        {"AdsBot-Google", "AdsBot-Google"},
        {"Googlebot", "Googlebot|Google-Site-Verification"},
        {"bingbot", "bingbot|BingPreview|adidxbot"},
        {"YandexBot", "Yandex(Bot|Mobile|Images|Webmaster)?"},
        {"Baiduspider", "Baiduspider"},
        {"DuckDuckBot", "DuckDuckBot|DuckDuckGo-Favicons"},
        {"Applebot", "Applebot"},
        {"PetalBot", "PetalBot|AspiegelBot"},
        {"SeznamBot", "SeznamBot"},
        {"Yeti", "Yeti/"},
        {"MojeekBot", "MojeekBot"},
        {"Qwantbot", "Qwantbot|Qwantify"},
        // SEO and backlink tools.
        {"AhrefsBot", "AhrefsBot|AhrefsSiteAudit"},
        {"SemrushBot", "SemrushBot|SiteAuditBot"},
        {"DotBot", "DotBot"},
        {"MJ12bot", "MJ12bot"},
        {"BLEXBot", "BLEXBot"},
        {"DataForSeoBot", "DataForSeoBot"},
        {"Barkrowler", "Barkrowler"},
        {"ScreamingFrog", "Screaming\\s?Frog"},
        {"ZoominfoBot", "ZoominfoBot"},
        // Link previews.
        {"facebookexternalhit", "facebookexternalhit"},
        {"Twitterbot", "Twitterbot"},
        {"LinkedInBot", "LinkedInBot"},
        {"Slackbot", "Slackbot|Slack-ImgProxy"},
        {"Discordbot", "Discordbot"},
        {"TelegramBot", "TelegramBot"},
        {"WhatsApp", "WhatsApp"},
        {"Pinterestbot", "Pinterest(bot)?/"},
        {"redditbot", "redditbot"},
        // Uptime and speed checks.
        {"UptimeRobot", "UptimeRobot"},
        {"Pingdom", "Pingdom"},
        {"BetterUptime", "Better\\s?Uptime|betteruptime"},
        {"Lighthouse", "Chrome-Lighthouse|Google Page Speed"},
        {"GTmetrix", "GTmetrix"},
        // Archives.
        {"ia_archiver", "ia_archiver"},
        {"archive.org_bot", "archive\\.org_bot|Wayback"},
    };
    private static final Pattern[] PATTERNS = new Pattern[BOTS.length];

    static {
        for (int i = 0; i < BOTS.length; i++) {
            PATTERNS[i] = Pattern.compile(BOTS[i][1], Pattern.CASE_INSENSITIVE);
        }
    }

    /** Anything else that names itself a bot: "Other bot", so a new crawler shows up instead of disappearing. */
    private static final Pattern GENERIC = Pattern.compile(
            "bot\\b|crawler|crawling|spider|scrapy|curl/|wget/|python-requests|headlesschrome|http-client|okhttp|java/|go-http-client",
            Pattern.CASE_INSENSITIVE);

    /** The crawler's catalogue name, or "" when the user agent isn't one. */
    static String detect(String userAgent) {
        if (userAgent == null || userAgent.isEmpty()) {
            return "";
        }
        for (int i = 0; i < BOTS.length; i++) {
            if (PATTERNS[i].matcher(userAgent).find()) {
                return BOTS[i][0];
            }
        }
        return GENERIC.matcher(userAgent).find() ? "Other bot" : "";
    }

    private static final class Key {
        final long minute;
        final String bot;
        final String path;
        final int status;

        Key(long minute, String bot, String path, int status) {
            this.minute = minute;
            this.bot = bot;
            this.path = path;
            this.status = status;
        }

        @Override
        public boolean equals(Object o) {
            if (!(o instanceof Key)) {
                return false;
            }
            Key k = (Key) o;
            return minute == k.minute && status == k.status && bot.equals(k.bot) && path.equals(k.path);
        }

        @Override
        public int hashCode() {
            return Objects.hash(minute, bot, path, status);
        }
    }

    private final Core core;
    final String serverName;
    final String runtime;
    private Map<Key, long[]> rows = new LinkedHashMap<>();
    private Map<String, Set<String>> agents = new LinkedHashMap<>();
    private final Periodic job;

    Crawlers(Core core, String serverName) {
        this.core = core;
        String name = serverName == null || serverName.isEmpty() ? Hosts.hostName() : serverName;
        this.serverName = name.length() > 100 ? name.substring(0, 100) : name;
        this.runtime = Core.runtime();
        this.job = core.valid ? core.every(this::flushJob, FLUSH_EVERY) : null;
    }

    /** One finished request from a crawler. bot: detect(userAgent). */
    void record(String bot, String path, int status, double ms, long size, String ip) {
        if (bot == null || bot.isEmpty() || !core.isOn("crawlers")) {
            return;
        }
        String clean = path == null || path.isEmpty() ? "/" : path.split("[?#]", 2)[0];
        if (clean.isEmpty()) {
            clean = "/";
        }
        if (clean.length() > MAX_PATH) {
            clean = clean.substring(0, MAX_PATH);
        }
        long minute = System.currentTimeMillis() / 60000 * 60;
        synchronized (this) {
            Key key = new Key(minute, bot, clean, status);
            // Past MAX_KEYS a crawler asking for thousands of URLs becomes one row.
            if (!rows.containsKey(key) && rows.size() >= MAX_KEYS) {
                key = new Key(minute, bot, "(other)", status);
            }
            long[] row = rows.computeIfAbsent(key, k -> new long[3]);
            row[0] += 1;
            row[1] += Math.max(0, size);
            row[2] += Math.max(0, (long) ms);
            if (ip != null && !ip.isEmpty()) {
                Set<String> seen = agents.computeIfAbsent(bot, b -> new LinkedHashSet<>());
                if (seen.size() < MAX_IPS_PER_BOT) {
                    seen.add(ip);
                }
            }
        }
    }

    /** Records a finished request when it came from a crawler. */
    void middleware(String userAgent, String path, int status, double ms, long size, String ip) {
        record(detect(userAgent), path, status, ms, size, ip);
    }

    void flush(boolean everything) {
        long current = System.currentTimeMillis() / 60000 * 60;
        List<Map<String, Object>> ready = new ArrayList<>();
        List<Map<String, Object>> agentRows = new ArrayList<>();
        synchronized (this) {
            Map<Key, long[]> keep = new LinkedHashMap<>();
            Set<String> sent = new LinkedHashSet<>();
            for (Map.Entry<Key, long[]> entry : rows.entrySet()) {
                Key k = entry.getKey();
                if (!everything && k.minute >= current) {
                    keep.put(k, entry.getValue());
                    continue;
                }
                long[] v = entry.getValue();
                Map<String, Object> row = new LinkedHashMap<>();
                row.put("minute", Instant.ofEpochSecond(k.minute).toString());
                row.put("bot", k.bot);
                row.put("path", k.path);
                row.put("status", k.status);
                row.put("count", v[0]);
                row.put("bytes", v[1]);
                row.put("sum_ms", v[2]);
                ready.add(row);
                sent.add(k.bot);
            }
            for (Map.Entry<String, Set<String>> agent : agents.entrySet()) {
                if (sent.contains(agent.getKey())) {
                    Map<String, Object> row = new LinkedHashMap<>();
                    row.put("bot", agent.getKey());
                    row.put("ips", new ArrayList<>(agent.getValue()));
                    agentRows.add(row);
                }
            }
            rows = keep;
            if (!ready.isEmpty()) {
                // A bot with rows still waiting keeps its addresses, so the next batch can be checked as well.
                Set<String> waiting = new LinkedHashSet<>();
                for (Key k : keep.keySet()) {
                    waiting.add(k.bot);
                }
                Map<String, Set<String>> kept = new LinkedHashMap<>();
                for (Map.Entry<String, Set<String>> agent : agents.entrySet()) {
                    if (waiting.contains(agent.getKey())) {
                        kept.put(agent.getKey(), agent.getValue());
                    }
                }
                agents = kept;
            }
        }
        for (int i = 0; i < ready.size(); i += MAX_ROWS) {
            Map<String, Object> body = new LinkedHashMap<>();
            body.put("server_name", serverName);
            body.put("runtime", runtime);
            body.put("rows", ready.subList(i, Math.min(ready.size(), i + MAX_ROWS)));
            body.put("agents", i == 0 ? agentRows : new ArrayList<>());
            core.post("crawlers", "/events/crawlers", body);
        }
    }

    private double flushJob() {
        flush(false);
        return FLUSH_EVERY;
    }

    void close() {
        if (job != null) {
            job.stop(core.stopWait());
        }
        flush(true);
    }
}
