<?php
// Crawlers module: counts the search engines and AI bots that fetch the site
// and sends one row a minute per bot, page and status to POST /events/crawlers
// (the protocol is sdk/protocols/crawlers.md). This traffic is invisible to
// the browser tracker, because crawlers don't run JavaScript: the server is
// the only place it can be counted.
//
// Only requests whose user agent names a known crawler are counted, so
// visitors are never counted twice. Like Server speed, each request appends
// one line to crawlers.jsonl in the storage directory, and once a minute one
// request adds them up and sends them, after its response.

namespace AnalyticsPlatform;

class Crawlers
{
    const FLUSH_EVERY = 60;
    const MAX_KEYS = 300;
    const HARD_MAX_KEYS = 400;
    const MAX_ROWS = 500;
    const MAX_IPS_PER_BOT = 5;
    const MAX_PATH = 400;
    const SPOOL_MAX = 5000000; // bytes waiting; more requests aren't recorded

    // The catalogue of the protocol, most specific first: "ChatGPT-User" must
    // be tried before "GPTBot", "Claude-User" before "ClaudeBot". Keep in step
    // with the collector (expresscollect/Analytics/crawlers.js CATALOGUE).
    const BOTS = array(
        // Fetched because a person asked an AI about the page.
        array('ChatGPT-User', '/ChatGPT-User/i'),
        array('OAI-SearchBot', '/OAI-SearchBot/i'),
        array('Perplexity-User', '/Perplexity-User/i'),
        array('Claude-User', '/Claude-User/i'),
        array('Claude-SearchBot', '/Claude-SearchBot/i'),
        array('MistralAI-User', '/MistralAI-User/i'),
        array('MistralAI-SearchBot', '/MistralAI-SearchBot/i'),
        array('Meta-ExternalFetcher', '/meta-externalfetcher/i'),
        // Bulk collection, for training or a dataset.
        array('GPTBot', '/GPTBot/i'),
        array('ClaudeBot', '/ClaudeBot|Claude-Web/i'),
        array('anthropic-ai', '/anthropic-ai/i'),
        array('CCBot', '/CCBot/i'),
        array('Bytespider', '/Bytespider/i'),
        array('Meta-ExternalAgent', '/meta-externalagent|facebookbot/i'),
        array('Amazonbot', '/Amazonbot/i'),
        array('Diffbot', '/Diffbot/i'),
        array('omgili', '/omgili/i'),
        array('AI2Bot', '/AI2Bot/i'),
        array('Timpibot', '/Timpibot/i'),
        array('Webzio-Extended', '/Webzio-Extended/i'),
        array('PerplexityBot', '/PerplexityBot/i'),
        array('DuckAssistBot', '/DuckAssistBot/i'),
        array('YouBot', '/YouBot/i'),
        // Search engines. Google's tools before Googlebot itself.
        array('Google-InspectionTool', '/Google-InspectionTool/i'),
        array('Storebot-Google', '/Storebot-Google/i'),
        array('AdsBot-Google', '/AdsBot-Google/i'),
        array('Googlebot', '/Googlebot|Google-Site-Verification/i'),
        array('bingbot', '/bingbot|BingPreview|adidxbot/i'),
        array('YandexBot', '/Yandex(Bot|Mobile|Images|Webmaster)?/i'),
        array('Baiduspider', '/Baiduspider/i'),
        array('DuckDuckBot', '/DuckDuckBot|DuckDuckGo-Favicons/i'),
        array('Applebot', '/Applebot/i'),
        array('PetalBot', '/PetalBot|AspiegelBot/i'),
        array('SeznamBot', '/SeznamBot/i'),
        array('Yeti', '#Yeti/#i'),
        array('MojeekBot', '/MojeekBot/i'),
        array('Qwantbot', '/Qwantbot|Qwantify/i'),
        // SEO and backlink tools.
        array('AhrefsBot', '/AhrefsBot|AhrefsSiteAudit/i'),
        array('SemrushBot', '/SemrushBot|SiteAuditBot/i'),
        array('DotBot', '/DotBot/i'),
        array('MJ12bot', '/MJ12bot/i'),
        array('BLEXBot', '/BLEXBot/i'),
        array('DataForSeoBot', '/DataForSeoBot/i'),
        array('Barkrowler', '/Barkrowler/i'),
        array('ScreamingFrog', '/Screaming\s?Frog/i'),
        array('ZoominfoBot', '/ZoominfoBot/i'),
        // Link previews.
        array('facebookexternalhit', '/facebookexternalhit/i'),
        array('Twitterbot', '/Twitterbot/i'),
        array('LinkedInBot', '/LinkedInBot/i'),
        array('Slackbot', '/Slackbot|Slack-ImgProxy/i'),
        array('Discordbot', '/Discordbot/i'),
        array('TelegramBot', '/TelegramBot/i'),
        array('WhatsApp', '/WhatsApp/i'),
        array('Pinterestbot', '#Pinterest(bot)?/#i'),
        array('redditbot', '/redditbot/i'),
        // Uptime and speed checks.
        array('UptimeRobot', '/UptimeRobot/i'),
        array('Pingdom', '/Pingdom/i'),
        array('BetterUptime', '/Better\s?Uptime|betteruptime/i'),
        array('Lighthouse', '/Chrome-Lighthouse|Google Page Speed/i'),
        array('GTmetrix', '/GTmetrix/i'),
        // Archives.
        array('ia_archiver', '/ia_archiver/i'),
        array('archive.org_bot', '/archive\.org_bot|Wayback/i'),
    );

    // Anything else that names itself a bot: counted as "Other bot", so a new
    // crawler shows up as traffic instead of disappearing.
    const GENERIC = '#bot\b|crawler|crawling|spider|scrapy|curl/|wget/|python-requests|headlesschrome|http-client|okhttp|java/|go-http-client#i';

    private $core;
    private $options;

    // Options: server_name (default the host name).
    public function __construct(Core $core, array $options = array())
    {
        $this->core = $core;
        $this->options = $options + array('server_name' => function_exists('gethostname') ? gethostname() : '');
    }

    // The crawler's catalogue name, or '' when the user agent isn't one.
    public static function detect($userAgent)
    {
        $ua = (string) $userAgent;
        if ($ua === '') {
            return '';
        }
        foreach (self::BOTS as $bot) {
            if (preg_match($bot[1], $ua)) {
                return $bot[0];
            }
        }
        return preg_match(self::GENERIC, $ua) ? 'Other bot' : '';
    }

    // The response's size, when the site said so.
    private static function bytesSent()
    {
        if (!function_exists('headers_list')) {
            return 0;
        }
        foreach (headers_list() as $header) {
            if (stripos($header, 'content-length:') === 0) {
                return (int) trim(substr($header, 15));
            }
        }
        return 0;
    }

    // Records the current request when it came from a crawler (Platform calls
    // it at shutdown, so the status and size are the ones the crawler got).
    public function recordRequest($ip = '')
    {
        if (!$this->core->isOn('crawlers') || !$this->core->ensureDir()) {
            return;
        }
        $bot = self::detect(isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '');
        if ($bot === '') {
            return; // A visitor: the tracker counts those.
        }
        $started = isset($_SERVER['REQUEST_TIME_FLOAT']) ? (float) $_SERVER['REQUEST_TIME_FLOAT'] : microtime(true);
        $status = (int) http_response_code();
        $path = explode('#', explode('?', isset($_SERVER['REQUEST_URI']) ? $_SERVER['REQUEST_URI'] : '/', 2)[0], 2)[0];
        $this->core->append('crawlers', array(
            't' => time(),
            'b' => $bot,
            'p' => substr($path === '' ? '/' : $path, 0, self::MAX_PATH),
            's' => $status ?: 200,
            'd' => (int) round((microtime(true) - $started) * 1000),
            'z' => self::bytesSent(),
            'i' => (string) $ip,
        ), self::SPOOL_MAX);
    }

    public function due()
    {
        return $this->core->waiting('crawlers') && $this->core->sendDue('crawlers', self::FLUSH_EVERY);
    }

    // Adds up the recorded requests and sends them, once a minute.
    public function flush($force = false)
    {
        $this->core->drain('crawlers', self::FLUSH_EVERY, $force, function (array $recorded) {
            $rows = array();
            $agents = array();
            foreach ($recorded as $r) {
                if (!isset($r['t'], $r['b'], $r['p'], $r['s'])) {
                    continue;
                }
                $minute = (int) (floor($r['t'] / 60) * 60);
                $path = (string) $r['p'];
                $key = json_encode(array($minute, $r['b'], $path, $r['s']));
                // Past MAX_KEYS a crawler asking for thousands of URLs becomes one row.
                if (!isset($rows[$key]) && count($rows) >= self::MAX_KEYS) {
                    $path = '(other)';
                    $key = json_encode(array($minute, $r['b'], $path, $r['s']));
                }
                // And past HARD_MAX_KEYS nothing new is kept at all: the
                // "(other)" rows still split by minute, bot and status.
                if (!isset($rows[$key]) && count($rows) >= self::HARD_MAX_KEYS) {
                    continue;
                }
                if (!isset($rows[$key])) {
                    $rows[$key] = array(
                        'minute' => gmdate('Y-m-d\TH:i:s\Z', $minute), 'bot' => $r['b'], 'path' => $path,
                        'status' => (int) $r['s'], 'count' => 0, 'bytes' => 0, 'sum_ms' => 0,
                    );
                }
                $rows[$key]['count']++;
                $rows[$key]['bytes'] += isset($r['z']) ? (int) $r['z'] : 0;
                $rows[$key]['sum_ms'] += isset($r['d']) ? (int) $r['d'] : 0;
                // Up to five addresses per bot, so the collector can check it
                // is itself. They are not stored.
                if (!empty($r['i'])) {
                    if (!isset($agents[$r['b']])) {
                        $agents[$r['b']] = array();
                    }
                    if (count($agents[$r['b']]) < self::MAX_IPS_PER_BOT && !in_array($r['i'], $agents[$r['b']], true)) {
                        $agents[$r['b']][] = $r['i'];
                    }
                }
            }
            $list = array();
            foreach ($agents as $bot => $ips) {
                $list[] = array('bot' => $bot, 'ips' => $ips);
            }
            foreach (array_chunk(array_values($rows), self::MAX_ROWS) as $i => $batch) {
                $this->core->post('crawlers', '/events/crawlers', array(
                    'server_name' => substr((string) $this->options['server_name'], 0, 100),
                    'runtime' => 'PHP ' . PHP_VERSION,
                    'rows' => $batch,
                    'agents' => $i === 0 ? $list : array(),
                ));
            }
        });
    }
}
