# frozen_string_literal: true

# Crawlers module: counts the search engines and AI bots that fetch the site
# and sends one row a minute per bot, page and status to POST /events/crawlers
# (the protocol is sdk/protocols/crawlers.md). This traffic is invisible to the
# browser tracker, because crawlers don't run JavaScript: the server is the
# only place it can be counted.
#
# Only requests whose user agent names a known crawler are counted, so
# visitors are never counted twice. Nothing about a visitor is sent; bot
# addresses go with the batch only so the collector can check a crawler is
# itself, and are not stored.

module SiteGoose
  class Crawlers
    FLUSH_EVERY = 60
    MAX_KEYS = 300
    MAX_ROWS = 500
    MAX_IPS_PER_BOT = 5
    MAX_PATH = 400

    # The catalogue of the protocol, most specific first: "ChatGPT-User" must
    # be tried before "GPTBot", "Claude-User" before "ClaudeBot". Keep in step
    # with the collector (expresscollect/Analytics/crawlers.js CATALOGUE).
    BOTS = [
      # Fetched because a person asked an AI about the page.
      ["ChatGPT-User", "ChatGPT-User"],
      ["OAI-SearchBot", "OAI-SearchBot"],
      ["Perplexity-User", "Perplexity-User"],
      ["Claude-User", "Claude-User"],
      ["Claude-SearchBot", "Claude-SearchBot"],
      ["MistralAI-User", "MistralAI-User"],
      ["MistralAI-SearchBot", "MistralAI-SearchBot"],
      ["Meta-ExternalFetcher", "meta-externalfetcher"],
      # Bulk collection, for training or a dataset.
      ["GPTBot", "GPTBot"],
      ["ClaudeBot", "ClaudeBot|Claude-Web"],
      ["anthropic-ai", "anthropic-ai"],
      ["CCBot", "CCBot"],
      ["Bytespider", "Bytespider"],
      ["Meta-ExternalAgent", "meta-externalagent|facebookbot"],
      ["Amazonbot", "Amazonbot"],
      ["Diffbot", "Diffbot"],
      ["omgili", "omgili"],
      ["AI2Bot", "AI2Bot"],
      ["Timpibot", "Timpibot"],
      ["Webzio-Extended", "Webzio-Extended"],
      ["PerplexityBot", "PerplexityBot"],
      ["DuckAssistBot", "DuckAssistBot"],
      ["YouBot", "YouBot"],
      # Search engines. Google's tools before Googlebot itself.
      ["Google-InspectionTool", "Google-InspectionTool"],
      ["Storebot-Google", "Storebot-Google"],
      ["AdsBot-Google", "AdsBot-Google"],
      ["Googlebot", "Googlebot|Google-Site-Verification"],
      ["bingbot", "bingbot|BingPreview|adidxbot"],
      ["YandexBot", "Yandex(Bot|Mobile|Images|Webmaster)?"],
      ["Baiduspider", "Baiduspider"],
      ["DuckDuckBot", "DuckDuckBot|DuckDuckGo-Favicons"],
      ["Applebot", "Applebot"],
      ["PetalBot", "PetalBot|AspiegelBot"],
      ["SeznamBot", "SeznamBot"],
      ["Yeti", "Yeti/"],
      ["MojeekBot", "MojeekBot"],
      ["Qwantbot", "Qwantbot|Qwantify"],
      # SEO and backlink tools.
      ["AhrefsBot", "AhrefsBot|AhrefsSiteAudit"],
      ["SemrushBot", "SemrushBot|SiteAuditBot"],
      ["DotBot", "DotBot"],
      ["MJ12bot", "MJ12bot"],
      ["BLEXBot", "BLEXBot"],
      ["DataForSeoBot", "DataForSeoBot"],
      ["Barkrowler", "Barkrowler"],
      ["ScreamingFrog", "Screaming\\s?Frog"],
      ["ZoominfoBot", "ZoominfoBot"],
      # Link previews.
      ["facebookexternalhit", "facebookexternalhit"],
      ["Twitterbot", "Twitterbot"],
      ["LinkedInBot", "LinkedInBot"],
      ["Slackbot", "Slackbot|Slack-ImgProxy"],
      ["Discordbot", "Discordbot"],
      ["TelegramBot", "TelegramBot"],
      ["WhatsApp", "WhatsApp"],
      ["Pinterestbot", "Pinterest(bot)?/"],
      ["redditbot", "redditbot"],
      # Uptime and speed checks.
      ["UptimeRobot", "UptimeRobot"],
      ["Pingdom", "Pingdom"],
      ["BetterUptime", "Better\\s?Uptime|betteruptime"],
      ["Lighthouse", "Chrome-Lighthouse|Google Page Speed"],
      ["GTmetrix", "GTmetrix"],
      # Archives.
      ["ia_archiver", "ia_archiver"],
      ["archive.org_bot", "archive\\.org_bot|Wayback"]
    ].map { |name, pattern| [name, Regexp.new(pattern, Regexp::IGNORECASE)] }.freeze

    # Anything else that names itself a bot: counted as "Other bot", so a new
    # crawler shows up as traffic instead of disappearing.
    GENERIC = Regexp.new(
      "bot\\b|crawler|crawling|spider|scrapy|curl/|wget/|python-requests|headlesschrome|http-client|okhttp|java/|go-http-client",
      Regexp::IGNORECASE
    )

    # The crawler's catalogue name, or "" when the user agent isn't one.
    def self.detect(user_agent)
      ua = SiteGoose.text(user_agent)
      return "" if ua.empty?

      BOTS.each { |name, pattern| return name if pattern.match?(ua) }
      GENERIC.match?(ua) ? "Other bot" : ""
    end

    attr_reader :rows, :agents

    # Options: server_name (default the host name).
    def initialize(core, server_name: nil, **_)
      @core = core
      @server_name = SiteGoose.text(server_name || SiteGoose.hostname, 100)
      @rows = {}
      @agents = {}
      @lock = Mutex.new
      @job = core.valid? ? Periodic.new(FLUSH_EVERY) { flush(everything: false); FLUSH_EVERY } : nil
      Forking.register(self)
    end

    def after_fork_in_child
      @lock = Mutex.new
      @rows = {}
      @agents = {}
    end

    # One finished request from a crawler. bot: Crawlers.detect(user_agent).
    def record(bot, path, status, ms = 0, size = 0, ip = "")
      return if bot.to_s.empty? || !@core.on?("crawlers")

      clean = SiteGoose.text(path.to_s.empty? ? "/" : path).split(/[?#]/, 2)[0].to_s
      clean = "/" if clean.empty?
      clean = clean[0, MAX_PATH]
      minute = (Time.now.to_i / 60) * 60
      @lock.synchronize do
        key = [minute, bot, clean, status.to_i]
        # Past MAX_KEYS a crawler asking for thousands of URLs becomes one row.
        key = [minute, bot, "(other)", status.to_i] if !@rows.key?(key) && @rows.size >= MAX_KEYS
        return if !@rows.key?(key) && @rows.size >= MAX_KEYS + 100

        row = (@rows[key] ||= { count: 0, bytes: 0, sum_ms: 0 })
        row[:count] += 1
        row[:bytes] += [0, size.to_i].max
        row[:sum_ms] += [0, ms.to_i].max
        unless ip.to_s.empty?
          seen = (@agents[bot] ||= [])
          seen << ip.to_s if seen.size < MAX_IPS_PER_BOT && !seen.include?(ip.to_s)
        end
      end
    end

    # Records a finished request when it came from a crawler.
    def middleware(user_agent, path, status, ms = 0, size = 0, ip = "")
      record(Crawlers.detect(user_agent), path, status, ms, size, ip)
    end

    def flush(everything: true)
      current = (Time.now.to_i / 60) * 60
      ready, agents = @lock.synchronize do
        taken = @rows.select { |k, _| everything || k[0] < current }
        taken.each_key { |k| @rows.delete(k) }
        sent = taken.keys.map { |k| k[1] }.uniq
        list = @agents.select { |bot, _| sent.include?(bot) }.map { |bot, ips| { "bot" => bot, "ips" => ips.dup } }
        unless taken.empty?
          # A bot with rows still waiting (this minute isn't over) keeps its
          # addresses, so the next batch can be checked as well.
          waiting = @rows.keys.map { |k| k[1] }.uniq
          @agents = @agents.select { |bot, _| waiting.include?(bot) }
        end
        [taken, list]
      end
      rows = ready.map do |k, v|
        { "minute" => Time.at(k[0]).utc.iso8601(3), "bot" => k[1], "path" => k[2], "status" => k[3],
          "count" => v[:count], "bytes" => v[:bytes], "sum_ms" => v[:sum_ms] }
      end
      rows.each_slice(MAX_ROWS).with_index do |batch, i|
        @core.request("crawlers", "/events/crawlers", body: {
                        "server_name" => @server_name, "runtime" => RUNTIME,
                        "rows" => batch, "agents" => i.zero? ? agents : []
                      })
      end
    end

    def close
      @job&.stop
      Forking.unregister(self)
      flush
    end
  end
end
