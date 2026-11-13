# frozen_string_literal: true

# First-party proxy: serving the tracker from the site's own domain, so ad
# blockers don't hide visitors.
#
# Blockers stop analytics by recognising the address a script comes from and
# what it is called ("track.js", "collect"). This app is already a server on
# the site's domain, so the package serves both itself:
#
#     <prefix>/js/<rest>   ->  <endpoint>/<rest>                  (tracker files)
#     <prefix>/api/<rest>  ->  <endpoint>/collectanalytics/<rest> (the collector)
#
# The same two rules as the hand-written Nginx/Cloudflare ones, so one install
# check covers both. The prefix comes from the site secret: not guessable from
# the page, and the same every time, so a browser's cache and a CDN in front
# stay valid. It answers before every other module: a visitor's beacon is our
# own traffic, not a page of the site, so it isn't counted, timed or rate-limited.

require "digest"
require "net/http"
require "uri"

module SiteGoose
  class Proxy
    # The tracker files, by name: anything else is refused rather than forwarded.
    FILES = %w[track.js s.js snapshot.js replay.js survey.js banner.js leadform.js notice.js editor.js picker.js
               feedback.js shield.js widget.js share.js].freeze
    # A pinned version never changes; /v<major>/ follows new releases, so it is
    # held for an hour, the same as the collector serves it with.
    TTL_PINNED_S = 7 * 24 * 60 * 60
    TTL_MAJOR_S = 60 * 60
    MAX_BODY = 6 * 1024 * 1024
    # The collector reads these; everything else, cookies above all, stays here.
    PASS_HEADERS = %w[content-type user-agent accept-language referer origin sec-fetch-site sec-ch-ua
                      sec-ch-ua-mobile sec-ch-ua-platform].freeze
    # What a collector answer may be served as from the site's own domain. Its
    # type comes from the collector, so anything else becomes plain text, and
    # nosniff stops a browser guessing: a server that is no longer ours still
    # can't answer <prefix>/api/... with a page that runs as the customer's own
    # site. Shared cases: sdk/protocols/proxy-answer-cases.json.
    ANSWER_TYPES = %w[application/json text/plain image/webp].freeze

    def self.answer_type(value)
      given = value.is_a?(String) ? value : ""
      kind = given.split(";", 2).first.to_s.strip.downcase
      ANSWER_TYPES.include?(kind) && given.match?(/\A[\x20-\x7e]*\z/) ? given : "text/plain; charset=utf-8"
    end

    SAFE_PATH = %r{\A[A-Za-z0-9/_.-]{1,120}\z}.freeze
    FILE_PATH = %r{\Av(\d+(?:\.\d+\.\d+)?)/([a-z]+\.js)\z}.freeze
    # These run on the app's own request threads, so they are short, and a
    # collector that stops answering is left alone for a while rather than
    # costing every beacon a timeout: a black-holed collector must not use
    # up Puma's threads.
    CONNECT_TIMEOUT = 1
    READ_TIMEOUT = 2
    BREAKER_FAILURES = 3
    BREAKER_OPEN_S = 30
    # A tracker file that couldn't be fetched isn't asked for again this soon.
    FILE_RETRY_S = 30

    def self.not_found
      [404, { "content-type" => "text/plain; charset=utf-8" }, "Not found"]
    end

    def self.prefix_for(secret)
      Digest::SHA256.hexdigest("proxy|#{secret}")[0, 8]
    end

    # Sent as X-Proxy-Key, so the collector believes the visitor addresses
    # this proxy passes on: anyone can write X-Forwarded-For. Worked out from
    # the secret as the collector does (expresscollect/utils/proxyKey.js).
    def self.key_for(secret)
      Digest::SHA256.hexdigest("proxykey|#{secret}")[0, 32]
    end

    attr_reader :prefix, :key

    # prefix: the path it answers on (default: from the secret).
    def initialize(core, prefix: nil, enabled: true, **_)
      @core = core
      @enabled = enabled
      @prefix = (prefix || Proxy.prefix_for(core.secret)).to_s.gsub(/[^A-Za-z0-9_-]/, "")
      @key = core.secret.empty? ? "" : Proxy.key_for(core.secret)
      # One copy of each tracker file, so a repeat visitor costs no upstream
      # request. A handful of small files: it never grows.
      @files = {}
      @failed = {}
      @lock = Mutex.new
      @failures = 0
      @open_until = 0.0
    end

    # True while the collector is being left alone (after BREAKER_FAILURES
    # failures in a row). When the pause ends one request tries again; the
    # others keep the short answer until it has.
    def resting?
      now = SiteGoose.clock
      @lock.synchronize do
        next false if @failures < BREAKER_FAILURES
        next true if now < @open_until

        @open_until = now + READ_TIMEOUT + CONNECT_TIMEOUT
        false
      end
    end

    def worked
      @lock.synchronize { @failures = 0 }
    end

    def failed
      @lock.synchronize do
        @failures += 1
        @open_until = SiteGoose.clock + BREAKER_OPEN_S if @failures >= BREAKER_FAILURES
      end
    end

    def on?
      @enabled && @core.valid? && !@prefix.empty? && @core.on?("proxy")
    end

    # The tracker's address on this site, for the page's script tag.
    def script_url(version = "1")
      "/#{@prefix}/js/v#{version}/s.js"
    end

    # Where visits are sent, for the tag's data-collect.
    def collect_url
      "/#{@prefix}/api/e"
    end

    # [kind ("js" | "api" | "bad"), the rest] when the address is ours, else nil.
    def match(path)
      return nil unless on?

      head = "/#{@prefix}/"
      path = path.to_s
      return nil unless path.start_with?(head)

      rest = path[head.size..]
      %w[js api].each do |kind|
        next unless rest.start_with?("#{kind}/")

        tail = rest[(kind.size + 1)..]
        return [kind, tail] if !tail.empty? && !tail.include?("..") && tail.match?(SAFE_PATH)

        break
      end
      ["bad", ""]
    end

    # [status, headers, body]. Blocking (up to the timeout).
    def handle(kind, rest, method: "GET", query: "", headers: {}, body: nil, client_ip: "")
      return file(rest) if kind == "js"
      return Proxy.not_found unless kind == "api"

      collector(rest, method, query, headers || {}, body, client_ip)
    end

    def fetch(url, method: "GET", headers: {}, body: nil)
      uri = URI.parse(url)
      klass = method == "POST" ? Net::HTTP::Post : Net::HTTP::Get
      req = klass.new(uri.request_uri, headers)
      req.body = body if body && method == "POST"
      Forking.sending do
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = uri.scheme == "https"
        http.open_timeout = CONNECT_TIMEOUT
        http.read_timeout = READ_TIMEOUT
        http.write_timeout = READ_TIMEOUT if http.respond_to?(:write_timeout=)
        http.start { |h| h.request(req) }
      end
    end

    # Any version number fits the file pattern, so the list is kept short.
    def remember_failure(rest)
      @lock.synchronize do
        @failed.delete(rest)
        @failed.shift while @failed.size >= 200
        @failed[rest] = SiteGoose.clock
      end
    end

    def file(rest)
      found = FILE_PATH.match(rest)
      return Proxy.not_found if found.nil? || !FILES.include?(found[2])

      pinned = found[1].include?(".")
      held = @lock.synchronize { @files[rest] }
      body = nil
      body = held[0] if held && held[1] > Time.now.to_f - (pinned ? TTL_PINNED_S : TTL_MAJOR_S)
      recently_failed = @lock.synchronize { (at = @failed[rest]) && at > SiteGoose.clock - FILE_RETRY_S }
      if body.nil? && !recently_failed && !resting?
        begin
          answer = fetch("#{@core.endpoint}/#{rest}")
          fetched = answer.body.to_s
          answer.code.to_i >= 500 ? failed : worked
          if answer.code.to_i == 200 && fetched.bytesize > 500 && fetched.bytesize <= MAX_BODY
            body = fetched
            @lock.synchronize do
              @files[rest] = [body, Time.now.to_f]
              @failed.delete(rest)
            end
          else
            remember_failure(rest)
          end
        rescue StandardError, Timeout::Error => e
          failed
          remember_failure(rest)
          @core.log("proxy", "could not fetch #{rest}: #{e.message}")
        end
      end
      # Upstream is unreachable: an old copy beats no tracker at all.
      body = held[0] if body.nil? && held
      return [502, {}, ""] if body.nil?

      [200, {
        "content-type" => "application/javascript; charset=utf-8",
        "cache-control" => pinned ? "public, max-age=31536000, immutable" : "public, max-age=3600",
        "x-content-type-options" => "nosniff"
      }, body]
    end

    def collector(rest, method, query, headers, body, client_ip)
      method = (method.to_s.empty? ? "GET" : method.to_s).upcase
      if method == "OPTIONS"
        # Same origin as the page, so a preflight shouldn't happen; answer it
        # cheaply rather than passing it on.
        return [204, { "access-control-allow-methods" => "GET, POST, OPTIONS", "access-control-allow-headers" => "Content-Type",
                       "access-control-max-age" => "86400" }, ""]
      end
      return Proxy.not_found unless %w[GET POST].include?(method)
      return [413, {}, ""] if body && body.bytesize > MAX_BODY

      # The visitor's address: the collector needs it for the country, the
      # daily visitor ID and the per-visitor rate limit.
      out = { "X-Forwarded-For" => client_ip.to_s }
      out["X-Proxy-Key"] = @key unless @key.empty?
      PASS_HEADERS.each do |name|
        value = headers[name]
        next if value.nil? || value.to_s.empty?

        out[name.split("-").map(&:capitalize).join("-")] = value.to_s.delete("\r\n")
      end
      url = "#{@core.endpoint}/collectanalytics/#{rest}#{query.to_s.empty? ? '' : "?#{query}"}"
      # Left alone for now: answered straight away; the tracker treats a
      # failed beacon as lost and carries on.
      return [502, { "retry-after" => BREAKER_OPEN_S.to_s }, ""] if resting?

      begin
        answer = fetch(url, method: method, headers: out, body: method == "POST" ? body.to_s : nil)
        answer.code.to_i >= 500 ? failed : worked
        passed = { "content-type" => Proxy.answer_type(answer["content-type"]), "x-content-type-options" => "nosniff" }
        %w[cache-control retry-after].each do |name|
          value = answer[name]
          passed[name] = value if value && !value.empty?
        end
        text = answer.body.to_s
        [answer.code.to_i, passed, text.bytesize > MAX_BODY ? text.byteslice(0, MAX_BODY) : text]
      rescue StandardError, Timeout::Error => e
        # The tracker already treats a failed beacon as lost and carries on.
        failed
        @core.log("proxy", "could not reach the collector: #{e.message}")
        [502, {}, ""]
      end
    end

    def flush; end

    def close; end
  end
end
