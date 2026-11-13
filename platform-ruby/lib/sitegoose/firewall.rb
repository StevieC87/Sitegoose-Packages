# frozen_string_literal: true

# Firewall module: rules from the collector (GET /events/firewall/rules,
# protocol in sdk/protocols/firewall.md) every minute or so; every request is
# checked against them in memory, so the app never waits on the collector.
# What was blocked (or, in monitor mode, would have been) goes back in batches.
#
# Fails open: until rules arrive, and whenever the collector can't be reached,
# requests pass (with the last rules that arrived, if any). The rate limit
# counts in this process: with several workers, pass `counter` (e.g. Redis)
# for one count across them.

require "json"

module SiteGoose
  class Firewall
    PROTOCOL = 1
    FLUSH_EVERY = 5
    BATCH = 200
    QUEUE_MAX = 2000
    COUNTER_MAX = 100_000
    # The layers this server runs (X-Firewall-Layers): the address firewall and the browser check.
    LAYERS = "app check"
    # Files a page load asks for by the dozen: not counted against `rate` or
    # the page limits (the agent's nginx limit leaves the same extensions
    # out). The extension follows a name in the last segment, not starts it:
    # "/login/.css" is no file. Matched on the lower-cased path.
    STATIC = %r{/[^/.][^/]*\.(?:css|js|mjs|map|png|jpe?g|gif|webp|avif|svg|ico|bmp|woff2?|ttf|otf|eot|mp4|webm|ogg|mp3|wav|pdf|wasm)\z}.freeze
    STATIC_PREFIXES = %w[/assets/ /packs/ /vite/ /static/ /_next/static/].freeze
    # In a path decoded once: a "%xx" still there (double encoding, which a
    # router that decodes again reads differently), a ";" (a path parameter
    # to some servers and proxies, part of the name to others), a "\\" (a
    # "/" to some), a "?" or "#" that was encoded, or a control character.
    STATIC_UNSURE = /%[0-9a-fA-F]{2}|[;\\?#\x00-\x1f\x7f]/.freeze
    # Only GET and HEAD fetch a file: a form posts to a page. No method given reads as GET.
    FETCHES = ["", "GET", "HEAD"].freeze
    # Rails' own controllers for uploaded files: an image on a page is a
    # request to them (and a redirect from them), 40 on a product list.
    FILE_CONTROLLERS = %r{\A(?:active_storage|action_text)/}.freeze
    # Page limits (firewall.md, "Page limits"): at most this many, ids as a request rule's.
    MAX_LIMITS = 50
    LIMIT_ID = /\A[a-z][a-z0-9_.-]{1,39}\z/.freeze
    # What a visitor over a blocking page limit reads, with its 429.
    LIMIT_BODY = "Too many requests to this page. Please wait a little and try again."

    attr_reader :pass_key, :queue, :bans
    attr_accessor :rules, :etag

    # The rules' probes (addresses of files no visitor asks for: .env,
    # .git/...) -> {exact:, prefix:, ban:}, or nil.
    def self.compile_probes(probes)
      return nil unless probes.is_a?(Hash)

      paths = ->(key) { Array(probes[key]).select { |p| p.is_a?(String) && !p.empty? }.map(&:downcase) }
      exact = paths.call("exact").to_h { |p| [p, true] }
      prefix = paths.call("prefix")
      return nil if exact.empty? && prefix.empty?

      ban = probes["ban"].is_a?(Numeric) ? [0, probes["ban"].to_i].max : 0
      { exact: exact, prefix: prefix, ban: ban }
    end

    # A file a page loads with itself, by its extension or its folder
    # (firewall.md, `rate`), read from the target as sent decoded once, as
    # the router reads PATH_INFO, lower case, "//" as "/". Only a path every
    # router reads the same way can be a file: one with a "." or ".."
    # segment, a ";", a "\\", an encoded "/" or a "%xx" left after decoding
    # is a page, so "/static/../login", "/static%2F..%2Flogin",
    # "/login;x.css" and "/login%3Bx.css" all count. A browser asks for its
    # files with none of those. Nor is a path past the rules' 2,000
    # characters: cut there, "/search/xxx...x.css/more" would end in .css and
    # flood a catch-all route past the limits.
    def self.static?(target, method = "")
      return false unless FETCHES.include?(method.to_s)

      raw = target.to_s.split(/[?#]/, 2).first.to_s
      return false if raw.length > RequestRules::MAX_TEXT || !raw.start_with?("/") || raw.match?(/%2f/i)

      decoded = RequestRules.decode_once(raw)
      return false if decoded.match?(STATIC_UNSURE)

      # A-Z only, as every package: "İ" is "i" lower-cased by some.
      segments = decoded.tr("A-Z", "a-z").split("/", -1)
      return false if segments.include?(".") || segments.include?("..")

      parts = segments.reject(&:empty?)
      path = "/#{parts.join('/')}"
      path += "/" if !parts.empty? && segments.last.empty? # "/app.css/" isn't a file
      STATIC_PREFIXES.any? { |prefix| path.start_with?(prefix) } || path.match?(STATIC)
    end

    # Who the rate limit, the login count and the bans here are about: an
    # IPv4 address (::ffff:a.b.c.d as a.b.c.d), or an IPv6 address's /64,
    # which one machine usually holds whole -- as the browser check binds.
    #
    # Written the same way by every package, so a site whose servers run
    # different languages on one Redis counts a visitor once: "198.51.100.7",
    # or the /64 as its network, RFC 5952 (lower-case, compressed):
    # "2001:db8:1:2::/64". The browser check's pass binds its own way
    # (Challenge.who), which this doesn't change.
    def self.who(ip)
      key = IP.key(ip)
      return ip.to_s if key.nil?
      return IPAddr.new(key & 0xFFFF_FFFF, Socket::AF_INET).to_s if (key >> 32) == 0xFFFF

      "#{IPAddr.new((key >> 64) << 64, Socket::AF_INET6)}/64"
    end

    # True when the path (no query, lower-cased, "//" as "/") is a probe, as
    # sent or as the router reads it (";params" dropped, "." and ".."
    # resolved, decoded once: "/x/..;/.env" is "/.env").
    def self.probe?(path, probes)
      return false unless probes

      clean = SiteGoose.text(path).split(/[?#]/, 2)[0].to_s.downcase.gsub(%r{/{2,}}, "/")
      [clean, RequestRules.normalize_target(path)].uniq.any? do |text|
        probes[:exact].key?(text) || probes[:prefix].any? { |p| text.start_with?(p) }
      end
    end

    # The rules' page limits -> {exempt:, rules:}, or nil when there are none.
    # A limit that doesn't parse is left out, not the others: a bad id, a
    # limit outside 1-100,000, a window outside 1-3,600 seconds, or nothing to
    # match on. Sections are matched as a request rule's, without `regex`, so
    # the agent's nginx can carry the same limit; a section with a regex only
    # is no section.
    def self.compile_limits(data)
      return nil unless data.is_a?(Hash) && data["rules"].is_a?(Array)

      rules = data["rules"].first(MAX_LIMITS).filter_map do |rule|
        next unless rule.is_a?(Hash) && rule["id"].is_a?(String) && rule["id"].match?(LIMIT_ID)

        limit = rule["limit"]
        window = rule["window"]
        next unless limit.is_a?(Integer) && limit.between?(1, 100_000) && window.is_a?(Integer) && window.between?(1, 3600)

        methods = rule["methods"]
        compiled = {
          "id" => rule["id"],
          "action" => rule["action"] == "block" ? "block" : "monitor",
          "limit" => limit,
          "window" => window,
          "each" => rule["each"] == "path",
          "methods" => methods.is_a?(Array) ? methods.select { |m| m.is_a?(String) }.map(&:upcase) : []
        }
        %w[path query].each do |name|
          part = rule[name].is_a?(Hash) ? RequestRules.section(rule[name].except("regex")) : nil
          compiled[name] = part if part
        end
        compiled if compiled["path"] || compiled["query"]
      end
      return nil if rules.empty?

      { exempt: IpSet.new(Array(data["exempt"])), rules: rules }
    end

    # The rules' browser check -> {skip:, exempt:}, or nil when the site isn't to be checked.
    def self.compile_challenge(data)
      return nil unless data.is_a?(Hash)

      { skip: Challenge.compile_skip(data["skip"]), exempt: IpSet.new(Array(data["exempt"])) }
    end

    # This machine's host name for X-Server-Name: plain ASCII, 100 characters at most.
    def self.server_name
      SiteGoose.hostname.gsub(/[^\x21-\x7e]/, "")[0, 100]
    end

    def self.int(value, fallback = 0)
      value.is_a?(Numeric) ? value.to_i : (value.is_a?(String) && value.match?(/\A\d+\z/) ? value.to_i : fallback)
    end

    # Options: trust_proxy, mode ("monitor"/"block": overrides the dashboard),
    # counter (callable(key, ttl) -> hits, shared between workers), cache_file
    # (rules kept there between restarts).
    def initialize(core, trust_proxy: nil, mode: nil, counter: nil, cache_file: nil, **_)
      @core = core
      @trust_proxy = trust_proxy
      @mode = %w[monitor block].include?(mode.to_s) ? mode.to_s : nil
      @counter = counter
      @cache_file = cache_file
      @rules = nil
      @etag = ""
      @lock = Mutex.new
      @counts = {}
      # Page limits: "id window who" -> [window start, hits]. Limits with
      # each: "path" ("id window who path") count in a table of their own:
      # one entry per address and page fills a table fast, and making room
      # there mustn't start the login limit's counts again mid-window.
      @limit_counts = {}
      @path_counts = {}
      # With a shared counter: the counts this process saw go over (their
      # key, window and all), so a static file asked for after them can be
      # turned away without adding to them (check, `peek`).
      @over_noted = {}
      @queue = {}
      # Bot protection here: address -> when its ban ends; address -> [window start, failed logins].
      @bans = {}
      @logins = {}
      # The browser check's passes are signed with the site secret, so any of
      # the site's servers accepts one another handed out.
      @pass_key = Challenge.pass_key(core.secret)
      load_cache
      @jobs = []
      return unless core.valid?

      @jobs = [Periodic.new { sync }, Periodic.new(FLUSH_EVERY) { flush; FLUSH_EVERY }]
      Forking.register(self)
    end

    def load_cache
      return unless @cache_file && File.exist?(@cache_file)

      cached = JSON.parse(File.read(@cache_file))
      @rules = compile(cached["rules"])
      @etag = cached["etag"].to_s
    rescue StandardError
      nil
    end

    def after_fork_in_child
      @lock = Mutex.new
      @queue = {}
    end

    def compile(data)
      raise ArgumentError, "unknown rules version" unless data.is_a?(Hash) && data["v"] == PROTOCOL

      rate = data["rate"].is_a?(Hash) ? data["rate"] : nil
      rate = if rate && Firewall.int(rate["limit"]).positive?
               { limit: Firewall.int(rate["limit"]), window: [1, Firewall.int(rate["window"], 60).nonzero? || 60].max }
             end
      login = data["login"].is_a?(Hash) && Firewall.int(data["login"]["limit"]).positive? ? data["login"] : nil
      {
        enabled: data["enabled"] == true,
        mode: data["mode"] == "block" ? "block" : "monitor",
        sync: [MIN_SYNC, Firewall.int(data["sync"], RETRY).nonzero? || RETRY].max,
        allow: IpSet.new(Array(data["allow"])),
        # Crawlers the rate limit must not catch (absent in older rules).
        goodbots: IpSet.new(Array(data["goodbots"])),
        deny: IpSet.new(Array(data["deny"])),
        list: IpSet.new(Array(data["lists"])),
        shared: IpSet.new(Array(data["shared"])),
        rate: rate,
        banned: IpSet.new(Array(data["banned"])),
        ban: data["ban"].is_a?(Hash) ? Firewall.int(data["ban"]["seconds"]) : 0,
        login: login,
        probes: Firewall.compile_probes(data["probes"]),
        # Virtual patching: rules that match the request, not the address.
        requests: RequestRules.compile(data["requests"]),
        # Page limits: caps on one kind of request (absent in older rules).
        limits: Firewall.compile_limits(data["limits"]),
        # The browser check: present only when the site is to be checked.
        challenge: Firewall.compile_challenge(data["challenge"])
      }
    end

    def sync
      headers = { "X-Firewall-Layers" => LAYERS }
      name = Firewall.server_name
      headers["X-Server-Name"] = name unless name.empty?
      headers["If-None-Match"] = @etag unless @etag.empty?
      res = @core.request("firewall", "/events/firewall/rules?site_id=#{@core.site_id}", method: "GET", auth: :bearer, headers: headers)
      if res && res.status == 200
        data = res.json
        begin
          @rules = compile(data)
          @etag = res.headers["etag"].to_s
          write_cache(data) if @cache_file
        rescue StandardError => e
          @core.log("firewall", "rules not used:", e.message)
        end
      end
      @rules ? @rules[:sync] : RETRY
    end

    # Written beside the file and renamed over it, so a crash or a second
    # worker writing at once never leaves half a file to load.
    def write_cache(data)
      temp = "#{@cache_file}.#{Process.pid}.#{Thread.current.object_id}.tmp"
      File.write(temp, JSON.generate({ "etag" => @etag, "rules" => data }))
      File.rename(temp, @cache_file)
    rescue StandardError => e
      File.delete(temp) rescue nil # rubocop:disable Style/RescueModifier
      @core.log("firewall", "rules not kept in the cache file:", e.message)
    end

    # peek: only compared with the count so far, nothing added (a static file).
    def over_rate?(ip, rate, peek: false)
      who = Firewall.who(ip)
      window = (Time.now.to_f / rate[:window]).floor
      if @counter
        name = "afw:#{@core.site_id}:#{who}:#{window}"
        return @over_noted.key?(name) if peek

        return note_over(name, @counter.call(name, rate[:window] * 2).to_i > rate[:limit])
      end
      if peek
        entry = @counts[who]
        return !entry.nil? && entry[0] == window && entry[1] > rate[:limit]
      end

      @lock.synchronize do
        entry = @counts[who]
        if entry.nil? || entry[0] != window
          # Taken out and put back, so the hash runs oldest window first and
          # a full table loses the addresses that went quiet longest ago.
          @counts.delete(who)
          Firewall.make_room(@counts)
          entry = [window, 0]
          @counts[who] = entry
        end
        entry[1] += 1
        entry[1] > rate[:limit]
      end
    end

    # Counts the request toward every page limit it matches (firewall.md,
    # step 6) and returns those now over their count, in the order sent.
    # Every matching limit counts, not just the first, so one that is over
    # can't hide the requests another one should see. A fixed window per
    # limit, as `rate`; `each: "path"` keeps a count per page (the routed
    # path), which stays here: one key per page in a shared counter would
    # be as many keys as a crawler can make up.
    # peek: as over_rate?'s.
    def over_limits(ip, limits, req, peek: false)
      who = Firewall.who(ip)
      now = Time.now.to_f
      limits.select do |limit|
        next false unless RequestRules.matches?(limit, req)

        window = (now / limit["window"]).floor
        if @counter && !limit["each"]
          name = "afw:#{@core.site_id}:l:#{limit['id']}:#{who}:#{window}"
          next @over_noted.key?(name) if peek

          next note_over(name, @counter.call(name, limit["window"] * 2).to_i > limit["limit"])
        end

        key = "#{limit['id']} #{limit['window']} #{who}#{limit['each'] ? " #{req[:routed_path]}" : ''}"
        table = limit["each"] ? @path_counts : @limit_counts
        if peek
          entry = table[key]
          next !entry.nil? && entry[0] == window && entry[1] > limit["limit"]
        end

        @lock.synchronize do
          entry = table[key]
          if entry.nil? || entry[0] != window
            # Oldest first, as the rate counters: a full table loses the counts that went quiet longest ago.
            table.delete(key)
            Firewall.make_room(table)
            entry = [window, 0]
            table[key] = entry
          end
          entry[1] += 1
          entry[1] > limit["limit"]
        end
      end
    end

    # A shared count seen over: noted under its key (window and all, so an
    # old one never matches again), for a static file's peek. -> over.
    def note_over(name, over)
      if over
        @lock.synchronize do
          Firewall.make_room(@over_noted) unless @over_noted.key?(name)
          @over_noted[name] = true
        end
      end
      over
    end

    # A table of addresses at COUNTER_MAX loses its oldest entries (insertion
    # order), not everyone's count at once.
    def self.make_room(table)
      table.shift while table.size >= COUNTER_MAX
    end

    def banned_here?(ip)
      who = Firewall.who(ip)
      ends = @bans[who]
      return false unless ends
      return true if ends > Time.now.to_f

      @lock.synchronize { @bans.delete(who) }
      false
    end

    def ban_here(ip, seconds)
      return unless seconds.positive?

      who = Firewall.who(ip)
      @lock.synchronize do
        ends = [@bans.delete(who) || 0, Time.now.to_f + seconds].max
        Firewall.make_room(@bans)
        @bans[who] = ends
      end
    end

    # A failed login on your site: counted here (past the site's limit the
    # address is banned straight away) and reported, so it counts on the
    # Security page and gets banned on the other servers too.
    def login_failed(ip)
      key = IP.key(ip)
      rules = @rules
      return if key.nil? || (rules && rules[:allow].has?(key))

      login = rules && rules[:login]
      if login
        now = Time.now.to_f
        window = Firewall.int(login["window"], 3600).nonzero? || 3600
        who = Firewall.who(ip)
        reached = @lock.synchronize do
          entry = @logins[who]
          if entry.nil? || now - entry[0] >= window
            @logins.delete(who)
            Firewall.make_room(@logins)
            entry = @logins[who] = [now, 0]
          end
          entry[1] += 1
          hit = entry[1] >= Firewall.int(login["limit"])
          @logins.delete(who) if hit
          hit
        end
        ban_here(ip.to_s, Firewall.int(login["ban"], 3600).nonzero? || 3600) if reached
      end
      report({ "ip" => ip.to_s, "rule" => "login", "action" => "monitor", "method" => "", "path" => "", "user_agent" => "" })
    end

    def report(event)
      key = event.values_at("ip", "rule", "action", "method", "path").join("|")
      @lock.synchronize do
        row = @queue[key]
        if row
          row["hits"] += 1
        elsif @queue.size < QUEUE_MAX
          @queue[key] = event.merge("at" => SiteGoose.iso_now, "hits" => 1)
        end
      end
    end

    def flush
      rows = @lock.synchronize do
        taken = @queue.values
        @queue = {}
        taken
      end
      rows.each_slice(BATCH) do |batch|
        @core.request("firewall", "/events/firewall/events", auth: :bearer, body: { "site_id" => @core.site_id, "events" => batch })
      end
    end

    # -> {action: "allow" | "block" | "monitor", rule:, status:}. Allowed
    # addresses skip every other rule. accept and cookie (the request's
    # headers) are for the browser check: rule "challenge", status 503,
    # answered with challenge_page().
    def check(ip, method = "", path = "", user_agent = "", accept = "", cookie = "", now = nil)
      allow = { action: "allow", rule: "", status: 200 }
      rules = @rules
      return allow if rules.nil? || !rules[:enabled]

      key = IP.key(ip)
      return allow if key.nil? || rules[:allow].has?(key)

      ip = ip.to_s
      action = (@mode || rules[:mode]) == "block" ? "block" : "monitor"
      event = lambda do |name, act|
        { "ip" => ip, "rule" => name, "action" => act, "method" => SiteGoose.text(method, 10),
          "path" => SiteGoose.text(path).split("?", 2)[0].to_s[0, 300], "user_agent" => SiteGoose.text(user_agent, 300) }
      end
      rule = address_rule(rules, key, ip)
      if rule.empty? && Firewall.probe?(path, rules[:probes])
        rule = "probe"
        # Asking for a secret file: banned here in block mode; the report bans it on the other servers.
        ban_here(ip, rules[:probes][:ban]) if action == "block"
      end
      limits = rules[:limits]
      req = RequestRules.prepare(method, path, user_agent) if rule.empty? && (!rules[:requests].empty? || limits)
      if rule.empty?
        matched = RequestRules.match(rules[:requests], method, path, user_agent, req)
        if matched
          rule = "request:#{matched['id']}"
          # A rule the dashboard only watches passes even in block mode; one
          # that blocks also bans the address here, as a flood does.
          action = action == "block" && matched["action"] == "block" ? "block" : "monitor"
          ban_here(ip, matched["ban"]) if action == "block" && matched["ban"].positive?
        end
      end
      # A static file isn't counted toward the page limits or `rate`, only
      # compared with the counts so far: an address already over them is
      # turned away for its files too. It is counted after the response if
      # the app routed it to a page after all (Rails reads /login.css as the
      # login action, format css) or it answered an error (count_static).
      static = Firewall.static?(path, method)
      goodbot = rules[:goodbots].has?(key)
      late_rate = false
      late_limits = false
      # Page limits (step 6). Never banned: a shopper who refreshes checkout
      # too often is a customer, and the cap lifts when the window ends.
      watched = nil
      limit_window = nil
      if rule.empty? && limits && !goodbot && !limits[:exempt].has?(key)
        late_limits = static
        over = over_limits(ip, limits[:rules], req, peek: static)
        blocking = action == "block" ? over.find { |limit| limit["action"] == "block" } : nil
        if blocking
          rule = "limit:#{blocking['id']}"
          limit_window = blocking["window"]
        else
          # Only watched: reported, and the check goes on to `rate`, so
          # watching the login page doesn't let a flood through it untouched.
          watched = over.first
        end
      end
      late_rate = static if rule.empty? && rules[:rate] && !goodbot
      if rule.empty? && rules[:rate] && !goodbot && over_rate?(ip, rules[:rate], peek: static)
        rule = "rate"
        # Banned here straight away in block mode, as a probe is; the report bans it on the other servers.
        ban_here(ip, rules[:ban]) if action == "block"
      end
      if watched
        if rule.empty?
          rule = "limit:#{watched['id']}"
          action = "monitor"
          limit_window = watched["window"]
        else
          # `rate` decides; the watched limit is reported as well.
          report(event.call("limit:#{watched['id']}", "monitor"))
        end
      end
      # Not a mode matter: the collector only sends `challenge` when the site
      # is to be checked, and a match only watched (monitor) gets it too
      # (firewall.md, step 8).
      if (rule.empty? || action != "block") && needs_check?(rules, key, ip, method, path, accept, cookie, now)
        report(event.call(rule, action)) unless rule.empty?
        rule = "challenge"
        action = "block"
        limit_window = nil
      end
      decision = if rule.empty?
                   allow
                 else
                   report(event.call(rule, action))
                   if limit_window
                     # retry_after: the limit's own window, which the 429 carries.
                     { action: action, rule: rule, status: 429, retry_after: limit_window }
                   else
                     { action: action, rule: rule, status: rule == "rate" ? 429 : (rule == "challenge" ? 503 : 403) }
                   end
                 end
      # What count_static needs after the response of a static file that went on to the app.
      if (late_rate || late_limits) && decision[:action] != "block"
        decision[:static] = { ip: ip, rate: late_rate, req: late_limits ? req : nil }
      end
      decision
    end

    # After the response to a static file check() let through (its
    # decision's :static): counted toward `rate` and the page limits it
    # skipped when the app routed it to a page after all, or it answered an
    # error (>= 400), so neither "/login.css" on Rails nor a flood of
    # made-up file names that each boot the app gets past them. env: the
    # Rack env, where Rails leaves the route it took.
    def count_static(hit, status, env = nil)
      return unless hit && (status.to_i >= 400 || Firewall.routed?(env))

      rules = @rules
      return unless rules

      over_rate?(hit[:ip], rules[:rate]) if hit[:rate] && rules[:rate]
      over_limits(hit[:ip], rules[:limits][:rules], hit[:req]) if hit[:req] && rules[:limits]
      nil
    end

    # Whether Rails' router sent the request to a controller action: it
    # leaves the action's path parameters in the env. A file
    # ActionDispatch::Static, Propshaft or a mounted app served has none,
    # and Active Storage's own controllers serve files (each image on a page
    # is a request to one, and with the disk service a second).
    def self.routed?(env)
      params = env.is_a?(Hash) ? env["action_dispatch.request.path_parameters"] : nil
      return false unless params.is_a?(Hash)

      controller = params[:controller] || params["controller"]
      !controller.nil? && !controller.to_s.match?(FILE_CONTROLLERS)
    end

    # The rules about the address alone (deny, bans, lists, shared): "" when none.
    def address_rule(rules, key, ip)
      if rules[:deny].has?(key) then "deny"
      elsif rules[:banned].has?(key) || banned_here?(ip) then "ban"
      elsif rules[:list].has?(key) then "list"
      elsif rules[:shared].has?(key) then "shared"
      else ""
      end
    end

    # The address rules only, for the tracker's own addresses (the proxy):
    # a denied or banned address gets nothing from us either, but beacons
    # are never rate-limited, checked or matched against request rules.
    # -> the same shape as check().
    def check_address(ip, method = "", path = "", user_agent = "")
      allow = { action: "allow", rule: "", status: 200 }
      rules = @rules
      return allow if rules.nil? || !rules[:enabled]

      key = IP.key(ip)
      return allow if key.nil? || rules[:allow].has?(key)

      rule = address_rule(rules, key, ip.to_s)
      return allow if rule.empty?

      action = (@mode || rules[:mode]) == "block" ? "block" : "monitor"
      report({ "ip" => ip.to_s, "rule" => rule, "action" => action, "method" => SiteGoose.text(method, 10),
               "path" => SiteGoose.text(path).split("?", 2)[0].to_s[0, 300], "user_agent" => SiteGoose.text(user_agent, 300) })
      { action: action, rule: rule, status: 403 }
    end

    # Step 8: the browser check is on, the request asks for a page outside
    # skip, the address is in none of allow (already passed), goodbots and
    # exempt, and it has no valid pass.
    def needs_check?(rules, key, ip, method, path, accept, cookie, now)
      check = rules[:challenge]
      return false if check.nil? || !Challenge.asks_for_page?(method, path, accept, check[:skip])
      return false if rules[:goodbots].has?(key) || check[:exempt].has?(key)

      !Challenge.pass?(@pass_key, ip, cookie, now)
    end

    # [503, headers, body] for a request check() gave rule "challenge".
    def challenge_page(ip, method)
      Challenge.page(@pass_key, ip, method)
    end

    def retry_after
      rules = @rules
      rules && rules[:rate] ? rules[:rate][:window].to_s : "60"
    end

    def client_ip(remote, headers)
      SiteGoose.client_ip(remote, headers, @trust_proxy)
    end

    def close
      @jobs.each(&:stop)
      Forking.unregister(self)
      flush
    end
  end
end
