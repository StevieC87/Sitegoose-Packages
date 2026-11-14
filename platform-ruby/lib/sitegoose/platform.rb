# frozen_string_literal: true

module SiteGoose
  MODULES = %w[proxy firewall errors analytics performance crawlers forms headers audit flags maintenance inventory
               posture resources].freeze

  # The site, its secret and the modules that are on. Each module is
  # separate: one failing to start never stops the others, and the firewall
  # never waits on reporting. A loaded module can also be switched off in the
  # dashboard (Security -> Server package).
  class Platform
    attr_reader :core

    # site_id, secret (site settings; keep it on the server), endpoint (the
    # collector's URL); trust_proxy (how to find the visitor's address: nil
    # uses the connection's, a number of proxies in X-Forwarded-For,
    # "cloudflare"); debug (print send problems); server_name (this
    # service's name); queries, calls, queues (false: Server speed without
    # the database queries, the outgoing calls, the job queues); per module
    # true / false / {options}.
    def initialize(site_id: nil, secret: nil, endpoint: nil, trust_proxy: nil, debug: false, server_name: nil,
                   logger: nil, queries: true, calls: true, queues: true, **modules)
      unknown = modules.keys.map(&:to_s) - MODULES
      warn "[analytics-platform] unknown options ignored: #{unknown.join(', ')}" unless unknown.empty?
      @core = Core.new(site_id, secret, endpoint, debug: debug, server_name: server_name, logger: logger)
      unless @core.valid?
        warn "[analytics-platform] site_id, secret and endpoint are required; nothing is sent and every request passes"
      end
      @modules = {}
      MODULES.each do |name|
        setting = modules.key?(name.to_sym) ? modules[name.to_sym] : true
        next if setting == false || setting.nil?

        opts = setting.is_a?(Hash) ? SiteGoose.symbolize(setting) : {}
        opts[:trust_proxy] = trust_proxy if name == "firewall" && !opts.key?(:trust_proxy)
        # server_name names this service for every module that sends one, so
        # its errors, timings and resources can be told apart.
        if server_name && %w[errors performance crawlers resources].include?(name)
          opts[:server_name] = server_name unless opts.key?(:server_name)
        end
        # Inventory and posture call it host, and are stored one per site and
        # host: without it two services on one machine overwrite each other's.
        opts[:host] = server_name if server_name && %w[inventory posture].include?(name) && !opts.key?(:host)
        begin
          @modules[name] = load(name, opts)
        rescue StandardError, ScriptError => e
          warn "[analytics-platform] the #{name} module could not start and is off: #{e.message}"
        end
      end
      @queries = @calls = @queues = nil
      performance = @modules["performance"]
      if performance
        @queries = part("database queries", queries) { Queries.new(@core, server_name: performance.server_name) }
        @calls = part("outgoing calls", calls) { Calls.new(@core, server_name: performance.server_name) }
        @queues = part("job queues", queues) { Queues.new(@core, server_name: performance.server_name) }
      end
      # The most requests in progress at once, beside the machine's figures.
      @modules["resources"]&.use_inflight(performance && -> { performance.take_inflight_peak })
      @core.start(@modules.keys)
      @closed = false
      SiteGoose.created(self)
    end

    # One of Server speed's parts, unless switched off with false.
    def part(what, setting)
      return nil if setting == false

      yield
    rescue StandardError, ScriptError => e
      warn "[analytics-platform] #{what} could not start and are off: #{e.message}"
      nil
    end
    private :part

    def load(name, opts)
      case name
      when "firewall" then Firewall.new(@core, **opts)
      when "errors" then Errors.new(@core, **opts)
      when "analytics" then Analytics.new(@core, **opts)
      when "performance" then Performance.new(@core, **opts)
      when "crawlers" then Crawlers.new(@core, **opts)
      when "forms" then Forms.new(@core, **opts)
      when "headers" then Headers.new
      when "audit" then Audit.new(@core, **opts)
      when "flags" then Flags.new(@core, **opts)
      when "maintenance" then Maintenance.new(@core, **opts)
      when "inventory" then Inventory.new(@core, **opts)
      when "posture" then Posture.new(@core, **opts)
      when "resources" then Resources.new(@core, **opts)
      when "proxy" then Proxy.new(@core, **opts)
      else raise ArgumentError, name
      end
    end
    private :load

    # ---- Modules ----

    # The modules that are on.
    def modules
      @modules.keys
    end

    def module(name)
      @modules[name.to_s]
    end

    def firewall
      @modules["firewall"]
    end

    def errors
      @modules["errors"]
    end

    # The database queries, outgoing calls and job queues Server speed
    # records (each nil when switched off with false, or performance off).
    attr_reader :queries, :calls, :queues

    # The first-party proxy: proxy.script_url and proxy.collect_url are the
    # two addresses the page's script tag needs, on this site's own domain.
    def proxy
      @modules["proxy"]
    end

    # [status, headers, body] when the address belongs to the proxy, else nil.
    # Called first: a visitor's beacon is our traffic, not a page of the site.
    def proxy_response(path, method: "GET", query: "", headers: {}, body: nil, remote: "")
      proxy = @modules["proxy"]
      return nil unless proxy

      found = proxy.match(path)
      return nil unless found

      ip = firewall ? firewall.client_ip(remote, headers) : remote
      # A denied or banned address gets nothing from us either; the rate
      # limit and the browser check aren't for beacons.
      if firewall
        decision = firewall.check_address(ip, method, path, SiteGoose.header(headers, "user-agent"))
        return [403, { "content-type" => "text/plain; charset=utf-8", "cache-control" => "no-store" }, "Forbidden"] if decision[:action] == "block"
      end
      body = body.call if body.respond_to?(:call)
      proxy.handle(found[0], found[1], method: method, query: query, headers: headers, body: body, client_ip: ip)
    rescue StandardError => e
      @core.log("proxy", "failed:", e.message)
      [502, {}, ""]
    end

    def capture_exception(error, request: nil, status: 0, kind: "handled")
      errors&.capture_exception(error, request: request, status: status, kind: kind)
      nil
    end

    # A step of your own in the trail shown before an error in this request or job.
    def add_breadcrumb(text)
      Context.add_breadcrumb(text) if errors
    end

    # A background job (a queue consumer, a cron task): its errors are sent
    # with the job's name as their route, and each run is timed (Health ->
    # Server speed -> Jobs); a run that raises counts as failed, and the
    # exception is raised on.
    #
    #     platform.job("nightly-import") { ... }
    #
    # report: ->(error) { true } when this error should be sent (Sidekiq: only
    # the last attempt); default every error.
    def job(name, report: nil)
      route = "/(job) #{SiteGoose.text(name.to_s.empty? ? 'job' : name, 180)}"
      fields = { "method" => "JOB", "path" => route, "route" => route, "session_id" => "" }
      started = SiteGoose.clock
      status = nil
      Context.with(fields) do
        result = yield
        status = 200
        result
      rescue SignalException, SystemExit
        # Interrupted or stopped: not a run that failed, and not timed.
        status = nil
        raise
      rescue Exception => e # rubocop:disable Lint/RescueException -- raised on
        status = 500
        begin
          capture_exception(e, status: 500, kind: "error", request: fields) if report.nil? || report.call(e)
        rescue StandardError
          nil
        end
        raise
      ensure
        time_request("JOB", route, status, started, route) if status
      end
    end

    # A failed login (bot protection): the address, or a Rack request.
    def login_failed(request_or_ip)
      return unless firewall

      ip = request_or_ip.is_a?(String) ? request_or_ip : request_ip(request_or_ip)
      firewall.login_failed(ip) unless ip.to_s.empty?
    end

    # The visitor's address for a Rack (or Rails) request or env.
    def request_ip(request)
      env = SiteGoose.env_of(request)
      return "" unless env

      remote = env["REMOTE_ADDR"].to_s
      firewall ? firewall.client_ip(remote, SiteGoose.headers_of(env)) : remote
    end

    # A feature flag from the dashboard (user: for rollouts and user lists;
    # default: until the flag is known, or with the module off).
    def enabled?(key, user: nil, default: false)
      flags = @modules["flags"]
      flags ? flags.enabled?(key, user, default) : default
    end
    alias is_enabled enabled?

    # Maintenance mode: nil to let the request through, [:pass, headers] to let
    # it through and remember the preview link, or [status, headers, body].
    def maintenance_response(remote, headers, path, query, secure: false)
      maintenance = @modules["maintenance"]
      return nil unless maintenance

      ip = firewall ? firewall.client_ip(remote, headers) : remote
      maintenance.decide(ip, path, query, SiteGoose.header(headers, "cookie"), secure: secure)
    rescue StandardError => e
      @core.log("maintenance", "check failed, request passed:", e.message)
      nil
    end

    # Records who did what (Security -> Audit log). action: e.g.
    # "user.role_changed"; request adds the actor's address and visit.
    def audit(action, actor: "", target: "", details: nil, request: nil)
      audit = @modules["audit"]
      return unless audit

      ip = request ? request_ip(request) : ""
      audit.record(action, actor, target, details, ip, request ? session_id(request) : "")
    rescue StandardError => e
      @core.log("audit", "could not record:", e.message)
    end

    # Form protection: checks a form before you accept it. The form is the
    # request's POST parameters (Rack, Rails), else pass fields.
    # -> {ok:, spam:, reasons:, checked:}; spam goes to Leads -> Spam.
    def check_form(request = nil, fields: nil, email: nil, name: nil, form: nil)
      forms = @modules["forms"]
      return { ok: true, spam: false, reasons: [], checked: false } unless forms

      if fields.nil? && request
        fields = if request.respond_to?(:request_parameters) then request.request_parameters
                 elsif request.respond_to?(:POST) then request.POST
                 end
        fields = fields.to_unsafe_h if fields.respond_to?(:to_unsafe_h)
      end
      forms.check(fields || {}, request ? request_ip(request) : "", email, name, form)
    rescue StandardError => e
      @core.log("forms", "could not check a form:", e.message)
      { ok: true, spam: false, reasons: ["unchecked"], checked: false }
    end

    def track(name, fields = nil, session_id: "")
      analytics = @modules["analytics"]
      analytics ? analytics.track(name, fields, session_id) : ""
    end

    # traits: optional user properties, name => text, number or true/false.
    def identify(user_id, session_id: "", traits: nil)
      analytics = @modules["analytics"]
      analytics ? analytics.identify(user_id, session_id, traits) : false
    end

    def lead(fields, session_id: "")
      analytics = @modules["analytics"]
      analytics&.lead(fields, session_id)
    end

    # The dashboard's security headers the response doesn't set itself
    # (present: the header names it has).
    def security_headers(present = [])
      return [] unless @modules.key?("headers")

      have = present.map { |name| name.to_s.downcase }
      @core.security_headers.reject { |name, _| have.include?(name.downcase) }
    end

    # Records a finished request for Server speed (started: SiteGoose.clock).
    # The request's database queries go under the same method and route.
    def time_request(method, route, status, started, path = "")
      performance = @modules["performance"]
      recorded = performance&.record(method, route, status, (SiteGoose.clock - started) * 1000, path)
      if recorded
        @queries&.finish(*recorded)
        @calls&.finish(*recorded)
      end
    rescue StandardError => e
      @core.log("performance", "could not time a request:", e.message)
    end

    # Records a finished request when it came from a crawler or AI bot
    # (Health -> Crawlers). started: SiteGoose.clock when it arrived.
    def record_crawler(user_agent, path, status, started = nil, size = 0, ip = "")
      crawlers = @modules["crawlers"]
      return unless crawlers

      ms = started ? (SiteGoose.clock - started) * 1000 : 0
      crawlers.middleware(user_agent, path, status, ms, size, ip)
    rescue StandardError => e
      @core.log("crawlers", "could not count a crawler request:", e.message)
    end

    # The browser's visit, from a Rack or Rails request (the X-Analytics-Session header).
    def session_id(request)
      env = SiteGoose.env_of(request)
      value = env && env["HTTP_X_ANALYTICS_SESSION"]
      value.is_a?(String) ? value : ""
    end

    # Exceptions a Logger is given at ERROR or above are sent too (kind
    # "logged"); the logger still writes them. Rails.logger is hooked on its
    # own with errors: {capture_logging: true}.
    def capture_logger(logger)
      return logger unless errors && logger

      targets = logger.respond_to?(:broadcasts) ? [logger, *logger.broadcasts] : [logger]
      targets.uniq.each do |target|
        next unless target.respond_to?(:add)

        target.singleton_class.prepend(LoggerCapture) unless target.singleton_class.include?(LoggerCapture)
        target.instance_variable_set(:@__sitegoose_capture, lambda { |error|
          name = target.respond_to?(:progname) ? target.progname.to_s : ""
          capture_exception(error, kind: "logged") unless name.start_with?("analytics")
        })
      end
      logger
    end

    # Sends everything waiting (serverless, a job runner: before returning).
    def flush
      [*@modules.values, @queries, @calls, @queues].compact.each do |mod|
        mod.flush
      rescue StandardError
        nil
      end
      nil
    end

    # Stops background work and sends what's waiting.
    def close
      return if @closed

      @closed = true
      @core.stop
      [*@modules.values, @queries, @calls, @queues].compact.each do |mod|
        mod.close
      rescue StandardError
        nil
      end
      nil
    end

    def closed?
      @closed
    end

    # ---- Requests ----

    # [status, headers, body] when the firewall turns the request away, else
    # nil. headers: a hash with lowercase names. target: the request target
    # as sent, query string and all (SiteGoose.request_target). late: a hash
    # given :static when the request is a static file let through, for
    # Firewall#count_static after the response. overrides and also_path:
    # Firewall#check's (SiteGoose.method_overrides, SiteGoose.routed_also).
    def blocked(remote, headers, method, target, late = nil, overrides: nil, also_path: nil)
      fw = firewall
      return nil unless fw

      begin
        ip = fw.client_ip(remote, headers)
        decision = fw.check(ip, method, target, SiteGoose.header(headers, "user-agent"),
                            SiteGoose.header(headers, "accept"), SiteGoose.header(headers, "cookie"),
                            fetch_site: SiteGoose.header(headers, "sec-fetch-site"),
                            overrides: overrides, also_path: also_path)
        return fw.challenge_page(ip, method) if decision[:action] == "block" && decision[:rule] == "challenge"

        late[:static] = decision[:static] if late && decision[:static]
      rescue StandardError => e
        @core.log("firewall", "check failed, request passed:", e.message)
        return nil
      end
      return nil unless decision[:action] == "block"

      extra = { "content-type" => "text/plain; charset=utf-8", "cache-control" => "no-store" }
      if decision[:status] == 429
        # A page limit waits out its own window, not the site-wide one.
        extra["retry-after"] = (decision[:retry_after] || fw.retry_after).to_s
        return [429, extra, decision[:rule].start_with?("limit:") ? Firewall::LIMIT_BODY : "Too Many Requests"]
      end
      [403, extra, "Forbidden"]
    end

    # The Rack integration: everything a request goes through, in order. The
    # block runs the app. Used by SiteGoose::Middleware.
    def rack_call(env)
      Forking.check
      started = SiteGoose.clock
      headers = SiteGoose.headers_of(env)
      method = env["REQUEST_METHOD"].to_s
      remote = env["REMOTE_ADDR"].to_s
      raw_path = "#{env['SCRIPT_NAME']}#{env['PATH_INFO']}"
      path = SiteGoose.decode_path(raw_path)
      query = env["QUERY_STRING"].to_s
      # The tracker's own addresses, answered before anything else.
      answered = proxy_response(raw_path, method: method, query: query, headers: headers, remote: remote,
                                          body: -> { SiteGoose.read_body(env) })
      return SiteGoose.rack_response(answered, method) if answered

      ip = nil
      late = {}
      target = SiteGoose.request_target(env)
      refused = blocked(remote, headers, method, target, late, overrides: SiteGoose.method_overrides(env, headers),
                                                               also_path: SiteGoose.routed_also(env, target))
      if refused
        ip = firewall ? firewall.client_ip(remote, headers) : remote
        # A crawler the firewall turned away is still a crawler, and counted
        # with the status it got.
        record_crawler(headers["user-agent"], path, refused[0], started, 0, ip)
        return SiteGoose.rack_response(refused, method)
      end
      closed = maintenance_response(remote, headers, path, query, secure: SiteGoose.https?(env))
      return SiteGoose.rack_response(closed, method) if closed && closed[0] != :pass

      remember = closed ? closed[1] : {}
      fields = -> { SiteGoose.request_fields(env, method, path) }
      status = 500
      response = nil
      performance = @modules["performance"]
      resources = @modules["resources"]
      resources.see_server unless resources.nil? || resources.server_seen?
      performance&.enter
      Context.with(fields) do
        response = yield
        status = response[0].to_i
        # Rails and Sinatra turn an exception into an error page themselves,
        # so it never reaches here raised; they leave it in the env.
        error = env["action_dispatch.exception"] || env["sinatra.error"]
        capture_exception(error, status: status, kind: "error", request: fields.call) if error.is_a?(Exception) && status >= 500
        response
      rescue Exception => e # rubocop:disable Lint/RescueException -- raised on
        unless e.is_a?(SignalException) || e.is_a?(SystemExit)
          capture_exception(e, status: 500, kind: "error", request: fields.call)
        end
        raise
      ensure
        begin
          # A static file the app routed to a page, or that answered an error, counts after all.
          firewall&.count_static(late[:static], status, env) if late[:static]
        rescue StandardError
          nil
        end
        begin
          route = SiteGoose.route_of(env, path)
          time_request(method, route, status, started, path)
          size = response ? SiteGoose.content_length(response[1]) : 0
          record_crawler(headers["user-agent"], path, status, started, size, ip || (firewall ? firewall.client_ip(remote, headers) : remote))
        rescue StandardError
          nil
        end
        performance&.leave
      end
      SiteGoose.add_headers(response, security_headers(SiteGoose.header_names(response[1])), remember)
    end
  end

  # ---- Rack helpers ----

  class << self
    # Whether the visitor's request came over HTTPS (a TLS-ending proxy says
    # so in X-Forwarded-Proto, as Rack reads it).
    def https?(env)
      return true if env["HTTPS"].to_s.downcase == "on" || env["rack.url_scheme"] == "https"

      env["HTTP_X_FORWARDED_PROTO"].to_s.split(",").first.to_s.strip.downcase == "https"
    end

    # The env of a Rack::Request, an ActionDispatch::Request, or an env itself.
    def env_of(request)
      return request if request.is_a?(Hash)
      return request.env if request.respond_to?(:env)

      nil
    end

    # The request's headers as a hash with lowercase names.
    def headers_of(env)
      headers = {}
      env.each do |key, value|
        next unless key.is_a?(String) && value.is_a?(String)

        if key.start_with?("HTTP_")
          headers[key[5..].tr("_", "-").downcase] = value
        elsif key == "CONTENT_TYPE" || key == "CONTENT_LENGTH"
          headers[key.tr("_", "-").downcase] = value
        end
      end
      headers
    end

    def read_body(env)
      input = env["rack.input"]
      return "" unless input

      body = input.read(Proxy::MAX_BODY + 1).to_s
      input.rewind if input.respond_to?(:rewind)
      body
    rescue StandardError
      ""
    end

    # The route as the framework names it: Rails 7.1+ keeps the matched
    # pattern (/users/:id), Sinatra its route ("GET /users/:id"); an older
    # Rails gives the path parameters, put back into the path; else "" (the
    # path is normalized).
    def route_of(env, path)
      pattern = env["action_dispatch.route_uri_pattern"]
      return pattern.sub(/\(\.:format\)\z/, "")[0, 200] if pattern.is_a?(String) && !pattern.empty?

      route = env["sinatra.route"]
      return route.split(" ", 2)[1].to_s[0, 200] if route.is_a?(String) && !route.empty?

      params = env["action_dispatch.request.path_parameters"]
      return "" unless params.is_a?(Hash) && params.key?(:controller)

      format = params[:format].to_s
      parts = path.split("/", -1)
      parts[-1] = parts[-1].delete_suffix(".#{format}") if !format.empty? && parts[-1]
      params.each do |key, value|
        next if %i[controller action format].include?(key) || !value.is_a?(String) || value.empty?

        index = parts.index(value)
        parts[index] = ":#{key}" if index
      end
      route = parts.join("/")
      route.empty? ? "/" : route[0, 200]
    rescue StandardError
      ""
    end

    def request_fields(env, method, path)
      session = env["HTTP_X_ANALYTICS_SESSION"]
      { "method" => method, "path" => path, "route" => route_of(env, path), "session_id" => session.is_a?(String) ? session : "" }
    end

    def header_names(headers)
      headers.respond_to?(:keys) ? headers.keys.map { |k| k.to_s.downcase } : []
    end

    def content_length(headers)
      return 0 unless headers.respond_to?(:each)

      headers.each { |k, v| return v.to_s.to_i if k.to_s.casecmp?("content-length") }
      0
    end

    # Our own answer (the check page, a refusal, the proxy) as a Rack response.
    def rack_response(answer, method)
      status, headers, body = answer
      body = "" if method.to_s.upcase == "HEAD"
      [status, headers.to_h { |k, v| [k.to_s.downcase, v.to_s] }, [body.to_s]]
    end

    # The dashboard's security headers and the maintenance cookie, onto the
    # app's own response.
    def add_headers(response, extra, remember)
      return response if extra.empty? && remember.empty?

      status, headers, body = response
      headers = headers.dup if headers.frozen?
      extra.each { |name, value| headers[name.downcase] = value }
      remember.each do |name, value|
        existing = headers[name]
        headers[name] = if existing.nil? || existing.empty? then value
                        elsif existing.is_a?(Array) then existing + [value]
                        elsif rack3? then [existing, value]
                        else "#{existing}\n#{value}"
                        end
      end
      [status, headers, body]
    end

    def rack3?
      defined?(::Rack::RELEASE) && ::Rack::RELEASE.to_s >= "3"
    end
  end
end
