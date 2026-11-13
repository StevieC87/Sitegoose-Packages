# frozen_string_literal: true

# Performance & API monitoring module: times every request (from arriving to
# the response being ready) and sends one row per minute, method, route and
# status code (how many, total and slowest time, and a count per time bucket)
# to POST /events/server-requests. Nothing about visitors is sent.
#
# The route is the framework's own pattern when the integration knows it
# (Rails, Sinatra); otherwise numbers and IDs in the path become ":id", and
# unmatched 404s are one route.

module SiteGoose
  class Performance
    # Keep in step with the collector (expresscollect/Analytics/serverRequests.js).
    BUCKET_EDGES_MS = [5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10_000].freeze
    FLUSH_EVERY = 60
    MAX_KEYS = 300
    # Past MAX_KEYS new routes fold into "(other)"; past this nothing new is
    # kept at all, whatever the requests carry.
    HARD_MAX_KEYS = 400
    # The method is the visitor's to choose: anything else is one "OTHER".
    METHODS = %w[GET HEAD POST PUT PATCH DELETE OPTIONS JOB].freeze
    MAX_ROWS = 500
    NOT_FOUND = "/(not found)"
    ID = /\A(\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{16,})\z/i.freeze

    # "/orders/123/items/9f8e..." -> "/orders/:id/items/:id"
    def self.normalize_route(path)
      path = SiteGoose.text(path).split(/[?#]/, 2)[0].to_s
      path = "/" if path.empty?
      parts = path.split("/", -1).map { |s| s.match?(ID) || (s.size >= 20 && s.match?(/\d/)) ? ":id" : s }
      route = parts.join("/")
      (route.start_with?("/") ? route : "/#{route}")[0, 200]
    end

    def self.method_of(method)
      name = SiteGoose.text(method).upcase
      return "GET" if name.empty?

      METHODS.include?(name) ? name : "OTHER"
    end

    def self.bucket_of(ms)
      BUCKET_EDGES_MS.index { |edge| ms <= edge } || BUCKET_EDGES_MS.size
    end

    attr_reader :rows, :server_name

    # Options: server_name (default the host name).
    def initialize(core, server_name: nil, **_)
      @core = core
      @server_name = SiteGoose.text(server_name || SiteGoose.hostname, 100)
      @rows = {}
      @lock = Mutex.new
      @job = core.valid? ? Periodic.new(FLUSH_EVERY) { flush(everything: false); FLUSH_EVERY } : nil
      reset_inflight
      Forking.register(self)
    end

    # In a forked worker the parent's rows are the parent's to send.
    def after_fork_in_child
      @lock = Mutex.new
      @rows = {}
      reset_inflight
    end

    # Requests in progress now, and the most at once since the resources
    # module last asked (resources.md, "Limits": inflight_peak). Nothing is
    # known until the middleware first runs, so an app without it reports no
    # peak rather than 0.
    def reset_inflight
      @inflight_lock = Mutex.new
      @inflight = 0
      @peak = 0
      @timed = false
    end
    private :reset_inflight

    def enter
      @inflight_lock.synchronize do
        @timed = true
        @inflight += 1
        @peak = @inflight if @inflight > @peak
      end
    end

    def leave
      @inflight_lock.synchronize { @inflight -= 1 if @inflight.positive? }
    end

    # The peak since the last call (nil before any request); it starts again
    # from what is still in progress.
    def take_inflight_peak
      @inflight_lock.synchronize do
        next nil unless @timed

        most = @peak
        @peak = @inflight
        most
      end
    end

    # One finished request. route: the framework's pattern, or "" to work it
    # out from path. -> [method, route] as recorded (the database queries go
    # under the same), or nil when Server speed is off.
    def record(method, route, status, ms, path = "")
      return unless @core.on?("performance")

      status = status.to_i
      route = SiteGoose.text(route)
      route = status == 404 ? NOT_FOUND : Performance.normalize_route(path) if route.empty?
      method = Performance.method_of(method)
      minute = (Time.now.to_i / 60) * 60
      ms = ms.to_f
      @lock.synchronize do
        key = [minute, method, route[0, 200], status]
        key = [minute, method, "(other)", status] if !@rows.key?(key) && @rows.size >= MAX_KEYS
        return key[1, 2] if !@rows.key?(key) && @rows.size >= HARD_MAX_KEYS

        row = (@rows[key] ||= { count: 0, sum_ms: 0.0, max_ms: 0.0, buckets: Array.new(BUCKET_EDGES_MS.size + 1, 0) })
        row[:count] += 1
        row[:sum_ms] += ms
        row[:max_ms] = ms if ms > row[:max_ms]
        row[:buckets][Performance.bucket_of(ms)] += 1
        key[1, 2]
      end
    end

    def flush(everything: true)
      current = (Time.now.to_i / 60) * 60
      ready = @lock.synchronize do
        taken = @rows.select { |k, _| everything || k[0] < current }
        taken.each_key { |k| @rows.delete(k) }
        taken
      end
      rows = ready.map do |k, v|
        { "minute" => Time.at(k[0]).utc.iso8601(3), "method" => k[1], "route" => k[2], "status" => k[3],
          "count" => v[:count], "sum_ms" => v[:sum_ms].round(1), "max_ms" => v[:max_ms].round(1), "buckets" => v[:buckets] }
      end
      rows.each_slice(MAX_ROWS) do |batch|
        @core.request("performance", "/events/server-requests",
                      body: { "server_name" => @server_name, "runtime" => RUNTIME, "rows" => batch })
      end
    end

    def close
      @job&.stop
      Forking.unregister(self)
      flush
    end
  end
end
