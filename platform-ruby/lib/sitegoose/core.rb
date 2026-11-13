# frozen_string_literal: true

# What every module shares: the site's credentials, sending to the
# collector, logging, background jobs, and the dashboard's module switches
# (Site settings -> Server, GET /events/platform/config about once a minute).
#
# A module the dashboard turns off stays loaded but does nothing; until the
# switches arrive, or when they can't be fetched, every loaded module stays on.
# Sending never raises into the app. Background jobs are threads that start
# again in a forked worker (Puma, Unicorn, Passenger), where threads don't
# survive: through Process._fork (Ruby 3.1+), and, for Ruby 3.0, by the
# middleware noticing the process ID changed.

require "json"
require "net/http"
require "openssl"
require "socket"
require "uri"
require "etc"
require "time"

module SiteGoose
  TIMEOUT = 5
  MIN_SYNC = 30
  RETRY = 60
  SESSION_HEADER = "x-analytics-session"
  RUNTIME = "Ruby #{RUBY_VERSION}"

  # A string as UTF-8 that JSON can carry: anything else (binary, a broken
  # encoding) is mended rather than raising on the way out. max: characters.
  def self.text(value, max = nil)
    s = value.nil? ? +"" : value.to_s
    s = s.dup.force_encoding(Encoding::UTF_8) unless s.encoding == Encoding::UTF_8
    s = s.scrub("�") unless s.valid_encoding?
    max ? s[0, max] : s
  end

  def self.iso_now(at = nil)
    (at || Time.now).utc.iso8601(3)
  end

  def self.clock
    Process.clock_gettime(Process::CLOCK_MONOTONIC)
  end

  # At exit (and Sidekiq's shutdown) everything waiting gets one overall
  # deadline, so the package never outlasts a container's or PM2's grace
  # period: each send waits at most what's left, none starts after it, and
  # what wasn't sent waits in the errors file.
  EXIT_DEADLINE = 5
  @deadline = nil

  class << self
    # Runs the block with every send (and job stop) inside seconds from now.
    def within(seconds = EXIT_DEADLINE)
      before = @deadline
      ends = clock + seconds
      @deadline = before ? [before, ends].min : ends
      yield
    ensure
      @deadline = before
    end

    # Seconds left before the deadline, or nil when there is none.
    def time_left
      ends = @deadline
      ends ? [ends - clock, 0.0].max : nil
    end

    # How long one send may wait: normal, cut to what's left of a deadline,
    # nil once it has passed (nothing more is sent).
    def send_timeout(normal)
      left = time_left
      return normal if left.nil?
      return nil if left < 0.05

      [normal, left].min
    end
  end

  # A header from a hash with lowercase names ("" when missing).
  def self.header(headers, name)
    value = headers && headers[name.downcase]
    value.is_a?(String) ? value.strip : ""
  end

  def self.hostname
    Socket.gethostname.to_s
  rescue StandardError
    ""
  end

  # Options given as a hash with string or symbol keys -> symbol keys.
  def self.symbolize(options)
    return {} unless options.is_a?(Hash)

    options.each_with_object({}) { |(k, v), out| out[k.to_sym] = v }
  end

  Response = Struct.new(:status, :headers, :body) do
    def ok?
      status >= 200 && status < 300
    end

    def json
      JSON.parse(body.to_s.empty? ? "null" : body)
    rescue JSON::ParserError, TypeError
      nil
    end
  end

  # Fork safety. Two things go wrong when a process forks while a background
  # thread works: the thread is gone in the child, and a send in flight there
  # may hold a lock the child then waits on forever. So a fork waits (at most
  # a send's timeout) for the sends in flight, a send waits for a fork, and
  # in the child every background job starts again.
  module Forking
    @mutex = Mutex.new
    @cond = ConditionVariable.new
    @in_flight = 0
    @forking = false
    @pid = Process.pid
    @children = []
    CHECK_LOCK = Mutex.new

    class << self
      attr_reader :pid

      def register(item)
        @mutex.synchronize { @children << item }
      end

      def unregister(item)
        @mutex.synchronize { @children.delete(item) }
      end

      def sending
        deadline = SiteGoose.clock + TIMEOUT
        @mutex.synchronize do
          while @forking && (left = deadline - SiteGoose.clock) > 0
            @cond.wait(@mutex, left)
          end
          @in_flight += 1
        end
        begin
          yield
        ensure
          @mutex.synchronize do
            @in_flight -= 1 if @in_flight.positive?
            @cond.broadcast
          end
        end
      end

      def before_fork
        deadline = SiteGoose.clock + TIMEOUT + 1
        @mutex.synchronize do
          @forking = true
          while @in_flight.positive? && (left = deadline - SiteGoose.clock) > 0
            @cond.wait(@mutex, left)
          end
        end
      rescue StandardError, ThreadError
        nil
      end

      def after_fork_in_parent
        @mutex.synchronize do
          @forking = false
          @cond.broadcast
        end
        @mutex.synchronize { @children.dup }.each { |c| c.respond_to?(:after_fork_in_parent) && c.after_fork_in_parent }
      rescue StandardError, ThreadError
        nil
      end

      # In the child (or, on Ruby 3.0, the first time a request sees a new
      # process ID): fresh locks, and every job started again.
      def after_fork_in_child
        @mutex = Mutex.new
        @cond = ConditionVariable.new
        @in_flight = 0
        @forking = false
        @children.dup.each do |child|
          child.after_fork_in_child
        rescue StandardError
          nil
        end
        # Last, so a request that checks meanwhile waits for the restart
        # rather than running on the parent's queues.
        @pid = Process.pid
      end

      # The Ruby 3.0 path, and a safety net on every other: a fork that went
      # around Process._fork. Under a lock, so two requests arriving at a new
      # worker at once restart its threads once. (A thread that held it at
      # the fork doesn't exist in the child, and Ruby releases what a thread
      # left behind there.)
      def check
        return if @pid == Process.pid

        CHECK_LOCK.synchronize { after_fork_in_child if @pid != Process.pid }
      end
    end

    # Process._fork is what fork, Process.fork and Kernel#fork all call (Ruby 3.1+).
    module Hook
      def _fork
        Forking.before_fork
        begin
          pid = super
        rescue Exception # rubocop:disable Lint/RescueException -- raised on
          # No child (EAGAIN, out of memory): sends must not keep waiting for one.
          Forking.after_fork_in_parent
          raise
        end
        if pid.zero?
          Forking.after_fork_in_child
        else
          Forking.after_fork_in_parent
        end
        pid
      end
    end

    Process.singleton_class.prepend(Hook) if Process.respond_to?(:_fork)
  end

  # Runs the block in a background thread; the block returns the seconds
  # until its next run. Never lets the job die, and starts again after a fork.
  class Periodic
    @running = []
    @lock = Mutex.new

    class << self
      def running
        @lock.synchronize { @running.dup }
      end

      def add(job)
        @lock.synchronize { @running << job }
      end

      def remove(job)
        @lock.synchronize { @running.delete(job) }
      end
    end

    attr_reader :thread

    def initialize(first = 0, &job)
      @job = job
      @first = first
      @stopped = false
      start
      Periodic.add(self)
      Forking.register(self)
    end

    def start
      return if @stopped

      @mutex = Mutex.new
      @cond = ConditionVariable.new
      @wake = false
      @thread = Thread.new { run }
      @thread.name = "analytics-platform" if @thread.respond_to?(:name=)
      @thread.report_on_exception = false
    end

    def stopped?
      @stopped
    end

    def run
      wait = @first
      until @stopped
        @mutex.synchronize do
          @cond.wait(@mutex, wait) if !@wake && !@stopped && wait.positive?
          @wake = false
        end
        break if @stopped

        wait = begin
          @job.call
        rescue SignalException, SystemExit
          break
        rescue Exception # rubocop:disable Lint/RescueException -- a job never dies
          RETRY
        end
        wait = RETRY unless wait.is_a?(Numeric) && wait >= 0
      end
    end

    def run_now
      @mutex.synchronize do
        @wake = true
        @cond.signal
      end
    end

    # Stops the job and waits (up to wait seconds) for its thread to end.
    def stop(wait = 2.0)
      @stopped = true
      begin
        @mutex.synchronize do
          @wake = true
          @cond.signal
        end
      rescue ThreadError
        nil
      end
      Periodic.remove(self)
      Forking.unregister(self)
      thread = @thread
      left = SiteGoose.time_left
      wait = [wait, left].min if wait && left
      thread.join(wait) if wait && wait.positive? && thread&.alive? && thread != Thread.current
    end

    def after_fork_in_child
      start
    end
  end

  # This process's resident memory in MB (Linux /proc), or nil.
  def self.rss_mb
    statm = File.read("/proc/self/statm")
    pages = statm.split[1].to_i
    (pages * page_size / 1_048_576.0).round
  rescue StandardError
    nil
  end

  def self.page_size
    @page_size ||= begin
      Etc.sysconf(Etc::SC_PAGESIZE)
    rescue StandardError
      4096
    end
  end

  class Core
    attr_reader :site_id, :secret, :endpoint, :server_name, :user_agent

    def initialize(site_id, secret, endpoint, debug: false, server_name: nil, logger: nil)
      @site_id = site_id.to_s
      # The name this service checks in under (X-Platform-App, on the switches
      # request): server_name, as every module sends it, else the machine's.
      @server_name = SiteGoose.text(server_name || SiteGoose.hostname, 100)
      @started = Time.now.to_f
      @secret = secret.to_s
      @endpoint = endpoint.to_s.sub(%r{/+\z}, "")
      @valid = @site_id.match?(/\A[a-fA-F0-9]{24}\z/) && !@secret.empty? && !@endpoint.empty?
      @debug = debug ? true : false
      @logger = logger
      @user_agent = "analytics-platform-ruby/#{VERSION}"
      @switches = {}
      @headers = []
      @flags = {}
      @maintenance = { "on" => false }
      @etag = ""
      @loaded = []
      @job = nil
    end

    def valid?
      @valid
    end

    def log(mod, *args)
      return unless @debug

      line = "[analytics-platform:#{mod}] #{args.join(' ')}"
      @logger ? @logger.warn(line) : warn(line)
    rescue StandardError
      nil
    end

    # JSON to the collector. auth :body puts site_id and sitesecret in the
    # body (the event endpoints), :bearer sends the secret as a header
    # (firewall, switches). Returns a Response, or nil when it couldn't be sent.
    def request(mod, path, method: "POST", body: nil, auth: :body, headers: nil)
      return nil unless @valid

      uri = URI.parse(@endpoint + path)
      all = { "User-Agent" => @user_agent }
      data = nil
      unless body.nil?
        body = body.merge("site_id" => @site_id, "sitesecret" => @secret) if auth == :body
        data = JSON.generate(body)
        all["Content-Type"] = "application/json"
      end
      all["Authorization"] = "Bearer #{@secret}" if auth == :bearer
      all.merge!(headers) if headers
      klass = method == "GET" ? Net::HTTP::Get : Net::HTTP::Post
      req = klass.new(uri.request_uri, all)
      req.body = data if data
      wait = SiteGoose.send_timeout(TIMEOUT)
      return nil if wait.nil?

      Forking.sending do
        http = Net::HTTP.new(uri.host, uri.port)
        http.use_ssl = uri.scheme == "https"
        http.open_timeout = wait
        http.read_timeout = wait
        http.write_timeout = wait if http.respond_to?(:write_timeout=)
        res = http.start { |h| h.request(req) }
        status = res.code.to_i
        log(mod, "collector answered #{status} to #{path}") if status >= 400
        Response.new(status, res.each_header.to_h { |k, v| [k.downcase, v] }, res.body.to_s)
      end
    rescue StandardError, Timeout::Error => e
      log(mod, "could not reach the collector (#{path}): #{e.class}: #{e.message}")
      nil
    end

    # ---- Module switches ----

    # False only when the dashboard turned the module off.
    def on?(name)
      @switches[name.to_s] != false
    end
    alias is_on on?

    # This service's check-in, form-encoded so any name is plain ASCII:
    # Health -> All systems shows it running and when it was last heard from.
    # nil when it can't be built: the switches still sync, without it.
    def check_in
      return nil if @server_name.empty?

      fields = [["server", @server_name], ["kind", "process"], ["pid", Process.pid.to_s],
                ["up_s", (Time.now.to_f - @started).to_i.to_s], ["runtime", RUNTIME]]
      rss = SiteGoose.rss_mb
      fields << ["rss_mb", rss.to_s] if rss
      URI.encode_www_form(fields)
    rescue StandardError
      nil
    end

    # The nine headers the dashboard can produce (expresscollect/Analytics/
    # platform.js, headersOf), lower case. A list of what's allowed, not of
    # what isn't: whoever got into our servers still couldn't make this app
    # grant another site its users' data (Access-Control-Allow-*), send every
    # page elsewhere (Refresh), log everyone out (Clear-Site-Data) or change
    # what a response is. Shared cases: sdk/protocols/header-cases.json.
    SECURITY_HEADERS = %w[strict-transport-security x-content-type-options x-frame-options referrer-policy
                          permissions-policy cross-origin-opener-policy content-security-policy
                          content-security-policy-report-only reporting-endpoints].freeze
    HEADER_VALUE = /\A[\x20-\x7e\t]*\z/.freeze

    # One of SECURITY_HEADERS, in any case, with a value of visible ASCII,
    # spaces and tabs (no line breaks, nothing a server rejects), at most
    # 4,000 characters.
    def self.safe_header?(pair)
      pair.is_a?(Array) && pair.size == 2 && pair[0].is_a?(String) && SECURITY_HEADERS.include?(pair[0].downcase) &&
        pair[1].is_a?(String) && pair[1].size <= 4000 && pair[1].match?(HEADER_VALUE)
    end

    def sync_switches
      headers = { "X-Platform-Modules" => @loaded.join(",") }
      app = check_in
      headers["X-Platform-App"] = app if app
      headers["If-None-Match"] = @etag unless @etag.empty?
      res = request("core", "/events/platform/config?site_id=#{@site_id}", method: "GET", auth: :bearer, headers: headers)
      return RETRY unless res && res.status == 200

      data = res.json
      data = {} unless data.is_a?(Hash)
      if data["v"] == 1 && data["modules"].is_a?(Hash)
        @switches = data["modules"]
        @flags = data["flags"].is_a?(Hash) ? data["flags"] : {}
        @maintenance = data["maintenance"].is_a?(Hash) ? data["maintenance"] : { "on" => false }
        @headers = (data["headers"].is_a?(Array) ? data["headers"] : []).select { |pair| Core.safe_header?(pair) }
        @etag = res.headers["etag"].to_s
      end
      [MIN_SYNC, (data["sync"].is_a?(Numeric) && data["sync"].positive? ? data["sync"].to_i : RETRY)].max
    end

    def flags
      @flags
    end

    def maintenance
      @maintenance
    end

    # The security headers picked on the dashboard, when the module is on.
    def security_headers
      on?("headers") ? @headers.dup : []
    end

    # Starts fetching the switches; names are the modules the code loaded.
    def start(names)
      @loaded = names.map(&:to_s)
      @job = Periodic.new { sync_switches } if @valid
    end

    def stop
      @job&.stop
    end

    # For tests: what the dashboard said.
    def switches=(value)
      @switches = value
    end
  end

  # The characters a path may carry unencoded (RFC 3986).
  PATH_SAFE = %r{[^A-Za-z0-9/:@!$&'()*+,;=\-._~%]}.freeze

  # The request target as the visitor sent it, query string and all, which
  # is what the request rules match (sdk/protocols/firewall.md). Rack's
  # PATH_INFO is not decoded, and Puma, Unicorn and WEBrick keep the target
  # itself as REQUEST_URI, so it is taken as it came; an absolute-form target
  # (a proxy request) loses its scheme and host.
  def self.request_target(env)
    raw = env["REQUEST_URI"]
    if raw.is_a?(String) && !raw.empty?
      target = raw.sub(%r{\A[a-zA-Z][a-zA-Z0-9+.-]*://[^/?#]*}, "")
      target = "/#{target}" unless target.start_with?("/") || target.start_with?("*")
    else
      target = "#{env['SCRIPT_NAME']}#{env['PATH_INFO']}"
      target = target.b.gsub(PATH_SAFE) { |c| format("%%%02X", c.ord) }
    end
    query = env["QUERY_STRING"].to_s
    target = "#{target}?#{query}" if !query.empty? && !target.include?("?")
    text(target)
  end

  # A path with its percent-escapes decoded once, as text (for display and
  # route names, never for the rules).
  def self.decode_path(path)
    text(path.to_s.b.gsub(/%[0-9a-fA-F]{2}/) { |m| m[1, 2].to_i(16).chr })
  end
end
