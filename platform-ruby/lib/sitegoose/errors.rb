# frozen_string_literal: true

# Error monitoring module: the server's errors go to the collector (POST
# /events/server-errors), where they join the browser's errors in the Errors
# report. An exception that ends the program is captured at exit; the Rack
# middleware captures request errors (5xx, including the ones Rails and
# Sinatra turn into an error page); capture_exception() captures errors you
# catch; Rails.error reports (handled exceptions) are sent too; and
# capture_logging sends the exceptions your code logs. An error is sent once
# however many of those see it. Errors are sent in small batches, a batch the
# collector couldn't take is tried once more, and sending never raises. What
# still can't be sent waits in a file and is sent once it can be, after a
# restart too; each error carries when it happened, and the trail of its
# request or job: the steps you add with add_breadcrumb().

require "digest"
require "json"
require "logger"
require "tmpdir"

module SiteGoose
  # The request or job being handled, per thread (fiber-local, so a fiber
  # server keeps requests apart too): a callable returning {method, path,
  # route, session_id}, so an error captured without a request (logged, or
  # caught deep in your code) still gets its route; and its trail of steps.
  module Context
    REQUEST = :sitegoose_request
    TRAIL = :sitegoose_trail
    QUERIES = :sitegoose_queries
    CALLS = :sitegoose_calls
    CRUMB_MAX = 15

    module_function

    def request
      Thread.current[REQUEST]
    end

    def trail
      Thread.current[TRAIL]
    end

    # Runs the block as one request or job: fields (a callable or a hash), a
    # new trail and no database queries or outgoing calls yet (Queries,
    # Calls), all put back as they were afterwards.
    def with(fields)
      saved = [Thread.current[REQUEST], Thread.current[TRAIL], Thread.current[QUERIES], Thread.current[CALLS]]
      Thread.current[REQUEST] = fields
      Thread.current[TRAIL] = []
      Thread.current[QUERIES] = nil
      Thread.current[CALLS] = nil
      yield
    ensure
      Thread.current[REQUEST], Thread.current[TRAIL], Thread.current[QUERIES], Thread.current[CALLS] = saved
    end

    def add_breadcrumb(text, type = "note")
      trail = Thread.current[TRAIL]
      return if trail.nil?

      trail << { "type" => type, "text" => SiteGoose.text(text, 200), "at" => Time.now.to_f }
      trail.shift while trail.size > CRUMB_MAX
    end

    # The trail as the tracker sends it: how long before now each step happened.
    def breadcrumbs
      now = Time.now.to_f
      (Thread.current[TRAIL] || []).map do |crumb|
        { "type" => crumb["type"], "text" => crumb["text"], "ms" => [0, ((now - crumb["at"]) * 1000).round].max }
      end
    end

    def request_fields
      fields = Thread.current[REQUEST]
      return nil if fields.nil?

      fields.respond_to?(:call) ? fields.call : fields
    rescue StandardError
      nil
    end
  end

  class Errors
    BATCH = 10
    QUEUE_MAX = 100
    FLUSH_EVERY = 2
    RESEND_EVERY = 60
    SPOOL_BYTES = 1024 * 1024
    MAX_FRAMES = 200
    MAX_CAUSES = 3
    # An exception's message can hold a whole response body or SQL dump.
    MAX_MESSAGE = 2000
    SEEN = :@__sitegoose_sent
    FIELDS = %w[method path route session_id].freeze

    class << self
      # A batch the collector couldn't take (unreachable, 429, 5xx) is sent
      # once more after this many seconds.
      attr_accessor :retry_after
    end
    self.retry_after = 2

    def self.failed?(res)
      res.nil? || res.status == 429 || res.status >= 500
    end

    def self.os_name
      host = RbConfig::CONFIG["host_os"].to_s
      case host
      when /linux/ then "linux"
      when /darwin/ then "darwin"
      when /mswin|mingw|cygwin/ then "win32"
      when /freebsd/ then "freebsd"
      else host[0, 32]
      end
    end

    attr_reader :queue, :spool_file

    # Options: server_name (default the host name), release (which build this
    # is; default the ANALYTICS_RELEASE environment variable), root (paths in
    # backtraces are made relative to it; default Rails.root or the working
    # directory), capture_uncaught (default true: the exception that ends the
    # program), capture_logging (default false: exceptions logged at ERROR or
    # above through a Logger are sent too; Rails.logger on its own, any other
    # with capture_logger), before_send (->(event, error) to change an event
    # or drop it: return nil), spool_dir (where errors that couldn't be sent
    # wait; default the system's temp folder, false to keep none).
    def initialize(core, server_name: nil, root: nil, release: nil, capture_uncaught: true, before_send: nil,
                   capture_logging: false, spool_dir: nil, **_)
      @core = core
      @server_name = SiteGoose.text(server_name || SiteGoose.hostname, 100)
      @root = (root || default_root).to_s.sub(%r{[/\\]+\z}, "")
      # Which build this is, for "introduced in" in the Errors report.
      @release = (release || ENV["ANALYTICS_RELEASE"]).to_s.strip.gsub(/[^\w.+\-]/, "")[0, 64]
      @before_send = before_send
      @capture_uncaught = capture_uncaught
      @capture_logging = capture_logging
      @queue = []
      @lock = Mutex.new
      @resend_lock = Mutex.new
      @resending = []
      @last_resend = 0.0
      # Named after the site and its secret, not the site id alone, so the
      # folder's listing tells nobody which site it is.
      @spool_file = nil
      if spool_dir != false && core.valid?
        name = Digest::SHA256.hexdigest("#{core.site_id}|#{core.secret}")[0, 16]
        @spool_file = File.join((spool_dir || Dir.tmpdir).to_s, "analytics-errors-#{name}.jsonl")
      end
      @job = core.valid? ? Periodic.new(FLUSH_EVERY) { flush; FLUSH_EVERY } : nil
      Forking.register(self)
    end

    attr_reader :capture_uncaught, :capture_logging

    def default_root
      defined?(::Rails) && ::Rails.respond_to?(:root) && ::Rails.root ? ::Rails.root.to_s : Dir.pwd
    rescue StandardError
      Dir.pwd
    end

    # In a forked worker: what was waiting is the parent's to send, or it
    # would be sent twice, and a lock the parent held at the fork would stay held.
    def after_fork_in_child
      @lock = Mutex.new
      @resend_lock = Mutex.new
      @queue = []
      @resending = []
    end

    # The program is ending with an exception (at_exit, $!): sent, and what
    # can't be sent waits in the file for the next start.
    def capture_exit(error)
      return unless @capture_uncaught && error && !error.is_a?(SystemExit) && !error.is_a?(SignalException)

      capture_exception(error, kind: "error")
      flush(resend: false)
      keep_resending
    end

    # The process is exiting: what a resend hasn't sent yet goes back in the file.
    def keep_resending
      left = @lock.synchronize do
        taken = @resending
        @resending = []
        taken
      end
      spool(left)
    end

    def relative(line)
      return line if @root.empty?

      line.start_with?("#{@root}/") ? line[(@root.size + 1)..] : line.gsub("#{@root}/", "")
    end

    # The backtrace in the shape the collector reads Ruby frames in
    # (expresscollect/utils/jsError.js RUBY_FRAME): "Class: message", then one
    # "path:line:in `method'" per line, then each cause the same way.
    def stack_of(error)
      out = []
      seen = {}
      current = error
      depth = 0
      while current.is_a?(Exception) && !seen[current.object_id] && depth <= MAX_CAUSES
        seen[current.object_id] = true
        first = SiteGoose.text(current.message, MAX_MESSAGE).lines.first.to_s.chomp
        out << "#{depth.zero? ? '' : 'Caused by: '}#{current.class.name}: #{first}"
        (current.backtrace || []).first(MAX_FRAMES).each { |frame| out << "\t#{relative(SiteGoose.text(frame))}" }
        current = current.cause
        depth += 1
      end
      out.join("\n")
    end

    # request: {"method", "path", "route", "session_id"} (the integrations fill it in).
    def capture_exception(error, request: nil, status: 0, kind: "handled")
      return unless @core.on?("errors")

      is_error = error.is_a?(Exception)
      request ||= Context.request_fields
      # The framework, your handler and logging can all see one error: sent
      # once, and a later capture fills in the event while it waits.
      waiting = is_error ? (error.instance_variable_get(SEEN) rescue nil) : nil # rubocop:disable Style/RescueModifier
      return upgrade(error, waiting, request, status, kind) if waiting

      message = SiteGoose.text(is_error ? error.message : error, MAX_MESSAGE)
      type = is_error ? error.class.name.to_s : "Error"
      event = {
        "message" => message.empty? ? (is_error ? type : "Unknown error") : message,
        "error_type" => type,
        "stack" => is_error ? stack_of(error) : "",
        "kind" => kind.to_s,
        "status_code" => status.to_i,
        "runtime" => "Ruby",
        "runtime_version" => RUBY_VERSION,
        "os" => Errors.os_name,
        "server_name" => @server_name,
        "release" => @release,
        # When it happened: a crash sent after a restart keeps its own time.
        "at" => SiteGoose.iso_now
      }
      trail = Context.breadcrumbs
      event["breadcrumbs"] = trail unless trail.empty?
      (request || {}).each do |k, v|
        key = k.to_s
        event[key] = SiteGoose.text(v) if FIELDS.include?(key)
      end
      if event["path"] && !event["path"].empty?
        event["path"] = event["path"].split("?", 2)[0].to_s
        # Named as Server speed names the request, so the two match.
        event["route"] = Performance.normalize_route(event["path"]) if event["route"].to_s.empty?
      end
      if @before_send
        event = run_before_send(event, error)
        return unless event
      end
      full = @lock.synchronize do
        if @queue.size >= QUEUE_MAX
          @core.log("errors", "queue full, error dropped")
          return
        end
        @queue << event
        @queue.size >= BATCH
      end
      begin
        error.instance_variable_set(SEEN, event) if is_error && !error.frozen?
      rescue StandardError
        nil
      end
      @job&.run_now if full
      nil
    rescue StandardError => e
      @core.log("errors", "could not capture error:", e.message)
      nil
    end

    # Your before_send's answer: a Hash is the event to send, nil drops it,
    # and anything else (a string, true, a raise) drops it too, said once.
    def run_before_send(event, error)
      out = @before_send.call(event, error)
      return out if out.nil? || out.is_a?(Hash)

      warn_once("before_send returned a #{out.class}, not a Hash or nil: the error was dropped")
      nil
    rescue StandardError => e
      warn_once("before_send raised #{e.class}: #{e.message}; the error was dropped")
      nil
    end

    def warn_once(text)
      return if @warned

      @warned = true
      warn "[analytics-platform] #{text}"
    end

    # An exception logged and then raised on is captured first as "logged",
    # with no status; the framework's capture that follows knows the status,
    # the kind and the request.
    def upgrade(error, waiting, request, status, kind)
      return if kind.to_s == "logged"

      @lock.synchronize do
        index = @queue.index { |queued| queued.equal?(waiting) }
        return if index.nil?

        event = waiting.merge(
          "kind" => waiting["kind"] == "logged" ? kind.to_s : waiting["kind"],
          "status_code" => waiting["status_code"].to_i.positive? ? waiting["status_code"] : status.to_i
        )
        FIELDS.each do |key|
          value = request && (request[key] || request[key.to_sym])
          event[key] = SiteGoose.text(value) if event[key].to_s.empty? && value && !value.to_s.empty?
        end
        event["path"] = event["path"].split("?", 2)[0].to_s if event["path"] && !event["path"].empty?
        if event["route"].to_s.empty? && event["path"] && !event["path"].empty?
          event["route"] = Performance.normalize_route(event["path"])
        end
        event = run_before_send(event, error) if @before_send
        if event
          @queue[index] = event
          error.instance_variable_set(SEEN, event) unless error.frozen?
        else
          @queue.delete_at(index)
        end
      end
      nil
    rescue StandardError => e
      @core.log("errors", "could not capture error:", e.message)
      nil
    end

    def flush(resend: true)
      waiting = @lock.synchronize do
        taken = @queue
        @queue = []
        taken
      end
      sent = true
      waiting.each_slice(BATCH) do |batch|
        body = { "errors" => batch }
        res = @core.request("errors", "/events/server-errors", body: body)
        # Tried once more a little later, but not when the process is
        # ending: what's left waits in the file instead.
        if Errors.failed?(res) && SiteGoose.time_left.nil?
          sleep(Errors.retry_after) if Errors.retry_after.positive?
          res = @core.request("errors", "/events/server-errors", body: body)
        end
        if Errors.failed?(res)
          sent = false
          spool(batch)
        end
      end
      # Not straight after the collector failed this flush: it would only
      # wait out another timeout.
      return unless resend && sent && @spool_file && SiteGoose.time_left.nil?

      self.resend if Time.now.to_f - @last_resend >= RESEND_EVERY
    end

    # Appends events to the file. Credentials are added when sent, never written down.
    def spool(events)
      return if @spool_file.nil? || events.nil? || events.empty?

      lines = events.map { |event| "#{JSON.generate(event)}\n" }
      have = File.exist?(@spool_file) ? File.size(@spool_file) : 0
      # What fits, oldest first: the file never grows past SPOOL_BYTES.
      room = SPOOL_BYTES - have
      kept = lines.take_while { |line| (room -= line.bytesize) >= 0 }
      @core.log("errors", "waiting errors file is full, #{lines.size - kept.size} errors dropped") if kept.size < lines.size
      return if kept.empty?

      File.open(@spool_file, File::WRONLY | File::CREAT | File::APPEND, 0o600) do |out|
        out.write(kept.join)
      end
    rescue StandardError => e
      @core.log("errors", "could not keep errors to send later:", e.message)
    end

    # Sends what earlier attempts (or an earlier run) couldn't. Taken by
    # renaming the file first, so two processes never send the same errors.
    def resend
      @last_resend = Time.now.to_f
      return if @spool_file.nil? || !@resend_lock.try_lock

      begin
        resend_taken
      ensure
        @resend_lock.unlock
      end
    end

    def resend_taken
      taken = "#{@spool_file}.#{Process.pid}.#{Thread.current.object_id}.sending"
      begin
        File.rename(@spool_file, taken)
      rescue SystemCallError
        return # nothing waiting
      end
      events = []
      begin
        File.foreach(taken, encoding: "UTF-8") do |line|
          event = JSON.parse(line)
          events << event if event.is_a?(Hash)
        rescue JSON::ParserError
          next
        end
      ensure
        File.delete(taken) rescue nil # rubocop:disable Style/RescueModifier
      end
      @lock.synchronize { @resending = events }
      loop do
        batch = @lock.synchronize do
          break nil if !@resending.equal?(events) || events.empty? # all sent, or written back by a crash

          events.first(BATCH)
        end
        break if batch.nil?

        if Errors.failed?(@core.request("errors", "/events/server-errors", body: { "errors" => batch }))
          left = @lock.synchronize do
            l = @resending.equal?(events) ? events : []
            @resending = []
            l
          end
          spool(left)
          return
        end
        @lock.synchronize { events.shift(batch.size) }
      end
      @lock.synchronize { @resending = [] if @resending.equal?(events) }
    end

    def close
      @job&.stop
      Forking.unregister(self)
      flush
    end
  end

  # Sends the exception a Logger is given at ERROR or above (logger.error(e),
  # or the exception as the message); still logged as before. A line of text
  # isn't sent: it has no backtrace to group it by.
  module LoggerCapture
    def add(severity, message = nil, progname = nil, &block)
      begin
        error = [message, progname].find { |m| m.is_a?(Exception) }
        hook = @__sitegoose_capture
        hook.call(error) if error && hook && severity.to_i >= ::Logger::ERROR
      rescue StandardError
        nil
      end
      super
    end
  end
end
