# frozen_string_literal: true

# Sidekiq: every job runs as a platform.job() named after its class (the
# ActiveJob class when Sidekiq runs ActiveJob). Its errors carry
# "/(job) <class>" as their route, and each run is timed (Health -> Server
# speed -> Jobs).
#
#     # config/initializers/sidekiq.rb
#     require "sitegoose/sidekiq"
#     SiteGoose::Sidekiq.install
#
# A failure that will be retried is timed as failed but not sent: the error
# is sent when the last attempt fails (retry: false, retry: 0, or the retries
# used up), or when Sidekiq gives the job up (its death handlers: a job sent
# to the Dead set, sidekiq_retry_in returning :kill). Sidekiq stopping a job
# mid-run (Sidekiq::Shutdown) is neither timed nor sent: it runs again. What's
# waiting is sent when Sidekiq shuts down.
#
# The queues' backlog (sdk/protocols/queues.md, system "sidekiq"): the
# Sidekiq process reads every queue once a minute through Sidekiq's API
# (sidekiq/api): waiting is Sidekiq::Queue#size, oldest_s its latency,
# running the WorkSet's jobs per queue, delayed the ScheduledSet's and
# RetrySet's jobs per queue, failed the DeadSet's. One process reads a
# minute (a Redis key per minute decides which); the others count only.
# added and finished are each process's own: a client middleware counts the
# jobs pushed, once each (it marks the job it counted, so the scheduler or a
# retry moving it back isn't a second one), the server middleware the jobs
# that left for good (done, or failed on the last attempt, or given up).

module SiteGoose
  module Sidekiq
    SKIP = :@__sitegoose_skip
    DEFAULT_RETRIES = 25
    SYSTEM = "sidekiq"
    # Set in the job's own hash (stored with it in Redis) once a push has
    # been counted as added: the scheduler, a retry or the Web UI pushing the
    # same job back carries it, so the job is never counted twice.
    ADDED = "sitegoose_added"
    # The jid the server middleware just counted as finished: the death
    # handler, which runs after it in the same thread, leaves it.
    COUNTED = :sitegoose_sidekiq_finished

    module_function

    # Adds the server and client middleware, the death handler, the queue
    # readings and the shutdown flush; in a process that only pushes jobs (a
    # Rails server), the client middleware.
    # platform: default the configured one (SiteGoose.platform).
    def install(platform = nil)
      ::Sidekiq.configure_server do |config|
        config.server_middleware { |chain| chain.add ServerMiddleware, platform }
        config.client_middleware { |chain| chain.add ClientMiddleware, platform } if config.respond_to?(:client_middleware)
        config.death_handlers << ->(job, error) { Sidekiq.died(platform, job, error) } if config.respond_to?(:death_handlers)
        if config.respond_to?(:on)
          config.on(:startup) { Sidekiq.start_reading(platform, config) }
          config.on(:shutdown) { SiteGoose.within { (platform || SiteGoose.platform)&.flush } }
        end
      end
      return unless ::Sidekiq.respond_to?(:configure_client)

      ::Sidekiq.configure_client do |config|
        config.client_middleware { |chain| chain.add ClientMiddleware, platform } if config.respond_to?(:client_middleware)
      end
    end

    def name_of(job)
      (job["wrapped"] || job["class"]).to_s
    end

    # Sidekiq 7+'s configuration, 6.5's Sidekiq[] (its Sidekiq.options logs
    # a deprecation warning on every call, here every job), or older 6's.
    def max_retries
      config = if ::Sidekiq.respond_to?(:default_configuration) then ::Sidekiq.default_configuration
               elsif ::Sidekiq.respond_to?(:[]) then ::Sidekiq
               elsif ::Sidekiq.respond_to?(:options) then ::Sidekiq.options
               end
      value = config && config[:max_retries]
      value.is_a?(Integer) ? value : DEFAULT_RETRIES
    rescue StandardError
      DEFAULT_RETRIES
    end

    # Whether this run is the job's last: no retries, or the retries used up.
    # retry_count is nil on the first run and 0 on the first retry. As
    # Sidekiq's JobRetry reads it: a retry that isn't an Integer is the
    # default count, and retry_for (7.1+) retries for a time rather than a
    # count, so no run is known to be the last; Sidekiq's death handler
    # counts and sends the one it gives up.
    def last_attempt?(job)
      retry_option = job["retry"]
      return true if retry_option == false || retry_option.nil?
      return false if job["retry_for"]

      allowed = retry_option.is_a?(Integer) ? retry_option : max_retries
      attempts = job["retry_count"].nil? ? 0 : job["retry_count"].to_i + 1
      attempts >= allowed
    end

    def died(platform, job, error)
      made = platform || SiteGoose.platform
      return unless made

      # Given up before its last attempt (sidekiq_retry_in :kill): it left
      # the queue for good, and the middleware didn't count it.
      counted = Thread.current[COUNTED]
      Thread.current[COUNTED] = nil
      finished(made, job["queue"]) if job.is_a?(Hash) && (counted.nil? || counted != job["jid"])
      return unless error.is_a?(Exception)

      error.remove_instance_variable(SKIP) if error.instance_variable_defined?(SKIP)
      route = "/(job) #{SiteGoose.text(name_of(job), 180)}"
      made.capture_exception(error, status: 500, kind: "error",
                                    request: { "method" => "JOB", "path" => route, "route" => route, "session_id" => "" })
    rescue StandardError
      nil
    end

    # ---- The queues ----

    def finished(made, queue)
      made.queues&.count(SYSTEM, broker, queue.to_s, :finished) unless queue.to_s.empty?
    rescue StandardError
      nil
    end

    # Whether a push is a new job rather than Sidekiq's scheduler, a retry
    # or the Web UI moving one onto its queue (client middleware runs for
    # all of them, with the job hash as it was stored). A job counted when
    # it was first pushed carries ADDED; a retry carries retry_count. Sidekiq
    # keeps nothing else that tells them apart: created_at is set once for a
    # whole push_bulk, so its age says nothing about a push.
    def new_job?(job)
      job.is_a?(Hash) && !job.key?(ADDED) && !job.key?("retry_count")
    end

    # Where the queues live: host, port and Redis database, never a user
    # name or password. Read once from Sidekiq's connection.
    def broker
      @broker ||= begin
        found = ::Sidekiq.redis { |conn| broker_of(conn) }
        found.is_a?(String) && !found.empty? ? found : broker_from_url(ENV["REDIS_URL"])
      rescue StandardError
        broker_from_url(ENV["REDIS_URL"])
      end
    end

    # For tests, and after the configuration changed.
    def broker=(value)
      @broker = value
    end

    # A connection's host:port/db: redis-client's config (Sidekiq 7+), or
    # the redis gem's connection hash (Sidekiq 6).
    def broker_of(conn)
      if conn.respond_to?(:config) && conn.config.respond_to?(:host)
        config = conn.config
        path = config.respond_to?(:path) ? config.path : nil
        return broker_string(config.host, config.port, config.db, path)
      end
      if conn.respond_to?(:connection)
        info = conn.connection
        return broker_string(info[:host], info[:port], info[:db], info[:path]) if info.is_a?(Hash)
      end
      nil
    end

    def broker_from_url(url)
      uri = URI.parse(url.to_s)
      return "localhost:6379/0" if uri.host.nil?

      broker_string(uri.host, uri.port, uri.path.to_s.delete("/").to_i, nil)
    rescue URI::Error
      "localhost:6379/0"
    end

    def broker_string(host, port, db, path)
      db = db.to_i
      return "#{path.to_s.split('/').last.to_s[0, 80]}/#{db}" if path.is_a?(String) && !path.empty?

      # Only what follows a user name or password, were one ever there.
      host = host.to_s.split("@").last.to_s.gsub(%r{[\s/]}, "")[0, 120]
      host = "localhost" if host.empty?
      "#{host}:#{port.to_i.positive? ? port.to_i : 6379}/#{db}"
    end

    # The queues this process runs jobs from (Sidekiq 7's capsules, or 6's
    # options): their finished count is 0 in a quiet minute, not unknown.
    def own_queues(config)
      names = if config.respond_to?(:capsules) then config.capsules.values.flat_map(&:queues)
              elsif config.respond_to?(:queues) then config.queues
              elsif config.respond_to?(:options) then config.options[:queues]
              elsif config.respond_to?(:[]) then config[:queues]
              end
      Array(names).map(&:to_s).reject(&:empty?).uniq
    rescue StandardError
      []
    end

    # At Sidekiq's startup: this process reads the queues once a minute.
    def start_reading(platform, config = nil)
      made = platform || SiteGoose.platform
      queues = made&.queues
      return unless queues

      own_queues(config).each { |name| queues.counting(SYSTEM, broker, name, :finished) }
      queues.watch(Reader.new(queues.sender, made.core.site_id))
    rescue StandardError => e
      made&.core&.log("queues", "could not start reading Sidekiq's queues:", e.message)
    end

    # Sidekiq's queues, read through its public API (sidekiq/api).
    class Reader
      # A sorted set bigger than this isn't counted per queue (Sidekiq reads
      # it 50 jobs at a time, each parsed): its field is unknown rather than
      # megabytes read from Redis every minute. With one queue no job has to
      # be read: the set's size is that queue's.
      SET_MAX = 1_000
      LOCK_SECONDS = 90

      # sender: this process (Queues#sender); site: the site the readings are
      # for, so two sites sharing one Redis each get theirs.
      def initialize(sender, site = "")
        @sender = sender
        @site = site.to_s
      end

      # -> one reading per queue ({system:, broker:, queue:, waiting: ...}),
      # [] when another process reads this minute. Raises when Redis
      # doesn't answer (a gap).
      def read
        require "sidekiq/api" unless defined?(::Sidekiq::Queue)
        return [] unless reader_this_minute?

        broker = Sidekiq.broker
        queues = ::Sidekiq::Queue.all.first(Queues::MAX_QUEUES)
        names = queues.map { |queue| queue.name.to_s }
        running = safely { running_by_queue }
        scheduled = safely { by_queue(::Sidekiq::ScheduledSet.new, names) }
        retrying = safely { by_queue(::Sidekiq::RetrySet.new, names) }
        dead = safely { by_queue(::Sidekiq::DeadSet.new, names) }
        queues.map do |queue|
          name = queue.name.to_s
          waiting = queue.size.to_i
          { system: SYSTEM, broker: broker, queue: name, waiting: waiting,
            running: running && running[name].to_i,
            delayed: scheduled && retrying ? scheduled[name].to_i + retrying[name].to_i : nil,
            failed: dead && dead[name].to_i,
            oldest_s: oldest(queue, waiting) }
        end
      end

      # Seconds the oldest waiting job has waited: 0 with none, unknown when
      # Sidekiq can't say (a job pushed without enqueued_at reads 0.0).
      def oldest(queue, waiting)
        return 0 if waiting.zero?

        latency = queue.latency.to_f
        latency.positive? ? latency.round : nil
      rescue StandardError
        nil
      end

      def safely
        yield
      rescue StandardError
        nil
      end

      def running_by_queue
        set = defined?(::Sidekiq::WorkSet) ? ::Sidekiq::WorkSet.new : ::Sidekiq::Workers.new
        out = Hash.new(0)
        set.each do |_process, _thread, work|
          name = work.respond_to?(:queue) ? work.queue : work["queue"]
          out[name.to_s] += 1
        end
        out
      end

      # queue name -> jobs of the set in it, or nil when that would mean
      # reading more than SET_MAX jobs.
      def by_queue(set, names = [])
        size = set.size
        out = Hash.new(0)
        return out if size.zero?
        return out.merge!(names[0] => size) if names.size == 1
        return nil if size > SET_MAX

        set.each { |entry| out[entry.queue.to_s] += 1 }
        out
      end

      # One Sidekiq process reads a minute: the first to set this minute's
      # key. Without the answer (an old client, a namespace) it reads anyway:
      # gauges taken twice are harmless, the dashboard keeps the largest.
      def reader_this_minute?
        key = "sitegoose:queues:#{@site}:#{MinuteRows.minute}"
        got = ::Sidekiq.redis { |conn| conn.call("SET", key, @sender, "NX", "EX", LOCK_SECONDS.to_s) }
        got.nil? || got == false ? false : true
      rescue StandardError
        true
      end
    end

    class ServerMiddleware
      include ::Sidekiq::ServerMiddleware if defined?(::Sidekiq::ServerMiddleware)

      def initialize(platform = nil)
        @platform = platform
      end

      def call(_worker, job, queue, &block)
        made = @platform || SiteGoose.platform
        return yield if made.nil?

        Forking.check
        last = Sidekiq.last_attempt?(job)
        done = false
        begin
          result = made.job(Sidekiq.name_of(job), report: lambda { |error|
            # Retried: Rails' own error report (its executor wraps the job) is
            # told to leave it too.
            error.instance_variable_set(SKIP, true) if !last && !error.frozen?
            last
          }, &block)
          done = true
          result
        rescue SignalException, SystemExit
          # Sidekiq::Shutdown: it runs again.
          raise
        rescue Exception # rubocop:disable Lint/RescueException -- raised on
          done = last
          raise
        ensure
          if done
            Thread.current[COUNTED] = job["jid"]
            Sidekiq.finished(made, queue)
          end
        end
      end
    end

    # Counts the jobs this process pushes (Health -> Server speed -> Jobs:
    # added), once each: the scheduler and a retry pushing one back aren't
    # new jobs. A scheduled job counts when it is scheduled. One pushed by a
    # process without this middleware counts when the scheduler moves it.
    class ClientMiddleware
      include ::Sidekiq::ClientMiddleware if defined?(::Sidekiq::ClientMiddleware)

      def initialize(platform = nil)
        @platform = platform
      end

      def call(_worker_class, job, queue, _redis_pool = nil)
        result = yield
        begin
          if result && Sidekiq.new_job?(job)
            counter = (@platform || SiteGoose.platform)&.queues
            if counter&.on?
              counter.count(SYSTEM, Sidekiq.broker, (queue || job["queue"]).to_s, :added)
              # The hash Sidekiq pushes (the job itself, unless a middleware
              # handed back another).
              (result.is_a?(Hash) ? result : job)[ADDED] = true
            end
          end
        rescue StandardError
          nil
        end
        result
      end
    end
  end
end
