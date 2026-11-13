# frozen_string_literal: true

# Database queries (sdk/protocols/queries.md), part of Server speed: per
# minute, request method and route, database and query, how many ran, how
# many failed, their total and slowest time and a count per time bucket, sent
# to POST /events/server-queries. Every value in a query is replaced by "?"
# before it is counted (QueryText); bound parameters are never read.
#
# Caught through each library's public hook, one layer per query:
#   Rails (Active Record): the sql.active_record notification, automatic.
#     SCHEMA and cached queries are left out.
#   Sequel: SiteGoose.watch_database(DB), one line. A Sequel query
#     run on Active Record's connection is counted once, as Sequel's.
#   Mongo (the mongo gem, Mongoid): a global command subscriber, automatic.
#   ClickHouse: the click_house gem's ClickHouse::Connection through
#     SiteGoose.watch_database(connection), one line; an Active Record
#     ClickHouse adapter (clickhouse-activerecord) through sql.active_record.
#   Redis: redis-client's global middleware (RedisClient.register),
#     automatic; the redis gem 5 and Sidekiq 7 run on it. Each command is
#     "GET user:?:cart" (QueryText.redis_command): the command and its first
#     key's shape, never an argument or value.
#
# A query is added to the request (or job) it ran in, and the request's
# queries go into the minute's rows when it finishes, under the method and
# route Server speed records for it. A query outside any request or job is
# "JOB" "(background)". Rides on the performance module: with Server speed
# off nothing is recorded; queries: false keeps Server speed without them.

module SiteGoose
  # What Queries and Calls share (sdk/protocols/queries.md and calls.md,
  # "Recording"): each timing is filed under the request (or job) it ran in,
  # keyed by its two fields (db + statement, call method + host); when the
  # request finishes they go into the minute's rows under the method and
  # route Server speed recorded; outside any request or job they are
  # "JOB" "(background)". Finished minutes are sent every 60 seconds, and
  # everything on shutdown. The including class names FIELDS (its two key
  # fields as sent), PATH, MOD (the name it logs under) and REQUEST (the
  # thread-local the request's own map lives in, which Context.with clears).
  module MinuteRows
    FLUSH_EVERY = 60
    MAX_ROWS = 500
    # Distinct keys one request keeps; past it new ones are "(other)".
    MAX_PER_REQUEST = 50
    # Keys in a minute: past MAX_KEYS new ones are "(other)", past
    # HARD_MAX_KEYS nothing new is kept.
    MAX_KEYS = 200
    HARD_MAX_KEYS = 300
    # Minutes kept unsent (a platform that can't send flushes by hand).
    MAX_MINUTES = 5
    OTHER = "(other)"
    BACKGROUND = ["JOB", "(background)"].freeze

    def self.minute
      (Time.now.to_i / 60) * 60
    end

    # -> [count, errors, sum_ms, max_ms, buckets] as a hash.
    def self.blank
      { count: 0, errors: 0, sum_ms: 0.0, max_ms: 0.0, buckets: Array.new(Performance::BUCKET_EDGES_MS.size + 1, 0) }
    end

    def self.merge(into, from)
      into[:count] += from[:count]
      into[:errors] += from[:errors]
      into[:sum_ms] += from[:sum_ms]
      into[:max_ms] = from[:max_ms] if from[:max_ms] > into[:max_ms]
      from[:buckets].each_with_index { |n, i| into[:buckets][i] += n }
      into
    end

    def self.add(into, ms, failed)
      into[:count] += 1
      into[:errors] += 1 if failed
      into[:sum_ms] += ms
      into[:max_ms] = ms if ms > into[:max_ms]
      into[:buckets][Performance.bucket_of(ms)] += 1
      into
    end

    attr_reader :rows

    def start_rows(core, server_name)
      @core = core
      @server_name = SiteGoose.text(server_name || SiteGoose.hostname, 100)
      @rows = {}
      @lock = Mutex.new
      @job = core.valid? ? Periodic.new(FLUSH_EVERY) { flush(everything: false); FLUSH_EVERY } : nil
      Forking.register(self)
    end

    # In a forked worker the parent's rows are the parent's to send.
    def after_fork_in_child
      @lock = Mutex.new
      @rows = {}
    end

    def on?
      @core.on?("performance")
    end

    # One timing (first, second: its two key fields) into its request's map,
    # or straight into the minute's rows as background.
    def file(first, second, ms, failed)
      ms = ms.to_f
      ms = 0.0 if ms.negative? || ms.nan?
      if Context.request
        mine = (Thread.current[self.class::REQUEST] ||= {})
        key = [first, second]
        key = [first, OTHER] if !mine.key?(key) && mine.size >= MAX_PER_REQUEST
        MinuteRows.add(mine[key] ||= MinuteRows.blank, ms, failed)
      else
        one = MinuteRows.add(MinuteRows.blank, ms, failed)
        @lock.synchronize { add_row(MinuteRows.minute, *BACKGROUND, first, second, one) }
      end
    end

    # The request (or job) finished, and Server speed recorded it under
    # method and route: its timings go into this minute's rows.
    def finish(method, route)
      mine = Thread.current[self.class::REQUEST]
      Thread.current[self.class::REQUEST] = nil
      return if mine.nil? || mine.empty? || !on?

      minute = MinuteRows.minute
      @lock.synchronize do
        mine.each { |(first, second), agg| add_row(minute, method, route, first, second, agg) }
      end
    end

    # Under @lock.
    def add_row(minute, method, route, first, second, agg)
      keys = @rows[minute]
      unless keys
        @rows.delete(@rows.keys.min) while @rows.size >= MAX_MINUTES
        keys = @rows[minute] = {}
      end
      key = [method, route, first, second]
      key = [method, route, first, OTHER] if !keys.key?(key) && keys.size >= MAX_KEYS
      return if !keys.key?(key) && keys.size >= HARD_MAX_KEYS

      MinuteRows.merge(keys[key] ||= MinuteRows.blank, agg)
    end
    private :add_row

    def flush(everything: true)
      current = MinuteRows.minute
      ready = @lock.synchronize do
        taken = @rows.select { |minute, _| everything || minute < current }
        taken.each_key { |minute| @rows.delete(minute) }
        taken
      end
      first_name, second_name = self.class::FIELDS
      rows = ready.flat_map do |minute, keys|
        at = Time.at(minute).utc.iso8601(3)
        keys.map do |(method, route, first, second), v|
          { "minute" => at, "method" => method, "route" => route, first_name => first, second_name => second,
            "count" => v[:count], "errors" => v[:errors], "sum_ms" => v[:sum_ms].round(1),
            "max_ms" => v[:max_ms].round(1), "buckets" => v[:buckets] }
        end
      end
      rows.each_slice(MAX_ROWS) do |batch|
        @core.request(self.class::MOD, self.class::PATH, auth: :bearer,
                      body: { "site_id" => @core.site_id, "server_name" => @server_name,
                              "runtime" => RUNTIME, "rows" => batch })
      end
    end

    def stop_rows
      @job&.stop
      Forking.unregister(self)
      flush
    end
  end

  # The instances a class's hooks report to (Queries, Calls): the newest
  # platform's that is still open. The class sets @open and @lock.
  module OpenList
    def active
      @lock.synchronize { @open.last }
    end

    def opened(item)
      @lock.synchronize { @open << item }
    end

    def closed(item)
      @lock.synchronize { @open.delete(item) }
    end
  end

  class Queries
    # The request's own queries, fiber-local beside Context's fields: Context.with
    # starts each request or job with none.
    REQUEST = Context::QUERIES
    # Set while an outer layer times a query, so an inner one leaves it.
    TIMING = :sitegoose_query_timing
    # Set while the package makes Redis commands of its own (the queue
    # readings), which aren't timed.
    OWN = :sitegoose_own_redis
    CACHE_MAX = 2000
    CACHE_TEXT = 4000

    @open = []
    @lock = Mutex.new
    @cache = {}
    @hooked = {}
    extend OpenList

    class << self
      # The statement as stored ("" to leave it out); the same query text
      # comes round again and again, so the answer is kept.
      def statement(text, db)
        return QueryText.normalize_statement(text, db) if !text.is_a?(String) || text.size > CACHE_TEXT

        key = [db, text]
        found = @lock.synchronize { @cache[key] }
        return found if found

        shaped = QueryText.normalize_statement(text, db).freeze
        @lock.synchronize do
          @cache.clear if @cache.size >= CACHE_MAX
          @cache[key.map { |part| part.dup.freeze }] = shaped
        end
        shaped
      end

      def timing?
        Thread.current[TIMING] ? true : false
      end

      # Runs the block with this thread's queries marked as timed by an outer layer.
      def timing
        saved = Thread.current[TIMING]
        Thread.current[TIMING] = true
        yield
      ensure
        Thread.current[TIMING] = saved
      end

      def own?
        Thread.current[OWN] ? true : false
      end

      # Whether a Redis command now goes untimed: the package's own, no
      # platform timing queries, or no answer to that (a signal handler
      # can't take the lock), which never reaches the app's command.
      def redis_untimed?
        own? || active.nil?
      rescue StandardError
        true
      end

      # Runs the block with this thread's Redis commands left out: the
      # package's own.
      def own
        saved = Thread.current[OWN]
        Thread.current[OWN] = true
        yield
      ensure
        Thread.current[OWN] = saved
      end

      # One finished query, from any hook. db: one of QueryText::DATABASES.
      def record(db, text, ms, failed: false)
        active&.record(db, text, ms, failed: failed)
      rescue StandardError
        nil
      end

      # ---- Hooks: installed once per process, for every platform ----

      def install
        hook_active_record
        hook_mongo
        hook_redis
      end

      # redis-client's global middleware, registered once per process. The
      # redis gem 4 has its own connection code, which this doesn't see.
      def hook_redis
        return if @hooked[:redis] || !defined?(::RedisClient) || !::RedisClient.respond_to?(:register)

        @hooked[:redis] = true
        return if defined?(::RedisClient::Middlewares) && ::RedisClient::Middlewares.include?(RedisHook)

        ::RedisClient.register(RedisHook)
      rescue StandardError
        nil
      end

      # The connection's own set-up, which redis-client sends as a pipeline
      # when it connects.
      PRELUDE = %w[HELLO AUTH SELECT CLIENT ROLE READONLY].to_h { |name| [name, true] }.freeze

      # A pipeline as one call: "PIPELINE <first command timed>", or "MULTI
      # <first command>" for a transaction (MULTI ... EXEC); nil when none
      # of its commands is timed, or it is the connection's set-up.
      def redis_pipeline(commands)
        return nil if !commands.is_a?(Array) || commands.empty?

        if redis_name(commands[0]) == "MULTI"
          prefix = "MULTI"
          ends = redis_name(commands[-1])
          last = ends == "EXEC" || ends == "DISCARD" ? -2 : -1
          inside = commands[1..last]
        else
          # Stops at the first command that isn't set-up: an app's pipeline
          # of thousands isn't read twice.
          return nil if commands.all? { |command| PRELUDE.key?(redis_name(command)) }

          prefix = "PIPELINE"
          inside = commands
        end
        inside.each do |command|
          first = QueryText.redis_command(command)
          return "#{prefix} #{first}" if first
        end
        nil
      end

      def redis_name(command)
        command.is_a?(Array) ? QueryText.redis_word(command[0]) : nil
      end

      # Runs a Redis command (or pipeline) and records it: failed when it
      # raised (an error reply, no answer) or, for a pipeline, answered an
      # error (sent with exception: false, or inside a transaction's EXEC,
      # which redis-client raises only after the middleware). A single
      # command's error reply always raises, so its answer isn't looked at.
      # MOVED and ASK are redirections: the cluster client sends the command
      # again (through this middleware too), so the redirected try isn't
      # recorded, only the one that answers.
      def time_redis(statement, pipelined: false)
        started = SiteGoose.clock
        failed = true
        redirected = false
        begin
          result = yield
          failed = pipelined ? redis_errors?(result, statement.start_with?("MULTI ")) : false
          result
        rescue StandardError => e
          failed = redis_error?(e)
          redirected = !failed
          raise
        ensure
          record("redis", statement, (SiteGoose.clock - started) * 1000, failed: failed) unless redirected
        end
      end

      # A pipeline's answers: an error among them, or in a transaction's
      # EXEC answer (its last).
      def redis_errors?(results, multi)
        return false unless results.is_a?(Array)
        return true if results.any? { |item| redis_error?(item) }

        multi && results.last.is_a?(Array) && results.last.any? { |item| redis_error?(item) }
      end

      def redis_error?(value)
        return false unless value.is_a?(StandardError)

        message = value.message.to_s
        !(message.start_with?("MOVED ") || message.start_with?("ASK "))
      rescue StandardError
        true
      end

      # Active Record's sql.active_record notification (Rails, or Active
      # Record on its own). Monotonic times where Rails has them.
      def hook_active_record
        return if @hooked[:active_record] || !defined?(::ActiveSupport::Notifications)

        @hooked[:active_record] = true
        handler = lambda do |_name, started, finished, _id, payload|
          Queries.active_record(started, finished, payload)
        end
        if ::ActiveSupport::Notifications.respond_to?(:monotonic_subscribe)
          ::ActiveSupport::Notifications.monotonic_subscribe("sql.active_record", &handler)
        else
          ::ActiveSupport::Notifications.subscribe("sql.active_record", &handler)
        end
      rescue StandardError
        nil
      end

      def active_record(started, finished, payload)
        return if !payload.is_a?(Hash) || timing? || active.nil?

        name = payload[:name].to_s
        return if name == "SCHEMA" || name == "CACHE" || payload[:cached]

        failed = payload[:exception] || payload[:exception_object] ? true : false
        record(active_record_db(payload[:connection]), payload[:sql], (finished - started).to_f * 1000, failed: failed)
      rescue StandardError
        nil
      end

      # The connection's adapter, as a database name.
      def active_record_db(connection)
        name = connection.respond_to?(:adapter_name) ? connection.adapter_name.to_s.downcase : ""
        case name
        when /postg/ then "postgresql"
        when "mysql", "mysql2", "trilogy" then "mysql"
        when /sqlite/ then "sqlite"
        when /sqlserver|mssql/ then "mssql"
        when /oracle/ then "oracle"
        when /clickhouse/ then "clickhouse"
        else "other"
        end
      end

      # The mongo gem's global command monitoring (Mongoid uses it too).
      def hook_mongo
        return if @hooked[:mongo] || !defined?(::Mongo::Monitoring::Global)

        @hooked[:mongo] = true
        ::Mongo::Monitoring::Global.subscribe(::Mongo::Monitoring::COMMAND, MongoSubscriber.new)
      rescue StandardError
        nil
      end

      def sequel_db(database)
        case database.respond_to?(:database_type) ? database.database_type.to_s : ""
        when "postgres" then "postgresql"
        when "mysql" then "mysql"
        when "sqlite" then "sqlite"
        when "mssql" then "mssql"
        when "oracle" then "oracle"
        when "clickhouse" then "clickhouse"
        else "other"
        end
      end

      # Times every query a Sequel::Database runs.
      def watch_sequel(database)
        database.instance_variable_set(:@__sitegoose_db, sequel_db(database))
        database.extend(SequelHook) unless database.singleton_class.include?(SequelHook)
        database
      end

      # Times one click_house gem connection's public query methods. Only the
      # methods the object has are wrapped, on that object alone.
      def watch_clickhouse(connection)
        return connection if connection.singleton_class.include?(ClickHouseHook)

        wrapped = ClickHouseHook::METHODS.select { |name| connection.respond_to?(name) }
        hook = Module.new do
          include ClickHouseHook

          wrapped.each do |name|
            define_method(name) do |*args, **options, &block|
              text = ClickHouseHook.text_of(name, args)
              return super(*args, **options, &block) if text.nil? || Queries.timing? || Queries.active.nil?

              Queries.time("clickhouse", text) { super(*args, **options, &block) }
            end
          end
        end
        connection.extend(hook)
        connection
      end

      # Runs the block as one timed query, recorded when it ends (failed
      # when it raised); queries the block runs underneath aren't timed again,
      # and neither are its HTTP requests (Calls).
      def time(db, text)
        started = SiteGoose.clock
        failed = false
        begin
          timing { yield }
        rescue StandardError
          failed = true
          raise
        ensure
          record(db, text, (SiteGoose.clock - started) * 1000, failed: failed)
        end
      end
    end

    # The click_house gem (ClickHouse::Connection): select_all, select_one,
    # select_value and execute carry the SQL; insert names its table, and
    # its rows are never read. The gem answers once the whole result is
    # read, so the time is the query's to the end.
    module ClickHouseHook
      METHODS = %i[select_all select_one select_value execute insert].freeze

      def self.text_of(name, args)
        first = args[0]
        case name
        when :insert then first.nil? ? nil : "INSERT INTO #{first}"
        else first.is_a?(String) ? first : nil
        end
      rescue StandardError
        # A table name that can't be written: the call runs untimed.
        nil
      end
    end

    # redis-client's middleware (RedisClient.register): every client's
    # commands, the redis gem 5's and Sidekiq's too. Blocking commands
    # (BLPOP, BRPOP: Sidekiq's fetch) aren't timed, nor the package's own
    # (Queries.own). With no platform timing queries it only passes on.
    module RedisHook
      def call(command, redis_config)
        return super if Queries.redis_untimed?

        statement = begin
          QueryText.redis_command(command)
        rescue StandardError
          nil
        end
        return super if statement.nil?

        Queries.time_redis(statement) { super }
      end

      def call_pipelined(commands, redis_config)
        return super if Queries.redis_untimed?

        statement = begin
          Queries.redis_pipeline(commands)
        rescue StandardError
          nil
        end
        return super if statement.nil?

        Queries.time_redis(statement, pipelined: true) { super }
      end
    end

    # Extends one Sequel::Database (Sequel's own extensions wrap the same
    # public method); nothing else of Sequel is changed.
    module SequelHook
      def log_connection_yield(sql, conn, args = nil)
        return super if Queries.timing? || Queries.active.nil?

        started = SiteGoose.clock
        failed = false
        begin
          Queries.timing { super }
        rescue StandardError
          failed = true
          raise
        ensure
          Queries.record(@__sitegoose_db, sql, (SiteGoose.clock - started) * 1000, failed: failed)
        end
      end
    end

    # Mongo::Monitoring's command subscriber: the statement is built when a
    # command starts, recorded when it ends.
    class MongoSubscriber
      CHATTER = %w[hello isMaster ismaster ping buildInfo saslStart saslContinue getMore endSessions killCursors
                   getLastError].freeze
      FILTER = { "find" => "filter", "aggregate" => "pipeline", "count" => "query", "distinct" => "query",
                 "findAndModify" => "query" }.freeze
      LISTS = { "delete" => "deletes", "update" => "updates" }.freeze
      WAITING_MAX = 1000

      def initialize
        @waiting = {}
        @lock = Mutex.new
      end

      # "find users {...}" for a command (a hash).
      def self.text(name, command)
        collection = command.is_a?(Hash) ? command[name] : nil
        return name if collection.nil?

        filter = if FILTER.key?(name) then command[FILTER[name]]
                 elsif LISTS.key?(name)
                   first = command[LISTS[name]]
                   first = first.first if first.is_a?(Array)
                   first.is_a?(Hash) ? (first["q"] || first[:q]) : nil
                 end
        text = "#{name} #{collection}"
        filter.nil? ? text : "#{text} #{JSON.generate(QueryText.mongo_shape(filter))}"
      rescue StandardError
        name
      end

      def started(event)
        name = event.command_name.to_s
        return if CHATTER.include?(name) || Queries.active.nil?

        text = MongoSubscriber.text(name, event.command)
        @lock.synchronize do
          @waiting.shift while @waiting.size >= WAITING_MAX
          @waiting[event.request_id] = text
        end
      rescue StandardError
        nil
      end

      def succeeded(event)
        finished(event, false)
      end

      def failed(event)
        finished(event, true)
      end

      def finished(event, failed)
        text = @lock.synchronize { @waiting.delete(event.request_id) }
        Queries.record("mongodb", text, event.duration.to_f * 1000, failed: failed) if text
      rescue StandardError
        nil
      end
    end

    include MinuteRows
    FIELDS = %w[db statement].freeze
    PATH = "/events/server-queries"
    MOD = "queries"

    def initialize(core, server_name: nil)
      start_rows(core, server_name)
      Queries.opened(self)
      Queries.install
    end

    # One finished query: into its request's (or job's) queries, or, with
    # none around it, straight into the minute's rows as background.
    def record(db, text, ms, failed: false)
      return unless on?

      db = QueryText.database_of(db)
      statement = Queries.statement(text, db)
      return if statement.empty?

      file(db, statement, ms, failed)
    end

    def close
      Queries.closed(self)
      stop_rows
    end
  end

  # Times every query this database object runs (Health -> Server speed ->
  # Queries): SiteGoose.watch_database(DB) for a Sequel::Database or a
  # click_house gem ClickHouse::Connection. Rails' Active Record and the
  # mongo gem are caught on their own.
  def self.watch_database(database)
    if defined?(::Sequel::Database) && database.is_a?(::Sequel::Database)
      Queries.watch_sequel(database)
    elsif defined?(::ClickHouse::Connection) && database.is_a?(::ClickHouse::Connection)
      Queries.watch_clickhouse(database)
    else
      warn "[analytics-platform] watch_database: #{database.class} is not a Sequel::Database or a ClickHouse::Connection; " \
           "Active Record and Mongo are timed on their own"
    end
    database
  end
end
