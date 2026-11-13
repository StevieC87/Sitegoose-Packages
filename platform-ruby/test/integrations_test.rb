# frozen_string_literal: true

# Sidekiq and the Rails error subscriber, with Sidekiq itself stood in for
# (it isn't a dependency of the package or its tests).

require_relative "test_helper"

module Sidekiq
  class << self
    attr_accessor :hooks, :client_hooks

    def default_configuration
      { max_retries: 25 }
    end

    def configure_server
      config = FakeConfig.new
      yield config
      self.hooks = config
    end

    def configure_client
      config = FakeConfig.new
      yield config
      self.client_hooks = config
    end

    def redis
      yield FakeRedis.instance
    end
  end

  class FakeConfig
    attr_reader :middleware, :client, :death_handlers, :shutdown, :startup

    def initialize
      @death_handlers = []
    end

    def chain(ivar)
      chain = Object.new
      sink = self
      chain.define_singleton_method(:add) { |klass, *args| sink.instance_variable_set(ivar, klass.new(*args)) }
      chain
    end

    def server_middleware
      yield chain(:@middleware)
    end

    def client_middleware
      yield chain(:@client)
    end

    def on(event, &block)
      @shutdown = block if event == :shutdown
      @startup = block if event == :startup
    end

    def queues
      %w[default default mailers]
    end
  end

  # redis-client's config, and SET NX remembered per key.
  class FakeRedis
    Config = Struct.new(:host, :port, :db, :path)

    def self.instance
      @instance ||= new
    end

    attr_accessor :down

    def initialize
      @keys = {}
    end

    def config
      Config.new("redis.internal", 6380, 2, nil)
    end

    def call(*command)
      raise IOError, "connection refused" if down
      return "PONG" unless command[0] == "SET" && command.include?("NX")
      return nil if @keys.key?(command[1])

      @keys[command[1]] = command[2]
      "OK"
    end

    def forget
      @keys.clear
    end
  end

  # sidekiq/api's readers, with what a busy Sidekiq holds.
  class Queue
    attr_reader :name, :size, :latency

    def self.all
      raise IOError, "connection refused" if FakeRedis.instance.down

      [new("default", 3, 12.4), new("mailers", 0, 0.0)]
    end

    def initialize(name, size, latency)
      @name = name
      @size = size
      @latency = latency
    end
  end

  Entry = Struct.new(:queue)

  class FakeSet
    def self.entries
      []
    end

    def size
      self.class.entries.size
    end

    def each(&block)
      self.class.entries.each(&block)
    end
  end

  class ScheduledSet < FakeSet
    def self.entries
      [Entry.new("default")]
    end
  end

  class RetrySet < FakeSet
    def self.entries
      [Entry.new("default"), Entry.new("mailers")]
    end
  end

  class DeadSet < FakeSet
    def self.entries
      [Entry.new("mailers")]
    end
  end

  class WorkSet
    Work = Struct.new(:queue)

    def each
      yield "host:1", "t1", { "queue" => "default" }
      yield "host:1", "t2", Work.new("default")
      yield "host:2", "t1", Work.new("mailers")
    end
  end
end
require "sitegoose/sidekiq"

class SidekiqTest < Minitest::Test
  SK = SiteGoose::Sidekiq

  def test_which_run_is_the_last
    assert SK.last_attempt?({ "retry" => false })
    assert SK.last_attempt?({ "retry" => 0 })
    refute SK.last_attempt?({ "retry" => 3 })
    refute SK.last_attempt?({ "retry" => 3, "retry_count" => 1 })
    assert SK.last_attempt?({ "retry" => 3, "retry_count" => 2 })
    refute SK.last_attempt?({ "retry" => true, "retry_count" => 23 })
    assert SK.last_attempt?({ "retry" => true, "retry_count" => 24 })
    # As Sidekiq reads them: a retry that isn't an Integer is the default
    # count, and retry_for retries for a time, so its death handler decides.
    refute SK.last_attempt?({ "retry" => "3", "retry_count" => 5 })
    refute SK.last_attempt?({ "retry" => 3, "retry_count" => 9, "retry_for" => 3600 })
    assert SK.last_attempt?({ "retry" => false, "retry_for" => 3600 })
  end

  def test_a_retried_failure_is_timed_but_only_the_last_is_sent
    made = quiet_platform(errors: { spool_dir: false }, performance: {})
    SK.install(made)
    middleware = Sidekiq.hooks.middleware
    job = { "class" => "Sidekiq::ActiveJob::Wrapper", "wrapped" => "ChargeJob", "retry" => 1 }
    first = assert_raises(ArgumentError) { middleware.call(nil, job, "default") { raise ArgumentError, "declined" } }
    assert_empty made.errors.queue
    assert first.instance_variable_defined?(:@__sitegoose_skip), "Rails' own report is told to leave it"
    assert_raises(ArgumentError) { middleware.call(nil, job.merge("retry_count" => 0), "default") { raise ArgumentError, "declined" } }
    assert_equal [["/(job) ChargeJob", 500]], made.errors.queue.map { |e| e.values_at("route", "status_code") }
    assert_equal :ok, middleware.call(nil, job, "default") { :ok }
    rows = made.module("performance").rows.keys.map { |k| [k[2], k[3]] }.sort
    assert_equal [["/(job) ChargeJob", 200], ["/(job) ChargeJob", 500]], rows
  end

  def test_a_job_sidekiq_gives_up_is_sent_once
    made = quiet_platform(errors: { spool_dir: false })
    SK.install(made)
    error = ArgumentError.new("killed")
    error.instance_variable_set(:@__sitegoose_skip, true)
    Sidekiq.hooks.death_handlers[0].call({ "class" => "HardJob" }, error)
    Sidekiq.hooks.death_handlers[0].call({ "class" => "HardJob" }, error)
    assert_equal ["/(job) HardJob"], made.errors.queue.map { |e| e["route"] }
  end
end

# The Rails error subscriber, without Rails (it only needs ::Rails::Railtie to load).
module Rails
  class Railtie
    def self.config
      @config ||= Struct.new(:sitegoose) do
        def after_initialize(*); end
      end.new
    end

    def self.initializer(*); end
  end
end
module ActiveSupport
  class OrderedOptions < Hash; end
end
$LOADED_FEATURES << "rails/railtie.rb"
require "sitegoose/railtie"

class ErrorSubscriberTest < Minitest::Test
  def test_handled_errors_are_sent_and_unhandled_ones_in_a_request_are_left_to_the_middleware
    made = quiet_platform(errors: { spool_dir: false })
    SiteGoose.platform = made
    subscriber = SiteGoose::ErrorSubscriber.new
    subscriber.report(ArgumentError.new("handled"), handled: true, severity: :warning, context: {})
    subscriber.report(ArgumentError.new("info"), handled: true, severity: :info, context: {})
    SiteGoose::Context.with({ "method" => "GET" }) do
      subscriber.report(ArgumentError.new("the middleware sends this"), handled: false, severity: :error, context: {}, source: "application.action_dispatch")
    end
    subscriber.report(ArgumentError.new("in a rake task"), handled: false, severity: :error, context: {})
    assert_equal [%w[handled handled], ["in a rake task", "error"]], made.errors.queue.map { |e| e.values_at("message", "kind") }
  ensure
    SiteGoose.platform = nil
  end
end

class SidekiqQueuesTest < Minitest::Test
  SK = SiteGoose::Sidekiq

  def setup
    Sidekiq::FakeRedis.instance.forget
    Sidekiq::FakeRedis.instance.down = false
    SK.broker = nil
  end

  def test_the_broker_is_host_port_and_database_never_credentials
    assert_equal "redis.internal:6380/2", SK.broker
    assert_equal "cache:6390/3", SK.broker_from_url("redis://user:secret@cache:6390/3")
    assert_equal "redis.sock/0", SK.broker_string(nil, nil, 0, "/var/run/redis.sock")
    assert_equal "localhost:6379/0", SK.broker_from_url(nil)
  end

  def test_one_process_reads_a_minute_every_queues_gauges
    readings = SK::Reader.new("one").read
    default = readings.find { |r| r[:queue] == "default" }
    assert_equal({ system: "sidekiq", broker: "redis.internal:6380/2", queue: "default", waiting: 3, running: 2,
                   delayed: 2, failed: 0, oldest_s: 12 }, default)
    mailers = readings.find { |r| r[:queue] == "mailers" }
    assert_equal [0, 1, 1, 1, 0], mailers.values_at(:waiting, :running, :delayed, :failed, :oldest_s)
    assert_equal [], SK::Reader.new("two").read, "another process has this minute"
  end

  def test_a_sorted_set_too_big_to_count_is_unknown
    big = Class.new { def size = SK::Reader::SET_MAX + 1 }.new
    assert_nil SK::Reader.new("x").by_queue(big, %w[default mailers])
    assert_equal SK::Reader::SET_MAX + 1, SK::Reader.new("x").by_queue(big, %w[default])["default"],
                 "with one queue the set's size is its own, nothing read"
  end

  def test_pushes_are_counted_once_and_finished_jobs_when_they_leave_for_good
    made = quiet_platform(errors: { spool_dir: false }, performance: {})
    SK.install(made)
    client = Sidekiq.hooks.client
    refute_nil Sidekiq.client_hooks.client, "a process that only pushes counts too"
    now = Time.now.to_f
    client.call("MailJob", { "queue" => "mailers", "created_at" => now }, "mailers") { true }
    scheduled = { "queue" => "mailers", "created_at" => now, "at" => now + 60 }
    client.call("MailJob", scheduled, "mailers") { scheduled }
    assert_equal true, scheduled[SK::ADDED], "the counted job carries the mark into Redis"
    # Sidekiq's scheduler moving it onto its queue, long after created_at.
    client.call("MailJob", scheduled.except("at"), "mailers") { true }
    client.call("MailJob", { "queue" => "mailers", "created_at" => now, "retry_count" => 0 }, "mailers") { true }
    # Scheduled by a process without the middleware: counted when it moves.
    client.call("MailJob", { "queue" => "mailers", "created_at" => now - 600 }, "mailers") { true }
    refused = { "queue" => "mailers", "created_at" => now }
    client.call("MailJob", refused, "mailers") { false }
    refute refused.key?(SK::ADDED), "a push a middleware stopped isn't counted or marked"
    server = Sidekiq.hooks.middleware
    server.call(nil, { "class" => "A", "jid" => "1", "retry" => 2 }, "default") { :ok }
    assert_raises(IOError) { server.call(nil, { "class" => "A", "jid" => "2", "retry" => 2 }, "default") { raise IOError } }
    assert_raises(IOError) do
      server.call(nil, { "class" => "A", "jid" => "3", "retry" => false }, "default") { raise IOError }
    end
    Sidekiq.hooks.death_handlers[0].call({ "class" => "A", "jid" => "3", "queue" => "default" }, IOError.new)
    Sidekiq.hooks.death_handlers[0].call({ "class" => "A", "jid" => "4", "queue" => "default" }, IOError.new)
    entries = made.queues.entries
    assert_equal 3, entries[["sidekiq", "redis.internal:6380/2", "mailers"]][:added], "new, scheduled (once), and one first seen when it moved"
    assert_equal 3, entries[["sidekiq", "redis.internal:6380/2", "default"]][:finished],
                 "done, the last attempt, and one given up before it; not the retried one"
    made.close
  end

  def test_a_reading_is_a_row_per_queue_with_this_processs_counts_and_the_sender
    core = FakeCore.new
    queues = SiteGoose::Queues.new(core, server_name: "worker-1")
    queues.counting("sidekiq", "redis.internal:6380/2", "default", :finished)
    queues.count("sidekiq", "redis.internal:6380/2", "default", :finished)
    queues.watch(SK::Reader.new(queues.sender))
    rows = queues.sample
    sent = core.sent.find { |s| s[:path] == "/events/server-queues" }
    assert_equal :bearer, sent[:auth]
    assert_equal [queues.sender, "worker-1"], sent[:body].values_at("sender", "server_name")
    assert_match(/\A\h{16}\z/, queues.sender)
    default = rows.find { |r| r["queue"] == "default" }
    assert_equal({ "system" => "sidekiq", "broker" => "redis.internal:6380/2", "queue" => "default", "waiting" => 3,
                   "running" => 2, "delayed" => 2, "failed" => 0, "oldest_s" => 12, "added" => nil, "finished" => 1,
                   "shared" => false }, default.except("minute"))
    assert_match(/:00\.000Z\z/, default["minute"])
    assert_equal [nil, nil], rows.find { |r| r["queue"] == "mailers" }.values_at("added", "finished")
    assert_equal 0, queues.sample.find { |r| r["queue"] == "default" }["finished"], "counts start again after each reading"
    queues.close
  end

  def test_a_failed_reading_is_a_gap_not_zeros
    core = FakeCore.new
    queues = SiteGoose::Queues.new(core)
    queues.count("sidekiq", "redis.internal:6380/2", "default", :added)
    queues.watch(SK::Reader.new("x"))
    Sidekiq::FakeRedis.instance.down = true
    rows = queues.sample
    assert_equal 1, rows.size
    assert_equal [nil, nil, nil, nil, nil, 1], rows[0].values_at("waiting", "running", "delayed", "failed", "oldest_s", "added")
    queues.close
  end

  def test_with_server_speed_off_nothing_is_read_and_queues_false_leaves_them_out
    core = FakeCore.new
    core.switches = { "performance" => false }
    queues = SiteGoose::Queues.new(core)
    queues.watch(SK::Reader.new("x"))
    assert_empty queues.sample
    assert_empty core.sent
    made = quiet_platform(performance: {}, queues: false)
    assert_nil made.queues
    made.close
  end
end
