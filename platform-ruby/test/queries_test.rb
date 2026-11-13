# frozen_string_literal: true

# Database queries (sdk/protocols/queries.md): the shared normalizing cases,
# attribution to a request or job, the caps, what is sent, and the Active
# Record and Sequel hooks when those gems are installed.

require_relative "test_helper"
require "minitest/mock"

class QueryTextTest < Minitest::Test
  def test_every_shared_case
    data = shared("query-cases.json")
    assert_equal SiteGoose::QueryText::MAX_STATEMENT, data["max_statement"]
    data["cases"].each do |c|
      assert_equal c["expected"], SiteGoose::QueryText.normalize_statement(c["statement"], c["db"]),
                   "#{c['db']}: #{c['statement'][0, 80]}"
    end
  end

  def test_every_shared_redis_command
    data = shared("query-cases.json")
    refute_empty data["redis_commands"]
    data["redis_commands"].each do |c|
      got = SiteGoose::QueryText.redis_command(c["args"])
      c["expected"].nil? ? assert_nil(got, c["args"].inspect) : assert_equal(c["expected"], got, c["args"].inspect)
    end
  end

  def test_a_redis_key_that_is_not_utf8_is_a_question_mark
    assert_equal "GET a:?:b", SiteGoose::QueryText.redis_command(["GET", (+"a:\xff:b").force_encoding(Encoding::UTF_8)])
    assert_equal "GET user:?", SiteGoose::QueryText.redis_command(["GET".b, "user:\xC3".b])
  end

  def test_mongo_is_compact_unescaped_and_keeps_key_order
    text = SiteGoose::QueryText.normalize_statement('find users {"z":1,"é":{"b":2,"a":3}}', "mongodb")
    assert_equal 'find users {"z":"?","é":{"b":"?","a":"?"}}', text
    # JavaScript's JSON.parse refuses comments; Ruby's would take them.
    assert_equal "find users", SiteGoose::QueryText.normalize_statement("find users {/*x*/}", "mongodb")
  end

  # Where Ruby's JSON and JavaScript's differ: an unknown escape (JavaScript
  # refuses it), a lone surrogate (Ruby does), "__proto__" (JavaScript drops it).
  def test_mongo_reads_json_as_javascript_does
    shape = ->(text) { SiteGoose::QueryText.normalize_statement(text, "mongodb") }
    assert_equal "find users", shape.call('find users {"a":"\\x"}')
    assert_equal 'find users {"a":"?"}', shape.call('find users {"a":"\\u00e9\\/"}')
    assert_equal 'find users {"\\ud800":"?","😀":"?"}', shape.call('find users {"\\ud800":1,"\\ud83d\\ude00":2}')
    assert_equal 'find users {"b":"?"}', shape.call('find users {"__proto__":{"a":1},"b":2}')
  end

  def test_mongo_command_text_from_a_driver_command
    sub = SiteGoose::Queries::MongoSubscriber
    assert_equal 'find users {"email":"?","age":{"$gt":"?"}}',
                 sub.text("find", { "find" => "users", "filter" => { "email" => "a@b.c", "age" => { "$gt" => 3 } } })
    assert_equal 'delete users {"_id":"?"}', sub.text("delete", { "delete" => "users", "deletes" => [{ "q" => { "_id" => 1 } }] })
    assert_equal "insert users", sub.text("insert", { "insert" => "users", "documents" => [{ "a" => 1 }] })
  end
end

class QueriesTest < Minitest::Test
  Q = SiteGoose::Queries
  ORDERS = lambda do |env|
    env["sinatra.route"] = "GET /orders/:id"
    SiteGoose::Queries.record("postgresql", "SELECT * FROM orders WHERE id = 7", 3.0)
    SiteGoose::Queries.record("postgresql", "SELECT * FROM orders WHERE id = 8", 12.0)
    SiteGoose::Queries.record("postgresql", "UPDATE orders SET seen = true WHERE id = 8", 1.0, failed: true)
    [200, {}, ["ok"]]
  end

  def setup
    @made = quiet_platform(performance: {})
  end

  def teardown
    @made.close
  end

  def rows
    @made.queries.rows.values.reduce({}, :merge)
  end

  def test_a_requests_queries_go_under_its_method_and_route
    %w[/orders/7 /orders/8].each do |path|
      env = rack_env(path: path)
      @made.rack_call(env) { ORDERS.call(env) }
    end
    select = rows[["GET", "/orders/:id", "postgresql", "SELECT * FROM orders WHERE id = ?"]]
    assert_equal [4, 0, 30.0, 12.0], select.values_at(:count, :errors, :sum_ms, :max_ms)
    update = rows[["GET", "/orders/:id", "postgresql", "UPDATE orders SET seen = true WHERE id = ?"]]
    assert_equal [2, 2], update.values_at(:count, :errors)
    assert(@made.module("performance").rows.keys.any? { |k| k[1, 2] == ["GET", "/orders/:id"] })
  end

  def test_outside_a_request_is_background_and_a_job_is_its_own_route
    Q.record("mysql", "DELETE FROM sessions WHERE at < 5", 2.0)
    @made.job("nightly") { Q.record("mysql", "SELECT 1", 1.0) }
    assert rows.key?(["JOB", "(background)", "mysql", "DELETE FROM sessions WHERE at < ?"])
    assert rows.key?(["JOB", "/(job) nightly", "mysql", "SELECT ?"])
  end

  def test_past_50_in_a_request_the_rest_is_other
    env = rack_env
    @made.rack_call(env) do
      60.times { |i| Q.record("sqlite", "SELECT c#{i} FROM t", 1.0) }
      [200, {}, []]
    end
    mine = rows.select { |k, _| k[1] == "/pricing" }
    assert_equal 51, mine.size
    assert_equal 10, mine[["GET", "/pricing", "sqlite", "(other)"]][:count]
  end

  def test_past_200_in_a_minute_other_and_past_300_nothing_new
    250.times { |i| Q.record("sqlite", "SELECT c#{i} FROM t", 1.0) }
    assert_equal 201, rows.size
    assert_equal 50, rows[["JOB", "(background)", "sqlite", "(other)"]][:count]
    150.times do |i|
      @made.rack_call(rack_env(path: "/p#{i}")) do
        Q.record("sqlite", "SELECT 1", 1.0)
        [200, {}, []]
      end
    end
    assert_equal 300, rows.size
  end

  def test_empty_statements_and_switched_off_record_nothing
    Q.record("postgresql", "-- only a comment", 1.0)
    @made.core.switches = { "performance" => false }
    Q.record("postgresql", "SELECT 1", 1.0)
    assert_empty rows
  end

  def test_queries_false_keeps_server_speed_only
    made = quiet_platform(performance: {}, queries: false)
    assert_nil made.queries
    refute_nil made.module("performance")
    made.close
    assert_nil quiet_platform.queries
  end

  def test_the_rows_sent
    core = FakeCore.new
    queries = Q.new(core, server_name: "web-1")
    Q.record("mongodb", 'find users {"a":1}', 3.04)
    Q.record("mongodb", 'find users {"a":2}', 7.06, failed: true)
    queries.close
    sent = core.sent.find { |s| s[:path] == "/events/server-queries" }
    assert_equal :bearer, sent[:auth]
    body = sent[:body]
    assert_equal ["a" * 24, "web-1", "Ruby #{RUBY_VERSION}"], body.values_at("site_id", "server_name", "runtime")
    row = body["rows"].find { |r| r["statement"] == 'find users {"a":"?"}' }
    assert_equal ["JOB", "(background)", "mongodb", 2, 1, 10.1, 7.1],
                 row.values_at("method", "route", "db", "count", "errors", "sum_ms", "max_ms")
    assert_equal [1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], row["buckets"]
    assert_match(/\A\d{4}-\d\d-\d\dT\d\d:\d\d:00\.000Z\z/, row["minute"])
  end

  def test_mongo_subscriber_times_commands_and_leaves_chatter
    sub = Q::MongoSubscriber.new
    started = Struct.new(:command_name, :command, :request_id)
    done = Struct.new(:command_name, :request_id, :duration)
    sub.started(started.new("find", { "find" => "users", "filter" => { "a" => 1 } }, 1))
    sub.started(started.new("ping", { "ping" => 1 }, 2))
    sub.succeeded(done.new("find", 1, 0.004))
    sub.succeeded(done.new("ping", 2, 0.001))
    assert_equal [["JOB", "(background)", "mongodb", 'find users {"a":"?"}']], rows.keys
  end
end

begin
  require "active_record"
  require "sqlite3"
rescue LoadError
  nil
end

if defined?(::ActiveRecord::Base) && defined?(::SQLite3)
  class ActiveRecordQueriesTest < Minitest::Test
    def setup
      ActiveRecord::Base.establish_connection(adapter: "sqlite3", database: ":memory:")
      ActiveRecord::Schema.verbose = false
      ActiveRecord::Schema.define { create_table(:widgets) { |t| t.string :name } }
      @made = quiet_platform(performance: {})
    end

    def teardown
      @made.close
      ActiveRecord::Base.remove_connection
    end

    def test_sql_active_record_is_timed_but_not_schema_cached_or_timed_outside
      model = Class.new(ActiveRecord::Base) { self.table_name = "widgets" }
      env = rack_env(path: "/widgets/3")
      @made.rack_call(env) do
        model.where(name: "secret").to_a
        ActiveRecord::Base.cache { 2.times { model.where(id: 3).to_a } }
        ActiveRecord::Base.connection.select_all("SELECT 1 FROM widgets WHERE id = 9", "SCHEMA")
        SiteGoose::Queries.timing { model.where(id: 4).to_a }
        assert_raises(ActiveRecord::StatementInvalid) { ActiveRecord::Base.connection.select_all("SELECT * FROM nope WHERE x = 'y'") }
        [200, {}, []]
      end
      rows = @made.queries.rows.values.reduce({}, :merge).select { |k, _| k[1] == "/widgets/:id" }
      statements = rows.keys.map { |k| k[3] }
      assert(rows.keys.all? { |k| k[2] == "sqlite" })
      by_name = statements.grep(/"name"/)
      assert_equal 1, by_name.size, statements.inspect
      refute_includes by_name[0], "secret"
      by_id = rows.select { |k, _| k[3].include?('"id"') }
      assert_equal [1], by_id.values.map { |v| v[:count] }, "cached copy and the timed one left out: #{statements.inspect}"
      refute(statements.any? { |s| s.include?("SELECT ? FROM widgets") }, "SCHEMA left out")
      assert_equal 1, rows[rows.keys.find { |k| k[3].include?("nope") }][:errors]
    end
  end
end

begin
  require "sequel"
rescue LoadError
  nil
end

if defined?(::Sequel) && defined?(::SQLite3)
  class SequelQueriesTest < Minitest::Test
    def test_a_watched_database_is_timed
      made = quiet_platform(performance: {})
      db = Sequel.sqlite
      assert_same db, SiteGoose.watch_database(db)
      SiteGoose.watch_database(db)
      db.create_table(:items) { primary_key :id }
      env = rack_env(path: "/items/5")
      made.rack_call(env) do
        db[:items].where(id: 5).all
        db[:items].where(id: 6).all
        assert_raises(Sequel::DatabaseError) { db["SELECT * FROM nope"].all }
        [200, {}, []]
      end
      rows = made.queries.rows.values.reduce({}, :merge).select { |k, _| k[1] == "/items/:id" }
      found = rows.find { |k, _| k[3].include?("FROM `items`") }
      refute_nil found, rows.keys.inspect
      assert_equal ["sqlite", 2, 0], [found[0][2], found[1][:count], found[1][:errors]]
      refute_includes found[0][3], "5"
      assert_equal 1, rows.find { |k, _| k[3].include?("nope") }[1][:errors]
      made.close
    end
  end
end

# redis-client's middleware stack as the gem builds it (redis_client/middlewares.rb),
# when the gem itself isn't installed.
unless defined?(::RedisClient)
  class RedisClient
    class BasicMiddleware
      def initialize(client)
        @client = client
      end

      def connect(_config)
        yield
      end

      def call(command, _config)
        yield command
      end
      alias call_pipelined call
    end

    class Middlewares < BasicMiddleware
    end

    def self.register(middleware)
      Middlewares.include(middleware)
    end
  end
end

class RedisQueriesTest < Minitest::Test
  Q = SiteGoose::Queries

  def setup
    @made = quiet_platform(performance: {})
    @stack = RedisClient::Middlewares.new(nil)
  end

  def teardown
    @made.close
  end

  def rows
    @made.queries.rows.values.reduce({}, :merge).select { |k, _| k[1] == "/cart" }
  end

  def test_registered_once
    Q.install
    Q.instance_variable_get(:@hooked).delete(:redis)
    Q.hook_redis
    assert_equal 1, RedisClient::Middlewares.ancestors.count(Q::RedisHook)
  end

  # A signal handler can't take the lock: the command still runs, untimed.
  def test_lock_unavailable_leaves_the_command_alone
    Q.install
    Q.stub(:active, -> { raise ThreadError, "can't be called from trap context" }) do
      assert_equal "v", @stack.call(%w[GET k], nil) { "v" }
      assert_equal %w[a b], @stack.call_pipelined([%w[GET a], %w[GET b]], nil) { %w[a b] }
    end
  end

  def test_commands_pipelines_and_transactions
    env = rack_env(path: "/cart")
    @made.rack_call(env) do
      env["sinatra.route"] = "GET /cart"
      assert_equal "v", @stack.call(["GET", "user:42:cart"], nil) { "v" }
      @stack.call(["GET", "user:43:cart"], nil) { "v" }
      @stack.call(["SET", "session:abc123", "hunter2", "EX", "60"], nil) { "OK" }
      assert_nil @stack.call(["GET", "nil:1"], nil) { nil }
      assert_raises(ArgumentError) { @stack.call(["LPUSH", "str", "x"], nil) { raise ArgumentError, "WRONGTYPE" } }
      assert_raises(RuntimeError) { @stack.call(["GET", "moved:1"], nil) { raise "MOVED 3999 127.0.0.1:6381" } }
      @stack.call(["GET", "moved:1"], nil) { "v" }
      assert_raises(Interrupt) { @stack.call(["GET", "cut:1"], nil) { raise Interrupt } }
      @stack.call_pipelined([%w[MULTI], %w[LPUSH str:2 x], %w[EXEC]], nil) { ["OK", "QUEUED", [RuntimeError.new("WRONGTYPE")]] }
      @stack.call(["BRPOP", "queue:default", "2"], nil) { nil }
      @stack.call_pipelined([%w[SET a:1 x], %w[GET b:2]], nil) { ["OK", RuntimeError.new("ERR")] }
      @stack.call_pipelined([%w[MULTI], %w[INCR hits:9], %w[EXEC]], nil) { ["OK", "QUEUED", [1]] }
      @stack.call_pipelined([%w[HELLO 3 AUTH default pw], %w[SELECT 1]], nil) { [{}, "OK"] }
      @stack.call_pipelined([%w[BLPOP q 1]], nil) { [nil] }
      @stack.call_pipelined([%w[MULTI], %w[EXEC]], nil) { ["OK", []] }
      Q.own { @stack.call(["GET", "own:1"], nil) { "v" } }
      [200, {}, []]
    end
    by = rows.to_h { |k, v| [k[3], v] }
    assert(rows.keys.all? { |k| k[2] == "redis" })
    assert_equal [2, 0], by["GET user:?:cart"].values_at(:count, :errors)
    assert by.key?("SET session:?")
    assert_equal 0, by["GET nil:?"][:errors], "a nil reply is a reply"
    assert_equal 1, by["LPUSH str"][:errors]
    assert_equal [1, 0], by["GET moved:?"].values_at(:count, :errors), "a redirection is not a failure, and its resend is counted once"
    assert_equal 1, by["GET cut:?"][:errors], "cut off before an answer"
    assert_equal 1, by["MULTI LPUSH str:?"][:errors], "an error inside EXEC's answer"
    assert_equal [1, 1], by["PIPELINE SET a:?"].values_at(:count, :errors)
    assert_equal [1, 0], by["MULTI INCR hits:?"].values_at(:count, :errors)
    assert_equal ["GET cut:?", "GET moved:?", "GET nil:?", "GET user:?:cart", "LPUSH str", "MULTI INCR hits:?", "MULTI LPUSH str:?",
                  "PIPELINE SET a:?", "SET session:?"], by.keys.sort, "blocking, set-up, empty and our own commands left out"
    refute_includes rows.to_s, "hunter2"
  end

  def test_switched_off_passes_straight_through
    @made.core.switches = { "performance" => false }
    assert_equal "v", @stack.call(["GET", "k:1"], nil) { "v" }
    assert_empty @made.queries.rows
  end
end
