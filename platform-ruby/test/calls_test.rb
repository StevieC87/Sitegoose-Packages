# frozen_string_literal: true

# Outgoing calls (sdk/protocols/calls.md): the host as stored, attribution to
# a request or job, the caps, what is sent, the package's own calls left out,
# SiteGoose.time_call, and the Faraday middleware when Faraday is installed.
# ClickHouse queries (queries.md) through watch_database, with the
# click_house gem stood in for.

require_relative "test_helper"

class CallsTest < Minitest::Test
  C = SiteGoose::Calls

  def setup
    @made = quiet_platform(performance: {})
  end

  def teardown
    @made.close
  end

  def rows
    @made.calls.rows.values.reduce({}, :merge)
  end

  def test_only_the_host_with_its_port_when_it_isnt_the_schemes_own
    assert_equal "api.stripe.com", C.host_of("https://API.Stripe.com/v1/customers/cus_8x?key=secret")
    assert_equal "localhost:8080", C.host_of("http://localhost:8080/x")
    assert_equal "example.com", C.host_of("http://example.com:80/")
    assert_equal "example.com:443", C.host_of("http://example.com:443/")
    assert_equal "[::1]:3000", C.host_of("http://[::1]:3000/")
    assert_equal "api.example.com", C.host_of("api.example.com")
    assert_equal "api.example.com", C.host_of(URI("https://api.example.com/a/b"))
    assert_equal "", C.host_of("")
    assert_equal "", C.host_of("http://exa mple.com/")
  end

  def test_a_requests_calls_go_under_its_route_by_call_method_and_host
    env = rack_env(path: "/checkout")
    @made.rack_call(env) do
      C.record("POST", "https://api.stripe.com/v1/charges", 120.0)
      C.record("post", URI("https://api.stripe.com/v1/refunds"), 80.0)
      C.record("GET", "https://mail.example.com/send?to=ana@example.com", 10.0, failed: true)
      [200, {}, []]
    end
    stripe = rows[["GET", "/checkout", "POST", "api.stripe.com"]]
    assert_equal [2, 0, 200.0, 120.0], stripe.values_at(:count, :errors, :sum_ms, :max_ms)
    assert_equal 1, rows[["GET", "/checkout", "GET", "mail.example.com"]][:errors]
    refute(rows.keys.flatten.any? { |part| part.to_s.include?("ana@") || part.to_s.include?("/v1") })
  end

  def test_past_50_hosts_in_a_request_the_rest_is_other
    @made.rack_call(rack_env) do
      60.times { |i| C.record("GET", "https://h#{i}.example.com/", 1.0) }
      [200, {}, []]
    end
    mine = rows.select { |k, _| k[1] == "/pricing" }
    assert_equal 51, mine.size
    assert_equal 10, mine[["GET", "/pricing", "GET", "(other)"]][:count]
  end

  def test_outside_a_request_is_background_and_a_job_is_its_own_route
    C.record("GET", "https://api.example.com/x", 2.0)
    @made.job("nightly") { C.record("PUT", "https://s3.example.com/b/k", 1.0) }
    assert rows.key?(["JOB", "(background)", "GET", "api.example.com"])
    assert rows.key?(["JOB", "/(job) nightly", "PUT", "s3.example.com"])
  end

  def test_the_rows_sent_and_the_collector_left_out
    core = FakeCore.new
    calls = C.new(core, server_name: "web-1")
    C.record("GET", "https://api.example.com/x", 3.04)
    C.record("GET", "https://api.example.com/y", 7.06, failed: true)
    C.record("POST", "http://collector.invalid/events/server-errors", 5.0)
    C.record("POST", "http://COLLECTOR.invalid:80/events/x", 5.0)
    calls.close
    sent = core.sent.find { |s| s[:path] == "/events/server-calls" }
    assert_equal :bearer, sent[:auth]
    body = sent[:body]
    assert_equal ["a" * 24, "web-1", "Ruby #{RUBY_VERSION}"], body.values_at("site_id", "server_name", "runtime")
    assert_equal 1, body["rows"].size
    row = body["rows"][0]
    assert_equal ["JOB", "(background)", "GET", "api.example.com", 2, 1, 10.1, 7.1],
                 row.values_at("method", "route", "call_method", "host", "count", "errors", "sum_ms", "max_ms")
    assert_equal [1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], row["buckets"]
  end

  def test_calls_false_or_server_speed_off_counts_none
    made = quiet_platform(performance: {}, calls: false)
    assert_nil made.calls
    refute_nil made.queries
    made.close
    @made.core.switches = { "performance" => false }
    C.record("GET", "https://api.example.com/", 1.0)
    assert_empty rows
  end

  def test_time_call_times_a_block_and_a_raise_is_a_failure
    @made.rack_call(rack_env(path: "/pay")) do
      assert_equal 42, SiteGoose.time_call("https://api.stripe.com/v1/charges", method: "POST") { 42 }
      assert_raises(IOError) { SiteGoose.time_call("api.stripe.com", method: "POST") { raise IOError, "reset" } }
      [1].each { SiteGoose.time_call("api.stripe.com", method: "POST") { break } }
      SiteGoose.time_call("api.stripe.com") { SiteGoose.time_call("api.stripe.com") { 1 } }
      [200, {}, []]
    end
    assert_equal [3, 1], rows[["GET", "/pay", "POST", "api.stripe.com"]].values_at(:count, :errors),
                 "a block left with break ended the call"
    assert_equal 1, rows[["GET", "/pay", "GET", "api.stripe.com"]][:count], "a call timed inside another is counted once"
  end

  def test_a_status_is_a_failure_only_without_an_answer_or_as_a_5xx
    assert C.failed_status?(0)
    assert C.failed_status?(nil)
    assert C.failed_status?(503)
    refute C.failed_status?(404)
    refute C.failed_status?(200)
  end
end

begin
  require "faraday"
  require "sitegoose/faraday"
rescue LoadError
  nil
end

if defined?(SiteGoose::Faraday)
  class FaradayCallsTest < Minitest::Test
    def setup
      @made = quiet_platform(performance: {})
      @stubs = Faraday::Adapter::Test::Stubs.new do |stub|
        stub.get("/v1/ok") { [200, {}, "ok"] }
        stub.get("/v1/missing") { [404, {}, ""] }
        stub.get("/v1/down") { [503, {}, ""] }
        stub.get("/v1/refused") { raise Faraday::ConnectionFailed, "refused" }
      end
    end

    def teardown
      @made.close
    end

    def rows
      @made.calls.rows.values.reduce({}, :merge)
    end

    def test_the_middleware_times_calls_by_host_and_a_4xx_is_an_answer
      conn = Faraday.new(url: "https://API.example.com") do |f|
        f.request :sitegoose
        f.adapter :test, @stubs
      end
      @made.rack_call(rack_env(path: "/orders")) do
        conn.get("/v1/ok")
        conn.get("/v1/missing")
        conn.get("/v1/down")
        assert_raises(Faraday::ConnectionFailed) { conn.get("/v1/refused") }
        [200, {}, []]
      end
      assert_equal [4, 2], rows[["GET", "/orders", "GET", "api.example.com"]].values_at(:count, :errors)
    end

    def test_a_4xx_raised_by_raise_error_is_still_an_answer
      conn = Faraday.new(url: "https://api.example.com") do |f|
        f.use SiteGoose::Faraday
        f.response :raise_error
        f.adapter :test, @stubs
      end
      assert_raises(Faraday::ResourceNotFound) { conn.get("/v1/missing") }
      assert_raises(Faraday::ServerError) { conn.get("/v1/down") }
      assert_equal [2, 1], rows[["JOB", "(background)", "GET", "api.example.com"]].values_at(:count, :errors)
    end
  end
end

# The click_house gem, stood in for: execute carries the SQL, select_* run
# on it, insert names its table and hands the rows to execute.
FAKE_CLICKHOUSE = !defined?(::ClickHouse::Connection)
if FAKE_CLICKHOUSE
  module ClickHouse
    class Connection
      attr_reader :ran

      def initialize
        @ran = []
      end

      def execute(query, body = nil, database: "default")
        raise ArgumentError, "Code: 62. Syntax error" if query.include?("BROKEN")

        @ran << [query, body, database]
        "ok"
      end

      def select_all(sql)
        execute(sql)
        [{ "n" => 1 }]
      end

      def select_value(sql)
        select_all(sql).first
      end

      def insert(table, body = [], format: "JSONEachRow")
        execute("INSERT INTO #{table} FORMAT #{format}", body)
        true
      end
    end
  end

  class ClickHouseQueriesTest < Minitest::Test
    def test_a_watched_connection_is_timed_once_per_call_and_insert_rows_are_never_read
      made = quiet_platform(performance: {})
      conn = ClickHouse::Connection.new
      assert_same conn, SiteGoose.watch_database(conn)
      SiteGoose.watch_database(conn)
      made.rack_call(rack_env(path: "/reports/7")) do
        assert_equal [{ "n" => 1 }], conn.select_all("SELECT count() FROM events WHERE site_id = 'abc' AND n > 5")
        assert conn.insert("events", [{ "email" => "ana@example.com" }], format: "JSONEachRow")
        assert_equal "ok", conn.execute("OPTIMIZE TABLE events", nil, database: "analytics")
        assert_raises(ArgumentError) { conn.execute("SELECT BROKEN") }
        [200, {}, []]
      end
      rows = made.queries.rows.values.reduce({}, :merge).select { |k, _| k[1] == "/reports/:id" }
      assert(rows.keys.all? { |k| k[2] == "clickhouse" }, rows.keys.inspect)
      by_statement = rows.to_h { |k, v| [k[3], v.values_at(:count, :errors)] }
      assert_equal({ "SELECT count() FROM events WHERE site_id = ? AND n > ?" => [1, 0], "INSERT INTO events" => [1, 0],
                     "OPTIMIZE TABLE events" => [1, 0], "SELECT BROKEN" => [1, 1] }, by_statement)
      assert_equal 3, conn.ran.size, "the connection still runs everything"
      made.close
    end

    def test_an_active_record_clickhouse_adapter_is_labeled_clickhouse
      adapter = Struct.new(:adapter_name)
      assert_equal "clickhouse", SiteGoose::Queries.active_record_db(adapter.new("Clickhouse"))
      assert_equal "postgresql", SiteGoose::Queries.active_record_db(adapter.new("PostgreSQL"))
    end
  end
end
