# frozen_string_literal: true

# What a review of the package found: slow patterns only Ruby can write,
# tables a visitor could grow, a collector that stops answering, the exit
# that outlasts a grace period, addresses that aren't one, IPv6 /64s and
# the rest. Each test names the item it holds to.

require_relative "test_helper"
require "socket"
require "tmpdir"

# Accepts connections and never answers: a black-holed collector.
class SilentServer
  attr_reader :port

  def initialize
    @server = TCPServer.new("127.0.0.1", 0)
    @port = @server.addr[1]
    @held = []
    @thread = Thread.new do
      loop { @held << @server.accept }
    rescue IOError, SystemCallError
      nil
    end
  end

  def endpoint
    "http://127.0.0.1:#{@port}"
  end

  def stop
    @server.close
    @held.each { |c| c.close rescue nil } # rubocop:disable Style/RescueModifier
    @thread.kill
  end
end

class RubyOnlyPatternsTest < Minitest::Test
  RR = SiteGoose::RequestRules

  def test_group_syntax_is_what_javascript_and_python_have_too
    refused = ["(a|aa)\\g<1>", "(?<x>a)\\g'x'", "(?'x'a)b", "(?<x>a)\\k'x'", "(?<x>a)\\k<x>", "(?~abc)", "(?(1)a|b)",
               "(?i)admin", "(?m:.)", "(?<=x)y", "(?<!x)y", "(?>a+)b", "(a)\\1"]
    refused.each { |p| refute RR.safe_pattern?(p), p }
    ["(?:wp-)?admin", "x(?=y)", "x(?!y)", "\\d+\\.php", "[\\g]x"].each { |p| assert RR.safe_pattern?(p), p }
  end

  def test_the_pattern_that_took_51_seconds_is_dropped
    slow = "(a|aa)#{'\\g<1>' * 25}$"
    rules = RR.compile({ "rules" => [{ "id" => "slow", "action" => "block", "path" => { "regex" => slow } }] })
    assert_equal [], rules
  end

  def test_without_a_regex_timeout_patterns_are_skipped_and_said_once
    allowed = RR.regex_allowed
    RR.regex_allowed = false
    RR.instance_variable_set(:@warned, false)
    said = StringIO.new
    saved = $stderr
    $stderr = said
    rules = RR.compile({ "rules" => [
                         { "id" => "both", "action" => "block", "path" => { "regex" => "\\.php$", "prefix" => ["/cgi-bin/"] } },
                         { "id" => "only", "action" => "block", "path" => { "regex" => "\\.asp$" } }
                       ] })
    $stderr = saved
    assert_equal ["both"], rules.map { |r| r["id"] }, "a rule with nothing left is dropped, one with other parts keeps them"
    refute rules[0]["path"].key?("regex")
    assert_equal "both", RR.match(rules, "GET", "/cgi-bin/x", "")["id"]
    assert_nil RR.match(rules, "GET", "/x.php", "")
    assert_equal 1, said.string.scan("can't time out a regex").size
  ensure
    $stderr = saved if saved
    RR.regex_allowed = allowed
  end
end

class BoundedTablesTest < Minitest::Test
  def test_methods_a_visitor_makes_up_are_one_method
    perf = SiteGoose::Performance.new(FakeCore.new)
    5000.times { |i| perf.record("X#{i}", "/r#{i}", 200, 1.0) }
    assert_operator perf.rows.size, :<=, SiteGoose::Performance::HARD_MAX_KEYS
    assert_equal ["OTHER"], perf.rows.keys.map { |k| k[1] }.uniq
    perf.record("get", "/x", 200, 1.0)
    perf.record("", "/x", 200, 1.0)
    assert_equal "GET", SiteGoose::Performance.method_of("get")
    assert_equal "JOB", SiteGoose::Performance.method_of("JOB")
  end

  def test_past_the_hard_cap_nothing_new_is_kept
    perf = SiteGoose::Performance.new(FakeCore.new)
    600.times { |i| perf.record("GET", "/r#{i}", 100 + i, 1.0) }
    assert_equal SiteGoose::Performance::HARD_MAX_KEYS, perf.rows.size
  end

  def test_a_full_counter_table_loses_its_oldest_not_everyone
    w = wall({ "mode" => "block", "rate" => { "limit" => 5, "window" => 60 } })
    counts = w.instance_variable_get(:@counts)
    window = (Time.now.to_f / 60).floor
    SiteGoose::Firewall::COUNTER_MAX.times { |i| counts["k#{i}"] = [window, 4] }
    w.check("203.0.113.9", "GET", "/")
    assert_equal SiteGoose::Firewall::COUNTER_MAX, counts.size
    refute counts.key?("k0")
    assert_equal [window, 4], counts["k#{SiteGoose::Firewall::COUNTER_MAX - 1}"], "the others keep their count"
  end
end

class AddressKeysTest < Minitest::Test
  RATE = { "mode" => "block", "rate" => { "limit" => 2, "window" => 60 }, "ban" => { "seconds" => 600 } }.freeze

  def test_an_ipv6_64_is_one_visitor_for_the_rate_limit_and_bans
    w = wall(RATE)
    rules = ["2001:db8:1:2::1", "2001:db8:1:2::2", "2001:db8:1:2:ffff::3"].map { |ip| w.check(ip, "GET", "/")[:rule] }
    assert_equal ["", "", "rate"], rules
    assert_equal "ban", w.check("2001:db8:1:2::99", "GET", "/")[:rule]
    assert_equal "", w.check("2001:db8:1:3::1", "GET", "/")[:rule], "the next /64 is someone else"
  end

  def test_ipv4_mapped_is_the_same_visitor
    w = wall(RATE)
    assert_equal ["", "", "rate"], ["198.51.100.4", "::ffff:198.51.100.4", "198.51.100.4"].map { |ip| w.check(ip, "GET", "/")[:rule] }
    assert_equal "ban", w.check("::ffff:198.51.100.4", "GET", "/")[:rule]
  end

  def test_failed_logins_count_by_64_too
    w = wall({ "mode" => "block", "login" => { "limit" => 2, "window" => 3600, "ban" => 600 } })
    w.login_failed("2001:db8::1")
    w.login_failed("2001:db8::2")
    assert_equal "ban", w.check("2001:db8::3")[:rule]
    assert_equal ["2001:db8::1", "2001:db8::2"], w.queue.values.select { |r| r["rule"] == "login" }.map { |r| r["ip"] }, "reports keep the address itself"
  end

  def test_a_shared_counter_gets_the_same_key
    keys = []
    w = wall(RATE, counter: ->(key, _ttl) { keys << key; 1 })
    w.check("2001:db8:1:2::1", "GET", "/")
    w.check("::ffff:198.51.100.4", "GET", "/")
    assert_equal ["2001:db8:1:2::/64", "198.51.100.4"], keys.map { |k| k.split(":", 3)[2].sub(/:\d+\z/, "") }
  end
end

class ClientAddressTest < Minitest::Test
  def ip(remote, headers, trust)
    SiteGoose.client_ip(remote, headers, trust)
  end

  def test_a_hop_that_is_not_an_address_gives_the_connections
    assert_equal "10.0.0.1", ip("10.0.0.1", { "x-forwarded-for" => "unknown" }, 1)
    assert_equal "10.0.0.1", ip("10.0.0.1", { "x-forwarded-for" => "198.51.100.1, _hidden" }, 1)
    assert_equal "10.0.0.1", ip("10.0.0.1", {}, ->(_h) { "not an address" })
    assert_equal "10.0.0.1", ip("10.0.0.1", {}, ->(_h) { nil })
    assert_equal "172.64.1.2", ip("172.64.1.2", { "cf-connecting-ip" => "garbage" }, "cloudflare")
  end

  def test_ports_on_hops_are_dropped
    assert_equal "198.51.100.1", ip("10.0.0.1", { "x-forwarded-for" => "198.51.100.1:5678" }, 1)
    assert_equal "2001:db8::1", ip("10.0.0.1", { "x-forwarded-for" => "[2001:db8::1]:443" }, 1)
    assert_equal "2001:db8::1", ip("10.0.0.1", { "x-forwarded-for" => "[2001:db8::1]" }, 1)
    assert_equal "2001:db8::1", ip("10.0.0.1", { "x-forwarded-for" => "2001:db8::1" }, 1)
  end

  def test_the_firewall_still_checks_such_a_request
    made = quiet_platform(firewall: { trust_proxy: 1 })
    made.firewall.rules = made.firewall.compile({ "v" => 1, "enabled" => true, "mode" => "block", "deny" => ["10.0.0.0/8"] })
    response = SiteGoose::Middleware.new(SITE, made).call(rack_env(remote: "10.0.0.1", x_forwarded_for: "unknown"))
    assert_equal 403, response[0]
  end
end

class StaticFilesTest < Minitest::Test
  def test_assets_rails_serves_are_not_counted_against_the_rate
    w = wall({ "mode" => "block", "rate" => { "limit" => 2, "window" => 60 } })
    ["/assets/app-1f2e.css", "/packs/x.js", "/logo.PNG", "/f.woff2?v=3", "/a.js", "/b.svg"].each do |path|
      assert_equal "", w.check("203.0.113.9", "GET", path)[:rule], path
    end
    assert_equal ["", "", "rate"], ["/", "/about", "/x.php"].map { |path| w.check("203.0.113.9", "GET", path)[:rule] }
  end

  # Tricks that would make a page read as a static file, so a flood of them
  # skips the rate and the page limits, and real assets: the cases every
  # package shares (sdk/protocols/static-cases.json, firewall.md, `rate`).
  CASES = shared("static-cases.json")["cases"].select { |c| c.fetch("only", ["ruby"]).include?("ruby") }.freeze
  NOT_STATIC = CASES.reject { |c| c["static"] }.map { |c| [c["path"], c.fetch("method", "GET")] }.freeze
  # Real assets: none counts.
  STATIC = CASES.select { |c| c["static"] }.map { |c| [c["path"], c.fetch("method", "GET")] }.freeze

  def test_tricks_count_toward_the_rate_and_page_limits
    NOT_STATIC.each { |target, method| refute SiteGoose::Firewall.static?(target, method), "#{method} #{target[0, 60]}" }
    STATIC.each { |target, method| assert SiteGoose::Firewall.static?(target, method), "#{method} #{target}" }
    rate = wall({ "mode" => "block", "rate" => { "limit" => 1, "window" => 60 } })
    limits = wall({ "mode" => "block", "limits" => { "rules" => [
      { "id" => "all", "action" => "block", "limit" => 1, "window" => 60, "path" => { "prefix" => ["/"] } }
    ] } })
    (NOT_STATIC + STATIC).each_with_index do |(target, method), i|
      ip = "198.51.100.#{i + 1}"
      counted = i < NOT_STATIC.length
      rate.check(ip, method, target)
      assert_equal counted ? "rate" : "", rate.check(ip, method, target)[:rule], "rate, #{target[0, 60]}"
      limits.check(ip, method, target)
      assert_equal counted ? "limit:all" : "", limits.check(ip, method, target)[:rule], "page limit, #{target[0, 60]}"
    end
  end
end

# A static file the app routes to a page after all (Rails reads /login.css
# as the login action, format css), or that answers an error, counts toward
# the rate and the page limits after the response (firewall.md, `rate`).
class StaticCountedLateTest < Minitest::Test
  RULES = { "v" => 1, "enabled" => true, "mode" => "block", "rate" => { "limit" => 3, "window" => 60 },
            "limits" => { "rules" => [{ "id" => "login", "action" => "block", "limit" => 2, "window" => 60,
                                        "path" => { "prefix" => ["/login"] } }] } }.freeze

  def setup
    @made = quiet_platform(firewall: {})
    @made.firewall.rules = @made.firewall.compile(RULES)
  end

  def statuses(app, path, times)
    middleware = SiteGoose::Middleware.new(app, @made)
    Array.new(times) { middleware.call(rack_env(path: path, remote: "198.51.100.40"))[0] }
  end

  RAILS = lambda do |env|
    env["action_dispatch.request.path_parameters"] = { controller: "sessions", action: "new", format: "css" }
    [200, { "content-type" => "text/css" }, ["the login page"]]
  end

  def test_rails_routing_a_file_to_an_action_counts_it
    # Counted after each answer: the third is compared with two, the fourth with three.
    assert_equal [200, 200, 200, 429, 429], statuses(RAILS, "/login.css", 5)
    assert_equal "limit:login", @made.firewall.check("198.51.100.40", "GET", "/login")[:rule]
  end

  def test_a_file_served_as_a_file_is_never_counted
    assert_equal [200] * 8, statuses(SITE, "/login.css", 8)
    assert_equal [200] * 2, statuses(SITE, "/about", 2)
  end

  def test_an_error_counts_without_rails
    missing = ->(_env) { [404, {}, ["no such file"]] }
    assert_equal [404, 404, 404, 404, 429], statuses(missing, "/made-up.woff2", 5)
    assert_equal "rate", @made.firewall.check("198.51.100.40", "GET", "/")[:rule]
  end

  def test_a_raised_error_counts
    boom = ->(_env) { raise ArgumentError, "boom" }
    middleware = SiteGoose::Middleware.new(boom, @made)
    3.times { assert_raises(ArgumentError) { middleware.call(rack_env(path: "/x.js", remote: "198.51.100.40")) } }
    assert_equal "rate", @made.firewall.check("198.51.100.40", "GET", "/")[:rule]
  end

  def test_with_a_shared_counter_the_counts_seen_over_turn_files_away
    hits = Hash.new(0)
    made = quiet_platform(firewall: { counter: ->(key, _ttl) { hits[key] += 1 } })
    made.firewall.rules = made.firewall.compile(RULES)
    @made = made
    assert_equal [200, 200, 200, 429], statuses(RAILS, "/login.css", 4)
    assert_equal 1, hits.count { |key, _| key.include?(":l:login:") }, "one key, counted late"
  end

  def test_routed_reads_the_path_parameters
    assert SiteGoose::Firewall.routed?({ "action_dispatch.request.path_parameters" => { controller: "a", action: "b" } })
    refute SiteGoose::Firewall.routed?({ "action_dispatch.request.path_parameters" => {} })
    refute SiteGoose::Firewall.routed?({})
    refute SiteGoose::Firewall.routed?(nil)
  end

  # Each image on a page is a request to Active Storage's controllers (and,
  # with the disk service, a redirect to a second): never counted as a page.
  def test_active_storage_files_are_not_counted
    storage = lambda do |env|
      env["action_dispatch.request.path_parameters"] = { controller: "active_storage/blobs/redirect", action: "show" }
      [302, { "location" => "/rails/active_storage/disk/x/photo.png" }, []]
    end
    assert_equal [302] * 8, statuses(storage, "/rails/active_storage/blobs/redirect/abc/photo.png", 8)
    refute SiteGoose::Firewall.routed?({ "action_dispatch.request.path_parameters" => { "controller" => "active_storage/disk" } })
  end

  # A form posts to a page: POST /login.css is no file, counted as it comes.
  def test_a_post_is_never_a_file
    middleware = SiteGoose::Middleware.new(RAILS, @made)
    answers = Array.new(4) { middleware.call(rack_env(path: "/login.css", method: "POST", remote: "198.51.100.41"))[0] }
    assert_equal [200, 200, 429, 429], answers
  end
end

class CookiesTest < Minitest::Test
  CH = SiteGoose::Challenge

  def test_two_cookie_headers_joined_by_a_comma
    assert_equal ["1.ab", "2.cd"], CH.cookie_values("a=1, __sg_pass=1.ab; b=2, __sg_pass=2.cd")
    assert_equal ["x"], CH.cookie_values("__sg_pass=x")
    assert_equal [], CH.cookie_values("other=a, b; c=__sg_pass=x")
  end

  def test_a_pass_in_the_second_header_is_accepted
    key = CH.pass_key("s")
    pass = CH.make_pass(key, "203.0.113.9")
    assert CH.pass?(key, "203.0.113.9", "session=abc, __sg_pass=#{pass}")
  end
end

class ForkHookTest < Minitest::Test
  def test_a_fork_that_fails_does_not_hold_up_sends
    failing = Class.new do
      def _fork
        raise Errno::EAGAIN, "no child"
      end
    end
    failing.prepend(SiteGoose::Forking::Hook)
    assert_raises(Errno::EAGAIN) { failing.new._fork }
    started = SiteGoose.clock
    SiteGoose::Forking.sending { nil }
    assert_operator SiteGoose.clock - started, :<, 0.5
  end

  def test_a_new_process_restarts_its_threads_once_however_many_requests_notice
    restarted = Queue.new
    child = Object.new
    child.define_singleton_method(:after_fork_in_child) { sleep 0.05; restarted << 1 }
    forking = SiteGoose::Forking
    forking.register(child)
    pid = forking.pid
    forking.instance_variable_set(:@pid, -1) # as if this were a new worker on Ruby 3.0
    8.times.map { Thread.new { forking.check } }.each(&:join)
    assert_equal 1, restarted.size
    assert_equal Process.pid, forking.pid
  ensure
    forking.unregister(child)
    forking.instance_variable_set(:@pid, pid) if pid
  end
end

class ExitDeadlineTest < Minitest::Test
  def test_sends_at_exit_stop_at_the_deadline
    silent = SilentServer.new
    core = SiteGoose::Core.new("a" * 24, "s", silent.endpoint)
    started = SiteGoose.clock
    SiteGoose.within(0.6) do
      assert_nil core.request("errors", "/events/server-errors", body: {})
      assert_nil core.request("errors", "/events/server-errors", body: {})
    end
    assert_operator SiteGoose.clock - started, :<, 1.5
    assert_nil SiteGoose.time_left, "and none after"
  ensure
    silent&.stop
  end

  def test_errors_left_at_exit_wait_in_the_file_without_a_retry
    Dir.mktmpdir do |dir|
      core = FakeCore.new(answers: [503, 503, 503])
      errors = SiteGoose::Errors.new(core, spool_dir: dir)
      errors.instance_variable_set(:@spool_file, File.join(dir, "waiting.jsonl"))
      errors.capture_exception(ArgumentError.new("at exit"))
      started = SiteGoose.clock
      SiteGoose.within(5) { errors.flush }
      assert_operator SiteGoose.clock - started, :<, 1.0, "no retry sleep"
      assert_equal 1, core.sent.size
      assert_equal 1, File.readlines(errors.spool_file).size
    end
  end

  def test_the_exit_hook_ends_within_its_deadline
    silent = SilentServer.new
    made = nil
    silence { made = SiteGoose::Platform.new(site_id: "a" * 24, secret: "s", endpoint: silent.endpoint, **SiteGoose::MODULES.to_h { |m| [m.to_sym, %w[errors performance analytics].include?(m)] }) }
    made.errors.instance_variable_set(:@spool_file, nil)
    made.module("performance").record("GET", "/x", 200, 1.0)
    made.track("x")
    made.capture_exception(ArgumentError.new("boom"))
    started = SiteGoose.clock
    SiteGoose.at_exit_hook(nil, 1)
    assert_operator SiteGoose.clock - started, :<, 2.5
    assert made.closed?
  ensure
    silent&.stop
  end
end

class TrackerProxyBreakerTest < Minitest::Test
  def proxy(&fetch)
    core = SiteGoose::Core.new("a" * 24, "s", "http://collector.invalid")
    made = SiteGoose::Proxy.new(core)
    calls = []
    made.define_singleton_method(:fetch) do |url, **_|
      calls << url
      fetch.call(url)
    end
    [made, calls]
  end

  def test_a_collector_that_keeps_failing_is_left_alone_for_a_while
    made, calls = proxy { raise Errno::ECONNREFUSED }
    3.times { assert_equal 502, made.handle("api", "e", method: "POST", body: "{}")[0] }
    assert_equal 3, calls.size
    started = SiteGoose.clock
    answer = made.handle("api", "e", method: "POST", body: "{}")
    assert_equal [502, "30"], [answer[0], answer[1]["retry-after"]]
    assert_equal 3, calls.size, "not asked again"
    assert_operator SiteGoose.clock - started, :<, 0.1
    made.instance_variable_set(:@open_until, SiteGoose.clock - 1)
    made.handle("api", "e", method: "POST", body: "{}")
    assert_equal 4, calls.size, "after the pause one request tries again"
  end

  def test_a_tracker_file_that_could_not_be_fetched_is_not_asked_for_again_at_once
    made, calls = proxy { raise Errno::ECONNREFUSED }
    2.times { assert_equal 502, made.handle("js", "v1/s.js")[0] }
    assert_equal 1, calls.size
  end

  def test_the_timeouts_are_short
    assert_operator SiteGoose::Proxy::CONNECT_TIMEOUT + SiteGoose::Proxy::READ_TIMEOUT, :<=, 3
    silent = SilentServer.new
    made = SiteGoose::Proxy.new(SiteGoose::Core.new("a" * 24, "s", silent.endpoint))
    started = SiteGoose.clock
    assert_equal 502, made.handle("api", "e", method: "POST", body: "{}")[0]
    assert_operator SiteGoose.clock - started, :<, 3.5
  ensure
    silent&.stop
  end
end

class SmallFixesTest < Minitest::Test
  def errors(**options)
    SiteGoose::Errors.new(FakeCore.new, spool_dir: false, **options)
  end

  def test_before_send_must_answer_a_hash_or_nil
    said = StringIO.new
    saved = $stderr
    $stderr = said
    made = errors(before_send: ->(_event, _error) { "oops" })
    2.times { made.capture_exception(ArgumentError.new("x")) }
    assert_empty made.queue
    assert_equal 1, said.string.scan("before_send returned a String").size
    raising = errors(before_send: ->(_event, _error) { raise "bug" })
    raising.capture_exception(ArgumentError.new("x"))
    assert_empty raising.queue
  ensure
    $stderr = saved
  end

  def test_a_long_message_is_cut
    made = errors
    made.capture_exception(ArgumentError.new("x" * 50_000))
    assert_equal SiteGoose::Errors::MAX_MESSAGE, made.queue[0]["message"].size
    assert_operator made.queue[0]["stack"].size, :<, 3000
  end

  def test_the_errors_file_never_grows_past_its_size
    Dir.mktmpdir do |dir|
      made = SiteGoose::Errors.new(FakeCore.new, spool_dir: dir)
      made.instance_variable_set(:@spool_file, File.join(dir, "w.jsonl"))
      big = { "message" => "y" * 400_000 }
      4.times { made.spool([big]) }
      assert_operator File.size(made.spool_file), :<=, SiteGoose::Errors::SPOOL_BYTES
      assert_equal 2, File.readlines(made.spool_file).size
    end
  end

  def test_the_rules_cache_is_written_whole
    Dir.mktmpdir do |dir|
      file = File.join(dir, "rules.json")
      rules = { "v" => 1, "enabled" => true, "deny" => ["198.51.100.0/24"] }
      core = FakeCore.new(answers: [SiteGoose::Response.new(200, { "etag" => '"7"' }, JSON.generate(rules))])
      SiteGoose::Firewall.new(core, cache_file: file).sync
      assert_equal [File.basename(file)], Dir.children(dir), "no temporary file left behind"
      assert_equal '"7"', JSON.parse(File.read(file))["etag"]
    end
  end

  def test_the_preview_cookie_is_secure_over_https
    core = FakeCore.new
    core.maintenance_given = { "on" => true, "bypass" => "c0de" }
    maintenance = SiteGoose::Maintenance.new(core)
    assert_includes maintenance.decide("203.0.113.9", "/", "site_preview=c0de", "", secure: true)[1]["set-cookie"], "; Secure"
    refute_includes maintenance.decide("203.0.113.9", "/", "site_preview=c0de", "")[1]["set-cookie"], "Secure"
    assert_equal 503, maintenance.decide("203.0.113.9", "/", "site_preview=c0dX", "")[0]
    assert_nil maintenance.decide("203.0.113.9", "/", "", "a=1, site_preview=c0de")
    assert SiteGoose.https?({ "HTTP_X_FORWARDED_PROTO" => "https" })
    refute SiteGoose.https?({ "rack.url_scheme" => "http" })
  end

  def test_the_middleware_added_twice_runs_once
    made = quiet_platform(performance: {})
    calls = 0
    app = ->(_env) { calls += 1; [200, {}, ["ok"]] }
    outer = SiteGoose::Middleware.new(SiteGoose::Middleware.new(app, made), made)
    outer.call(rack_env(path: "/x"))
    assert_equal 1, calls
    assert_equal [1], made.module("performance").rows.values.map { |r| r[:count] }
  end
end
