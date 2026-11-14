# frozen_string_literal: true

# The request-rule matcher (virtual patching), against the cases every client
# shares: sdk/protocols/request-rules-cases.json.

require_relative "test_helper"

RR = SiteGoose::RequestRules

class RequestRulesSharedCasesTest < Minitest::Test
  CASES = shared("request-rules-cases.json")
  # The shared cases are about matching, so patterns are compiled here even
  # on a Ruby that skips them in use (no regex timeout before 3.2).
  RULES = begin
    allowed = RR.regex_allowed
    RR.regex_allowed = true
    RR.compile({ "rules" => CASES["rules"] })
  ensure
    RR.regex_allowed = allowed
  end

  # These tests are about matching too (a Ruby without a regex timeout skips
  # patterns in use: HardeningTest covers that).
  def setup
    @allowed = RR.regex_allowed
    RR.regex_allowed = true
  end

  def teardown
    RR.regex_allowed = @allowed
  end

  def test_every_shared_case_decides_the_same_way
    CASES["requests"].each do |r|
      matched = RR.match(RULES, r["method"], r["target"], r["ua"])
      expected = r["expect"]
      got = matched && matched["id"]
      if expected.nil?
        assert_nil got, "#{r['why']}: #{r['method']} #{r['target']}"
      else
        assert_equal expected, got, "#{r['why']}: #{r['method']} #{r['target']}"
      end
    end
  end

  def test_the_shared_pattern_lists_decide_the_same_way
    CASES["patterns"]["refused"].each { |p| refute RR.safe_pattern?(p), p }
    CASES["patterns"]["allowed"].each { |p| assert RR.safe_pattern?(p), p }
  end

  def test_a_rule_with_nothing_to_match_is_dropped
    assert_equal [], RR.compile({ "rules" => [{ "id" => "empty", "action" => "block" }] })
  end

  def test_a_pattern_that_does_not_compile_is_dropped
    rules = RR.compile({ "rules" => [
                         { "id" => "bad", "action" => "block", "path" => { "regex" => "([" } },
                         { "id" => "good", "action" => "block", "path" => { "exact" => ["/shell.php"] } }
                       ] })
    assert_equal 1, rules.size
    assert_equal "good", RR.match(rules, "GET", "/shell.php", "")["id"]
  end

  def test_no_rules_no_match
    assert_nil RR.match([], "GET", "/../../etc/passwd", "")
    assert_nil RR.match(RR.compile(nil), "GET", "/../../etc/passwd", "")
    assert_nil RR.match(RR.compile({ "rules" => "nonsense" }), "GET", "/x", "")
  end

  def test_at_most_200_rules
    many = 250.times.map { |i| { "id" => "r#{i}", "action" => "monitor", "path" => { "exact" => ["/#{i}"] } } }
    assert_equal 200, RR.compile({ "rules" => many }).size
  end

  def test_an_unsafe_rule_is_dropped_and_matching_stays_quick
    rules = RR.compile({ "rules" => [
                         { "id" => "slow", "action" => "block", "path" => { "regex" => "(a+)+b" } },
                         { "id" => "fine", "action" => "block", "path" => { "exact" => ["/x"] } }
                       ] })
    assert_equal ["fine"], rules.map { |r| r["id"] }
    started = SiteGoose.clock
    assert_nil RR.match(rules, "GET", "/#{'a' * 100_000}!", "")
    assert_operator SiteGoose.clock - started, :<, 1.0
  end

  # Ruby's ^ and $ are line anchors: a decoded %0a must not end the "line".
  def test_anchors_mean_the_whole_text
    rules = RR.compile({ "rules" => [{ "id" => "php", "action" => "block", "path" => { "regex" => "^/uploads/[^?]*\\.php$" } }] })
    assert_equal "php", RR.match(rules, "GET", "/uploads/x.php", "")["id"]
    assert_nil RR.match(rules, "GET", "/uploads/x.php%0a.jpg", "")
    assert_nil RR.match(rules, "GET", "/a%0a/uploads/x.php", "")
    assert_equal "\\A/x\\z[$^]", RR.ruby_anchors("^/x$[$^]")
    assert_equal "[^$]\\z", RR.ruby_anchors("[^$]$")
  end

  def test_a_body_rule_is_skipped_whole
    rules = RR.compile({ "rules" => [{ "id" => "body", "action" => "block", "path" => { "exact" => ["/x"] }, "body" => { "contains" => ["x"] } }] })
    assert_equal [], rules
  end

  def test_a_bad_escape_stays_as_it_is
    assert_equal "%zz 1", RR.decode_once("%zz+1")
    assert_equal "\uFFFD", RR.decode_once("%ff")
  end

  # A regex reads a long part in windows of 2,000 every 1,000; one anchored
  # to the start or the end reads only the window that holds it.
  def test_a_regex_reads_a_long_part_in_windows
    rules = ->(pattern) { RR.compile({ "rules" => [{ "id" => "r", "action" => "block", "query" => { "regex" => pattern } }] }) }
    filler = "x" * 5000
    assert_equal "r", RR.match(rules.call("union[^&]{0,20}select"), "GET", "/?a=#{filler}&q=union%20select", "")["id"]
    assert_equal "r", RR.match(rules.call("select$"), "GET", "/?a=#{filler}&q=union%20select", "")["id"]
    assert_nil RR.match(rules.call("^q=union"), "GET", "/?a=#{filler}&q=union", "")
    assert_equal "r", RR.match(rules.call("^a=x"), "GET", "/?a=#{filler}&q=union", "")["id"]
    # The window that starts at 1,000 must not read as the start of the query.
    assert_nil RR.match(rules.call("^x{1000}$"), "GET", "/?#{'y' * 1000}#{'x' * 1000}", "")
    assert_nil RR.match(rules.call("^y.*$"), "GET", "/?#{'y' * 2001}", "")
    assert_equal [0, 1000, 2000, 3000], RR.window_starts(5000, false, false).to_a
    assert_equal [1000], RR.window_starts(2500, false, true).to_a
    assert_equal [0], RR.window_starts(2000, true, true).to_a
    refute RR.ends_anchored?("a\\$")
    assert RR.ends_anchored?("a\\\\$")
  end

  # Rack::MethodOverride runs after us: a POST asking for DELETE is routed
  # as a DELETE, and HEAD runs GET routes.
  def test_a_post_is_also_the_method_it_asks_for_and_head_is_also_get
    rules = RR.compile({ "rules" => [
                         { "id" => "delete", "action" => "block", "methods" => ["DELETE"], "path" => { "prefix" => ["/api/users/"] } },
                         { "id" => "get", "action" => "block", "methods" => ["GET"], "path" => { "exact" => ["/admin"] } }
                       ] })
    assert_nil RR.match(rules, "POST", "/api/users/1", "")
    assert_equal "delete", RR.match(rules, "POST", "/api/users/1", "", RR.prepare("POST", "/api/users/1", "", overrides: ["delete"]))["id"]
    assert_nil RR.match(rules, "PUT", "/api/users/1", "", RR.prepare("PUT", "/api/users/1", "", overrides: ["DELETE"])), "only a POST is overridden"
    assert_equal "get", RR.match(rules, "HEAD", "/admin", "")["id"]
    assert_equal "get", RR.match(rules, "POST", "/admin", "", RR.prepare("POST", "/admin", "", overrides: ["HEAD"]))["id"]
    assert_equal %w[POST], RR.methods_of("POST", ["DE LETE", "", "x" * 30])
  end

  # The path the app routes on counts too, when the server read the target differently.
  def test_the_routed_path_is_matched_as_well
    rules = RR.compile({ "rules" => [{ "id" => "admin", "action" => "block", "path" => { "prefix" => ["/admin"] } }] })
    assert_nil RR.match(rules, "GET", "/x:/admin", "")
    assert_equal "admin", RR.match(rules, "GET", "/x:/admin", "", RR.prepare("GET", "/x:/admin", "", also_path: "/admin"))["id"]
  end
end

class OriginFormTest < Minitest::Test
  def test_every_shared_target
    shared("request-rules-cases.json")["targets"].each do |c|
      assert_equal c["origin"], SiteGoose.origin_form(c["target"]), c["target"]
      env = { "REQUEST_URI" => c["target"], "QUERY_STRING" => "" }
      assert_equal c["origin"], SiteGoose.request_target(env), "request_target: #{c['target']}"
    end
  end
end

class RequestTargetTest < Minitest::Test
  def target(env)
    SiteGoose.request_target(env)
  end

  def test_the_servers_own_copy_wins
    assert_equal "/a%252e?q=1", target({ "REQUEST_URI" => "/a%252e?q=1", "PATH_INFO" => "/a%2e", "QUERY_STRING" => "q=1" })
    assert_equal "/x%20y?a=1", target({ "REQUEST_URI" => "/x%20y", "PATH_INFO" => "/x%20y", "QUERY_STRING" => "a=1" })
  end

  def test_an_absolute_target_loses_its_scheme_and_host
    assert_equal "/p?q=1", target({ "REQUEST_URI" => "http://example.com/p?q=1", "QUERY_STRING" => "q=1" })
    assert_equal "/admin", target({ "REQUEST_URI" => "x:/admin", "PATH_INFO" => "/admin", "QUERY_STRING" => "" })
  end

  def test_the_routed_path_only_when_it_differs
    env = { "REQUEST_URI" => "/a%2e?q=1", "SCRIPT_NAME" => "", "PATH_INFO" => "/a%2e", "QUERY_STRING" => "q=1" }
    assert_nil SiteGoose.routed_also(env, target(env))
    env = { "REQUEST_URI" => "weird", "SCRIPT_NAME" => "", "PATH_INFO" => "/admin", "QUERY_STRING" => "" }
    assert_equal "/admin", SiteGoose.routed_also(env, target(env))
    assert_nil SiteGoose.routed_also({ "PATH_INFO" => "/admin" }, "/other"), "no REQUEST_URI: the target is the routed path"
  end

  def test_what_a_post_asks_to_be_routed_as
    env = { "REQUEST_METHOD" => "POST", "QUERY_STRING" => "a=1&_method=patch&%5Fmethod=put" }
    assert_equal %w[DELETE patch put], SiteGoose.method_overrides(env, { "x-http-method-override" => "DELETE" })
    env["rack.request.form_hash"] = { "_method" => "delete" }
    assert_includes SiteGoose.method_overrides(env, {}), "delete"
    assert_equal [], SiteGoose.method_overrides({ "REQUEST_METHOD" => "GET", "QUERY_STRING" => "_method=delete" }, {})
  end

  # Rack's PATH_INFO is not decoded, so it is taken as it is; raw bytes are encoded.
  def test_otherwise_script_name_and_path_info_with_the_query
    assert_equal "/app/caf%C3%A9?id=1%20union", target({ "SCRIPT_NAME" => "/app", "PATH_INFO" => "/caf\u00e9", "QUERY_STRING" => "id=1%20union" })
    assert_equal "/a%2e%2e/", target({ "PATH_INFO" => "/a%2e%2e/", "QUERY_STRING" => "" })
  end

  def test_the_query_string_reaches_the_rules
    rules = RR.compile({ "rules" => [{ "id" => "sqli", "action" => "block", "query" => { "contains" => ["union select"] } }] })
    t = target({ "PATH_INFO" => "/item", "QUERY_STRING" => "id=1%20union%20select" })
    assert_equal "sqli", RR.match(rules, "GET", t, "")["id"]
  end
end
