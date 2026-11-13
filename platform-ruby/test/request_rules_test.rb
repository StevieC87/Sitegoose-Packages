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
