# frozen_string_literal: true

# Page limits (firewall.md, "Page limits" and step 6 of "Checking a
# request"), against the cases every client shares:
# sdk/protocols/page-limits-cases.json. Then what the shared cases leave to
# each client: a window ending, and the 429 the middleware answers.

require_relative "test_helper"
require "minitest/mock"

class PageLimitsSharedCasesTest < Minitest::Test
  CASES = shared("page-limits-cases.json")

  def test_every_shared_scenario_decides_the_same_way
    CASES["scenarios"].each do |scenario|
      w = wall(CASES["base"].merge(scenario["rules"] || {}).merge("limits" => scenario["limits"]))
      scenario["requests"].each_with_index do |r, i|
        w.queue.clear
        got = w.check(r["ip"], r["method"], r["target"])
        where = "#{scenario['name']}, request #{i + 1} (#{r['why']}): #{r['method']} #{r['target']} from #{r['ip']}"
        if r["expect"] == "allow"
          assert_equal "allow", got[:action], where
          assert_empty w.queue, "#{where}: nothing reported"
        else
          assert_equal r["expect"].values_at("action", "rule", "status"), got.values_at(:action, :rule, :status), where
        end
        assert_equal r["reports"].sort, w.queue.values.map { |e| e["rule"] }.sort, where if r["reports"]
      end
    end
  end
end

class PageLimitsTest < Minitest::Test
  LOGIN = { "mode" => "block", "limits" => { "rules" => [
    { "id" => "wp.login", "action" => "block", "limit" => 1, "window" => 60, "methods" => ["POST"], "path" => { "exact" => ["/wp-login.php"] } }
  ] } }.freeze

  def test_the_count_starts_again_when_the_window_ends
    w = wall(LOGIN)
    start = Time.at(((Time.now.to_i / 60) + 1) * 60)
    Time.stub(:now, start) do
      assert_equal "allow", w.check("198.51.100.7", "POST", "/wp-login.php")[:action]
      assert_equal "limit:wp.login", w.check("198.51.100.7", "POST", "/wp-login.php")[:rule]
    end
    Time.stub(:now, start + 60) do
      assert_equal "allow", w.check("198.51.100.7", "POST", "/wp-login.php")[:action]
    end
  end

  # The "any one page" watcher keeps a count per address and page, which can
  # fill a table; it has one of its own, so making room there never drops
  # the login limit's counts.
  def test_a_full_per_page_table_leaves_other_limits_counting
    rules = { "mode" => "block", "limits" => { "rules" => [
      { "id" => "login", "action" => "block", "limit" => 2, "window" => 600, "path" => { "exact" => ["/login"] } },
      { "id" => "any.page", "action" => "block", "limit" => 600, "window" => 600, "each" => "path", "path" => { "prefix" => ["/"] } }
    ] } }
    w = wall(rules)
    Time.stub(:now, Time.at(((Time.now.to_i / 600) + 1) * 600)) do
      2.times { assert_equal "allow", w.check("198.51.100.7", "POST", "/login")[:action] }
      pages = w.instance_variable_get(:@path_counts)
      i = 0
      (pages["any.page 600 x /#{i += 1}"] = [0, 1]) while pages.size < SiteGoose::Firewall::COUNTER_MAX
      10.times { |n| assert_equal "allow", w.check("198.51.100.8", "GET", "/page/#{n}")[:action] }
      assert_equal SiteGoose::Firewall::COUNTER_MAX, pages.size
      assert_equal "limit:login", w.check("198.51.100.7", "POST", "/login")[:rule], "the login count was kept"
      2.times { assert_equal "allow", w.check("203.0.113.9", "POST", "/login")[:action] }
      assert_equal "limit:login", w.check("203.0.113.9", "POST", "/login")[:rule], "a new address is counted"
    end
  end

  def test_a_shared_counter_is_keyed_per_limit_and_never_per_page
    hits = Hash.new(0)
    counter = lambda { |key, _ttl| hits[key] += 1 }
    rules = { "mode" => "block", "limits" => { "rules" => [
      { "id" => "login", "action" => "block", "limit" => 5, "window" => 60, "path" => { "exact" => ["/login"] } },
      { "id" => "any", "action" => "block", "limit" => 5, "window" => 60, "each" => "path", "path" => { "prefix" => ["/"] } }
    ] } }
    w = wall(rules, counter: counter)
    w.check("198.51.100.7", "GET", "/login")
    assert_equal 1, hits.size
    assert hits.keys[0].start_with?("afw:#{'a' * 24}:l:login:198.51.100.7:"), hits.keys[0]
  end

  def test_a_blocking_limit_answers_429_with_its_window_and_the_plain_text
    made = quiet_platform(firewall: {})
    made.firewall.rules = made.firewall.compile({ "v" => 1, "enabled" => true, "mode" => "block",
                                                  "rate" => { "limit" => 1000, "window" => 300 } }.merge(LOGIN))
    app = SiteGoose::Middleware.new(SITE, made)
    assert_equal 200, app.call(rack_env(method: "POST", path: "/wp-login.php", remote: "198.51.100.7"))[0]
    response = app.call(rack_env(method: "POST", path: "/wp-login.php", remote: "198.51.100.7"))
    assert_equal 429, response[0]
    assert_equal "60", response[1]["retry-after"]
    assert_equal "Too many requests to this page. Please wait a little and try again.", body_of(response)
    refute_includes made.firewall.bans.keys, "198.51.100.7", "a page limit never bans"
  end
end
