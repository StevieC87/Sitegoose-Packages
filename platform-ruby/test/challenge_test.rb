# frozen_string_literal: true

# The browser check (rule `challenge`): the shared cases every client runs
# (sdk/protocols/challenge-cases.json), then the check as the middleware answers it.

require_relative "test_helper"

SHARED = shared("challenge-cases.json")
C = SiteGoose::Challenge

def check_rules(mode: "monitor", check: SHARED["challenge"], **more)
  { "v" => 1, "enabled" => true, "mode" => mode, "challenge" => check }.merge(more.transform_keys(&:to_s))
end

def checking_firewall(core: FakeCore.new(secret: SHARED["secret"]), mode: nil, **rules)
  wall = SiteGoose::Firewall.new(core, mode: mode)
  wall.rules = wall.compile(check_rules(**rules))
  wall
end

class ChallengeSharedCasesTest < Minitest::Test
  KEY = C.pass_key(SHARED["secret"])

  def test_tokens
    SHARED["tokens"].each do |c|
      assert_equal c["who"], C.who(c["ip"]), c["ip"]
      assert_equal c["token"], C.make_pass(KEY, c["ip"], c["now"]), c["ip"]
    end
  end

  def test_checks
    SHARED["checks"].each do |c|
      assert_equal c["valid"], C.valid?(KEY, c["ip"], c["cookie"], c["now"]), c["why"]
    end
  end

  def test_decisions
    SHARED["decisions"].each do |c|
      r = c["request"]
      wall = checking_firewall
      cookie = r["cookie"].empty? ? "" : "__sg_pass=#{r['cookie']}"
      decision = wall.check(r["ip"], r["method"], r["path"], "Mozilla/5.0", r["accept"], cookie, c["now"])
      assert_equal c["challenged"], decision[:rule] == "challenge", c["why"]
      assert_equal %w[block 503], [decision[:action], decision[:status].to_s], c["why"] if c["challenged"]
    end
  end
end

class ChallengeDecisionTest < Minitest::Test
  def test_allow_and_goodbots_are_never_checked
    wall = checking_firewall(allow: ["198.51.100.9"], goodbots: ["192.0.2.0/24"])
    assert_equal "", wall.check("198.51.100.9", "GET", "/", "", HTML)[:rule]
    assert_equal "", wall.check("192.0.2.5", "GET", "/", "", HTML)[:rule]
    assert_equal "challenge", wall.check("203.0.113.5", "GET", "/", "", HTML)[:rule]
  end

  def test_blocks_even_in_monitor_mode_and_with_the_mode_overridden
    wall = checking_firewall(mode: "monitor")
    wall.rules = wall.compile(check_rules(mode: "block"))
    assert_equal "block", wall.check("203.0.113.5", "GET", "/", "", HTML)[:action]
  end

  def test_earlier_rules_win_in_block_mode
    wall = checking_firewall(mode: "block", deny: ["203.0.113.0/24"])
    wall.rules = wall.compile(check_rules(mode: "block", deny: ["203.0.113.0/24"]))
    assert_equal "deny", wall.check("203.0.113.5", "GET", "/", "", HTML)[:rule]
    wall = checking_firewall
    wall.rules = wall.compile(check_rules(mode: "block", rate: { "limit" => 1, "window" => 60 }))
    assert_equal %w[challenge rate], 2.times.map { wall.check("203.0.113.5", "GET", "/", "", HTML)[:rule] }
  end

  def test_a_match_only_watched_still_gets_the_check
    wall = checking_firewall(deny: ["203.0.113.0/24"])
    got = wall.check("203.0.113.5", "GET", "/", "", HTML)
    assert_equal ["challenge", "block", 503], got.values_at(:rule, :action, :status)
    assert_equal [%w[challenge block], %w[deny monitor]], wall.queue.values.map { |r| r.values_at("rule", "action") }.sort
    # Not a page load: the watched match passes, as before.
    assert_equal "monitor", wall.check("203.0.113.5", "POST", "/", "", HTML)[:action]
  end

  def test_a_pass_from_this_server_lets_the_next_request_through
    wall = checking_firewall
    token = C.make_pass(wall.pass_key, "203.0.113.5")
    assert_equal "", wall.check("203.0.113.5", "GET", "/", "", HTML, "theme=dark; __sg_pass=#{token}")[:rule]
  end

  def test_a_stale_pass_on_another_path_does_not_hide_a_good_one
    wall = checking_firewall
    token = C.make_pass(wall.pass_key, "203.0.113.5")
    assert_equal "", wall.check("203.0.113.5", "GET", "/", "", HTML, "__sg_pass=1.#{'0' * 32}; __sg_pass=\"#{token}\"")[:rule]
  end

  def test_no_challenge_key_changes_nothing
    wall = checking_firewall(check: nil)
    assert_equal({ action: "allow", rule: "", status: 200 }, wall.check("203.0.113.5", "GET", "/", "", HTML))
  end

  def test_reported_as_challenge_block
    wall = checking_firewall
    2.times { wall.check("203.0.113.5", "GET", "/pricing?x=1", "Mozilla/5.0", HTML) }
    rows = wall.queue.values
    assert_equal 1, rows.size
    assert_equal({ "ip" => "203.0.113.5", "rule" => "challenge", "action" => "block", "method" => "GET", "path" => "/pricing", "hits" => 2 },
                 rows[0].slice("ip", "rule", "action", "method", "path", "hits"))
  end
end

class ChallengePageTest < Minitest::Test
  KEY = C.pass_key("s")

  def test_page
    status, headers, body = C.page(KEY, "203.0.113.5", "GET")
    assert_equal 503, status
    assert_equal "text/html; charset=utf-8", headers["content-type"]
    assert_equal "no-store", headers["cache-control"]
    assert_equal "noindex", headers["x-robots-tag"]
    nonce = headers["content-security-policy"][/script-src 'nonce-([^']+)'/, 1]
    assert_includes body, "<script nonce=\"#{nonce}\">"
    assert_includes body, "<style nonce=\"#{nonce}\">"
    assert_includes body, C.make_pass(KEY, "203.0.113.5")
    assert_includes body, "Max-Age=86400; Path=/; SameSite=Lax"
    assert_includes body, 's=location.protocol==="https:"'
    assert_includes body, '(s?"; Secure":"")'
    assert_includes body, "location.reload()"
    assert_includes body, "<noscript>"
  end

  def test_the_script_stops_after_three_reloads_a_minute
    script = C.script("20761.0ddc48fd8c38f7a225623a9a27f1d364")
    assert_includes script, "sessionStorage.getItem(k)"
    assert_includes script, "r>=3"
    assert_includes script, "Date.now()-x<60000"
    assert_includes script, "address keeps changing"
    assert_includes script, "__sg_tries"
  end

  # The same script as the Node, PHP and Python clients': byte for byte.
  def test_the_script_is_the_other_clients_one
    expected = '(function(){var n="__sg_pass",v="1.x",m=document.getElementById("m"),s=location.protocol==="https:";' \
               'document.cookie=n+"="+v+"; Max-Age=86400; Path=/; SameSite=Lax"+(s?"; Secure":"");' \
               'if((" "+document.cookie+";").indexOf(" "+n+"="+v+";")<0){m.textContent="Please allow cookies for this site, then reload the page.";return;}' \
               'var k="__sg_tries",r=0,t;try{t=JSON.parse(sessionStorage.getItem(k)||"[]").filter(function(x){return Date.now()-x<60000;});' \
               'r=t.length;if(r<3){t.push(Date.now());sessionStorage.setItem(k,JSON.stringify(t));}}' \
               'catch(e){t=/(?:^|; )__sg_tries=([0-9]+)/.exec(document.cookie);r=t?+t[1]:0;if(r<3)document.cookie=k+"="+(r+1)+"; Max-Age=60; Path=/; SameSite=Lax"+(s?"; Secure":"");}' \
               "if(r>=3){m.textContent=\"This page couldn't be opened because your connection's address keeps changing. Please try again in a minute.\";return;}" \
               "location.reload();})();"
    assert_equal expected, C.script("1.x")
  end

  def test_a_fresh_nonce_each_time
    first = C.page(KEY, "203.0.113.5", "GET")[1]["content-security-policy"]
    refute_equal first, C.page(KEY, "203.0.113.5", "GET")[1]["content-security-policy"]
  end

  def test_head_gets_no_body
    status, headers, body = C.page(KEY, "203.0.113.5", "HEAD")
    assert_equal [503, ""], [status, body]
    assert headers.key?("content-security-policy")
  end

  def test_a_ten_digit_day_is_read
    now = 1_234_567_890 * 86_400
    value = C.make_pass(KEY, "203.0.113.5", now)
    assert value.start_with?("1234567890.")
    assert C.valid?(KEY, "203.0.113.5", value, now)
  end
end

class FirewallFetchHeadersTest < Minitest::Test
  def test_layers_and_server_name_on_every_fetch
    core = FakeCore.new(answers: [nil, nil])
    wall = SiteGoose::Firewall.new(core)
    wall.sync
    wall.etag = '"x"'
    wall.sync
    assert_equal "app check", SiteGoose::Firewall::LAYERS
    core.sent.each do |sent|
      assert_equal "app check", sent[:headers]["X-Firewall-Layers"]
      assert_includes 1..100, sent[:headers]["X-Server-Name"].size
      assert_equal :bearer, sent[:auth]
    end
    assert_equal '"x"', core.sent[1][:headers]["If-None-Match"]
  end
end

class ChallengeRackTest < Minitest::Test
  def app(check: SHARED["challenge"], **rules)
    made = quiet_platform(firewall: {})
    made.firewall.rules = made.firewall.compile(check_rules(check: check, **rules))
    [made, SiteGoose::Middleware.new(SITE, made)]
  end

  def test_a_browser_page_gets_the_check
    _, middleware = app
    status, headers, body = middleware.call(rack_env)
    assert_equal 503, status
    assert_equal "text/html; charset=utf-8", headers["content-type"]
    assert_includes body_of([status, headers, body]), "__sg_pass"
  end

  def test_head_gets_the_check_without_a_body
    _, middleware = app
    response = middleware.call(rack_env(method: "HEAD"))
    assert_equal [503, ""], [response[0], body_of(response)]
  end

  def test_post_and_json_reach_the_site
    _, middleware = app
    assert_equal "the site", body_of(middleware.call(rack_env(method: "POST")))
    assert_equal "the site", body_of(middleware.call(rack_env(accept: "application/json")))
    assert_equal "the site", body_of(middleware.call(rack_env(path: "/api/orders")))
  end

  def test_with_a_pass_the_site_answers
    made, middleware = app
    token = C.make_pass(made.firewall.pass_key, "203.0.113.5")
    assert_equal "the site", body_of(middleware.call(rack_env(cookie: "__sg_pass=#{token}")))
  end

  def test_no_challenge_changes_nothing
    _, middleware = app(check: nil)
    assert_equal "the site", body_of(middleware.call(rack_env))
  end

  def test_other_refusals_keep_their_status
    _, middleware = app(mode: "block", deny: ["203.0.113.5"])
    response = middleware.call(rack_env)
    assert_equal [403, "Forbidden"], [response[0], body_of(response)]
  end
end
