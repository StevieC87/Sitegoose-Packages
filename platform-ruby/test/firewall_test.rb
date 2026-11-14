# frozen_string_literal: true

# The firewall's own decisions: the lists, when an address gets banned here,
# the Cloudflare mode, IPv4 kept in IPv6 space, reporting and the rules fetch.

require_relative "test_helper"

FW = SiteGoose::Firewall

class RateBanTest < Minitest::Test
  RATE = { "rate" => { "limit" => 2, "window" => 60 }, "ban" => { "seconds" => 600 } }.freeze

  def test_monitor_mode_bans_nobody
    w = wall(RATE.merge("mode" => "monitor"))
    assert_equal ["", "", "rate", "rate", "rate"], 5.times.map { w.check("203.0.113.9", "GET", "/")[:rule] }
    assert_empty w.bans
  end

  def test_block_mode_bans_here
    w = wall(RATE.merge("mode" => "block"))
    assert_equal ["", "", "rate", "ban"], 4.times.map { w.check("203.0.113.9", "GET", "/")[:rule] }
    assert_equal 429, wall(RATE.merge("mode" => "block")).tap { |x| 2.times { x.check("203.0.113.9") } }.check("203.0.113.9")[:status]
  end

  def test_goodbots_skip_only_the_rate_limit
    w = wall(RATE.merge("mode" => "block", "goodbots" => ["192.0.2.0/24"], "deny" => ["192.0.2.66"]))
    assert_equal [""] * 5, 5.times.map { w.check("192.0.2.5", "GET", "/")[:rule] }
    assert_equal "deny", w.check("192.0.2.66", "GET", "/")[:rule]
  end

  def test_a_shared_counter_counts_across_workers
    hits = Hash.new(0)
    counter = ->(key, ttl) { assert_equal 120, ttl; hits[key] += 1 }
    w = wall(RATE.merge("mode" => "block"), counter: counter)
    3.times { w.check("203.0.113.9", "GET", "/") }
    assert_equal [3], hits.values
    assert hits.keys[0].start_with?("afw:#{'a' * 24}:203.0.113.9:")
  end
end

class ListsTest < Minitest::Test
  def test_order_allow_deny_ban_list_shared
    w = wall({ "mode" => "block", "allow" => ["10.0.0.0/8"], "deny" => ["10.1.0.0/16", "198.51.100.0/24"],
               "banned" => ["198.51.100.7", "192.0.2.1"], "lists" => ["192.0.2.0/24", "203.0.113.0/24"], "shared" => ["203.0.113.4", "2001:db8::/32"] })
    assert_equal "", w.check("10.1.2.3")[:rule]
    assert_equal "deny", w.check("198.51.100.7")[:rule]
    assert_equal "ban", w.check("192.0.2.1")[:rule]
    assert_equal "list", w.check("203.0.113.4")[:rule]
    assert_equal "shared", w.check("2001:db8::1")[:rule]
    assert_equal "list", w.check("::ffff:203.0.113.9")[:rule]
    assert_equal 403, w.check("198.51.100.7")[:status]
  end

  def test_disabled_or_unknown_rules_pass
    w = wall({ "enabled" => false, "deny" => ["0.0.0.0/0"] })
    assert_equal "allow", w.check("203.0.113.9")[:action]
    assert_raises(ArgumentError) { w.compile({ "v" => 2 }) }
    assert_equal "allow", FW.new(FakeCore.new).check("203.0.113.9")[:action]
    assert_equal "allow", wall({ "deny" => ["0.0.0.0/0"] }).check("not an address")[:action]
  end

  def test_monitor_reports_and_passes
    w = wall({ "mode" => "monitor", "deny" => ["203.0.113.0/24"] })
    assert_equal({ action: "monitor", rule: "deny", status: 403 }, w.check("203.0.113.9", "GET", "/x?secret=1", "UA"))
    row = w.queue.values[0]
    assert_equal ["203.0.113.9", "deny", "monitor", "GET", "/x", "UA", 1], row.values_at("ip", "rule", "action", "method", "path", "user_agent", "hits")
    assert_match(/\A\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z\z/, row["at"])
  end

  def test_the_mode_option_overrides_the_dashboard
    assert_equal "block", wall({ "mode" => "monitor", "deny" => ["203.0.113.0/24"] }, mode: "block").check("203.0.113.9")[:action]
  end
end

class ProbesAndRequestRulesTest < Minitest::Test
  PROBES = { "probes" => { "exact" => ["/.env"], "prefix" => ["/.git/"], "ban" => 3600 } }.freeze

  def test_a_probe_is_banned_here_only_in_block_mode
    w = wall(PROBES.merge("mode" => "block"))
    assert_equal "probe", w.check("203.0.113.9", "GET", "//.ENV?x")[:rule]
    assert_equal "ban", w.check("203.0.113.9", "GET", "/")[:rule]
    w = wall(PROBES.merge("mode" => "monitor"))
    assert_equal "probe", w.check("203.0.113.9", "GET", "/.git/config")[:rule]
    assert_equal "", w.check("203.0.113.9", "GET", "/")[:rule]
  end

  def test_a_watched_rule_passes_even_in_block_mode
    w = wall({ "mode" => "block", "requests" => { "rules" => [
               { "id" => "watch", "action" => "monitor", "path" => { "exact" => ["/w"] } },
               { "id" => "stop", "action" => "block", "ban" => 60, "path" => { "exact" => ["/s"] } }
             ] } })
    assert_equal({ action: "monitor", rule: "request:watch", status: 403 }, w.check("203.0.113.9", "GET", "/w"))
    assert_equal "block", w.check("203.0.113.9", "GET", "/s")[:action]
    assert_equal "ban", w.check("203.0.113.9", "GET", "/")[:rule]
  end
end

# firewall.md, "Checking a request": another site can make a visitor's
# browser ask for /.env, or flood a page, from the visitor's own address.
class CrossSiteTest < Minitest::Test
  RULES = { "mode" => "block", "rate" => { "limit" => 2, "window" => 60 }, "ban" => { "seconds" => 600 },
            "probes" => { "exact" => ["/.env"], "ban" => 600 },
            "requests" => { "rules" => [{ "id" => "stop", "action" => "block", "ban" => 60, "path" => { "exact" => ["/s"] } }] } }.freeze

  def test_refused_but_never_banned_and_reported_as_watched
    %w[cross-site Same-Site].each do |site|
      w = wall(RULES)
      assert_equal [403, "probe"], w.check("203.0.113.9", "GET", "/.env", fetch_site: site).values_at(:status, :rule)
      assert_equal [403, "request:stop"], w.check("203.0.113.9", "GET", "/s", fetch_site: site).values_at(:status, :rule)
      assert_equal ["", "", "rate"], 3.times.map { w.check("203.0.113.9", "GET", "/", fetch_site: site)[:rule] }
      assert_equal "block", w.check("203.0.113.9", "GET", "/", fetch_site: site)[:action], "still refused"
      assert_empty w.bans, site
      assert_equal "rate", w.check("203.0.113.9", "GET", "/x", fetch_site: site)[:rule], "not banned: only over the rate"
      assert_equal(%w[monitor], w.queue.values.map { |e| e["action"] }.uniq, site)
      assert_equal %w[probe rate request:stop], w.queue.values.map { |e| e["rule"] }.uniq.sort
    end
  end

  def test_the_sites_own_requests_are_banned_as_before
    ["same-origin", "none", ""].each do |site|
      w = wall(RULES)
      assert_equal "probe", w.check("203.0.113.9", "GET", "/.env", fetch_site: site)[:rule]
      assert_equal "ban", w.check("203.0.113.9", "GET", "/")[:rule], site
      assert_equal "block", w.queue.values.find { |e| e["rule"] == "probe" }["action"]
    end
  end
end

class LoginFailedTest < Minitest::Test
  def test_past_the_limit_the_address_is_banned_and_every_failure_reported
    w = wall({ "mode" => "block", "login" => { "limit" => 3, "window" => 3600, "ban" => 600 } })
    2.times { w.login_failed("203.0.113.9") }
    assert_equal "", w.check("203.0.113.9")[:rule]
    w.login_failed("203.0.113.9")
    assert_equal "ban", w.check("203.0.113.9")[:rule]
    login = w.queue.values.find { |r| r["rule"] == "login" }
    assert_equal ["monitor", "", "", 3], login.values_at("action", "method", "path", "hits")
  end

  def test_allowed_and_invalid_addresses_are_not_counted
    w = wall({ "allow" => ["203.0.113.0/24"], "login" => { "limit" => 1 } })
    w.login_failed("203.0.113.9")
    w.login_failed("nonsense")
    assert_empty w.queue
  end
end

class CloudflareTest < Minitest::Test
  def test_the_ranges_are_the_shared_file
    assert_equal shared("cloudflare-ranges.json")["ranges"], SiteGoose::CLOUDFLARE
  end

  def test_the_header_only_from_a_cloudflare_connection
    headers = { "cf-connecting-ip" => "198.51.100.7" }
    ip = ->(remote, h = headers) { SiteGoose.client_ip(remote, h, "cloudflare") }
    assert_equal "198.51.100.7", ip.call("172.64.1.2")
    assert_equal "198.51.100.7", ip.call("::ffff:162.158.0.9")
    assert_equal "198.51.100.7", ip.call("2606:4700::1")
    assert_equal "203.0.113.50", ip.call("203.0.113.50")
    assert_equal "172.64.1.2", ip.call("172.64.1.2", {})
  end

  def test_forwarded_for_counts_the_proxies_you_run
    headers = { "x-forwarded-for" => "1.1.1.1, 2.2.2.2, 3.3.3.3" }
    assert_equal "9.9.9.9", SiteGoose.client_ip("9.9.9.9", headers, nil)
    assert_equal "3.3.3.3", SiteGoose.client_ip("9.9.9.9", headers, 1)
    assert_equal "3.3.3.3", SiteGoose.client_ip("9.9.9.9", headers, true)
    assert_equal "2.2.2.2", SiteGoose.client_ip("9.9.9.9", headers, 2)
    assert_equal "1.1.1.1", SiteGoose.client_ip("9.9.9.9", headers, 9)
    assert_equal "4.4.4.4", SiteGoose.client_ip("9.9.9.9", headers, ->(_h) { "4.4.4.4" })
  end
end

class MappedSpaceTest < Minitest::Test
  def test_ranges_covering_ipv4_are_dropped
    ["::/64", "::ffff:0:0/64", "::/0", "::ffff:0:0/96", "::/8"].each do |wide|
      assert_nil SiteGoose::IP.range(wide), wide
      refute SiteGoose::IpSet.new([wide]).has?(SiteGoose::IP.key("203.0.113.9")), wide
    end
  end

  def test_narrower_ranges_still_count
    key = SiteGoose::IP.method(:key)
    assert SiteGoose::IpSet.new(["::ffff:203.0.113.0/120"]).has?(key.call("203.0.113.9"))
    assert SiteGoose::IpSet.new(["2001:db8:0:1::/64"]).has?(key.call("2001:db8:0:1::9"))
    assert SiteGoose::IpSet.new(["203.0.113.0/24", "::/64"]).has?(key.call("203.0.113.9"))
    assert SiteGoose::IpSet.new(["203.0.113.7/24"]).has?(key.call("203.0.113.200")), "host bits are masked off"
  end

  def test_a_banned_v6_64_does_not_block_ipv4
    w = wall({ "mode" => "block", "banned" => ["::/64"], "shared" => ["::ffff:0:0/64"] })
    assert_equal "", w.check("203.0.113.9", "GET", "/")[:rule]
  end

  def test_addresses_are_read_strictly
    key = SiteGoose::IP.method(:key)
    assert_equal key.call("203.0.113.9"), key.call("::ffff:203.0.113.9")
    assert_equal key.call("fe80::1"), key.call("fe80::1%eth0")
    [nil, "", "1.2.3", "1.2.3.256", "01.2.3.4", "1.2.3.0/24", "x::y", "localhost"].each { |bad| assert_nil key.call(bad), bad.inspect }
  end

  def test_overlapping_ranges_merge
    set = SiteGoose::IpSet.new(["10.0.0.0/24", "10.0.0.128/25", "10.0.1.0/24", "bad", 7])
    assert_equal 1, set.size
    assert set.has?(SiteGoose::IP.key("10.0.1.255"))
    refute set.has?(SiteGoose::IP.key("10.0.2.0"))
  end
end

class RulesFetchTest < Minitest::Test
  def test_rules_are_kept_with_their_etag_and_survive_a_restart
    path = File.join(Dir.tmpdir, "fw-#{Process.pid}-#{rand(1 << 30)}.json")
    body = JSON.generate({ "v" => 1, "enabled" => true, "mode" => "block", "sync" => 45, "deny" => ["198.51.100.0/24"] })
    core = FakeCore.new(answers: [SiteGoose::Response.new(200, { "etag" => '"e1"' }, body),
                                  SiteGoose::Response.new(304, {}, "")])
    w = FW.new(core, cache_file: path)
    assert_equal 45, w.sync
    assert_equal "deny", w.check("198.51.100.1")[:rule]
    assert_equal 45, w.sync, "a 304 keeps the rules"
    assert_equal '"e1"', core.sent[1][:headers]["If-None-Match"]
    again = FW.new(FakeCore.new, cache_file: path)
    assert_equal "deny", again.check("198.51.100.1")[:rule]
    assert_equal '"e1"', again.etag
  ensure
    File.delete(path) if path && File.exist?(path)
  end

  def test_a_bad_answer_keeps_the_last_rules
    core = FakeCore.new(answers: [SiteGoose::Response.new(200, {}, '{"v":7}'), nil])
    w = wall({ "deny" => ["198.51.100.0/24"] }, core: core)
    w.sync
    w.sync
    assert_equal "deny", w.check("198.51.100.1")[:rule]
  end

  def test_reports_go_in_batches_of_200
    core = FakeCore.new
    w = wall({ "deny" => ["198.51.100.0/24"] }, core: core)
    250.times { |i| w.check("198.51.100.#{i % 250}", "GET", "/p#{i}") }
    w.flush
    assert_equal [200, 50], core.sent.map { |s| s[:body]["events"].size }
    assert_equal "/events/firewall/events", core.sent[0][:path]
    assert_equal :bearer, core.sent[0][:auth]
  end
end
