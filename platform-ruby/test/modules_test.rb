# frozen_string_literal: true

# Server speed, crawlers, server analytics, forms, audit, flags, maintenance.

require_relative "test_helper"

class PerformanceTest < Minitest::Test
  P = SiteGoose::Performance

  def test_routes_are_named_like_the_other_packages
    assert_equal "/orders/:id/items/:id", P.normalize_route("/orders/123/items/9f8e7d6c5b4a39281706f5e4d3c2b1a0")
    assert_equal "/u/:id/x", P.normalize_route("/u/abc123def456ghi789jk/x")
    assert_equal "/", P.normalize_route("")
    assert_equal "/a/:id", P.normalize_route("a/550e8400-e29b-41d4-a716-446655440000?x=1")
  end

  def test_buckets_are_the_collectors
    assert_equal [0, 0, 1, 11, 11], [0, 5, 6, 10_000.5, 99_999].map { |ms| P.bucket_of(ms) }
  end

  def test_one_row_per_minute_method_route_and_status
    core = FakeCore.new
    perf = P.new(core, server_name: "web-1")
    perf.record("get", "/users/:id", 200, 12.0, "/users/1")
    perf.record("GET", "/users/:id", 200, 30.0, "/users/2")
    perf.record("GET", "", 404, 1.0, "/nothing/here")
    perf.record("POST", "", 201, 3.0, "/orders/77")
    perf.flush
    body = core.sent[0][:body]
    assert_equal ["web-1", "Ruby #{RUBY_VERSION}"], body.values_at("server_name", "runtime")
    rows = body["rows"].to_h { |r| [[r["method"], r["route"], r["status"]], r] }
    users = rows[["GET", "/users/:id", 200]]
    assert_equal [2, 42.0, 30.0], users.values_at("count", "sum_ms", "max_ms")
    assert_equal 12, users["buckets"].size
    assert rows.key?(["GET", "/(not found)", 404])
    assert rows.key?(["POST", "/orders/:id", 201])
  end

  def test_past_300_keys_the_rest_is_other
    perf = P.new(FakeCore.new)
    400.times { |i| perf.record("GET", "/r#{i}", 200, 1.0) }
    assert_equal 301, perf.rows.size
    assert_equal 100, perf.rows.find { |k, _| k[2] == "(other)" }[1][:count]
  end

  def test_switched_off_nothing_is_recorded
    core = FakeCore.new
    core.switches = { "performance" => false }
    perf = P.new(core)
    perf.record("GET", "/x", 200, 1.0)
    assert_empty perf.rows
  end
end

class CrawlersTest < Minitest::Test
  CR = SiteGoose::Crawlers

  def test_most_specific_name_wins
    assert_equal "ChatGPT-User", CR.detect("Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0")
    assert_equal "GPTBot", CR.detect("Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)")
    assert_equal "Claude-User", CR.detect("Claude-User/1.0")
    assert_equal "ClaudeBot", CR.detect("ClaudeBot/1.0")
    assert_equal "Google-InspectionTool", CR.detect("Google-InspectionTool/1.0 Googlebot")
    assert_equal "Googlebot", CR.detect("Mozilla/5.0 (compatible; Googlebot/2.1)")
  end

  def test_an_unlisted_crawler_is_still_counted_and_visitors_are_not
    assert_equal "Other bot", CR.detect("NewThingBot/0.1")
    assert_equal "Other bot", CR.detect("curl/8.0")
    assert_equal "", CR.detect("Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/130.0 Safari/537.36")
    assert_equal "", CR.detect(nil)
  end

  def test_rows_add_up_and_carry_addresses
    core = FakeCore.new
    crawlers = CR.new(core, server_name: "web-1")
    2.times { crawlers.middleware("GPTBot/1.2", "/pricing?utm=x", 200, 4, 1000, "20.171.207.1") }
    crawlers.middleware("GPTBot/1.2", "/pricing", 404, 2, 10, "20.171.207.2")
    crawlers.middleware("Mozilla/5.0 Chrome/130", "/pricing", 200, 2, 10, "198.51.100.1")
    crawlers.flush
    body = core.sent[0][:body]
    rows = body["rows"].to_h { |r| [[r["bot"], r["path"], r["status"]], r] }
    assert_equal [2, 2000, 8], rows[["GPTBot", "/pricing", 200]].values_at("count", "bytes", "sum_ms")
    assert_equal 2, rows.size
    assert_equal [{ "bot" => "GPTBot", "ips" => ["20.171.207.1", "20.171.207.2"] }], body["agents"]
    assert_equal "Ruby #{RUBY_VERSION}", body["runtime"]
  end

  def test_thousands_of_pages_become_one_row
    crawlers = CR.new(FakeCore.new)
    500.times { |i| crawlers.record("GPTBot", "/p/#{i}", 200) }
    assert_equal 301, crawlers.rows.size
  end
end

class AnalyticsTest < Minitest::Test
  def test_track_queues_with_a_uid_and_sends_in_batches
    core = FakeCore.new
    analytics = SiteGoose::Analytics.new(core)
    uid = analytics.track("purchase", { numeric_value: 49.9, currency: "EUR" }, "11111111-1111-4111-8111-111111111111")
    assert_match(/\A\h{8}-\h{4}-4\h{3}-\h{4}-\h{12}\z/, uid)
    assert_equal "order-1", analytics.track("purchase", { "event_uid" => "order-1" })
    assert_equal "", analytics.track("")
    assert analytics.flush
    events = core.sent[0][:body]["events"]
    assert_equal ["purchase", "49.9", "EUR", uid], events[0].values_at("event_name", "numeric_value", "currency", "event_uid")
    assert_equal "/events/server-events", core.sent[0][:path]
  end

  def test_a_batch_the_collector_could_not_take_is_kept
    core = FakeCore.new(answers: [503])
    analytics = SiteGoose::Analytics.new(core)
    analytics.track("signup")
    refute analytics.flush
    assert_equal 1, analytics.queue.size
    assert analytics.flush
    assert_empty analytics.queue
  end

  def test_identify_and_lead_wait_for_the_answer
    core = FakeCore.new(answers: [202, SiteGoose::Response.new(200, {}, '{"status":"created","lead_id":"l1"}')])
    analytics = SiteGoose::Analytics.new(core)
    refute analytics.identify("u1", "")
    assert analytics.identify("u1", "s1")
    assert_equal({ "status" => "created", "lead_id" => "l1" }, analytics.lead({ email: "ana@example.com" }, "s1"))
    assert_equal({ "email" => "ana@example.com", "session_id" => "s1" }, core.sent[1][:body])
  end

  def test_identify_passes_scalar_traits_through
    core = FakeCore.new
    analytics = SiteGoose::Analytics.new(core)
    assert analytics.identify("u1", "s1")
    assert analytics.identify("u1", "s1", { plan: :pro, "Seats" => 5, ratio: 0.5, trial: false,
                                            tags: ["a"], meta: { a: 1 }, gone: nil, bad: Float::NAN })
    assert analytics.identify("u1", "s1", { tags: ["a"] })
    assert_equal({ "user_id" => "u1", "session_id" => "s1" }, core.sent[0][:body])
    assert_equal({ "plan" => "pro", "Seats" => 5, "ratio" => 0.5, "trial" => false }, core.sent[1][:body]["traits"])
    refute core.sent[2][:body].key?("traits")
  end
end

class FormsTest < Minitest::Test
  def test_private_fields_never_leave_and_nested_names_are_kept
    fields = SiteGoose::Forms.plain_fields({ "user" => { "email" => "a@b.c", "password" => "x" }, "card_number" => "4111",
                                                     "tags" => %w[a b], "analytics-shield" => "t", "note" => "hi" })
    assert_equal({ "user[email]" => "a@b.c", "tags" => "a, b", "note" => "hi" }, fields)
  end

  # platform-php's FormsTest list and the autocomplete names: a sign-up or checkout form
  # handed over whole must not send any of these.
  def test_the_wide_list_of_private_fields
    drop = %w[password pwd passwd user_pass card cc_number cc-number cc-csc cc-exp api-key cvc cvv expiry exp_month api_key apikey auth authorization
              access_token client_secret otp mfa_code pin security_code ssn tax_id iban swift routing account_number
              dob birthday licence signature private_notes _csrf _wpnonce analytics-shield]
    keep = %w[name email message author subject phone order_number]
    sent = SiteGoose::Forms.plain_fields((drop + keep).to_h { |name| [name, "x"] })
    assert_equal keep, sent.keys
    assert_equal ["user[name]"], SiteGoose::Forms.plain_fields({ "user" => { "name" => "x", "pin" => "1" } }).keys
  end

  def test_a_card_number_is_taken_out_of_any_field
    sent = SiteGoose::Forms.plain_fields({ "field_12" => "my card is 4111 1111 1111 1111 thanks",
                                           "phone" => "+44 20 7946 0958", "order" => "100000123" })
    assert_equal "my card is [removed] thanks", sent["field_12"]
    assert_equal "+44 20 7946 0958", sent["phone"]
    assert_equal "100000123", sent["order"]
    assert_equal "ref 1234567890123", SiteGoose::Forms.without_card_numbers("ref 1234567890123")
    assert_equal "[removed]", SiteGoose::Forms.without_card_numbers("4111-1111-1111-1111")
  end

  def test_the_check_and_failing_open
    core = FakeCore.new(answers: [SiteGoose::Response.new(200, {}, '{"success":false,"reasons":["disposable"]}'), 503])
    forms = SiteGoose::Forms.new(core)
    got = forms.check({ "analytics-shield" => "tok", "email" => "x@y.z" }, "203.0.113.5", "x@y.z")
    assert_equal({ ok: false, spam: true, reasons: ["disposable"], checked: true }, got)
    assert_equal ["tok", "203.0.113.5", "x@y.z"], core.sent[0][:body].values_at("token", "ip", "email")
    assert_equal({ ok: true, spam: false, reasons: ["unchecked"], checked: false }, forms.check({}))
  end
end

class AuditTest < Minitest::Test
  def test_entries_go_in_batches
    core = FakeCore.new
    audit = SiteGoose::Audit.new(core)
    audit.record("user.role_changed", "ana", "bob", { "to" => "admin" }, "203.0.113.5", "s1")
    audit.record("")
    audit.flush
    entry = core.sent[0][:body]["entries"][0]
    assert_equal ["user.role_changed", "ana", "bob", { "to" => "admin" }, "203.0.113.5", "s1"],
                 entry.values_at("action", "actor", "target", "details", "actor_ip", "session_id")
    assert_equal 1, core.sent[0][:body]["entries"].size
  end
end

class FlagsTest < Minitest::Test
  F = SiteGoose::Flags

  def test_buckets_are_the_other_packages
    assert_equal [44, 63, 82, 1, 68], 5.times.map { |i| F.bucket("new-checkout", "user-#{i}") }
    assert_equal 86, F.bucket("k", "café")
  end

  def test_rules
    core = FakeCore.new
    core.flags_given = { "on" => { "on" => true }, "off" => { "on" => false }, "listed" => { "on" => true, "rollout" => 0, "users" => [7] },
                         "half" => { "on" => true, "rollout" => 50 } }
    flags = F.new(core)
    assert flags.enabled?("on")
    refute flags.enabled?("off")
    assert flags.enabled?("listed", 7)
    refute flags.enabled?("listed", 8)
    refute flags.enabled?("half"), "a rollout needs a user"
    assert_equal F.bucket("half", "u") < 50, flags.enabled?("half", "u")
    assert flags.enabled?("unknown", nil, true)
    core.switches = { "flags" => false }
    refute flags.enabled?("on")
  end
end

class MaintenanceTest < Minitest::Test
  def test_the_page_the_allowance_and_the_preview_link
    core = FakeCore.new
    core.maintenance_given = { "on" => true, "message" => "<b>Soon</b>", "allow" => ["198.51.100.0/24"], "bypass" => "c0de" }
    m = SiteGoose::Maintenance.new(core, skip: ->(path) { path == "/health" })
    status, headers, body = m.decide("203.0.113.5", "/", "", "")
    assert_equal [503, "600"], [status, headers["retry-after"]]
    assert_includes body, "&lt;b&gt;Soon&lt;/b&gt;"
    assert_nil m.decide("198.51.100.4", "/", "", "")
    assert_nil m.decide("203.0.113.5", "/health", "", "")
    passed = m.decide("203.0.113.5", "/", "a=1&site_preview=c0de", "")
    assert_equal :pass, passed[0]
    assert_includes passed[1]["set-cookie"], "site_preview=c0de; Path=/; Max-Age=86400; HttpOnly"
    assert_nil m.decide("203.0.113.5", "/", "", "x=1; site_preview=c0de")
    core.maintenance_given = { "on" => false }
    assert_nil m.decide("203.0.113.5", "/", "", "")
  end
end
