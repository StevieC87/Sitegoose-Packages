# frozen_string_literal: true

# The Rack middleware: what a request goes through, the route names Rails and
# Sinatra leave in the env, the errors they turn into an error page, and the
# headers and cookie it adds.

require_relative "test_helper"

class RackMiddlewareTest < Minitest::Test
  def platform(**on)
    made = quiet_platform(firewall: {}, errors: { spool_dir: false }, performance: {}, crawlers: {}, headers: {}, maintenance: {}, **on)
    made.firewall.rules = made.firewall.compile({ "v" => 1, "enabled" => true, "mode" => "block", "deny" => ["198.51.100.0/24"] })
    made
  end

  def test_the_site_answers_and_the_request_is_timed
    made = platform
    response = SiteGoose::Middleware.new(SITE, made).call(rack_env(path: "/orders/42"))
    assert_equal [200, "the site"], [response[0], body_of(response)]
    row = made.module("performance").rows.find { |k, _| k[2] == "/orders/:id" }
    assert_equal ["GET", 200], [row[0][1], row[0][3]]
  end

  def test_a_blocked_crawler_is_still_counted
    made = platform
    response = SiteGoose::Middleware.new(SITE, made).call(rack_env(remote: "198.51.100.9", user_agent: "GPTBot/1.2"))
    assert_equal 403, response[0]
    assert_equal [["GPTBot", "/pricing", 403]], made.module("crawlers").rows.keys.map { |k| k[1..3] }
  end

  # What the firewall reads off the env: the target in origin form, the
  # method a POST asks for, and Sec-Fetch-Site.
  def test_the_firewall_sees_the_request_as_the_app_routes_it
    made = platform
    made.firewall.rules = made.firewall.compile({ "v" => 1, "enabled" => true, "mode" => "block",
                                                  "probes" => { "exact" => ["/.env"], "ban" => 600 },
                                                  "requests" => { "rules" => [
                                                    { "id" => "admin", "action" => "block", "path" => { "prefix" => ["/admin"] } },
                                                    { "id" => "delete", "action" => "block", "methods" => ["DELETE"], "path" => { "prefix" => ["/api/"] } }
                                                  ] } })
    app = SiteGoose::Middleware.new(SITE, made)
    assert_equal 403, app.call(rack_env(path: "/admin").merge("REQUEST_URI" => "x:/admin"))[0]
    assert_equal 200, app.call(rack_env(method: "POST", path: "/api/users/1"))[0]
    assert_equal 403, app.call(rack_env(method: "POST", path: "/api/users/1", x_http_method_override: "DELETE"))[0]
    assert_equal 403, app.call(rack_env(method: "POST", path: "/api/users/1", query: "_method=delete"))[0]
    assert_equal 403, app.call(rack_env(path: "/.env", remote: "203.0.113.77", sec_fetch_site: "cross-site"))[0]
    assert_empty made.firewall.bans, "another site's request bans no one"
    assert_equal 403, app.call(rack_env(path: "/.env", remote: "203.0.113.77"))[0]
    assert_equal 1, made.firewall.bans.size
  end

  def test_rails_and_sinatra_route_names
    rails = { "action_dispatch.route_uri_pattern" => "/users/:id(.:format)" }
    assert_equal "/users/:id", SiteGoose.route_of(rails, "/users/7")
    assert_equal "/users/:id", SiteGoose.route_of({ "sinatra.route" => "GET /users/:id" }, "/users/7")
    older = { "action_dispatch.request.path_parameters" => { controller: "users", action: "show", id: "7", format: "json" } }
    assert_equal "/users/:id", SiteGoose.route_of(older, "/users/7.json")
    assert_equal "", SiteGoose.route_of({}, "/x")
  end

  def test_a_raised_error_is_sent_and_raised_on
    made = platform
    app = ->(_env) { raise ArgumentError, "boom" }
    assert_raises(ArgumentError) { SiteGoose::Middleware.new(app, made).call(rack_env(path: "/pay", x_analytics_session: "s1")) }
    event = made.errors.queue[0]
    assert_equal ["boom", 500, "error", "GET", "/pay", "s1"], event.values_at("message", "status_code", "kind", "method", "path", "session_id")
    assert(made.module("performance").rows.any? { |k, _| k[3] == 500 }, "timed as failed")
  end

  def test_an_error_page_rails_or_sinatra_made_is_still_sent
    made = platform
    app = lambda do |env|
      env["action_dispatch.route_uri_pattern"] = "/pay/:id(.:format)"
      env["action_dispatch.exception"] = ArgumentError.new("rendered as a 500")
      [500, {}, ["Something went wrong"]]
    end
    SiteGoose::Middleware.new(app, made).call(rack_env(path: "/pay/9"))
    not_found = lambda do |env|
      env["sinatra.error"] = KeyError.new("404s are not errors")
      [404, {}, ["no"]]
    end
    SiteGoose::Middleware.new(not_found, made).call(rack_env)
    assert_equal [["rendered as a 500", 500, "/pay/:id"]], made.errors.queue.map { |e| e.values_at("message", "status_code", "route") }
  end

  def test_an_error_captured_inside_the_request_keeps_its_route
    made = platform
    app = lambda do |env|
      env["sinatra.route"] = "POST /orders/:id"
      SiteGoose.platform = made
      made.add_breadcrumb("charging")
      made.capture_exception(ArgumentError.new("handled"))
      [200, {}, ["ok"]]
    end
    SiteGoose::Middleware.new(app, made).call(rack_env(method: "POST", path: "/orders/3"))
    event = made.errors.queue[0]
    assert_equal ["handled", "handled", "/orders/:id", "POST"], event.values_at("message", "kind", "route", "method")
    assert_equal "charging", event["breadcrumbs"][0]["text"]
  ensure
    SiteGoose.platform = nil
  end

  def test_security_headers_never_override_the_apps_own
    made = platform
    made.core.instance_variable_set(:@headers, [["X-Frame-Options", "DENY"], ["Referrer-Policy", "no-referrer"]])
    app = ->(_env) { [200, { "Referrer-Policy" => "origin" }.freeze, ["ok"]] }
    headers = SiteGoose::Middleware.new(app, made).call(rack_env)[1]
    assert_equal "DENY", headers["x-frame-options"]
    assert_equal "origin", headers["Referrer-Policy"]
    refute headers.key?("referrer-policy")
  end

  def test_maintenance_answers_and_the_preview_link_passes
    made = platform
    made.core.instance_variable_set(:@maintenance, { "on" => true, "bypass" => "c0de" })
    middleware = SiteGoose::Middleware.new(SITE, made)
    assert_equal 503, middleware.call(rack_env)[0]
    passed = middleware.call(rack_env(query: "site_preview=c0de"))
    assert_equal "the site", body_of(passed)
    assert_includes Array(passed[1]["set-cookie"]).join, "site_preview=c0de"
  end

  def test_the_proxy_answers_before_everything_else
    made = platform(proxy: {})
    made.core.instance_variable_set(:@valid, true)
    made.proxy.define_singleton_method(:handle) { |kind, rest, **| [202, { "Content-Type" => "application/json" }, "#{kind}:#{rest}"] }
    response = SiteGoose::Middleware.new(SITE, made).call(rack_env(path: made.proxy.collect_url, remote: "203.0.113.9"))
    assert_equal [202, "api:e"], [response[0], body_of(response)]
    assert_equal({ "content-type" => "application/json" }, response[1])
    assert_empty made.module("performance").rows
    denied = SiteGoose::Middleware.new(SITE, made).call(rack_env(path: made.proxy.collect_url, remote: "198.51.100.9"))
    assert_equal 403, denied[0], "a denied address gets nothing from the proxy either"
    assert_equal [["198.51.100.9", "deny"]], made.firewall.queue.values.map { |e| e.values_at("ip", "rule") }
  ensure
    made&.core&.instance_variable_set(:@valid, false)
  end

  def test_a_failure_of_ours_passes_the_request
    made = platform
    made.define_singleton_method(:rack_call) { |_env| raise "our bug" }
    assert_equal "the site", body_of(SiteGoose::Middleware.new(SITE, made).call(rack_env))
  end

  def test_without_a_platform_every_request_passes
    SiteGoose.reset
    assert_equal "the site", body_of(SiteGoose::Middleware.new(SITE).call(rack_env))
  end

  def test_jobs_are_timed_and_their_errors_sent
    made = platform
    assert_equal 3, made.job("nightly-import") { 3 }
    assert_raises(KeyError) { made.job("charge") { raise KeyError, "x" } }
    assert_raises(Interrupt) { made.job("stopped") { raise Interrupt } }
    routes = made.module("performance").rows.keys.map { |k| [k[1], k[2], k[3]] }.sort
    assert_equal [["JOB", "/(job) charge", 500], ["JOB", "/(job) nightly-import", 200]], routes
    assert_equal [["/(job) charge", "JOB"]], made.errors.queue.map { |e| e.values_at("route", "method") }
  end

  def test_the_global_configuration
    SiteGoose.reset
    SiteGoose.configure(site_id: "", secret: "s", endpoint: "", enabled: false)
    assert_nil SiteGoose.platform
    SiteGoose.reset
    SiteGoose.configure { |c| c.site_id = ""; c.secret = "s"; c.firewall = false; c.analytics = false }
    made = nil
    silence { made = SiteGoose.platform }
    refute_includes made.modules, "firewall"
    assert_equal "", SiteGoose.track("x")
  ensure
    SiteGoose.reset
  end
end
