# frozen_string_literal: true

require_relative "test_helper"

# With the keys in the environment and nothing else: Rails (its Railtie adds
# the middleware) and a bare `use SiteGoose::Middleware` need no options.
class EnvTest < Minitest::Test
  KEYS = {
    "ANALYTICS_SITE_ID" => "a" * 24, "ANALYTICS_SITE_SECRET" => "s3cret", "ANALYTICS_ENDPOINT" => "http://127.0.0.1:9",
  }.freeze
  OFF = %i[firewall errors analytics performance crawlers forms headers audit flags maintenance inventory posture
           resources proxy].to_h { |name| [name, false] }.freeze

  def with_env(values)
    saved = ENV.to_h
    ENV.update(values)
    yield
  ensure
    ENV.replace(saved)
    SiteGoose.reset
  end

  def test_the_environment_alone_makes_the_platform
    with_env(KEYS) do
      SiteGoose.defaults(**OFF)
      platform = SiteGoose.platform
      refute_nil platform
      assert platform.core.valid?
    end
  end

  def test_a_bare_middleware_uses_it_and_lets_a_request_through
    with_env(KEYS) do
      SiteGoose.defaults(**OFF)
      app = SiteGoose::Middleware.new(->(_env) { [200, { "content-type" => "text/plain" }, ["ok"]] })
      status, = app.call(rack_env(path: "/"))
      assert_equal 200, status
      assert SiteGoose.platform.core.valid?
    end
  end
end
