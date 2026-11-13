# frozen_string_literal: true

module SiteGoose
  # Rack middleware: the proxy, the firewall and the browser check,
  # maintenance mode, then the app, timed, with its errors captured and the
  # dashboard's security headers added. Put it first.
  #
  #     use SiteGoose::Middleware                      # configured elsewhere (Rails, configure, ENV)
  #     use SiteGoose::Middleware, site_id: "...", secret: "...", endpoint: "..."
  #     use SiteGoose::Middleware, platform            # one you made: SiteGoose::Platform.new(...)
  #
  # Never breaks a request: when the package itself fails, the request goes
  # on to the app as if it weren't there.
  class Middleware
    def initialize(app, platform = nil, **options)
      @app = app
      @given = platform
      SiteGoose.configure(**options) unless options.empty?
    end

    def platform
      @given || SiteGoose.platform
    rescue StandardError
      nil
    end

    # Set on the env by the first copy: a second (the Railtie's and one added
    # by hand, or an engine's) passes the request straight on, so nothing is
    # checked, timed or reported twice.
    SEEN = "sitegoose.seen"

    def call(env)
      return @app.call(env) if env[SEEN]

      env[SEEN] = true
      made = platform
      return @app.call(env) if made.nil?

      reached = false
      made.rack_call(env) do
        reached = true
        @app.call(env)
      end
    rescue StandardError, ScriptError => e
      # The app's own errors are raised on; ours never reach the visitor.
      raise if reached

      made&.core&.log("middleware", "failed, request passed:", e.message)
      @app.call(env)
    end
  end
end
