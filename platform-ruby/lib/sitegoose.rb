# frozen_string_literal: true

# One package for a site's Ruby server, run from the analytics dashboard:
# firewall, error monitoring and server analytics. Each module is separate:
# one failing never stops the others, and the firewall never waits on
# reporting. A loaded module can also be switched off in the dashboard
# (Security -> Server package).
#
#     # Rails: the Railtie puts the middleware first; config in an initializer.
#     SiteGoose.configure(site_id: "...", secret: ENV["ANALYTICS_SITE_SECRET"], endpoint: "https://...")
#
#     # Sinatra, Hanami, Roda, any Rack app:
#     use SiteGoose::Middleware, site_id: "...", secret: ENV["ANALYTICS_SITE_SECRET"], endpoint: "https://..."
#
# A module is on with true (or its options as a hash) and off with false.
# Standard library only, and rack; Ruby 3.0+.

require_relative "sitegoose/version"
require_relative "sitegoose/core"
require_relative "sitegoose/ip"
require_relative "sitegoose/challenge"
require_relative "sitegoose/request_rules"
require_relative "sitegoose/firewall"
require_relative "sitegoose/performance"
require_relative "sitegoose/errors"
require_relative "sitegoose/query_text"
require_relative "sitegoose/queries"
require_relative "sitegoose/calls"
require_relative "sitegoose/queues"
require_relative "sitegoose/crawlers"
require_relative "sitegoose/analytics"
require_relative "sitegoose/small_modules"
require_relative "sitegoose/inventory"
require_relative "sitegoose/posture"
require_relative "sitegoose/resources"
require_relative "sitegoose/proxy"
require_relative "sitegoose/platform"
require_relative "sitegoose/middleware"

module SiteGoose
  @lock = Mutex.new
  @options = nil
  @defaults = {}
  @platform = nil
  @created = []
  @created_lock = Mutex.new
  @when_made = []

  # The options a block sets: SiteGoose.configure { |c| c.site_id = "..." }.
  class Config
    def initialize(values = {})
      @values = SiteGoose.symbolize(values)
    end

    def to_h
      @values.dup
    end

    def [](key)
      @values[key.to_sym]
    end

    def []=(key, value)
      @values[key.to_sym] = value
    end

    def method_missing(name, *args)
      key = name.to_s
      if key.end_with?("=") && args.size == 1
        @values[key.chomp("=").to_sym] = args[0]
      elsif args.empty?
        @values[name]
      else
        super
      end
    end

    def respond_to_missing?(_name, _private = false)
      true
    end
  end

  class << self
    # Sets the options the platform is made from; it is made on first use
    # (the first request, job or call), so a Puma or Unicorn master that only
    # forks workers starts no threads of its own. Options already given (the
    # Rails config, credentials, the environment) are kept unless named again.
    def configure(**options)
      config = Config.new(options)
      yield config if block_given?
      @lock.synchronize do
        @options = (@options || {}).merge(config.to_h)
        if @platform
          warn "[analytics-platform] configure after the platform was made: the new options apply after SiteGoose.reset"
        end
      end
      nil
    end

    # Options under what configure() gives (the Railtie's, from the Rails
    # config and credentials), over the environment's.
    def defaults(**options)
      @lock.synchronize { @defaults = @defaults.merge(SiteGoose.symbolize(options)) }
      nil
    end

    # Runs the block with the platform once it is made (now, if it is).
    def when_made(&block)
      made = @lock.synchronize do
        @when_made << block
        @platform
      end
      block.call(made) if made
      nil
    end

    # Options from the environment, under what configure() gives.
    def env_options
      out = {}
      out[:site_id] = ENV["ANALYTICS_SITE_ID"] if ENV["ANALYTICS_SITE_ID"]
      out[:secret] = ENV["ANALYTICS_SITE_SECRET"] if ENV["ANALYTICS_SITE_SECRET"]
      endpoint = ENV["ANALYTICS_ENDPOINT"] || ENV["ANALYTICS_FIREWALL_ENDPOINT"]
      out[:endpoint] = endpoint if endpoint
      out[:server_name] = ENV["ANALYTICS_SERVER_NAME"] if ENV["ANALYTICS_SERVER_NAME"]
      trust = ENV["ANALYTICS_TRUST_PROXY"]
      out[:trust_proxy] = trust.match?(/\A\d+\z/) ? trust.to_i : trust if trust && !trust.empty?
      out
    end

    def options
      env_options.merge(@defaults).merge(@options || {})
    end

    def configured?
      !@options.nil? || !@defaults.empty? || !env_options.empty?
    end

    # The platform, made on first use from configure(), the Rails config and
    # credentials, and the environment; nil when nothing configures it, or
    # with enabled: false (the middleware then passes every request).
    def platform
      return @platform if @platform

      hooks = nil
      made = @lock.synchronize do
        return @platform if @platform
        return nil unless configured?

        given = options
        return nil if given.delete(:enabled) == false

        hooks = @when_made.dup
        @platform = Platform.new(**given)
      end
      hooks&.each do |hook|
        hook.call(made)
      rescue StandardError => e
        warn "[analytics-platform] #{e.class}: #{e.message}"
      end
      made
    end

    # Uses this platform as the one everything else reaches (tests, or a
    # platform you made yourself).
    def platform=(value)
      @lock.synchronize { @platform = value }
    end

    # Closes the platform and forgets it and its options.
    def reset
      made = @lock.synchronize do
        taken = @platform
        @platform = nil
        @options = nil
        @defaults = {}
        taken
      end
      made&.close
      nil
    end

    def created(platform)
      @created_lock.synchronize { @created << platform }
    end

    # At exit: the exception that is ending the program is sent, then every
    # platform sends what's waiting and stops its threads.
    # All of it within EXIT_DEADLINE seconds: a container's grace period is
    # longer than that, and what wasn't sent by then waits in the errors file.
    def at_exit_hook(error, seconds = EXIT_DEADLINE)
      platforms = @created_lock.synchronize { @created.dup }
      within(seconds) do
        platforms.each do |made|
          next if made.closed?

          made.errors&.capture_exit(error)
          made.close
        rescue StandardError
          nil
        end
      end
    end

    # ---- The platform's API, on the module ----

    def track(name, fields = nil, session_id: "")
      platform&.track(name, fields, session_id: session_id) || ""
    end

    def identify(user_id, session_id: "", traits: nil)
      platform ? platform.identify(user_id, session_id: session_id, traits: traits) : false
    end

    def lead(fields, session_id: "")
      platform&.lead(fields, session_id: session_id)
    end

    def capture_exception(error, request: nil, status: 0, kind: "handled")
      platform&.capture_exception(error, request: request, status: status, kind: kind)
    end

    def add_breadcrumb(text)
      platform&.add_breadcrumb(text)
    end

    def audit(action, actor: "", target: "", details: nil, request: nil)
      platform&.audit(action, actor: actor, target: target, details: details, request: request)
    end

    def enabled?(key, user: nil, default: false)
      made = platform
      made ? made.enabled?(key, user: user, default: default) : default
    end

    def check_form(request = nil, **options)
      made = platform
      made ? made.check_form(request, **options) : { ok: true, spam: false, reasons: [], checked: false }
    end

    def login_failed(request_or_ip)
      platform&.login_failed(request_or_ip)
    end

    def session_id(request)
      made = platform
      made ? made.session_id(request) : ""
    end

    def job(name, report: nil, &block)
      made = platform
      made ? made.job(name, report: report, &block) : yield
    end

    def flush
      @created_lock.synchronize { @created.dup }.each(&:flush)
      nil
    end
  end

  at_exit { SiteGoose.at_exit_hook($!) }
end

require_relative "sitegoose/railtie" if defined?(::Rails::Railtie)
# Faraday's middleware is registered when Faraday is already loaded; else
# require "sitegoose/faraday" after it.
require_relative "sitegoose/faraday" if defined?(::Faraday::Middleware)
