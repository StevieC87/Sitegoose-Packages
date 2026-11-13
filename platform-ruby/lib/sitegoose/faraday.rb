# frozen_string_literal: true

# Outgoing calls made through Faraday (sdk/protocols/calls.md), timed by a
# Faraday middleware: Faraday's own public extension point, so neither
# Faraday nor its adapter is changed. One line per connection:
#
#     require "sitegoose/faraday"
#     conn = Faraday.new(url: "https://api.stripe.com") do |f|
#       f.request :sitegoose        # first, so a retried call is timed once
#       ...
#     end
#     # or: conn.use SiteGoose::Faraday
#
# A call is timed from being handed to the adapter to Faraday handing the
# response back (with a parallel adapter, its on_complete). Faraday gives the
# answer over whole, so a body read with it is in the time; a body streamed
# with on_data is too. Only the host is kept (Calls).

require "faraday"
require_relative "../sitegoose" unless defined?(SiteGoose::Calls)

module SiteGoose
  class Faraday < ::Faraday::Middleware
    def call(env)
      return @app.call(env) if Calls.active.nil? || Queries.timing? || Calls.timing?

      started = SiteGoose.clock
      call_method = env.method.to_s.upcase
      url = env.url
      begin
        response = @app.call(env)
      rescue Exception => e # rubocop:disable Lint/RescueException -- raised on; a timeout around it is no answer
        # raise_error inside this middleware: a 4xx raised is still an answer.
        Calls.record(call_method, url, (SiteGoose.clock - started) * 1000,
                     failed: Calls.failed_status?(Calls.status_of_error(e)))
        raise
      end
      return response unless response.respond_to?(:on_complete)

      response.on_complete do |done|
        status = done.respond_to?(:status) ? done.status : nil
        Calls.record(call_method, url, (SiteGoose.clock - started) * 1000, failed: Calls.failed_status?(status))
      end
      response
    end
  end

  # f.request :sitegoose, f.use :sitegoose, f.response :sitegoose all name it.
  [::Faraday::Request, ::Faraday::Middleware, ::Faraday::Response].each do |registry|
    registry.register_middleware(sitegoose: SiteGoose::Faraday) if registry.respond_to?(:register_middleware)
  rescue StandardError
    nil
  end
end
