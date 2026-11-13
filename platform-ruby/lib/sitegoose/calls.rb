# frozen_string_literal: true

# Outgoing calls (sdk/protocols/calls.md), part of Server speed: per minute,
# request method and route, the host called and the call's own method, how
# many calls, how many failed, their total and slowest time and a count per
# time bucket, sent to POST /events/server-calls. Only the host is kept: a
# call's path, query string, headers and body never leave the server.
#
# Caught through public hooks only, never by patching a library:
#   Faraday: the SiteGoose::Faraday middleware, one line per connection
#     (require "sitegoose/faraday"; conn.request :sitegoose).
#   Anything else: SiteGoose.time_call("api.example.com") { ... }.
# Net::HTTP itself is left alone (nothing in it is a public hook).
#
# Filed like queries: under the request or job it ran in, else
# "JOB" "(background)". A call that got no answer or a 5xx counts as failed;
# a 4xx is the other side's answer. The package's own calls to the collector
# are left out, and so are a database client's own HTTP requests (the
# click_house gem's: they are its queries). Rides on the performance module:
# with Server speed off nothing is recorded; calls: false keeps Server speed
# without them.

require "uri"

module SiteGoose
  class Calls
    include MinuteRows
    FIELDS = %w[call_method host].freeze
    PATH = "/events/server-calls"
    MOD = "calls"
    REQUEST = Context::CALLS
    HOST = /\A[a-z0-9._\-\[\]:]{1,255}\z/.freeze
    CALL_METHOD = /\A[A-Z]{1,10}\z/.freeze
    # Set while time_call times a call, so a Faraday call inside it (a
    # vendor's client built on Faraday) isn't counted a second time.
    TIMING = :sitegoose_call_timing

    @open = []
    @lock = Mutex.new
    extend OpenList

    class << self
      def timing?
        Thread.current[TIMING] ? true : false
      end

      def timing
        saved = Thread.current[TIMING]
        Thread.current[TIMING] = true
        yield
      ensure
        Thread.current[TIMING] = saved
      end

      # One finished call, from any hook: target a URL (a URI or a string) or
      # a bare host ("api.example.com", "localhost:8080").
      def record(call_method, target, ms, failed: false)
        active&.record(call_method, target, ms, failed: failed)
      rescue StandardError
        nil
      end

      # A URI for target, or nil.
      def uri_of(target)
        return target if target.is_a?(URI::Generic)

        text = SiteGoose.text(target).strip
        return nil if text.empty?

        text = "https://#{text}" unless text.match?(%r{\A[a-zA-Z][a-zA-Z0-9+.-]*://})
        URI.parse(text)
      rescue URI::Error, ArgumentError
        nil
      end

      # The host as calls.md stores it: lower case, with its port only when
      # it isn't the scheme's own. "" when it isn't one.
      def host_of(target)
        uri = uri_of(target)
        return "" if uri.nil? || uri.host.nil? || uri.host.empty?

        host = uri.host.downcase
        host = "#{host}:#{uri.port}" if uri.port && uri.port != uri.default_port
        host.match?(HOST) ? host : ""
      rescue StandardError
        ""
      end

      # scheme://host[:port]/path, lower case and without a trailing slash,
      # to tell the package's own calls to the collector from the app's.
      def address_of(target)
        uri = uri_of(target)
        return "" if uri.nil? || uri.host.nil?

        port = uri.port && uri.port != uri.default_port ? ":#{uri.port}" : ""
        "#{uri.scheme.to_s.downcase}://#{uri.host.downcase}#{port}#{uri.path.to_s.sub(%r{/+\z}, '')}"
      rescue StandardError
        ""
      end

      # The status an HTTP library's error carries (Faraday's raise_error:
      # a 404 raised is still the other side's answer), or nil.
      def status_of_error(error)
        return error.response_status.to_i if error.respond_to?(:response_status) && error.response_status
        return nil unless error.respond_to?(:response)

        response = error.response
        status = response.is_a?(Hash) ? (response[:status] || response["status"]) : nil
        status&.to_i
      rescue StandardError
        nil
      end

      # Whether a call that ended with status failed: no answer, or a 5xx.
      def failed_status?(status)
        status = status.respond_to?(:to_i) ? status.to_i : 0
        !(status.positive? && status < 500)
      end
    end

    def initialize(core, server_name: nil)
      start_rows(core, server_name)
      @own = Calls.address_of(core.endpoint)
      Calls.opened(self)
    end

    # The package's own calls to the collector.
    def own?(target)
      return false if @own.empty?

      address = Calls.address_of(target)
      address == @own || address.start_with?("#{@own}/")
    end

    # One finished call: into its request's (or job's) calls, or, with none
    # around it, straight into the minute's rows as background.
    def record(call_method, target, ms, failed: false)
      return unless on?
      return if own?(target)

      host = Calls.host_of(target)
      call_method = SiteGoose.text(call_method.nil? ? "GET" : call_method).upcase
      return if host.empty? || !call_method.match?(CALL_METHOD)

      file(call_method, host, ms, failed)
    end

    def close
      Calls.closed(self)
      stop_rows
    end
  end

  # Times one outgoing call made by anything the Faraday middleware doesn't
  # see (Health -> Server speed -> Calls): target is the URL or host called.
  # The block's result is returned; a block that raises counts as a failed
  # call and the exception is raised on (a block left with return, break or
  # next is a call that ended). Only the host is kept.
  #
  #     SiteGoose.time_call("https://api.stripe.com", method: "POST") { stripe.charge(...) }
  def self.time_call(target, method: "GET")
    return yield if Calls.active.nil? || Queries.timing? || Calls.timing?

    started = clock
    failed = false
    begin
      Calls.timing { yield }
    rescue Exception # rubocop:disable Lint/RescueException -- raised on; a timeout is a call with no answer
      failed = true
      raise
    ensure
      Calls.record(method, target, (clock - started) * 1000, failed: failed)
    end
  end
end
