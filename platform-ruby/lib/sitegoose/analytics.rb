# frozen_string_literal: true

# Analytics module: what only the server sees for sure (payments, sign-ups,
# plan changes), next to the browser tracker's visits. Not pageviews: the
# tracker counts those, and counting them here too would count them twice.
#
# - track(): events, batched to POST /events/server-events in the background.
#   Each gets an event_uid, so a retried batch can be told apart from new events.
# - identify(): links the browser's visit to your user ID (/events/identify),
#   with optional traits about the user (plan, seats...).
# - lead(): adds or updates a lead (/events/lead).
# identify() and lead() wait for the answer (up to 5 seconds).

require "securerandom"

module SiteGoose
  class Analytics
    BATCH = 100
    QUEUE_MAX = 1000
    FLUSH_EVERY = 2
    RETRY_EVERY = 15

    attr_reader :queue

    def initialize(core, **_)
      @core = core
      @queue = []
      @lock = Mutex.new
      @job = core.valid? ? Periodic.new(FLUSH_EVERY) { flush ? FLUSH_EVERY : RETRY_EVERY } : nil
      Forking.register(self)
    end

    def after_fork_in_child
      @lock = Mutex.new
      @queue = []
    end

    # name: the event's name; fields: value, numeric_value, currency, url,
    # event_label, variant, id, timestamp, event_uid, transaction_id, coupon
    # (expresscollect/docs/server-events.md). Returns the event_uid, or ""
    # when not queued.
    def track(name, fields = nil, session_id = "")
      return "" unless name.is_a?(String) && !name.empty? && @core.on?("analytics")

      fields = (fields || {}).each_with_object({}) { |(k, v), out| out[k.to_s] = v }
      event = { "timestamp" => SiteGoose.iso_now, "session_id" => session_id.to_s }
      event.merge!(fields)
      event["event_name"] = name[0, 100]
      event["event_uid"] = fields["event_uid"].to_s.empty? ? SecureRandom.uuid : fields["event_uid"].to_s
      event["numeric_value"] = event["numeric_value"].to_s if event["numeric_value"].is_a?(Numeric)
      full = @lock.synchronize do
        if @queue.size >= QUEUE_MAX
          @core.log("analytics", "queue full, event dropped")
          return ""
        end
        @queue << event
        @queue.size >= BATCH
      end
      @job&.run_now if full
      event["event_uid"]
    end

    # Sends what's waiting; false when some of it must be tried again.
    def flush
      waiting = @lock.synchronize do
        taken = @queue
        @queue = []
        taken
      end
      ok = true
      waiting.each_slice(BATCH) do |batch|
        res = @core.request("analytics", "/events/server-events", body: { "events" => batch })
        if res.nil? || res.status == 429 || res.status >= 500
          ok = false
          @lock.synchronize { @queue = (batch + @queue).first(QUEUE_MAX) }
        elsif !res.ok?
          @core.log("analytics", "events refused:", res.body.to_s[0, 300])
        end
      end
      ok
    end

    # Links the visit to your user ID. true when stored. traits: what you know
    # about the user, name => text, number or true/false
    # ({ plan: "pro", seats: 5 }); anything else is left out, and the
    # collector cleans the names and values.
    def identify(user_id, session_id = "", traits = nil)
      return false if user_id.to_s.empty? || session_id.to_s.empty? || !@core.on?("analytics")

      body = { "user_id" => user_id.to_s, "session_id" => session_id.to_s }
      kept = self.class.scalar_traits(traits)
      body["traits"] = kept unless kept.empty?
      res = @core.request("analytics", "/events/identify", body: body)
      res ? res.ok? : false
    end

    # The traits that are text (a symbol as its name), a finite number or
    # true/false, with their names as strings.
    def self.scalar_traits(traits)
      return {} unless traits.is_a?(Hash)

      traits.each_with_object({}) do |(name, value), kept|
        case value
        when String, Integer, true, false then kept[name.to_s] = value
        when Symbol then kept[name.to_s] = value.to_s
        when Float then kept[name.to_s] = value if value.finite?
        end
      end
    end

    # fields: email or phone, and name, status, tags, note, deal fields...
    # Returns {"status", "lead_id"}, or nil.
    def lead(fields, session_id = "")
      return nil unless @core.on?("analytics")

      body = { "session_id" => session_id.to_s }
      (fields || {}).each { |k, v| body[k.to_s] = v }
      res = @core.request("analytics", "/events/lead", body: body)
      return nil if res.nil?

      unless res.ok?
        @core.log("analytics", "lead refused:", res.body.to_s[0, 300])
        return nil
      end
      res.json
    end

    def close
      @job&.stop
      Forking.unregister(self)
      flush
    end
  end
end
