# frozen_string_literal: true

# Job queues (sdk/protocols/queues.md), part of Server speed: once a minute,
# one row per queue to POST /events/server-queues, for Health -> Server
# speed -> Jobs: how many jobs wait, run, are delayed and are kept as
# failed, how long the oldest waiting one has waited (gauges, read from the
# queue's readers), and how many jobs this process added and finished
# (its own counters, shared: false). Rides on the performance module's
# switch; queues: false leaves them out.
#
# A reader (SiteGoose::Sidekiq's) answers read with the gauges of every
# queue it can see; a reading that fails is a gap for that minute, never a
# zero. Counters are counted by the integration's middleware. Nothing runs
# until a reader or a counter is added.

require "securerandom"

module SiteGoose
  class Queues
    SAMPLE_EVERY = 60
    MAX_QUEUES = 100
    MAX_ROWS = 500
    SYSTEMS = %w[bullmq bull sidekiq laravel celery rq hangfire asynq rabbitmq other].freeze
    GAUGES = %w[waiting running delayed failed oldest_s].freeze

    attr_reader :sender, :entries

    def initialize(core, server_name: nil)
      @core = core
      @server_name = SiteGoose.text(server_name || SiteGoose.hostname, 100)
      # This process, so the collector can tell a reading resent after a
      # failed answer from another process's on the same machine.
      @sender = SecureRandom.hex(8)
      # [system, broker, queue] -> { added:, finished:, counts: [:added, :finished] }
      @entries = {}
      @readers = []
      @lock = Mutex.new
      @job = nil
      Forking.register(self)
    end

    def on?
      @core.on?("performance")
    end

    # Reads this reader's queues once a minute from now on.
    def watch(reader)
      @lock.synchronize { @readers << reader unless @readers.include?(reader) }
      start
      reader
    end

    # One job added to (kind :added) or finished from (:finished) a queue by
    # this process. A queue past MAX_QUEUES isn't counted.
    def count(system, broker, queue, kind)
      return unless on?

      @lock.synchronize do
        entry = entry_for(system, broker, queue)
        next unless entry

        entry[:counts] |= [kind]
        entry[kind] += 1
      end
      start
    end

    # This process counts kind for the queue even in a minute with none
    # (a Sidekiq process its queues' finished jobs): 0, not unknown.
    def counting(system, broker, queue, kind)
      @lock.synchronize do
        entry = entry_for(system, broker, queue)
        entry[:counts] |= [kind] if entry
      end
      start
    end

    # [system, broker, queue] as sent.
    def self.key(system, broker, queue)
      [SYSTEMS.include?(system.to_s) ? system.to_s : "other", SiteGoose.text(broker, 200), SiteGoose.text(queue, 200)]
    end

    # Under @lock.
    def entry_for(system, broker, queue)
      key = Queues.key(system, broker, queue)
      found = @entries[key]
      return found if found
      return nil if @entries.size >= MAX_QUEUES

      @entries[key] = { added: 0, finished: 0, counts: [] }
    end
    private :entry_for

    # One reading of every queue: a row each, sent at once. -> the rows.
    def sample
      return [] unless on?

      readers = @lock.synchronize { @readers.dup }
      gauges = {}
      readers.each do |reader|
        # The package's own Redis commands: not timed as the app's.
        Array(Queries.own { reader.read }).each do |reading|
          gauges[Queues.key(reading[:system], reading[:broker], reading[:queue])] = reading
        end
      rescue StandardError => e
        # A gap for this minute, never zeros.
        @core.log("queues", "could not read the queues:", e.message)
      end
      minute = Time.at(MinuteRows.minute).utc.iso8601(3)
      rows = @lock.synchronize do
        gauges.each_key { |key| entry_for(*key) }
        @entries.filter_map do |key, entry|
          reading = gauges[key]
          take_row(minute, key, entry, reading) if reading || !entry[:counts].empty?
        end
      end
      send_rows(rows)
      rows
    end

    # Under @lock: the queue's row, its gauges from reading (nil: unknown),
    # and the counts since the last row, which start again from 0.
    def take_row(minute, key, entry, reading)
      row = { "minute" => minute, "system" => key[0], "broker" => key[1], "queue" => key[2] }
      GAUGES.each { |name| row[name] = Queues.gauge(reading && reading[name.to_sym]) }
      row["added"] = entry[:counts].include?(:added) ? entry[:added] : nil
      row["finished"] = entry[:counts].include?(:finished) ? entry[:finished] : nil
      row["shared"] = false
      entry[:added] = 0
      entry[:finished] = 0
      row
    end
    private :take_row

    # A whole count, or nil for one the system couldn't give.
    def self.gauge(value)
      return nil unless value.is_a?(Numeric) && value.finite?

      [value.round, 0].max
    end

    def send_rows(rows)
      rows.each_slice(MAX_ROWS) do |batch|
        @core.request("queues", "/events/server-queues", auth: :bearer,
                      body: { "site_id" => @core.site_id, "server_name" => @server_name, "runtime" => RUNTIME,
                              "sender" => @sender, "rows" => batch })
      end
    end
    private :send_rows

    # What was counted since the last reading (Sidekiq's shutdown, exit):
    # counter rows only, no gauges.
    def flush
      return unless on?

      minute = Time.at(MinuteRows.minute).utc.iso8601(3)
      rows = @lock.synchronize do
        @entries.filter_map do |key, entry|
          take_row(minute, key, entry, nil) unless entry[:added].zero? && entry[:finished].zero?
        end
      end
      send_rows(rows)
    end

    def start
      return if @job || !@core.valid?

      @lock.synchronize do
        @job ||= Periodic.new(SAMPLE_EVERY) do
          sample
          SAMPLE_EVERY
        end
      end
    end
    private :start

    # A forked worker is another process: its own sender and counts.
    def after_fork_in_child
      @lock = Mutex.new
      @sender = SecureRandom.hex(8)
      @entries.each_value do |entry|
        entry[:added] = 0
        entry[:finished] = 0
      end
    end

    def close
      @job&.stop
      Forking.unregister(self)
      flush
    end
  end
end
