# frozen_string_literal: true

# How the machine is doing (protocol in sdk/protocols/resources.md).
#
# CPU, load, memory, swap and disks, sampled every minute and sent to
# POST /events/resources every few minutes. The companion of the performance
# module: that says how the requests went, this says whether the box can
# still serve them.
#
# Nothing is guessed. A reading this machine won't give us is left out of the
# row, never sent as a zero: the collector stores it as NULL and the dashboard
# shows "-", because "0% CPU" and "we couldn't measure CPU" are different
# statements and only one of them means healthy.
#
# Linux's /proc for everything but the disks. Ruby's standard library has no
# statvfs, so the disks come from `df -kP` and `df -iP` (POSIX output, the
# same statvfs figures: used is total minus free, and total is used plus what
# is available to us, which is the percentage df prints); without df, the
# disks are left out.
#
# Beside them, the limits pass (Limits, below): the container's memory and
# CPU caps, throttling and kills, the machine's waiting time (PSI), refused
# connections, the connection-tracking table, open files, garbage collection,
# Puma's thread pool and the most requests in progress at once. Ruby has no
# heap cap, so heap_used_mb / heap_max_mb are never sent.

require "etc"
require "io/wait"
require "securerandom"

module SiteGoose
  # How close the app is to a wall (resources.md, "Limits"): its
  # container's own caps, the machine's waiting time, connections refused
  # before the app saw them, the process's open files and garbage
  # collection, and Puma's thread pool. A port of the Node package's
  # lib/limits.js. Same rule as the rest of the module: a figure this
  # machine won't give is left out, never sent as 0; every reader here gets
  # nil from a file that isn't there, which off Linux is all of them.
  module Limits
    MB = 1024 * 1024
    # cgroup v1 says "no limit" with the largest page-aligned 64-bit number;
    # v2 says "max". Anything this size is not a cap a machine has.
    NO_LIMIT_BYTES = 2**62
    NUMBER = /\A-?\d+(?:\.\d+)?\z/.freeze
    READ = ->(path) { Resources.read_text(path) }

    module_function

    # A number from a file holding one, or nil for a missing or unreadable one.
    def num(text)
      trimmed = text.to_s.strip
      return nil unless trimmed.match?(NUMBER)

      trimmed.include?(".") ? trimmed.to_f : trimmed.to_i
    end

    # "name value" lines (memory.stat, cpu.stat, memory.events) as numbers.
    def key_values(text)
      text.to_s.each_line.with_object({}) do |line, out|
        name, value = line.strip.split(/\s+/)
        n = num(value)
        out[name] = n if name && n
      end
    end

    # /proc/self/cgroup: the v2 path ("0::<path>") and the v1 memory and cpu
    # controllers' paths ("4:memory:<path>", "3:cpu,cpuacct:<path>").
    def cgroup_paths(text)
      out = { v2: nil, memory: nil, cpu: nil }
      text.to_s.each_line do |line|
        id, controllers, at = line.chomp.split(":", 3)
        next if at.nil?

        at = at.strip
        next if at.empty?

        names = controllers.split(",")
        out[:v2] = at if id == "0" && names.empty?
        out[:memory] = at if names.include?("memory")
        out[:cpu] = at if names.include?("cpu")
      end
      out
    end

    # Where this process's cgroup files are, or nil. Under the mount at the
    # path /proc/self/cgroup names first, then the mount itself: in a
    # container with its own cgroup namespace the path is "/" and the mount
    # is already the container's; without one the path names the host's
    # hierarchy. v2 needs the memory or cpu controller's own files: a hybrid
    # machine lists a v2 path with no controllers while the limits live in v1.
    def find_cgroup(read = READ)
      paths = cgroup_paths(read.call("/proc/self/cgroup"))
      under = lambda do |base, at, probes|
        dirs = at && at != "/" ? [base + at, base] : [base]
        dirs.find { |dir| probes.any? { |probe| !read.call("#{dir}/#{probe}").empty? } }
      end
      if paths[:v2]
        dir = under.call("/sys/fs/cgroup", paths[:v2], %w[memory.current cpu.max])
        return { version: 2, memory: dir, cpu: dir } if dir
      end
      memory = paths[:memory] && under.call("/sys/fs/cgroup/memory", paths[:memory], %w[memory.usage_in_bytes])
      cpu = paths[:cpu] && under.call("/sys/fs/cgroup/cpu", paths[:cpu], %w[cpu.cfs_quota_us])
      memory || cpu ? { version: 1, memory: memory, cpu: cpu } : nil
    end

    # One reading of the cgroup's caps and counters, in bytes and raw counts.
    def cgroup_reading(cgroup, read = READ)
      return nil unless cgroup

      out = { mem_cap: nil, mem_used: nil, cpu_cores: nil, periods: nil, throttled: nil, oom: nil }
      if cgroup[:version] == 2
        max = read.call("#{cgroup[:memory]}/memory.max").strip
        out[:mem_cap] = max == "max" ? nil : num(max)
        current = num(read.call("#{cgroup[:memory]}/memory.current"))
        # The working set: page cache counts against the cgroup too, so
        # memory.current sits near the cap on a healthy container that reads
        # files. Less inactive_file is what Docker and the kubelet report.
        stat = key_values(read.call("#{cgroup[:memory]}/memory.stat"))
        out[:mem_used] = [0, current - (stat["inactive_file"] || 0)].max if current
        out[:oom] = key_values(read.call("#{cgroup[:memory]}/memory.events"))["oom_kill"]
        quota, period = read.call("#{cgroup[:cpu]}/cpu.max").strip.split(/\s+/)
        quota_n = num(quota)
        period_n = num(period)
        out[:cpu_cores] = quota_n.to_f / period_n if quota != "max" && quota_n&.positive? && period_n&.positive?
        cpu = key_values(read.call("#{cgroup[:cpu]}/cpu.stat"))
        out[:periods] = cpu["nr_periods"]
        out[:throttled] = cpu["nr_throttled"]
        return out
      end
      if cgroup[:memory]
        out[:mem_cap] = num(read.call("#{cgroup[:memory]}/memory.limit_in_bytes"))
        usage = num(read.call("#{cgroup[:memory]}/memory.usage_in_bytes"))
        stat = key_values(read.call("#{cgroup[:memory]}/memory.stat"))
        out[:mem_used] = [0, usage - (stat["total_inactive_file"] || 0)].max if usage
        # Kernels from 4.13 carry the count here.
        out[:oom] = key_values(read.call("#{cgroup[:memory]}/memory.oom_control"))["oom_kill"]
      end
      if cgroup[:cpu]
        quota = num(read.call("#{cgroup[:cpu]}/cpu.cfs_quota_us"))
        period = num(read.call("#{cgroup[:cpu]}/cpu.cfs_period_us"))
        out[:cpu_cores] = quota.to_f / period if quota&.positive? && period&.positive?
        cpu = key_values(read.call("#{cgroup[:cpu]}/cpu.stat"))
        out[:periods] = cpu["nr_periods"]
        out[:throttled] = cpu["nr_throttled"]
      end
      out
    end

    # How much a counter moved between two readings, or nil: no pair, or it
    # went down (a reset, not a negative count). Unlike a rate, a count is
    # never dropped for the pair being far apart: a kill is a kill.
    def count_since(before, after)
      return nil if before.nil? || after.nil?

      after >= before ? after - before : nil
    end

    # The row's cgroup fields from two readings. A cap at or above what the
    # machine itself has isn't one, so neither half is sent.
    def cgroup_fields(before, after, mem_total_mb: nil, cores: nil)
      out = {}
      return out unless after

      cap = after[:mem_cap]
      cap_mb = cap&.positive? && cap < NO_LIMIT_BYTES ? cap / MB : nil
      if cap_mb&.positive? && !(mem_total_mb && cap_mb >= mem_total_mb) && after[:mem_used]
        out["limit_mem_mb"] = cap_mb
        out["limit_mem_used_mb"] = [cap_mb, after[:mem_used] / MB].min
      end
      cores_cap = after[:cpu_cores]
      out["limit_cpu_cores"] = cores_cap.round(2) if cores_cap && !(cores && cores_cap >= cores)
      # Periods only pass while a quota is set, so no cap means nothing sent.
      periods = count_since(before && before[:periods], after[:periods])
      throttled = count_since(before && before[:throttled], after[:throttled])
      out["cpu_throttled_pct"] = [100.0, 100.0 * throttled / periods].min.round(1) if periods&.positive? && throttled
      # Kills of other processes in this cgroup: this process's own kill
      # can't be reported by it (see the protocol).
      oom = count_since(before && before[:oom], after[:oom])
      out["oom_kills"] = oom if oom
      out
    end

    # /proc/pressure/<resource>'s "some" line, avg60: the share of the last
    # minute in which at least one task was waiting. One reading is enough.
    def pressure_some(text)
      match = /^some\b[^\n]*\bavg60=([\d.]+)/.match(text.to_s)
      match ? [100.0, match[1].to_f].min.round(1) : nil
    end

    def pressure_fields(read = READ)
      { "psi_cpu_pct" => "cpu", "psi_mem_pct" => "memory", "psi_io_pct" => "io" }.each_with_object({}) do |(name, file), out|
        value = pressure_some(read.call("/proc/pressure/#{file}"))
        out[name] = value if value
      end
    end

    # TcpExt ListenOverflows from /proc/net/netstat: connections refused
    # since boot because the accept queue was full. A header and a value line.
    def listen_overflows(text)
      lines = text.to_s.split("\n")
      lines.each_cons(2) do |names, values|
        next unless names.start_with?("TcpExt:") && values.start_with?("TcpExt:")

        at = names.strip.split(/\s+/).index("ListenOverflows")
        return at&.positive? ? num(values.strip.split(/\s+/)[at]) : nil
      end
      nil
    end

    # How full the connection-tracking table is. Only where the firewall
    # loaded it, and usually unreadable inside a container.
    def conntrack_pct(read = READ)
      count = num(read.call("/proc/sys/net/netfilter/nf_conntrack_count"))
      max = num(read.call("/proc/sys/net/netfilter/nf_conntrack_max"))
      count && max&.positive? ? [100.0, 100.0 * count / max].min.round(1) : nil
    end

    # The soft "Max open files" from /proc/self/limits, or nil when unlimited.
    def fd_limit(text)
      match = /^Max open files\s+(\S+)/.match(text.to_s)
      match ? num(match[1]) : nil
    end

    # Open descriptors of this process, less the one listing them takes.
    def open_files(list = -> { Dir.children("/proc/self/fd") })
      [0, list.call.size - 1].max
    rescue StandardError
      nil
    end

    def file_fields(read = READ, list = nil)
      out = {}
      used = list ? open_files(list) : open_files
      max = fd_limit(read.call("/proc/self/limits"))
      out["fds_used"] = max&.positive? ? [used, max].min : used if used
      out["fds_max"] = max if max&.positive?
      out
    end

    # Milliseconds spent in garbage collection since the process started
    # (GC.stat(:time), Ruby 3.1+), or nil where Ruby doesn't keep it.
    def gc_total_ms
      value = GC.stat(:time)
      value.is_a?(Numeric) ? value : nil
    rescue StandardError
      nil
    end

    # How long this process has run, from /proc/self/stat's start time
    # (clock ticks after boot) and the machine's uptime, or nil.
    def proc_uptime(stat_text, uptime_text, ticks)
      rest = stat_text.to_s.rpartition(")")[2].split
      start = num(rest[19])
      up = num(uptime_text.to_s.split.first)
      return nil unless start && up && ticks.to_i.positive?

      seconds = (up - start.to_f / ticks.to_i).floor
      seconds.negative? ? nil : seconds
    end

    def clock_ticks
      Etc.sysconf(Etc::SC_CLK_TCK)
    rescue StandardError
      nil
    end

    # Puma's thread pool: Puma::Server#stats (or Puma.stats_hash in single
    # mode). Busy is the pool's threads less what it could still take on;
    # max_threads is a real cap, so it is sent.
    def puma_fields(stats)
      return {} unless stats.is_a?(Hash)

      get = ->(name) { stats[name] || stats[name.to_s] }
      max = get.call(:max_threads)
      return {} unless max.is_a?(Integer) && max.positive?

      out = { "workers_max" => max }
      capacity = get.call(:pool_capacity)
      out["workers_busy"] = (max - capacity).clamp(0, max) if capacity.is_a?(Integer)
      backlog = get.call(:backlog)
      out["queue_waiting"] = backlog if backlog.is_a?(Integer) && !backlog.negative?
      out
    end
  end

  class Resources
    # Keep in step with the collector (expresscollect/Analytics/resources.js) and
    # the agent (sdk/vps-agent).
    SAMPLE_EVERY = 60
    EVERY = 5 * 60
    RETRY_EVERY = 60
    OFF_EVERY = 600
    MAX_ROWS = 500
    MAX_DISKS = 20
    MIN_DISK_MB = 1024
    MIN_CPU_SECONDS = 1.0
    FSTYPES = %w[ext2 ext3 ext4 xfs btrfs zfs f2fs jfs reiserfs ufs vfat exfat ntfs ntfs3 overlay apfs hfs].freeze
    MB = 1024 * 1024
    IO_SECTOR = 512
    IO_MAX_PAIR_SECONDS = 300
    IO_NOT_A_DISK = /\A(?:loop|ram|zram|sr|fd|dm-|md\d)/.freeze
    IO_PARTITION = /\A(?:(?:sd|vd|xvd|hd)[a-z]+\d+|(?:nvme\d+n\d+|mmcblk\d+)p\d+)\z/.freeze
    NET_NOT_REAL = /\A(?:lo|veth|docker|br-|virbr|tap|tun|vnet)/.freeze
    CPU_SHARES = [
      ["cpu_user_pct", [0, 1]],
      ["cpu_system_pct", [2]],
      ["cpu_iowait_pct", [4]],
      ["cpu_steal_pct", [7]]
    ].freeze
    DF_TIMEOUT = 5

    class << self
      def read_text(path, limit = 65_536)
        File.open(path, "rb") { |f| SiteGoose.text(f.read(limit).to_s) }
      rescue SystemCallError, IOError
        ""
      end

      # The jiffie counters from /proc/stat's first line, or nil.
      # In order: user, nice, system, idle, iowait, irq, softirq, steal.
      def cpu_fields(text)
        text.each_line do |line|
          next unless line.start_with?("cpu ")

          fields = line.split[1..]
          return nil unless fields.all? { |f| f.match?(/\A\d+\z/) }

          fields = fields.map(&:to_i)
          return fields.size >= 4 ? fields : nil
        end
        nil
      end

      # guest and guest_nice (columns 9 and 10) are already inside user and nice.
      def cpu_total(fields)
        fields.first(8).sum
      end

      def cpu_times_of(fields)
        total = cpu_total(fields)
        idle = fields[3] + (fields.size > 4 ? fields[4] : 0)
        [total - idle, total]
      end

      def cpu_shares(before, after)
        return {} if before.nil? || after.nil?

        total = cpu_total(after) - cpu_total(before)
        return {} if total <= 0

        out = {}
        CPU_SHARES.each do |name, columns|
          next if columns.any? { |i| i >= before.size || i >= after.size }

          moved = columns.sum { |i| after[i] - before[i] }
          return {} if moved.negative?

          out[name] = [100.0, 100.0 * moved / total].min.round(1)
        end
        out
      end

      def disk_counters(text)
        read = written = 0
        found = false
        text.each_line do |line|
          fields = line.split
          next if fields.size < 10

          name = fields[2]
          next if name.match?(IO_NOT_A_DISK) || name.match?(IO_PARTITION)
          next unless fields[5].match?(/\A\d+\z/) && fields[9].match?(/\A\d+\z/)

          read += fields[5].to_i * IO_SECTOR
          written += fields[9].to_i * IO_SECTOR
          found = true
        end
        found ? [read, written] : nil
      end

      def net_counters(text)
        rx = tx = 0
        found = false
        text.each_line do |line|
          next unless line.include?(":")

          name, rest = line.split(":", 2)
          name = name.strip
          next if name.empty? || name.match?(NET_NOT_REAL)

          fields = rest.split
          next if fields.size < 9 || !fields[0].match?(/\A\d+\z/) || !fields[8].match?(/\A\d+\z/)

          rx += fields[0].to_i
          tx += fields[8].to_i
          found = true
        end
        found ? [rx, tx] : nil
      end

      def rate_mbs(before, after, seconds)
        return nil if before.nil? || after.nil?
        return nil if seconds <= 0 || seconds > IO_MAX_PAIR_SECONDS

        moved = after - before
        return nil if moved.negative?

        (moved.to_f / seconds / MB).round(1)
      end

      def cpu_percent(before, after)
        return nil if before.nil? || after.nil?

        busy = after[0] - before[0]
        total = after[1] - before[1]
        return nil if total <= 0 || busy.negative?

        [100.0, 100.0 * busy / total].min.round(1)
      end

      # Used is total - MemAvailable, never total - MemFree: page cache is not pressure.
      def memory_mb(text)
        values = {}
        text.each_line do |line|
          name, _, rest = line.partition(":")
          first = rest.split.first
          values[name] = first.to_i / 1024 if first&.match?(/\A\d+\z/)
        end
        out = {}
        if values.key?("MemTotal")
          out["mem_total_mb"] = values["MemTotal"]
          out["mem_used_mb"] = [0, values["MemTotal"] - values["MemAvailable"]].max if values.key?("MemAvailable")
        end
        if values.key?("SwapTotal")
          out["swap_total_mb"] = values["SwapTotal"]
          out["swap_used_mb"] = [0, values["SwapTotal"] - values["SwapFree"]].max if values.key?("SwapFree")
        end
        out
      end

      # The real disks behind /proc/mounts, one per device under its shortest
      # mount point, so a bind mount isn't reported as a second disk; a mount
      # that isn't a directory (Docker bind-mounts /etc/hosts) doesn't win.
      # Off Linux, the one filesystem we can name without guessing: "/".
      def mount_points(mounts_text, is_dir = nil)
        return ["/"] if mounts_text.to_s.empty?

        is_dir ||= ->(path) { File.directory?(path) }
        dirs = {}
        any = {}
        mounts_text.each_line do |line|
          fields = line.split
          next if fields.size < 3

          device = fields[0]
          mount = fields[1].gsub("\\040", " ")
          next unless FSTYPES.include?(fields[2]) && mount.start_with?("/")

          any[device] = mount if !any.key?(device) || mount.size < any[device].size
          confirmed = begin
            is_dir.call(mount)
          rescue StandardError
            false
          end
          dirs[device] = mount if confirmed && (!dirs.key?(device) || mount.size < dirs[device].size)
        end
        any.map { |device, mount| dirs[device] || mount }.uniq.sort
      end

      # df's POSIX output: "<fs> <total> <used> <available> <capacity> <mount>",
      # in 1024-byte blocks (-k) or inodes (-i), by mount point.
      def parse_df(text)
        out = {}
        text.to_s.each_line.drop(1).each do |line|
          m = /\A\S+\s+(\d+)\s+(\d+)\s+(\d+)\s+\S+\s+(.+?)\s*\z/.match(line)
          out[m[4]] = [m[1].to_i, m[2].to_i, m[3].to_i] if m
        end
        out
      end

      def run(argv, timeout = DF_TIMEOUT)
        reader, writer = IO.pipe
        pid = Process.spawn(*argv, out: writer, err: File::NULL, in: File::NULL)
        writer.close
        output = +""
        deadline = SiteGoose.clock + timeout
        loop do
          left = deadline - SiteGoose.clock
          break if left <= 0 || !reader.wait_readable(left)

          chunk = reader.read_nonblock(65_536, exception: false)
          break if chunk.nil?

          output << chunk unless chunk == :wait_readable
        end
        begin
          Process.kill("KILL", pid) if Process.waitpid(pid, Process::WNOHANG).nil?
        rescue SystemCallError
          nil
        end
        begin
          Process.waitpid(pid)
        rescue SystemCallError
          nil
        end
        output
      rescue StandardError
        ""
      ensure
        reader&.close unless reader&.closed?
        writer&.close unless writer&.closed?
      end

      def df(points)
        return [{}, {}] if points.empty?

        [parse_df(run(["df", "-kP", *points])), parse_df(run(["df", "-iP", *points]))]
      end

      # Both figures are df's own, so a customer can check them. One
      # filesystem behind two devices (a container's overlay and the host disk
      # bind-mounted into it) reports the same sizes, so a repeat is dropped.
      def disk_rows(points, blocks = nil, inodes = nil)
        blocks, inodes = df(points) if blocks.nil?
        seen = {}
        rows = []
        points.each do |mount|
          figures = blocks[mount]
          next unless figures

          _, used_kb, avail_kb = figures
          used = used_kb * 1024
          total = used + avail_kb * 1024
          next if total.zero?

          row = { "mount" => mount, "total_mb" => total / MB, "used_mb" => used / MB }
          next if row["total_mb"] < MIN_DISK_MB
          next if seen[[total, used]]

          seen[[total, used]] = true
          # A filesystem can refuse a write with gigabytes free once these meet.
          files = inodes && inodes[mount]
          if files && files[0].positive?
            row["inodes_total"] = files[0]
            row["inodes_used"] = files[1]
          end
          rows << row
          break if rows.size >= MAX_DISKS
        end
        rows
      end

      def host_uptime(text)
        first = text.to_s.split.first
        first&.match?(/\A\d+(\.\d+)?\z/) ? first.to_f.to_i : nil
      end

      def load_average(text)
        parts = text.to_s.split
        return {} if parts.size < 3 || !parts.first(3).all? { |p| p.match?(/\A\d+(\.\d+)?\z/) }

        { "load1" => parts[0].to_f.round(2), "load5" => parts[1].to_f.round(2), "load15" => parts[2].to_f.round(2) }
      end

      # This package runs inside the application, so unlike the agent it can
      # honestly report the application's own memory.
      def process_rss_mb(text)
        text.each_line do |line|
          next unless line.start_with?("VmRSS:")

          kb = line.split[1]
          return kb&.match?(/\A\d+\z/) ? [1, kb.to_i / 1024].max : nil
        end
        nil
      end
    end

    attr_reader :rows, :every, :enabled

    # Options: server_name (the server's name as the dashboard shows it).
    def initialize(core, server_name: nil, **_)
      @core = core
      @server_name = SiteGoose.text(server_name.nil? ? SiteGoose.hostname : server_name, 100)
      # minute (ISO) -> row, so a minute sampled twice is kept once.
      @rows = {}
      @lock = Mutex.new
      @every = EVERY
      @enabled = true
      @last_cpu = Resources.cpu_fields(Resources.read_text("/proc/stat"))
      @last_disk = Resources.disk_counters(Resources.read_text("/proc/diskstats"))
      @last_net = Resources.net_counters(Resources.read_text("/proc/net/dev"))
      @last_at = Time.now.to_f
      # The limits pass: the cgroup is found once, its counters, the listen
      # queue's and garbage collection's are read every sample and diffed.
      @cgroup = Limits.find_cgroup
      limits_baseline
      # Requests in progress at once, from the performance module (the
      # platform wires it); nil until then.
      @inflight = nil
      @puma = nil
      @server_seen = false
      new_process
      @sampler = core.valid? ? Periodic.new(SAMPLE_EVERY) { sample; SAMPLE_EVERY } : nil
      @job = core.valid? ? Periodic.new(EVERY) { report } : nil
      Forking.register(self)
    end

    def after_fork_in_child
      @lock = Mutex.new
      @rows = {}
      @puma = nil
      @server_seen = false
      new_process
      # The parent counts what happened before the fork: the child's first
      # differences start here, not at the parent's last sample.
      limits_baseline
    end

    # The first readings the limits pass's counts are differences from.
    def limits_baseline
      @last_cgroup = Limits.cgroup_reading(@cgroup)
      @last_overflows = Limits.listen_overflows(Resources.read_text("/proc/net/netstat"))
      @last_gc = Limits.gc_total_ms
    end
    private :limits_baseline

    # This process among others of the same name (Puma's workers each send
    # their own), so a read can tell siblings from resent copies.
    def new_process
      @proc_key = SecureRandom.hex(6)
      @started = SiteGoose.clock
    end
    private :new_process

    attr_reader :proc_key

    # callable -> the most requests in progress at once since it was last
    # asked (Performance#take_inflight_peak), or nil.
    def use_inflight(callable)
      @inflight = callable.respond_to?(:call) ? callable : nil
    end

    def server_seen?
      @server_seen
    end

    # From a request's thread, once: the Puma server running it, whose
    # thread pool the samples read (Puma::Server.current, public).
    def see_server
      @server_seen = true
      @puma = ::Puma::Server.current if defined?(::Puma::Server) && ::Puma::Server.respond_to?(:current)
    rescue StandardError
      @puma = nil
    end

    # Puma's pool now: this process's own server, else Puma's stats in
    # single mode (a cluster's master stats are its workers', not ours).
    def puma_stats
      return @puma.stats if @puma.respond_to?(:stats)
      return nil unless defined?(::Puma) && ::Puma.respond_to?(:stats_hash)

      stats = ::Puma.stats_hash
      stats.is_a?(Hash) && (stats.key?(:max_threads) || stats.key?("max_threads")) ? stats : nil
    rescue StandardError
      nil
    end

    # The limits pass for one sample: caps and counters diffed against the
    # previous sample's, the rest read once.
    def limits_row(row)
      out = {}
      uptime = Limits.proc_uptime(Resources.read_text("/proc/self/stat"), Resources.read_text("/proc/uptime"), Limits.clock_ticks)
      out["proc_uptime_s"] = uptime || (SiteGoose.clock - @started).floor
      reading = Limits.cgroup_reading(@cgroup)
      out.merge!(Limits.cgroup_fields(@last_cgroup, reading, mem_total_mb: row["mem_total_mb"], cores: row["cpu_cores"]))
      @last_cgroup = reading
      out.merge!(Limits.pressure_fields)
      overflows = Limits.listen_overflows(Resources.read_text("/proc/net/netstat"))
      drops = Limits.count_since(@last_overflows, overflows)
      out["listen_drops"] = drops if drops
      @last_overflows = overflows
      conntrack = Limits.conntrack_pct
      out["conntrack_pct"] = conntrack if conntrack
      out.merge!(Limits.file_fields)
      gc = Limits.gc_total_ms
      spent = Limits.count_since(@last_gc, gc)
      out["gc_ms"] = spent.to_f.round(1) if spent
      @last_gc = gc
      out.merge!(Limits.puma_fields(puma_stats))
      peak = @inflight&.call
      out["inflight_peak"] = peak if peak.is_a?(Integer) && !peak.negative?
      out
    end

    # Takes one sample, covering the time since the last one.
    def sample(at = nil)
      at ||= Time.now.to_f
      cpu = Resources.cpu_fields(Resources.read_text("/proc/stat"))
      disk = Resources.disk_counters(Resources.read_text("/proc/diskstats"))
      net = Resources.net_counters(Resources.read_text("/proc/net/dev"))
      percent = Resources.cpu_percent(@last_cpu && Resources.cpu_times_of(@last_cpu), cpu && Resources.cpu_times_of(cpu))
      elapsed = at - @last_at
      # The minute the interval started in, not the one it ended in.
      row = { "minute" => Time.at((@last_at.to_i / 60) * 60).utc.iso8601(3), "proc_key" => @proc_key }
      shares = Resources.cpu_shares(@last_cpu, cpu)
      rates = {}
      if @last_disk && disk
        rates["disk_read_mbs"] = Resources.rate_mbs(@last_disk[0], disk[0], elapsed)
        rates["disk_write_mbs"] = Resources.rate_mbs(@last_disk[1], disk[1], elapsed)
      end
      if @last_net && net
        rates["net_rx_mbs"] = Resources.rate_mbs(@last_net[0], net[0], elapsed)
        rates["net_tx_mbs"] = Resources.rate_mbs(@last_net[1], net[1], elapsed)
      end
      @last_cpu = cpu
      @last_disk = disk
      @last_net = net
      @last_at = at
      row.merge!(shares)
      rates.each { |name, value| row[name] = value unless value.nil? }
      row["cpu_pct"] = percent if percent && elapsed >= MIN_CPU_SECONDS
      cores = begin
        Etc.nprocessors
      rescue StandardError
        nil
      end
      row["cpu_cores"] = cores if cores&.positive?
      row.merge!(Resources.load_average(Resources.read_text("/proc/loadavg")))
      row.merge!(Resources.memory_mb(Resources.read_text("/proc/meminfo")))
      disks = Resources.disk_rows(Resources.mount_points(Resources.read_text("/proc/mounts")))
      row["disks"] = disks unless disks.empty?
      rss = Resources.process_rss_mb(Resources.read_text("/proc/self/status"))
      row["proc_rss_mb"] = rss if rss
      uptime = Resources.host_uptime(Resources.read_text("/proc/uptime"))
      row["host_uptime_s"] = uptime if uptime
      begin
        row.merge!(limits_row(row))
      rescue StandardError
        nil
      end
      @lock.synchronize do
        # Off in the dashboard: only the newest minute is kept, as the one row
        # that asks the collector, now and then, whether it is back on.
        @rows.clear unless @enabled
        @rows[row["minute"]] = row
        # Oldest first out: a long outage keeps the recent minutes.
        @rows.delete(@rows.keys.min) while @rows.size > MAX_ROWS
      end
      row
    end

    # Sends what's buffered. Rows are kept only when the collector couldn't
    # take them and retrying may work.
    def flush
      minutes, rows = @lock.synchronize do
        keys = @rows.keys.sort
        [keys, keys.map { |m| @rows[m] }]
      end
      return true if rows.empty?

      body = { "site_id" => @core.site_id, "server_name" => @server_name, "runtime" => RUNTIME[0, 32], "rows" => rows }
      res = @core.request("resources", "/events/resources", auth: :bearer, body: body)
      return false if res.nil?

      unless res.ok?
        # Unreachable or storage down: these rows are still good. A 4xx means
        # resending won't make them acceptable.
        return false if res.status >= 500

        drop(minutes)
        return true
      end
      answer = res.json
      if answer.is_a?(Hash)
        @every = [RETRY_EVERY, answer["every"].to_i].max if answer["every"].is_a?(Numeric) && answer["every"].positive?
        @enabled = answer["enabled"] != false
      end
      drop(minutes)
      true
    end

    def drop(minutes)
      @lock.synchronize { minutes.each { |m| @rows.delete(m) } }
    end

    def report
      unless @core.on?("resources")
        # Switched off: keep nothing, and ask again later.
        @lock.synchronize { @rows.clear }
        return [OFF_EVERY, @every].max
      end
      sent = flush
      # The collector said the module is off: ask again later, as the agent does.
      return [OFF_EVERY, @every].max unless @enabled

      sent ? @every : RETRY_EVERY
    end

    def close
      @sampler&.stop
      @job&.stop
      Forking.unregister(self)
      # What's buffered goes out, as with every other module.
      flush if @core.on?("resources") && @enabled
    end
  end
end
