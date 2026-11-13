# frozen_string_literal: true

# The resources module's limits pass (sdk/protocols/resources.md, "Limits"),
# read from stand-in files: the same cases as the Node package's
# test/limits.test.js, and Puma's pool and the requests in progress.

require_relative "test_helper"

class LimitsTest < Minitest::Test
  L = SiteGoose::Limits
  MB = 1024 * 1024

  def files(map)
    ->(path) { map.fetch(path, "") }
  end

  def test_a_v2_container_is_found_at_the_mount_itself_a_host_service_under_its_path
    container = files("/proc/self/cgroup" => "0::/\n", "/sys/fs/cgroup/memory.current" => "100\n")
    assert_equal({ version: 2, memory: "/sys/fs/cgroup", cpu: "/sys/fs/cgroup" }, L.find_cgroup(container))
    service = files("/proc/self/cgroup" => "0::/system.slice/app.service\n",
                    "/sys/fs/cgroup/system.slice/app.service/cpu.max" => "max 100000\n")
    assert_equal "/sys/fs/cgroup/system.slice/app.service", L.find_cgroup(service)[:memory]
    assert_nil L.find_cgroup(files({}))
  end

  def test_a_hybrid_machine_with_no_v2_controllers_reads_its_limits_from_v1
    hybrid = files("/proc/self/cgroup" => "12:memory:/docker/abc\n4:cpu,cpuacct:/docker/abc\n0::/docker/abc\n",
                   "/sys/fs/cgroup/memory/memory.usage_in_bytes" => "1000\n",
                   "/sys/fs/cgroup/cpu/cpu.cfs_quota_us" => "50000\n")
    assert_equal({ version: 1, memory: "/sys/fs/cgroup/memory", cpu: "/sys/fs/cgroup/cpu" }, L.find_cgroup(hybrid))
  end

  def v2(current:, inactive:, periods:, throttled:, oom:, max: (512 * MB).to_s)
    files("/c/memory.max" => "#{max}\n", "/c/memory.current" => "#{current}\n",
          "/c/memory.stat" => "anon 1\ninactive_file #{inactive}\n", "/c/memory.events" => "low 0\noom_kill #{oom}\n",
          "/c/cpu.max" => "150000 100000\n", "/c/cpu.stat" => "usage_usec 9\nnr_periods #{periods}\nnr_throttled #{throttled}\n")
  end

  def test_container_memory_is_the_working_set_and_throttling_a_share_of_periods
    cg = { version: 2, memory: "/c", cpu: "/c" }
    before = L.cgroup_reading(cg, v2(current: 300 * MB, inactive: 0, periods: 100, throttled: 10, oom: 0))
    after = L.cgroup_reading(cg, v2(current: 400 * MB, inactive: 100 * MB, periods: 200, throttled: 35, oom: 2))
    assert_equal({ "limit_mem_mb" => 512, "limit_mem_used_mb" => 300, "limit_cpu_cores" => 1.5,
                   "cpu_throttled_pct" => 25.0, "oom_kills" => 2 },
                 L.cgroup_fields(before, after, mem_total_mb: 8000, cores: 4))
  end

  def test_a_cap_that_isnt_one_is_left_out_and_one_reading_gives_no_counts
    cg = { version: 2, memory: "/c", cpu: "/c" }
    none = L.cgroup_reading(cg, v2(current: 1, inactive: 0, periods: 5, throttled: 0, oom: 0, max: "max"))
    refute L.cgroup_fields(nil, none).key?("limit_mem_mb")
    big = L.cgroup_reading(cg, v2(current: 1, inactive: 0, periods: 5, throttled: 0, oom: 0, max: (16_000 * MB).to_s))
    fields = L.cgroup_fields(nil, big, mem_total_mb: 8000, cores: 1)
    refute fields.key?("limit_mem_mb"), "at or above the machine's memory"
    refute fields.key?("limit_cpu_cores"), "at or above the machine's cores"
    refute fields.key?("cpu_throttled_pct")
    refute fields.key?("oom_kills")
    v1 = files("/m/memory.limit_in_bytes" => "9223372036854771712\n", "/m/memory.usage_in_bytes" => "100\n",
               "/p/cpu.cfs_quota_us" => "-1\n", "/p/cpu.cfs_period_us" => "100000\n")
    assert_equal({}, L.cgroup_fields(nil, L.cgroup_reading({ version: 1, memory: "/m", cpu: "/p" }, v1)))
  end

  def test_a_counter_that_went_down_was_reset_and_says_nothing
    assert_nil L.count_since(5, 3)
    assert_nil L.count_since(nil, 3)
    assert_equal 0, L.count_since(3, 3)
  end

  def test_waiting_time_is_the_some_lines_avg60_and_a_kernel_without_psi_sends_none
    psi = "some avg10=1.00 avg60=2.50 avg300=0.10 total=123\nfull avg10=0.00 avg60=9.00 avg300=0.00 total=1\n"
    assert_equal 2.5, L.pressure_some(psi)
    assert_nil L.pressure_some("")
    assert_equal({ "psi_cpu_pct" => 2.5 }, L.pressure_fields(files("/proc/pressure/cpu" => psi)))
  end

  def test_refused_connections_come_from_tcpext_listen_overflows
    text = "TcpExt: SyncookiesSent ListenOverflows ListenDrops\nTcpExt: 0 7 9\nIpExt: InNoRoutes\nIpExt: 0\n"
    assert_equal 7, L.listen_overflows(text)
    assert_nil L.listen_overflows("")
  end

  def test_open_files_against_the_soft_limit_and_unlimited_is_no_limit
    limits = "Limit                     Soft Limit           Hard Limit           Units\n" \
             "Max open files            1024                 4096                 files\n"
    assert_equal 1024, L.fd_limit(limits)
    assert_nil L.fd_limit("Max open files            unlimited            unlimited            files\n")
    assert_equal({ "fds_used" => 4, "fds_max" => 1024 }, L.file_fields(files("/proc/self/limits" => limits), -> { %w[0 1 2 3 4] }))
  end

  def test_conntrack_and_the_process_uptime
    assert_equal 25.0, L.conntrack_pct(files("/proc/sys/net/netfilter/nf_conntrack_count" => "16384\n",
                                             "/proc/sys/net/netfilter/nf_conntrack_max" => "65536\n"))
    assert_nil L.conntrack_pct(files({}))
    stat = "42 (ruby (a) b) #{(['S'] + ['0'] * 18 + ['500'] + ['0'] * 5).join(' ')}"
    assert_equal 95, L.proc_uptime(stat, "100.5 50.0", 100)
    assert_nil L.proc_uptime("", "100", 100)
  end

  def test_pumas_pool_busy_threads_cap_and_backlog
    assert_equal({ "workers_max" => 5, "workers_busy" => 3, "queue_waiting" => 2 },
                 L.puma_fields({ max_threads: 5, pool_capacity: 2, backlog: 2, running: 5 }))
    assert_equal({}, L.puma_fields(nil))
    assert_equal({}, L.puma_fields({ "max_threads" => 0 }))
  end

  def test_requests_in_progress_peak_per_interval_and_none_until_the_middleware_runs
    made = quiet_platform(performance: {}, resources: {})
    perf = made.module("performance")
    assert_nil perf.take_inflight_peak
    resources = made.module("resources")
    refute resources.sample.key?("inflight_peak"), "no requests yet: no peak, not 0"
    perf.enter
    perf.enter
    perf.leave
    assert_equal 2, perf.take_inflight_peak
    assert_equal 1, perf.take_inflight_peak, "starts again from what is still in progress"
    perf.leave
    made.rack_call(rack_env) { [200, {}, []] }
    row = resources.sample
    assert_equal 1, row["inflight_peak"]
    assert_match(/\A\h{12}\z/, row["proc_key"])
    assert_kind_of Integer, row["proc_uptime_s"]
    assert_kind_of Float, row["gc_ms"] if RUBY_VERSION >= "3.1"
    made.close
  end

  def test_a_forked_child_is_another_process
    resources = SiteGoose::Resources.new(FakeCore.new)
    key = resources.proc_key
    resources.after_fork_in_child
    refute_equal key, resources.proc_key
  end
end
