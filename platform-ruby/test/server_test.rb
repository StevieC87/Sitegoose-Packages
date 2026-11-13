# frozen_string_literal: true

# Resources, inventory, posture and the first-party proxy.

require_relative "test_helper"
require "tmpdir"

R = SiteGoose::Resources

class ResourcesTest < Minitest::Test
  STAT1 = "cpu  100 0 50 800 50 0 0 0 0 0\ncpu0 1 2 3 4\n"
  STAT2 = "cpu  160 0 70 900 70 0 0 0 0 0\n"

  def test_cpu_needs_two_readings_and_ignores_idle
    before = R.cpu_times_of(R.cpu_fields(STAT1))
    after = R.cpu_times_of(R.cpu_fields(STAT2))
    assert_equal 40.0, R.cpu_percent(before, after)
    assert_nil R.cpu_percent(nil, after)
    assert_nil R.cpu_fields("nothing")
  end

  def test_shares_and_a_kernel_without_steal_says_nothing
    shares = R.cpu_shares(R.cpu_fields(STAT1), R.cpu_fields(STAT2))
    assert_equal({ "cpu_user_pct" => 30.0, "cpu_system_pct" => 10.0, "cpu_iowait_pct" => 10.0, "cpu_steal_pct" => 0.0 }, shares)
    refute R.cpu_shares([1, 1, 1, 1, 1], [2, 2, 2, 2, 2]).key?("cpu_steal_pct")
  end

  def test_memory_used_is_total_minus_available
    text = "MemTotal: 2048000 kB\nMemFree: 100000 kB\nMemAvailable: 1024000 kB\nSwapTotal: 1024 kB\nSwapFree: 1024 kB\n"
    assert_equal({ "mem_total_mb" => 2000, "mem_used_mb" => 1000, "swap_total_mb" => 1, "swap_used_mb" => 0 }, R.memory_mb(text))
    assert_equal({ "mem_total_mb" => 2000 }, R.memory_mb("MemTotal: 2048000 kB\n"))
  end

  def test_only_real_disks_once_each_and_not_a_bind_mounted_file
    mounts = "/dev/sda1 / ext4 rw 0 0\n/dev/sda1 /etc/hosts ext4 rw 0 0\ntmpfs /run tmpfs rw 0 0\n" \
             "/dev/sdb1 /data xfs rw 0 0\n/dev/sdb1 /mnt/data\\040copy xfs rw 0 0\nproc /proc proc rw 0 0\n"
    dirs = ["/", "/data", "/mnt/data copy"]
    assert_equal ["/", "/data"], R.mount_points(mounts, ->(p) { dirs.include?(p) })
    assert_equal ["/"], R.mount_points("")
  end

  def test_disk_figures_are_the_ones_df_prints
    blocks = R.parse_df("Filesystem 1024-blocks Used Available Capacity Mounted on\n" \
                        "/dev/sda1 10485760 4194304 5242880 45% /\n/dev/sdb1 512 1 511 1% /boot/efi\n" \
                        "overlay 10485760 4194304 5242880 45% /var/lib/x y\n")
    inodes = R.parse_df("Filesystem Inodes IUsed IFree IUse% Mounted on\n/dev/sda1 655360 1000 654360 1% /\n")
    rows = R.disk_rows(["/", "/boot/efi", "/var/lib/x y"], blocks, inodes)
    assert_equal [{ "mount" => "/", "total_mb" => 9216, "used_mb" => 4096, "inodes_total" => 655_360, "inodes_used" => 1000 }], rows,
                 "used + available is the total; too small and the same filesystem twice are left out"
  end

  def test_rates_and_counters
    disks = R.disk_counters("   8 0 sda 1 0 2048 0 1 0 4096 0 0 0 0\n   8 1 sda1 1 0 99 0 1 0 99 0\n   7 0 loop0 1 0 99 0 1 0 99 0\n")
    assert_equal [2048 * 512, 4096 * 512], disks
    net = R.net_counters("Inter-|\n lo: 999 0 0 0 0 0 0 0 999 0\n eth0: 1048576 1 0 0 0 0 0 0 2097152 1\n veth1: 5 0 0 0 0 0 0 0 5 0\n")
    assert_equal [1_048_576, 2_097_152], net
    assert_equal 0.5, R.rate_mbs(0, 1_048_576, 2)
    assert_nil R.rate_mbs(0, 10, 3600), "a quiet hour is not a rate"
    assert_nil R.rate_mbs(10, 0, 60), "a reboot reset the counters"
  end

  def test_a_sample_carries_the_minute_and_what_the_machine_gives
    resources = R.new(FakeCore.new, server_name: "web-1")
    row = resources.sample(Time.now.to_f + 61)
    assert_match(/\A\d{4}-\d\d-\d\dT\d\d:\d\d:00\.000Z\z/, row["minute"])
    if File.exist?("/proc/meminfo")
      assert row.key?("mem_total_mb")
      assert row.key?("load1")
      assert row.key?("proc_rss_mb")
      refute_empty row["disks"].to_a, "df reports the container's disk"
    end
  end

  def test_rows_are_dropped_once_stored_kept_when_the_collector_cannot_take_them
    core = FakeCore.new(answers: [503, SiteGoose::Response.new(200, {}, '{"enabled":false,"every":900}')])
    resources = R.new(core)
    resources.sample
    refute resources.flush
    assert_equal 1, resources.rows.size
    assert resources.flush
    assert_empty resources.rows
    assert_equal [900, false], [resources.every, resources.enabled]
    assert_equal ["Ruby #{RUBY_VERSION}"[0, 32], :bearer], [core.sent[0][:body]["runtime"], core.sent[0][:auth]]
  end
end

class InventoryTest < Minitest::Test
  LOCK = <<~LOCK
    GEM
      remote: https://rubygems.org/
      specs:
        nokogiri (1.16.7-x86_64-linux)
          racc (~> 1.4)
        rack (3.1.8)
        racc (1.8.1)

    PLATFORMS
      x86_64-linux

    DEPENDENCIES
      nokogiri
      rack (>= 3)!

    BUNDLED WITH
       2.5.22
  LOCK

  def test_the_lockfile_is_read
    assert_equal({ "nokogiri" => "1.16.7", "rack" => "3.1.8", "racc" => "1.8.1" }, SiteGoose::Inventory.lockfile_specs(LOCK))
    assert_equal %w[nokogiri rack], SiteGoose::Inventory.lockfile_direct(LOCK).keys
  end

  def test_the_loaded_gems_are_reported
    packages = SiteGoose::Inventory.installed_packages
    json = packages.find { |p| p["name"] == "json" }
    assert_equal ["RubyGems", Gem.loaded_specs["json"].version.to_s], json.values_at("ecosystem", "version")
    assert_equal packages.map { |p| p["name"].downcase }.sort, packages.map { |p| p["name"].downcase }
  end

  def test_the_report
    core = FakeCore.new(answers: [SiteGoose::Response.new(200, {}, '{"v":1,"every":7200}')])
    inventory = SiteGoose::Inventory.new(core, host: "web 1")
    assert_equal 7200, inventory.report
    body = core.sent[0][:body]
    assert_equal ["web-1", { "ruby" => RUBY_VERSION }, false], body.values_at("host", "runtime", "truncated")
    assert_equal "/events/inventory", core.sent[0][:path]
    core.switches = { "inventory" => false }
    assert_equal 3600, inventory.report
    assert_equal 1, core.sent.size
  end
end

class PostureTest < Minitest::Test
  def test_the_walk_finds_what_should_not_be_public
    Dir.mktmpdir do |dir|
      File.write(File.join(dir, "dump.sql"), "x")
      File.write(File.join(dir, ".env"), "x")
      File.write(File.join(dir, "index.html"), "x")
      Dir.mkdir(File.join(dir, ".git"))
      Dir.mkdir(File.join(dir, "assets"))
      File.write(File.join(dir, "assets", "app.rb.bak"), "x")
      File.write(File.join(dir, "assets", "open.rb"), "x")
      File.chmod(0o666, File.join(dir, "assets", "open.rb"))
      posture = SiteGoose::Posture.new(FakeCore.new, roots: [{ dir: dir, prefix: "/static/" }, File.join(dir, "assets")], host: "web-1")
      body = posture.report
      kinds = body["exposure"].to_h { |row| [row["path"], row["kind"]] }
      assert_equal({ "static/dump.sql" => "database_dump", "static/.env" => "env", "static/.git/config" => "vcs",
                     "static/assets/app.rb.bak" => "backup" }, kinds)
      writable = body["checks"].find { |c| c["id"] == "server.code_writable" }
      assert_equal ["fail", "1 files, e.g. static/assets/open.rb"], writable.values_at("state", "value")
      assert_equal "ruby/#{RUBY_VERSION}", body["facts"]["agent"]
      assert(body["checks"].any? { |c| c["id"] == "server.runs_as_root" })
    end
  end

  def test_no_folder_no_exposure_section_and_checks_of_your_own
    posture = SiteGoose::Posture.new(FakeCore.new, checks: -> { [{ id: "App.Custom", state: "fail", value: "yes" }, { id: "x", state: "maybe" }] })
    body = posture.report
    refute body.key?("exposure"), "left out: nothing was looked at"
    assert_equal [{ "id" => "app.custom", "state" => "fail", "value" => "yes" }], body["checks"].select { |c| c["id"].start_with?("app.") }
  end
end

class ProxyTest < Minitest::Test
  def setup
    @collector = FakeCollector.new.start
    @core = SiteGoose::Core.new("a" * 24, "s3cret", @collector.endpoint)
    @proxy = SiteGoose::Proxy.new(@core)
  end

  def teardown
    @collector.stop
  end

  def test_the_prefix_and_key_are_the_other_packages
    assert_equal "4da6ae10", SiteGoose::Proxy.prefix_for("s")
    assert_equal "91136005e32a04cc1b0a2876634feff2", SiteGoose::Proxy.key_for("s")
    assert_equal "/#{SiteGoose::Proxy.prefix_for('s3cret')}/js/v1/s.js", @proxy.script_url
  end

  def test_only_our_addresses_and_tracker_files
    assert_nil @proxy.match("/pricing")
    assert_equal ["api", "e"], @proxy.match(@proxy.collect_url)
    assert_equal ["bad", ""], @proxy.match("/#{@proxy.prefix}/js/../x")
    assert_equal 404, @proxy.handle("js", "v1/evil.js")[0]
  end

  def test_the_tracker_is_fetched_once_and_then_held
    2.times { assert_equal 200, @proxy.handle("js", "v1/s.js")[0] }
    assert_equal 1, @collector.requests("/v1/s.js").size
  end

  def test_visits_reach_the_collector_without_cookies
    status, = @proxy.handle("api", "e", method: "POST", query: "x=1", body: '{"a":1}', client_ip: "198.51.100.9",
                                        headers: { "content-type" => "text/plain", "cookie" => "session=secret", "user-agent" => "UA" })
    assert_equal 202, status
    seen = @collector.requests("/collectanalytics/e")[0]
    assert_equal ["198.51.100.9", SiteGoose::Proxy.key_for("s3cret"), "UA"], seen["headers"].values_at("x-forwarded-for", "x-proxy-key", "user-agent")
    refute seen["headers"].key?("cookie")
    assert_equal "/collectanalytics/e?x=1", seen["target"]
    assert_equal 404, @proxy.handle("api", "e", method: "DELETE")[0]
  end
end
