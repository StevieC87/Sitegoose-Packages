"""The agent's own checks: the text that reaches nftables and nginx, what the
file scan walks and reads, and the limits that keep one scan bounded.

    python3 -m unittest discover -s test
"""
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

AGENT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "analytics-agent")
spec = importlib.util.spec_from_loader("analytics_agent", importlib.machinery.SourceFileLoader("analytics_agent", AGENT))
agent = importlib.util.module_from_spec(spec)
sys.modules["analytics_agent"] = agent
spec.loader.exec_module(agent)
# The tests never reach this machine's own web servers or logs.
agent.DEFAULTS.update(web_checks=[], access_logs=[])
# Nor this machine's iptables and ipset (test_iptables.py patches them in per test).
agent.ipt_tools = lambda refresh=False: None


class DockerSocket(unittest.TestCase):
    """Docker sets the group bit on every install, so only who is in the group
    can make this a finding."""

    def accounts(self, mode, members=(), primary=()):
        with tempfile.NamedTemporaryFile() as sock:
            os.chmod(sock.name, mode)
            gid = os.stat(sock.name).st_gid
            users = [SimpleNamespace(pw_name=name, pw_gid=gid) for name in primary]
            users.append(SimpleNamespace(pw_name="other", pw_gid=gid + 1))
            with mock.patch.object(agent.grp, "getgrgid", return_value=SimpleNamespace(gr_mem=list(members))), \
                    mock.patch.object(agent.pwd, "getpwall", return_value=users):
                return agent.docker_socket_accounts(sock.name)

    def test_an_empty_group_reaches_no_one(self):
        self.assertEqual(self.accounts(0o660), [])

    def test_root_in_the_group_is_nobody_new(self):
        self.assertEqual(self.accounts(0o660, members=["root"], primary=["root"]), [])

    def test_members_and_primary_group_accounts_are_named(self):
        self.assertEqual(self.accounts(0o660, members=["deploy", "root"], primary=["ci"]), ["ci", "deploy"])

    def test_a_group_without_write_is_nobody(self):
        self.assertEqual(self.accounts(0o640, members=["deploy"]), [])

    def test_a_world_writable_socket_reaches_everyone(self):
        self.assertEqual(self.accounts(0o666), ["every account"])


class Addresses(unittest.TestCase):
    """Everything from the collector lands in nftables and nginx config as text,
    so nothing that isn't an address may survive this."""

    def test_only_addresses_and_ranges_get_through(self):
        v4, v6 = agent.networks([
            "203.0.113.4", "198.51.100.0/24", "2001:db8::1",
            "1.2.3.4 }; chain evil { type filter hook input priority 0; policy drop; }",
            "203.0.113.5; deny all;", "not-an-address", "", None, {"ip": "1.2.3.4"}, "999.999.999.999",
        ])
        # Single addresses come back canonicalised as /32 and /128.
        self.assertEqual(v4, ["198.51.100.0/24", "203.0.113.4/32"])
        self.assertEqual(v6, ["2001:db8::1/128"])
        for entry in v4 + v6:
            self.assertNotIn(";", entry)
            self.assertNotIn("{", entry)
            self.assertNotIn(" ", entry)

    def test_an_injected_rule_cannot_reach_the_ruleset(self):
        plan = agent.plan({"enabled": True, "mode": "block", "allow": [], "deny": ["1.2.3.4 }; policy drop; #"]})
        ruleset = agent.nft_ruleset({"ports": [80, 443]}, plan)
        self.assertNotIn("policy drop", ruleset.replace("policy accept", ""))
        self.assertIn("table inet analytics_firewall", ruleset)

    def test_ipv4_mapped_addresses_count_as_ipv4(self):
        v4, v6 = agent.networks(["::ffff:203.0.113.7"])
        self.assertEqual(v4, ["203.0.113.7/32"])
        self.assertEqual(v6, [])


class WatchedFiles(unittest.TestCase):
    def test_which_names_are_watched(self):
        for name in ("index.php", "app.js", "page.html", "shell.phtml", ".env", ".env.local", ".htaccess", ".user.ini"):
            self.assertTrue(agent.watched_file(name), name)
        for name in ("php", "html", "logo.png", "notes.txt", "archive.tar.gz", "Makefile"):
            self.assertFalse(agent.watched_file(name), name)


class Scanning(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def write(self, name, body=b"<?php echo 1;"):
        path = os.path.join(self.dir, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(body)
        return path

    def test_a_symlink_is_never_followed_or_hashed(self):
        self.write("real.php")
        os.symlink("/etc/passwd", os.path.join(self.dir, "sneaky.php"))
        current, truncated = agent.scan_files([self.dir], [], {}, True)
        self.assertIn(os.path.join(self.dir, "real.php"), current)
        self.assertNotIn(os.path.join(self.dir, "sneaky.php"), current)
        self.assertFalse(truncated)

    def test_a_change_is_reported_with_what_was_found_in_it(self):
        self.write("ok.php")
        shell = self.write("bad.php", b"<?php eval(base64_decode($_GET['x']));")
        current, _ = agent.scan_files([self.dir], [], {}, True)
        changes = agent.file_changes({}, current)
        found = {c["path"]: c for c in changes}
        self.assertEqual(found[shell]["change"], "added")
        self.assertIn("eval_decode", found[shell]["signals"])
        self.assertEqual(found[os.path.join(self.dir, "ok.php")]["signals"], [])
        # The ones worth looking at come first.
        self.assertEqual(changes[0]["path"], shell)

    def test_a_deploy_of_everything_does_not_read_everything(self):
        for i in range(12):
            self.write("f%d.php" % i)
        current, _ = agent.scan_files([self.dir], [], {}, True)
        reads = []
        real = agent.file_signals
        agent.file_signals = lambda path: reads.append(path) or []
        try:
            changes = agent.file_changes({}, current, budget=5)
        finally:
            agent.file_signals = real
        self.assertEqual(len(changes), 12, "every change is still reported")
        self.assertEqual(len(reads), 5, "only the budget is read")

    def test_the_first_scan_only_reads_its_budget(self):
        for i in range(12):
            self.write("g%d.php" % i)
        current, _ = agent.scan_files([self.dir], [], {}, True)
        reads = []
        real = agent.file_signals
        agent.file_signals = lambda path: reads.append(path) or []
        try:
            agent.flagged_files(current, budget=4)
        finally:
            agent.file_signals = real
        self.assertEqual(len(reads), 4)

    def test_an_excluded_folder_is_skipped(self):
        self.write("keep.php")
        self.write("skipme/drop.php")
        current, _ = agent.scan_files([self.dir], [os.path.join(self.dir, "skipme")], {}, True)
        self.assertIn(os.path.join(self.dir, "keep.php"), current)
        self.assertNotIn(os.path.join(self.dir, "skipme", "drop.php"), current)

    def test_only_hashes_and_facts_leave_the_server_never_contents(self):
        secret = b"<?php $db_password = 'hunter2';"
        path = self.write("config.php", secret)
        current, _ = agent.scan_files([self.dir], [], {}, True)
        changes = agent.file_changes({}, current)
        blob = repr(changes) + repr(current)
        self.assertNotIn("hunter2", blob)
        self.assertEqual(set(current[path][0:1][0]) <= set("0123456789abcdef"), True)


class Machine(unittest.TestCase):
    """How the machine is doing (sdk/protocols/resources.md). The rule the
    whole feature rests on: a reading this machine won't give is left out, so
    the collector stores NULL — never a zero that reads as healthy."""

    STAT = "cpu  100 10 50 1000 20 0 5 0 0 0\ncpu0 50 5 25 500 10 0 2 0 0 0\nintr 1\n"
    MEMINFO = ("MemTotal:        8143868 kB\n"
               "MemFree:          210000 kB\n"
               "MemAvailable:    5021228 kB\n"
               "Buffers:          100000 kB\n"
               "Cached:          4000000 kB\n"
               "SwapTotal:       2097152 kB\n"
               "SwapFree:        2084864 kB\n")

    def test_cpu_percent_needs_two_readings_and_ignores_idle(self):
        before = agent.cpu_times(self.STAT)
        self.assertEqual(before, (165, 1185))  # everything but idle + iowait
        # One reading alone can say nothing.
        self.assertIsNone(agent.cpu_percent(None, before))
        # 100 busy jiffies out of 200 that passed.
        after = (before[0] + 100, before[1] + 200)
        self.assertEqual(agent.cpu_percent(before, after), 50.0)
        # A counter that went backwards (a reboot) says nothing either.
        self.assertIsNone(agent.cpu_percent(after, before))
        self.assertIsNone(agent.cpu_percent(before, before))

    def test_memory_used_is_total_minus_available_not_minus_free(self):
        memory = agent.memory_mb(self.MEMINFO)
        self.assertEqual(memory["mem_total_mb"], 7952)
        # 7952 - 4903 available. Using MemFree instead would claim 7747 MB
        # used and make a healthy machine look full.
        self.assertEqual(memory["mem_used_mb"], 3049)
        self.assertEqual(memory["swap_total_mb"], 2048)
        self.assertEqual(memory["swap_used_mb"], 12)

    def test_a_field_the_kernel_did_not_give_is_left_out(self):
        memory = agent.memory_mb("MemTotal:        8143868 kB\nMemFree:  210000 kB\n")
        self.assertEqual(memory, {"mem_total_mb": 7952})
        self.assertNotIn("mem_used_mb", memory, "no MemAvailable means no used figure, not 0")
        self.assertEqual(agent.memory_mb(""), {})
        self.assertIsNone(agent.host_uptime(""))
        self.assertIsNone(agent.host_uptime("not-a-number"))
        self.assertEqual(agent.host_uptime("864000.12 1700000.00"), 864000)

    def test_only_real_disks_are_reported_once_each(self):
        mounts = (
            "/dev/sda1 / ext4 rw,relatime 0 0\n"
            "proc /proc proc rw 0 0\n"
            "sysfs /sys sysfs rw 0 0\n"
            "tmpfs /run tmpfs rw 0 0\n"
            "udev /dev devtmpfs rw 0 0\n"
            "/dev/loop3 /snap/core20/2105 squashfs ro 0 0\n"
            "nas:/export /mnt/nas nfs4 rw 0 0\n"
            "/dev/sdb1 /data xfs rw 0 0\n"
            # The same device bind-mounted deeper: one disk, not two.
            "/dev/sda1 /var/www ext4 rw 0 0\n"
        )

        class Stat:
            f_frsize = 4096
            f_bsize = 4096
            f_blocks = 1024 * 1024  # a 4 GiB disk
            f_bfree = 300 * 1024    # 1200 MB free
            f_bavail = 256 * 1024   # of which 1024 MB is ours (the rest is root's)
            f_files = 262_144       # inodes
            f_ffree = 200_000

        class OtherStat(Stat):
            f_blocks = 2048 * 1024  # a second disk, its own size and usage
            f_bfree = 900 * 1024
            f_bavail = 880 * 1024

        # Two separate disks have to report separate figures: a second mount
        # whose size and free space match an earlier one to the byte is the
        # same storage seen twice, and is collapsed.
        rows = agent.disk_rows(
            mounts,
            statvfs=lambda mount: Stat() if mount == "/" else OtherStat(),
            is_dir=lambda mount: True,
        )
        self.assertEqual([r["mount"] for r in rows], ["/", "/data"])
        # Both figures are df's: used = total - free, total = used + available.
        # The 176 MB reserved for root is in neither, so used/total is df's Use%.
        self.assertEqual(rows[0]["used_mb"], 2896)
        self.assertEqual(rows[0]["total_mb"], 3920)
        # Inodes ride along with the mount: a disk can refuse writes with
        # gigabytes free once these meet, and every byte check looks healthy.
        self.assertEqual(rows[0]["inodes_total"], 262_144)
        self.assertEqual(rows[0]["inodes_used"], 62_144)

    def test_a_bind_mounted_file_is_not_one_of_the_disks(self):
        # Docker bind-mounts single files, so a container's mount table lists
        # /etc/hosts and friends on the host's own device. Those paths are
        # short, so without a directory test one of them wins the
        # shortest-path race and the panel names a file as a disk.
        mounts = (
            "overlay / overlay rw,relatime 0 0\n"
            "/dev/nvme0n1p6 /var/www/html/wp-content/plugins/site-analytics ext4 rw 0 0\n"
            "/dev/nvme0n1p6 /etc/resolv.conf ext4 rw 0 0\n"
            "/dev/nvme0n1p6 /etc/hostname ext4 rw 0 0\n"
            "/dev/nvme0n1p6 /etc/hosts ext4 rw 0 0\n"
        )

        class Stat:
            f_frsize = 4096
            f_bsize = 4096
            f_blocks = 1024 * 1024
            f_bfree = 300 * 1024
            f_bavail = 256 * 1024
            f_files = 0
            f_ffree = 0

        class Host(Stat):
            f_blocks = 2048 * 1024

        rows = agent.disk_rows(
            mounts,
            statvfs=lambda mount: Stat() if mount == "/" else Host(),
            is_dir=lambda mount: not mount.startswith("/etc/"),
        )
        self.assertEqual(
            [r["mount"] for r in rows],
            ["/", "/var/www/html/wp-content/plugins/site-analytics"],
        )

    def test_a_device_whose_mounts_we_cannot_confirm_keeps_its_shortest(self):
        # open_basedir and the like can make every directory test false.
        # Reporting no disks would be worse than reporting an odd mount point.
        mounts = "/dev/sda1 / ext4 rw 0 0\n"

        class Stat:
            f_frsize = 4096
            f_bsize = 4096
            f_blocks = 1024 * 1024
            f_bfree = 300 * 1024
            f_bavail = 256 * 1024
            f_files = 0
            f_ffree = 0

        rows = agent.disk_rows(mounts, statvfs=lambda m: Stat(), is_dir=lambda m: False)
        self.assertEqual([r["mount"] for r in rows], ["/"])

    def test_one_filesystem_behind_two_devices_is_reported_once(self):
        # The bug seen on a real container: / is the overlay and /sdk is a
        # bind of the host disk the overlay's upperdir lives on. The kernel
        # calls them different devices (overlay vs /dev/nvme0n1p6, and two
        # different st_dev), so only the byte-identical size and free space
        # give it away.
        mounts = (
            "overlay / overlay rw,relatime 0 0\n"
            "/dev/nvme0n1p6 /sdk ext4 rw,relatime 0 0\n"
        )

        class Stat:
            f_frsize = 4096
            f_bsize = 4096
            f_blocks = 78_280_000
            f_bfree = 28_570_000
            f_bavail = 24_500_000
            f_files = 19_537_920
            f_ffree = 17_000_000

        rows = agent.disk_rows(mounts, statvfs=lambda m: Stat(), is_dir=lambda m: True)
        self.assertEqual([r["mount"] for r in rows], ["/"])

    def test_a_disk_we_cannot_stat_is_skipped_not_guessed(self):
        mounts = "/dev/sda1 / ext4 rw 0 0\n/dev/sdb1 /data xfs rw 0 0\n"

        def statvfs(mount):
            if mount == "/data":
                raise OSError("permission denied")

            class Stat:
                f_frsize, f_bsize = 4096, 4096
                f_blocks, f_bfree, f_bavail = 1024 * 1024, 256 * 1024, 256 * 1024
                f_files, f_ffree = 262_144, 200_000
            return Stat()

        rows = agent.disk_rows(mounts, statvfs=statvfs)
        self.assertEqual([r["mount"] for r in rows], ["/"])

    def test_a_partition_too_small_to_care_about_is_left_out(self):
        # The EFI partition every UEFI machine has: real, and noise.
        mounts = "/dev/sda1 / ext4 rw 0 0\n/dev/sda15 /boot/efi vfat rw 0 0\n"

        def statvfs(mount):
            class Stat:
                f_frsize, f_bsize = 4096, 4096
                f_blocks = 64 * 1024 if mount == "/boot/efi" else 1024 * 1024
                f_bfree = f_bavail = f_blocks // 2
                f_files, f_ffree = 262_144, 200_000
            return Stat()

        self.assertEqual([r["mount"] for r in agent.disk_rows(mounts, statvfs=statvfs)], ["/"])

    def test_a_sample_leaves_out_what_it_could_not_read(self):
        # A machine that gives us nothing: every optional field is absent, and
        # the row still carries the minute it covers.
        row = agent.resource_sample(1_760_000_123, cpu=None, reader=lambda path, limit=65536: "")
        self.assertEqual(row["minute"], "2025-10-09T08:55:00Z")
        for field in ("cpu_pct", "mem_total_mb", "mem_used_mb", "swap_total_mb", "disks", "host_uptime_s"):
            self.assertNotIn(field, row, "%s must be absent, not zero" % field)

    def test_a_sample_carries_what_it_could_read(self):
        reads = {"/proc/meminfo": self.MEMINFO, "/proc/mounts": "", "/proc/uptime": "864000.00 1.0"}
        row = agent.resource_sample(1_760_000_100, cpu=42.5, reader=lambda path, limit=65536: reads.get(path, ""))
        self.assertEqual(row["cpu_pct"], 42.5)
        self.assertEqual(row["mem_used_mb"], 3049)
        self.assertEqual(row["host_uptime_s"], 864000)
        self.assertNotIn("disks", row)
        # The agent is not the site's application, so it reports no process memory.
        self.assertNotIn("proc_rss_mb", row)

    def test_the_machine_is_reported_to_every_site_on_it(self):
        config = dict(agent.DEFAULTS, site_id="a" * 24, secret="one", endpoint="https://c.example",
                      sites=[{"site_id": "b" * 24, "secret": "two", "files_roots": ["/var/www/b"]}])
        sites = agent.resources_sites(config)
        self.assertEqual([(s["site_id"], s["secret"]) for s in sites], [("a" * 24, "one"), ("b" * 24, "two")])
        for site in sites:
            self.assertEqual(site["endpoint"], "https://c.example")


class Reporting(unittest.TestCase):
    """What the sampler does with the collector's answers."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.config = dict(agent.DEFAULTS, site_id="a" * 24, secret="s", endpoint="https://c.example",
                           state_dir=self.dir, sites=[])
        self.sent = []
        self.answer = (202, {}, b'{"v":1,"enabled":true,"every":300,"stored":1}')
        self.real_request = agent.request
        agent.request = self.fake_request

    def tearDown(self):
        agent.request = self.real_request

    def fake_request(self, config, method, path, body=None, headers=None):
        self.sent.append((config["site_id"], path, body))
        return self.answer

    def sampler(self):
        checks = agent.Resources(self.config)
        checks.rows = {"2026-10-20T12:00:00Z": {"minute": "2026-10-20T12:00:00Z", "cpu_pct": 10.0}}
        return checks

    def test_a_posted_batch_is_dropped_once_it_is_stored(self):
        checks = self.sampler()
        self.assertTrue(checks.post())
        self.assertEqual(len(self.sent), 1)
        self.assertEqual(self.sent[0][1], "/events/resources")
        self.assertEqual(self.sent[0][2]["rows"][0]["cpu_pct"], 10.0)
        self.assertEqual(checks.rows, {}, "stored rows are not sent twice")

    def test_rows_are_kept_when_the_collector_cannot_take_them(self):
        checks = self.sampler()
        for self.answer in ((0, {}, b""), (503, {}, b""), (500, {}, b"")):
            checks.rows = {"2026-10-20T12:00:00Z": {"minute": "2026-10-20T12:00:00Z", "cpu_pct": 10.0}}
            self.assertFalse(checks.post())
            self.assertEqual(len(checks.rows), 1, "a retry can still deliver these")

    def test_rows_the_collector_refused_are_not_retried_forever(self):
        checks = self.sampler()
        self.answer = (400, {}, b'{"error":"rows must hold 1 to 500 valid rows"}')
        self.assertTrue(checks.post())
        self.assertEqual(checks.rows, {}, "resending won't make them acceptable")

    def test_the_module_switch_is_followed(self):
        checks = self.sampler()
        self.answer = (200, {}, b'{"v":1,"enabled":false,"every":300}')
        checks.post()
        self.assertFalse(checks.enabled)
        # And it comes back on without a restart.
        checks.rows = {"2026-10-20T12:01:00Z": {"minute": "2026-10-20T12:01:00Z", "cpu_pct": 11.0}}
        self.answer = (202, {}, b'{"v":1,"enabled":true,"every":300}')
        checks.post()
        self.assertTrue(checks.enabled)

    def test_the_buffer_is_bounded_and_keeps_the_newest_minutes(self):
        checks = agent.Resources(self.config)
        for i in range(agent.RESOURCES_MAX_ROWS + 20):
            minute = "2026-10-20T%02d:%02d:00Z" % (i // 60, i % 60)
            checks.rows[minute] = {"minute": minute}
            while len(checks.rows) > agent.RESOURCES_MAX_ROWS:
                del checks.rows[min(checks.rows)]
        self.assertEqual(len(checks.rows), agent.RESOURCES_MAX_ROWS)
        self.assertIn("2026-10-20T08:39:00Z", checks.rows)
        self.assertNotIn("2026-10-20T00:00:00Z", checks.rows)


if __name__ == "__main__":
    unittest.main()


class MachineDetail(unittest.TestCase):
    """The CPU breakdown, disk and network throughput, and inodes."""

    # user nice system idle iowait irq softirq steal
    BEFORE = [1000, 100, 500, 8000, 200, 10, 20, 170]
    AFTER = [1100, 100, 550, 8600, 240, 10, 20, 180]

    def test_steal_is_reported_because_nothing_else_can_tell_them(self):
        shares = agent.cpu_shares(self.BEFORE, self.AFTER)
        # 800 jiffies passed; 10 of them went to another tenant. 1.25 rounds
        # to 1.2, not 1.3: Python rounds an exact half to even, and a tenth of
        # a percent either way is not worth special-casing.
        self.assertEqual(shares["cpu_steal_pct"], 1.2)
        self.assertEqual(shares["cpu_iowait_pct"], 5.0)
        self.assertEqual(shares["cpu_system_pct"], 6.2)
        # user folds nice in, as top adds them together.
        self.assertEqual(shares["cpu_user_pct"], 12.5)

    def test_a_kernel_without_a_column_leaves_it_out_rather_than_sending_nought(self):
        # A /proc/stat with no steal column at all: four fields.
        shares = agent.cpu_shares([1000, 100, 500, 8000], [1100, 100, 550, 8600])
        self.assertNotIn("cpu_steal_pct", shares)
        self.assertNotIn("cpu_iowait_pct", shares)
        self.assertIn("cpu_user_pct", shares)

    def test_one_reading_or_a_reset_says_nothing(self):
        self.assertEqual(agent.cpu_shares(None, self.AFTER), {})
        # Counters that went backwards are a reboot, not negative time.
        self.assertEqual(agent.cpu_shares(self.AFTER, self.BEFORE), {})

    def test_a_partition_is_not_counted_twice_with_its_disk(self):
        # sda plus its partition, a loop device and a device-mapper volume.
        stats = (
            "   8   0 sda 100 0 2000 0 50 0 4000 0 0 0 0\n"
            "   8   1 sda1 90 0 1800 0 40 0 3000 0 0 0 0\n"
            "   7   0 loop0 10 0 100 0 0 0 0 0 0 0 0\n"
            " 253   0 dm-0 10 0 500 0 5 0 500 0 0 0 0\n"
            " 259   0 nvme0n1 20 0 1000 0 10 0 2000 0 0 0 0\n"
            " 259   1 nvme0n1p1 15 0 900 0 8 0 1500 0 0 0 0\n"
        )
        # Only sda and nvme0n1: (2000 + 1000) sectors read, (4000 + 2000) written.
        self.assertEqual(agent.disk_counters(stats), (3000 * 512, 6000 * 512))

    def test_a_machine_with_no_real_disk_reports_nothing_not_zero(self):
        self.assertIsNone(agent.disk_counters("   7   0 loop0 10 0 100 0 0 0 0 0 0 0 0\n"))
        self.assertIsNone(agent.disk_counters(""))

    def test_container_and_loopback_traffic_is_not_our_traffic(self):
        dev = (
            "Inter-|   Receive                    |  Transmit\n"
            " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets\n"
            "    lo: 5000 10 0 0 0 0 0 0 5000 10 0 0 0 0 0 0\n"
            "  eth0: 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0\n"
            "docker0: 9000 10 0 0 0 0 0 0 9000 10 0 0 0 0 0 0\n"
            "  eth1: 500 5 0 0 0 0 0 0 250 2 0 0 0 0 0 0\n"
        )
        self.assertEqual(agent.net_counters(dev), (1500, 2250))

    def test_a_rate_needs_two_readings_close_enough_together(self):
        megabyte = 1024 * 1024
        self.assertEqual(agent.rate_mbs(0, 60 * megabyte, 60), 1.0)
        # A reboot reset the counter: not a negative rate.
        self.assertIsNone(agent.rate_mbs(60 * megabyte, 0, 60))
        # A gap too long to call an average of: a suspended VM, or a client
        # that only runs when a visitor arrives.
        self.assertIsNone(agent.rate_mbs(0, 60 * megabyte, 301))
        self.assertIsNone(agent.rate_mbs(0, 60 * megabyte, 0))
        self.assertIsNone(agent.rate_mbs(None, 60 * megabyte, 60))


class PendingUpdates(unittest.TestCase):
    """What the server says is waiting to be installed. Nothing here installs
    anything, so the only risk is reading a count wrong."""

    def test_ubuntus_own_counter_is_all_and_security(self):
        # apt-check prints this on stderr, among whatever else it says.
        self.assertEqual(agent.parse_apt_check("WARNING: apt does not have a stable CLI\n31;7\n"), (31, 7))
        self.assertEqual(agent.parse_apt_check("0;0"), (0, 0))

    def test_a_counter_that_said_something_else_is_not_read_as_zero(self):
        for text in ["", "31", "no;thing", None, "E: could not open lock file"]:
            self.assertIsNone(agent.parse_apt_check(text))

    def test_a_simulation_counts_a_security_pocket_separately(self):
        text = (
            "Reading package lists...\n"
            "Inst libssl3 [3.0.2-0ubuntu1.15] (3.0.2-0ubuntu1.16 Ubuntu:24.04/noble-security [amd64])\n"
            "Inst curl [8.5.0-2] (8.5.0-2ubuntu10.1 Ubuntu:24.04/noble-updates [amd64])\n"
            "Inst linux-libc-dev [6.8.0-31] (6.8.0-45 Debian-Security:12/stable [amd64])\n"
            "Conf libssl3 (3.0.2-0ubuntu1.16 Ubuntu:24.04/noble-security [amd64])\n"
        )
        # Three to take, two of them security. Conf lines are the same packages again.
        self.assertEqual(agent.parse_apt_simulation(text), (3, 2))

    def test_a_server_with_nothing_waiting_is_not_confused_with_one_that_cannot_say(self):
        # A run that succeeded and listed nothing is a clean server.
        self.assertEqual(agent.parse_apt_simulation("Reading package lists...\n0 upgraded, 0 newly installed.\n"), (0, 0))
        # A run that never happened says nothing at all, and the check goes
        # out as "unknown" rather than as a pass nobody earned.
        self.assertIsNone(agent.parse_apt_simulation(None))

    def test_a_command_that_failed_is_not_an_answer(self):
        # apt-get prints its complaint and exits 100 when it can't take the
        # lock; reading that as "nothing to install" would call a server
        # behind on patches a clean one.
        self.assertIsNone(agent._run(["/bin/sh", "-c", "echo 'E: Could not get lock' >&2; exit 100"]))
        # Unless the caller said that code is an answer, which dnf needs.
        self.assertIsNotNone(agent._run(["/bin/sh", "-c", "exit 100"], ok=(0, 100)))
        self.assertIsNone(agent._run(["/definitely/not/a/program"]))

    def test_dnf_counts_its_table_and_stops_at_the_obsoleting_tail(self):
        text = (
            "Last metadata expiry check: 0:12:01 ago on Tue 21 Oct 2026.\n"
            "\n"
            "kernel.x86_64          6.1.0-22.el9      baseos\n"
            "openssl-libs.x86_64    3.0.7-27.el9      baseos\n"
            "Obsoleting Packages\n"
            "gone.x86_64            1.0-1.el9         appstream\n"
        )
        self.assertEqual(agent.parse_dnf_check(text), 2)
        self.assertEqual(agent.parse_dnf_check(""), 0)


class ReviewFixes(unittest.TestCase):
    """What the 2026-10-26 review found: each case is a way the agent was wrong."""

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.patched = []

    def tearDown(self):
        for name, value in reversed(self.patched):
            setattr(agent, name, value)

    def patch(self, name, value):
        self.patched.append((name, getattr(agent, name)))
        setattr(agent, name, value)

    def write(self, name, body=b"x"):
        path = os.path.join(self.dir, name)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(body)
        return path

    def test_guest_time_is_not_counted_twice(self):
        # guest (column 9) is already inside user: 400 of the 800 busy jiffies.
        before = [1000, 0, 0, 8000, 0, 0, 0, 0, 0, 0]
        after = [1800, 0, 0, 8200, 0, 0, 0, 0, 400, 0]
        self.assertEqual(agent.cpu_percent(agent.cpu_times_of(before), agent.cpu_times_of(after)), 80.0)
        self.assertEqual(agent.cpu_shares(before, after)["cpu_user_pct"], 80.0)

    def test_udp_to_the_web_ports_is_checked_too(self):
        plan = agent.plan({"enabled": True, "mode": "block", "allow": [], "deny": ["198.51.100.7"]})
        ruleset = agent.nft_ruleset({"ports": [80, 443]}, plan)
        self.assertIn("meta l4proto != { tcp, udp } accept", ruleset)
        self.assertIn("udp dport != { 80, 443 } accept", ruleset)
        self.assertNotIn("meta l4proto != tcp accept", ruleset)

    def test_a_table_flushed_by_a_reboot_is_put_back(self):
        config = dict(agent.DEFAULTS, site_id="a" * 24, secret="s", endpoint="https://c.example",
                      state_dir=self.dir, sites=[], backend="nftables", ports=[80, 443])
        applied = []
        rules = {"v": 1, "enabled": True, "mode": "block", "sync": 60, "deny": ["198.51.100.7"]}
        self.patch("fetch_rules", lambda config, etag, **_: (None, etag))
        self.patch("nft_apply", lambda config, p: applied.append(p) or True)
        self.patch("nft_counters", lambda: {})
        present = {"value": True}
        self.patch("nft_table_present", lambda table=agent.TABLE: present["value"])
        self.patch("nft", lambda *args, stdin=None: agent.subprocess.CompletedProcess(args, 0, "", ""))
        self.patch("nginx_installed", lambda config: False)
        firewall = agent.Agent(config)
        firewall.rules = rules
        firewall.step()
        self.assertEqual(len(applied), 1)
        firewall.step()
        self.assertEqual(len(applied), 1, "unchanged rules with the table in place are left alone")
        present["value"] = False
        firewall.step()
        self.assertEqual(len(applied), 2, "the saved digest alone doesn't prove the table is there")

    def test_an_include_is_read_where_it_stands(self):
        files = {
            "/etc/ssh/sshd_config": "Include /etc/ssh/sshd_config.d/*.conf\nPasswordAuthentication yes\nPort 22\n",
            "/etc/ssh/sshd_config.d/50-cloud.conf": "PasswordAuthentication no\n",
        }
        self.patch("read_text", lambda path, *_: files.get(path, ""))
        real_glob = agent.glob.glob
        agent.glob.glob = lambda pattern: [p for p in files if p.startswith(pattern.split("*")[0]) and p != "/etc/ssh/sshd_config"]
        try:
            values = agent.sshd_settings()
        finally:
            agent.glob.glob = real_glob
        self.assertEqual(values["passwordauthentication"], "no")
        self.assertEqual(values["port"], "22")

    def test_files_the_scan_did_not_reach_are_not_deleted(self):
        here = self.write("site/kept.php")
        gone = os.path.join(self.dir, "site", "gone.php")
        baseline = {here: ["h", 1, 1], gone: ["h", 1, 1]}
        # A truncated scan: neither is in current, but only one is off the disk.
        changes = agent.file_changes(baseline, {os.path.join(self.dir, "site", "other.php"): ["h", 1, 1]},
                                     roots=[os.path.join(self.dir, "site")])
        deleted = [c["path"] for c in changes if c["change"] == "deleted"]
        self.assertEqual(deleted, [gone])

    def test_a_root_that_read_as_empty_is_not_everything_deleted(self):
        unmounted = os.path.join(self.dir, "share")
        baseline = {os.path.join(unmounted, "a.php"): ["h", 1, 1], os.path.join(unmounted, "b.php"): ["h", 1, 1]}
        self.assertEqual(agent.file_changes(baseline, {}, roots=[unmounted]), [])

    def test_excluding_a_folder_does_not_skip_its_namesakes(self):
        self.write("www/app/dump.sql")
        self.write("www/app-backup/dump.sql")
        exposure, _, _, _ = agent.scan_posture([os.path.join(self.dir, "www")], [os.path.join(self.dir, "www", "app")])
        paths = [e["path"] for e in exposure]
        self.assertIn("app-backup/dump.sql", paths)
        self.assertNotIn("app/dump.sql", paths)

    def test_resources_switched_off_keep_one_row(self):
        config = dict(agent.DEFAULTS, site_id="a" * 24, secret="s", endpoint="https://c.example",
                      state_dir=self.dir, sites=[])
        checks = agent.Resources(config)
        checks.enabled = False
        checks.rows = {"2026-10-20T12:00:00Z": {"minute": "2026-10-20T12:00:00Z"}}
        checks.last_at -= 120
        checks.sample()
        self.assertEqual(len(checks.rows), 1)
        self.assertNotIn("2026-10-20T12:00:00Z", checks.rows)


class AppsRepoNames(unittest.TestCase):
    """A remote's URL can carry a token: only owner/name may leave the machine."""

    def test_every_shape_of_remote_comes_down_to_owner_and_name(self):
        cases = {
            "git@github.com:acme/shop.git": "acme/shop",
            "https://github.com/acme/shop.git": "acme/shop",
            "https://github.com/acme/shop": "acme/shop",
            "https://github.com/acme/shop.git/": "acme/shop",
            "ssh://git@github.com/acme/shop.git": "acme/shop",
            "ssh://git@gitlab.com:2222/group/sub/repo.git": "group/sub/repo",
            "https://oauth2:glpat-SECRET@gitlab.example.com/group/sub/repo.git": "group/sub/repo",
            "https://x-access-token:ghp_SECRET@github.com/acme/shop.git": "acme/shop",
            "https://ghp_SECRET@github.com/acme/shop.git": "acme/shop",
            "https://user:pa/ss@word@github.com/acme/shop.git": "acme/shop",
            "https://github.com/acme/shop.git?access_token=SECRET": "acme/shop",
            "deploy:SECRET@github.com:acme/shop.git": "acme/shop",
        }
        for url, want in cases.items():
            self.assertEqual(agent.repo_name(url), want, url)

    def test_the_host_is_sent_without_user_password_or_port(self):
        cases = {
            "https://github.com/acme/shop": "github.com",
            "ssh://git@gitlab.com:2222/group/sub/repo.git": "gitlab.com",
            "https://oauth2:glpat-SECRET@GitLab.Example.com/group/sub/repo.git": "gitlab.example.com",
            "https://user:pa/ss@word@github.com/acme/shop.git": "github.com",
            "deploy:SECRET@github.com:acme/shop.git": "github.com",
            "git@bitbucket.org:acme/shop.git": "bitbucket.org",
        }
        for url, want in cases.items():
            self.assertEqual(agent.repo_host(url), want, url)
        for url in ("/srv/git/shop.git", "file:///srv/git/shop.git", "", None, "https://localhost/acme/shop"):
            self.assertIsNone(agent.repo_host(url), url)

    def test_nothing_that_is_not_owner_and_name_gets_through(self):
        for url in ("/srv/git/shop.git", "../shop", "file:///srv/git/shop.git", "https://github.com",
                    "https://github.com/shop", "", None, "https://host/a b/c", "git@host:"):
            self.assertIsNone(agent.repo_name(url), url)


class AppsGit(unittest.TestCase):
    """What a git folder is reported as, with git itself stubbed."""

    HEAD = "a" * 40
    REMOTE = "b" * 40

    def setUp(self):
        self.dir = tempfile.mkdtemp()
        os.makedirs(os.path.join(self.dir, "shop", ".git"))
        self.folder = os.path.join(self.dir, "shop")
        self.calls = []
        self.answers = {}
        self.real = agent._command
        agent._command = self.fake

    def tearDown(self):
        agent._command = self.real

    def fake(self, args, env=None, cwd=None, timeout=None):
        self.calls.append((list(args), env))
        git = args[args.index("git") + 3:] if "git" in args else args
        for key, answer in self.answers.items():
            if " ".join(git).startswith(key):
                return answer
        return 1, ""

    def repo(self, remote=REMOTE, local=True, ancestor=True, ahead=False):
        self.answers = {
            "rev-parse HEAD": (0, self.HEAD + "\n"),
            "rev-parse --abbrev-ref HEAD": (0, "main\n"),
            "config --get branch.main.remote": (0, "origin\n"),
            "config --get branch.main.merge": (0, "refs/heads/main\n"),
            "config --get remote.origin.url": (0, "https://x-access-token:ghp_SECRET@github.com/acme/shop.git\n"),
            "log -1": (0, "Fix checkout\x001762160000\n"),
            "ls-remote origin refs/heads/main": (0, "%s\trefs/heads/main\n" % remote) if remote else (128, ""),
            "cat-file -e": (0, "") if local else (128, ""),
            "merge-base --is-ancestor %s %s" % (self.HEAD, self.REMOTE): (0 if ancestor else 1, ""),
            "merge-base --is-ancestor %s %s" % (self.REMOTE, self.HEAD): (0 if ahead else 1, ""),
            "rev-list --count": (0, "3\n"),
        }

    def app(self, checks=None):
        return agent.git_app(self.folder, {} if checks is None else checks, 1762160000)

    def test_behind_counts_the_commits(self):
        self.repo()
        app = self.app()
        self.assertEqual((app["state"], app["behind"]), ("behind", 3))
        self.assertEqual(app["remote"]["version"], self.REMOTE)
        self.assertEqual((app["version"], app["branch"], app["repo"]), (self.HEAD, "main", "acme/shop"))
        self.assertEqual((app["message"], app["committed_at"]), ("Fix checkout", "2025-11-03T08:53:20Z"))
        self.assertNotIn("SECRET", json.dumps(app))

    def test_the_other_states(self):
        for setup, want in (
            (dict(remote=self.HEAD), "current"),
            (dict(local=False), "newer_remote"),
            (dict(ancestor=False, ahead=True), "ahead"),
            (dict(ancestor=False, ahead=False), "diverged"),
        ):
            self.repo(**setup)
            app = self.app()
            self.assertEqual(app["state"], want, setup)
            self.assertNotIn("behind", app)
            self.assertIsNotNone(app["remote"])

    def test_a_failed_check_or_no_upstream_is_unknown_with_no_remote(self):
        self.repo(remote=None)
        app = self.app()
        self.assertEqual((app["state"], app["remote"]), ("unknown", None))
        self.repo()
        self.answers["cat-file -e"] = (None, "")  # timed out
        self.assertEqual(self.app()["state"], "unknown")
        self.repo()
        self.answers["config --get branch.main.remote"] = (1, "")
        app = self.app()
        self.assertEqual((app["state"], app["remote"]), ("unknown", None))

    def test_a_folder_git_cannot_read_is_not_an_app(self):
        self.repo()
        self.answers["rev-parse HEAD"] = (128, "")
        self.assertIsNone(self.app())

    def test_the_remote_is_asked_at_most_hourly(self):
        self.repo()
        checks = {}
        agent.git_app(self.folder, checks, 1000)
        agent.git_app(self.folder, checks, 1000 + agent.APPS_REMOTE_EVERY - 1)
        asked = [c for c, _ in self.calls if "ls-remote" in c]
        self.assertEqual(len(asked), 1)
        agent.git_app(self.folder, checks, 1000 + agent.APPS_REMOTE_EVERY)
        self.assertEqual(len([c for c, _ in self.calls if "ls-remote" in c]), 2)

    def test_a_pull_asks_the_remote_again_rather_than_reading_ahead(self):
        # Checked while on the old commit, then pulled: the remote seen an
        # hour ago is now an ancestor of HEAD, which is not "ahead".
        self.repo(remote=self.HEAD)
        checks = {}
        old = self.HEAD
        agent.git_app(self.folder, checks, 1000)
        self.answers["rev-parse HEAD"] = (0, self.REMOTE + "\n")
        self.answers["ls-remote origin refs/heads/main"] = (0, "%s\trefs/heads/main\n" % self.REMOTE)
        app = agent.git_app(self.folder, checks, 1060)
        self.assertEqual(app["state"], "current")
        self.assertEqual(len([c for c, _ in self.calls if "ls-remote" in c]), 2)
        self.assertNotEqual(old, self.REMOTE)

    def test_git_only_reads_and_never_prompts(self):
        for setup in (dict(), dict(local=False), dict(ancestor=False), dict(remote=None)):
            self.repo(**setup)
            self.app()
        self.assertTrue(self.calls)
        for args, env in self.calls:
            git = args[args.index("git"):]
            self.assertEqual(git[1:3], ["-C", self.folder])
            self.assertIn(git[3], agent.GIT_READS, args)
            for word in ("fetch", "pull", "push", "checkout", "reset", "gc", "clone", "merge", "remote"):
                self.assertNotIn(word, git[3:4], args)
            if git[3] == "config":
                self.assertEqual(git[4], "--get")
            self.assertEqual(env["GIT_TERMINAL_PROMPT"], "0")
            self.assertIn("BatchMode=yes", env["GIT_SSH_COMMAND"])

    def test_a_command_that_writes_is_refused_before_it_runs(self):
        owner = ("root", "/root")
        for args in (("fetch", "origin"), ("pull",), ("config", "user.name", "x"), ("gc",), ()):
            self.assertEqual(agent.git(self.folder, owner, *args), (None, ""))
        self.assertEqual(self.calls, [])

    def test_git_runs_as_the_folders_owner(self):
        self.repo()
        with mock.patch.object(agent.os, "geteuid", return_value=0), \
                mock.patch.object(agent, "folder_owner", return_value=("deploy", "/home/deploy")):
            self.app()
        args, env = self.calls[0]
        self.assertEqual(args[:4], ["runuser", "-u", "deploy", "--"])
        self.assertEqual(env["HOME"], "/home/deploy")

    def test_an_upstream_that_looks_like_an_option_is_not_used(self):
        self.repo()
        self.answers["config --get branch.main.remote"] = (0, "--upload-pack=touch /tmp/x\n")
        app = self.app()
        self.assertEqual(app["state"], "unknown")
        self.assertFalse([c for c, _ in self.calls if "ls-remote" in c])


class AppsFinding(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()

    def repo(self, *parts):
        path = os.path.join(self.dir, *parts)
        os.makedirs(os.path.join(path, ".git"))
        return path

    def test_work_trees_two_levels_down_and_the_listed_ones(self):
        shop = self.repo("www", "shop")
        deep = self.repo("www", "a", "b")
        self.repo("www", "a", "b", "c", "too-deep")
        self.repo("www", "x", "y", "too-deep")
        self.repo("www", "node_modules", "pkg")
        self.repo("www", "a", "vendor")
        listed = self.repo("opt", "far", "away", "api")
        found = agent.git_folders([os.path.join(self.dir, "www")], [listed, shop])
        self.assertEqual(sorted(found), sorted([shop, deep, listed]))

    def test_names_are_unique_and_safe(self):
        apps = [{"kind": "git", "path": "/var/www/a/current"}, {"kind": "git", "path": "/var/www/b/current"},
                {"kind": "git", "path": "/srv/my shop!"}, {"kind": "docker", "name": "shop-api-1"},
                {"kind": "git", "path": "/srv/shop-api-1"}]
        names = [a["name"] for a in agent.name_apps(apps)]
        self.assertEqual(names, ["a/current", "b/current", "my-shop", "shop-api-1", "srv/shop-api-1"])
        names = [a["name"] for a in agent.name_apps([{"kind": "git", "path": "/a/x/current"}, {"kind": "git", "path": "/b/x/current"}])]
        self.assertEqual(names, ["x/current", "x/current-2"])

    def test_docker_goes_with_the_main_site_only_when_it_is_the_only_site(self):
        config = dict(agent.DEFAULTS, site_id="a" * 24, secret="s", endpoint="https://c.example", files_roots=[self.dir])
        with mock.patch.object(agent.shutil, "which", return_value="/usr/bin/docker"):
            self.assertTrue(agent.apps_sites(dict(config, sites=[]))[0]["docker_apps"])
            other = {"site_id": "b" * 24, "secret": "t", "files_roots": [], "files_exclude": [], "apps": ["/opt/x"]}
            sites = agent.apps_sites(dict(config, sites=[other]))
            self.assertEqual([s["docker_apps"] for s in sites], [False, False])
            self.assertEqual((sites[1]["site_id"], sites[1]["secret"], sites[1]["apps"]), ("b" * 24, "t", ["/opt/x"]))
            self.assertTrue(agent.apps_sites(dict(config, sites=[other], docker_apps=True))[0]["docker_apps"])

    def process(self, proc, pid, cwd, tty=0, ns="mnt:[1]", exe="/usr/bin/node"):
        base = os.path.join(proc, str(pid))
        os.makedirs(os.path.join(base, "ns"))
        with open(os.path.join(base, "stat"), "w") as f:
            f.write("%d (node (pm2) x) S 1 %d %d %d -1 4194560" % (pid, pid, pid, tty))
        os.symlink(cwd, os.path.join(base, "cwd"))
        os.symlink(exe, os.path.join(base, "exe"))
        os.symlink(ns, os.path.join(base, "ns", "mnt"))

    def proc(self):
        proc = os.path.join(self.dir, "proc")
        os.makedirs(os.path.join(proc, "self", "ns"))
        os.symlink("mnt:[1]", os.path.join(proc, "self", "ns", "mnt"))
        return proc

    def folder(self, *parts, files=("package.json",)):
        path = os.path.join(self.dir, *parts)
        os.makedirs(path, exist_ok=True)
        for name in files:
            with open(os.path.join(path, name), "w") as f:
                f.write("{}")
        return path

    def test_the_folders_running_services_were_started_in(self):
        proc = self.proc()
        api = self.repo("srv", "api")
        os.makedirs(os.path.join(api, "dist", "server"))
        web = self.repo("var", "www", "web")
        shell = self.repo("home", "me", "scratch")
        boxed = self.repo("app")
        os.makedirs(os.path.join(self.dir, "plain"))
        self.process(proc, 10, os.path.join(api, "dist", "server"))  # two folders below the work tree
        self.process(proc, 11, web, exe="/usr/sbin/nginx")  # a work tree counts whatever runs in it
        self.process(proc, 12, web)
        self.process(proc, 13, shell, tty=34816)  # someone's shell
        self.process(proc, 14, boxed, ns="mnt:[2]")  # a container
        self.process(proc, 15, os.path.join(self.dir, "plain"))
        self.process(proc, 16, "/")
        self.assertEqual(agent.running_apps(proc), (sorted([api, web]), []))
        self.assertEqual(agent.running_apps(os.path.join(self.dir, "none")), ([], []))

    def test_apps_copied_without_git(self):
        proc = self.proc()
        shop = self.folder("opt", "shop")
        os.makedirs(os.path.join(shop, "build"))
        java = self.folder("srv", "billing", files=("billing.jar",))
        data = self.folder("var", "lib", "db", files=("package.json",))
        bare = self.folder("srv", "bare", files=("index.js",))
        inner = self.folder("srv", "api", "worker")
        os.makedirs(os.path.join(self.dir, "srv", "api", ".git"))
        self.process(proc, 20, os.path.join(shop, "build"), exe="/usr/bin/node (deleted)")  # upgraded under it
        self.process(proc, 21, java, exe="/usr/lib/jvm/bin/java")
        self.process(proc, 22, data, exe="/usr/sbin/postgres")  # not an app runtime
        self.process(proc, 23, bare)  # no app files
        self.process(proc, 24, inner, exe="/usr/bin/python3.12")  # inside a work tree: that's the app
        git, plain = agent.running_apps(proc)
        self.assertEqual(git, [os.path.join(self.dir, "srv", "api")])
        self.assertEqual(plain, sorted([(shop, "node"), (java, "java")]))

    def test_a_folder_app_is_versioned_by_its_files(self):
        shop = self.folder("opt", "shop", files=("package.json", "server.js"))
        for name in ("app.log", "data.json"):
            with open(os.path.join(shop, name), "w") as f:
                f.write("x")
        os.makedirs(os.path.join(shop, "node_modules"))
        app = agent.folder_app(shop, "node")
        self.assertEqual((app["kind"], app["path"], app["runtime"]), ("folder", shop, "node"))
        self.assertRegex(app["version"], r"^[0-9a-f]{24}$")
        self.assertIn("changed_at", app)
        # A log or data file written changes nothing; a deploy does.
        for name in ("app.log", "data.json"):
            with open(os.path.join(shop, name), "a") as f:
                f.write("more")
        self.assertEqual(agent.folder_app(shop, "node")["version"], app["version"])
        with open(os.path.join(shop, "server.js"), "w") as f:
            f.write("changed")
        self.assertNotEqual(agent.folder_app(shop, "node")["version"], app["version"])
        self.assertIsNone(agent.folder_app(os.path.join(self.dir, "gone"), "node"))
        self.assertEqual([a["name"] for a in agent.name_apps([app])], ["shop"])

    def test_each_running_app_goes_to_the_site_whose_folder_it_is_in(self):
        config = dict(agent.DEFAULTS, site_id="a" * 24, secret="s", endpoint="https://c.example", files_roots=[])
        self.assertTrue(agent.apps_sites(dict(config, sites=[]))[0]["running_apps"])
        with mock.patch.object(agent.shutil, "which", return_value=None):
            self.assertEqual(agent.apps_sites(dict(config, sites=[], running_apps=False)), [])
        roots = [os.path.join(self.dir, "other")]
        other = {"site_id": "b" * 24, "secret": "t", "files_roots": roots, "files_exclude": [], "apps": []}
        main, second = agent.apps_sites(dict(config, sites=[other]))
        self.assertEqual((main["running_apps"], main["elsewhere"], main["within"]), (True, roots, None))
        self.assertEqual((second["site_id"], second["running_apps"], second["within"]), ("b" * 24, True, roots))
        mine, theirs = self.repo("srv", "api"), self.repo("other", "deep", "er", "shop")
        copied, copied_theirs = self.folder("opt", "shop"), self.folder("other", "copied")
        found = ([mine, theirs], [(copied, "node"), (copied_theirs, "python3")])
        with mock.patch.object(agent, "running_apps", return_value=found), \
                mock.patch.object(agent, "git_app", lambda folder, checks, now: {"kind": "git", "path": folder}):
            self.assertEqual([a["path"] for a in agent.collect_apps(main, {})], [mine, copied])
            self.assertEqual([a["path"] for a in agent.collect_apps(second, {})], [theirs, copied_theirs])


class AppsDocker(unittest.TestCase):
    def test_running_containers_with_their_image_and_revision(self):
        text = json.dumps([
            {"Name": "/shop-api-1", "Image": "sha256:" + "1" * 64,
             "State": {"Running": True, "StartedAt": "2026-11-03T09:40:00.123456789Z"},
             "Config": {"Image": "ghcr.io/acme/api:1.4.2", "Labels": {"org.opencontainers.image.revision": "c" * 40}}},
            {"Name": "/stopped", "Image": "sha256:" + "2" * 64, "State": {"Running": False}, "Config": {}},
            {"Name": "/db", "Image": "sha256:" + "3" * 64, "State": {"Running": True, "StartedAt": "0001-01-01T00:00:00Z"},
             "Config": {"Image": "postgres:16", "Labels": None}},
        ])
        apps = agent.docker_apps(text)
        self.assertEqual([a["name"] for a in apps], ["db", "shop-api-1"])
        api = apps[1]
        self.assertEqual(api, {"name": "shop-api-1", "kind": "docker", "version": "sha256:" + "1" * 64,
                               "image": "ghcr.io/acme/api:1.4.2", "revision": "c" * 40,
                               "started_at": "2026-11-03T09:40:00Z"})
        self.assertNotIn("revision", apps[0])
        self.assertNotIn("started_at", apps[0])

    def test_what_docker_did_not_say_is_nothing(self):
        for text in ("", "not json", "{}", "[1, null]"):
            self.assertEqual(agent.docker_apps(text), [])

    def test_the_digest_it_was_pulled_as(self):
        text = json.dumps([
            {"Name": "/db", "Image": "sha256:" + "1" * 64, "State": {"Running": True}, "Config": {"Image": "mongo:8.0.32-noble"}},
            {"Name": "/reg", "Image": "sha256:" + "2" * 64, "State": {"Running": True}, "Config": {"Image": "localhost:5000/acme/api:2"}},
            {"Name": "/built", "Image": "sha256:" + "3" * 64, "State": {"Running": True}, "Config": {"Image": "mine"}},
        ])
        images = json.dumps([
            {"Id": "sha256:" + "1" * 64, "RepoDigests": ["mongo@sha256:" + "a" * 64]},
            {"Id": "sha256:" + "2" * 64, "RepoDigests": ["other/name@sha256:" + "b" * 64, "localhost:5000/acme/api@sha256:" + "c" * 64]},
            {"Id": "sha256:" + "3" * 64, "RepoDigests": []},
        ])
        apps = {a["name"]: a for a in agent.docker_apps(text, images)}
        self.assertEqual(apps["db"]["digest"], "sha256:" + "a" * 64)
        self.assertEqual(apps["reg"]["digest"], "sha256:" + "c" * 64)
        self.assertNotIn("digest", apps["built"])
        self.assertEqual(agent.image_repo("localhost:5000/acme/api:2"), "localhost:5000/acme/api")
        self.assertEqual(agent.image_repo("mongo@sha256:" + "a" * 64), "mongo")


class AppsReporting(unittest.TestCase):
    """A change is reported at the next read; the same list waits for the hour."""

    def setUp(self):
        self.config = dict(agent.DEFAULTS, site_id="a" * 24, secret="s", endpoint="https://c.example", sites=[])
        self.list = [{"name": "shop", "kind": "git", "path": "/var/www/shop", "version": "a" * 40, "state": "current",
                      "remote": {"version": "a" * 40, "checked_at": "2026-11-03T10:00:00Z"}}]
        self.sent = []
        self.answer = (200, {}, b'{"v":1}')
        self.patches = [mock.patch.object(agent, "request", self.fake_request),
                        mock.patch.object(agent, "collect_apps", lambda site, checks, now=None: json.loads(json.dumps(self.list)))]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()

    def fake_request(self, config, method, path, body=None, headers=None):
        self.sent.append((path, body))
        return self.answer

    def test_a_changed_list_is_reported_and_an_unchanged_one_waits_for_the_hour(self):
        job, t = agent.Apps(self.config), 100000
        job.tick(t)
        self.assertEqual(len(self.sent), 1, "the first read is the baseline and goes straight away")
        path, body = self.sent[0]
        self.assertEqual(path, "/events/apps")
        self.assertEqual((body["v"], body["client"]), (1, "vps-agent/" + agent.VERSION))
        self.assertEqual(agent.VERSION, "0.9.0")
        for minutes in (1, 5, 10, 30):
            job.tick(t + minutes * 60)
        self.assertEqual(len(self.sent), 1, "nothing changed")
        # Only the time the remote was asked moved: not a change.
        self.list[0]["remote"]["checked_at"] = "2026-11-03T11:00:00Z"
        job.tick(t + 35 * 60)
        self.assertEqual(len(self.sent), 1)
        self.list[0]["version"] = "b" * 40
        job.tick(t + 39 * 60)
        self.assertEqual(len(self.sent), 1, "read every five minutes, not every second")
        job.tick(t + 40 * 60)
        self.assertEqual(len(self.sent), 2, "a new HEAD is reported at the next read")
        job.tick(t + 40 * 60 + agent.APPS_REPORT_EVERY - 1)
        self.assertEqual(len(self.sent), 2)
        job.tick(t + 40 * 60 + agent.APPS_REPORT_EVERY)
        self.assertEqual(len(self.sent), 3, "and at least hourly when nothing changes")

    def test_the_answers_every_is_followed_but_not_below_a_minute(self):
        job = agent.Apps(self.config)
        self.answer = (200, {}, b'{"v":1,"every":5}')
        job.tick(100000)
        self.assertEqual(job.every, 60)
        job.tick(100059)
        self.assertEqual(len(self.sent), 1)
        job.tick(100060)
        self.assertEqual(len(self.sent), 2)

    def test_a_failure_retries_later_and_never_raises(self):
        job = agent.Apps(self.config)
        self.answer = (0, {}, b"")
        job.tick(100000)
        job.tick(100001)
        job.tick(100100)
        self.assertEqual(len(self.sent), 1, "not resent every second")
        self.answer = (200, {}, b"not json")
        job.tick(100000 + agent.RETRY * 5)
        self.assertEqual(len(self.sent), 2)
        self.assertEqual(job.sent, job.read_print)
        with mock.patch.object(agent, "collect_apps", side_effect=RuntimeError("boom")):
            job.next_read = 0
            job.tick(200000)  # logged, not raised


class ServicesConfig(unittest.TestCase):
    """What the config's "services" list may hold: anything else is skipped
    with a line in the log, never a stopped agent."""

    def test_each_kind_of_check(self):
        with mock.patch.object(agent, "log"):
            checks = agent.service_list([
                {"name": "redis", "tcp": 6379},
                {"name": "db", "tcp": "[::1]:5432"},
                {"name": "api", "http": "https://user:pw@127.0.0.1:3000/health?token=abc", "expect_ok": True},
                {"name": "worker", "unit": "worker"},
                {"name": "queue", "process": "celery"},
            ])
        self.assertEqual([(c["name"], c["type"], c["target"]) for c in checks], [
            ("redis", "tcp", "127.0.0.1:6379"),
            ("db", "tcp", "[::1]:5432"),
            ("api", "http", "https://127.0.0.1:3000/health"),
            ("worker", "unit", "worker.service"),
            ("queue", "process", "celery"),
        ])
        self.assertEqual((checks[0]["host"], checks[1]["host"]), ("127.0.0.1", "::1"))
        self.assertTrue(checks[2]["expect_ok"])
        self.assertEqual(checks[2]["url"], "https://user:pw@127.0.0.1:3000/health?token=abc", "the check itself keeps the whole address")

    def test_what_is_not_a_check_is_skipped(self):
        with mock.patch.object(agent, "log") as logged:
            checks = agent.service_list([
                "redis", {"name": "x"}, {"tcp": 0}, {"tcp": "host:99999"}, {"http": "ftp://x"},
                {"unit": "a;rm -rf /"}, {"unit": "--now"}, {"process": "/usr/bin/x"},
                {"name": "ok", "tcp": 80}, {"name": "OK", "tcp": 81},
            ])
        self.assertEqual([c["name"] for c in checks], ["ok"], "a second check of the same name is skipped too")
        self.assertEqual(logged.call_count, 9)
        self.assertEqual(agent.service_list(None), [])


class ServiceChecks(unittest.TestCase):
    """Each kind of check, against the real thing on this machine."""

    def test_tcp(self):
        import socket as sock
        server = sock.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        try:
            ok, detail, ms = agent.check_tcp("127.0.0.1", port)
            self.assertEqual((ok, detail), (True, ""))
            self.assertIsInstance(ms, int)
        finally:
            server.close()
        ok, detail, ms = agent.check_tcp("127.0.0.1", port)
        self.assertFalse(ok)
        self.assertTrue(detail)
        self.assertIsNone(ms)

    def test_http(self):
        import http.server
        import threading

        answers = {"/health": (200, b'{"ok": true}'), "/sick": (200, b'{"ok": false}'), "/moved": (302, b""),
                   "/broken": (503, b"")}

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                status, body = answers[self.path]
                self.send_response(status)
                if status == 302:
                    self.send_header("Location", "http://198.51.100.1/elsewhere")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        base = "http://127.0.0.1:%d" % server.server_port
        try:
            self.assertTrue(agent.check_http(base + "/health", True)[0])
            self.assertTrue(agent.check_http(base + "/sick")[0], "without expect_ok any 2xx is up")
            self.assertEqual(agent.check_http(base + "/sick", True)[:2], (False, 'Answered 200 without "ok": true'))
            self.assertTrue(agent.check_http(base + "/moved")[0], "a redirect is an answer, and isn't followed")
            self.assertEqual(agent.check_http(base + "/broken")[:2], (False, "Answered 503"))
        finally:
            server.shutdown()
            server.server_close()
        self.assertFalse(agent.check_http(base + "/health", timeout=1)[0])

    def test_process_names_come_from_proc(self):
        with tempfile.TemporaryDirectory() as proc:
            for pid, comm, cmdline in (("1", "systemd\n", "/sbin/init\0"), ("42", "node\n", "/usr/bin/pm2-runtime\0app.js\0"),
                                       ("self", "x", "x")):
                os.makedirs(os.path.join(proc, pid))
                with open(os.path.join(proc, pid, "comm"), "w") as f:
                    f.write(comm)
                with open(os.path.join(proc, pid, "cmdline"), "w") as f:
                    f.write(cmdline)
            self.assertEqual(agent.running_processes(proc), {"systemd", "init", "node", "pm2-runtime"})


class ServicesParsing(unittest.TestCase):
    def test_units_worth_a_light(self):
        text = "\n".join([
            "redis-server.service loaded active running Advanced key-value store",
            "postgresql.service loaded active exited PostgreSQL RDBMS",
            "postgresql@16-main.service loaded failed failed PostgreSQL Cluster 16-main",
            "php8.3-fpm.service loaded active running The PHP 8.3 FastCGI Process Manager",
            "nginx.service not-found inactive dead nginx.service",
            "ssh.service loaded active running OpenBSD Secure Shell server",
        ])
        self.assertEqual(agent.parse_unit_list(text), ["php8.3-fpm.service", "postgresql@16-main.service", "redis-server.service"])

    def test_unit_show_blocks(self):
        text = "Id=redis-server.service\nActiveState=active\nSubState=running\nUnitFileState=enabled\nLoadState=loaded\n\n" \
               "Id=worker.service\nActiveState=failed\nSubState=failed\nUnitFileState=disabled\nLoadState=loaded\n"
        units = agent.parse_unit_show(text)
        self.assertEqual(agent.unit_result("redis-server.service", units["redis-server.service"]), (True, ""))
        self.assertEqual(agent.unit_result("worker.service", units["worker.service"]), (False, "failed"))
        self.assertEqual(agent.unit_result("gone.service", {"Id": "gone.service", "LoadState": "not-found"}), (False, "No such unit"))
        self.assertEqual(agent.unit_result("x.service", {"ActiveState": "inactive", "SubState": "dead"}), (False, "inactive (dead)"))

    def test_containers(self):
        found = agent.parse_containers("db\trunning\tUp 3 hours (healthy)\nqueue\trunning\tUp 2 minutes (unhealthy)\n"
                                       "old\texited\tExited (137) 5 minutes ago\n")
        self.assertEqual(agent.container_result(*found["db"]), (True, ""))
        self.assertEqual(agent.container_result(*found["queue"]), (False, "Up 2 minutes (unhealthy)"))
        self.assertEqual(agent.container_result(*found["old"]), (False, "Exited (137) 5 minutes ago"))


class ServicesFound(unittest.TestCase):
    """What the agent finds on its own: shown while it runs or is set to
    start, and red, not missing, once it stops."""

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.config = dict(agent.DEFAULTS, site_id="a" * 24, secret="s", endpoint="https://c.example", sites=[],
                           state_dir=self.dir.name)
        self.units = {"redis-server.service": ("active", "running", "enabled"),
                      "nginx.service": ("inactive", "dead", "disabled")}
        self.containers = "db\trunning\tUp 3 hours\n"
        self.broken = set()
        self.calls = []
        # Every command "exists", so this machine's own cgroups and Podman
        # storage stay out of it: an empty tree and storage of the test's own.
        empty = os.path.join(self.dir.name, "empty")
        self.patches = [mock.patch.object(agent, "_command", self.fake_command),
                        mock.patch.object(agent.shutil, "which", lambda name: "/usr/bin/" + name),
                        mock.patch.object(agent, "CGROUP_ROOT", empty),
                        mock.patch.object(agent, "PODMAN_STORAGE", empty),
                        mock.patch.object(agent, "PODMAN_STORAGE_CONF", os.path.join(empty, "storage.conf"))]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        self.dir.cleanup()

    def fake_command(self, args, env=None, cwd=None, timeout=None):
        self.calls.append(args)
        if args[0] in self.broken:
            return None, ""
        if args[:2] == ["systemctl", "list-units"]:
            return 0, "".join("%s loaded %s %s x\n" % (u, a, s) for u, (a, s, _) in self.units.items())
        if args[:2] == ["systemctl", "show"]:
            wanted = args[args.index("--") + 1:]
            return 0, "\n".join("Id=%s\nActiveState=%s\nSubState=%s\nUnitFileState=%s\nLoadState=loaded\n" % ((u,) + self.units[u])
                                for u in wanted if u in self.units)
        if args[0] == "docker":
            return 0, self.containers
        return 1, ""

    def results(self, job, now):
        return {c["name"]: (c["ok"], c["detail"]) for c in job.run_checks(now)}

    def test_running_and_enabled_are_shown_and_a_stopped_one_goes_red(self):
        job = agent.Services(self.config)
        self.assertEqual(self.results(job, 1000), {"redis-server": (True, ""), "db": (True, "")},
                         "nginx is installed but neither runs nor starts at boot")
        self.units["redis-server.service"] = ("failed", "failed", "disabled")
        self.containers = "db\texited\tExited (1) 1 minute ago\n"
        self.assertEqual(self.results(job, 1060), {"redis-server": (False, "failed"), "db": (False, "Exited (1) 1 minute ago")})
        # Still red after a restart: when each last ran is kept in the state folder.
        again = agent.Services(self.config)
        self.assertEqual(self.results(again, 1120), {"redis-server": (False, "failed"), "db": (False, "Exited (1) 1 minute ago")})
        self.assertEqual(self.results(again, 1060 + agent.SERVICES_KEEP_GONE + 1), {}, "a week stopped and it isn't held against the site")

    def test_how_long_it_has_been_down_survives_a_restart(self):
        job = agent.Services(self.config)
        self.results(job, 1000)
        self.units["redis-server.service"] = ("failed", "failed", "disabled")
        self.results(job, 1060)
        again = agent.Services(self.config)
        down = {c["name"]: c["for_s"] for c in again.run_checks(1300)}
        self.assertEqual(down["redis-server"], 240, "a restart must not make it newly stopped (a removed one would come back)")

    def test_removed_altogether_goes_at_once(self):
        job = agent.Services(self.config)
        self.results(job, 1000)
        del self.units["redis-server.service"]
        self.containers = ""
        self.assertEqual(self.results(job, 1060), {}, "a unit uninstalled or a container taken down was meant")

    def test_a_read_that_failed_keeps_the_last_answer(self):
        job = agent.Services(self.config)
        first = self.results(job, 1000)
        self.broken = {"systemctl", "docker"}
        self.assertEqual(self.results(job, 1060), first)

    def test_listed_checks_go_first_and_detection_can_be_off(self):
        config = dict(self.config, services=[{"name": "redis", "unit": "redis-server"}], services_detect=False)
        job = agent.Services(config)
        checks = job.run_checks(1000)
        self.assertEqual([(c["name"], c["auto"]) for c in checks], [("redis", False)])
        self.assertFalse(any(args[:2] == ["systemctl", "list-units"] or args[0] == "docker" for args in self.calls))
        job = agent.Services(dict(config, services_detect=True))
        self.assertEqual([c["name"] for c in job.run_checks(1000)], ["redis", "db"], "a listed unit isn't found twice")

    def test_for_s_counts_from_the_last_change(self):
        job = agent.Services(self.config)
        job.run_checks(1000)
        self.assertEqual({c["name"]: c["for_s"] for c in job.run_checks(1300)}, {"redis-server": 300, "db": 300})
        self.units["redis-server.service"] = ("failed", "failed", "enabled")
        self.assertEqual({c["name"]: c["for_s"] for c in job.run_checks(1400)}["redis-server"], 0)

    def test_no_command_sees_a_config_string_through_a_shell(self):
        config = dict(self.config, services=[{"name": "x", "unit": "x$(id).service"}])
        with mock.patch.object(agent, "log"):
            job = agent.Services(config)
        self.assertEqual(job.listed, [], "a unit name with $ ( ) is refused before it reaches systemctl")
        job.run_checks(1000)
        for args in self.calls:
            self.assertIsInstance(args, list)


class ServicesReporting(unittest.TestCase):
    def setUp(self):
        self.config = dict(agent.DEFAULTS, site_id="a" * 24, secret="s", endpoint="https://c.example",
                           sites=[{"site_id": "b" * 24, "secret": "t", "files_roots": [], "apps": []}],
                           state_dir=tempfile.mkdtemp())
        self.sent = []
        self.checks = [{"name": "redis", "type": "unit", "target": "redis-server.service", "ok": True, "detail": "",
                        "ms": None, "auto": True, "for_s": 0}]

    def fake_request(self, config, method, path, body=None, headers=None):
        self.sent.append((config["site_id"], path, body))
        return 202, {}, b'{"v":1,"every":60}'

    def test_every_site_gets_each_round_and_an_empty_list_is_sent_once(self):
        job = agent.Services(self.config)
        with mock.patch.object(agent, "request", self.fake_request), \
                mock.patch.object(job, "run_checks", lambda now=None: list(self.checks)):
            job.tick(1000)
            self.assertEqual([(s, p) for s, p, _ in self.sent], [("a" * 24, "/events/services"), ("b" * 24, "/events/services")])
            body = self.sent[0][2]
            self.assertEqual((body["v"], body["client"], body["checks"]), (1, "vps-agent/" + agent.VERSION, self.checks))
            job.tick(1030)
            self.assertEqual(len(self.sent), 2, "a minute apart")
            self.checks = []
            job.tick(1060)
            self.assertEqual(len(self.sent), 4, "the empty list clears what the dashboard shows")
            job.tick(1120)
            self.assertEqual(len(self.sent), 4, "and isn't sent again")


class ServiceUsage(unittest.TestCase):
    """What each unit and container uses, from its own cgroup (services.md, "Usage")."""

    CID = "ab" * 32
    MB = 1024 * 1024

    def tree(self, files):
        root = tempfile.mkdtemp()
        for path, text in files.items():
            full = os.path.join(root, path)
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "w") as f:
                f.write(text)
        return root

    def v2_container(self, current, cpu_us, oom=0, limit="max"):
        place = "system.slice/docker-%s.scope/" % self.CID
        return {
            "cgroup.controllers": "cpu memory\n",
            place + "memory.current": "%d\n" % current,
            place + "memory.stat": "anon 1\ninactive_file %d\n" % (50 * self.MB),
            place + "memory.max": "%s\n" % limit,
            place + "memory.events": "low 0\noom 0\noom_kill %d\n" % oom,
            place + "cpu.stat": "usage_usec %d\nuser_usec 1\n" % cpu_us,
        }

    def test_container_ids_come_from_the_same_docker_ps(self):
        text = "db\trunning\tUp 3 hours\t%s\nodd\trunning\tUp\tnot-an-id\n" % self.CID
        self.assertEqual(agent.container_ids(text), {"db": self.CID})
        # The status parse ignores the extra column.
        self.assertEqual(agent.parse_containers(text)["db"], ("running", "Up 3 hours"))

    def test_both_docker_drivers_and_units_are_found_and_nothing_climbs_out(self):
        systemd = self.tree(self.v2_container(1, 1))
        self.assertEqual(agent.cgroup_dirs("container", self.CID, systemd)[2], 2)
        cgroupfs = self.tree({"cgroup.controllers": "", "docker/%s/memory.current" % self.CID: "1"})
        self.assertTrue(agent.cgroup_dirs("container", self.CID, cgroupfs)[0].endswith("docker/" + self.CID))
        unit = self.tree({"cgroup.controllers": "", "system.slice/redis-server.service/memory.current": "1"})
        self.assertIsNotNone(agent.cgroup_dirs("unit", "redis-server.service", unit))
        self.assertIsNone(agent.cgroup_dirs("unit", "../../etc", unit))
        self.assertIsNone(agent.cgroup_dirs("container", "../" + self.CID, unit))
        v1 = self.tree({"memory/docker/%s/memory.usage_in_bytes" % self.CID: "1", "cpuacct/docker/%s/cpuacct.usage" % self.CID: "1"})
        memory, cpu, version = agent.cgroup_dirs("container", self.CID, v1)
        self.assertEqual(version, 1)
        self.assertTrue(cpu.endswith("cpuacct/docker/" + self.CID))

    def test_memory_is_the_working_set_cpu_a_share_of_the_machine_and_kills_a_count(self):
        dirs = agent.cgroup_dirs("container", self.CID, self.tree(self.v2_container(300 * self.MB, 1000000, oom=1)))
        before = agent.cgroup_reading(dirs)
        dirs = agent.cgroup_dirs("container", self.CID, self.tree(self.v2_container(350 * self.MB, 7000000, oom=3, limit=512 * self.MB)))
        after = agent.cgroup_reading(dirs)
        # 6 s of CPU in 60 s on 4 cores is 2.5% of the machine.
        self.assertEqual(agent.usage_fields(before, after, 60, 4, 8000),
                         {"mem_mb": 300, "mem_limit_mb": 512, "cpu_pct": 2.5, "oom_kills": 2})
        # The first round has no pair: memory only, no CPU and no count.
        self.assertEqual(agent.usage_fields(None, before, 0, 4, 8000), {"mem_mb": 250})

    def test_no_limit_is_no_limit_and_a_reset_counter_says_nothing(self):
        reading = {"mem": 100 * self.MB, "limit": 9223372036854771712, "oom": 0, "cpu_us": 5}
        self.assertNotIn("mem_limit_mb", agent.usage_fields(None, reading, 0, 4, 8000))
        bigger = dict(reading, limit=16000 * self.MB)
        self.assertNotIn("mem_limit_mb", agent.usage_fields(None, bigger, 0, 4, 8000))
        later = dict(reading, oom=0, cpu_us=1)
        self.assertEqual(agent.usage_fields(dict(reading, oom=4), later, 60, 4, 8000), {"mem_mb": 100})

    def test_each_round_reads_afresh_and_never_resends_a_stale_figure(self):
        root = self.tree(self.v2_container(300 * self.MB, 1000000))
        config = dict(agent.DEFAULTS, site_id="a" * 24, secret="s", endpoint="https://c.example", state_dir=tempfile.mkdtemp())
        job = agent.Services(config)
        job.container_ids = {"db": self.CID}
        results = [{"name": "db", "type": "container", "target": "db", "ok": True},
                   {"name": "web", "type": "process", "target": "nginx", "ok": True}]
        job.attach_usage(results, 1000, root)
        self.assertEqual((results[0]["mem_mb"], results[0]["container_id"]), (250, self.CID[:12]))
        self.assertNotIn("cpu_pct", results[0])
        self.assertNotIn("mem_mb", results[1], "a process has no cgroup of its own")
        # The container is gone from the cgroup tree: last round's figures go too.
        stale = [dict(results[0])]
        job.attach_usage(stale, 1060, tempfile.mkdtemp())
        self.assertNotIn("mem_mb", stale[0])


class MachineLimits(unittest.TestCase):
    """The machine's half of resources.md's "Limits": kills, waiting time,
    refused connections and the connection table."""

    NETSTAT = ("TcpExt: SyncookiesSent ListenOverflows ListenDrops\nTcpExt: 0 %d 9\n"
               "IpExt: InNoRoutes\nIpExt: 0\n")
    PSI = "some avg10=1.50 avg60=%s avg300=0.10 total=123\nfull avg10=0.00 avg60=0.00 avg300=0.00 total=0\n"

    def files(self, oom=3, overflows=10, psi=True, conntrack=True):
        out = {"/proc/vmstat": "nr_free_pages 1\noom_kill %d\npgfault 2\n" % oom,
               "/proc/net/netstat": self.NETSTAT % overflows}
        if psi:
            out.update({"/proc/pressure/cpu": self.PSI % "12.34", "/proc/pressure/memory": self.PSI % "0.00",
                        "/proc/pressure/io": self.PSI % "140.0"})
        if conntrack:
            out.update({"/proc/sys/net/netfilter/nf_conntrack_count": "6000\n",
                        "/proc/sys/net/netfilter/nf_conntrack_max": "262144\n"})
        return out

    def reader(self, files):
        return lambda path, limit=65536: files.get(path, "")

    def test_each_reading(self):
        self.assertEqual(agent.vmstat_oom_kills("oom_kill 7\n"), 7)
        self.assertIsNone(agent.vmstat_oom_kills("nr_free_pages 1\n"), "a kernel before 4.13 has no count")
        self.assertEqual(agent.listen_overflows(self.NETSTAT % 42), 42)
        self.assertIsNone(agent.listen_overflows("TcpExt: A B\nTcpExt: 1 2\n"))
        self.assertEqual(agent.pressure_some(self.PSI % "12.34"), 12.3)
        self.assertEqual(agent.pressure_some(self.PSI % "140"), 100.0)
        self.assertIsNone(agent.pressure_some(""), "no PSI (psi=0): left out")
        self.assertEqual(agent.conntrack_pct(self.reader(self.files())), 2.3)
        self.assertIsNone(agent.conntrack_pct(self.reader({})))

    def test_counts_keep_their_whole_difference_and_a_reset_sends_nothing(self):
        before = agent.limits_counters(self.reader(self.files(oom=3, overflows=10)))
        after = agent.limits_counters(self.reader(self.files(oom=5, overflows=10)))
        fields = agent.limits_fields(before, after, self.reader(self.files()))
        self.assertEqual(fields, {"oom_kills": 2, "listen_drops": 0, "psi_cpu_pct": 12.3, "psi_mem_pct": 0.0,
                                  "psi_io_pct": 100.0, "conntrack_pct": 2.3})
        reset = agent.limits_counters(self.reader(self.files(oom=1, overflows=4)))
        fields = agent.limits_fields(after, reset, self.reader({}))
        self.assertEqual(fields, {}, "a counter that went down was reset, and a missing file is no reading")

    def test_the_sampler_puts_them_on_the_row_and_never_a_zero_it_did_not_read(self):
        files = self.files(oom=3, overflows=10)
        config = dict(agent.DEFAULTS, site_id="a" * 24, secret="s", endpoint="https://c.example",
                      state_dir=tempfile.mkdtemp(), sites=[])
        job = agent.Resources(config, reader=self.reader(files))
        files.update(self.files(oom=4, overflows=15))
        row = job.sample()
        self.assertEqual((row["oom_kills"], row["listen_drops"], row["psi_cpu_pct"]), (1, 5, 12.3))
        self.assertNotIn("proc_key", row, "the agent isn't a process of the app")
        bare = agent.Resources(config, reader=self.reader({}))
        row = bare.sample()
        for field in ("oom_kills", "listen_drops", "psi_cpu_pct", "psi_mem_pct", "psi_io_pct", "conntrack_pct"):
            self.assertNotIn(field, row, "%s must be absent, not zero" % field)


class OtherContainers(unittest.TestCase):
    """Podman's and Kubernetes' containers: found, named, and measured from
    their own cgroups (services.md, "Usage")."""

    A, B, C, D = "a1" * 32, "b2" * 32, "c3" * 32, "d4" * 32
    MB = 1024 * 1024

    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.root = os.path.join(self.dir.name, "cgroup")
        self.storage = os.path.join(self.dir.name, "storage")
        os.makedirs(self.root)
        self.write("cgroup/cgroup.controllers", "cpu memory\n")
        self.crictl = None
        self.patches = [mock.patch.object(agent, "_command", self.fake_command),
                        mock.patch.object(agent.shutil, "which", lambda name: "/usr/bin/" + name if name in ("podman", "crictl") else None),
                        mock.patch.object(agent, "CGROUP_ROOT", self.root),
                        mock.patch.object(agent, "PODMAN_STORAGE", self.storage),
                        mock.patch.object(agent, "PODMAN_STORAGE_CONF", os.path.join(self.dir.name, "storage.conf"))]
        for p in self.patches:
            p.start()
        self.config = dict(agent.DEFAULTS, site_id="a" * 24, secret="s", endpoint="https://c.example", sites=[],
                           state_dir=self.dir.name)

    def tearDown(self):
        for p in self.patches:
            p.stop()
        self.dir.cleanup()

    def write(self, rel, text):
        path = os.path.join(self.dir.name, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(text)

    def fake_command(self, args, env=None, cwd=None, timeout=None):
        if args[:2] == ["crictl", "ps"] and self.crictl is not None:
            return 0, self.crictl
        if args[:2] == ["crictl", "pods"] and getattr(self, "pods", None) is not None:
            return 0, self.pods
        return 1, ""

    def cgroup(self, rel, mem_mb=100, cpu_us=1000):
        self.write("cgroup/%s/memory.current" % rel, "%d\n" % (mem_mb * self.MB))
        self.write("cgroup/%s/memory.stat" % rel, "inactive_file 0\n")
        self.write("cgroup/%s/memory.max" % rel, "max\n")
        self.write("cgroup/%s/cpu.stat" % rel, "usage_usec %d\n" % cpu_us)

    def test_the_walk_finds_each_layout_and_only_whole_ids(self):
        self.cgroup("machine.slice/libpod-%s.scope" % self.A)
        self.cgroup("machine.slice/libpod-conmon-%s.scope" % self.B)
        self.cgroup("user.slice/user-1000.slice/user@1000.service/user.slice/libpod-%s.scope" % self.B)
        self.cgroup("kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1234_5678.slice/cri-containerd-%s.scope" % self.C)
        self.cgroup("kubepods/pod9999/%s" % self.D)
        self.cgroup("kubepods/pod9999/%s-x" % ("e5" * 32))
        found = agent.container_cgroups(self.root)
        self.assertEqual(set(found), {self.A, self.B, self.C, self.D})
        self.assertTrue(found[self.B].startswith("user.slice/"), "the conmon scope is the runtime's, not the container")
        for cid in (self.A, self.B, self.C, self.D):
            memory, cpu, version = agent.cgroup_dirs("container", cid)
            self.assertEqual((version, memory), (2, os.path.join(self.root, found[cid])))

    def test_cgroup_v1_finds_them_under_each_controller(self):
        root = os.path.join(self.dir.name, "v1")
        rel = "kubepods.slice/kubepods-pod1.slice/crio-%s.scope" % self.C
        self.write("v1/memory/%s/memory.usage_in_bytes" % rel, "1")
        self.write("v1/cpu,cpuacct/%s/cpuacct.usage" % rel, "1")
        memory, cpu, version = agent.cgroup_dirs("container", self.C, root)
        self.assertEqual(version, 1)
        self.assertTrue(memory.endswith("memory/" + rel) and cpu.endswith("cpu,cpuacct/" + rel))

    def test_podman_containers_are_red_when_stopped_and_go_when_removed(self):
        self.write("storage/overlay-containers/containers.json",
                   json.dumps([{"id": self.A, "names": ["db"]}, {"id": self.B, "names": ["cache"]},
                               {"id": "nothex", "names": ["odd"]}]))
        self.cgroup("machine.slice/libpod-%s.scope" % self.A, mem_mb=300)
        job = agent.Services(self.config)
        checks = {c["name"]: c for c in job.run_checks(1000)}
        self.assertEqual(set(checks), {"db"}, "cache never ran, so it was never worth a light")
        self.assertEqual((checks["db"]["type"], checks["db"]["ok"], checks["db"]["mem_mb"], checks["db"]["container_id"]),
                         ("container", True, 300, self.A[:12]))
        os.rename(os.path.join(self.root, "machine.slice/libpod-%s.scope" % self.A), os.path.join(self.dir.name, "gone"))
        checks = {c["name"]: c for c in job.run_checks(1060)}
        self.assertEqual((checks["db"]["ok"], checks["db"]["detail"]), (False, "Not running"))
        self.assertNotIn("mem_mb", checks["db"])
        self.write("storage/overlay-containers/containers.json", json.dumps([{"id": self.B, "names": ["cache"]}]))
        self.assertEqual(job.run_checks(1120), [], "podman rm was meant")

    def test_a_rootless_users_containers_are_named_after_them(self):
        home = os.path.join(self.dir.name, "home")
        self.write("home/.local/share/containers/storage/overlay-containers/containers.json",
                   json.dumps([{"id": self.B, "names": ["web"]}]))
        self.cgroup("user.slice/user-1000.slice/user@1000.service/user.slice/libpod-%s.scope" % self.B, mem_mb=50)
        account = SimpleNamespace(pw_name="alice", pw_dir=home, pw_uid=os.getuid())
        with mock.patch.object(agent.pwd, "getpwuid", lambda uid: account):
            job = agent.Services(self.config)
            checks = job.run_checks(1000)
            self.assertEqual([(c["name"], c["ok"], c["mem_mb"]) for c in checks], [("alice/web", True, 50)])
            self.assertEqual(job.podman_users, {1000})
            # Stopped: the cgroup is gone, but the user is remembered, across a restart too.
            os.rename(os.path.join(self.root, "user.slice"), os.path.join(self.dir.name, "gone"))
            again = agent.Services(self.config)
            self.assertEqual([(c["name"], c["ok"]) for c in again.run_checks(1060)], [("alice/web", False)])

    def test_kubernetes_containers_are_the_latest_attempt_of_each(self):
        rel = "kubepods.slice/kubepods-besteffort.slice/kubepods-besteffort-poduid.slice/cri-containerd-%s.scope" % self.D
        self.cgroup(rel, mem_mb=80)

        def entry(cid, attempt, state, name="app"):
            return {"id": cid, "metadata": {"name": name, "attempt": attempt}, "state": state, "createdAt": str(attempt),
                    "labels": {"io.kubernetes.pod.name": "web-7d9f-x2x9k", "io.kubernetes.pod.namespace": "shop",
                               "io.kubernetes.container.name": name}}
        self.crictl = json.dumps({"containers": [entry(self.C, 0, "CONTAINER_EXITED"), entry(self.D, 1, "CONTAINER_RUNNING"),
                                                 {"id": self.A, "state": "CONTAINER_RUNNING"}]})
        job = agent.Services(self.config)
        checks = job.run_checks(1000)
        self.assertEqual([(c["name"], c["ok"], c["mem_mb"], c["container_id"]) for c in checks],
                         [("shop/web-7d9f-x2x9k/app", True, 80, self.D[:12])])
        self.crictl = json.dumps({"containers": [entry(self.D, 1, "CONTAINER_EXITED")]})
        self.assertEqual([(c["ok"], c["detail"]) for c in job.run_checks(1060)], [(False, "Exited")],
                         "a container waiting to be restarted is red, not missing")
        self.crictl = "not json"
        self.assertEqual([c["name"] for c in job.run_checks(1120)], ["shop/web-7d9f-x2x9k/app"],
                         "a read that failed keeps the last answer")

    def test_a_container_docker_already_lists_is_not_listed_twice(self):
        self.write("storage/overlay-containers/containers.json", json.dumps([{"id": self.A, "names": ["db"]}]))
        self.cgroup("machine.slice/libpod-%s.scope" % self.A)
        job = agent.Services(self.config)
        sources, ids = job.other_containers({"db": self.A}, {})
        self.assertEqual(sources["podman"], ({}, True))
        self.assertEqual(sources["k8s"], ({}, True), "no kubepods cgroup: crictl isn't asked")

    def test_a_fifo_where_a_file_should_be_is_not_read(self):
        path = os.path.join(self.dir.name, "fifo")
        os.mkfifo(path)
        self.assertIsNone(agent.read_regular(path, 100))

    def test_units_come_first_and_kubernetes_last_since_only_fifty_are_sent(self):
        job = agent.Services(self.config)
        keys = job.found(1000, [("k8s:a/b/c", True, False), ("podman:p", True, False), ("unit:redis.service", True, False),
                                ("container:x", True, False)], set())
        self.assertEqual(keys, ["unit:redis.service", "container:x", "podman:p", "k8s:a/b/c"])

    def test_a_users_file_is_read_only_when_they_own_it(self):
        path = os.path.join(self.dir.name, "mine")
        self.write("mine", "[]")
        self.assertEqual(agent.read_regular(path, 100, owner=os.getuid()), "[]")
        self.assertIsNone(agent.read_regular(path, 100, owner=os.getuid() + 1),
                          "a symlink or hard link to someone else's file is not theirs to make root read")
        storage = os.path.join(self.dir.name, "theirs")
        self.write("theirs/overlay-containers/containers.json", json.dumps([{"id": self.A, "names": ["db"]}]))
        self.assertEqual(agent.podman_containers(storage, owner=os.getuid() + 1), {}, "as good as no file")

    def test_the_walk_stops_at_its_bound(self):
        for i in range(30):
            self.cgroup("user.slice/user-%d.slice/x" % i)
        self.cgroup("user.slice/user-99.slice/libpod-%s.scope" % self.A)
        self.assertEqual(set(agent.container_cgroups(self.root)), {self.A})
        with mock.patch.object(agent, "CGROUP_WALK_MAX", 20):
            agent.container_cgroups(self.root)  # returns, whatever it found by then

    def test_cri_o_and_buildah_containers_in_the_storage_are_not_podmans(self):
        self.write("storage/overlay-containers/containers.json", json.dumps([
            {"id": self.D, "names": ["odd"], "big-data-names": 5, "metadata": 7},
            {"id": self.A, "names": ["db"], "metadata": json.dumps({"image-name": "redis", "name": "db"})},
            {"id": self.B, "names": ["k8s_app_web"], "metadata": json.dumps({"pod-name": "web", "pod-id": "x"})},
            {"id": self.C, "names": ["alpine-working-container"], "big-data-names": ["buildah.json"]}]))
        self.assertEqual(agent.podman_containers(self.storage), {self.A: "db", self.D: "odd"}, "an odd entry doesn't raise")

    def test_kubernetes_containers_are_not_podmans_too_and_a_finished_pod_is_left_out(self):
        self.write("storage/overlay-containers/containers.json", json.dumps([{"id": self.D, "names": ["k8s_app"]}]))
        self.cgroup("kubepods.slice/kubepods-pod1.slice/crio-%s.scope" % self.D)
        self.crictl = json.dumps({"containers": [
            {"id": self.D, "podSandboxId": "p1", "state": "CONTAINER_RUNNING", "metadata": {"name": "app"},
             "labels": {"io.kubernetes.pod.name": "web", "io.kubernetes.pod.namespace": "shop"}},
            {"id": self.C, "podSandboxId": "p2", "state": "CONTAINER_EXITED", "metadata": {"name": "job"},
             "labels": {"io.kubernetes.pod.name": "nightly-1", "io.kubernetes.pod.namespace": "shop"}},
            {"id": self.B, "podSandboxId": "p1", "state": "CONTAINER_EXITED", "metadata": {"name": "side"},
             "labels": {"io.kubernetes.pod.name": "web", "io.kubernetes.pod.namespace": "shop"}}]})
        self.pods = json.dumps({"items": [{"id": "p1", "state": "SANDBOX_READY"}, {"id": "p2", "state": "SANDBOX_NOTREADY"}]})
        sources, ids = agent.Services(self.config).other_containers({}, {})
        self.assertEqual(sources["k8s"][0], {"shop/web/app": ("running", "Running"), "shop/web/side": ("exited", "Exited")},
                         "a Job that finished is done, a sidecar in a pod still up is red")
        self.assertEqual(sources["podman"], ({}, True), "CRI-O's container is Kubernetes', not Podman's")

