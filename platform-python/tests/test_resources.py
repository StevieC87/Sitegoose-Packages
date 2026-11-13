"""The resources module: what is read from the machine, and the rule the whole
feature rests on - a reading this machine won't give is left out of the row,
never sent as a zero (sdk/protocols/resources.md).

    python3 -m unittest discover -s tests
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analytics_platform import resources as mod  # noqa: E402
from analytics_platform.resources import Resources  # noqa: E402

STAT = "cpu  100 10 50 1000 20 0 5 0 0 0\ncpu0 50 5 25 500 10 0 2 0 0 0\nintr 1\n"
MEMINFO = (
    "MemTotal:        8143868 kB\n"
    "MemFree:          210000 kB\n"
    "MemAvailable:    5021228 kB\n"
    "Cached:          4000000 kB\n"
    "SwapTotal:       2097152 kB\n"
    "SwapFree:        2084864 kB\n"
)


class Answer:
    def __init__(self, ok=True, status=202, body=None):
        self.ok = ok
        self.status = status
        self._body = body if body is not None else {"v": 1, "enabled": True, "every": 300, "stored": 1}

    def json(self):
        return self._body


class FakeCore:
    """A core that keeps what would be sent instead of sending it."""

    valid = False  # no background threads in tests; sample()/flush() are called directly

    def __init__(self, answer=None):
        self.site_id = "a" * 24
        self.sent = []
        self.on = True
        self.answer = answer if answer is not None else Answer()

    def is_on(self, _name):
        return self.on

    def log(self, *_args):
        pass

    def send(self, module, path, method="POST", body=None, auth="body", headers=None):
        self.sent.append({"module": module, "path": path, "auth": auth, "body": body})
        return self.answer


class Readings(unittest.TestCase):
    def test_cpu_needs_two_readings_and_ignores_idle(self):
        before = mod.cpu_times(STAT)
        self.assertEqual(before, (165, 1185))  # everything but idle + iowait
        self.assertIsNone(mod.cpu_percent(None, before))
        self.assertIsNone(mod.cpu_percent(before, before))
        after = (before[0] + 100, before[1] + 200)
        self.assertEqual(mod.cpu_percent(before, after), 50.0)
        # A counter that went backwards (a reboot) says nothing either.
        self.assertIsNone(mod.cpu_percent(after, before))

    def test_memory_used_is_total_minus_available(self):
        memory = mod.memory_mb(MEMINFO)
        self.assertEqual(memory["mem_total_mb"], 7952)
        # MemFree would claim 7747 MB used and make a healthy machine look full.
        self.assertEqual(memory["mem_used_mb"], 3049)
        self.assertEqual(memory["swap_total_mb"], 2048)
        self.assertEqual(memory["swap_used_mb"], 12)

    def test_what_the_kernel_did_not_give_is_left_out(self):
        self.assertEqual(mod.memory_mb("MemTotal: 8143868 kB\nMemFree: 1 kB\n"), {"mem_total_mb": 7952})
        self.assertEqual(mod.memory_mb(""), {})
        self.assertIsNone(mod.host_uptime(""))
        self.assertEqual(mod.host_uptime("864000.12 1700000.00"), 864000)
        self.assertIsNone(mod.process_rss_mb("Name:\tpython3\n"))
        self.assertEqual(mod.process_rss_mb("Name:\tpython3\nVmRSS:\t   65536 kB\n"), 64)

    def test_only_real_disks_are_reported_once_each(self):
        mounts = (
            "/dev/sda1 / ext4 rw,relatime 0 0\n"
            "proc /proc proc rw 0 0\n"
            "tmpfs /run tmpfs rw 0 0\n"
            "/dev/loop3 /snap/core20/2105 squashfs ro 0 0\n"
            "nas:/export /mnt/nas nfs4 rw 0 0\n"
            "/dev/sdb1 /data xfs rw 0 0\n"
            # The same device bind-mounted deeper: one disk, not two.
            "/dev/sda1 /var/www ext4 rw 0 0\n"
        )
        # An explicit directory test, so the case does not depend on which of
        # these paths happens to exist on the machine running the suite.
        self.assertEqual(mod.mount_points(mounts, is_dir=lambda _m: True), ["/", "/data"])

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
        self.assertEqual(
            mod.mount_points(mounts, is_dir=lambda m: not m.startswith("/etc/")),
            ["/", "/var/www/html/wp-content/plugins/site-analytics"],
        )
        # With no directory test to go on, the device keeps its shortest mount
        # rather than being dropped: open_basedir and friends can refuse every
        # path, and reporting no disks would be worse than an odd mount point.
        self.assertEqual(mod.mount_points(mounts, is_dir=lambda _m: False), ["/", "/etc/hosts"])

    def test_one_filesystem_behind_two_devices_is_reported_once(self):
        # The bug seen on a real container: / is the overlay and /sdk is a bind
        # of the host disk the overlay's upperdir lives on. The kernel calls
        # them different devices (overlay vs /dev/nvme0n1p6, two different
        # st_dev), so only the byte-identical size and free space give it away.
        class Stat:
            f_frsize = f_bsize = 4096
            f_blocks = 78_280_000
            f_bfree = 28_570_000
            f_bavail = 24_500_000
            f_files = f_ffree = 0

        rows = mod.disk_rows(["/", "/sdk"], statvfs=lambda _m: Stat())
        self.assertEqual([r["mount"] for r in rows], ["/"])

        # Two disks that merely round to the same megabyte stay apart: the
        # test is on raw bytes.
        class Other(Stat):
            f_bfree = 28_570_001
            f_bavail = 24_500_001

        rows = mod.disk_rows(["/", "/data"], statvfs=lambda m: Stat() if m == "/" else Other())
        self.assertEqual([r["mount"] for r in rows], ["/", "/data"])

    def test_disk_figures_are_the_ones_df_prints(self):
        class Stat:
            f_frsize = 4096
            f_bsize = 4096
            f_blocks = 1024 * 1024  # a 4 GiB disk
            f_bfree = 300 * 1024    # 1200 MB free
            f_bavail = 256 * 1024   # of which 1024 MB is ours
            f_files = 262_144       # inodes, as real statvfs always carries
            f_ffree = 200_000

        rows = mod.disk_rows(["/"], statvfs=lambda _m: Stat())
        # used = total - free; total = used + available. The 176 MB reserved
        # for root is in neither, so used/total is df's Use%.
        self.assertEqual(rows[0]["used_mb"], 2896)
        self.assertEqual(rows[0]["total_mb"], 3920)

    def test_a_disk_too_small_or_unreadable_is_left_out(self):
        class Small:
            f_frsize = f_bsize = 4096
            f_blocks = f_bfree = f_bavail = 64 * 1024

        self.assertEqual(mod.disk_rows(["/boot/efi"], statvfs=lambda _m: Small()), [])

        def refuses(_mount):
            raise OSError("permission denied")

        self.assertEqual(mod.disk_rows(["/locked"], statvfs=refuses), [])


class Reporting(unittest.TestCase):
    def sampler(self, core):
        checks = Resources(core, server_name="web-1")
        checks.rows = {"2026-10-20T12:00:00Z": {"minute": "2026-10-20T12:00:00Z", "cpu_pct": 10.0}}
        return checks

    def test_a_sample_carries_the_minute_and_the_machine_s_figures(self):
        checks = Resources(FakeCore(), server_name="web-1")
        row = checks.sample()
        self.assertRegex(row["minute"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:00")
        self.assertGreaterEqual(row["cpu_cores"], 1)
        # No CPU figure: this sample is microseconds after the first reading,
        # and the counters move in ticks, so any percentage would be noise.
        self.assertNotIn("cpu_pct", row)

    def test_a_posted_batch_is_dropped_once_it_is_stored(self):
        core = FakeCore()
        checks = self.sampler(core)
        self.assertTrue(checks.flush())
        self.assertEqual(len(core.sent), 1)
        self.assertEqual(core.sent[0]["path"], "/events/resources")
        # Bearer, like posture and inventory - not the body field the older
        # server-requests endpoint takes.
        self.assertEqual(core.sent[0]["auth"], "bearer")
        self.assertEqual(core.sent[0]["body"]["site_id"], "a" * 24)
        self.assertEqual(core.sent[0]["body"]["server_name"], "web-1")
        self.assertEqual(checks.rows, {}, "stored rows are not sent twice")

    def test_rows_are_kept_when_the_collector_cannot_take_them(self):
        for answer in (Answer(ok=False, status=503, body={}), Answer(ok=False, status=500, body={})):
            core = FakeCore(answer)
            checks = self.sampler(core)
            self.assertFalse(checks.flush())
            self.assertEqual(len(checks.rows), 1, "a retry can still deliver these")

    def test_rows_the_collector_refused_are_not_retried_forever(self):
        core = FakeCore(Answer(ok=False, status=400, body={}))
        checks = self.sampler(core)
        self.assertTrue(checks.flush())
        self.assertEqual(checks.rows, {}, "resending won't make them acceptable")

    def test_the_module_switch_stops_it_and_buffers_nothing(self):
        core = FakeCore()
        core.on = False
        checks = self.sampler(core)
        wait = checks._report()
        self.assertEqual(len(core.sent), 0)
        self.assertEqual(checks.rows, {})
        self.assertGreaterEqual(wait, mod.OFF_EVERY)

    def test_the_answer_sets_how_often_to_report(self):
        core = FakeCore(Answer(body={"v": 1, "enabled": True, "every": 900}))
        checks = self.sampler(core)
        checks.flush()
        self.assertEqual(checks.every, 900)
        # A silly interval can't drop below the retry floor.
        core.answer = Answer(body={"v": 1, "enabled": True, "every": 1})
        checks.rows = {"2026-10-20T12:01:00Z": {"minute": "2026-10-20T12:01:00Z"}}
        checks.flush()
        self.assertEqual(checks.every, mod.RETRY_EVERY)


class Detail(unittest.TestCase):
    """The CPU breakdown, throughput and inodes — the figures people opened
    Grafana for. Every one of them is left out when it can't be measured."""

    # user nice system idle iowait irq softirq steal
    BEFORE = [1000, 100, 500, 8000, 200, 10, 20, 170]
    AFTER = [1100, 100, 550, 8600, 240, 10, 20, 180]

    def test_steal_is_reported_because_nothing_else_tells_them(self):
        shares = mod.cpu_shares(self.BEFORE, self.AFTER)
        # 800 jiffies passed; 10 went to another tenant on the same host.
        self.assertEqual(shares["cpu_steal_pct"], 1.2)
        self.assertEqual(shares["cpu_iowait_pct"], 5.0)
        self.assertEqual(shares["cpu_user_pct"], 12.5)

    def test_a_kernel_without_the_column_says_nothing_rather_than_nought(self):
        shares = mod.cpu_shares([1000, 100, 500, 8000], [1100, 100, 550, 8600])
        self.assertNotIn("cpu_steal_pct", shares)
        self.assertIn("cpu_user_pct", shares)

    def test_one_reading_or_a_reboot_says_nothing(self):
        self.assertEqual(mod.cpu_shares(None, self.AFTER), {})
        self.assertEqual(mod.cpu_shares(self.AFTER, self.BEFORE), {})

    def test_a_partition_is_not_counted_twice_with_its_disk(self):
        stats = (
            "   8   0 sda 100 0 2000 0 50 0 4000 0 0 0 0\n"
            "   8   1 sda1 90 0 1800 0 40 0 3000 0 0 0 0\n"
            "   7   0 loop0 10 0 100 0 0 0 0 0 0 0 0\n"
            " 259   0 nvme0n1 20 0 1000 0 10 0 2000 0 0 0 0\n"
            " 259   1 nvme0n1p1 15 0 900 0 8 0 1500 0 0 0 0\n"
        )
        self.assertEqual(mod.disk_counters(stats), (3000 * 512, 6000 * 512))
        self.assertIsNone(mod.disk_counters(""))

    def test_container_traffic_is_not_the_sites_traffic(self):
        dev = (
            "    lo: 5000 10 0 0 0 0 0 0 5000 10 0 0 0 0 0 0\n"
            "  eth0: 1000 10 0 0 0 0 0 0 2000 20 0 0 0 0 0 0\n"
            "docker0: 9000 10 0 0 0 0 0 0 9000 10 0 0 0 0 0 0\n"
        )
        self.assertEqual(mod.net_counters(dev), (1000, 2000))

    def test_a_quiet_site_does_not_report_an_hour_as_a_rate(self):
        megabyte = 1024 * 1024
        self.assertEqual(mod.rate_mbs(0, 60 * megabyte, 60), 1.0)
        # This client only samples while a request is served, so the two
        # readings can be an hour apart. That is not this minute's rate.
        self.assertIsNone(mod.rate_mbs(0, 60 * megabyte, 3600))
        # A reboot reset the counter.
        self.assertIsNone(mod.rate_mbs(60 * megabyte, 0, 60))

    def test_inodes_ride_along_with_the_mount(self):
        class Stat:
            f_frsize = f_bsize = 4096
            f_blocks = 1024 * 1024
            f_bfree = f_bavail = 512 * 1024
            f_files = 262_144
            f_ffree = 200_000

        row = mod.disk_rows(["/"], statvfs=lambda _m: Stat())[0]
        self.assertEqual(row["inodes_total"], 262_144)
        self.assertEqual(row["inodes_used"], 62_144)


class ReviewFixes(unittest.TestCase):
    def test_guest_time_is_not_counted_twice(self):
        # guest (column 9) is already inside user: 400 of the 800 busy jiffies.
        before = [1000, 0, 0, 8000, 0, 0, 0, 0, 0, 0]
        after = [1800, 0, 0, 8200, 0, 0, 0, 0, 400, 0]
        self.assertEqual(mod.cpu_percent(mod.cpu_times_of(before), mod.cpu_times_of(after)), 80.0)
        self.assertEqual(mod.cpu_shares(before, after)["cpu_user_pct"], 80.0)

    def test_the_collectors_off_answer_slows_reporting_and_keeps_one_row(self):
        core = FakeCore(Answer(status=200, body={"v": 1, "enabled": False, "every": 300}))
        checks = Resources(core)
        checks.rows = {"2026-10-20T12:00:00Z": {"minute": "2026-10-20T12:00:00Z"}}
        self.assertGreaterEqual(checks._report(), mod.OFF_EVERY)
        self.assertFalse(checks.enabled)
        checks.last_at -= 120
        checks.sample()
        checks.last_at -= 120
        checks.sample()
        self.assertEqual(len(checks.rows), 1, "only the row that asks again")
        core.answer = Answer()
        self.assertEqual(checks._report(), checks.every)
        self.assertTrue(checks.enabled)

    def test_close_sends_what_is_buffered(self):
        core = FakeCore()
        checks = Resources(core)
        checks.rows = {"2026-10-20T12:00:00Z": {"minute": "2026-10-20T12:00:00Z"}}
        checks.close()
        self.assertEqual(len(core.sent), 1)
        core.on = False
        checks.rows = {"2026-10-20T12:01:00Z": {"minute": "2026-10-20T12:01:00Z"}}
        checks.close()
        self.assertEqual(len(core.sent), 1, "nothing goes out once the module is switched off")
