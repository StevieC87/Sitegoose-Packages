"""How close the app is to a wall (resources.py, protocol resources.md
"Limits"): the container's caps, waiting time, refused connections, open
files and requests in progress. Everything is read through a fake file
reader, so no cgroup is needed.

    python3 -m unittest discover -s tests
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from analytics_platform import create_platform  # noqa: E402
from analytics_platform import resources as r  # noqa: E402

MB = 1024 * 1024


def files(found):
    return lambda path, *_: found.get(path, "")


def v2(**over):
    found = {
        "/c/memory.max": "%d\n" % (512 * MB),
        "/c/memory.current": "%d\n" % (400 * MB),
        "/c/memory.stat": "anon %d\ninactive_file %d\n" % (200 * MB, 150 * MB),
        "/c/memory.events": "low 0\nhigh 0\nmax 3\noom 1\noom_kill 1\n",
        "/c/cpu.max": "150000 100000\n",
        "/c/cpu.stat": "usage_usec 10\nnr_periods 1000\nnr_throttled 100\n",
    }
    found.update({"/c/" + k.replace("_", ".", 1): v for k, v in over.items()})
    return files(found)


CG = {"version": 2, "memory": "/c", "cpu": "/c"}


class Cgroups(unittest.TestCase):
    def test_a_v2_container_is_found_at_the_mount_itself_and_a_host_service_under_its_path(self):
        in_container = files({"/proc/self/cgroup": "0::/\n", "/sys/fs/cgroup/memory.current": "1000\n"})
        self.assertEqual(r.find_cgroup(in_container), {"version": 2, "memory": "/sys/fs/cgroup", "cpu": "/sys/fs/cgroup"})
        service = files({"/proc/self/cgroup": "0::/system.slice/app.service\n",
                         "/sys/fs/cgroup/system.slice/app.service/memory.current": "1000\n"})
        self.assertEqual(r.find_cgroup(service)["memory"], "/sys/fs/cgroup/system.slice/app.service")

    def test_a_hybrid_machine_with_no_v2_controllers_reads_its_limits_from_v1(self):
        hybrid = files({"/proc/self/cgroup": "12:memory:/docker/abc\n4:cpu,cpuacct:/docker/abc\n0::/docker/abc\n",
                        "/sys/fs/cgroup/memory/memory.usage_in_bytes": "5\n",
                        "/sys/fs/cgroup/cpu/cpu.cfs_quota_us": "-1\n"})
        self.assertEqual(r.find_cgroup(hybrid), {"version": 1, "memory": "/sys/fs/cgroup/memory", "cpu": "/sys/fs/cgroup/cpu"})
        self.assertIsNone(r.find_cgroup(files({})))

    def test_container_memory_is_the_working_set_and_throttling_a_share_of_periods(self):
        before = r.cgroup_reading(CG, v2())
        after = r.cgroup_reading(CG, v2(memory_events="oom_kill 3\n", cpu_stat="nr_periods 1600\nnr_throttled 250\n"))
        row = r.cgroup_fields(before, after, mem_total_mb=8000, cores=4)
        self.assertEqual(row, {"limit_mem_mb": 512, "limit_mem_used_mb": 250, "limit_cpu_cores": 1.5,
                               "cpu_throttled_pct": 25.0, "oom_kills": 2})

    def test_a_cap_that_isnt_one_is_left_out_and_one_reading_gives_no_counts(self):
        open_ = r.cgroup_reading(CG, v2(memory_max="max\n", cpu_max="max 100000\n"))
        self.assertEqual(r.cgroup_fields(None, open_, mem_total_mb=8000, cores=4), {})
        big = r.cgroup_reading(CG, v2(memory_max="%d\n" % (16000 * MB)))
        self.assertNotIn("limit_mem_mb", r.cgroup_fields(None, big, mem_total_mb=8000))
        v1 = files({"/m/memory.limit_in_bytes": "9223372036854771712\n", "/m/memory.usage_in_bytes": "100\n"})
        reading = r.cgroup_reading({"version": 1, "memory": "/m", "cpu": None}, v1)
        self.assertNotIn("limit_mem_mb", r.cgroup_fields(None, reading))

    def test_a_counter_that_went_down_was_reset_and_says_nothing(self):
        self.assertIsNone(r.count_since(5, 3))
        self.assertIsNone(r.count_since(None, 3))
        self.assertEqual(r.count_since(3, 3), 0)


class Machine(unittest.TestCase):
    def test_waiting_time_is_the_some_lines_avg60_and_a_kernel_without_psi_sends_none(self):
        text = "some avg10=1.50 avg60=12.34 avg300=3.00 total=123\nfull avg10=0.00 avg60=9.00 avg300=0.00 total=1\n"
        self.assertEqual(r.pressure_some(text), 12.3)
        self.assertEqual(r.pressure_fields(files({"/proc/pressure/io": text})), {"psi_io_pct": 12.3})
        self.assertEqual(r.pressure_fields(files({})), {})

    def test_refused_connections_come_from_tcpext_listenoverflows(self):
        netstat = "TcpExt: SyncookiesSent ListenOverflows ListenDrops\nTcpExt: 0 17 20\nIpExt: InOctets\nIpExt: 5\n"
        self.assertEqual(r.listen_overflows(netstat), 17)
        self.assertIsNone(r.listen_overflows("IpExt: a\nIpExt: 1\n"))
        self.assertEqual(r.conntrack_pct(files({"/proc/sys/net/netfilter/nf_conntrack_count": "300\n",
                                                "/proc/sys/net/netfilter/nf_conntrack_max": "1200\n"})), 25.0)
        self.assertIsNone(r.conntrack_pct(files({})))

    def test_open_files_against_the_soft_limit_and_unlimited_is_no_limit(self):
        limits = ("Limit                     Soft Limit           Hard Limit           Units\n"
                  "Max open files            1024                 1048576              files\n")
        self.assertEqual(r.fd_limit(limits), 1024)
        self.assertIsNone(r.fd_limit("Max open files            unlimited            unlimited            files\n"))
        # Eleven entries, one of them the listing's own.
        self.assertEqual(r.file_fields(files({"/proc/self/limits": limits}), lambda _: [0] * 11), {"fds_used": 10, "fds_max": 1024})

        def no_proc(_):
            raise OSError("no /proc")

        self.assertEqual(r.file_fields(files({}), no_proc), {})

    def test_the_process_uptime_is_its_start_against_the_machines(self):
        stat = "4242 (gunicorn: worker [x]) S " + " ".join(["0"] * 18) + " 50000 0 0"
        ticks = os.sysconf("SC_CLK_TCK")
        reading = files({"/proc/self/stat": stat, "/proc/uptime": "%d.5 100.0\n" % (50000 // ticks + 90)})
        self.assertEqual(r.process_uptime(reading), 90)
        self.assertIsNone(r.process_uptime(files({})))


def make_platform():
    return create_platform(site_id="a1b2c3d4e5f6a1b2c3d4e5f6", secret="s", endpoint="http://127.0.0.1:9",
                           firewall=False, analytics=False, flags=False, inventory=False, posture=False,
                           proxy=False, maintenance=False, crawlers=False, forms=False,
                           audit=False, headers=False, errors=False)


class InFlight(unittest.TestCase):
    def test_requests_in_progress_peak_per_sample_and_there_is_no_peak_before_one_is_timed(self):
        platform = make_platform()
        try:
            resources = platform._modules["resources"]
            self.assertNotIn("inflight_peak", resources.sample(), "never 0 for an app that times nothing")
            seen = []

            def inner(environ, start_response):
                seen.append(resources.inflight_peak())
                start_response("200 OK", [])
                return [b""]

            def outer(environ, start_response):
                platform.wsgi(inner)(environ, start_response)
                start_response("200 OK", [])
                return [b""]

            environ = {"REQUEST_METHOD": "GET", "PATH_INFO": "/", "REMOTE_ADDR": "1.2.3.4"}
            platform.wsgi(outer)(dict(environ), lambda *a: None)
            self.assertEqual(seen, [2], "two at once")
            row = resources.sample()
            self.assertEqual(row["inflight_peak"], 2, "still in progress when it was last taken")
            self.assertEqual(resources.sample()["inflight_peak"], 0, "the peak starts again from what's in progress")
            self.assertRegex(row["proc_key"], r"^[0-9a-f]{12}$")
            if os.path.exists("/proc/self/stat"):
                self.assertGreaterEqual(row["proc_uptime_s"], 0)
            for field in ("gc_ms", "heap_used_mb", "heap_max_mb"):
                self.assertNotIn(field, row)
        finally:
            platform.close()


if __name__ == "__main__":
    unittest.main()
