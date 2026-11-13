"""What fills the disks (sdk/protocols/disk-usage.md): the walk counts each
file once and in its deepest place, never through a symlink or onto a disk
that isn't reported; the notes read Docker's, logrotate's and journald's own
words; the child is bounded; and file names reach the main site only.

    python3 -m unittest discover -s test
"""
import importlib.util
import json
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

AGENT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "analytics-agent")
if "analytics_agent" in sys.modules:
    agent = sys.modules["analytics_agent"]
else:
    spec = importlib.util.spec_from_loader("analytics_agent", importlib.machinery.SourceFileLoader("analytics_agent", AGENT))
    agent = importlib.util.module_from_spec(spec)
    sys.modules["analytics_agent"] = agent
    spec.loader.exec_module(agent)
ID = "0123456789abcdef" * 4


class Parsing(unittest.TestCase):
    def test_docker_sizes_are_decimal_as_docker_prints_them(self):
        self.assertEqual(agent.docker_size("1.2GB (50%)"), 1200000000)
        self.assertEqual(agent.docker_size("412.6MB"), 412600000)
        self.assertEqual(agent.docker_size("0B"), 0)
        self.assertEqual(agent.docker_size("3kB (1%)"), 3000)
        self.assertIsNone(agent.docker_size("n/a"))

    def test_docker_df_gives_the_three_reclaimable_notes(self):
        text = "\n".join([
            '{"Active":"28","Reclaimable":"18.62GB (40%)","Size":"45.42GB","TotalCount":"108","Type":"Images"}',
            '{"Active":"12","Reclaimable":"412.6MB (23%)","Size":"1.754GB","TotalCount":"32","Type":"Containers"}',
            '{"Active":"32","Reclaimable":"12.96GB (49%)","Size":"26.18GB","TotalCount":"171","Type":"Local Volumes"}',
            '{"Active":"0","Reclaimable":"4.615GB","Size":"21.08GB","TotalCount":"283","Type":"Build Cache"}',
            "not json"])
        self.assertEqual(agent.docker_df(text), {"docker_unused_images": 18620000000,
                                                 "docker_stopped_containers": 412600000,
                                                 "docker_build_cache": 4615000000})

    def test_docker_log_limit(self):
        self.assertFalse(agent.docker_log_limit({}))
        self.assertFalse(agent.docker_log_limit({"log-opts": {"max-file": "3"}}))
        self.assertTrue(agent.docker_log_limit({"log-opts": {"max-size": "10m"}}))
        self.assertTrue(agent.docker_log_limit({"log-driver": "journald"}))
        self.assertEqual(agent.docker_data_root({"data-root": "/data/docker/"}), "/data/docker")
        self.assertEqual(agent.docker_data_root(None), "/var/lib/docker")

    def test_logrotate_rules_name_their_paths_not_their_directives_or_scripts(self):
        text = """
# comment /var/log/nope.log
weekly
include /etc/logrotate.d
/var/log/wtmp {
    monthly
}
"/var/log/nginx/*.log" /var/log/app/debug.log
{
    postrotate
        [ -f /run/nginx.pid ] && kill -USR1 `cat /run/nginx.pid` || { true; }
    endscript
}
/var/log/after.log{
}
"""
        patterns = agent.logrotate_paths(text)
        self.assertEqual(patterns, ["/var/log/wtmp", "/var/log/nginx/*.log", "/var/log/app/debug.log", "/var/log/after.log"])
        self.assertTrue(agent.rotated_by("/var/log/nginx/access.log", patterns))
        self.assertFalse(agent.rotated_by("/var/log/nginx/sub/access.log", patterns), "a glob stays in its folder")
        self.assertFalse(agent.rotated_by("/var/log/other.log", patterns))

    def test_journald_limit_reads_uncommented_settings(self):
        folder = tempfile.mkdtemp()
        main, drop = os.path.join(folder, "journald.conf"), os.path.join(folder, "10-size.conf")
        with open(main, "w") as f:
            f.write("[Journal]\n#SystemMaxUse=500M\nSystemMaxUse=\n")
        self.assertFalse(agent.journald_limit((main, os.path.join(folder, "*.d.conf"))))
        with open(drop, "w") as f:
            f.write("[Journal]\nSystemMaxUse=1G\n")
        self.assertTrue(agent.journald_limit((main, os.path.join(folder, "*-size.conf"))))

    def test_journal_vacuum_keeps_the_newest_that_fit(self):
        mb = 1024 * 1024
        files = [(1, 300 * mb), (2, 300 * mb), (3, 300 * mb), (4, 100 * mb)]
        # Newest first: 100 (4) + 300 (3) fit in 500; 2 doesn't, so 2 and 1 go.
        self.assertEqual(agent.journal_vacuum(files), 600 * mb)
        self.assertEqual(agent.journal_vacuum([(1, 10 * mb)]), 0)

    def test_crash_program_names(self):
        self.assertEqual(agent.crash_program("_usr_bin_foo.0.crash"), "foo")
        self.assertEqual(agent.crash_program("_usr_sbin_php-fpm8.1.33.crash"), "php-fpm8.1")
        self.assertEqual(agent.crash_program("core.nginx.0.6f3a.812.1731160000000000.zst"), "nginx")
        self.assertEqual(agent.crash_program("README"), "")

    def test_cgroup_owner(self):
        self.assertEqual(agent.cgroup_owner("0::/system.slice/nginx.service\n"), ("nginx.service", ""))
        self.assertEqual(agent.cgroup_owner("0::/system.slice/docker-%s.scope\n" % ID), ("", ID[:12]))
        v1 = "12:memory:/docker/%s\n1:name=systemd:/docker/%s\n" % (ID, ID)
        self.assertEqual(agent.cgroup_owner(v1), ("", ID[:12]))
        self.assertEqual(agent.cgroup_owner(""), ("", ""))
        # A login session is nobody's service to restart.
        self.assertEqual(agent.cgroup_owner("0::/user.slice/user-1000.slice/user@1000.service/app.slice/x.scope\n"), ("", ""))
        self.assertEqual(agent.cgroup_owner(
            "0::/user.slice/user-1000.slice/user@1000.service/session.slice/org.gnome.Shell@wayland.service\n"), ("", ""))

    def test_config_paths_must_be_absolute(self):
        self.assertEqual(agent.disk_scan_paths(["/data/", "relative", 5, "/a/../b"]), ["/data", "/b"])
        self.assertEqual(agent.disk_scan_paths("/data"), [])


class Walking(unittest.TestCase):
    """A scan of a made-up tree, mounted on a made-up "/"."""

    def setUp(self):
        self.root = os.path.realpath(tempfile.mkdtemp())
        self.mounts = "/dev/sda1 / ext4 rw 0 0\n/dev/sdb1 %s/other ext4 rw 0 0\ntmpfs %s/ram tmpfs rw 0 0\n" % (
            self.root, self.root)
        self.big = agent.DISK_BIG_LOG
        agent.DISK_BIG_LOG = 100 * 1024

    def tearDown(self):
        agent.DISK_BIG_LOG = self.big

    def write(self, rel, size=4096, age_days=0):
        path = os.path.join(self.root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(b"x" * size)
        if age_days:
            then = time.time() - age_days * 86400
            os.utime(path, (then, then))
        return path

    def place(self, kind, rel, **extra):
        return dict({"place": kind, "path": os.path.join(self.root, rel)}, **extra)

    def scan(self, places, **kwargs):
        with mock.patch.object(agent, "logrotate_patterns", return_value=[os.path.join(self.root, "log/app/*.log")]), \
                mock.patch.object(agent, "journald_limit", return_value=False):
            scan = agent.DiskScan(places, self.mounts, ["/"], proc=os.path.join(self.root, "noproc"), **kwargs)
            return scan, scan.run()

    def test_each_file_counts_once_in_its_deepest_place(self):
        self.write("log/app/app.log", 200 * 1024)
        self.write("log/app/app.log.1", 8192)
        self.write("log/syslog-20261101", 8192)
        self.write("log/messages.2.gz", 8192)
        self.write("log/journal/system.journal", 8192)
        self.write("log/journal/system@0001-0002.journal", 8192)
        self.write("log/journal/user-1000.journal~", 8192)
        os.symlink(self.write("elsewhere/huge", 300 * 1024), os.path.join(self.root, "log/link"))
        linked = self.write("log/hard", 50 * 1024)
        os.link(linked, os.path.join(self.root, "log/hard2"))
        self.write("other/file", 50 * 1024)
        self.write("ram/file", 50 * 1024)
        os.symlink(os.path.join(self.root, "log"), os.path.join(self.root, "logs-again"))
        places = [self.place("logs", "log"), self.place("journal", "log/journal"), self.place("custom", "logs-again"),
                  self.place("custom", "other"), self.place("temp", "ram"), self.place("custom", "missing")]
        scan, report = self.scan(places)
        by_path = {p["path"]: p for p in report["places"]}
        self.assertEqual(sorted(by_path), [os.path.join(self.root, "log"), os.path.join(self.root, "log/journal")],
                         "the same folder twice is measured once; other disks, tmpfs and missing folders aren't")
        logs, journal = by_path[os.path.join(self.root, "log")], by_path[os.path.join(self.root, "log/journal")]
        self.assertEqual(logs["mount"], "/")
        # app.log, app.log.1, syslog-…, messages.2.gz, and the hard-linked file once; no symlink, no journal.
        self.assertEqual(logs["files"], 5)
        self.assertEqual(journal["files"], 3)
        self.assertFalse(report["partial"])
        notes = {n["code"]: n for n in report["notes"]}
        self.assertEqual((notes["rotated_logs"]["files"], notes["rotated_logs"]["bytes"]), (3, 3 * 8192))
        self.assertEqual(notes["big_log"]["path"], os.path.join(self.root, "log/app/app.log"))
        self.assertIs(notes["big_log"]["flag"], True)
        self.assertIn("journal_no_limit", notes)
        self.assertNotIn("journal_archived", notes, "16 KB of archives is well inside the newest 500 MB")
        self.assertEqual(report["files"][0]["path"], os.path.join(self.root, "log/app/app.log"))
        self.assertEqual(report["files"][0]["place"], "logs")
        self.assertNotIn(os.path.join(self.root, "elsewhere/huge"), [f["path"] for f in report["files"]])
        self.assertEqual(report["deleted"], [])

    def test_age_and_tool_notes(self):
        self.write("tmp/old", 8192, age_days=11)
        self.write("tmp/new", 8192)
        self.write("backups/db.sql.gz", 8192, age_days=31)
        self.write("crash/_usr_bin_foo.0.crash", 8192)
        self.write("mysql/binlog.000001", 8192)
        self.write("mysql/app/binlog.000002", 8192)
        self.write("home/bob/.cache/pip/wheel", 8192)
        self.write("home/bob/.cache/other", 8192)
        places = [self.place("temp", "tmp"), self.place("backups", "backups"), self.place("crash", "crash"),
                  self.place("databases", "mysql", role="mysql"),
                  self.place("caches", "home/bob/.cache", tool="", user="bob")]
        with mock.patch.object(agent, "DISK_USER_CACHE_MIN", 1):
            _, report = self.scan(places)
        notes = {n["code"]: n for n in report["notes"]}
        self.assertEqual(notes["old_temp"]["files"], 1)
        self.assertEqual(notes["old_backups"]["files"], 1)
        self.assertEqual((notes["crash_dumps"]["files"], notes["crash_dumps"]["value"]), (1, "foo"))
        self.assertEqual(notes["mysql_binlogs"]["files"], 1, "only the data folder's own binary logs")
        self.assertEqual((notes["user_cache"]["value"], notes["user_cache"]["user"]), ("pip", "bob"))
        self.assertEqual(notes["user_cache"]["bytes"], 8192, "~/.cache counts as pip's only in its pip folder")

    def test_the_entry_budget_makes_the_scan_partial(self):
        for i in range(10):
            self.write("log/f%d" % i)
        with mock.patch.object(agent, "DISK_ENTRIES", 3):
            _, report = self.scan([self.place("logs", "log")])
        self.assertTrue(report["partial"])
        self.assertLessEqual(report["places"][0]["files"], 3)

    def test_a_deleted_file_still_open_is_found_on_its_disk(self):
        if not os.path.isdir("/proc/self/fd"):
            self.skipTest("no /proc")
        mounts = agent.read_text("/proc/mounts", 4 * 1024 * 1024)
        table = agent.mount_table(mounts)
        mine = max((m for _, m, _, _ in table if self.root == m or self.root.startswith(m.rstrip("/") + "/")), key=len)
        path = self.write("held.log", 64 * 1024)
        with open(path, "rb") as held:
            os.unlink(path)
            scan = agent.DiskScan([], mounts, [mine])
            deleted = scan.deleted_files()
            ours = [d for d in deleted if d["path"] == path]
            self.assertEqual(len(ours), 1, "held open by this process")
            self.assertEqual((ours[0]["pid"], ours[0]["fd"], ours[0]["mount"]), (os.getpid(), held.fileno(), mine))
            self.assertGreaterEqual(ours[0]["bytes"], 64 * 1024)
            self.assertGreaterEqual(scan.notes[(mine, "open_deleted")]["bytes"], ours[0]["bytes"],
                                    "the per-disk total counts every one, not only the biggest 20")


class Child(unittest.TestCase):
    def test_the_report_comes_back(self):
        report, why = agent.run_disk_child({}, 20, args=[sys.executable, "-c", "print('{\"places\": []}')"])
        self.assertEqual((report, why), ({"places": []}, None))

    def test_a_child_past_its_time_is_killed(self):
        start = time.time()
        report, why = agent.run_disk_child({}, 1, args=[sys.executable, "-c", "import time; time.sleep(30)"])
        self.assertIsNone(report)
        self.assertIn("longer than", why)
        self.assertLess(time.time() - start, 15)

    def test_what_it_prints_is_capped(self):
        with mock.patch.object(agent, "DISK_OUT_BYTES", 1000):
            report, why = agent.run_disk_child({}, 20, args=[sys.executable, "-c", "print('x' * 5000)"])
        self.assertIsNone(report)
        self.assertIn("more than", why)

    def test_a_failed_child_says_why(self):
        report, why = agent.run_disk_child({}, 20, args=[sys.executable, "-c", "raise SystemExit('no luck')"])
        self.assertIsNone(report)
        self.assertIn("no luck", why)


REPORT = {"scanned_at": "2026-11-09T14:05:00Z", "took_s": 4.2, "partial": False,
          "places": [{"mount": "/", "place": "logs", "path": "/var/log", "bytes": 10, "files": 1}],
          "notes": [{"mount": "/", "code": "big_log", "path": "/var/log/x.log", "bytes": 5, "flag": False},
                    {"mount": "/", "code": "rotated_logs", "bytes": 3, "files": 1}],
          "files": [{"mount": "/", "place": "logs", "path": "/var/log/x.log", "bytes": 5, "age_days": 0}],
          "deleted": [{"mount": "/", "path": "/var/log/y.log", "bytes": 4, "process": "nginx", "pid": 1, "fd": 3,
                       "unit": "nginx.service", "container_id": ""}]}


class Reporting(unittest.TestCase):
    def setUp(self):
        self.config = dict(agent.DEFAULTS, site_id="a" * 24, secret="s", endpoint="https://c.example",
                           state_dir=tempfile.mkdtemp(), sites=[{"site_id": "b" * 24, "secret": "t"}])
        self.sent, self.answers = [], []
        patcher = mock.patch.object(agent, "request", self.fake_request)
        patcher.start()
        self.addCleanup(patcher.stop)

    def fake_request(self, config, method, path, body=None, headers=None):
        self.sent.append((config["site_id"], path, body))
        return self.answers.pop(0) if self.answers else (202, {}, b'{"v":1,"enabled":true,"stored":3}')

    def test_file_names_go_to_the_main_site_only(self):
        job = agent.DiskUsage(self.config)
        job.queue(REPORT)
        self.assertTrue(job.deliver())
        (main, path, first), (other, _, second) = self.sent
        self.assertEqual((main, other, path), ("a" * 24, "b" * 24, "/events/disk-usage"))
        self.assertEqual((first["v"], first["client"], first["scanned_at"]), (1, "vps-agent/" + agent.VERSION, REPORT["scanned_at"]))
        self.assertEqual(len(first["files"]), 1)
        self.assertEqual(first["notes"][0]["path"], "/var/log/x.log")
        self.assertNotIn("files", second)
        self.assertNotIn("deleted", second)
        self.assertNotIn("path", second["notes"][0])
        self.assertEqual(second["places"], REPORT["places"], "every site gets the places")

    def test_no_names_at_all_when_switched_off(self):
        job = agent.DiskUsage(dict(self.config, disk_scan_files=False))
        job.queue(REPORT)
        job.deliver()
        for _, _, body in self.sent:
            self.assertNotIn("files", body)
            self.assertNotIn("path", body["notes"][0])

    def test_unreachable_is_retried_for_an_hour_and_a_refusal_is_dropped(self):
        job = agent.DiskUsage(dict(self.config, sites=[]))
        job.queue(REPORT, now=1000)
        self.answers = [(503, {}, b"")]
        self.assertFalse(job.deliver(1000))
        self.assertEqual((len(job.pending), job.retry_at), (1, 1000 + agent.DISK_RETRY))
        self.answers = [(0, {}, b"")]
        with mock.patch.object(agent, "log"):
            job.deliver(1000 + agent.DISK_RETRY_FOR)
        self.assertEqual(job.pending, [], "dropped after an hour")
        job.queue(REPORT, now=5000)
        self.answers = [(400, {}, b"")]
        with mock.patch.object(agent, "log"):
            self.assertTrue(job.deliver(5000))
        self.assertEqual(job.pending, [])

    def test_the_module_switch_is_followed(self):
        job = agent.DiskUsage(dict(self.config, sites=[]))
        job.queue(REPORT)
        self.answers = [(200, {}, b'{"v":1,"enabled":false}')]
        with mock.patch.object(agent, "log"):
            job.deliver()
        self.assertFalse(job.due(job.next_scan + 1), "no scan while every site has it off")
        job.answered("a" * 24, {"v": 1, "enabled": True})
        self.assertTrue(job.due(job.next_scan + 1))

    def test_scan_now_takes_the_first_id_as_seen_and_waits_ten_minutes(self):
        job = agent.DiskUsage(self.config)
        t = job.next_scan - 200
        job.answered("a" * 24, {"enabled": True, "disk_scan": "c" * 24})
        self.assertFalse(job.due(t), "the click from before the restart")
        job.answered("a" * 24, {"enabled": True, "disk_scan": "c" * 24})
        self.assertFalse(job.due(t))
        job.answered("a" * 24, {"enabled": True, "disk_scan": "d" * 24})
        self.assertTrue(job.due(t), "a new click, and no scan yet")
        job.last_done = t - 60
        self.assertFalse(job.due(t), "too soon after the last scan")
        self.assertTrue(job.due(t - 60 + agent.DISK_SCAN_NOW_GAP))
        # A site with no request yet starts from nothing, and its first click counts.
        job.answered("b" * 24, {"enabled": True})
        job.wanted = False
        job.answered("b" * 24, {"enabled": True, "disk_scan": "e" * 24})
        self.assertTrue(job.wanted)

    def test_a_scan_is_posted_and_the_schedule_moves_on(self):
        job = agent.DiskUsage(dict(self.config, sites=[], disk_scan_every=60))
        self.assertEqual(job.every, agent.DISK_SCAN_MIN_EVERY)
        with mock.patch.object(agent, "run_disk_child", return_value=(REPORT, None)), \
                mock.patch.object(agent, "docker_reclaimable", return_value=None):
            job.tick(job.next_scan)
        self.assertEqual(len(self.sent), 1)
        self.assertGreater(job.next_scan, time.time() + agent.DISK_SCAN_MIN_EVERY - 5)
        with mock.patch.object(agent, "run_disk_child", return_value=(None, "killed")), \
                mock.patch.object(agent, "log") as logged:
            job.tick(job.next_scan)
        self.assertEqual(len(self.sent), 1)
        self.assertEqual(logged.call_count, 1)

    def test_the_resources_answer_reaches_the_disk_job(self):
        checks = agent.Resources(dict(self.config, sites=[]))
        checks.disk = agent.DiskUsage(dict(self.config, sites=[]))
        checks.rows = {"2026-11-09T12:00:00Z": {"minute": "2026-11-09T12:00:00Z"}}
        self.answers = [(202, {}, b'{"v":1,"enabled":true,"disk_scan":"%s"}' % (b"c" * 24))]
        checks.post()
        self.assertEqual(checks.disk.requests, {"a" * 24: "c" * 24})


if __name__ == "__main__":
    unittest.main()
