"""Backups (sdk/protocols/backups.md): the config read as documented, every
database dumped with its own tool and no password on a command line, the
download link signed as S3 signs it, and, with restic installed, a real run
into a repository on disk, put back and undone.

    python3 -m unittest discover -s test
"""
import base64
import hashlib
import hmac
import importlib.util
import io
import json
import os
import shutil
import sqlite3
import sys
import tempfile
import unittest
import zipfile
from datetime import datetime, timezone
from unittest import mock

AGENT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "analytics-agent")
if "analytics_agent" in sys.modules:
    agent = sys.modules["analytics_agent"]
else:
    spec = importlib.util.spec_from_loader("analytics_agent", importlib.machinery.SourceFileLoader("analytics_agent", AGENT))
    agent = importlib.util.module_from_spec(spec)
    sys.modules["analytics_agent"] = agent
    spec.loader.exec_module(agent)


def config(**backups):
    return {"site_id": "a" * 24, "secret": "s", "endpoint": "https://c", "state_dir": tempfile.mkdtemp(),
            "files_roots": ["/var/www/html"], "apps": ["/opt/shop"], "databases": [], "backups": backups}


class Settings(unittest.TestCase):
    def test_off_without_a_repository(self):
        self.assertIsNone(agent.backup_config(config()))
        self.assertIsNone(agent.backup_config(dict(config(), backups=None)))

    def test_defaults_and_folders_from_the_site(self):
        conf = agent.backup_config(config(repository="s3:https://nbg1.your-objectstorage.com/b/srv", at="25:00",
                                          env={"AWS_ACCESS_KEY_ID": "k", "PATH": "/evil"}))
        self.assertEqual(conf["at"], "03:00")
        self.assertEqual(conf["folders"], ["/var/www/html", "/opt/shop"])
        self.assertEqual(conf["env"], {"AWS_ACCESS_KEY_ID": "k"})
        self.assertFalse(conf["allow_restore"])
        self.assertEqual(conf["keep"], {"daily": 14, "weekly": 8, "monthly": 12})

    def test_databases_come_from_the_readings_list_when_not_given(self):
        c = config(repository="/srv/r")
        c["databases"] = [{"postgresql": "local"}, {"redis": "local"}, {"clickhouse": "http://127.0.0.1:8123"}]
        conf = agent.backup_config(c)
        self.assertEqual([d["label"] for d in conf["databases"]], ["postgresql local"])
        self.assertEqual(conf["skipped"], ["clickhouse", "redis"])

    def test_labels_never_carry_a_password(self):
        dbs = agent.backup_databases([{"mysql": "mysql://root:hunter2@db.internal:3307/shop"},
                                      {"mongodb": "mongodb://u:hunter2@10.0.0.5"}, {"postgresql": "docker:shop-db"},
                                      {"mariadb": "local"}, {"sqlite": "relative.db"}, {"postgresql": "docker:bad name"}])
        self.assertEqual([d["label"] for d in dbs], ["mysql db.internal:3307", "mongodb 10.0.0.5", "postgresql in shop-db", "mysql local"])
        self.assertNotIn("hunter2", json.dumps([d["label"] for d in dbs]))

    def test_shown_repository_drops_passwords(self):
        self.assertEqual(agent.shown_repository("rest:https://u:pw@host:8000/repo"), "rest:https://host:8000/repo")
        self.assertEqual(agent.shown_repository("sftp:user:pw@host:/srv"), "sftp:host:/srv")


class Dumps(unittest.TestCase):
    def source(self, kind, target):
        return agent.DumpSource(agent.backup_databases([{kind: target}])[0], tempfile.mkdtemp())

    def test_mysql_password_goes_in_a_file_not_the_command_line(self):
        src = self.source("mysql", "mysql://root:hunter2@db:3306/shop")
        with mock.patch.object(agent, "_proc", return_value=(0, "shop\nmysql\nsys\n", "")):
            dumps = src.dumps()
        self.assertEqual([name for name, _ in dumps], ["shop.sql"])
        args = dumps[0][1]
        self.assertNotIn("hunter2", " ".join(args))
        option = next(a for a in args if a.startswith("--defaults-extra-file="))
        with open(option.split("=", 1)[1]) as f:
            self.assertIn('password="hunter2"', f.read())
        self.assertIn("--add-drop-database", args)
        src.close()
        self.assertFalse(os.path.exists(option.split("=", 1)[1]))

    def test_postgres_url_password_goes_in_the_environment(self):
        src = self.source("postgresql", "postgresql://app:hunter2@db/shop")
        dumps = src.dumps()
        self.assertEqual([name for name, _ in dumps], ["shop.pgdump"])
        self.assertNotIn("hunter2", " ".join(dumps[0][1]))
        self.assertEqual(src.env()["PGPASSWORD"], "hunter2")

    def test_local_postgres_dumps_each_database_and_the_roles(self):
        src = self.source("postgresql", "local")
        with mock.patch.object(agent, "_proc", return_value=(0, "postgres\nshop\n", "")):
            names = [name for name, _ in src.dumps()]
        self.assertEqual(names, ["postgres.pgdump", "shop.pgdump", "_roles.sql"])

    def test_postgres_restore_is_one_transaction_when_the_database_exists(self):
        src = self.source("postgresql", "local")
        with mock.patch.object(agent, "_proc", return_value=(0, "shop\n", "")):
            command = src.restore_command("shop.pgdump")
            created = src.restore_command("gone.pgdump")
        self.assertIn("--single-transaction", command)
        self.assertIn("--create", created)

    def test_mongo_uri_goes_in_a_config_file(self):
        src = self.source("mongodb", "mongodb://u:hunter2@10.0.0.5/admin")
        args = src.dumps()[0][1]
        self.assertNotIn("hunter2", " ".join(args))
        src.close()

    def test_containers_use_their_own_variables(self):
        src = self.source("mysql", "docker:shop-db")
        with mock.patch.object(agent, "_proc", return_value=(0, "shop\n", "")):
            args = src.dumps()[0][1]
        self.assertEqual(args[:4], ["docker", "exec", "shop-db", "sh"])
        self.assertIn("MYSQL_PWD", args[5])
        self.assertEqual(args[-1], "shop")

    def test_a_listing_failure_is_said(self):
        src = self.source("postgresql", "local")
        with mock.patch.object(agent, "_proc", return_value=(2, "", "connection refused")):
            with self.assertRaisesRegex(RuntimeError, "connection refused"):
                src.dumps()


class Signing(unittest.TestCase):
    # AWS's own worked examples ("Authenticating Requests (AWS Signature Version 4)" in the S3 docs).
    LOC = {"scheme": "https", "host": "examplebucket.s3.amazonaws.com", "bucket": "", "region": "us-east-1"}
    KEYS = ("AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
    NOW = datetime(2013, 5, 24, tzinfo=timezone.utc)

    def test_s3_location_and_region(self):
        loc = agent.s3_location("s3:https://nbg1.your-objectstorage.com/bucket/server-1")
        self.assertEqual((loc["host"], loc["bucket"], loc["prefix"], loc["region"]),
                         ("nbg1.your-objectstorage.com", "bucket", "server-1", "nbg1"))
        self.assertEqual(agent.s3_location("s3:s3.eu-central-1.amazonaws.com/b")["region"], "eu-central-1")
        self.assertEqual(agent.s3_location("s3:s3.amazonaws.com/b")["region"], "us-east-1")
        self.assertIsNone(agent.s3_location("sftp:host:/srv"))

    def test_header_signature_matches_aws(self):
        empty = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        url, headers = agent.s3_sign("GET", self.LOC, "test.txt", {}, {"range": "bytes=0-9"}, empty, *self.KEYS, now=self.NOW)
        self.assertEqual(url, "https://examplebucket.s3.amazonaws.com/test.txt")
        self.assertTrue(headers["Authorization"].endswith(
            "SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, "
            "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"))

    def test_presigned_link_matches_aws(self):
        url, _ = agent.s3_sign("GET", self.LOC, "test.txt", {}, {}, "", *self.KEYS, now=self.NOW, presign=86400)
        self.assertTrue(url.endswith("X-Amz-Signature=aeeed9bbccd4d02ee5c0109b86d86835f995330da4c265957d157751f604d404"), url)

    def test_downloads_go_beside_the_repository(self):
        s3 = agent.S3(agent.s3_location("s3:https://h.example/bucket/srv/one"), {})
        self.assertEqual(s3.key("x.gz"), "sitegoose-downloads/srv_one/x.gz")


CASES = json.load(open(os.path.join(os.path.dirname(AGENT), "..", "protocols", "download-cases.json")))


def unwrap(wrapped):
    """RSA-OAEP-SHA256 undone with the fixture's private key, as the browser does it."""
    key = CASES["test_key"]
    n, d = (int.from_bytes(base64.urlsafe_b64decode(key[k] + "=" * (-len(key[k]) % 4)), "big") for k in ("n", "d"))
    k = (n.bit_length() + 7) // 8
    em = pow(int.from_bytes(wrapped, "big"), d, n).to_bytes(k, "big")
    masked_seed, masked = em[1:33], em[33:]
    seed = bytes(a ^ b for a, b in zip(masked_seed, agent._mgf1(masked, 32)))
    block = bytes(a ^ b for a, b in zip(masked, agent._mgf1(seed, k - 33)))
    return block[block.index(b"\x01", 32) + 1:]


def decrypt(data, secret):
    """The download file read back as the dashboard reads it: tags checked, chunk by chunk."""
    enc_key, mac_key = agent.download_keys(secret)
    header, chunk = data[:12], int.from_bytes(data[8:12], "big")
    assert header[:8] == agent.DL_MAGIC
    out, pos, index, aes = [], 12, 0, agent.AesCtr(enc_key)
    while pos < len(data):
        size = min(chunk, len(data) - pos - 32)
        sealed, tag = data[pos:pos + size], data[pos + size:pos + size + 32]
        pos += size + 32
        last = b"\x01" if pos >= len(data) else b"\x00"
        assert hmac.compare_digest(tag, hmac.new(mac_key, header + index.to_bytes(8, "big") + last + sealed, hashlib.sha256).digest())
        out.append(aes.update(sealed))
        index += 1
    return b"".join(out)


class Downloads(unittest.TestCase):
    def test_the_file_matches_the_shared_cases(self):
        secret = bytes.fromhex(CASES["secret"])
        for case in CASES["cases"]:
            out = io.BytesIO()
            agent.encrypt_download(io.BytesIO(bytes.fromhex(case["plaintext"])), out, secret, chunk=CASES["chunk"])
            self.assertEqual(out.getvalue().hex(), case["file"])

    def test_a_file_too_big_stops(self):
        with self.assertRaises(OverflowError):
            agent.encrypt_download(io.BytesIO(b"x" * 100), io.BytesIO(), bytes(32), chunk=32, limit=80)

    def test_the_key_is_wrapped_for_the_browser_only(self):
        public = {k: CASES["test_key"][k] for k in ("kty", "n", "e")}
        wrapped = agent.oaep_wrap(public, bytes(range(32)))
        self.assertEqual(len(wrapped), 256)
        self.assertEqual(unwrap(wrapped), bytes(range(32)))
        self.assertNotEqual(agent.oaep_wrap(public, bytes(range(32))), wrapped)  # a new seed each time
        for bad in ({"kty": "EC"}, dict(public, e="Aw"), dict(public, n="AQAB")):
            with self.assertRaises(RuntimeError):
                agent.oaep_wrap(bad, bytes(32))


class Schedule(unittest.TestCase):
    def job(self, **backups):
        c = config(repository="/srv/backups", **backups)
        return agent.Backups(c)

    def test_nightly_weekly_off(self):
        wed = datetime(2026, 11, 4, 3, 30).timestamp()  # a Wednesday, 03:30 local
        self.assertTrue(self.job().due(wed))
        self.assertFalse(self.job(schedule="weekly").due(wed))
        self.assertTrue(self.job(schedule="weekly", weekday="Wednesday").due(wed))
        self.assertFalse(self.job(schedule="off").due(wed))

    def test_the_dashboard_wins_over_the_config(self):
        job = self.job(schedule="nightly", at="03:00")
        job.state["schedule"] = {"schedule": "off"}
        self.assertEqual(job.schedule()["from"], "dashboard")
        self.assertFalse(job.due(datetime(2026, 11, 4, 3, 30).timestamp()))
        job.state["schedule"] = {"schedule": "nightly", "at": "23:00"}
        self.assertFalse(job.due(datetime(2026, 11, 4, 3, 30).timestamp()))
        job.state["schedule"] = None
        self.assertEqual(job.schedule(), {"schedule": "nightly", "at": "03:00", "weekday": "sun", "from": "config"})


@unittest.skipUnless(shutil.which("restic"), "restic isn't installed")
class RealRun(unittest.TestCase):
    """A run into a repository on disk: a SQLite database and a folder, put back and checked."""

    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.site = os.path.join(self.root, "www", "site")
        os.makedirs(self.site)
        with open(os.path.join(self.site, "index.html"), "w") as f:
            f.write("good")
        self.db = os.path.join(self.root, "app.db")
        con = sqlite3.connect(self.db)
        con.execute("CREATE TABLE t (v TEXT)")
        con.execute("INSERT INTO t VALUES ('good')")
        con.commit()
        con.close()
        password = os.path.join(self.root, "password")
        with open(password, "w") as f:
            f.write("test password\n")
        c = config(repository=os.path.join(self.root, "repo"), password_file=password, databases=[{"sqlite": self.db}],
                   folders=[self.site], allow_restore=True)
        c["state_dir"] = os.path.join(self.root, "state")
        os.makedirs(c["state_dir"])
        self.sent = []
        self.patches = [mock.patch.object(agent, "request", side_effect=self.collector),
                        mock.patch.object(agent.Backups, "_services_up", return_value=set()),
                        mock.patch.object(agent.time, "sleep")]
        for p in self.patches:
            p.start()
        self.job = agent.Backups(c)

    def tearDown(self):
        for p in self.patches:
            p.stop()
        shutil.rmtree(self.root, ignore_errors=True)

    def collector(self, config, method, path, body=None, headers=None):
        self.sent.append((path, body))
        return 200, {}, b"{}"

    def value(self):
        con = sqlite3.connect(self.db)
        try:
            return con.execute("SELECT v FROM t").fetchone()[0]
        finally:
            con.close()

    def test_back_up_report_restore(self):
        record = self.job.back_up("nightly")
        self.assertEqual(record["state"], "ok", record)
        self.assertEqual(sorted(i["kind"] for i in record["items"]), ["database", "folder"])
        self.assertTrue(self.job.report())
        report = next(body for path, body in self.sent if path == "/events/backups")
        self.assertEqual(report["setup"], None)
        self.assertEqual(len(report["runs"]), 1)
        self.assertNotIn("id", report["runs"][0]["items"][0])

        # Broken since: a page defaced, a file added, the row changed.
        with open(os.path.join(self.site, "index.html"), "w") as f:
            f.write("hacked")
        with open(os.path.join(self.site, "backdoor.php"), "w") as f:
            f.write("<?php")
        con = sqlite3.connect(self.db)
        con.execute("UPDATE t SET v = 'bad'")
        con.commit()
        con.close()

        result = self.job.restore(record["run"], [], "req123456789abc")
        with open(os.path.join(self.site, "index.html")) as f:
            self.assertEqual(f.read(), "good")
        self.assertFalse(os.path.exists(os.path.join(self.site, "backdoor.php")))
        self.assertEqual(self.value(), "good")
        self.assertEqual(len(result["aside"]), 1)
        self.assertTrue(os.path.exists(os.path.join(result["aside"][0], "backdoor.php")))
        # Alerts paused, then the pause ended.
        pauses = [body for path, body in self.sent if path == "/events/maintenance"]
        self.assertEqual([("minutes" in p, p.get("end")) for p in pauses], [(True, None), (False, True)])

    def test_a_failed_restore_is_undone(self):
        record = self.job.back_up("nightly")
        with open(os.path.join(self.site, "index.html"), "w") as f:
            f.write("newer")
        with mock.patch.object(agent.Backups, "_services_up", side_effect=[{"web"}, set(), set(), set(), set(), set(), set()]):
            with self.assertRaisesRegex(RuntimeError, "web stopped after the restore. Everything was put back as it was"):
                self.job.restore(record["run"], [], "req2")
        with open(os.path.join(self.site, "index.html")) as f:
            self.assertEqual(f.read(), "newer")

    def test_a_lost_folder_comes_back(self):
        record = self.job.back_up("nightly")
        shutil.rmtree(self.site)
        self.job.restore(record["run"], [self.site], "req3")
        with open(os.path.join(self.site, "index.html")) as f:
            self.assertEqual(f.read(), "good")

    def test_export_writes_the_database_file(self):
        record = self.job.back_up("nightly")
        name = next(i["name"] for i in record["items"] if i["kind"] == "database")
        out = os.path.join(self.root, "out.db")
        self.job.export(record["run"], name, out)
        con = sqlite3.connect(out)
        self.assertEqual(con.execute("SELECT v FROM t").fetchone()[0], "good")
        con.close()

    def test_restore_refuses_when_not_allowed_from_the_dashboard(self):
        self.job.conf["allow_restore"] = False
        with mock.patch.object(agent, "request", side_effect=lambda c, m, p, body=None, headers=None: (
                200, {}, json.dumps({"requests": [{"id": "r1", "kind": "restore", "run": "20261107T030000Z"}]}).encode())
                if m == "GET" else self.collector(c, m, p, body)):
            self.job.poll()
        failed = [body for path, body in self.sent if path == "/events/backups/requests" and body["state"] == "failed"]
        self.assertIn("allow_restore", failed[0]["error"])

    def test_back_up_now_and_download_from_our_storage(self):
        uploaded = {}

        def collector(c, method, path, body=None, headers=None):
            self.sent.append((path, body))
            if method == "GET":
                return 200, {}, json.dumps({"schedule": {"schedule": "weekly", "weekday": "mon", "at": "04:00"}, "requests": [{
                    "id": "r7", "kind": "backup", "download": True,
                    "hosted": {"public_key": {k: CASES["test_key"][k] for k in ("kty", "n", "e")}, "max_bytes": 10 ** 9}}]}).encode()
            if path == "/events/backups/upload":
                uploaded["size"] = body["bytes"]
                return 200, {}, json.dumps({"part_size": 1024, "parts": [{"n": n + 1, "url": "https://up/%d" % n} for n in range(-(-body["bytes"] // 1024))]}).encode()
            return 200, {}, b"{}"

        def put(url, data, timeout=300):
            uploaded.setdefault("data", b"")
            uploaded["data"] += data
            return '"etag%d"' % len(uploaded["data"])

        with mock.patch.object(agent, "request", side_effect=collector), mock.patch.object(agent, "put_part", side_effect=put):
            self.job.poll()
        done = [body for path, body in self.sent if path == "/events/backups/requests" and body["state"] == "done"]
        self.assertEqual(len(done), 1, self.sent)
        self.assertTrue(done[0]["hosted"])
        self.assertEqual(self.job.schedule()["schedule"], "weekly")
        self.assertEqual(len(uploaded["data"]), uploaded["size"])
        plain = decrypt(uploaded["data"], unwrap(base64.b64decode(done[0]["wrapped_key"])))
        archive = zipfile.ZipFile(io.BytesIO(plain))
        names = archive.namelist()
        self.assertEqual(len(names), 2)
        self.assertTrue(any(n.endswith(".tar") for n in names))
        finished = [body for path, body in self.sent if path == "/events/backups/upload/done"][0]
        self.assertEqual([p["n"] for p in finished["parts"]], list(range(1, len(finished["parts"]) + 1)))
        self.assertEqual(os.listdir(self.job.conf["temp_dir"]).count("x"), 0)
        self.assertFalse([n for n in os.listdir(self.job.conf["temp_dir"]) if n.startswith("backup-download-")])

    def test_a_download_over_the_plan_is_refused(self):
        record = self.job.back_up("manual")
        hosted = {"public_key": {k: CASES["test_key"][k] for k in ("kty", "n", "e")}, "max_bytes": 100}
        with self.assertRaisesRegex(RuntimeError, "more than the 100 bytes a file your plan allows"):
            self.job.download(record["run"], [], hosted, "r8")


if __name__ == "__main__":
    unittest.main()
