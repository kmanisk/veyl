#!/usr/bin/env python3
"""Native YOLO and Standard black-box regressions against isolated state."""

import json
import os
import socket
import subprocess
import time
import unittest

import product_features as product


class UnifiedYolo(unittest.TestCase):
    def setUp(self):
        self.f = f = product.ProductFeatures()
        f.setUp()
        self.addCleanup(f.doCleanups)
        f.doc.update(policy_version=4, job_state_dir=str(f.base / "jobs"), job_profiles={
            "health": {"executable": "/usr/bin/true", "args": [], "timeout_seconds": 3},
        })
        for client in f.doc["clients"]:
            client.update(mode="standard", disabled=False, tools=["read_file", "exec_command"])
        f.write_config()

    def mode(self, *args, binary=product.BIN, success=True):
        p = subprocess.run([binary, "mode", *args, "--config", self.f.config],
                           capture_output=True, text=True, timeout=10)
        self.assertEqual(p.returncode == 0, success, p.stderr)
        return p.stdout

    def result(self, tool, args, session):
        result = self.f.call(tool, args, session)
        self.assertFalse(result["isError"], result)
        return json.loads(result["content"][0]["text"])

    def test_host_execution_and_isolation_after_restart(self):
        f = self.f
        outside = f.base / "sibling.txt"
        outside.write_text("host data")
        gateway = f.start()
        session = f.connect()
        self.assertTrue(f.call("read_file", {"path": str(outside)}, session)["isError"])
        self.assertTrue(f.call("git_status", {}, session)["isError"])
        self.assertTrue(f.call("exec_command", {"command": "true", "cwd": str(f.base)}, session)["isError"])
        standard = f.call("exec_command", {"command": "printf standard", "timeout_seconds": 5}, session)
        if os.environ.get("VEYL_BWRAP_DISABLED"):
            self.assertTrue(standard["isError"] or json.loads(standard["content"][0]["text"])["exit_code"] != 0)
        else:
            self.assertFalse(standard["isError"], standard)
            self.assertEqual(json.loads(standard["content"][0]["text"])["stdout"], "standard")
        self.mode("full", "primary", success=False)
        self.mode("yolo", "primary", success=False)
        self.mode("yolo", "primary", "--confirm-native")
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen()
            command = ("import pathlib,socket,os; assert os.geteuid()!=0; "
                       "assert 'NoNewPrivs:\\t1' in pathlib.Path('/proc/self/status').read_text(); "
                       "assert pathlib.Path('sibling.txt').read_text()=='host data'; "
                       f"socket.create_connection(('127.0.0.1',{listener.getsockname()[1]})).close(); "
                       "print('native')")
            job = self.result("exec_command", {
                "argv": ["/usr/bin/python3", "-c", command], "cwd": str(f.base),
                "timeout_seconds": 5}, session)
            self.assertEqual(job["exit_code"], 0, job)
            self.assertEqual(job["stdout"], "native\n")
        repo = f.base / "repo"
        subprocess.run(["git", "init", "-q", str(repo)], check=True, timeout=5)
        (repo / "example.txt").write_text("native fixture")
        self.result("git_status", {"path": str(repo)}, session)
        self.result("git_add", {"path": str(repo), "files": ["example.txt"]}, session)
        self.result("git_commit", {"path": str(repo), "message": "Native fixture"}, session)
        self.assertEqual(subprocess.check_output(["git", "-C", repo, "show", "HEAD:example.txt"],
                                                 text=True, timeout=5), "native fixture")
        other = f.connect(product.OTHER_TOKEN)
        self.assertTrue(f.call("job_status", {"job_id": job["job_id"]}, other,
                               product.OTHER_TOKEN)["isError"])
        f.stop(gateway)
        f.start()
        session = f.connect()
        self.assertEqual(self.result("job_status", {"job_id": job["job_id"]}, session)["exit_code"], 0)
        self.mode("standard", "primary")
        self.assertTrue(f.call("read_file", {"path": str(outside)}, session)["isError"])
        self.mode("disable", "primary")
        status, _, _ = f.request(f.mcp, "POST", "/mcp",
                                 {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
                                 Authorization="Bearer " + product.TOKEN)
        self.assertEqual(status, 401)

    def test_legacy_scoped_yolo_requires_new_local_confirmation(self):
        baseline = os.environ.get("VEYL_BASELINE_BIN")
        if baseline is None:
            self.skipTest("Set VEYL_BASELINE_BIN to an explicit 0.6.1-beta fixture binary")
        f = self.f
        config_dir = f.base / "private"
        config_dir.mkdir(mode=0o700)
        f.config = config_dir / "clients.json"
        f.doc["policy_version"] = 1
        for client in f.doc["clients"]:
            del client["mode"], client["disabled"]
            client["tools"] = ["read_file"]
        f.write_config()
        legacy = subprocess.run([baseline, "yolo", "enable", "--client", "primary", "--config", f.config],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(legacy.returncode, 0, legacy.stderr)
        f.start()
        session = f.connect()
        _, listed = f.rpc("tools/list", session)
        self.assertEqual([tool["name"] for tool in listed["result"]["tools"]], ["read_file"])
        self.mode("yolo", "primary", "--confirm-native", success=False)
        self.mode("migrate")
        state = json.loads(f.config.read_text())
        self.assertEqual(state["clients"][0]["mode"], "standard")
        self.assertNotIn("yolo_revision", state["clients"][0])
        self.assertTrue(f.call("exec_command", {"command": "true"}, session)["isError"])
        self.mode("yolo", "primary", "--confirm-native")
        self.assertEqual(self.result("exec_command", {"command":"true","timeout_seconds":5}, session)["exit_code"], 0)

    def test_downgrade_stops_an_existing_native_job(self):
        f = self.f
        self.mode("yolo", "primary", "--confirm-native")
        f.start()
        session = f.connect()
        job = self.result("task_run", {"command": "printf alive; sleep 900", "wait_seconds": 0}, session)
        until = time.monotonic() + 8
        while "alive" not in self.result("job_logs", {"job_id": job["job_id"]}, session)["stdout"]:
            self.assertLess(time.monotonic(), until)
            time.sleep(.04)
        self.mode("standard", "primary")
        auth = f.pair()
        while time.monotonic() < until:
            status, _, body = f.request(f.admin, "GET", "/api/dashboard/jobs?client=primary", **auth)
            self.assertEqual(status, 200, body)
            current = next(row for row in json.loads(body)["jobs"] if row["job_id"] == job["job_id"])
            if current["state"] == "canceled":
                break
            time.sleep(.1)
        else:
            self.fail(current)

    def test_cancel_stops_standard_and_native_descendants(self):
        f = self.f
        f.doc["clients"][0]["tools"] += ["task_run", "job_logs", "job_cancel"]
        f.write_config()
        f.start()
        session = f.connect()
        start = self.result("task_run", {"command":
            "(while :; do printf x >> heartbeat; sleep .1; done) & wait",
            "wait_seconds": 0, "timeout_seconds": 10}, session)
        heartbeat = f.workspace / "heartbeat"
        until = time.monotonic() + 5
        while not heartbeat.exists() or heartbeat.stat().st_size < 3:
            self.assertLess(time.monotonic(), until)
            time.sleep(.05)
        status = self.result("job_cancel", {"job_id": start["job_id"]}, session)
        self.assertEqual(status["state"], "canceled")
        count = heartbeat.stat().st_size
        time.sleep(.3)
        self.assertEqual(heartbeat.stat().st_size, count)

        self.mode("yolo", "primary", "--confirm-native")
        job = self.result("task_run", {"command": "sleep 60 & echo $!; wait",
                                       "wait_seconds": 0}, session)
        jid = {"job_id": job["job_id"]}
        until = time.monotonic() + 5
        while not (pid := self.result("job_logs", jid, session)["stdout"].strip()).isdigit():
            self.assertLess(time.monotonic(), until)
            time.sleep(.05)
        self.assertTrue(os.path.exists(f"/proc/{pid}"))
        self.assertEqual(self.result("job_cancel", jid, session)["state"], "canceled")
        self.assertFalse(os.path.exists(f"/proc/{pid}"))

    def test_pipe_and_pty_sessions(self):
        f = self.f
        self.mode("yolo", "primary", "--confirm-native")
        f.start()
        session = f.connect()
        for name, transport in (("shell", "pipe"), ("pty", "pty")):
            with self.subTest(transport=transport):
                job = self.result("process_start", {"profile": name, "timeout_seconds": 8}, session)
                jid = {"job_id": job["job_id"]}
                self.assertEqual(job["transport"], transport)
                until = time.monotonic() + 4
                while self.result("job_status", jid, session)["state"] != "running":
                    self.assertLess(time.monotonic(), until)
                    time.sleep(.04)
                if name == "pty":
                    self.result("process_resize", dict(jid, rows=30, cols=73), session)
                self.result("process_input", dict(jid, sequence=0, data="printf 'session-%s\n' ready; exit\n"), session)
                while "session-ready" not in self.result("job_logs", jid, session)["stdout"]:
                    self.assertLess(time.monotonic(), until)
                    time.sleep(.04)

    def test_disabled_legacy_full_reenable_and_replay(self):
        baseline = os.environ.get("VEYL_BASELINE_BIN")
        if baseline is None:
            self.skipTest("Set VEYL_BASELINE_BIN to an explicit 0.6.1-beta fixture binary")
        f = self.f
        f.doc["policy_version"] = 3
        f.write_config()
        self.mode("full", "primary", "--confirm-full", binary=baseline)
        old_enabled = f.config.read_bytes()
        self.mode("disable", "primary", binary=baseline)
        self.mode("migrate")
        migrated = json.loads(f.config.read_text())["clients"][0]
        self.assertEqual((migrated["disabled"], migrated["mode"]), (True, "standard"))
        self.assertNotIn("yolo_revision", migrated)
        self.mode("yolo", "primary", "--confirm-native", success=False)
        self.mode("enable", "primary")
        gateway = f.start()
        session = f.connect()
        _, reply = f.rpc("tools/list", session)
        self.assertNotIn("task_run", [tool["name"] for tool in reply["result"]["tools"]])

        standard = f.config.read_bytes()
        self.mode("disable", "primary")
        disabled = f.config.read_bytes()
        f.stop(gateway)
        f.config.write_bytes(standard)
        self.mode("list", success=False)
        f.config.write_bytes(disabled)
        self.mode("enable", "primary")
        self.mode("yolo", "primary", "--confirm-native")
        approved = f.config.read_bytes()
        gateway = f.start()
        session = f.connect()
        self.assertEqual(self.result("exec_command", {"command":"true","timeout_seconds":5}, session)["exit_code"], 0)
        self.mode("standard", "primary")
        revoked = f.config.read_bytes()
        f.stop(gateway)
        for stale in (old_enabled, approved):
            f.config.write_bytes(stale)
            self.mode("list", success=False)
        f.config.write_bytes(revoked)
        f.start()
        session = f.connect()
        self.assertTrue(f.call("exec_command", {"command":"true","cwd":str(f.base)}, session)["isError"])
        self.assertEqual(f.call("read_file", {"path":"missing"}, session)["isError"], True)

    def test_interrupted_migration_recovers_before_and_after_publication(self):
        f = self.f
        f.doc["policy_version"] = 3
        f.write_config()
        marker = f.config.with_name(".clients.json.policy-pending")
        prepublication = f.config.read_bytes()
        for phase in ("before", "after"):
            with self.subTest(phase=phase):
                if phase == "before":
                    f.config.write_bytes(prepublication)
                else:
                    # Simulate a published privilege revision whose audited
                    # outcome was lost. Standard recovery must remove it.
                    doc = json.loads(f.config.read_bytes())
                    doc["clients"][0].update(mode="yolo", yolo_revision="a"*32,
                                              native_tool_preset=True)
                    f.config.write_text(json.dumps(doc))
                marker.write_text("@mode-migration")
                marker.chmod(0o600)
                self.mode("list", success=False)
                refused = subprocess.run([product.BIN, "http", "--listen", "127.0.0.1:0",
                                          "--config", f.config], capture_output=True, text=True, timeout=5)
                self.assertIn("Interrupted policy update", refused.stderr)
                self.mode("standard", "--all")
                self.assertFalse(marker.exists())
                self.assertEqual(json.loads(f.config.read_text())["policy_version"], 4)
                gateway = f.start()
                session = f.connect()
                self.assertTrue(f.call("exec_command", {"command":"true","cwd":str(f.base)}, session)["isError"])
                f.stop(gateway)

    def test_migrate_real_legacy_full_approval(self):
        baseline = os.environ.get("VEYL_BASELINE_BIN")
        if baseline is None:
            self.skipTest("Set VEYL_BASELINE_BIN to an explicit 0.6.1-beta fixture binary")
        self.f.doc["policy_version"] = 3
        self.f.write_config()
        self.mode("full", "primary", "--confirm-full", binary=baseline)
        self.mode("migrate")
        state = json.loads(self.f.config.read_text())
        self.assertEqual(state["policy_version"], 4)
        self.assertEqual(state["clients"][0]["mode"], "yolo")
        self.assertEqual(state["clients"][1]["mode"], "standard")
        self.assertNotIn("native_tool_preset", state["clients"][0])
        self.f.start()
        session = self.f.connect()
        job = self.result("exec_command", {"command": "printf migrated", "timeout_seconds": 5}, session)
        self.assertEqual(job["stdout"], "migrated")


if __name__ == "__main__":
    unittest.main()
