#!/usr/bin/env python3
"""Integration regressions for canonical mode admission without production state."""

import json
import os
import pty
import subprocess
import time
import unittest

import product_features as product


class PermissionModes(unittest.TestCase):
    def setUp(self):
        self.fixture = product.ProductFeatures()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def cli(self, *args, success=True, binary=product.BIN):
        f = self.fixture
        result = subprocess.run(
            [binary, *args, "--config", f.config],
            env=dict(os.environ, HOME=str(f.base)),
            capture_output=True,
            text=True,
            timeout=12,
        )
        self.assertEqual(result.returncode == 0, success, result.stderr)
        return result.stdout if success else result.stderr

    def tools(self, session, token=product.TOKEN):
        _, reply = self.fixture.rpc("tools/list", session, token)
        return {tool["name"] for tool in reply["result"]["tools"]}

    def test_interactive_mode_selects_the_chosen_client(self):
        master, slave = pty.openpty()
        try:
            with subprocess.Popen(
                [product.BIN, "mode", "get", "--config", self.fixture.config],
                stdin=slave, stderr=slave, stdout=subprocess.PIPE, text=True,
            ) as command:
                os.write(master, b"2\n")
                output, _ = command.communicate(timeout=5)
            self.assertEqual(command.returncode, 0)
            self.assertIn("client=secondary client_state=enabled mode=standard", output)
        finally:
            os.close(master)
            os.close(slave)

    def test_migrates_scoped_workspace_without_widening_grants(self):
        f = self.fixture
        baseline = os.environ.get("VEYL_BASELINE_BIN")
        if not baseline:
            self.skipTest("Requires the published 0.6.1-beta executable")
        private = f.base / "private"
        private.mkdir(mode=0o700)
        f.config = private / "clients.json"
        extra = f.base / "approved-workspace"
        extra.mkdir()
        (extra / "approved.txt").write_text("approved")
        outside = f.base / "outside.txt"
        outside.write_text("outside")
        f.doc["policy_version"] = 1
        primary = f.doc["clients"][0]
        primary.update(tools=["read_file"], yolo_roots=[str(extra)])
        f.write_config()
        self.cli("yolo", "enable", "--client", "primary", binary=baseline)
        f.start()
        session = f.connect()
        self.assertIn("mode=standard", self.cli("mode", "get", "primary"))
        self.assertEqual(self.tools(session), {"read_file"})
        self.cli("mode", "migrate")
        new = json.loads(f.config.read_text())["clients"][0]
        self.assertEqual(new["mode"], "standard")
        self.assertNotIn("yolo_roots", new)
        self.assertEqual(new["token_sha256"], primary["token_sha256"])
        self.assertEqual(new["tools"], ["read_file"])
        self.assertNotIn("native_tool_preset", new)
        read = f.call("read_file", {"path": str(extra / "approved.txt")}, session)
        self.assertTrue(read["isError"])
        self.assertTrue(f.call("read_file", {"path": str(outside)}, session)["isError"])
        self.assertEqual(self.tools(session), {"read_file"})

    def test_preset_and_explicit_denials_follow_the_current_policy(self):
        f = self.fixture
        state = f.base / "private-state"
        state.mkdir(mode=0o700)
        jobs = state / "jobs"
        jobs.mkdir(mode=0o700)
        f.config = state / "clients.json"
        f.audit = state / "audit.jsonl"
        f.audit.touch(mode=0o600)
        f.doc.update(
            policy_version=4, audit_log=str(f.audit), job_state_dir=str(jobs),
            job_profiles={
                "probe": {
                    "executable": "/usr/bin/python3",
                    "args": ["-c", "from pathlib import Path; import sys; assert Path(sys.argv[1]).exists()",
                             str(f.config)],
                    "timeout_seconds": 6, "max_output_bytes": 1024,
                }
            },
        )
        primary, secondary = f.doc["clients"]
        for client in (primary, secondary):
            client.update(mode="standard", disabled=False, tools=["read_file"])
        primary["deny_tools"] = ["apply_patch", "mcp_servers_call"]
        f.write_config()
        outside = f.base / "outside.txt"
        gateway = f.start()
        session = f.connect()
        self.assertEqual(self.tools(session), {"read_file"})
        self.assertIn("Multiple clients configured", self.cli("mode", "yolo", "--confirm-native", success=False))
        self.cli("mode", "full", "primary", success=False)
        # Validate that an unsafe state layout cannot be approved.
        alias = f.base / "state-alias"
        alias.hardlink_to(f.config)
        self.cli("mode", "yolo", "primary", "--confirm-native", success=False)
        alias.unlink()
        self.assertEqual(self.tools(session), {"read_file"})
        self.assertIn("mode=yolo", self.cli("mode", "yolo", "primary", "--confirm-native"))
        tools = self.tools(session)
        self.assertTrue({"write_file", "search_files", "git_inspect", "system_inspect",
                         "job_start", "exec_command", "skills_read"} <= tools)
        self.assertTrue({"apply_patch", "edit_file", "mcp_servers_list", "mcp_servers_call"}.isdisjoint(tools))
        self.assertEqual(self.tools(f.connect(product.OTHER_TOKEN), product.OTHER_TOKEN), {"read_file"})
        written = f.call("write_file", {"path": str(outside), "content": "permitted"}, session)
        self.assertFalse(written["isError"])
        self.assertEqual(outside.read_text(), "permitted")
        for denied in ("apply_patch", "edit_file", "mcp_servers_call"):
            self.assertTrue(f.call(denied, {}, session)["isError"])
        self.assertFalse(f.call("read_file", {"path": str(f.config)}, session)["isError"])
        started = f.call("job_start", {"profile": "probe"}, session)
        self.assertFalse(started["isError"], started)
        job = json.loads(started["content"][0]["text"])["job_id"]
        deadline = time.monotonic() + 8
        while True:
            receipt = f.call("job_status", {"job_id": job}, session)
            receipt = json.loads(receipt["content"][0]["text"])
            if receipt.get("state") not in ("starting", "running"):
                break
            self.assertLess(time.monotonic(), deadline, receipt)
            time.sleep(.04)
        if receipt["exit_code"] != 0:
            self.fail(f"{receipt}\n{f.call('job_logs', {'job_id': job}, session)}")

        self.cli("diagnostics", "revoke", "primary")
        self.assertNotIn("system_inspect", self.tools(session))
        self.assertTrue(f.call("system_inspect", {}, session)["isError"])
        self.cli("diagnostics", "grant", "primary")
        self.assertIn("system_inspect", self.tools(session))
        self.cli("mode", "disable", "primary")
        status, _, _ = f.request(
            f.mcp, "POST", "/mcp", {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            Authorization="Bearer " + product.TOKEN, **{"Mcp-Session-Id": session},
        )
        self.assertEqual(status, 401)
        self.assertIn("mode=standard", self.cli("mode", "get", "primary"))
        self.cli("mode", "enable", "primary")
        self.assertEqual(self.tools(session), {"read_file", "system_inspect"})
        self.cli("mode", "yolo", "primary", "--confirm-native")

        # Startup must recognize the same approval after the original process exits.
        f.stop(gateway)
        f.start()
        restarted = f.connect()
        self.assertEqual(self.tools(restarted), tools)
        self.cli("mode", "standard", "primary")
        self.assertEqual(self.tools(restarted), {"read_file", "system_inspect"})
        self.assertTrue(f.call("read_file", {"path": str(outside)}, restarted)["isError"])
        self.assertTrue(f.call("write_file", {"path": "denied", "content": "denied"}, restarted)["isError"])
        self.assertIn("VERIFY_RESULT=VALID", self.cli("audit", "verify"))

    def test_explicit_bulk_mode_keeps_client_boundaries(self):
        f = self.fixture
        state = f.base / "state"
        state.mkdir(mode=0o700)
        jobs = state / "jobs"
        jobs.mkdir(mode=0o700)
        f.config = state / "clients.json"
        f.audit = state / "ledger.jsonl"
        f.audit.touch(mode=0o600)
        f.doc.update(policy_version=4, audit_log=str(f.audit), job_state_dir=str(jobs))
        for client in f.doc["clients"]:
            client.update(mode="standard", disabled=False, tools=["read_file"])
        f.doc["clients"][0]["deny_tools"] = ["apply_patch"]
        f.write_config()
        before = json.loads(f.config.read_text())["clients"]
        f.start()
        session = f.connect()
        other = f.connect(product.OTHER_TOKEN)
        self.cli("mode", "full", "--all", success=False)
        self.cli("mode", "yolo", "--all", "primary", "--confirm-native", success=False)
        alias = f.base / "alias"
        alias.hardlink_to(f.config)
        self.cli("mode", "yolo", "--all", "--confirm-native", success=False)
        alias.unlink()
        self.assertEqual(json.loads(f.config.read_text())["clients"], before)
        self.assertEqual(self.tools(session), {"read_file"})
        self.cli("mode", "yolo", "--all", "--confirm-native")
        after = json.loads(f.config.read_text())["clients"]
        self.assertTrue(all(c["mode"] == "yolo" and c["native_tool_preset"] for c in after))
        for original, changed in zip(before, after):
            for key in ("root", "tools", "deny_tools", "token_sha256", "disabled"):
                self.assertEqual(original.get(key), changed.get(key))
        self.assertNotIn("apply_patch", self.tools(session))
        self.assertIn("apply_patch", self.tools(other, product.OTHER_TOKEN))
        self.cli("mode", "disable", "secondary")
        self.cli("mode", "standard", "--all")
        self.assertEqual(self.tools(session), {"read_file"})
        disabled = json.loads(f.config.read_text())["clients"][1]
        self.assertTrue(disabled["disabled"])
        self.assertEqual(disabled["mode"], "standard")
        # A synthetic interrupted batch marker keeps admission closed and can
        # only be recovered by the explicit bulk Standard downgrade.
        pending = state / ".clients.json.policy-pending"
        pending.write_text("@mode-all")
        pending.chmod(0o600)
        self.cli("mode", "yolo", "--all", "--confirm-native", success=False)
        self.cli("mode", "standard", "primary", success=False)
        self.assertTrue(pending.exists())
        self.cli("mode", "standard", "--all")
        self.assertFalse(pending.exists())
        recovered = json.loads(f.config.read_text())["clients"]
        self.assertTrue(all(c["mode"] == "standard" and "yolo_revision" not in c for c in recovered))
        self.assertTrue(recovered[1]["disabled"])
        self.assertIn("VERIFY_RESULT=VALID", self.cli("audit", "verify"))

    def test_old_broad_approval_cannot_activate_native_preset(self):
        f = self.fixture
        baseline = os.environ.get("VEYL_BASELINE_BIN")
        if not baseline:
            self.skipTest("Requires the published 0.6.1-beta executable")
        state = f.base / "state"
        state.mkdir(mode=0o700)
        f.config = state / "clients.json"
        f.audit = state / "ledger.jsonl"
        f.audit.touch(mode=0o600)
        jobs = state / "jobs"
        jobs.mkdir(mode=0o700)
        f.doc.update(policy_version=2, audit_log=str(f.audit), job_state_dir=str(jobs))
        f.doc["clients"][0]["tools"] = ["read_file"]
        f.doc["clients"][1]["tools"] = ["read_file"]
        # No skill or job grants are needed for this approval.
        f.write_config()
        self.cli("yolo", "set", "--client", "primary", "--mode", "yolo", binary=baseline)
        legacy_revision = json.loads(f.config.read_text())["clients"][0]["yolo_revision"]
        self.cli("mode", "migrate")
        document = json.loads(f.config.read_text())
        self.assertEqual(document["clients"][0]["mode"], "standard")
        self.assertNotIn("native_tool_preset", document["clients"][0])
        f.start()
        self.assertEqual(self.tools(f.connect()), {"read_file"})
        document["clients"][0].update(mode="yolo", native_tool_preset=True, yolo_revision=legacy_revision)
        f.config.write_text(json.dumps(document))
        self.assertIn("Cannot verify durable", self.cli("mode", "get", "primary", success=False))


if __name__ == "__main__":
    unittest.main()
