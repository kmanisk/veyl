#!/usr/bin/env python3
"""Regression: job-enabled policy and native tool grants coexist with workspace delegation."""
import json
import os
from pathlib import Path
import re
import subprocess
import unittest

import product_features as pf
from upstream_workspace import PEER

PROVIDERS = {
    "rea": ["audit_release_exposure", "extract_artifact", "inspect_artifact",
            "inspect_python_pyc", "inspect_rust_binary", "inspect_sqlite_database",
            "inspect_wasm_artifact"],
    "rust-anything": ["analyze", "diff", "profile", "report"],
    "node-utils": ["json_summary", "sha256_text"],
}
NATIVE = set(re.findall(r'Self::[A-Za-z]+\s*=>\s*"([a-z0-9_]+)"',
                        (Path(__file__).resolve().parents[1] / "src/core/tools.rs").read_text())) - {"rewind", "rewind_restore", "rewind_clear"}


class WorkspaceJobs(unittest.TestCase):
    def setUp(self):
        self.f = f = pf.ProductFeatures()
        f.setUp()
        self.addCleanup(f.doCleanups)
        state = f.base / "state"
        state.mkdir(mode=0o700)
        jobs = state / "jobs"
        jobs.mkdir(mode=0o700)
        f.config = state / "clients.json"
        f.audit = state / "audit.jsonl"
        f.audit.touch(mode=0o600)
        self.scope = f.workspace / "project"
        self.scope.mkdir()
        (self.scope / "sample.txt").write_text("workspace-job-canary")
        self.assertTrue({"exec_command", "goal_create", "mcp_servers_call"} <= NATIVE)
        f.doc.update(policy_version=4, audit_log=str(f.audit), job_state_dir=str(jobs),
                     job_profiles={"shell": {"executable": "/usr/bin/bash",
                         "args": ["--noprofile", "--norc", "-i"], "timeout_seconds": 3600,
                         "extended_runtime": True, "interactive": True, "pty": True,
                         "max_output_bytes": 65536}}, mcp_servers={})
        for client in f.doc["clients"]:
            client.update(mode="standard", disabled=False, tools=sorted(NATIVE),
                          allowed_servers=list(PROVIDERS), allowed_server_tools=PROVIDERS)
        bundles = state / "upstream-bundles"
        bundles.mkdir(mode=0o700)
        for name, tools in PROVIDERS.items():
            bundle = bundles / name
            bundle.mkdir(mode=0o700)
            script = bundle / "server.py"
            script.write_text(PEER.replace('("analyze","inspect_python_pyc","inspect_rust_binary")', repr(tuple(tools))))
            script.chmod(0o600)
            f.doc["mcp_servers"][name] = {"transport": "stdio", "command": "/usr/bin/python3",
                "args": ["/upstream/bundle/server.py"], "runtime_bundle": True}
        f.write_config()
        self.process = f.start()
        self.session = f.connect()

    def assert_inventory(self, session):
        _, reply = self.f.rpc("tools/list", session, pf.TOKEN)
        expected = NATIVE | {f"{provider}__{tool}" for provider, tools in PROVIDERS.items() for tool in tools}
        actual = [t["name"] for t in reply["result"]["tools"]]
        self.assertEqual(len(actual), len(expected), "duplicate tool registrations")
        self.assertEqual(set(actual), expected)

    def assert_workspace(self, session):
        for name, args in (("rea__inspect_python_pyc", {"path": str(self.scope / "sample.txt")}),
                           ("rust-anything__analyze", {"root": str(self.scope)})):
            result = self.f.call(name, args, session)
            self.assertFalse(result.get("isError", False), result)
            body = json.loads(result["content"][0]["text"])
            self.assertEqual(body["content"], "workspace-job-canary")
            self.assertTrue(body["readonly"])

    def test_job_policy_live_grants_and_restart(self):
        f = self.f
        self.assert_inventory(self.session)
        for provider in ("rea", "rust-anything"):
            f.cli("mcp-servers", "workspace", "primary", provider, str(self.scope))
        self.assert_inventory(self.session)
        self.assert_workspace(self.session)
        result = f.call("exec_command", {"command": "printf job-enabled", "timeout_seconds": 6}, self.session)
        self.assertFalse(result.get("isError", False), result)
        self.assertEqual(json.loads(result["content"][0]["text"])["stdout"], "job-enabled")
        f.stop(self.process)
        self.process = f.start()
        self.session = f.connect()
        self.assert_inventory(self.session)
        self.assert_workspace(self.session)
        f.cli("mcp-servers", "unworkspace", "primary", "rea")
        result = f.call("rea__inspect_python_pyc", {"path": str(self.scope / "sample.txt")}, self.session)
        self.assertFalse(result.get("isError", False), result)
        self.assertFalse(json.loads(result["content"][0]["text"])["visible"])
        self.assert_inventory(self.session)

    def test_yolo_stale_workspace_identity_and_recovery(self):
        f = self.f
        f.cli("mode", "yolo", "primary", "--confirm-native")
        for provider in ("rea", "rust-anything"):
            f.cli("mcp-servers", "workspace", "primary", provider, str(self.scope))
        self.assert_inventory(self.session)
        self.assert_workspace(self.session)
        saved = self.scope.with_name("project-original")
        self.scope.rename(saved)
        self.scope.mkdir()
        (self.scope / "sample.txt").write_text("replacement")
        try:
            for name, args in (("rea__inspect_python_pyc", {"path": "sample.txt"}),
                               ("rust-anything__analyze", {"root": str(self.scope)})):
                self.assertTrue(f.call(name, args, self.session)["isError"])
        finally:
            (self.scope / "sample.txt").unlink()
            self.scope.rmdir()
            saved.rename(self.scope)
        self.assert_workspace(self.session)

    def test_invalid_workspace_policy_still_rejected(self):
        f = self.f
        for value in ({"rea": 7}, ["rea"], {"node-utils": str(self.scope)}, {"rea": str(f.base)}):
            doc = json.loads(f.config.read_text())
            doc["clients"][0]["upstream_workspace_roots"] = value
            # A separate invalid config must never start or accept grants.
            invalid = f.config.parent / "invalid.json"
            invalid.write_text(json.dumps(doc))
            invalid.chmod(0o600)
            run = subprocess.run([pf.BIN, "mcp-servers", "list", "--config", invalid],
                                 capture_output=True, text=True, timeout=8)
            self.assertNotEqual(run.returncode, 0, value)
        self.assert_inventory(self.session)


if __name__ == "__main__":
    unittest.main()
