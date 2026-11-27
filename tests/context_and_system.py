#!/usr/bin/env python3
"""E2E and security acceptance suite for Phase C1 system inspection and context tools."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import product_features as pf


class ContextAndSystemTests(unittest.TestCase):
    def setUp(self):
        self.f = pf.ProductFeatures()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        state = self.f.base / "private-state"
        state.mkdir(mode=0o700)
        jobs = state / "jobs"
        jobs.mkdir(mode=0o700)
        self.f.audit = state / "audit.jsonl"
        self.f.audit.touch(mode=0o600)
        self.f.config = state / "clients.json"
        self.f.doc["audit_log"] = str(self.f.audit)
        self.f.doc["job_state_dir"] = str(jobs)
        self.f.doc["job_profiles"] = {
            "probe": {
                "executable": "/usr/bin/true",
                "args": [],
                "timeout_seconds": 8,
                "max_output_bytes": 128,
            }
        }
        self.repo = Path(self.f.doc["clients"][0]["root"])

    def start(self, tools, native=False):
        self.f.doc["policy_version"] = 4
        for client in self.f.doc["clients"]:
            client["mode"] = "standard"
            client["disabled"] = False
        primary = self.f.doc["clients"][0]
        primary["tools"] = tools
        self.f.write_config()
        if native:
            self.f.cli("mode", "yolo", primary["id"], "--confirm-native")
        proc = self.f.start()
        self.addCleanup(self.f.stop, proc)
        return self.f.connect(token=pf.TOKEN)

    def call(self, session, name, arguments=None, error=False):
        res = self.f.call(name, arguments or {}, session)
        if error:
            self.assertTrue(res["isError"], f"{name} unexpectedly succeeded: {res}")
            return res["content"][0]["text"]
        self.assertFalse(res["isError"], f"{name} unexpectedly failed: {res}")
        return json.loads(res["content"][0]["text"])

    def test_system_inspect_processes_network_rates_and_gpu_wake_safety(self):
        sess = self.start(["system_inspect"])
        data = self.call(sess, "system_inspect", {"sections": ["resources", "processes", "network", "gpu"]})
        self.assertTrue(data["read_only"])
        res = data["sections"]["resources"]
        self.assertGreater(res["top_processes"]["items"][0]["rss_bytes"], 0)
        procs = data["sections"]["processes"]
        self.assertTrue(procs["available"])
        self.assertGreater(len(procs["items"]), 0)
        self.assertNotIn("environ", json.dumps(procs))
        net = data["sections"]["network"]
        self.assertTrue(net["available"])
        if net["items"]:
            first = net["items"][0]
            self.assertIn("rx_bytes_per_sec", first)
            self.assertIn("tx_bytes_per_sec", first)
        gpu = data["sections"]["gpu"]
        self.assertIn("nvidia_telemetry", gpu)
        for item in gpu["items"]:
            if item.get("vendor_id") == "0x10de" and item.get("runtime_status") != "active":
                self.assertFalse(gpu["nvidia_telemetry"].get("available"))
                self.assertIsNone(item.get("busy_percent"))

    def test_path_rules_auto_memory_project_skills_and_grants(self):
        rules_dir = self.repo / ".claude/rules"
        rules_dir.mkdir(parents=True)
        (rules_dir / "rust.md").write_text(
            '---\npaths:\n  - "src/**/*.rs"\n---\nUse handle-relative filesystem calls.\n'
        )
        (rules_dir / "docs.md").write_text(
            "---\npaths:\n  - docs/**/*.md\n---\nNo emojis in docs.\n"
        )
        skill_dir = self.repo / ".agents/skills/demo-check"
        skill_dir.mkdir(parents=True)
        (skill_dir / "SKILL.md").write_text(
            "---\nname: demo-check\ndescription: Verify workspace checks\n---\nRun focused tests.\n"
        )
        outside = self.f.base / "secret.txt"
        outside.write_text("hidden\n")
        sym_mem = self.repo / ".veyl-memory"

        sess = self.start(["load_path_rules", "remember", "list_skills", "load_skill"])
        # System tools ungranted must fail
        self.call(sess, "chezmoi_inspect", {"path": "a.txt"}, error=True)

        matched = self.call(sess, "load_path_rules", {"path": "src/tools/main.rs"})
        self.assertEqual(matched["count"], 1)
        self.assertIn("handle-relative", matched["rules"][0]["content"])
        self.call(sess, "load_path_rules", {"path": "../secret.txt"}, error=True)
        self.call(sess, "load_path_rules", {"path": str(outside)}, error=True)

        skills = self.call(sess, "list_skills")
        self.assertEqual(skills["count"], 1)
        self.assertEqual(skills["skills"][0]["name"], "demo-check")
        loaded = self.call(sess, "load_skill", {"name": "demo-check", "max_bytes": 40})
        self.assertEqual(loaded["skill"]["name"], "demo-check")
        self.assertTrue(loaded["truncated"])

        saved = self.call(sess, "remember", {"note": "Always run targeted cargo tests."})
        mem_file = Path(saved["saved_to"])
        self.assertTrue(mem_file.is_file())
        self.assertIn("Always run targeted cargo tests.", mem_file.read_text())
        self.call(sess, "remember", {"note": "   "}, error=True)

        # Symlink attack on .veyl-memory/MEMORY.md must fail closed.
        mem_file.unlink()
        mem_file.symlink_to(outside)
        self.call(sess, "remember", {"note": "Should not follow symlink"}, error=True)
        self.assertEqual(outside.read_text(), "hidden\n")
        shutil.rmtree(sym_mem)

    def test_chezmoi_inspect_modes_generated_source_and_protected_paths(self):
        gen = self.repo / "generated.conf"
        gen.write_text("# Auto-generated by test. Do not edit manually.\nkey=val\n")
        plain = self.repo / "plain.txt"
        plain.write_text("hello\n")

        source_dir = self.f.base / ".local/share/chezmoi"
        source_dir.mkdir(parents=True)
        dot_src = source_dir / "dot_example.conf"
        dot_src.write_text("managed=true\n")
        subprocess.run(["/usr/bin/git", "init"], cwd=source_dir, capture_output=True, check=True)
        subprocess.run(["/usr/bin/git", "config", "user.name", "Test"], cwd=source_dir, capture_output=True, check=True)
        subprocess.run(["/usr/bin/git", "config", "user.email", "t@e.com"], cwd=source_dir, capture_output=True, check=True)
        subprocess.run(["/usr/bin/git", "add", "."], cwd=source_dir, capture_output=True, check=True)
        subprocess.run(["/usr/bin/git", "commit", "-m", "init"], cwd=source_dir, capture_output=True, check=True)

        ssh_dir = self.f.base / ".ssh"
        ssh_dir.mkdir(mode=0o700)
        (ssh_dir / "id_ed25519").write_text("PRIVATE\n")

        sess = self.start(["chezmoi_inspect"], native=True)
        res_gen = self.call(sess, "chezmoi_inspect", {"path": "generated.conf"})
        self.assertEqual(res_gen["kind"], "generated_target")
        self.assertIn("Do not edit", res_gen["generatedMarker"])

        res_plain = self.call(sess, "chezmoi_inspect", {"path": "plain.txt"})
        self.assertEqual(res_plain["kind"], "unmanaged")

        res_src = self.call(sess, "chezmoi_inspect", {"path": str(dot_src)})
        self.assertEqual(res_src["kind"], "source")

        # Native YOLO can inspect locations outside the authorized Standard workspace.
        self.call(sess, "chezmoi_inspect", {"path": str(ssh_dir / "id_ed25519")})
        self.call(sess, "chezmoi_inspect", {"path": str(self.f.config)})


if __name__ == "__main__":
    unittest.main()
