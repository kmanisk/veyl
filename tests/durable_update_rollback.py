#!/usr/bin/env python3
"""Exercise actual update --recover against a migrated legacy ledger.
Requires exact previous Linux release binaries, passed as argument 1, and
the new bundle as argument 2. All state and installations are disposable.
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import unittest
from pathlib import Path

import durable_identity as fixture

OLD = Path(sys.argv[1]).resolve()
NEW = Path(sys.argv[2]).resolve()
NAMES = ("veyl", "veyl-monitor", "mcp-gateway")

class MigrationRollback(unittest.TestCase):
    def setUp(self):
        holder = fixture.make_btrfs_temp_base()
        self.addCleanup(holder.cleanup)
        self.base = Path(holder.name)
        self.home, _, self.audit, original = fixture.DurableIdentityIntegration().setup_policy(self.base, policy_version=3)
        state = self.home / ".local/state/veyl"
        state.parent.mkdir(parents=True, mode=0o700)
        doc = json.loads(original.read_text())
        source = original.parent
        source.rename(state)
        self.config = state / "clients.json"
        self.audit = state / "audit/audit.jsonl"
        self.head = self.audit.with_name("audit.jsonl.head")
        doc["audit_log"] = str(self.audit)
        doc["job_state_dir"] = str(state / "jobs")
        self.config.write_text(json.dumps(doc))
        self.env = dict(os.environ, HOME=str(self.home), XDG_RUNTIME_DIR=str(self.base / "no-manager"))
        self.bin_dir = self.home / ".local/bin"
        self.bin_dir.mkdir(parents=True, mode=0o700)
        for name in NAMES:
            shutil.copy2(NEW / name, self.bin_dir / name)
        self.assertEqual(self.run_cli(OLD / "veyl", "mode", "yolo", "dev").returncode, 0)
        self.prior = json.loads(self.head.read_text())
        self.assertEqual(self.prior["version"], 1)
        self.policy_bytes = self.config.read_bytes()
        self.assertEqual(self.run_cli(NEW / "veyl", "audit", "rotate").returncode, 0)
        self.assertEqual(json.loads(self.head.read_text())["version"], 2)
        self.assertEqual(self.run_cli(NEW / "veyl", "mode", "list").returncode, 0)
        self.assertNotEqual(self.run_cli(OLD / "veyl", "mode", "list").returncode, 0)
        self.root = self.home / ".veyl-update-backups"
        self.nonce = "ab" * 16
        self.backup = self.root / self.nonce
        self.root.mkdir(mode=0o700)
        self.backup.mkdir(mode=0o700)
        self.manifest = []
        for idx, name in enumerate(NAMES):
            target = self.backup / f"0-{name}.old"
            shutil.copy2(OLD / name, target)
            self.manifest.append({
                "destination": str(self.bin_dir / name),
                "backup": str(target),
                "original_mode": target.stat().st_mode & 0o777,
                "original_sha256": hashlib.sha256(target.read_bytes()).hexdigest(),
            })
        self.private_json(self.backup / "manifest.json", self.manifest)
        self.journal = {
            "nonce": self.nonce, "phase": "replacing",
            "dirs": [str(self.bin_dir)], "backup_dir": str(self.backup),
            "service_executable": None, "service_active": False,
            "legacy_audit": {"policy_sha256": hashlib.sha256(self.policy_bytes).hexdigest(),
                             "tip": [self.prior["tip"]["sequence"], self.prior["tip"]["hash"]]},
        }
        self.private_json(self.root / "active.json", self.journal)

    def private_json(self, path, value):
        path.write_text(json.dumps(value))
        path.chmod(0o600)

    def run_cli(self, binary, *args):
        args = list(args)
        if args[0] != "update":
            args += ["--config", str(self.config)]
        return subprocess.run([str(binary), *args], env=self.env,
                              capture_output=True, text=True, timeout=30)

    def test_interrupted_migration_recovery(self):
        tip = json.loads(self.head.read_text())["tip"]
        result = self.run_cli(NEW / "veyl", "update", "--recover")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        after = json.loads(self.head.read_text())
        self.assertEqual(after["version"], 1)
        self.assertEqual(after["tip"], tip)
        self.assertEqual(self.config.read_bytes(), self.policy_bytes)
        for name in NAMES:
            self.assertEqual((self.bin_dir / name).read_bytes(), (OLD / name).read_bytes())
        self.assertFalse((self.root / "active.json").exists())
        self.assertEqual(self.run_cli(self.bin_dir / "veyl", "audit", "verify").returncode, 0)
        modes = self.run_cli(self.bin_dir / "veyl", "mode", "list")
        self.assertEqual(modes.returncode, 0, modes.stderr)
        self.assertIn("dev\tyolo\tenabled", modes.stdout)

    def test_wrong_prefix_fails_closed(self):
        self.journal["legacy_audit"]["tip"][1] = "0" * 64
        self.private_json(self.root / "active.json", self.journal)
        result = self.run_cli(NEW / "veyl", "update", "--recover")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("incompatible history or prefix", result.stderr)
        self.assertEqual(json.loads(self.head.read_text())["version"], 2)
        self.assertEqual((self.bin_dir / "veyl").read_bytes(), (NEW / "veyl").read_bytes())
        self.assertTrue((self.root / "active.json").exists())

    def test_changed_policy_fails_closed(self):
        self.config.write_bytes(self.policy_bytes + b"\n")
        result = self.run_cli(NEW / "veyl", "update", "--recover")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Policy changed", result.stderr)
        self.assertEqual(json.loads(self.head.read_text())["version"], 2)
        self.assertEqual((self.bin_dir / "veyl").read_bytes(), (NEW / "veyl").read_bytes())

if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]], verbosity=2)
