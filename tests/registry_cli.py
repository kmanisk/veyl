#!/usr/bin/env python3
"""Unified CLI transition suite: empty init, default_mode, confirmation, and unified mode updates."""
import hashlib
import json
import os
import pty
import select
import subprocess
import time
import unittest

from oauth_managed_login import ManagedLogin


class RegistryCli(ManagedLogin):
    def native_policy(self):
        state = self.base / ".local/state/veyl"
        state.mkdir(parents=True, mode=0o700)
        audit = state / "audit"
        audit.mkdir(mode=0o700)
        ledger = audit / "events.jsonl"
        ledger.touch(mode=0o600)
        config = state / "clients.json"
        clients = [
            dict(id=name, root=str(self.root), mode="standard", disabled=disabled,
                 token_sha256=hashlib.sha256((name + "-synthetic").encode()).hexdigest(),
                 expires_at_unix_seconds=int(time.time()) + 300, tools=["read_file"])
            for name, disabled in (("primary", False), ("secondary", True))
        ]
        config.write_text(json.dumps(dict(policy_version=4, audit_log=str(ledger), clients=clients)))
        config.chmod(0o600)
        return config

    def mode(self, *args, ok=True):
        result = self.execute([str(self.veyl), "mode", *args])
        self.assertEqual(result.returncode == 0, ok, (result.stdout, result.stderr))
        return result

    def native_modes(self, config):
        return [(c["id"], c["mode"], c["disabled"])
                for c in json.loads(config.read_text())["clients"]]

    def terminal_mode(self, answer, ok):
        master, slave = pty.openpty()
        proc = subprocess.Popen([str(self.veyl), "mode", "yolo"], env=self.env,
                                stdin=slave, stdout=slave, stderr=slave)
        os.close(slave)
        try:
            deadline = time.monotonic() + 5
            output = b""
            while b"Type YOLO to confirm:" not in output:
                remaining = deadline - time.monotonic()
                self.assertGreater(remaining, 0)
                self.assertTrue(select.select([master], [], [], remaining)[0])
                output += os.read(master, 4096)
            os.write(master, answer.encode() + b"\n")
            self.assertEqual(proc.wait(timeout=8) == 0, ok)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=5)
            os.close(master)

    def test_fresh_empty_and_legacy_oauth_reconciliation(self):
        listing = self.mode()
        self.assertIn("default_mode=standard", listing.stdout)
        self.assertIn("No clients configured", listing.stdout)
        self.mode("yolo", ok=False)
        self.terminal_mode("no", False)
        self.terminal_mode("YOLO", True)
        cfg = self.base / ".local/state/veyl/clients.json"
        self.assertEqual(json.loads(cfg.read_text())["default_mode"], "yolo")
        self.assertEqual(json.loads(cfg.read_text())["clients"], [])
        self.mode("standard")
        self.assertEqual(json.loads(cfg.read_text())["default_mode"], "standard")

    def test_combined_migration_applies_globally_and_preserves_disabled(self):
        self.start_managed(first=True)
        cid, _ = self.authorize_managed()
        self.stop_funnel()
        config = self.native_policy()
        # First invocation reconciles native ~/.local/state/veyl and ~/.veyl-login/profile cleanly.
        self.mode("yolo", ok=False)
        self.terminal_mode("no", False)
        self.terminal_mode("YOLO", True)
        doc = json.loads(config.read_text())
        self.assertEqual(doc["default_mode"], "yolo")
        self.assertEqual(self.native_modes(config),
                         [("primary", "yolo", False), ("secondary", "standard", True)])
        out = self.mode("list").stdout
        self.assertIn("primary\tyolo\tenabled\ttype=static", out)
        self.assertIn("secondary\tstandard\tdisabled\ttype=static", out)
        self.assertIn(f"{cid}\tyolo", out)
        self.mode("standard")
        self.assertEqual(json.loads(config.read_text())["default_mode"], "standard")
        self.assertEqual(self.native_modes(config),
                         [("primary", "standard", False), ("secondary", "standard", True)])
        self.mode("yolo", "primary", "--yes")
        self.assertEqual(self.native_modes(config)[0], ("primary", "yolo", False))
        # Targeted change does not overwrite default_mode.
        self.assertEqual(json.loads(config.read_text())["default_mode"], "standard")
        verify = self.execute([str(self.veyl), "audit", "verify", "--config", str(config)])
        self.assertEqual(verify.returncode, 0, verify.stderr)
        # Legacy originals remain preserved untouched.
        self.assertTrue((self.base / ".veyl-login/profile/clients.json").exists())


if __name__ == "__main__":
    suite = unittest.TestSuite(RegistryCli(name) for name in (
        "test_fresh_empty_and_legacy_oauth_reconciliation",
        "test_combined_migration_applies_globally_and_preserves_disabled"))
    raise SystemExit(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())
