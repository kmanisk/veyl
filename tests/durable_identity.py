#!/usr/bin/env python3
"""Integration tests for reboot-stable durable filesystem identity and legacy recovery."""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

BIN = Path(sys.argv[1] if len(sys.argv) > 1 else os.environ.get("MCP_GATEWAY_BIN", "target/debug/mcp-gateway")).resolve()


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def make_btrfs_temp_base():
    # Use candidate parent (Btrfs /home) for persistent FS tests so tmpfs /tmp does not mask persistent FS behavior.
    probe = Path(__file__).resolve().parents[2]
    return tempfile.TemporaryDirectory(prefix="veyl-durable-int-", dir=probe)


class DurableIdentityIntegration(unittest.TestCase):
    def cli(self, *args, home=None):
        env = dict(os.environ)
        if home is not None:
            env["HOME"] = str(home)
        return subprocess.run([str(BIN), *args], capture_output=True, text=True, env=env, timeout=20)

    def setup_policy(self, base: Path, policy_version=4):
        home = base / "home"
        home.mkdir(mode=0o700)
        root = base / "workspace"
        root.mkdir(mode=0o700)
        state = base / "state"
        state.mkdir(mode=0o700)
        audit_dir = state / "audit"
        audit_dir.mkdir(mode=0o700)
        audit_log = audit_dir / "audit.jsonl"
        audit_log.touch()
        audit_log.chmod(0o600)
        jobs_dir = state / "jobs"
        jobs_dir.mkdir(mode=0o700)
        config = state / "clients.json"
        token = "4c" * 32
        doc = {
            "policy_version": policy_version,
            "audit_log": str(audit_log),
            "job_state_dir": str(jobs_dir),
            "job_profiles": {"ok": {"executable": "/usr/bin/true", "args": [], "timeout_seconds": 5}},
            "clients": [{
                "id": "dev",
                "token_sha256": sha256_hex(token),
                "root": str(root),
                "mode": "standard",
                "disabled": False,
                "extra_roots": [],
                "tools": ["read_file", "write_file"],
                "expires_at_unix_seconds": int(time.time()) + 3600,
            }],
        }
        config.write_text(json.dumps(doc))
        config.chmod(0o600)
        return home, root, audit_log, config

    def test_audit_v2_head_and_legacy_v1_recovery_cli(self):
        holder = make_btrfs_temp_base()
        self.addCleanup(holder.cleanup)
        base = Path(holder.name)
        home, root, audit_log, config = self.setup_policy(base)

        # Trigger real audited policy mode transition (Standard -> Yolo -> Standard) to create ledger + records.
        r = self.cli("mode", "yolo", "dev", "--confirm-native", "--config", str(config), home=home)
        self.assertEqual(r.returncode, 0, r.stderr)
        anchor = base / "anchor.json"
        r = self.cli("audit", "export-head", "--config", str(config), "--out", str(anchor), home=home)
        self.assertEqual(r.returncode, 0, r.stderr)

        head_path = audit_log.with_name("audit.jsonl.head")
        head_v2 = json.loads(head_path.read_text())
        self.assertEqual(head_v2["version"], 2)
        self.assertEqual(head_v2["durable"]["fs"]["kind"], "persistent")
        self.assertEqual(head_v2["durable"]["inode"], head_v2["active"][1])

        # Simulated reboot device renumbering in v2 head: change `active[0]` (`st_dev`) while keeping durable intact.
        head_rebooted = dict(head_v2)
        head_rebooted["active"] = [head_v2["active"][0] ^ 19, head_v2["active"][1]]
        head_path.write_text(json.dumps(head_rebooted))
        head_path.chmod(0o600)

        r = self.cli("audit", "verify", "--config", str(config), home=home)
        self.assertEqual(r.returncode, 0, r.stderr)
        r = self.cli("audit", "verify", "--config", str(config), "--anchor", str(anchor), home=home)
        self.assertEqual(r.returncode, 0, r.stderr)
        # Mode transition re-opens read-write and refreshes the live st_dev hint seamlessly.
        r = self.cli("mode", "standard", "dev", "--config", str(config), home=home)
        self.assertEqual(r.returncode, 0, r.stderr)
        refreshed = json.loads(head_path.read_text())
        self.assertEqual(refreshed["active"][0], os.stat(audit_log).st_dev)

        # Downgrade .head to legacy v1 with stale device ID -> verify/mode MUST fail closed until explicit recovery.
        head_v1_stale = {
            "version": 1,
            "active": [refreshed["active"][0] ^ 23, refreshed["active"][1]],
            "tip": refreshed["tip"],
        }
        head_path.write_text(json.dumps(head_v1_stale))
        head_path.chmod(0o600)
        r = self.cli("audit", "verify", "--config", str(config), home=home)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("recover-identity", r.stderr)

        # Negative control: wrong inode on v1 must still fail recover-identity.
        bad_ino = {
            "version": 1,
            "active": [refreshed["active"][0] ^ 23, refreshed["active"][1] + 5],
            "tip": refreshed["tip"],
        }
        head_path.write_text(json.dumps(bad_ino))
        head_path.chmod(0o600)
        r = self.cli("audit", "recover-identity", "--config", str(config), home=home)
        self.assertNotEqual(r.returncode, 0)

        # Valid legacy v1 stale-dev -> recover-identity succeeds, upgrades to v2, and preserves anchor & history.
        head_path.write_text(json.dumps(head_v1_stale))
        head_path.chmod(0o600)
        r = self.cli("audit", "recover-identity", "--config", str(config), home=home)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("AUDIT_IDENTITY=RECOVERED", r.stdout)

        r = self.cli("audit", "verify", "--config", str(config), "--anchor", str(anchor), home=home)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_protected_paths_durable_and_legacy_migration(self):
        holder = make_btrfs_temp_base()
        self.addCleanup(holder.cleanup)
        base = Path(holder.name)
        home, root, audit_log, config = self.setup_policy(base)
        secret_dir = base / "secret-dir"
        secret_dir.mkdir(mode=0o700)

        r = self.cli("protected-paths", "add", "--optional", str(secret_dir), "--config", str(config), home=home)
        self.assertEqual(r.returncode, 0, r.stderr)
        doc = json.loads(config.read_text())
        rule = doc["protected_paths"]["optional"][0]
        self.assertEqual(rule["durable"]["fs"]["kind"], "persistent")

        # Simulated device renumbering in clients.json stays verified when durable is present.
        rule["device"] ^= 11
        config.write_text(json.dumps(doc))
        config.chmod(0o600)
        r = self.cli("protected-paths", "list", "--optional", "--config", str(config), home=home)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn(f"{secret_dir} identity=verified", r.stdout)

        # Snapshot/fs substitution (altered durable fsid) MUST become stale.
        rule["durable"]["fs"]["fsid"] ^= 1
        config.write_text(json.dumps(doc))
        config.chmod(0o600)
        r = self.cli("protected-paths", "list", "--optional", "--config", str(config), home=home)
        self.assertIn(f"{secret_dir} identity=stale", r.stdout)

        # Strip `durable` back to legacy format with live dev -> `protected-paths migrate` upgrades cleanly.
        rule.pop("durable")
        rule["device"] = os.stat(secret_dir).st_dev
        config.write_text(json.dumps(doc))
        config.chmod(0o600)
        r = self.cli("protected-paths", "migrate", "--config", str(config), home=home)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("migrated 1 rules", r.stdout)
        doc2 = json.loads(config.read_text())
        self.assertEqual(doc2["protected_paths"]["optional"][0]["durable"]["inode"], os.stat(secret_dir).st_ino)

    def test_upstream_workspace_folder_durable_grant(self):
        holder = make_btrfs_temp_base()
        self.addCleanup(holder.cleanup)
        base = Path(holder.name)
        home, root, audit_log, config = self.setup_policy(base)
        doc = json.loads(config.read_text())
        tmp_folder_holder = tempfile.TemporaryDirectory(prefix="veyl-up-tmp-")
        self.addCleanup(tmp_folder_holder.cleanup)
        folder = Path(tmp_folder_holder.name) / "shared-ro"
        folder.mkdir(mode=0o700)
        Path(tmp_folder_holder.name).chmod(0o700)
        bundle = base / "state" / "upstream-bundles" / "rea"
        bundle.mkdir(parents=True, mode=0o700)
        (base / "state" / "upstream-bundles").chmod(0o700)
        (bundle / "server.py").write_text("#!/usr/bin/env python3\n")
        (bundle / "server.py").chmod(0o600)

        doc["mcp_servers"] = {
            "rea": {
                "transport": "stdio",
                "command": "/usr/bin/python3",
                "args": ["/upstream/bundle/server.py"],
                "runtime_bundle": True,
                "enabled": True,
            }
        }
        doc["clients"][0]["tools"].append("mcp_servers_call")
        doc["clients"][0]["allowed_servers"] = ["rea"]
        doc["clients"][0]["allowed_server_tools"] = {"rea": ["inspect_python_pyc"]}
        config.write_text(json.dumps(doc))
        config.chmod(0o600)
        r = self.cli("mcp-servers", "workspace-folder", "dev", "rea", str(folder), "--config", str(config), home=home)
        self.assertEqual(r.returncode, 0, r.stderr)
        doc2 = json.loads(config.read_text())
        grant = doc2["clients"][0]["upstream_workspace_roots"]["rea"]
        self.assertEqual(grant["durable"]["inode"], os.stat(folder).st_ino)
        r = self.cli("service", "validate", "--config", str(config), home=home)
        self.assertEqual(r.returncode, 0, r.stderr)


if __name__ == "__main__":
    unittest.main(argv=[sys.argv[0]])
