#!/usr/bin/env python3
"""Kernel loopback reproduction: real Btrfs/ext4 st_dev renumbering across remount,
Btrfs snapshot subvolume substitution rejection, and volatile tmpfs rejection.

Requires passwordless sudo loop mount; always unmounts and removes disposable mounts.
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

BIN = Path(sys.argv[1]).resolve()


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def run(cmd, home=None, check=True):
    env = dict(os.environ)
    if home is not None:
        env["HOME"] = str(home)
    return subprocess.run(cmd, capture_output=True, text=True, env=env, check=check, timeout=30)


def write_cfg(cfg: Path, root: Path, audit_log: Path, jobs_dir: Path):
    doc = {
        "policy_version": 4,
        "audit_log": str(audit_log),
        "job_state_dir": str(jobs_dir),
        "job_profiles": {"ok": {"executable": "/usr/bin/true", "args": [], "timeout_seconds": 5}},
        "clients": [{
            "id": "dev",
            "token_sha256": sha256_hex("5d" * 32),
            "root": str(root),
            "mode": "standard",
            "disabled": False,
            "extra_roots": [],
            "tools": ["read_file", "write_file"],
            "expires_at_unix_seconds": int(time.time()) + 3600,
        }],
    }
    cfg.write_text(json.dumps(doc))
    cfg.chmod(0o600)


def main():
    tmp = Path(tempfile.mkdtemp(prefix="veyl-loopback-"))
    btrfs_img = tmp / "btrfs.img"
    ext4_img = tmp / "ext4.img"
    ext4_other_img = tmp / "ext4_other.img"
    mnt_btrfs = tmp / "btrfs_mnt"
    mnt_admin = tmp / "btrfs_admin"
    mnt_ext4 = tmp / "ext4_mnt"
    mnt_tmpfs = tmp / "tmpfs_mnt"
    mnt_dummy = tmp / "dummy_mnt"
    for p in (mnt_btrfs, mnt_admin, mnt_ext4, mnt_tmpfs, mnt_dummy):
        p.mkdir(mode=0o700)

    def cleanup():
        for m in (mnt_admin, mnt_btrfs, mnt_ext4, mnt_tmpfs, mnt_dummy):
            subprocess.run(["sudo", "umount", str(m)], stderr=subprocess.DEVNULL)
        shutil.rmtree(tmp, ignore_errors=True)

    try:
        subprocess.run(["truncate", "-s", "128M", str(btrfs_img)], check=True)
        subprocess.run(["mkfs.btrfs", "-q", str(btrfs_img)], check=True)
        subprocess.run(["truncate", "-s", "16M", str(ext4_img)], check=True)
        subprocess.run(["mkfs.ext4", "-q", str(ext4_img)], check=True)
        subprocess.run(["truncate", "-s", "16M", str(ext4_other_img)], check=True)
        subprocess.run(["mkfs.ext4", "-q", str(ext4_other_img)], check=True)

        # Create sub_live inside btrfs image via temporary top-level mount.
        subprocess.run(["sudo", "mount", "-o", "loop", str(btrfs_img), str(mnt_admin)], check=True)
        subprocess.run(["sudo", "btrfs", "subvolume", "create", str(mnt_admin / "sub_live")], check=True, stdout=subprocess.DEVNULL)
        subprocess.run(["sudo", "chown", f"{os.getuid()}:{os.getgid()}", str(mnt_admin / "sub_live")], check=True)
        subprocess.run(["sudo", "umount", str(mnt_admin)], check=True)

        # Mount sub_live directly at mnt_btrfs.
        subprocess.run(["sudo", "mount", "-o", "loop,subvol=sub_live", str(btrfs_img), str(mnt_btrfs)], check=True)
        home = mnt_btrfs / "home"
        root = mnt_btrfs / "workspace"
        state = mnt_btrfs / "state"
        audit_dir = state / "audit"
        jobs_dir = state / "jobs"
        for d in (home, root, state, audit_dir, jobs_dir):
            d.mkdir(mode=0o700)
        cfg = state / "clients.json"
        audit_log = audit_dir / "audit.jsonl"
        audit_log.touch()
        audit_log.chmod(0o600)
        write_cfg(cfg, root, audit_log, jobs_dir)

        run([str(BIN), "mode", "yolo", "dev", "--confirm-native", "--config", str(cfg)], home=home)
        secret_dir = mnt_btrfs / "secret-dir"
        secret_dir.mkdir(mode=0o700)
        run([str(BIN), "protected-paths", "add", "--optional", str(secret_dir), "--config", str(cfg)], home=home)
        anchor = state / "anchor.json"
        run([str(BIN), "audit", "export-head", "--config", str(cfg), "--out", str(anchor)], home=home)
        dev_before = os.stat(audit_log).st_dev
        ino_before = os.stat(audit_log).st_ino

        # Snapshot sub_live -> sub_snap via top-level subvol=5 mount (same pool, same inode, different treeid!).
        subprocess.run(["sudo", "mount", "-o", "loop,subvolid=5", str(btrfs_img), str(mnt_admin)], check=True)
        subprocess.run(["sudo", "btrfs", "subvolume", "snapshot", str(mnt_admin / "sub_live"), str(mnt_admin / "sub_snap")], check=True, stdout=subprocess.DEVNULL)
        subprocess.run(["sudo", "umount", str(mnt_admin)], check=True)
        subprocess.run(["sudo", "umount", str(mnt_btrfs)], check=True)

        # Occupy an extra anon dev before remounting sub_live at the exact same path -> real st_dev renumbering!
        subprocess.run(["sudo", "mount", "-t", "tmpfs", "-o", "size=1M", "tmpfs", str(mnt_dummy)], check=True)
        subprocess.run(["sudo", "mount", "-o", "loop,subvol=sub_live", str(btrfs_img), str(mnt_btrfs)], check=True)
        dev_after = os.stat(audit_log).st_dev
        ino_after = os.stat(audit_log).st_ino
        assert ino_before == ino_after, f"Expected same inode across remount: {ino_before} != {ino_after}"
        assert dev_before != dev_after, f"Expected kernel Btrfs st_dev renumbering: {dev_before} == {dev_after}"
        print(f"BTRFS_DEV_RENUMBERED {dev_before} -> {dev_after} ino={ino_after}", flush=True)

        v = run([str(BIN), "audit", "verify", "--config", str(cfg), "--anchor", str(anchor)], home=home)
        assert "VERIFY_RESULT=VALID" in v.stdout, v.stdout + v.stderr
        pl = run([str(BIN), "protected-paths", "list", "--optional", "--config", str(cfg)], home=home)
        assert f"{secret_dir} identity=verified" in pl.stdout, pl.stdout + pl.stderr
        run([str(BIN), "mode", "standard", "dev", "--config", str(cfg)], home=home)

        # Negative control: swap sub_snap into the EXACT SAME mountpoint path mnt_btrfs (same inode, same path, different subvol!).
        subprocess.run(["sudo", "umount", str(mnt_btrfs)], check=True)
        subprocess.run(["sudo", "mount", "-o", "loop,subvol=sub_snap", str(btrfs_img), str(mnt_btrfs)], check=True)
        assert os.stat(audit_log).st_ino == ino_before
        bad = run([str(BIN), "audit", "verify", "--config", str(cfg), "--anchor", str(anchor)], home=home, check=False)
        assert bad.returncode != 0, f"Btrfs snapshot subvolume MUST be rejected! Got: {bad.stdout}"
        print("BTRFS_SNAPSHOT_REJECTED_OK", flush=True)

        subprocess.run(["sudo", "umount", str(mnt_btrfs)], check=True)
        subprocess.run(["sudo", "umount", str(mnt_dummy)], check=True)

        # 2. Real ext4 persistent FS remount on shifted loop minor (st_dev change) + swapped ext4 filesystem rejection.
        subprocess.run(["sudo", "mount", "-o", "loop", str(ext4_img), str(mnt_ext4)], check=True)
        subprocess.run(["sudo", "chown", f"{os.getuid()}:{os.getgid()}", str(mnt_ext4)], check=True)
        for d in ("home", "workspace", "state", "state/audit", "state/jobs"):
            (mnt_ext4 / d).mkdir(mode=0o700)
        e_cfg = mnt_ext4 / "state/clients.json"
        e_audit = mnt_ext4 / "state/audit/audit.jsonl"
        e_audit.touch()
        e_audit.chmod(0o600)
        write_cfg(e_cfg, mnt_ext4 / "workspace", e_audit, mnt_ext4 / "state/jobs")
        run([str(BIN), "mode", "yolo", "dev", "--confirm-native", "--config", str(e_cfg)], home=mnt_ext4 / "home")
        ext4_dev1 = os.stat(e_audit).st_dev
        subprocess.run(["sudo", "umount", str(mnt_ext4)], check=True)

        subprocess.run(["sudo", "mount", "-o", "loop", str(ext4_other_img), str(mnt_dummy)], check=True)
        subprocess.run(["sudo", "mount", "-o", "loop", str(ext4_img), str(mnt_ext4)], check=True)
        ext4_dev2 = os.stat(e_audit).st_dev
        assert ext4_dev1 != ext4_dev2, f"Expected loop minor shift: {ext4_dev1} == {ext4_dev2}"
        v_ext4 = run([str(BIN), "audit", "verify", "--config", str(e_cfg)], home=mnt_ext4 / "home")
        assert "VERIFY_RESULT=VALID" in v_ext4.stdout
        print(f"EXT4_DEV_RENUMBERED_OK {ext4_dev1} -> {ext4_dev2}", flush=True)

        # Copy ledger onto distinct ext4_other_img (different fsid & inode) -> MUST FAIL.
        subprocess.run(["sudo", "chown", f"{os.getuid()}:{os.getgid()}", str(mnt_dummy)], check=True)
        for p in ("home", "workspace", "state"):
            shutil.copytree(mnt_ext4 / p, mnt_dummy / p)
            os.chmod(mnt_dummy / p, 0o700)
        for root_dir, _, files in os.walk(mnt_dummy / "state"):
            os.chmod(root_dir, 0o700)
            for f in files:
                os.chmod(Path(root_dir) / f, 0o600)
        d_cfg = mnt_dummy / "state/clients.json"
        d_text = d_cfg.read_text().replace(str(mnt_ext4), str(mnt_dummy))
        d_cfg.write_text(d_text)
        d_cfg.chmod(0o600)
        bad_ext4 = run([str(BIN), "audit", "verify", "--config", str(d_cfg)], home=mnt_dummy / "home", check=False)
        assert bad_ext4.returncode != 0, "Copied filesystem MUST be rejected"
        print("EXT4_SUBSTITUTION_REJECTED_OK", flush=True)

        subprocess.run(["sudo", "umount", str(mnt_ext4)], check=True)
        subprocess.run(["sudo", "umount", str(mnt_dummy)], check=True)

        # 3. Volatile tmpfs remount preservation: mismatched device MUST fail closed.
        subprocess.run(["sudo", "mount", "-t", "tmpfs", "-o", f"size=8M,uid={os.getuid()},gid={os.getgid()},mode=0700,nosuid,nodev", "tmpfs", str(mnt_tmpfs)], check=True)
        for d in ("home", "workspace", "state", "state/audit", "state/jobs"):
            (mnt_tmpfs / d).mkdir(mode=0o700)
        t_cfg = mnt_tmpfs / "state/clients.json"
        t_audit = mnt_tmpfs / "state/audit/audit.jsonl"
        t_audit.touch()
        t_audit.chmod(0o600)
        write_cfg(t_cfg, mnt_tmpfs / "workspace", t_audit, mnt_tmpfs / "state/jobs")
        run([str(BIN), "mode", "yolo", "dev", "--confirm-native", "--config", str(t_cfg)], home=mnt_tmpfs / "home")
        t_head = Path(str(t_audit) + ".head")
        saved_head = json.loads(t_head.read_text())
        assert saved_head["durable"]["fs"]["kind"] == "volatile", saved_head
        saved_head["durable"]["fs"]["device"] ^= 15
        saved_head["active"][0] ^= 15
        t_head.write_text(json.dumps(saved_head))
        t_head.chmod(0o600)
        bad_tmpfs = run([str(BIN), "audit", "verify", "--config", str(t_cfg)], home=mnt_tmpfs / "home", check=False)
        assert bad_tmpfs.returncode != 0, "Volatile tmpfs with mismatched device MUST fail closed"
        print("VOLATILE_TMPFS_STRICT_DEV_OK", flush=True)
    finally:
        cleanup()


if __name__ == "__main__":
    main()
