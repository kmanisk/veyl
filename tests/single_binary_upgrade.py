#!/usr/bin/env python3
"""Single ELF update, legacy alias compatibility, and rollback in a nested systemd manager."""
import hashlib
import http.client
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

base, old, new = map(lambda p: Path(p).resolve(), sys.argv[1:4])
home = base / "home"
assert Path.home() == home
bins = home / ".local/bin"
bins.mkdir(parents=True, mode=0o700)
names = ("veyl", "veyl-monitor", "mcp-gateway")
for name in names:
    shutil.copy2(old / name, bins / name)
state = home / ".local/state/veyl"
state.mkdir(parents=True, mode=0o700)
root = base / "workspace"
root.mkdir(mode=0o700)
audit_dir = state / "audit"
audit_dir.mkdir(mode=0o700)
audit = audit_dir / "audit.jsonl"
audit.touch(mode=0o600)
jobs = state / "jobs"
jobs.mkdir(mode=0o700)
config = state / "clients.json"
token = "4c" * 32
config.write_text(json.dumps({
    "policy_version": 3, "audit_log": str(audit), "job_state_dir": str(jobs),
    "job_profiles": {"ok": {"executable": "/usr/bin/true", "args": [], "timeout_seconds": 5}},
    "clients": [{"id": "dev", "root": str(root), "mode": "standard",
                 "tools": ["read_file"], "disabled": False, "extra_roots": [],
                 "token_sha256": hashlib.sha256(token.encode()).hexdigest(),
                 "expires_at_unix_seconds": int(time.time()) + 3600}]
}))
config.chmod(0o600)
head = audit.with_name("audit.jsonl.head")
def run(binary, *args, expect=0):
    r = subprocess.run([str(binary), *args], capture_output=True, text=True, timeout=35)
    if expect == 0:
        assert r.returncode == 0, (args, r.stdout, r.stderr)
    else:
        assert r.returncode != 0, (args, r.stdout, r.stderr)
    return r
def pid():
    return int(subprocess.check_output(["systemctl", "--user", "show", "-p", "MainPID", "--value", "mcp-gateway.service"], timeout=5))
def connect():
    conn = http.client.HTTPConnection("127.0.0.1", 7331, timeout=4)
    try:
        conn.request("POST", "/mcp", json.dumps({"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"durable-update","version":"1"}}}), {"Authorization":"Bearer "+token,"Content-Type":"application/json"})
        response = conn.getresponse()
        assert response.status == 200, response.status
        assert "result" in json.loads(response.read())
    finally:
        conn.close()
manager_log = (base / "nested-manager.log").open("wb")
manager = subprocess.Popen(["/usr/lib/systemd/systemd", "--user", "--unit=veyl-test.target"], stdout=manager_log, stderr=manager_log)
try:
    for _ in range(50):
        if manager.poll() is not None:
            raise RuntimeError((base / "nested-manager.log").read_text())
        if subprocess.run(["systemctl","--user","show","-p","SystemState"],capture_output=True,timeout=3).returncode == 0:
            break
        time.sleep(.15)
    else:
        raise RuntimeError("nested manager unavailable")
    # The nested user manager cannot satisfy native Broad's outer isolation
    # probe; YOLO grant preservation is tested independently in durable_update_rollback.py.
    for action in ("install", "enable", "start"):
        run(bins / "mcp-gateway", "service", action, "--confirm", "--config", str(config))
    for _ in range(40):
        try:
            connect()
            break
        except OSError:
            time.sleep(.15)
    else:
        raise RuntimeError("old service unavailable")
    first = pid()
    assert first > 0
    assert json.loads(head.read_text())["version"] == 2
    policy = config.read_bytes()
    # The old updater must refuse a single-binary bundle before mutation.
    old_attempt = run(bins / "veyl", "update", "--from-dir", str(new), expect=1)
    assert pid() == first
    assert config.read_bytes() == policy
    assert (bins / "mcp-gateway").read_bytes() == (old / "mcp-gateway").read_bytes()
    assert sorted(p.name for p in new.iterdir()) == ["SHA256SUMS", "veyl"]
    assert "veyl-monitor" in run(new / "veyl", "monitor", "--version").stdout
    assert "veyl-connector" in run(new / "veyl", "connector", "--version").stdout
    unit = home / ".config/systemd/user/mcp-gateway.service"
    unit_bytes = unit.read_bytes()
    run(new / "veyl", "update", "--from-dir", str(new))
    def check_single_install():
        assert not (bins / "veyl").is_symlink()
        assert (bins / "veyl").read_bytes() == (new / "veyl").read_bytes()
        for name in names[1:]:
            assert (bins / name).is_symlink()
            assert os.readlink(bins / name) == "veyl"
            assert (bins / name).stat().st_ino == (bins / "veyl").stat().st_ino
            assert name in run(bins / name, "--version").stdout
        assert unit.read_bytes() == unit_bytes
        assert config.read_bytes() == policy
        assert json.loads(head.read_text())["version"] == 2
        run(bins / "veyl", "audit", "verify", "--config", str(config))
        assert "dev\tstandard\tenabled" in run(bins / "veyl", "mode", "list", "--config", str(config)).stdout
        connect()
    check_single_install()
    run(bins / "veyl", "service", "restart", "--confirm", "--config", str(config))
    for _ in range(40):
        try:
            connect()
            break
        except OSError:
            time.sleep(.15)
    else:
        raise RuntimeError("service alias restart failed")
    print("SINGLE_ELF_LEGACY_MIGRATION_PASS", flush=True)
    run(bins / "veyl", "update", "--from-dir", str(new))
    check_single_install()
    print("SINGLE_ELF_REINSTALL_PASS", flush=True)
    # Force failed startup with a version-correct ELF and ensure rollback
    # restores aliases, not copies, and leaves the working service intact.
    broken = base / "broken"
    broken.mkdir(mode=0o700)
    c = base / "fail.c"
    version = run(new / "veyl", "--version").stdout.strip().split()[-1]
    c.write_text('#include <stdio.h>\n#include <string.h>\nint main(int argc,char**argv){if(argc==2&&!strcmp(argv[1],"--persistent-format")){puts("veyl-linux-state-4");return 0;}if(argc==2&&!strcmp(argv[1],"--version")){const char*n=strrchr(argv[0],47);printf("%s %s\\n",n?n+1:argv[0],' + json.dumps(version) + ');return 0;}return 1;}\n')
    subprocess.run(["/usr/bin/cc", "-O2", str(c), "-o", str(broken / "veyl")], check=True)
    (broken / "SHA256SUMS").write_text(hashlib.sha256((broken / "veyl").read_bytes()).hexdigest() + "  veyl\n")
    result = run(bins / "veyl", "update", "--from-dir", str(broken), expect=1)
    assert "previous binaries restored" in result.stderr, result.stderr
    check_single_install()
    print("SINGLE_ELF_FAILED_START_ALIAS_ROLLBACK_PASS", flush=True)
    # Wrong-target aliases must be refused, even when owned by the operator.
    alias = bins / "veyl-monitor"
    alias.unlink()
    alias.symlink_to("/usr/bin/true")
    p = pid()
    result = run(bins / "veyl", "update", "--from-dir", str(new), expect=1)
    assert "unknown compatibility symlink" in result.stderr, result.stderr
    assert pid() == p and os.readlink(alias) == "/usr/bin/true"
    print("SINGLE_ELF_FOREIGN_SYMLINK_REFUSED_PASS", flush=True)

finally:
    subprocess.run(["systemctl", "--user", "stop", "mcp-gateway.service"], capture_output=True, timeout=8)
    if manager.poll() is None:
        manager.terminate()
        try:
            manager.wait(timeout=3)
        except subprocess.TimeoutExpired:
            manager.kill()
            manager.wait(timeout=2)
    manager_log.close()
