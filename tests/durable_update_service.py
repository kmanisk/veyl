#!/usr/bin/env python3
"""Isolated systemd service: fail the first new startup *after* audit migration."""
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
    assert json.loads(head.read_text())["version"] == 1
    policy = config.read_bytes()
    # The old updater does not know how to reverse schema migration.
    # Its failed upgrade must leave the legacy checkpoint readable.
    old_attempt = run(bins / "veyl", "update", "--from-dir", str(new), expect=1)
    assert "previous binaries restored" in old_attempt.stderr, old_attempt.stderr
    assert json.loads(head.read_text())["version"] == 1
    assert config.read_bytes() == policy
    assert (bins / "mcp-gateway").read_bytes() == (old / "mcp-gateway").read_bytes()
    connect()
    first = pid()
    print("LEGACY_UPDATER_REFUSED_UNSAFE_MIGRATION_PASS", flush=True)
    broken = base / "broken"
    broken.mkdir(mode=0o700)
    for name in names:
        shutil.copy2(new / name, broken / name)
    # The failed gateway must be a real ELF and correctly report its version.
    # On startup it invokes the *new* CLI to migrate/rotate the audit ledger,
    # records a success witness only if migration worked, then exits nonzero.
    c = base / "fail.c"
    witness = base / "migrated"
    c.write_text('#include <stdio.h>\n#include <string.h>\n#include <stdlib.h>\n#include <sys/wait.h>\nint main(int argc,char**argv){if(argc==2&&!strcmp(argv[1],"--version")){puts("mcp-gateway 0.6.0-beta");return 0;}int r=system(' + json.dumps(str(new / "veyl") + " audit rotate --config " + str(config)) + ');if(r==0){FILE*f=fopen(' + json.dumps(str(witness)) + ',"w");if(f){fputs("migration done",f);fclose(f);}}return 1;}\n')
    subprocess.run(["/usr/bin/cc", "-O2", str(c), "-o", str(broken / "mcp-gateway")], check=True)
    (broken / "SHA256SUMS").write_text("".join(f"{hashlib.sha256((broken / n).read_bytes()).hexdigest()}  {n}\n" for n in names))
    result = run(new / "veyl", "update", "--from-dir", str(broken), expect=1)
    print(result.stdout, result.stderr, flush=True)
    assert witness.read_text() == "migration done"
    assert "previous binaries restored" in result.stderr
    assert pid() not in (0, first)
    assert json.loads(head.read_text())["version"] == 1
    assert config.read_bytes() == policy
    for name in names:
        assert (bins / name).read_bytes() == (old / name).read_bytes()
    assert "dev\tstandard\tenabled" in run(bins / "veyl", "mode", "list", "--config", str(config)).stdout
    run(bins / "veyl", "audit", "verify", "--config", str(config))
    connect()
    print("FAILED_START_AFTER_MIGRATION_ROLLBACK_PASS", flush=True)
    # Now install the good new candidate and verify migration and exact grants.
    run(new / "veyl", "update", "--from-dir", str(new))
    assert json.loads(head.read_text())["version"] == 2
    assert config.read_bytes() == policy
    for name in names:
        assert (bins / name).read_bytes() == (new / name).read_bytes()
    run(bins / "veyl", "audit", "verify", "--config", str(config))
    assert "dev\tstandard\tenabled" in run(bins / "veyl", "mode", "list", "--config", str(config)).stdout
    connect()
    print("SUCCESSFUL_LEGACY_UPGRADE_PASS", flush=True)
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
