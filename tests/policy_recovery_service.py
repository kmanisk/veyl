#!/usr/bin/env python3
"""Real systemd and MCP readiness through failed post-migration recovery."""
import hashlib
import http.client
import json
from pathlib import Path
import shutil
import subprocess
import sys
import time

base, old, new = map(lambda p: Path(p).resolve(), sys.argv[1:4])
home = base / "home"
assert Path.home() == home
state = home / ".local/state/veyl"
state.mkdir(parents=True, mode=0o700)
bins = home / ".local/bin"
bins.mkdir(parents=True, mode=0o700)
installed = bins / "veyl"
shutil.copy2(old / "veyl", installed)
for alias in ("mcp-gateway", "veyl-monitor"):
    (bins / alias).symlink_to("veyl")
workspace = base / "workspace"
workspace.mkdir(mode=0o700)
(workspace / "canary").write_text("ready")
(config := state / "clients.json").touch(mode=0o600)
(audit_dir := state / "audit").mkdir(mode=0o700)
(audit := audit_dir / "audit.jsonl").touch(mode=0o600)
(jobs := state / "jobs").mkdir(mode=0o700)
token = "6b" * 32
config.write_text(json.dumps({
    "policy_version": 3, "audit_log": str(audit), "job_state_dir": str(jobs),
    "job_profiles": {"ok": {"executable": "/usr/bin/true", "args": [], "timeout_seconds": 5}},
    "clients": [{"id": "primary", "root": str(workspace), "mode": "standard", "disabled": False,
                 "tools": ["read_file", "exec_command", "job_status"],
                 "token_sha256": hashlib.sha256(token.encode()).hexdigest(),
                 "expires_at_unix_seconds": int(time.time()) + 3600}]
}))

def run(binary, *args, expect=True, data=None):
    result = subprocess.run([binary, *args], input=data, capture_output=True, text=True, timeout=35)
    assert (result.returncode == 0) == expect, (args, result.stdout, result.stderr)
    return result

def rpc(method, params=None, session=None, token=token):
    headers = {"Authorization": "Bearer " + token, "Content-Type": "application/json"}
    if session:
        headers["Mcp-Session-Id"] = session
    body = {"jsonrpc": "2.0", "method": method, "params": params or {}}
    if not method.startswith("notifications/"):
        body["id"] = 1
    c = http.client.HTTPConnection("127.0.0.1", 7331, timeout=2)
    try:
        c.request("POST", "/mcp", json.dumps(body), headers)
        r = c.getresponse()
        data = r.read()
        assert r.status in (200, 202), (r.status, data)
        return r.getheader("Mcp-Session-Id"), json.loads(data) if data else None
    finally:
        c.close()

def ready():
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline:
        try:
            session, result = rpc("initialize", {"protocolVersion":"2025-11-25", "capabilities":{},
                                                 "clientInfo":{"name":"recovery","version":"1"}})
            assert session and "result" in result, result
            rpc("notifications/initialized", session=session)
            return session
        except (OSError, http.client.HTTPException):
            time.sleep(.1)
    raise AssertionError("No authenticated MCP readiness")

log = (base / "nested-manager.log").open("wb")
manager = subprocess.Popen(["/usr/lib/systemd/systemd", "--user", "--unit=veyl-test.target"],
                           stdout=log, stderr=log)
try:
    until = time.monotonic() + 10
    while subprocess.run(["systemctl","--user","show","-p","SystemState"],
                         capture_output=True, timeout=3).returncode:
        assert manager.poll() is None and time.monotonic() < until
        time.sleep(.1)
    run(installed, "mode", "full", "primary", "--confirm-full", "--config", str(config))
    old_policy = config.read_bytes()
    run(installed, "service", "install", "--confirm", "--config", str(config))
    run(installed, "service", "start", "--confirm", "--config", str(config))
    ready()
    run(new / "veyl", "update", "--from-dir", str(new))
    ready()
    run(installed, "mode", "migrate", "--config", str(config))
    session = ready()
    result = rpc("tools/call", {"name":"exec_command","arguments":
                 {"command":"printf retained-job","timeout_seconds":5}}, session)[1]["result"]
    assert not result["isError"], result
    job = json.loads(result["content"][0]["text"])
    assert job["exit_code"] == 0, job
    result = run(installed, "goal", "create", "--client", "primary", "--config", str(config),
                 data=json.dumps({"description":"Retain my goal","request_id":"recovery-goal",
                                  "acceptance_criteria":[{"description":"Prove recovery"}]}))
    goal = json.loads(result.stdout)
    saved_policy = config.read_bytes()
    assert json.loads(saved_policy)["policy_version"] == 4
    receipt = jobs / job["job_id"] / "receipt.json"
    goal_path = state / ".clients.json.goals/goals.json"
    preserved = {path: path.read_bytes() for path in [config, receipt, goal_path]}
    anchor = base / "audit-anchor.json"
    run(installed, "audit", "export-head", "--config", str(config), "--out", str(anchor))
    registry = home / ".veyl-update-backups"
    backup = next(p for p in registry.iterdir() if p.is_dir())
    unit = (home / ".config/systemd/user/mcp-gateway.service").read_text()
    service_executable = next(p for p in (installed, bins/"mcp-gateway")
                              if f'ExecStart="{p}" ' in unit)
    (active := registry / "active.json").touch(mode=0o600)
    active.write_text(json.dumps({
        "nonce": backup.name, "phase":"replacing", "dirs":[str(bins)], "backup_dir":str(backup),
        "service_executable":str(service_executable), "service_active":True
    }))
    failed = run(new / "veyl", "update", "--recover", expect=False)
    assert "Rollback refused" in failed.stderr and "--recover-forward" in failed.stderr, failed.stderr
    # Older in-flight journals may lack a separate policy digest. The actual
    # backed-up 0.6.1 executable must still fail the format probe.
    digest = backup / "policy.sha256"
    digest_copy = digest.read_bytes()
    digest.unlink()
    failed = run(new / "veyl", "update", "--recover", expect=False)
    assert "cannot read the current persistent state" in failed.stderr, failed.stderr
    digest.write_bytes(digest_copy)
    digest.chmod(0o600)
    assert config.read_bytes() != old_policy
    assert all(p.read_bytes() == data for p, data in preserved.items())

    # A trusted fixture binary speaks the format probe but fails on startup.
    broken = base / "broken"
    broken.mkdir(mode=0o700)
    source = base / "broken.c"
    source.write_text('#include <stdio.h>\n#include <string.h>\nint main(int n,char **a){if(n==2 && !strcmp(a[1],"--persistent-format")){puts("veyl-linux-state-4");return 0;}return 1;}\n')
    subprocess.run(["/usr/bin/cc", str(source), "-o", str(broken/"veyl")], check=True)
    (broken / "SHA256SUMS").write_text(hashlib.sha256((broken/"veyl").read_bytes()).hexdigest()+"  veyl\n")
    failure = run(new / "veyl", "update", "--recover-forward", str(broken), expect=False)
    assert "service" in failure.stderr.lower(), failure.stderr
    assert active.exists() and installed.read_bytes() == (broken/"veyl").read_bytes(), failure.stderr
    assert all(p.read_bytes() == data for p, data in preserved.items())
    run(new / "veyl", "update", "--recover-forward", str(new))
    session = ready()
    result = rpc("tools/call", {"name":"read_file","arguments":{"path":"canary"}}, session)[1]["result"]
    assert result["content"][0]["text"] == "ready", result
    assert installed.read_bytes() == (new/"veyl").read_bytes()
    assert not active.exists() and backup.is_dir()
    assert all(p.read_bytes() == data for p, data in preserved.items())
    run(installed, "audit", "verify", "--anchor", str(anchor), "--config", str(config))
    after = run(installed, "goal", "get", goal["id"], "--config", str(config))
    assert json.loads(after.stdout) == goal
    result = rpc("tools/call", {"name":"job_status","arguments":{"job_id":job["job_id"]}}, session)[1]["result"]
    assert json.loads(result["content"][0]["text"])["exit_code"] == 0
    print("SCHEMA4_LEGACY_ROLLBACK_REFUSED_AND_FORWARD_RECOVERY_READY")
finally:
    subprocess.run(["systemctl","--user","stop","mcp-gateway.service"], capture_output=True, timeout=8)
    if manager.poll() is None:
        manager.terminate()
        try:
            manager.wait(3)
        except subprocess.TimeoutExpired:
            manager.kill()
            manager.wait(2)
    log.close()
