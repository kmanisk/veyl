"""Isolated nested systemd --user acceptance test for opt-in `veyl.service`."""
import hashlib
import http.client
import json
import os
import pathlib
import socket
import subprocess
import sys
import time

base = pathlib.Path(sys.argv[1])
gateway = pathlib.Path(sys.argv[2])
workspace = base / "workspace"
workspace.mkdir(mode=0o700)
state_dir = base / "home/.local/state/veyl"
for p in (base / "home", base / "home/.local", base / "home/.local/state", state_dir):
    p.mkdir(mode=0o700, exist_ok=True)
    p.chmod(0o700)
(state_dir / "audit").mkdir(mode=0o700)
(state_dir / "jobs").mkdir(mode=0o700)
(state_dir / "skills").mkdir(mode=0o700)
audit = state_dir / "audit/events.jsonl"
audit.touch(mode=0o600)
bearer = "c4" * 32
cfg = state_dir / "clients.json"
cfg.write_text(json.dumps({
    "policy_version": 4,
    "default_mode": "standard",
    "audit_log": str(audit),
    "job_state_dir": str(state_dir / "jobs"),
    "skills_dir": str(state_dir / "skills"),
    "admin_listen": "127.0.0.1:0",
    "job_profiles": {"sleep": {"executable": "/usr/bin/sleep", "args": ["8"], "timeout_seconds": 12}},
    "clients": [{
        "id": "svc-client",
        "root": str(workspace),
        "mode": "standard",
        "disabled": False,
        "token_sha256": hashlib.sha256(bearer.encode()).hexdigest(),
        "expires_at_unix_seconds": int(time.time()) + 600,
        "tools": ["read_file", "job_start", "job_status", "job_cancel"],
    }],
}))
cfg.chmod(0o600)

with socket.socket() as s:
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]

log = (base / "nested-manager.log").open("wb")
mgr = subprocess.Popen(["/usr/lib/systemd/systemd", "--user", "--unit=veyl-test.target"], stdout=log, stderr=log)
try:
    for _ in range(40):
        assert mgr.poll() is None, (base / "nested-manager.log").read_text()
        p = subprocess.run(["systemctl", "--user", "show", "--property=SystemState"], capture_output=True, text=True, timeout=1)
        if p.returncode == 0:
            break
        time.sleep(0.15)
    else:
        raise RuntimeError("Isolated systemd user manager unavailable")

    def cli(*args, check=True):
        r = subprocess.run([str(gateway), *args], capture_output=True, text=True, timeout=30)
        if check and r.returncode != 0:
            raise RuntimeError(f"{args}: {r.stderr}\n{(base / 'nested-manager.log').read_text()}")
        return r

    # 1. Opt-in `service install` writes veyl.service with `ExecStart=".../veyl" serve` and `Restart=on-failure`, stays inactive/disabled!
    inst = cli("service", "install", "--listen", f"127.0.0.1:{port}").stdout
    unit_file = base / "home/.config/systemd/user/veyl.service"
    assert unit_file.exists(), inst
    unit_text = unit_file.read_text()
    assert f'"{gateway}" serve --listen 127.0.0.1:{port}' in unit_text, unit_text
    assert "Restart=on-failure" in unit_text, unit_text
    st = cli("service", "status").stdout
    assert "ActiveState=inactive" in st and "UnitFileState=disabled" in st, st

    # 2. Explicit `enable --now` activates service & preserves job receipts across restart!
    cli("service", "enable", "--now")
    assert "ActiveState=active" in cli("service", "status").stdout

    def rpc(method, params, session=None):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=4)
        pkt = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
        headers = {"Authorization": "Bearer " + bearer, "Content-Type": "application/json"}
        if session:
            headers["Mcp-Session-Id"] = session
            if method == "notifications/initialized":
                pkt.pop("id")
        try:
            conn.request("POST", "/mcp", json.dumps(pkt), headers)
            resp = conn.getresponse()
            raw = resp.read()
            assert resp.status in (200, 202), (resp.status, raw)
            return resp.getheader("Mcp-Session-Id"), (json.loads(raw) if raw else None)
        finally:
            conn.close()

    for _ in range(40):
        try:
            sid, _ = rpc("initialize", {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "svc", "version": "1"}})
            rpc("notifications/initialized", {}, sid)
            break
        except OSError:
            time.sleep(0.1)
    else:
        raise RuntimeError("veyl.service listener not ready")

    _, res = rpc("tools/call", {"name": "job_start", "arguments": {"profile": "sleep"}}, sid)
    job_id = json.loads(res["result"]["content"][0]["text"])["job_id"]

    before_pid = int(subprocess.check_output(["systemctl", "--user", "show", "--property=MainPID", "--value", "veyl.service"], timeout=4))
    cli("service", "restart")
    after_pid = int(subprocess.check_output(["systemctl", "--user", "show", "--property=MainPID", "--value", "veyl.service"], timeout=4))
    assert after_pid not in (0, before_pid)

    for _ in range(40):
        try:
            sid, _ = rpc("initialize", {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "svc", "version": "1"}})
            rpc("notifications/initialized", {}, sid)
            break
        except OSError:
            time.sleep(0.1)
    _, res = rpc("tools/call", {"name": "job_status", "arguments": {"job_id": job_id}}, sid)
    assert json.loads(res["result"]["content"][0]["text"])["job_id"] == job_id
    _, res = rpc("tools/call", {"name": "job_cancel", "arguments": {"job_id": job_id}}, sid)
    assert json.loads(res["result"]["content"][0]["text"])["state"] == "canceled"

    # 3. `veyl down` cleanly stops active veyl.service!
    cli("down")
    assert "ActiveState=inactive" in cli("service", "status").stdout

    # 4. Tampered unit must be refused by uninstall; clean uninstall removes unit & preserves state!
    saved = unit_text
    unit_file.write_text(saved.replace("Restart=on-failure", "Restart=always"))
    bad_uninst = cli("service", "uninstall", check=False)
    assert bad_uninst.returncode != 0 and unit_file.exists()
    unit_file.write_text(saved)
    cli("service", "uninstall")
    assert not unit_file.exists()
    assert cfg.exists() and audit.exists()
    print("UNIFIED_SYSTEMD_SERVICE_PASS", flush=True)
finally:
    if mgr.poll() is None:
        mgr.terminate()
        try:
            mgr.wait(timeout=3)
        except subprocess.TimeoutExpired:
            mgr.kill()
            mgr.wait(timeout=3)
    log.close()
