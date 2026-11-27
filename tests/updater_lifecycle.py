"""Independent updater E2E verification: portable, --recover, active-job block, service upgrade and failed-start rollback."""

import hashlib
import http.client
import json
import os
import pathlib
import shutil
import subprocess
import sys
import time

base = pathlib.Path(sys.argv[1])
src_bins = pathlib.Path(sys.argv[2])
home = base / "home"
veyl_bin = home / ".local/bin/veyl"
gw_bin = home / ".local/bin/mcp-gateway"
mon_bin = home / ".local/bin/veyl-monitor"
names = ("veyl", "veyl-monitor", "mcp-gateway")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def make_bundle(directory: pathlib.Path, hardlink_from: pathlib.Path | None = None, broken_gateway: bool = False, oversized: bool = False):
    directory.mkdir(mode=0o700, exist_ok=True)
    sums = []
    for name in names:
        dest = directory / name
        if name in ("veyl", "mcp-gateway") and broken_gateway:
            ver = subprocess.check_output([src_bins / "veyl", "--version"], text=True).split()[1]
            persistent_format = subprocess.check_output(
                [src_bins / "veyl", "--persistent-format"], text=True).strip()
            c_src = directory / f"broken-{name}.c"
            c_src.write_text(
                '#include <stdio.h>\n'
                '#include <string.h>\n'
                'int main(int argc, char **argv) {\n'
                f'  if (argc == 2 && strcmp(argv[1], "--version") == 0) {{ puts("{name} {ver}"); return 0; }}\n'
                f'  if (argc == 2 && strcmp(argv[1], "--persistent-format") == 0) {{ puts("{persistent_format}"); return 0; }}\n'
                '  return 1;\n'
                '}\n'
            )
            subprocess.run(["/usr/bin/cc", "-O2", str(c_src), "-o", str(dest)], check=True)
            c_src.unlink()
        elif hardlink_from is not None:
            os.link(hardlink_from / name, dest)
        else:
            shutil.copy2(src_bins / name, dest)
        dest.chmod(0o755)
        if oversized and name == "veyl":
            # ELF loaders ignore trailing padding. Preserve the >32 MiB
            # regression even when debug symbols are deliberately disabled.
            with dest.open("r+b") as executable:
                executable.truncate(max(dest.stat().st_size, 32 * 1024 * 1024 + 1))
            assert subprocess.check_output([dest, "--version"]) == subprocess.check_output([src_bins / name, "--version"])
        digest = sha256_bytes(dest.read_bytes())
        sums.append(f"{digest}  {name}")
    (directory / "SHA256SUMS").write_text("\n".join(sums) + "\n")
    (directory / "SHA256SUMS").chmod(0o600)


# 1. Portable no-manager test (before systemd --user is started) with >32 MiB debug hardlinked bundle
portable_home = base / "portable-home"
portable_home.mkdir(mode=0o700)
(portable_home / ".local/bin").mkdir(parents=True, mode=0o700)
bundle_v1 = base / "bundle-v1"
make_bundle(bundle_v1, oversized=True)
# Hardlink bundle_v2 from bundle_v1 to verify st_nlink > 1 and the >32 MiB input boundary.
bundle_v2 = base / "bundle-v2"
make_bundle(bundle_v2, hardlink_from=bundle_v1)
assert (bundle_v2 / "veyl").stat().st_nlink >= 2
assert (bundle_v2 / "veyl").stat().st_size > 32 * 1024 * 1024
# Pre-install an older dummy regular file at portable_home/.local/bin/veyl
(portable_home / ".local/bin/veyl").write_bytes(b"old-veyl")
(portable_home / ".local/bin/veyl").chmod(0o755)

portable_env = dict(os.environ, HOME=str(portable_home), XDG_RUNTIME_DIR=str(base / "missing-run"))
# Corrupt bundle checksum must fail closed cleanly
bad_bundle = base / "bad-bundle"
make_bundle(bad_bundle)
(bad_bundle / "SHA256SUMS").write_text("0" * 64 + "  veyl\n")
res = subprocess.run([bundle_v2 / "veyl", "update", "--from-dir", str(bad_bundle)], env=portable_env, capture_output=True, text=True)
assert res.returncode != 0, res
assert (portable_home / ".local/bin/veyl").read_bytes() == b"old-veyl"
assert not list((portable_home / ".local/bin").glob(".veyl-update-*"))

# Real portable --from-dir update succeeds with no systemd manager running
res = subprocess.run([bundle_v2 / "veyl", "update", "--from-dir", str(bundle_v2)], env=portable_env, capture_output=True, text=True)
assert res.returncode == 0, f"Portable update failed: {res.stdout}\n{res.stderr}"
for name in names:
    assert (portable_home / ".local/bin" / name).read_bytes() == (bundle_v2 / name).read_bytes()
assert not list((portable_home / ".local/bin").glob(".veyl-update-*"))
assert not (portable_home / ".veyl-update-backups/active.json").exists()
print("Portable no-manager update with >32 MiB hardlinked bundle passed.", flush=True)

# 2. Simulate interrupted 'replacing' journal on veyl-monitor and test --recover
old_bytes = (portable_home / ".local/bin/veyl-monitor").read_bytes()
new_bytes = b"\x7fELF-partial-monitor"
(portable_home / ".local/bin/veyl-monitor").write_bytes(new_bytes)
(portable_home / ".local/bin/veyl-monitor").chmod(0o755)
nonce = "aa" * 16
backup_dir = portable_home / ".veyl-update-backups" / nonce
backup_dir.mkdir(parents=True, mode=0o700)
orphan_stage = portable_home / ".local/bin" / f".veyl-update-{nonce}"
orphan_stage.mkdir(mode=0o700)
(orphan_stage / "veyl").write_bytes(b"leftover")
manifest = []
for name in names:
    dest = portable_home / ".local/bin" / name
    if name == "veyl-monitor":
        bpath = backup_dir / f"0-{name}.old"
        bpath.write_bytes(old_bytes)
        bpath.chmod(0o755)
        manifest.append({"destination": str(dest), "backup": str(bpath), "original_mode": 0o755, "original_sha256": sha256_bytes(old_bytes)})
    else:
        data = dest.read_bytes()
        bpath = backup_dir / f"0-{name}.old"
        bpath.write_bytes(data)
        bpath.chmod(0o755)
        manifest.append({"destination": str(dest), "backup": str(bpath), "original_mode": 0o755, "original_sha256": sha256_bytes(data)})
(backup_dir / "manifest.json").write_text(json.dumps(manifest))
(backup_dir / "manifest.json").chmod(0o600)
(portable_home / ".veyl-update-backups/active.json").write_text(json.dumps({
    "nonce": nonce,
    "phase": "replacing",
    "dirs": [str(portable_home / ".local/bin")],
    "backup_dir": str(backup_dir),
    "service_executable": None,
    "service_active": False,
}))
(portable_home / ".veyl-update-backups/active.json").chmod(0o600)
blocked = subprocess.run([portable_home / ".local/bin/veyl", "update", "--from-dir", str(bundle_v2)], env=portable_env, capture_output=True, text=True)
assert blocked.returncode != 0 and "--recover" in (blocked.stderr + blocked.stdout), blocked
rec = subprocess.run([portable_home / ".local/bin/veyl", "update", "--recover"], env=portable_env, capture_output=True, text=True)
assert rec.returncode == 0, f"Recover failed: {rec.stdout}\n{rec.stderr}"
assert (portable_home / ".local/bin/veyl-monitor").read_bytes() == old_bytes
assert not orphan_stage.exists()
assert not (portable_home / ".veyl-update-backups/active.json").exists()
print("Interrupted transaction journal and --recover passed.", flush=True)

# 3. Full isolated systemd user manager on 127.0.0.1:7331 in disposable netns
(home / ".local/bin").mkdir(parents=True, mode=0o700)
for name in names:
    shutil.copy2(bundle_v1 / name, home / ".local/bin" / name)
    (home / ".local/bin" / name).chmod(0o755)
(home / ".local/state/veyl").mkdir(parents=True, mode=0o700)
(base / "workspace").mkdir(mode=0o700)
(base / "audit").mkdir(mode=0o700)
(base / "jobs").mkdir(mode=0o700)
audit = base / "audit/main.jsonl"
audit.touch(mode=0o600)
config = home / ".local/state/veyl/clients.json"
bearer = "b4" * 32
config.write_text(json.dumps({
    "policy_version": 2,
    "audit_log": str(audit),
    "job_state_dir": str(base / "jobs"),
    "job_profiles": {"sleep": {"executable": "/usr/bin/sleep", "args": ["20"], "timeout_seconds": 30, "max_output_bytes": 4096}},
    "clients": [{
        "id": "updater-probe",
        "root": str(base / "workspace"),
        "tools": ["job_start", "job_status", "job_cancel"],
        "token_sha256": hashlib.sha256(bearer.encode()).hexdigest(),
        "expires_at_unix_seconds": int(time.time()) + 300,
    }],
}))
config.chmod(0o600)

manager_log = (base / "nested-manager.log").open("wb")
manager = subprocess.Popen(["/usr/lib/systemd/systemd", "--user", "--unit=veyl-test.target"], stdout=manager_log, stderr=manager_log)
try:
    for _ in range(40):
        if manager.poll() is not None:
            raise RuntimeError((base / "nested-manager.log").read_text())
        probe = subprocess.run(["systemctl", "--user", "show", "--property=SystemState"], capture_output=True, text=True, timeout=2)
        if probe.returncode == 0:
            break
        time.sleep(0.15)
    else:
        raise RuntimeError("Isolated systemd user manager unavailable")

    def rpc(method, params, session=None):
        conn = http.client.HTTPConnection("127.0.0.1", 7331, timeout=3)
        try:
            packet = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
            headers = {"Authorization": "Bearer " + bearer, "Content-Type": "application/json"}
            if session:
                headers["Mcp-Session-Id"] = session
                if method == "notifications/initialized":
                    packet.pop("id")
            conn.request("POST", "/mcp", json.dumps(packet), headers)
            response = conn.getresponse()
            payload = response.read()
            assert response.status in (200, 202), (response.status, payload)
            return response.headers.get("Mcp-Session-Id"), json.loads(payload) if payload else None
        finally:
            conn.close()

    def connect():
        for _ in range(40):
            try:
                session, _ = rpc("initialize", {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "updater-e2e", "version": "1"}})
                rpc("notifications/initialized", {}, session)
                return session
            except OSError:
                time.sleep(0.15)
        raise RuntimeError("Service did not start listening on 127.0.0.1:7331")

    def tool(name, args, session):
        _, result = rpc("tools/call", {"name": name, "arguments": args}, session)
        assert not result["result"].get("isError"), result
        return json.loads(result["result"]["content"][0]["text"])

    def main_pid():
        return int(subprocess.check_output(["systemctl", "--user", "show", "--property=MainPID", "--value", "mcp-gateway.service"], timeout=4))

    for args in (["service", "install", "--confirm", "--config", str(config)],
                 ["service", "enable", "--confirm", "--config", str(config)],
                 ["service", "start", "--confirm", "--config", str(config)]):
        r = subprocess.run([veyl_bin, *args], capture_output=True, text=True, timeout=30)
        assert r.returncode == 0, f"{args}: {r.stdout}\n{r.stderr}"

    pid1 = main_pid()
    assert pid1 > 0
    sess = connect()
    job_id = tool("job_start", {"profile": "sleep"}, sess)["job_id"]

    # Active job must block updater
    blocked_job = subprocess.run([veyl_bin, "update", "--from-dir", str(bundle_v2)], capture_output=True, text=True, timeout=30)
    assert blocked_job.returncode != 0 and "active or uncertain jobs" in (blocked_job.stderr + blocked_job.stdout), blocked_job

    assert tool("job_cancel", {"job_id": job_id}, sess)["state"] == "canceled"

    # Successful live service update
    ok_upd = subprocess.run([veyl_bin, "update", "--from-dir", str(bundle_v2)], capture_output=True, text=True, timeout=30)
    assert ok_upd.returncode == 0, f"Live service update failed: {ok_upd.stdout}\n{ok_upd.stderr}"
    pid2 = main_pid()
    assert pid2 not in (0, pid1)
    sess2 = connect()
    assert tool("job_status", {"job_id": job_id}, sess2)["state"] == "canceled"
    print("Active-job block + live systemd service update passed.", flush=True)

    # Failed new binary startup must roll back even from ActiveState=failed and restore healthy v2 service
    broken_bundle = base / "broken-bundle"
    make_bundle(broken_bundle, broken_gateway=True)
    v2_gateway_bytes = gw_bin.read_bytes()
    fail_upd = subprocess.run([veyl_bin, "update", "--from-dir", str(broken_bundle)], capture_output=True, text=True, timeout=30)
    assert fail_upd.returncode != 0
    assert "previous binaries restored" in (fail_upd.stderr + fail_upd.stdout), f"Unexpected failure output: {fail_upd.stdout}\n{fail_upd.stderr}"
    assert gw_bin.read_bytes() == v2_gateway_bytes
    state_out = subprocess.check_output(["systemctl", "--user", "show", "--property=ActiveState", "--value", "mcp-gateway.service"], text=True).strip()
    assert state_out == "active", state_out
    sess3 = connect()
    assert tool("job_status", {"job_id": job_id}, sess3)["state"] == "canceled"
    print("Broken-service automatic rollback from ActiveState=failed passed.", flush=True)
finally:
    if manager.poll() is None:
        manager.terminate()
        try:
            manager.wait(timeout=3)
        except subprocess.TimeoutExpired:
            manager.kill()
            manager.wait(timeout=2)
    manager_log.close()
