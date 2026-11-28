#!/usr/bin/env python3
"""Disposable first-run browser probe; no production state or routes are touched."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]

def main():
    binary = Path(os.environ.get("MCP_GATEWAY_BIN", "target/release/mcp-gateway")).resolve()
    browser = os.environ.get("VEYL_TEST_BROWSER") or shutil.which("brave") or shutil.which("chromium")
    if not browser:
        raise RuntimeError("Install or select a Chromium-family browser for this optional probe")
    with tempfile.TemporaryDirectory(prefix="veyl-first-run-") as tmp:
        base = Path(tmp)
        home = base / "home"
        home.mkdir(mode=0o700)
        workspace = base / "workspace"
        workspace.mkdir(mode=0o700)
        env = {**os.environ, "HOME": str(home)}
        subprocess.run([binary, "init", "--root", workspace], env=env, check=True, capture_output=True)
        for action in ("revoke","grant"):
            subprocess.run([binary,"diagnostics",action,"dev"],env=env,check=True,capture_output=True)
        config = home / ".local/state/veyl/clients.json"
        document = json.loads(config.read_text())
        subprocess.run([binary, "goal", "create", "--client", "dev", "--config", config],
                       env=env, input=json.dumps({"description": "Browser roadmap fixture",
                                                  "request_id": "browser-goal",
                                                  "acceptance_criteria": [{"description": "Observe persisted goal"}],
                                                  "roadmap": [{"id": "review", "description": "Review goal"}]}),
                       text=True, check=True, capture_output=True)
        admin_port = port()
        mcp_port = port()
        document["admin_listen"] = f"127.0.0.1:{admin_port}"
        document["default_mode"] = "standard"
        config.write_text(json.dumps(document))
        origin = f"http://127.0.0.1:{admin_port}"
        gateway = subprocess.Popen([binary, "run", "--listen", f"127.0.0.1:{mcp_port}"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                if gateway.poll() is not None:
                    raise AssertionError("Disposable foreground gateway exited")
                try:
                    with urllib.request.urlopen(origin + "/dashboard/login", timeout=.4):
                        break
                except OSError:
                    time.sleep(.1)
            else:
                raise AssertionError("Disposable admin listener did not become ready")
            bearer = (config.parent / "dev.bearer").read_text().strip()
            def rpc(method, params=None, session=None):
                headers = {"Authorization": "Bearer " + bearer, "Content-Type": "application/json"}
                if session:
                    headers["Mcp-Session-Id"] = session
                data = {"jsonrpc": "2.0", "method": method}
                if not method.startswith("notifications/"):
                    data["id"] = 1
                if params is not None:
                    data["params"] = params
                request = urllib.request.Request(f"http://127.0.0.1:{mcp_port}/mcp",
                    data=json.dumps(data).encode(), headers=headers)
                with urllib.request.urlopen(request, timeout=4) as response:
                    return response.headers.get("Mcp-Session-Id")
            session = rpc("initialize", {"protocolVersion":"2025-11-25","capabilities":{},
                                     "clientInfo":{"name":"browser-fixture","version":"1"}})
            assert session
            rpc("notifications/initialized", session=session)
            for arguments in ({}, {}, {"path":"BROWSER_SYNTHETIC_CREDENTIAL"}):
                rpc("tools/call", {"name":"system_info","arguments":arguments}, session)
            # Capture only the local opener's single argument in private test
            # storage, never print it. The real browser redeems the fragment.
            opener = base / "bin"
            opener.mkdir(mode=0o700)
            shim = opener / "xdg-open"
            shim.write_text('#!/bin/sh\numask 077\nprintf "%s" "$1" > "$VEYL_TEST_URL"\n')
            shim.chmod(0o700)
            url_file = base / "browser-url"
            launch_env = {**env, "PATH": str(opener) + os.pathsep + env["PATH"], "VEYL_TEST_URL": str(url_file)}
            result = subprocess.run([binary, "ui"], env=launch_env, check=True, capture_output=True, text=True)
            deadline = time.monotonic() + 3
            while not url_file.exists() and time.monotonic() < deadline:
                time.sleep(.05)
            url = url_file.read_text()
            assert url.startswith(origin + "/dashboard/login#pair=")
            assert "?token=" not in url
            code = url.split("#pair=", 1)[1]
            assert len(code) == 48 and code not in result.stdout and code not in result.stderr
            # The code is single-use and only the verifier is persisted.
            verifier = config.with_name(".clients.json.dashboard-pair").read_text()
            assert code not in verifier and hashlib.sha256(code.encode()).hexdigest() in verifier
            tabs = subprocess.run(["node", str(Path(__file__).with_name("dashboard_tabs.mjs")), browser],
                                  input=url, text=True, capture_output=True, timeout=55)
            assert tabs.returncode == 0, "Real browser tab-navigation test failed: " + tabs.stderr[-1000:]
            assert "DASHBOARD_TABS_AND_KEYBOARD_PASS" in tabs.stdout
            print("FIRST_RUN_BROWSER_PAIRING_PASS")
            print(tabs.stdout.strip())
            request = urllib.request.Request(origin + "/dashboard/api/pair",
                data=json.dumps({"pairing_token": code}).encode(),
                headers={"Origin": origin, "Content-Type": "application/json"})
            try:
                urllib.request.urlopen(request, timeout=3)
            except urllib.error.HTTPError as error:
                assert error.code == 401
            else:
                raise AssertionError("A consumed pairing code was replayable")
        finally:
            gateway.terminate()
            try:
                gateway.wait(timeout=5)
            except subprocess.TimeoutExpired:
                gateway.kill()
                gateway.wait()

if __name__ == "__main__":
    main()
