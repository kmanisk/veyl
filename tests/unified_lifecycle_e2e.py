#!/usr/bin/env python3
"""Comprehensive black-box acceptance suite for Veyl unified registry & lifecycle."""
import base64
import hashlib
import http.client
import json
import os
import pty
import select
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.parse
from pathlib import Path

import oauth_funnel as funnel


def pkce_s256(verifier: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def write_executable(path: Path, body: str):
    path.write_text(body)
    path.chmod(0o700)


class UnifiedLifecycleSuite(unittest.TestCase):
    # oauth_http_preview consumes the executable argument during import.
    # Reuse that resolved path rather than silently testing the shared debug build.
    BIN = Path(funnel.preview.BIN).resolve()

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="veyl-unified-e2e."))
        self.tmp.chmod(0o700)
        self.home = self.tmp / "home"
        self.home.mkdir(mode=0o700)
        self.workspace = self.tmp / "workspace"
        self.workspace.mkdir(mode=0o700)
        (self.workspace / "hello.txt").write_text("workspace-hello")
        self.outside = self.tmp / "outside.txt"
        self.outside.write_text("host-outside")
        self.env = {
            k: v
            for k, v in os.environ.items()
            if k not in ("XDG_CONFIG_HOME", "VEYL_PROFILE", "MCP_GATEWAY_CONFIG")
        }
        self.env["HOME"] = str(self.home)
        self.env["XDG_RUNTIME_DIR"] = str(self.tmp / "run")
        (self.tmp / "run").mkdir(mode=0o700)
        self.procs = []
        self.fakes = []

    def tearDown(self):
        for p in reversed(self.procs):
            if p.poll() is None:
                p.terminate()
                try:
                    p.wait(timeout=6)
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.wait(timeout=4)
        for fk in reversed(self.fakes):
            try:
                fk.close()
            except Exception:
                pass
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_cli(self, *args, ok=True, env=None, timeout=15):
        r = subprocess.run(
            [str(self.BIN), *args],
            env=env or self.env,
            capture_output=True,
            text=True,
            timeout=timeout,
            stdin=subprocess.DEVNULL,
        )
        self.assertEqual(r.returncode == 0, ok, (args, r.returncode, r.stdout, r.stderr))
        return r

    def start_fake_tailscale(self):
        sock_path = self.tmp / f"tailscale-{len(self.fakes)}.sock"
        fk = funnel.FakeDaemon(sock_path)
        self.fakes.append(fk)
        return fk, sock_path

    def start_bg(self, *args, env=None):
        p = subprocess.Popen(
            [str(self.BIN), *args],
            env=env or self.env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
            stdin=subprocess.DEVNULL,
        )
        self.procs.append(p)
        lines = []
        admin_addr = None
        mcp_addr = None
        buf = b""
        fd = p.stderr.fileno()
        deadline = time.monotonic() + 12
        while time.monotonic() < deadline:
            if p.poll() is not None:
                try:
                    buf += os.read(fd, 65536)
                except OSError:
                    pass
                rest = buf.decode(errors="replace")
                raise RuntimeError(f"Process exited early ({p.returncode}): {' '.join(lines)}\n{rest}")
            r, _, _ = select.select([fd], [], [], 0.25)
            if not r:
                continue
            chunk = os.read(fd, 8192)
            if not chunk:
                continue
            buf += chunk
            while b"\n" in buf:
                raw_line, buf = buf.split(b"\n", 1)
                line = raw_line.decode(errors="replace").strip()
                if not line:
                    continue
                lines.append(line)
                if line.startswith("ADMIN_HTTP_LISTEN="):
                    admin_addr = line.split("=", 1)[1].strip()
                elif line.startswith("MCP_HTTP_LISTEN="):
                    mcp_addr = line.split("=", 1)[1].strip()
                    if admin_addr is not None:
                        return p, mcp_addr, admin_addr, lines
        self.assertIsNotNone(mcp_addr, f"Did not publish MCP listener: {lines}")
        return p, mcp_addr, admin_addr, lines

    def pair_dashboard(self, admin_addr, cfg_path=None):
        args = ["dashboard", "pair", "--config", str(cfg_path or (self.home / ".local/state/veyl/clients.json"))]
        out = self.run_cli(*args).stdout
        tok = None
        for line in out.splitlines():
            if line.startswith("PAIRING_TOKEN="):
                tok = line.split("=", 1)[1].strip()
        self.assertIsNotNone(tok, out)
        conn = http.client.HTTPConnection(admin_addr, timeout=5)
        try:
            conn.request(
                "POST",
                "/api/dashboard/pair",
                json.dumps({"pairing_token": tok}),
                {
                    "Host": admin_addr,
                    "Origin": f"http://{admin_addr}",
                    "Content-Type": "application/json",
                },
            )
            resp = conn.getresponse()
            body = json.loads(resp.read())
            self.assertEqual(resp.status, 200, body)
            cookie = resp.getheader("Set-Cookie").split(";", 1)[0]
            return cookie, body["csrf"]
        finally:
            conn.close()

    def dashboard_oauth(self, admin_addr, cookie, csrf, payload):
        conn = http.client.HTTPConnection(admin_addr, timeout=5)
        try:
            conn.request(
                "POST",
                "/api/dashboard/oauth",
                json.dumps(payload),
                {
                    "Host": admin_addr,
                    "Origin": f"http://{admin_addr}",
                    "Content-Type": "application/json",
                    "Cookie": cookie,
                    "X-CSRF-Token": csrf,
                },
            )
            resp = conn.getresponse()
            return resp.status, json.loads(resp.read())
        finally:
            conn.close()

    def proxy_request(self, mcp_addr, authority, method, path, body=None, headers=None, cf=False):
        conn = http.client.HTTPConnection(mcp_addr, timeout=6)
        hdrs = {
            "Host": authority,
            "X-Forwarded-Proto": "https",
            "X-Forwarded-For": "203.0.113.42",
        }
        if cf:
            hdrs["CF-Connecting-IP"] = "203.0.113.42"
        else:
            hdrs["X-Forwarded-Host"] = authority
            hdrs["Tailscale-Funnel-Request"] = "?1"
        if headers:
            hdrs.update(headers)
        try:
            conn.request(method, path, body, hdrs)
            resp = conn.getresponse()
            raw = resp.read()
            return resp.status, dict(resp.getheaders()), raw
        finally:
            conn.close()

    def rpc(self, target_addr, authority, bearer, method, params=None, session=None, via_tunnel=True, cf=False, timeout=6):
        pkt = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}
        if method.startswith("notifications/"):
            pkt.pop("id")
        hdrs = {"Content-Type": "application/json", "Authorization": f"Bearer {bearer}"}
        if session:
            hdrs["Mcp-Session-Id"] = session
        def _parse_body(raw_bytes):
            if not raw_bytes:
                return None
            try:
                return json.loads(raw_bytes)
            except Exception:
                return raw_bytes.decode(errors="replace")

        if via_tunnel:
            st, r_hdrs, raw = self.proxy_request(
                target_addr, authority, "POST", "/mcp", json.dumps(pkt), hdrs, cf=cf
            )
            sid = None
            for k, v in r_hdrs.items():
                if k.lower() == "mcp-session-id":
                    sid = v
            return st, sid, _parse_body(raw)
        conn = http.client.HTTPConnection(target_addr, timeout=timeout)
        try:
            hdrs["Host"] = target_addr
            conn.request("POST", "/mcp", json.dumps(pkt), hdrs)
            resp = conn.getresponse()
            raw = resp.read()
            return resp.status, resp.getheader("Mcp-Session-Id"), _parse_body(raw)
        finally:
            conn.close()

    def test_01_fresh_empty_default_yolo_dcr_approval_and_roundtrip(self):
        # 1. Fresh state reports empty, default_mode=standard, zero clients.
        st = self.run_cli("status", "--json")
        sdata = json.loads(st.stdout)
        self.assertFalse(sdata["initialized"])
        self.assertEqual(sdata["default_mode"], "standard")
        self.assertEqual(self.run_cli("clients", "list").stdout.splitlines()[0], "default_mode=standard")

        # 2. Non-interactive YOLO refused fail-closed before touching state.
        self.run_cli("mode", "yolo", ok=False)
        self.run_cli("up", "--root", str(self.workspace), "--local", "--yolo", ok=False)
        self.assertFalse((self.home / ".local/state/veyl/clients.json").exists())

        # 3. Set default_mode=yolo before any clients exist cleanly.
        self.run_cli("mode", "yolo", "--yes")
        cfg_file = self.home / ".local/state/veyl/clients.json"
        doc = json.loads(cfg_file.read_text())
        self.assertEqual(doc["default_mode"], "yolo")
        self.assertEqual(doc["clients"], [])

        # 4. Bring up with Tailscale fake socket -> preserves default_mode=yolo & adds no static clients!
        fk, ts_sock = self.start_fake_tailscale()
        p, mcp_addr, admin_addr, _ = self.start_bg(
            "up", "--root", str(self.workspace), "--tailscale", "--funnel-socket", str(ts_sock), "--no-ui"
        )
        doc_after = json.loads(cfg_file.read_text())
        self.assertEqual(doc_after["default_mode"], "yolo")
        self.assertEqual(doc_after["clients"], [])
        for name in ("chatgpt", "codex", "agy"):
            self.assertNotIn(name, [c["id"] for c in doc_after["clients"]])

        # Duplicate `veyl up` / `veyl serve` refused without disrupting owned tunnel or running process!
        self.run_cli("serve", "--local", ok=False)
        self.run_cli("up", "--local", ok=False)

        # 5. Live DCR + auth request -> verify default_mode=yolo preselects YOLO in dashboard inspect,
        # YET remote token exchange stays impossible until explicit local approval!
        authority = funnel.AUTHORITY
        origin = f"https://{authority}"
        reg_st, _, reg_raw = self.proxy_request(
            mcp_addr,
            authority,
            "POST",
            "/oauth/register",
            json.dumps({
                "client_name": "RemoteAgent",
                "redirect_uris": ["https://client.example/cb"],
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
                "scope": "mcp",
            }),
            {"Content-Type": "application/json"},
        )
        self.assertEqual(reg_st, 201, reg_raw)
        cid = json.loads(reg_raw)["client_id"]

        verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        challenge = pkce_s256(verifier)
        q = urllib.parse.urlencode({
            "client_id": cid,
            "redirect_uri": "https://client.example/cb",
            "resource": f"{origin}/mcp",
            "scope": "mcp",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "response_type": "code",
            "state": "st1",
        })
        auth_st, _, auth_raw = self.proxy_request(mcp_addr, authority, "GET", f"/oauth/authorize?{q}")
        self.assertEqual(auth_st, 200, auth_raw)
        import re
        handle = re.search(r'id="request">([^<]+)<', auth_raw.decode()).group(1)

        # Before approval, client must not be able to use /mcp cleanly.
        unauth_st, _, _ = self.rpc(mcp_addr, authority, "bogus-token", "initialize", {})
        self.assertEqual(unauth_st, 401)

        cookie, csrf = self.pair_dashboard(admin_addr, cfg_file)
        ist, inspect_body = self.dashboard_oauth(admin_addr, cookie, csrf, {"action": "inspect", "request": handle})
        self.assertEqual(ist, 200, inspect_body)
        self.assertEqual(inspect_body["default_mode"], "yolo")
        self.assertEqual(inspect_body["mode"], "yolo")

        # Approve explicitly in preselected YOLO mode via dashboard!
        ast, app_body = self.dashboard_oauth(admin_addr, cookie, csrf, {
            "action": "approve",
            "request": handle,
            "confirm": True,
            "client_id": cid,
            "redirect_uri": "https://client.example/cb",
            "resource": f"{origin}/mcp",
            "local_client": inspect_body["local_client"],
            "mode": "yolo",
            "scope_fingerprint": inspect_body["scope_fingerprint"],
        })
        self.assertEqual(ast, 200, app_body)
        self.assertEqual(app_body["mode"], "yolo")

        # Poll /oauth/authorize?request=<handle> to retrieve 303 redirect code & exchange for tokens!
        conn = http.client.HTTPConnection(mcp_addr, timeout=5)
        conn.request("GET", f"/oauth/authorize?request={urllib.parse.quote(handle)}", headers={
            "Host": authority, "X-Forwarded-Proto": "https",
            "X-Forwarded-For": "203.0.113.42", "X-Forwarded-Host": authority,
            "Tailscale-Funnel-Request": "?1",
        })
        r302 = conn.getresponse()
        r302.read()
        conn.close()
        self.assertEqual(r302.status, 303)
        loc = r302.getheader("Location")
        self.assertIsNotNone(loc)
        code = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query)["code"][0]

        tok_form = urllib.parse.urlencode({
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "https://client.example/cb",
            "client_id": cid,
            "resource": f"{origin}/mcp",
            "code_verifier": verifier,
        })
        tst, _, tok_raw = self.proxy_request(
            mcp_addr, authority, "POST", "/oauth/token", tok_form,
            {"Content-Type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(tst, 200, tok_raw)
        at = json.loads(tok_raw)["access_token"]

        # Actual MCP round trip in YOLO mode!
        _, sid, init_res = self.rpc(mcp_addr, authority, at, "initialize", {
            "protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "e2e", "version": "1"}
        })
        self.assertIsNotNone(sid, init_res)
        self.rpc(mcp_addr, authority, at, "notifications/initialized", {}, session=sid)
        _, _, rd = self.rpc(mcp_addr, authority, at, "tools/call", {"name": "read_file", "arguments": {"path": str(self.outside)}}, session=sid)
        self.assertFalse(rd["result"].get("isError"), rd)
        self.assertEqual(rd["result"]["content"][0]["text"], "host-outside")

        # Global `veyl mode standard` downgrades active live OAuth client immediately!
        self.run_cli("mode", "standard")
        _, _, denied = self.rpc(mcp_addr, authority, at, "tools/call", {"name": "read_file", "arguments": {"path": str(self.outside)}}, session=sid)
        self.assertTrue(denied["result"].get("isError"), denied)
        # In Standard workspace-only, in-workspace read succeeds cleanly:
        _, _, ws_ok = self.rpc(mcp_addr, authority, at, "tools/call", {"name": "read_file", "arguments": {"path": "hello.txt"}}, session=sid)
        self.assertFalse(ws_ok["result"].get("isError"), ws_ok)

        # Verify unrelated Tailscale route survived while Veyl shuts down cleanly via `veyl down`!
        self.run_cli("down")
        p.wait(timeout=8)
        snap = fk.snapshot()
        self.assertIn(f"{funnel.HOST}:8443", snap.get("Web", {}))
        self.assertIn("other-owner", snap.get("Foreground", {}))
        for own_id in fk.own_ids():
            self.assertNotIn(own_id, snap.get("Foreground", {}))

    def test_02_migrations_combined_runtime_conflicts_and_revocation(self):
        # Build legacy ~/.config/mcp-gateway AND legacy ~/.veyl-login/profile separately first!
        legacy_dir = self.home / ".config/mcp-gateway"
        (legacy_dir / "audit").mkdir(parents=True, mode=0o700)
        (legacy_dir / "jobs").mkdir(mode=0o700)
        legacy_audit = legacy_dir / "audit/events.jsonl"
        legacy_audit.touch(mode=0o600)
        legacy_token = "11" * 32
        disabled_token = "22" * 32
        legacy_cfg = legacy_dir / "clients.json"
        legacy_cfg.write_text(json.dumps({
            "policy_version": 4,
            "admin_listen": "127.0.0.1:0",
            "audit_log": str(legacy_audit),
            "job_state_dir": str(legacy_dir / "jobs"),
            "job_profiles": {"pwd": {"executable": "/usr/bin/pwd", "args": [], "timeout_seconds": 5}},
            "clients": [
                {
                    "id": "static-dev", "root": str(self.workspace), "mode": "standard", "disabled": False,
                    "token_sha256": hashlib.sha256(legacy_token.encode()).hexdigest(),
                    "expires_at_unix_seconds": int(time.time()) + 600,
                    "tools": ["read_file", "write_file"],
                },
                {
                    "id": "static-disabled", "root": str(self.workspace), "mode": "standard", "disabled": True,
                    "token_sha256": hashlib.sha256(disabled_token.encode()).hexdigest(),
                    "expires_at_unix_seconds": int(time.time()) + 600,
                    "tools": ["read_file"],
                },
            ],
        }))
        legacy_cfg.chmod(0o600)

        # Also create legacy ~/.veyl-login/profile via real `veyl oauth setup` on fake tailscale!
        fk, ts_sock = self.start_fake_tailscale()
        prof = self.home / ".veyl-login/profile"
        (self.home / ".veyl-login").mkdir(mode=0o700)
        lp, mcp_addr, admin_addr, _ = self.start_bg(
            "oauth", "setup", "--root", str(self.workspace), "--profile", str(prof),
            "--funnel", "--funnel-socket", str(ts_sock),
        )
        authority = funnel.AUTHORITY
        origin = f"https://{authority}"
        reg_st, _, reg_raw = self.proxy_request(mcp_addr, authority, "POST", "/oauth/register", json.dumps({
            "client_name": "LegacyOAuthApp", "redirect_uris": ["https://client.example/cb"],
            "token_endpoint_auth_method": "none", "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"], "scope": "mcp",
        }), {"Content-Type": "application/json"})
        self.assertEqual(reg_st, 201, reg_raw)
        cid = json.loads(reg_raw)["client_id"]
        verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        q = urllib.parse.urlencode({
            "client_id": cid, "redirect_uri": "https://client.example/cb",
            "resource": f"{origin}/mcp", "scope": "mcp", "code_challenge": pkce_s256(verifier),
            "code_challenge_method": "S256", "response_type": "code",
        })
        _, _, auth_raw = self.proxy_request(mcp_addr, authority, "GET", f"/oauth/authorize?{q}")
        import re
        handle = re.search(r'id="request">([^<]+)<', auth_raw.decode()).group(1)
        cookie, csrf = self.pair_dashboard(admin_addr, prof / "clients.json")
        _, ib = self.dashboard_oauth(admin_addr, cookie, csrf, {"action": "inspect", "request": handle})
        self.dashboard_oauth(admin_addr, cookie, csrf, {
            "action": "approve", "request": handle, "confirm": True,
            "client_id": cid, "redirect_uri": "https://client.example/cb",
            "resource": f"{origin}/mcp", "local_client": ib["local_client"],
            "mode": "standard", "scope_fingerprint": ib["scope_fingerprint"],
        })
        conn = http.client.HTTPConnection(mcp_addr, timeout=5)
        conn.request("GET", f"/oauth/authorize?request={urllib.parse.quote(handle)}", headers={
            "Host": authority, "X-Forwarded-Proto": "https",
            "X-Forwarded-For": "203.0.113.42", "X-Forwarded-Host": authority,
            "Tailscale-Funnel-Request": "?1",
        })
        r302 = conn.getresponse()
        r302.read()
        conn.close()
        self.assertEqual(r302.status, 303)
        code = urllib.parse.parse_qs(urllib.parse.urlparse(r302.getheader("Location")).query)["code"][0]
        _, _, tok_raw = self.proxy_request(mcp_addr, authority, "POST", "/oauth/token", urllib.parse.urlencode({
            "grant_type": "authorization_code", "code": code, "redirect_uri": "https://client.example/cb",
            "client_id": cid, "resource": f"{origin}/mcp", "code_verifier": verifier,
        }), {"Content-Type": "application/x-www-form-urlencoded"})
        oauth_tok = json.loads(tok_raw)["access_token"]
        lp.terminate()
        lp.wait(timeout=8)

        # Trigger transactional migration on first unified `veyl status` or `veyl mode`!
        st_out = self.run_cli("status", "--json")
        st_json = json.loads(st_out.stdout)
        self.assertTrue(st_json["initialized"])
        self.assertEqual([c["id"] for c in st_json["static_clients"]], ["static-dev", "static-disabled"])
        self.assertEqual([r["client_id"] for r in st_json["oauth_registrations"]], [cid])

        # Originals must still be preserved untouched!
        self.assertTrue(legacy_cfg.exists())
        self.assertTrue((prof / "oauth/oauth-state.json").exists())

        # Start ONE unified `veyl serve` and admit BOTH static bearer AND migrated OAuth token!
        listen_port = free_port()
        sp, unified_mcp, _, _ = self.start_bg(
            "serve", "--listen", f"127.0.0.1:{listen_port}", "--tailscale", "--funnel-socket", str(ts_sock),
        )
        # Verify status shows running runtime accurately:
        live_status = json.loads(self.run_cli("status", "--json").stdout)
        self.assertIn("running", live_status["runtime"])

        # Static client over loopback works:
        s_st, s_sid, _ = self.rpc(unified_mcp, unified_mcp, legacy_token, "initialize", {
            "protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "static", "version": "1"}
        }, via_tunnel=False)
        self.assertEqual(s_st, 200)
        self.rpc(unified_mcp, unified_mcp, legacy_token, "notifications/initialized", {}, session=s_sid, via_tunnel=False)
        _, _, sr = self.rpc(unified_mcp, unified_mcp, legacy_token, "tools/call", {"name": "read_file", "arguments": {"path": "hello.txt"}}, session=s_sid, via_tunnel=False)
        self.assertEqual(sr["result"]["content"][0]["text"], "workspace-hello")

        # Disabled static client stays denied:
        d_st, _, _ = self.rpc(unified_mcp, unified_mcp, disabled_token, "initialize", {}, via_tunnel=False)
        self.assertEqual(d_st, 401)

        # Static bearer must NEVER be accepted over public tunnel ingress:
        bad_tunnel_st, _, _ = self.rpc(unified_mcp, authority, legacy_token, "initialize", {}, via_tunnel=True)
        self.assertEqual(bad_tunnel_st, 401)

        # Migrated OAuth token works over public tunnel with preserved issuer!
        o_st, o_sid, _ = self.rpc(unified_mcp, authority, oauth_tok, "initialize", {
            "protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "oauth", "version": "1"}
        }, via_tunnel=True)
        self.assertEqual(o_st, 200)
        self.rpc(unified_mcp, authority, oauth_tok, "notifications/initialized", {}, session=o_sid, via_tunnel=True)
        _, _, or_res = self.rpc(unified_mcp, authority, oauth_tok, "tools/call", {"name": "read_file", "arguments": {"path": "hello.txt"}}, session=o_sid, via_tunnel=True)
        self.assertEqual(or_res["result"]["content"][0]["text"], "workspace-hello")

        # Revoke OAuth client by unambiguous display name ("LegacyOAuthApp") -> immediate + durable!
        self.run_cli("clients", "revoke", "LegacyOAuthApp", "--yes")
        rev_st, _, _ = self.rpc(unified_mcp, authority, oauth_tok, "tools/call", {"name": "read_file", "arguments": {"path": "hello.txt"}}, session=o_sid, via_tunnel=True)
        self.assertEqual(rev_st, 401)

        # Revoke static client cleanly as well -> immediate denial + survives restart!
        self.run_cli("clients", "revoke", "static-dev", "--yes")
        s_rev_st, _, _ = self.rpc(unified_mcp, unified_mcp, legacy_token, "tools/call", {"name": "read_file", "arguments": {"path": "hello.txt"}}, session=s_sid, via_tunnel=False)
        self.assertEqual(s_rev_st, 401)

        # SIGINT cleanup check (unrelated Foreground['other-owner'] preserved, owned removed):
        sp.send_signal(signal.SIGINT)
        sp.wait(timeout=8)
        snap = fk.snapshot()
        self.assertIn("other-owner", snap.get("Foreground", {}))
        for own_id in fk.own_ids():
            self.assertNotIn(own_id, snap.get("Foreground", {}))

    def test_03_migration_conflicts_interrupted_and_cloudflare_controls(self):
        # Interrupted migration marker refuses fail-closed:
        state_dir = self.home / ".local/state/veyl"
        state_dir.mkdir(parents=True, mode=0o700)
        pending = state_dir / ".migration-pending"
        pending.write_text("in_progress\n")
        pending.chmod(0o600)
        err = self.run_cli("status", ok=False)
        self.assertIn("Interrupted unified registry migration", err.stderr)
        pending.unlink()

        # Cloudflare missing/invalid rejection (never installs or stubs success):
        self.run_cli("up", "--root", str(self.workspace), "--cloudflare", ok=False)
        bad_creds = self.tmp / "cf-creds.json"
        bad_creds.write_text("{}")
        bad_creds.chmod(0o600)
        self.run_cli(
            "up", "--root", str(self.workspace), "--cloudflare",
            "--cf-hostname", "random.trycloudflare.com",
            "--cf-tunnel", "t1", "--cf-credentials", str(bad_creds),
            ok=False,
        )

        # Reject group/world-readable credentials even with an owner-only parent.
        bad_creds.chmod(0o644)
        refused = self.run_cli(
            "up", "--root", str(self.workspace), "--cloudflare",
            "--cf-hostname", "mcp.custom.example", "--cf-tunnel", "veyl-cf-test",
            "--cf-credentials", str(bad_creds), ok=False,
        )
        self.assertIn("owner-controlled private regular file", refused.stderr)
        bad_creds.chmod(0o600)

        # Explicit Cloudflare config with local fake cloudflared binary starts, serves, and tears down cleanly!
        pid_file = self.tmp / "cf.pid"
        fake_cf = self.tmp / "fake-cloudflared"
        write_executable(
            fake_cf,
            f"#!/usr/bin/env bash\necho $$ > {str(pid_file)}\ntrap 'rm -f {str(pid_file)}; exit 0' TERM INT\nwhile true; do sleep 0.1; done\n",
        )
        p, mcp_addr, _, _ = self.start_bg(
            "up", "--root", str(self.workspace), "--cloudflare",
            "--cf-hostname", "mcp.custom.example",
            "--cf-tunnel", "veyl-cf-test",
            "--cf-credentials", str(bad_creds),
            "--cf-bin", str(fake_cf),
            "--no-ui",
        )
        # Wait briefly for fake cloudflared to record PID
        deadline = time.monotonic() + 5
        while not pid_file.exists() and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertTrue(pid_file.exists())
        cf_pid = int(pid_file.read_text().strip())

        # Verify Cloudflare proxy envelope works cleanly on /oauth/register
        st, _, _ = self.proxy_request(mcp_addr, "mcp.custom.example", "GET", "/.well-known/oauth-authorization-server", cf=True)
        self.assertEqual(st, 200)
        # Reject Tailscale headers on Cloudflare ingress!
        bad_st, _, _ = self.proxy_request(mcp_addr, "mcp.custom.example", "GET", "/.well-known/oauth-authorization-server", cf=False)
        self.assertEqual(bad_st, 403)

        self.run_cli("down")
        p.wait(timeout=8)
        self.assertFalse(pid_file.exists())
        try:
            os.kill(cf_pid, 0)
            self.fail("cloudflared child still alive after veyl down")
        except ProcessLookupError:
            pass

    def test_04_isolated_migrations_and_conflict_controls(self):
        # 1. Symlink traversal in legacy clients.json is refused fail-closed:
        legacy_dir = self.home / ".config/mcp-gateway"
        legacy_dir.mkdir(parents=True, mode=0o700)
        real_target = self.tmp / "outside-target.json"
        real_target.write_text('{"policy_version":4,"clients":[]}')
        real_target.chmod(0o600)
        (legacy_dir / "clients.json").symlink_to(real_target)
        err = self.run_cli("status", ok=False)
        self.assertNotEqual(err.returncode, 0)
        self.assertFalse((self.home / ".local/state/veyl/clients.json").exists())

        # 2. Native-only ~/.config/mcp-gateway migration preserves static client + goals + jobs:
        (legacy_dir / "clients.json").unlink()
        tok = "33" * 32
        (legacy_dir / "audit").mkdir(mode=0o700)
        (legacy_dir / "audit/events.jsonl").touch(mode=0o600)
        (legacy_dir / "jobs").mkdir(mode=0o700)
        (legacy_dir / "jobs/sample.json").write_text("{}")
        (legacy_dir / "jobs/sample.json").chmod(0o600)
        goals_dir = legacy_dir / ".clients.json.goals"
        goals_dir.mkdir(mode=0o700)
        (goals_dir / "g1.json").write_text('{"title":"preserved-goal"}')
        (goals_dir / "g1.json").chmod(0o600)
        (legacy_dir / "clients.json").write_text(json.dumps({
            "policy_version": 4,
            "audit_log": str(legacy_dir / "audit/events.jsonl"),
            "job_state_dir": str(legacy_dir / "jobs"),
            "clients": [{
                "id": "native-only", "root": str(self.workspace), "mode": "standard", "disabled": False,
                "token_sha256": hashlib.sha256(tok.encode()).hexdigest(),
                "expires_at_unix_seconds": int(time.time()) + 600,
                "tools": ["read_file"],
            }],
        }))
        (legacy_dir / "clients.json").chmod(0o600)
        st = json.loads(self.run_cli("status", "--json").stdout)
        self.assertTrue(st["initialized"])
        self.assertEqual([c["id"] for c in st["static_clients"]], ["native-only"])
        state_dir = self.home / ".local/state/veyl"
        self.assertTrue((state_dir / "jobs/sample.json").exists())
        self.assertTrue((state_dir / ".clients.json.goals/g1.json").exists())

        # 3. Conflicting independent static policies (~/.local/state/veyl vs ~/.config/mcp-gateway) fail closed:
        doc_no_prov = json.loads((state_dir / "clients.json").read_text())
        doc_no_prov.pop("migrated_from", None)
        (state_dir / "clients.json").write_text(json.dumps(doc_no_prov))
        conflict_err = self.run_cli("status", ok=False)
        self.assertIn("Conflicting static policies", conflict_err.stderr)

        # 4. OAuth-only migration when ~/.config/mcp-gateway & ~/.local/state/veyl are absent:
        shutil.rmtree(state_dir)
        shutil.rmtree(legacy_dir)
        fk, ts_sock = self.start_fake_tailscale()
        prof2 = self.home / ".veyl-login/profile"
        (self.home / ".veyl-login").mkdir(mode=0o700)
        lp, _, _, _ = self.start_bg(
            "oauth", "setup", "--root", str(self.workspace), "--profile", str(prof2),
            "--funnel", "--funnel-socket", str(ts_sock),
        )
        lp.terminate()
        lp.wait(timeout=8)
        oauth_st = json.loads(self.run_cli("status", "--json").stdout)
        self.assertTrue(oauth_st["initialized"])
        self.assertTrue(oauth_st["audit_verified"])
        self.assertEqual(oauth_st["static_clients"], [])
        migrated_cfg = json.loads((state_dir / "clients.json").read_text())
        self.assertTrue(migrated_cfg["oauth"]["enabled"])
        self.assertEqual(migrated_cfg["tailscale_serve"]["hostname"], funnel.HOST)
        self.assertTrue((state_dir / "oauth/oauth-state.json").exists())

    def test_05_explicit_saved_issuer_cutover(self):
        # Production-shaped split-port configuration. Both stores are real,
        # but all credentials and Tailscale routes are disposable fixtures.
        fk, sock = self.start_fake_tailscale()
        prof = self.home / ".veyl-login/profile"
        prof.parent.mkdir(mode=0o700)
        legacy, _, _, _ = self.start_bg(
            "oauth", "setup", "--root", str(self.workspace), "--profile", str(prof),
            "--funnel", "--funnel-socket", str(sock),
        )
        legacy.terminate()
        self.assertEqual(legacy.wait(timeout=8), 0)
        source = prof / "oauth/oauth-state.json"
        original_oauth = source.read_bytes()
        self.assertEqual(json.loads(original_oauth)["payload"]["registry"]["resource"],
                         f"https://{funnel.AUTHORITY}/mcp")
        state = self.home / ".local/state/veyl"
        (state / "audit").mkdir(parents=True, mode=0o700)
        state.chmod(0o700)
        ledger = state / "audit/events.jsonl"
        ledger.touch(mode=0o600)
        cfg = state / "clients.json"
        token = "44" * 32
        public_token = "55" * 32
        clients = [{
            "id": "primary", "root": str(self.workspace), "mode": "standard", "disabled": False,
            "tools": ["read_file"], "token_sha256": hashlib.sha256(token.encode()).hexdigest(),
            "expires_at_unix_seconds": int(time.time()) + 600,
        }]
        cfg.write_text(json.dumps({
            "policy_version": 4, "audit_log": str(ledger), "admin_listen": "127.0.0.1:0",
            "clients": clients,
            "tailscale_serve": {"hostname": funnel.HOST, "mcp_https_port": 8443,
                "admin_https_port": 9443, "funnel": {"client": "primary",
                    "token_sha256": hashlib.sha256(public_token.encode()).hexdigest(),
                    "allow_secret_path": True}},
        }))
        cfg.chmod(0o600)
        before = cfg.read_bytes()
        before_routes = fk.snapshot()
        err = self.run_cli("status", "--json", ok=False)
        self.assertIn("Tailscale Funnel port conflict", err.stderr)
        self.assertEqual(cfg.read_bytes(), before)
        self.assertEqual(source.read_bytes(), original_oauth)
        self.assertFalse((state / ".migration-pending").exists())
        err = self.run_cli("up", "--adopt-oauth-issuer", "--funnel-port", "8443", ok=False)
        self.assertIn("do not override", err.stderr)
        self.assertEqual(cfg.read_bytes(), before)
        # Explicit consent preserves the issuer, not the obsolete public bearer.
        proc, mcp, _, _ = self.start_bg(
            "up", "--adopt-oauth-issuer", "--tailscale", "--funnel-socket", str(sock),
            "--listen", "127.0.0.1:0", "--no-ui",
        )
        migrated = json.loads(cfg.read_text())
        self.assertEqual(migrated["clients"], clients)
        self.assertEqual(migrated["tailscale_serve"]["mcp_https_port"], 10000)
        self.assertNotIn("funnel", migrated["tailscale_serve"])
        backup = state / "clients.pre-unified.json"
        self.assertEqual(backup.read_bytes(), before)
        self.assertEqual(backup.stat().st_mode & 0o777, 0o600)
        self.assertEqual(source.read_bytes(), original_oauth)
        self.assertFalse((state / ".migration-pending").exists())
        status = json.loads(self.run_cli("status", "--json").stdout)
        self.assertEqual(status["runtime_details"]["issuer"], f"https://{funnel.AUTHORITY}")
        self.assertEqual(status["runtime_details"]["public_mcp_url"], f"https://{funnel.AUTHORITY}/mcp")
        init = {"protocolVersion": "2025-11-25", "capabilities": {},
                "clientInfo": {"name": "migration-test", "version": "1"}}
        code, sid, _ = self.rpc(mcp, mcp, token, "initialize", init, via_tunnel=False)
        self.assertEqual(code, 200)
        self.assertIsNotNone(sid)
        self.rpc(mcp, mcp, token, "notifications/initialized", {}, session=sid, via_tunnel=False)
        _, _, result = self.rpc(mcp, mcp, token, "tools/call",
            {"name": "read_file", "arguments": {"path": "hello.txt"}}, session=sid, via_tunnel=False)
        self.assertEqual(result["result"]["content"][0]["text"], "workspace-hello")
        for bearer in (token, public_token):
            code, _, _ = self.rpc(mcp, funnel.AUTHORITY, bearer, "initialize", init, via_tunnel=True)
            self.assertIn(code, (401, 403))
        self.run_cli("down")
        self.assertEqual(proc.wait(timeout=8), 0)
        self.assertEqual(fk.snapshot(), before_routes)
        self.assertEqual(json.loads(self.run_cli("status", "--json").stdout)["runtime"], "stopped")
        self.assertEqual(backup.read_bytes(), before)

    def test_06_unified_dashboard_static_and_oauth_jobs(self):
        fk, sock = self.start_fake_tailscale()
        state = self.home / ".local/state/veyl"
        (state / "audit").mkdir(parents=True, mode=0o700)
        (state / "jobs").mkdir(parents=True, mode=0o700)
        state.chmod(0o700)
        ledger = state / "audit/events.jsonl"
        ledger.touch(mode=0o600)
        token = "66" * 32
        cfg = state / "clients.json"
        cfg.write_text(json.dumps({
            "policy_version": 4,
            "audit_log": str(ledger),
            "job_state_dir": str(state / "jobs"),
            "admin_listen": "127.0.0.1:0",
            "job_profiles": {"pwd": {"executable": "/usr/bin/pwd", "args": [], "timeout_seconds": 5}},
            "clients": [{
                "id": "primary",
                "root": str(self.workspace),
                "mode": "standard",
                "disabled": False,
                "tools": ["exec_command", "job_start", "job_status", "job_logs", "list_jobs"],
                "token_sha256": hashlib.sha256(token.encode()).hexdigest(),
                "expires_at_unix_seconds": int(time.time()) + 600,
            }],
        }))
        cfg.chmod(0o600)
        self.run_cli("mode", "yolo", "--yes")
        env = dict(self.env)
        if os.environ.get("XDG_RUNTIME_DIR"):
            env["XDG_RUNTIME_DIR"] = os.environ["XDG_RUNTIME_DIR"]
        proc, mcp, admin, _ = self.start_bg(
            "up", "--root", str(self.workspace), "--tailscale",
            "--funnel-socket", str(sock), "--listen", "127.0.0.1:0", "--no-ui",
            env=env,
        )
        init = {"protocolVersion": "2025-11-25", "capabilities": {}, "clientInfo": {"name": "jobs-ui", "version": "1"}}
        code, sid, _ = self.rpc(mcp, mcp, token, "initialize", init, via_tunnel=False)
        self.assertEqual(code, 200)
        self.rpc(mcp, mcp, token, "notifications/initialized", {}, session=sid, via_tunnel=False)
        _, _, started = self.rpc(mcp, mcp, token, "tools/call", {"name": "exec_command", "arguments": {"command": "/usr/bin/pwd"}}, session=sid, via_tunnel=False)
        self.assertFalse(started["result"].get("isError"), started)
        job_id = json.loads(started["result"]["content"][0]["text"])["job_id"]
        cookie, csrf = self.pair_dashboard(admin, cfg)
        for path, expected_code, must_contain, must_omit in [
            ("/api/dashboard/jobs?client=primary", 200, job_id, None),
            (f"/api/dashboard/jobs/{job_id}/logs?client=primary", 200, job_id, None),
            ("/api/dashboard/jobs?client=oauth", 200, None, job_id),
            (f"/api/dashboard/jobs/{job_id}/logs?client=oauth", 404, None, None),
            ("/api/dashboard/jobs?client=missing", 404, None, None),
        ]:
            conn = http.client.HTTPConnection(admin, timeout=5)
            try:
                conn.request("GET", path, headers={"Host": admin, "Origin": f"http://{admin}", "Cookie": cookie, "X-CSRF-Token": csrf})
                resp = conn.getresponse()
                body = resp.read().decode()
                self.assertEqual(resp.status, expected_code, (path, resp.status, body))
                if must_contain:
                    self.assertIn(must_contain, body)
                if must_omit:
                    self.assertNotIn(must_omit, body)
            finally:
                conn.close()
        self.run_cli("down")
        self.assertEqual(proc.wait(timeout=8), 0)

if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(UnifiedLifecycleSuite)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    raise SystemExit(not result.wasSuccessful())
