#!/usr/bin/env python3
"""Real loopback HTTP authorization preview; never contacts a public endpoint."""
import base64
import hashlib
import http.client
import json
import os
import pathlib
import re
import secrets
import subprocess
import sys
import tempfile
import unittest
import urllib.parse

BIN = pathlib.Path(sys.argv.pop(1)).resolve()
ORIGIN = "https://node.example:8443"
HOST = "node.example:8443"
RESOURCE = ORIGIN + "/mcp"
CALLBACK = "https://client.example/callback"
LOCAL = "fixture-only"
STATE = "state&code=wrong + /é"
VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
CHALLENGE = base64.urlsafe_b64encode(hashlib.sha256(VERIFIER.encode()).digest()).rstrip(b"=").decode()


class OAuthHttpPreview(unittest.TestCase):
    def setUp(self):
        self.secret = secrets.token_hex(32)
        self.sensitive = [self.secret]
        self.proc = None
        self.addCleanup(self.cleanup_server)
        self.start_server()

    def start_server(self, directory=None):
        self.assertIsNone(self.proc)
        args = [str(BIN), "oauth-preview", "0", "0", ORIGIN]
        if directory is not None:
            args.append(str(directory))
        self.proc = subprocess.Popen(args,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        self.proc.stdin.write(json.dumps({"operator_token": self.secret, "local_fixture_client": LOCAL}))
        self.proc.stdin.close()
        import select
        self.assertTrue(select.select([self.proc.stdout], [], [], 5)[0], "preview did not start")
        line = self.proc.stdout.readline()
        m = re.fullmatch(r"OAUTH_PREVIEW 127\.0\.0\.1:(\d+) 127\.0\.0\.1:(\d+)\n", line)
        self.assertIsNotNone(m, line)
        self.public, self.admin = map(int, m.groups())
        self.assertNotEqual(self.public, self.admin)

    def cleanup_server(self):
        if self.proc is None:
            return
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=5)
        logs = self.proc.stderr.read() + self.proc.stdout.read()
        self.proc.stderr.close()
        self.proc.stdout.close()
        self.proc = None
        for secret in self.sensitive:
            self.assertNotIn(secret, logs, "credential leaked into process logs")

    def initialize_registry(self, directory):
        result = subprocess.run([str(BIN), "oauth-state-init", str(directory), ORIGIN],
                                capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)

    def refused_start(self, directory, origin=ORIGIN):
        result = subprocess.run([str(BIN), "oauth-preview", "0", "0", origin, str(directory)],
            input=json.dumps({"operator_token": self.secret, "local_fixture_client": LOCAL}),
            capture_output=True, text=True, timeout=5)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("OAUTH_PREVIEW", result.stdout)
        self.assertNotIn(self.secret, result.stderr)

    def request(self, method, path, body=None, *, admin=False, auth=None,
                headers=(), host=None, content=None):
        port = self.admin if admin else self.public
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        try:
            conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
            conn.putheader("Host", host or (f"127.0.0.1:{port}" if admin else HOST))
            if auth is not None:
                conn.putheader("Authorization", "Bearer " + auth)
            for key, value in headers:
                conn.putheader(key, value)
            if body is not None:
                if not isinstance(body, bytes):
                    body = json.dumps(body).encode()
                conn.putheader("Content-Type", content or "application/json")
                conn.putheader("Content-Length", str(len(body)))
            conn.endheaders(body)
            res = conn.getresponse()
            result = res.read()
            self.assertEqual(res.getheader("Cache-Control"), "no-store")
            self.assertEqual(res.getheader("Referrer-Policy"), "no-referrer")
            return res.status, {key.lower(): value for key, value in res.getheaders()}, result
        finally:
            conn.close()

    def form(self, path, **data):
        return self.request("POST", path, urllib.parse.urlencode(data).encode(),
                            content="application/x-www-form-urlencoded")

    def registration(self, callback=CALLBACK):
        return {"client_name": "Synthetic client", "redirect_uris": [callback],
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"], "scope": "mcp"}

    def register(self, callback=CALLBACK):
        status, _, body = self.request("POST", "/oauth/register", self.registration(callback))
        self.assertEqual(status, 201)
        return json.loads(body)["client_id"]

    def begin(self, client, **override):
        params = {"response_type": "code", "client_id": client, "redirect_uri": CALLBACK,
                  "resource": RESOURCE, "scope": "mcp", "code_challenge": CHALLENGE,
                  "code_challenge_method": "S256", "state": STATE}
        params.update(override)
        return self.request("GET", "/oauth/authorize?" + urllib.parse.urlencode(params))

    def pending(self, client):
        status, _, body = self.begin(client)
        self.assertEqual(status, 200)
        handle = re.search(rb'<code id="request">([a-f0-9]{64})</code>', body).group(1).decode()
        self.sensitive.append(handle)
        return handle

    def local(self, path, body, **kwargs):
        return self.request("POST", path, body, admin=True,
                            auth=kwargs.pop("auth", self.secret), **kwargs)

    def approve(self, handle):
        status, _, body = self.local("/inspect", {"request": handle})
        self.assertEqual(status, 200)
        details = json.loads(body)
        self.assertEqual(details["redirect_uri"], CALLBACK)
        self.assertEqual(details["local_fixture_client"], LOCAL)
        self.assertEqual(self.local("/approve", {"request": handle, "local_client": LOCAL})[0], 200)
        self.assertEqual(self.local("/approve", {"request": handle, "local_client": LOCAL})[0], 400)
        status, headers, _ = self.request("GET", "/oauth/authorize?request=" + handle)
        self.assertEqual(status, 303)
        callback = urllib.parse.urlsplit(headers["location"])
        self.assertEqual(callback.scheme + "://" + callback.netloc + callback.path, CALLBACK)
        query = urllib.parse.parse_qs(callback.query, strict_parsing=True)
        self.assertEqual(query["state"], [STATE])
        self.assertEqual(set(query), {"code", "state"})
        code = query["code"][0]
        self.sensitive.append(code)
        self.assertEqual(self.request("GET", "/oauth/authorize?request=" + handle)[0], 400)
        return code

    def exchange(self, client, code, **overrides):
        data = {"grant_type": "authorization_code", "client_id": client, "resource": RESOURCE,
                "code": code, "redirect_uri": CALLBACK, "code_verifier": VERIFIER}
        data.update(overrides)
        return self.form("/oauth/token", **data)

    def refresh(self, client, refresh, **overrides):
        data = {"grant_type": "refresh_token", "client_id": client, "resource": RESOURCE,
                "refresh_token": refresh}
        data.update(overrides)
        return self.form("/oauth/token", **data)

    def capture_tokens(self, response):
        self.assertEqual(response[0], 200)
        tokens = json.loads(response[2])
        self.assertEqual(tokens["token_type"], "Bearer")
        self.assertEqual(tokens["scope"], "mcp")
        self.assertGreater(tokens["expires_in"], 0)
        self.sensitive.extend([tokens["access_token"], tokens["refresh_token"]])
        return tokens

    def mcp(self, token=None, **kwargs):
        return self.request("POST", "/mcp", {}, auth=token, **kwargs)

    def test_discovery_and_boundary(self):
        status, headers, body = self.mcp()
        self.assertEqual(status, 401)
        self.assertIn(ORIGIN + "/.well-known/oauth-protected-resource/mcp", headers["www-authenticate"])
        status, _, body = self.request("GET", "/.well-known/oauth-protected-resource/mcp")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["resource"], RESOURCE)
        status, _, body = self.request("GET", "/.well-known/oauth-authorization-server")
        self.assertEqual(status, 200)
        metadata = json.loads(body)
        self.assertEqual(metadata["issuer"], ORIGIN)
        self.assertEqual(metadata["code_challenge_methods_supported"], ["S256"])
        for path in ("/dashboard", "/oauth/approve", "/approve", "/revoke",
                     "/mcp/secret", "/oauth%2ftoken", "/.well-known/other"):
            self.assertEqual(self.request("GET", path)[0], 404, path)
        self.assertEqual(self.request("GET", "/.well-known/oauth-authorization-server", host="evil.example")[0], 403)
        self.assertEqual(self.request("GET", "/.well-known/oauth-authorization-server", headers=[("Host", HOST)])[0], 403)
        self.assertEqual(self.request("GET", "/.well-known/oauth-authorization-server", headers=[("Origin", "https://evil.example")])[0], 403)
        self.assertEqual(self.request("GET", "/.well-known/oauth-authorization-server", headers=[("Tailscale-Funnel-Request", "?1")])[0], 403)
        self.assertEqual(self.mcp(self.secret)[0], 401)
        self.assertEqual(self.local("/inspect", {"request": "a"*64}, auth=None)[0], 401)
        self.assertEqual(self.local("/inspect", {"request": "a"*64}, headers=[("Authorization", "Bearer " + self.secret)])[0], 401)

    def test_registration_consent_pkce_refresh_and_replay(self):
        client = self.register()
        other = self.register()
        for override in ({"redirect_uri": CALLBACK+"/evil"}, {"resource": "https://other.example/mcp"},
                         {"code_challenge_method": "plain"}, {"scope": "full"}, {"response_type": "token"}):
            self.assertEqual(self.begin(client, **override)[0], 400)
        handle = self.pending(client)
        self.assertEqual(self.exchange(client, handle)[0], 400)
        self.assertEqual(self.local("/approve", {"request": handle, "local_client": "other"})[0], 400)
        self.assertEqual(self.local("/approve", {"request": handle, "local_client": LOCAL},
                                    headers=[("Origin", ORIGIN)])[0], 403)
        self.assertEqual(self.request("POST", "/approve", {"request": handle, "local_client": LOCAL}, auth=self.secret)[0], 404)
        code = self.approve(handle)
        self.assertEqual(self.exchange(other, code)[0], 400)
        self.assertEqual(self.exchange(client, code, code_verifier="a"*43)[0], 400)
        self.assertEqual(self.exchange(client, code, redirect_uri=CALLBACK+"/evil")[0], 400)
        first = self.capture_tokens(self.exchange(client, code))
        self.assertEqual(self.mcp(first["access_token"])[0], 503)
        self.assertEqual(self.mcp(first["refresh_token"])[0], 401)
        self.assertEqual(self.mcp(first["access_token"], headers=[("Authorization", "Bearer " + first["access_token"])])[0], 401)
        self.assertEqual(self.refresh(other, first["refresh_token"])[0], 400)
        second = self.capture_tokens(self.refresh(client, first["refresh_token"]))
        self.assertEqual(self.mcp(first["access_token"])[0], 401)
        self.assertEqual(self.mcp(second["access_token"])[0], 503)
        self.assertEqual(self.refresh(client, first["refresh_token"])[0], 400)
        self.assertEqual(self.mcp(second["access_token"])[0], 401)
        self.assertEqual(self.refresh(client, second["refresh_token"])[0], 400)

    def test_revoke_and_deny(self):
        client = self.register()
        other = self.register()
        pending = self.pending(client)
        self.assertEqual(self.local("/deny", {"request": pending})[0], 200)
        self.assertEqual(self.local("/approve", {"request": pending, "local_client": LOCAL})[0], 400)
        status, headers, _ = self.request("GET", "/oauth/authorize?request="+pending)
        self.assertEqual(status, 303)
        denied = urllib.parse.urlsplit(headers["location"])
        self.assertEqual(denied.scheme + "://" + denied.netloc + denied.path, CALLBACK)
        self.assertEqual(urllib.parse.parse_qs(denied.query), {"error":["access_denied"],"state":[STATE]})
        self.assertEqual(self.request("GET", "/oauth/authorize?request="+pending)[0], 400)
        code = self.approve(self.pending(client))
        first = self.capture_tokens(self.exchange(client, code))
        second = self.capture_tokens(self.exchange(other, self.approve(self.pending(other))))
        pending = self.pending(client)
        self.assertEqual(self.local("/revoke", {"client_id": client})[0], 200)
        self.assertEqual(self.mcp(first["access_token"])[0], 401)
        self.assertEqual(self.refresh(client, first["refresh_token"])[0], 400)
        self.assertEqual(self.local("/approve", {"request": pending, "local_client": LOCAL})[0], 400)
        self.assertEqual(self.mcp(second["access_token"])[0], 503)
        self.assertEqual(self.exchange(other, self.approve(self.pending(other)))[0], 200)

    def test_strict_parsing_and_rate_limit(self):
        self.assertEqual(self.request("POST", "/oauth/register", b'{"client_name":"a","client_name":"b"}')[0], 400)
        self.assertEqual(self.request("POST", "/oauth/register", b'{"client_name":"a","client_\\u006eame":"b"}')[0], 400)
        self.assertEqual(self.request("POST", "/oauth/register", b"x"*16385)[0], 400)
        self.assertEqual(self.request("POST", "/oauth/register", self.registration(), headers=[("Content-Type", "application/json")])[0], 415)
        self.assertEqual(self.request("POST", "/oauth/register", self.registration(), auth=self.secret)[0], 400)
        for data in (b"client_id=a&client_id=b", b"x=%FF", b"x=%00", b"x=%", b"x=1&"):
            self.assertEqual(self.request("POST", "/oauth/token", data, content="application/x-www-form-urlencoded")[0], 400)
        client = self.register()
        handle = self.pending(client)
        self.assertEqual(self.request("GET", "/oauth/authorize?request="+handle+"&%72equest="+handle)[0], 400)
        # Exhaust only public capacity. Private operator still has its own budget.
        statuses = []
        for _ in range(65):
            status = self.request("GET", "/.well-known/oauth-authorization-server")[0]
            statuses.append(status)
            if status == 429:
                break
        self.assertIn(429, statuses)
        self.assertEqual(self.local("/inspect", {"request": handle})[0], 200)

    def test_durable_registration_restart_and_revocation(self):
        self.cleanup_server()
        with tempfile.TemporaryDirectory(prefix="veyl-oauth-") as raw:
            directory = pathlib.Path(raw)
            self.initialize_registry(directory)
            self.start_server(directory)
            try:
                self.refused_start(directory)  # Exclusive directory lock.
                client = self.register()
                other = self.register()
                tokens = self.capture_tokens(self.exchange(client, self.approve(self.pending(client))))
                snapshot = directory / "oauth-registry.json"
                self.assertEqual(snapshot.stat().st_mode & 0o777, 0o600)
                self.assertEqual({c["client_id"] for c in json.loads(snapshot.read_text())["clients"]},
                                 {client, other})
                for secret in self.sensitive:
                    self.assertNotIn(secret, snapshot.read_text())
                self.cleanup_server()
                self.start_server(directory)
                # Registration persists, but authentication does not silently
                # recover: fresh local approval is required after restart.
                self.assertEqual(self.mcp(tokens["access_token"])[0], 401)
                self.assertEqual(self.refresh(client, tokens["refresh_token"])[0], 400)
                self.assertEqual(self.local("/revoke", {"client_id": client})[0], 200)
                self.cleanup_server()
                self.start_server(directory)
                self.assertEqual(self.begin(client)[0], 400)
                fresh = self.capture_tokens(self.exchange(other, self.approve(self.pending(other))))
                self.assertEqual(self.mcp(fresh["access_token"])[0], 503)
                # Tampering detected on the next registry mutation; all
                # auth operations fail closed for the rest of this process.
                snapshot.write_text("{}")
                self.assertEqual(self.request("POST", "/oauth/register", self.registration())[0], 503)
                self.assertEqual(self.request("GET", "/.well-known/oauth-authorization-server")[0], 503)
                self.cleanup_server()
                self.refused_start(directory)
            finally:
                self.cleanup_server()

    def test_durable_registry_rejects_unsafe_state(self):
        self.cleanup_server()
        with tempfile.TemporaryDirectory(prefix="veyl-oauth-") as raw:
            directory = pathlib.Path(raw)
            self.initialize_registry(directory)
            snapshot = directory / "oauth-registry.json"
            self.refused_start(directory, "https://other.example:8443")
            snapshot.chmod(0o644)
            self.refused_start(directory)
            snapshot.chmod(0o600)
            alias = directory / "alias"
            os.link(snapshot, alias)
            self.refused_start(directory)
            alias.unlink()
            original = snapshot.read_bytes()
            snapshot.rename(alias)
            snapshot.symlink_to(alias)
            self.refused_start(directory)
            snapshot.unlink()
            alias.rename(snapshot)
            snapshot.write_bytes(original + b" ")
            self.refused_start(directory)
            snapshot.write_bytes(original)
            self.start_server(directory)
            try:
                self.assertEqual(self.request("GET", "/.well-known/oauth-authorization-server")[0], 200)
            finally:
                self.cleanup_server()


if __name__ == "__main__":
    unittest.main()
