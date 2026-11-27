#!/usr/bin/env python3
"""The OAuth primitives must not accidentally expose unfinished HTTP routes."""
import unittest

import linux_features as linux


class DirectRemoteBoundary(unittest.TestCase):
    def exercise(self, shared):
        fixture = linux.LinuxFeatures()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        token, _ = fixture.prepare_public_client(shared=shared)
        fixture.start()
        f = fixture.f
        authority = linux.TAIL["hostname"]
        prefix = "/veyl" if shared else ""
        if not shared:
            authority += ":" + str(linux.TAIL["mcp_https_port"])
        headers = {"Host": authority, "Origin": "https://" + authority,
                   "Tailscale-Funnel-Request": "?1"}
        paths = [
            ("/.well-known/oauth-protected-resource", "GET"),
            ("/.well-known/oauth-protected-resource/mcp", "GET"),
            ("/.well-known/oauth-authorization-server", "GET"),
            ("/oauth/authorize?client_id=fixture", "GET"),
            ("/oauth/register", "POST"),
            ("/oauth/token", "POST"),
            ("/oauth/approve", "POST"),
            ("/oauth/revoke", "POST"),
            ("/dashboard", "GET"),
            ("/api/dashboard/pair", "POST"),
            ("/oauth%2ftoken", "POST"),
        ]
        for path, method in paths:
            with self.subTest(path=path, method=method, shared=shared):
                body = {} if method == "POST" else None
                self.assertEqual(f.request(f.mcp, method, prefix + path, body, **headers)[0], 404)
                admin_host = linux.TAIL["hostname"] + ":" + str(linux.TAIL["admin_https_port"])
                self.assertEqual(f.request(f.admin, method, path, body,
                    Host=admin_host, **{"Tailscale-Funnel-Request": "?1"})[0], 400)

        init = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                           "clientInfo": {"name": "direct-boundary", "version": "1"}}}
        self.assertEqual(f.request(f.mcp, "POST", prefix + "/mcp", init, **headers)[0], 404)
        status, response_headers, _ = f.request(f.mcp, "POST", prefix + "/mcp", init,
                                                 Authorization="Bearer " + token, **headers)
        self.assertEqual(status, 200)
        self.assertEqual(len(response_headers["Mcp-Session-Id"]), 48)

    def test_dedicated_funnel_unchanged(self):
        self.exercise(False)

    def test_shared_funnel_unchanged(self):
        self.exercise(True)


if __name__ == "__main__":
    unittest.main()
