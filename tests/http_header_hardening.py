#!/usr/bin/env python3
"""Raw HTTP regression tests for ambiguous singleton headers on the Linux gateway."""
import http.client
import json
import socket
import unittest

import product_features as pf

INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-11-25", "capabilities": {},
                   "clientInfo": {"name": "header-test", "version": "1"}}}


class HeaderHardening(unittest.TestCase):
    def setUp(self):
        self.fixture = pf.ProductFeatures()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.start()

    def request(self, headers, message=INIT):
        body = json.dumps(message).encode()
        port = self.fixture.mcp
        lines = [b"POST /mcp HTTP/1.1", f"Host: 127.0.0.1:{port}".encode(),
                 *[f"{k}: {v}".encode() for k, v in headers],
                 f"Content-Length: {len(body)}".encode(), b"Connection: close", b"", b""]
        with socket.create_connection(("127.0.0.1", port), timeout=5) as conn:
            conn.sendall(b"\r\n".join(lines) + body)
            response = http.client.HTTPResponse(conn)
            response.begin()
            try:
                return response.status, response.headers, response.read()
            finally:
                response.close()

    def test_duplicate_authorization_rejected_in_both_orders(self):
        primary = "Bearer " + pf.TOKEN
        secondary = "Bearer " + pf.OTHER_TOKEN
        for first, second in [(primary, secondary), (secondary, primary), (primary, primary)]:
            with self.subTest(order=(first == primary, second == primary)):
                status, headers, _ = self.request([
                    ("Authorization", first), ("authorization", second),
                    ("Content-Type", "application/json")])
                self.assertEqual(status, 401)
                self.assertIsNone(headers.get("Mcp-Session-Id"))
        status, headers, _ = self.request([
            ("Authorization", primary), ("Content-Type", "application/json")])
        self.assertEqual(status, 200)
        self.assertEqual(len(headers["Mcp-Session-Id"]), 48)

    def test_duplicate_session_version_and_content_type_rejected(self):
        auth = [("Authorization", "Bearer " + pf.TOKEN)]
        valid = auth + [("Content-Type", "application/json")]
        status, headers, _ = self.request(valid)
        self.assertEqual(status, 200)
        session = headers["Mcp-Session-Id"]
        initialized = {"jsonrpc": "2.0", "method": "notifications/initialized"}
        self.assertEqual(self.request(valid + [
            ("Mcp-Session-Id", session), ("mcp-session-id", session)], initialized)[0], 400)
        self.assertEqual(self.request(valid + [
            ("Mcp-Protocol-Version", "2025-11-25"),
            ("mcp-protocol-version", "2025-11-25")])[0], 400)
        self.assertEqual(self.request(valid + [
            ("content-type", "application/json")])[0], 415)
        # A rejected duplicate must not advance the live session phase.
        self.assertEqual(self.request(valid + [
            ("Mcp-Session-Id", session)], initialized)[0], 202)
        status, _, body = self.request(valid + [("Mcp-Session-Id", session)],
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        self.assertEqual(status, 200)
        self.assertIn("tools", json.loads(body)["result"])


if __name__ == "__main__":
    unittest.main()
