#!/usr/bin/env python3
import io
import json
from pathlib import Path
import unittest
import zipfile
import chatgpt_plugin_package as plugin

ORIGIN = "https://fixture.tailtest.ts.net:10000"
ENDPOINT = ORIGIN + "/mcp"


def fixture(origin, path):
    assert origin == ORIGIN
    if path == "/mcp":
        return 401, f'Bearer resource_metadata="{origin}{plugin.RESOURCE_PATH}", scope="mcp"', b""
    if path == plugin.RESOURCE_PATH:
        value = {"resource": ENDPOINT, "authorization_servers": [origin],
                 "scopes_supported": ["mcp"], "bearer_methods_supported": ["header"]}
    elif path == plugin.AUTH_PATH:
        value = {"issuer": origin, "authorization_endpoint": origin + "/oauth/authorize",
                 "token_endpoint": origin + "/oauth/token", "registration_endpoint": origin + "/oauth/register",
                 "scopes_supported": ["mcp"], "response_types_supported": ["code"],
                 "grant_types_supported": ["authorization_code", "refresh_token"],
                 "token_endpoint_auth_methods_supported": ["none"],
                 "code_challenge_methods_supported": ["S256"]}
    else:
        raise AssertionError(path)
    return 200, "", json.dumps(value).encode()


class PluginPackageTests(unittest.TestCase):
    def test_verified_fixture_packages_exact_oauth_dcr(self):
        icon = (Path(__file__).resolve().parents[1] / "assets/veyl.svg").read_bytes()
        with zipfile.ZipFile(io.BytesIO(plugin.package(ENDPOINT, icon, fixture))) as z:
            self.assertIsNone(z.testzip())
            self.assertEqual(set(z.namelist()), {"plugin.json", "mcp.json", "assets/veyl.svg",
                                                 "skills/veyl-workspace/SKILL.md"})
            manifest = json.loads(z.read("plugin.json"))
            self.assertEqual(manifest["name"], "veyl-private-preview")
            ui = manifest["extensions"]["com.openai"]["interface"]
            self.assertLessEqual(len(ui["shortDescription"]), 30)
            self.assertEqual(z.read("assets/veyl.svg"), icon)
            server = json.loads(z.read("mcp.json"))["mcpServers"]["veyl"]
            self.assertEqual(server["url"], ENDPOINT)
            self.assertEqual(server["type"], "streamable-http")
            self.assertEqual(server["extensions"]["com.openai"]["auth"]["client"], {"mode": "dcr"})
            self.assertNotIn("headers", server)
            self.assertNotIn("clientSecret", json.dumps(server))

    def test_rejects_unverified_or_legacy_urls(self):
        for endpoint in ("http://fixture.tailtest.ts.net:10000/mcp", ORIGIN + "/secret/mcp",
                         ENDPOINT + "?token=x", ENDPOINT + "#fragment", "https://127.0.0.1:10000/mcp",
                         "https://user:pass@fixture.tailtest.ts.net:10000/mcp",
                         "https://fixture.tailtest.ts.net:443/mcp", "https://veyl.example/mcp"):
            with self.subTest(endpoint=endpoint):
                with self.assertRaises(ValueError):
                    plugin.package(endpoint, b"", lambda *_: self.fail("must not fetch"))

    def test_missing_challenge_redirect_duplicate_and_wrong_issuer_denied(self):
        with self.assertRaises(ValueError):
            plugin.package(ENDPOINT, b"", lambda *_: (200, "", b"{}"))
        with self.assertRaises(ValueError):
            plugin.package(ENDPOINT, b"", lambda *_: (302, "", b""))
        for wrong in (b'{"issuer":"other","issuer":"other"}', b'{"issuer":"https://other.example"}'):
            def fetch(origin, path):
                return (200, "", wrong) if path == plugin.AUTH_PATH else fixture(origin, path)
            with self.assertRaises(ValueError):
                plugin.package(ENDPOINT, b"", fetch)


if __name__ == "__main__":
    unittest.main()
