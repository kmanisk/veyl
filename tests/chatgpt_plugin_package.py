#!/usr/bin/env python3
"""Build a private ChatGPT Plugin Creator archive from a verified Veyl endpoint."""
import argparse
import http.client
import io
import json
import os
from pathlib import Path
import re
import ssl
import sys
from urllib.parse import urlsplit
import zipfile

LIMIT = 65536
HOST = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\.ts\.net\Z")
RESOURCE_PATH = "/.well-known/oauth-protected-resource/mcp"
AUTH_PATH = "/.well-known/oauth-authorization-server"


def exact_origin(endpoint):
    uri = urlsplit(endpoint)
    if (uri.scheme != "https" or uri.path != "/mcp" or uri.query or uri.fragment
            or uri.username is not None or uri.password is not None
            or not uri.hostname or not HOST.fullmatch(uri.hostname)
            or uri.port not in (8443, 10000)
            or endpoint != f"https://{uri.hostname}:{uri.port}/mcp"):
        raise ValueError("Expected exact dedicated Veyl Funnel HTTPS /mcp endpoint")
    return endpoint[:-4]


def unique_object(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("Duplicate metadata key")
        out[key] = value
    return out


def https_get(origin, path):
    """Verify TLS using the default trust store; no redirects or proxy credentials."""
    uri = urlsplit(origin)
    conn = http.client.HTTPSConnection(
        uri.hostname, uri.port, timeout=8, context=ssl.create_default_context()
    )
    try:
        conn.request("GET", path, headers={"Accept": "application/json"})
        response = conn.getresponse()
        body = response.read(LIMIT + 1)
        if len(body) > LIMIT:
            raise ValueError("Discovery response exceeds limit")
        return response.status, response.getheader("WWW-Authenticate", ""), body
    finally:
        conn.close()


def verify_discovery(endpoint, fetch=https_get):
    origin = exact_origin(endpoint)
    status, challenge, _ = fetch(origin, "/mcp")
    expected = f'Bearer resource_metadata="{origin}{RESOURCE_PATH}", scope="mcp"'
    if status != 401 or challenge != expected:
        raise ValueError("MCP endpoint did not require the expected OAuth authorization")
    def document(path):
        status, _, raw = fetch(origin, path)
        if status != 200 or len(raw) > LIMIT:
            raise ValueError("OAuth discovery unavailable")
        value = json.loads(raw, object_pairs_hook=unique_object)
        if not isinstance(value, dict):
            raise ValueError("OAuth metadata must be an object")
        return value
    protected = document(RESOURCE_PATH)
    authorization = document(AUTH_PATH)
    required_resource = {
        "resource": endpoint, "authorization_servers": [origin],
        "scopes_supported": ["mcp"], "bearer_methods_supported": ["header"],
    }
    required_authorization = {
        "issuer": origin, "authorization_endpoint": origin + "/oauth/authorize",
        "token_endpoint": origin + "/oauth/token",
        "registration_endpoint": origin + "/oauth/register",
        "scopes_supported": ["mcp"], "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["none"],
        "code_challenge_methods_supported": ["S256"],
    }
    for actual, required in ((protected, required_resource), (authorization, required_authorization)):
        if any(actual.get(k) != v for k, v in required.items()):
            raise ValueError("Discovery does not match the Veyl OAuth contract")
    return origin


def package(endpoint, icon, fetch=https_get):
    # No archive is generated from an unverified URL.
    verify_discovery(endpoint, fetch)
    manifest = {
        "$schema": "https://agent-plugins.org/schemas/1.0.0/plugin.schema.json",
        "name": "veyl-private-preview", "version": "0.1.0",
        "description": "Connect to your own Veyl gateway using explicit local OAuth approval.",
        "author": {"name": "Veyl"},
        "extensions": {"com.openai": {"interface": {
            "displayName": "Veyl Private Preview",
            "shortDescription": "Your local Veyl gateway",
            "longDescription": "Use approved workspace tools through your self-hosted Veyl gateway. The local operator determines permissions. This private preview does not deploy the gateway or enable additional grants.",
            "developerName": "Veyl", "category": "Productivity",
            "capabilities": ["Interactive"],
            "logo": "./assets/veyl.svg", "composerIcon": "./assets/veyl.svg",
            "defaultPrompt": "Inspect my available Veyl tools and approved workspace."
        }}},
    }
    config = {
        "$schema": "https://agent-plugins.org/schemas/1.0.0/mcp.schema.json",
        "mcpServers": {"veyl": {"type": "streamable-http", "url": endpoint,
            "extensions": {"com.openai": {"auth": {
                "type": "oauth", "client": {"mode": "dcr"},
                "baseScopes": ["mcp"], "defaultScopes": ["mcp"],
            }}}}},
    }
    skill = """---
name: veyl-workspace
description: Use when working in a workspace explicitly authorized by the local Veyl operator.
---
Use only the tools discovered from the connected Veyl server and their actual schemas.
Respect the workspace and capability grants returned by the gateway. Never try to bypass
denied access, broaden a grant, reuse another client's receipt, or extract credentials.
If local approval is pending, direct the user to their local paired Veyl dashboard.
Inspect existing state before retrying a timed-out mutation or command. Use bounded jobs
for longer operations and preserve running processes. Ask for explicit user approval
before destructive changes or production deployment. Distinguish actual tool results from
suggested commands; never claim a host action succeeded without verification.
"""
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, value in (("plugin.json", manifest), ("mcp.json", config)):
            archive.writestr(name, json.dumps(value, indent=2) + "\n")
        archive.writestr("skills/veyl-workspace/SKILL.md", skill)
        archive.writestr("assets/veyl.svg", icon)
    return out.getvalue()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("endpoint", help="Actual HTTPS URL printed by the approved Veyl preview")
    parser.add_argument("output", type=Path, help="New private ZIP file (not overwritten)")
    args = parser.parse_args()
    if args.output.exists() or args.output.is_symlink():
        parser.error("Output already exists")
    try:
        icon = (Path(__file__).resolve().parents[1] / "assets/veyl.svg").read_bytes()
        data = package(args.endpoint, icon)
        fd = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except (OSError, ValueError, http.client.HTTPException) as error:
        print(f"Plugin packaging failed: {type(error).__name__}", file=sys.stderr)
        return 1
    print("Private plugin ZIP created; OAuth client interoperability still requires actual connection.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
