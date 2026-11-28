#!/usr/bin/env python3
"""Discover and call the installed upstreams through a disposable unified runtime."""
import json
import os
from pathlib import Path
import plistlib
import re
import py_compile
import shutil
import subprocess
import threading
import time
import unittest
import urllib.parse
import zipfile

from unified_lifecycle_e2e import UnifiedLifecycleSuite, free_port, funnel, pkce_s256

REA = ("inspect_rust_binary", "inspect_keyed_archive", "inspect_python_pyc", "inspect_nuget_nupkg", "open_bundle_resources")
RA = ("analyze", "diff", "profile", "report")
BUNDLES = Path(os.environ["VEYL_UPSTREAM_BUNDLES"]).resolve()


def prepare_native_port(bundle, home):
    """Generate and record a real port, then bind its Rust function through N-API."""
    source = bundle / "demo-source"
    crate = bundle / "demo-port"
    source.mkdir(mode=0o700)
    (source / "canary.ts").write_text("export function addOne(n: number): number { return n + 1; }\n")
    compiler = bundle / "bin/rust-anything"
    for args in (["bridge", source, "canary.ts", "--kind", "napi", "--out", crate],
                 ["record", crate, "--count", "6"]):
        subprocess.run([compiler, *args], env={"PATH":"/usr/bin:/bin", "HOME":str(home)},
                       check=True, timeout=15, capture_output=True)
    rust = home / "port.rs"
    c = home / "port.c"
    rust.write_text("#[no_mangle] pub extern \"C\" fn add_one(x: f64) -> f64 { x + 1.0 }\n")
    c.write_text(r"""
#include <node/node_api.h>
extern double add_one(double);
static napi_value port(napi_env env, napi_callback_info cb) {
    napi_value args[1], result;
    size_t count = 1;
    double number;
    if (napi_get_cb_info(env, cb, &count, args, 0, 0) != napi_ok ||
        count != 1 || napi_get_value_double(env, args[0], &number) != napi_ok ||
        napi_create_double(env, add_one(number), &result) != napi_ok) {
        napi_throw_type_error(env, 0, "expected one number");
        return 0;
    }
    return result;
}
NAPI_MODULE_INIT() {
    napi_value fn;
    if (napi_create_function(env, "addOne", 6, port, 0, &fn) != napi_ok ||
        napi_set_named_property(env, exports, "addOne", fn) != napi_ok)
        return 0;
    return exports;
}
""")
    subprocess.run(["rustc", "--edition=2021", "--crate-type=cdylib", rust, "-o", crate / "libcanary.so"],
                   check=True, timeout=20, capture_output=True)
    subprocess.run(["cc", "-shared", "-fPIC", c, "-L" + str(crate), "-lcanary", "-Wl,-rpath,$ORIGIN",
                    "-o", crate / "canary_rs.node"], check=True, timeout=20, capture_output=True)
    (crate / "index.cjs").write_text("module.exports = require('./canary_rs.node');\n")
    # report rebuilds the addon. Use a self-contained real Rust port so the
    # sandbox performs no dependency fetch. This probe runs under the guard.
    (crate / "Cargo.toml").write_text("""[package]
name = "canary-rs"
version = "0.1.0"
edition = "2021"
publish = false
[lib]
crate-type = ["cdylib"]
""")
    (crate / "build.rs").write_text(r"""
use std::path::PathBuf;
use std::process::Command;
fn main() {
    let object = PathBuf::from(std::env::var_os("OUT_DIR").unwrap()).join("adapter.o");
    let status = Command::new("/usr/bin/cc").args(["-fPIC", "-c", "adapter.c", "-o"])
        .arg(&object).status().unwrap();
    assert!(status.success());
    println!("cargo:rustc-link-arg={}", object.display());
}
""")
    declarations = r"""
typedef __SIZE_TYPE__ size_t;
typedef struct napi_env__ *napi_env;
typedef struct napi_callback_info__ *napi_callback_info;
typedef struct napi_value__ *napi_value;
typedef int napi_status;
typedef napi_value (*napi_callback)(napi_env, napi_callback_info);
enum { napi_ok = 0 };
extern napi_status napi_get_cb_info(napi_env, napi_callback_info, size_t *, napi_value *, napi_value *, void **);
extern napi_status napi_get_value_double(napi_env, napi_value, double *);
extern napi_status napi_create_double(napi_env, double, napi_value *);
extern napi_status napi_throw_type_error(napi_env, const char *, const char *);
extern napi_status napi_create_function(napi_env, const char *, size_t, napi_callback, void *, napi_value *);
extern napi_status napi_set_named_property(napi_env, napi_value, const char *, napi_value);
"""
    script = c.read_text().replace("#include <node/node_api.h>", declarations)
    script = script.replace("NAPI_MODULE_INIT() {", "napi_value setup_port(napi_env env, napi_value exports) {")
    (crate / "adapter.c").write_text(script)
    (crate / "src/lib.rs").write_text(r"""
use std::ffi::c_void;
extern "C" {
    fn setup_port(env: *mut c_void, exports: *mut c_void) -> *mut c_void;
}
#[no_mangle]
pub extern "C" fn add_one(x: f64) -> f64 { x + 1.0 }
#[no_mangle]
pub extern "C" fn napi_register_module_v1(env: *mut c_void, exports: *mut c_void) -> *mut c_void {
    unsafe { setup_port(env, exports) }
}
""")
    config = crate / "rust-anything.json"
    doc = json.loads(config.read_text())
    doc["root"] = "/upstream/bundle/demo-source"
    config.write_text(json.dumps(doc))
    for path in [crate, *crate.rglob("*"), *source.rglob("*")]:
        path.chmod(0o700 if path.is_dir() else 0o600)


class InstalledUpstreams(UnifiedLifecycleSuite):
    def oauth_client(self, addr, admin, config):
        authority = funnel.AUTHORITY
        resource = "https://" + authority + "/mcp"
        redirect = "https://client.example/cb"
        verifier = "o" * 43
        status, _, body = self.proxy_request(addr, authority, "POST", "/oauth/register", json.dumps({
            "client_name":"Installed provider OAuth",
            "redirect_uris":[redirect], "token_endpoint_auth_method":"none",
            "grant_types":["authorization_code","refresh_token"], "response_types":["code"], "scope":"mcp"
        }), {"Content-Type":"application/json"})
        self.assertEqual(status, 201, body)
        registration = json.loads(body)["client_id"]
        query = urllib.parse.urlencode({"client_id":registration,"redirect_uri":redirect,
            "resource":resource,"scope":"mcp","code_challenge":pkce_s256(verifier),
            "code_challenge_method":"S256","response_type":"code"})
        status, _, body = self.proxy_request(addr, authority, "GET", "/oauth/authorize?" + query)
        self.assertEqual(status, 200, body)
        handle = re.search(r'id="request">([^<]+)<',body.decode()).group(1)
        cookie, csrf = self.pair_dashboard(admin, config)
        status, consent = self.dashboard_oauth(admin, cookie, csrf, {"action":"inspect","request":handle})
        self.assertEqual(status, 200, consent)
        self.assertEqual(consent["mode"],"standard")
        status, body = self.dashboard_oauth(admin, cookie, csrf, {
            "action":"approve","request":handle,"confirm":True,"client_id":registration,"redirect_uri":redirect,
            "resource":resource,"local_client":consent["local_client"],"mode":"standard","scope_fingerprint":consent["scope_fingerprint"]
        })
        self.assertEqual(status, 200, body)
        status, headers, body = self.proxy_request(addr, authority, "GET", "/oauth/authorize?request=" + handle)
        self.assertEqual(status, 303, body)
        code = urllib.parse.parse_qs(urllib.parse.urlparse(next(value for key, value in headers.items() if key.lower() == "location")).query)["code"][0]
        status, _, body = self.proxy_request(addr, authority, "POST", "/oauth/token", urllib.parse.urlencode({
            "grant_type":"authorization_code","code":code,"redirect_uri":redirect,
            "client_id":registration,"code_verifier":verifier,"resource":resource
        }), {"Content-Type":"application/x-www-form-urlencoded"})
        self.assertEqual(status, 200)
        token = json.loads(body)["access_token"]
        status, session, body = self.rpc(addr, authority, token, "initialize", {
            "protocolVersion":"2025-11-25","capabilities":{},
            "clientInfo":{"name":"oauth-provider-fixture","version":"1"}
        })
        self.assertEqual(status, 200, body)
        self.assertIsNotNone(session)
        self.assertEqual(self.rpc(addr, authority, token, "notifications/initialized", {}, session)[0], 202)
        return lambda method, params=None: self.rpc(addr, authority, token, method, params, session)

    def test_installed_bundles(self):
        self.run_cli("init", "--root", str(self.workspace))
        root = self.home / ".local/state/veyl"
        cfg = root / "clients.json"
        doc = json.loads(cfg.read_text())
        doc.update(admin_listen="127.0.0.1:0", default_mode="standard", workspace=str(self.workspace))
        bundles = root / "upstream-bundles"
        bundles.mkdir(mode=0o700)
        for name in ("rea", "rust-anything"):
            subprocess.run(["cp", "-a", "--reflink=auto", BUNDLES / name, bundles / name], check=True, timeout=25)
        artifact = bundles / "rea" / "fixture"
        artifact.mkdir(mode=0o700)
        for name in ("demo.py", "archive.plist", "synthetic-elf"):
            (artifact / name).touch(mode=0o600)
        (artifact / "demo.py").write_text("def veyl_upstream_canary(n):\n    return n + 2\n")
        py_compile.compile(str(artifact / "demo.py"), cfile=str(artifact / "demo.pyc"), dfile="demo.py", doraise=True)
        (artifact / "demo.pyc").chmod(0o600)
        shutil.copyfile("/usr/bin/true", artifact / "synthetic-elf")
        (artifact / "archive.plist").write_bytes(plistlib.dumps({
            "$archiver":"NSKeyedArchiver", "$version":100000,
            "$objects":["$null","veyl-keyed-archive-canary"], "$top":{"root":plistlib.UID(1)}
        }, fmt=plistlib.FMT_BINARY))
        app = artifact / "Fixture.app"
        resources = app / "Contents/Resources"
        resources.mkdir(parents=True, mode=0o700)
        app.chmod(0o700)
        (app / "Contents").chmod(0o700)
        info = app / "Contents/Info.plist"
        info.write_bytes(plistlib.dumps({
            "CFBundleIdentifier":"org.veyl.fixture", "CFBundleName":"Fixture", "CFBundlePackageType":"APPL"
        }))
        info.chmod(0o600)
        shutil.copyfile(artifact / "archive.plist", resources / "archive.plist")
        (resources / "archive.plist").chmod(0o600)
        with zipfile.ZipFile(artifact / "fixture.nupkg", "w") as archive:
            archive.writestr("veyl-canary.nuspec", '<package><metadata><id>veyl-canary</id><version>1.2.3</version><description>Fixture</description></metadata></package>')
            archive.writestr("lib/net8.0/readme.txt", "disposable archive fixture")
        (artifact / "fixture.nupkg").chmod(0o600)
        project = bundles / "rust-anything" / "fixture"
        project.mkdir(mode=0o700)
        (project / "workload.py").write_text("""import sys
import time

def workload(n):
    return sum(i*i for i in range(n))

if __name__ == '__main__':
    if '--wait' in sys.argv:
        time.sleep(30)
    print(workload(10000))
""")
        (project / "workload.py").chmod(0o600)
        prepare_native_port(bundles / "rust-anything", self.home)
        doc["mcp_servers"] = {
            "rea":{"transport":"stdio","command":"/usr/bin/env","args":["REA_MCP_TOOL_FAMILIES=artifact,session",
               "/usr/bin/node","/upstream/bundle/scripts/rea.mjs","mcp"],"enabled":True,"runtime_bundle":True},
            "rust-anything":{"transport":"stdio","command":str(bundles / "rust-anything/bin/rust-anything"),
               "args":["mcp"],"enabled":True,"runtime_bundle":True},
        }
        doc["clients"][0]["tools"].extend(["mcp_servers_list", "mcp_servers_call"])
        doc["clients"][0].update(allowed_servers=["rea","rust-anything"],
                                 allowed_server_tools={"rea":list(REA),"rust-anything":list(RA)})
        doc["oauth"] = {"enabled":True, "state_dir":str(root / "oauth"), "local_client":"veyl-oauth",
                        "workspace_upstreams":True, "allowed_server_tools":{"rea":["inspect_python_pyc","inspect_keyed_archive"],
                            "rust-anything":["analyze"]}}
        cfg.write_text(json.dumps(doc))
        bearer = (root / "dev.bearer").read_text().strip()
        process, addr, _, _ = self.start_bg("serve", "--local", "--listen", f"127.0.0.1:{free_port()}")
        def rpc(method, params=None, session=None):
            return self.rpc(addr, addr, bearer, method, params, session, via_tunnel=False, timeout=36)

        def connect():
            status, session, body = rpc("initialize", {"protocolVersion":"2025-11-25","capabilities":{},
                "clientInfo":{"name":"installed-provider-fixture","version":"1"}})
            self.assertEqual(status, 200, body)
            self.assertIsNotNone(session)
            self.assertEqual(rpc("notifications/initialized", session=session)[0], 202)
            return session

        for provider in ("rea", "rust-anything"):
            probe = self.run_cli("mcp-servers", "probe", provider, "--config", str(cfg))
            print("PROBE", provider, probe.stdout)
        session = connect()
        status, _, body = rpc("tools/list", session=session)
        self.assertEqual(status, 200, body)
        schemas = {tool["name"]:tool.get("inputSchema") for tool in body["result"]["tools"] if "__" in tool["name"]}
        self.assertEqual(set(schemas), {f"rea__{name}" for name in REA} | {f"rust-anything__{name}" for name in RA})
        self.assertIn("path", schemas["rea__inspect_keyed_archive"]["properties"])
        self.assertIn("bundle_path", schemas["rea__inspect_keyed_archive"]["properties"])
        self.assertIn("command", schemas["rust-anything__profile"]["properties"])
        print("EXACT_DISCOVERY", sorted(schemas))

        def call(name, args, success=True):
            status, _, body = rpc("tools/call", {"name":name,"arguments":args}, session)
            self.assertEqual(status, 200, body)
            result = body["result"]
            if success:
                self.assertFalse(result.get("isError"), result)
            print("CALL", name, json.dumps(result)[:800])
            return result

        def artifact_call(name, file, **args):
            return call("rea__" + name, {"path":"/upstream/bundle/fixture/" + file, **args})

        self.assertIn("veyl_upstream_canary", json.dumps(artifact_call("inspect_python_pyc", "demo.pyc", detail="complete")))
        with self.subTest(provider="REA keyed archive"):
            archive = call("rea__inspect_keyed_archive", {"path":"/upstream/bundle/fixture/archive.plist"}, success=False)
            self.assertIn("target_unavailable", json.dumps(archive))
            selection = {"bundle_path":"/upstream/bundle/fixture/Fixture.app",
                         "path":"Contents/Resources/archive.plist"}
            result = call("rea__inspect_keyed_archive", selection)
            graph = result["structuredContent"]["normalized_result"]
            self.assertEqual(graph["total_objects"], 2)
            self.assertEqual(graph["objects"][1]["value"], "veyl-keyed-archive-canary")
            self.assertEqual(graph["references"][0]["target"], 1)
            print("REA_KEYED_ARCHIVE_SESSION_PASS")
            for malformed in ({**selection, "bundle_path":"/upstream/bundle/../etc"},
                              {**selection, "path":"../../etc/passwd"}):
                denied = call("rea__inspect_keyed_archive", malformed, success=False)
                self.assertTrue(denied.get("isError"), denied)
                self.assertIn("safe bundle-relative paths", json.dumps(denied))
            # The selected resource must not carry over to another request.
            fresh = call("rea__inspect_keyed_archive", {"path":"Contents/Resources/archive.plist"}, success=False)
            self.assertIn("target_unavailable", json.dumps(fresh))
        with self.subTest(provider="REA NuGet artifact"):
            archive = artifact_call("inspect_nuget_nupkg", "fixture.nupkg")
            self.assertIn("veyl-canary", json.dumps(archive))
        with self.subTest(provider="REA ELF"):
            elf = artifact_call("inspect_rust_binary", "synthetic-elf", detail="summary")
            self.assertIn("ELF", json.dumps(elf).upper())
        args = {"root":"/upstream/bundle/fixture","lang":"python"}
        with self.subTest(provider="Rust Anything analyze"):
            self.assertIn("workload", json.dumps(call("rust-anything__analyze", args)))
        with self.subTest(provider="Rust Anything profile"):
            profile = call("rust-anything__profile", {**args, "command":["/usr/bin/python3","workload.py"]})
            self.assertIn("workload", json.dumps(profile))
        with self.subTest(provider="Rust Anything cancel"):
            marker = f"veyl-installed-cancel-{self.home.name}"

            def workers():
                matches = []
                for path in Path("/proc").glob("[0-9]*/cmdline"):
                    try:
                        command = path.read_bytes().split(b"\0")
                    except OSError:
                        continue
                    if marker.encode() in command and any(a.endswith(b"workload.py") for a in command):
                        matches.append(path.parent.name)
                return matches

            result = []
            caller = threading.Thread(target=lambda: result.append(call("rust-anything__profile", {
                **args, "command":["/usr/bin/python3","workload.py","--wait", marker]
            }, success=False)))
            caller.start()
            try:
                deadline = time.monotonic() + 2
                while not workers() and time.monotonic() < deadline:
                    time.sleep(0.02)
                self.assertTrue(workers(), "Rust Anything did not start the disposable profiler workload")
                self.assertEqual(rpc("notifications/cancelled", {"requestId":1}, session)[0], 202)
                caller.join(timeout=1)
                self.assertFalse(caller.is_alive(), "upstream cancellation did not wake the worker")
                self.assertIn("cancelled", result[0]["content"][0]["text"])
            finally:
                caller.join(timeout=8)
            deadline = time.monotonic() + .8
            while workers() and time.monotonic() < deadline:
                time.sleep(0.02)
            self.assertEqual(workers(), [])
            print("RUST_PROFILE_CANCEL_AND_CLEANUP_PASS")
        crate = "/upstream/bundle/demo-port"
        with self.subTest(provider="Rust Anything diff"):
            diff = call("rust-anything__diff", {"crate":crate})
            match = diff["structuredContent"]
            self.assertGreater(match["total"], 0)
            self.assertEqual(match["passed"], match["total"])
            self.assertEqual(match["failed"], 0)
            print("RUST_DIFF", match["passed"], "cases passed")
            self.assertFalse((bundles / "rust-anything/demo-port/diff.json").exists())
            failed = call("rust-anything__diff", {"crate":"/upstream/bundle/fixture"}, success=False)
            self.assertTrue(failed.get("isError"), failed)
            self.assertIn("cases.jsonl", failed["structuredContent"]["message"])
        with self.subTest(provider="Rust Anything report"):
            report = call("rust-anything__report", {"crate":crate,"out":"/tmp/veyl-report","min_ms":5})
            self.assertIn("canary-rs", json.dumps(report))
            self.assertIn("REPORT.md", json.dumps(report))
            print("RUST_REPORT_PASS")
            failed = call("rust-anything__report", {"crate":"/upstream/bundle/fixture"}, success=False)
            self.assertTrue(failed.get("isError"), failed)
            self.assertIn("rust-anything.json", failed["structuredContent"]["message"])
        self.assertTrue(call("rea__inspect_model_artifact", {"path":"/upstream/bundle/fixture/demo.pyc"}, success=False)["isError"])
        self.run_cli("mode", "yolo", "dev", "--yes")
        self.assertIn("workload", json.dumps(call("rust-anything__analyze", args)))
        self.run_cli("mode", "standard", "dev")
        self.assertIn("workload", json.dumps(call("rust-anything__analyze", args)))
        self.run_cli("down")
        process.wait(timeout=8)
        _, socket = self.start_fake_tailscale()
        process, addr, admin, _ = self.start_bg("up", "--root", str(self.workspace), "--tailscale",
            "--funnel-socket", str(socket), "--listen", f"127.0.0.1:{free_port()}", "--no-ui")
        oauth = self.oauth_client(addr, admin, cfg)
        status, _, inventory = oauth("tools/list")
        self.assertEqual(status, 200, inventory)
        names = {tool["name"] for tool in inventory["result"]["tools"] if "__" in tool["name"]}
        self.assertEqual(names, {"rea__inspect_python_pyc", "rea__inspect_keyed_archive", "rust-anything__analyze"})
        archive_schema = next(t["inputSchema"] for t in inventory["result"]["tools"] if t["name"] == "rea__inspect_keyed_archive")
        self.assertNotIn("bundle_path", archive_schema["properties"])
        _, _, denied = oauth("tools/call", {"name":"rea__inspect_keyed_archive","arguments":selection})
        self.assertTrue(denied["result"]["isError"], denied)
        self.assertIn("both tool grants", json.dumps(denied))
        for tool, arguments, canary in [
            ("rea__inspect_python_pyc", {"path":"/upstream/bundle/fixture/demo.pyc"}, "veyl_upstream_canary"),
            ("rust-anything__analyze", args, "workload"),
        ]:
            status, _, reply = oauth("tools/call", {"name":tool,"arguments":arguments})
            self.assertEqual(status, 200, reply)
            self.assertFalse(reply["result"].get("isError"), reply)
            self.assertIn(canary, json.dumps(reply))
            print("OAUTH_CALL", tool, "verified")
        _, _, reply = oauth("tools/call", {"name":"rust-anything__profile","arguments":args})
        self.assertTrue(reply["result"]["isError"], reply)
        print("OAUTH_EXACT_GRANTS_PASS")
        self.run_cli("down")
        process.wait(timeout=8)


if __name__ == "__main__":
    suite = unittest.TestSuite([InstalledUpstreams("test_installed_bundles")])
    raise SystemExit(not unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful())
