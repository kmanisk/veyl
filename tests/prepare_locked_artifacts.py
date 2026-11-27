#!/usr/bin/env python3
"""Stage exact guarded Cargo outputs for independent locked acceptance.

No locked source, pins, or trusted harness are modified. The staging directory
has the historical target/debug and target/test-hooks/debug layout. The
locked Rust executables are compiled from pinned external sources under the
same guard lock as the library build, not linked to an older target artifact.
This candidate-side adapter is not itself independent acceptance.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

import guarded_cargo as guard

SOURCE = Path(__file__).resolve().parents[1]
LAB = Path.home() / ".local/share/veyl-development/rust-mcp-gateway-lab"
BINS = ("mcp-gateway", "veyl", "veyl-monitor", "veyl-connector")


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def pins():
    manifest = LAB / "harness/acceptance.py"
    pairs = re.findall(r'LAB_ROOT / "([^"]+)",\s*"([0-9a-f]{64})"', manifest.read_text())
    if len(pairs) != 28 or len({name for name, _ in pairs}) != len(pairs):
        raise ValueError("Unexpected locked acceptance manifest")
    for name, expected in pairs:
        path = LAB / name
        if not path.resolve().is_relative_to(LAB.resolve()) or digest(path) != expected:
            raise ValueError(f"Locked test pin mismatch: {name}")
    return pairs


def source_identity():
    names = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=SOURCE
    ).split(b"\0")
    files = []
    for raw in sorted(set(names) - {b""}):
        name = os.fsdecode(raw)
        path = SOURCE / name
        if path.is_symlink():
            identity = "link:" + os.readlink(path)
        elif path.is_file():
            identity = digest(path)
        elif not path.exists():
            identity = "deleted"
        else:
            raise ValueError(f"Unexpected source entry: {name}")
        files.append((name, identity))
    return {
        "head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=SOURCE, text=True).strip(),
        "working_tree_sha256": hashlib.sha256(json.dumps(files, ensure_ascii=True).encode()).hexdigest(),
    }


def candidate_artifact(messages, name, kind):
    candidates = [
        m for m in messages if m.get("reason") == "compiler-artifact"
        and m.get("manifest_path") == str(SOURCE / "Cargo.toml")
        and m.get("target", {}).get("name") == name
        and kind in m.get("target", {}).get("kind", [])
        and not m.get("profile", {}).get("test", False)
    ]
    if len(candidates) != 1:
        raise ValueError(f"Expected exactly one candidate artifact: {name} ({kind})")
    return candidates[0]


def checked_artifact(value, target):
    path = Path(value)
    if not path.is_absolute() or not path.resolve().is_relative_to(target.resolve()) or not path.is_file():
        raise ValueError("Cargo reported an unavailable or external artifact")
    return path


def stage_build(destination, identity, locked, hooks=False):
    arguments = ["build", "--bin", "mcp-gateway", "--features", "test-hooks"] if hooks else [
        "build", "--bins", "--lib"]
    arguments.append("--message-format=json")
    def execute(command, env, paths):
        if source_identity() != identity or pins() != locked:
            raise ValueError("Candidate source or locked pins changed")
        target = Path(env["CARGO_TARGET_DIR"])
        with tempfile.TemporaryFile(mode="w+", dir=env["TMPDIR"]) as log:
            rc = guard.supervise(command, env, paths, stdout=log)
            if rc != 0:
                return rc
            log.seek(0)
            messages = [json.loads(line) for line in log if line.strip()]
        if not any(m.get("reason") == "build-finished" and m.get("success") is True for m in messages):
            raise ValueError("Cargo did not report a successful build")
        if source_identity() != identity:
            raise ValueError("Candidate source changed during build")
        layout = destination / ("target/test-hooks/debug" if hooks else "target/debug")
        layout.mkdir(parents=True, mode=0o700)
        for name in (("mcp-gateway",) if hooks else BINS):
            artifact = candidate_artifact(messages, name, "bin")
            features = artifact.get("features", [])
            if ("test-hooks" in features) != hooks:
                raise ValueError("Wrong test-hook feature set")
            path = checked_artifact(artifact["executable"], target)
            shutil.copy2(path, layout / name)
            if digest(path) != digest(layout / name):
                raise ValueError("Executable copy mismatch")
        if hooks:
            # The shared final executable name is reused when switching Cargo
            # features. Restore normal outputs while still owning the guard.
            restore = ["cargo", "build", "--offline", "--locked", "-j", "1", "--bins", "--lib"]
            result = guard.supervise(restore, env, paths)
            if result != 0:
                return result
            for name in BINS:
                if digest(target / "debug" / name) != digest(destination / "target/debug" / name):
                    raise ValueError("Normal artifact restore did not match staged binary")
            return 0
        library = candidate_artifact(messages, "mcp_gateway", "lib")
        if "test-hooks" in library.get("features", []):
            raise ValueError("Normal library contains test hooks")
        libraries = [checked_artifact(f, target) for f in library["filenames"] if f.endswith(".rlib")]
        if len(libraries) != 1:
            raise ValueError("Expected exactly one normal library artifact")
        dependency_dirs = set()
        for message in messages:
            if message.get("reason") != "compiler-artifact":
                continue
            for filename in message.get("filenames", []):
                if filename.endswith((".rlib", ".rmeta", ".so")):
                    dependency_dirs.add(checked_artifact(filename, target).parent)
        # Cargo may expose an un-hashed public library while its hashed
        # dependency artifacts remain in the per-unit build output directory.
        # All dependencies are derived from this invocation, not a stale glob.
        dependency_args = []
        for directory in sorted(dependency_dirs):
            dependency_args.extend(["-L", f"dependency={directory}"])
        for message in messages:
            if message.get("reason") == "build-script-executed":
                for linked in message.get("linked_paths", []):
                    dependency_args.extend(["-L", linked])
        for name, expected in locked:
            if not name.endswith(".rs"):
                continue
            test = LAB / name
            if digest(test) != expected:
                raise ValueError(f"Locked Rust test changed: {name}")
            result = guard.supervise(
                ["rustc", "--edition=2024", "--test", *dependency_args,
                 "--extern", f"mcp_gateway={libraries[0]}", str(test),
                 "-o", str(layout / test.stem)],
                env, paths
            )
            if result:
                return result
        return 0
    return guard.main(arguments, executor=execute)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path, help="New absolute staging directory outside source")
    args = parser.parse_args()
    output = args.output
    if (not output.is_absolute() or output.parent.resolve() != output.parent
            or output.is_relative_to(SOURCE) or output.exists() or output.is_symlink()):
        parser.error("Use a new canonical absolute output directory outside source")
    if Path.cwd().resolve() != SOURCE:
        parser.error("Run from the exact candidate source root")
    os.umask(0o077)
    locked = pins()
    identity = source_identity()
    output.mkdir(mode=0o700)
    for hooks in (False, True):
        code = stage_build(output, identity, locked, hooks)
        if code != 0:
            print("Preparation incomplete: no acceptance receipt", file=sys.stderr)
            return code
    if source_identity() != identity or pins() != locked:
        raise ValueError("Candidate source or locked pins changed")
    files = {str(p.relative_to(output)): digest(p) for p in output.rglob("*") if p.is_file()}
    receipt = {
        "source": str(SOURCE), **identity, "locked_pins": dict(locked),
        "artifact_sha256": files,
        "scope": "prepared artifacts only; independent acceptance not run",
    }
    with (output / "receipt.json").open("x") as f:
        json.dump(receipt, f, indent=2)
        f.write("\n")
    print("LOCKED_ARTIFACTS_PREPARED", len(locked), len(files))
    return 0

if __name__ == "__main__":
    sys.exit(main())
