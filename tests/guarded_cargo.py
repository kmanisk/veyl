#!/usr/bin/env python3
"""On-demand, cooperative disk guard for Veyl development builds (Linux)."""
import fcntl
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time

GIB = 1024 ** 3
START_FREE = 38 * GIB
STOP_FREE = 15 * GIB
INTERVAL = 0.5
COMMANDS = {"build", "test", "check", "clippy"}


def free_bytes(paths):
    return min(shutil.disk_usage(path).free for path in paths)


def stop_group(child):
    # Only signal the process group created by this invocation.
    try:
        os.killpg(child.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        child.wait(timeout=3)
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(child.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    child.wait()


def supervise(command, env, paths, measure=free_bytes, stdout=None):
    available = measure(paths)
    if available < START_FREE:
        print(f"Build refused: {available / GIB:.2f} GiB free; need {START_FREE / GIB:g} GiB.", file=sys.stderr)
        return 75
    child = subprocess.Popen(command, env=env, start_new_session=True, stdout=stdout)
    try:
        while child.poll() is None:
            if measure(paths) < STOP_FREE:
                print("Build stopped: available storage below 15 GiB.", file=sys.stderr)
                stop_group(child)
                return 75
            time.sleep(INTERVAL)
        return child.returncode if child.returncode >= 0 else 128 - child.returncode
    except BaseException:
        stop_group(child)
        raise


def main(args, executor=None):
    if not args or args[0] not in COMMANDS:
        print("Usage: guarded_cargo.py build|test|check|clippy [cargo arguments]", file=sys.stderr)
        return 2
    # Refuse competing output/parallelism settings; the wrapper owns these.
    cargo_args = args[:args.index("--")] if "--" in args else args
    if any(a.startswith(("-j", "--jobs", "--target-dir", "--build-dir", "--config"))
           for a in cargo_args[1:]):
        print("Build guard owns Cargo jobs, paths and configuration overrides.", file=sys.stderr)
        return 2
    home = Path.home()
    target = home / "Projects/veyl/target"
    state = home / ".local/share/veyl-development"
    if not target.is_dir() or not state.is_dir():
        print("Shared target or Veyl development directory missing.", file=sys.stderr)
        return 75
    paths = (Path("/"), home, Path.cwd(), target)
    env = dict(os.environ, CARGO_TARGET_DIR=str(target),
               CARGO_BUILD_BUILD_DIR=str(target / "build"), CARGO_BUILD_JOBS="1",
               CARGO_INCREMENTAL="0", CARGO_PROFILE_DEV_DEBUG="0",
               CARGO_PROFILE_TEST_DEBUG="0")
    # This lock coordinates all callers of the guard, including separate worktrees.
    # It cannot prevent an unrelated or manually launched unguarded build.
    lock_path = state / "guarded-cargo.lock"
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "r+") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            print("Another guarded Veyl build owns the lock.", file=sys.stderr)
            return 75
        # Preserve cargo's argument separator and force serial compilation.
        cmd = ["cargo", args[0], "--offline", "--locked", "-j", "1", *args[1:]]
        # Keep linker scratch on the monitored disk, not the small /tmp tmpfs.
        with tempfile.TemporaryDirectory(prefix=".guard-tmp-", dir=target) as scratch:
            env["TMPDIR"] = scratch
            return (executor or supervise)(cmd, env, paths)


if __name__ == "__main__":
    def interrupted(signum, _frame):
        raise SystemExit(128 + signum)

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    sys.exit(main(sys.argv[1:]))
