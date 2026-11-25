#!/usr/bin/env bash
# Test portable updates, interrupted recovery, and isolated systemd updater rollback.
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
bin_dir=$(realpath "${1:-/home/onyx/Projects/veyl/target/debug}")
fixture=$(mktemp -d /tmp/veyl-updater-lifecycle.XXXXXX)
cleanup() {
    python3 -B - "$fixture" <<'PY_CLEAN'
import os
from pathlib import Path
import shutil
import sys

root = Path(sys.argv[1])
assert root.parent == Path("/tmp") and root.name.startswith("veyl-updater-lifecycle.")
for current, dirs, _ in os.walk(root, topdown=True, followlinks=False):
    for name in dirs:
        directory = Path(current) / name
        if not directory.is_symlink() and directory.stat().st_uid == os.geteuid():
            directory.chmod(0o700)
shutil.rmtree(root)
PY_CLEAN
}
trap cleanup EXIT
mkdir -m 700 "$fixture/home" "$fixture/run" "$fixture/units"
for unit in veyl-test basic sockets timers paths shutdown default; do
    printf '[Unit]\nDescription=Veyl updater test fixture\nDefaultDependencies=no\n' > "$fixture/units/$unit.target"
done
job="veyl-updater-test-${fixture##*.}"
if ! systemd-run --user --unit="$job" --collect --wait --pipe \
    --property=Delegate=yes --property=MemoryMax=1536M --property=TasksMax=96 \
    --property=RuntimeMaxSec=90s -- /usr/bin/bwrap --dev-bind / / --unshare-net \
    /usr/bin/env -i PATH=/usr/bin \
    HOME="$fixture/home" XDG_CONFIG_HOME="$fixture/home/.config" XDG_RUNTIME_DIR="$fixture/run" \
    SYSTEMD_UNIT_PATH="$fixture/units:$fixture/home/.config/systemd/user" LANG=C.UTF-8 \
    /usr/bin/dbus-run-session -- /usr/bin/python3 -B "$repo/tests/updater_lifecycle.py" "$fixture" "$bin_dir"; then
    if [[ -f "$fixture/nested-manager.log" ]]; then cat "$fixture/nested-manager.log"; fi
    exit 1
fi
