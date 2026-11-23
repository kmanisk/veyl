#!/usr/bin/env bash
# Run only the synthetic unit under an isolated user manager.
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
gateway=$(realpath "${1:-$repo/target/debug/mcp-gateway}")
fixture=$(mktemp -d /tmp/veyl-systemd-lifecycle.XXXXXX)
cleanup() {
    python3 -B - "$fixture" <<'PY_CLEAN'
import os
from pathlib import Path
import shutil
import sys

root = Path(sys.argv[1])
assert root.parent == Path("/tmp") and root.name.startswith("veyl-systemd-lifecycle.")
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
    printf '[Unit]\nDescription=Veyl disposable fixture\nDefaultDependencies=no\n' > "$fixture/units/$unit.target"
done
job="veyl-linux-test-${fixture##*.}"
if ! systemd-run --user --unit="$job" --collect --wait --pipe \
    --property=Delegate=yes --property=MemoryMax=768M --property=TasksMax=96 \
    --property=RuntimeMaxSec=60s -- /usr/bin/env -i PATH=/usr/bin \
    HOME="$fixture/home" XDG_CONFIG_HOME="$fixture/home/.config" XDG_RUNTIME_DIR="$fixture/run" \
    SYSTEMD_UNIT_PATH="$fixture/units:$fixture/home/.config/systemd/user" LANG=C.UTF-8 \
    /usr/bin/dbus-run-session -- /usr/bin/python3 -B "$repo/tests/systemd_lifecycle.py" "$fixture" "$gateway"; then
    if [[ -f "$fixture/nested-manager.log" ]]; then cat "$fixture/nested-manager.log"; fi
    exit 1
fi
