#!/usr/bin/env bash
# Nested systemd --user lifecycle test for opt-in veyl.service (`ExecStart="<abs-veyl>" serve`).
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
gateway=$(realpath "${1:-/home/onyx/Projects/veyl/target/debug/veyl}")
fixture=$(mktemp -d /tmp/veyl-unified-systemd.XXXXXX)
cleanup() {
    python3 -B - "$fixture" <<'PY_CLEAN'
import os, shutil, sys
from pathlib import Path
root = Path(sys.argv[1])
assert root.parent == Path("/tmp") and root.name.startswith("veyl-unified-systemd.")
for current, dirs, _ in os.walk(root, topdown=True, followlinks=False):
    for d in dirs:
        p = Path(current) / d
        if not p.is_symlink() and p.stat().st_uid == os.geteuid():
            p.chmod(0o700)
shutil.rmtree(root)
PY_CLEAN
}
trap cleanup EXIT
mkdir -m 700 "$fixture/home" "$fixture/run" "$fixture/units"
for unit in veyl-test basic sockets timers paths shutdown default; do
    printf '[Unit]\nDescription=Veyl unified systemd fixture\nDefaultDependencies=no\n' > "$fixture/units/$unit.target"
done
job="veyl-unified-svc-${fixture##*.}"
if ! systemd-run --user --unit="$job" --collect --wait --pipe \
    --property=Delegate=yes --property=MemoryMax=768M --property=TasksMax=96 \
    --property=RuntimeMaxSec=60s -- /usr/bin/env -i PATH=/usr/bin \
    HOME="$fixture/home" XDG_CONFIG_HOME="$fixture/home/.config" XDG_RUNTIME_DIR="$fixture/run" \
    SYSTEMD_UNIT_PATH="$fixture/units:$fixture/home/.config/systemd/user" LANG=C.UTF-8 \
    /usr/bin/dbus-run-session -- /usr/bin/python3 -B "$repo/tests/unified_service.py" "$fixture" "$gateway"; then
    if [[ -f "$fixture/nested-manager.log" ]]; then cat "$fixture/nested-manager.log"; fi
    exit 1
fi
