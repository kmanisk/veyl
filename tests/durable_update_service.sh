#!/usr/bin/env bash
# Disposable network namespace + nested user manager, not the production service.
set -euo pipefail
repo=$(cd "$(dirname "$0")/.." && pwd)
old=$(realpath "$1")
new=$(realpath "$2")
test_script=durable_update_service.py
case "${3:-}" in
    single-binary) test_script=single_binary_upgrade.py ;;
    policy-recovery) test_script=policy_recovery_service.py ;;
esac
fixture=$(mktemp -d /tmp/veyl-durable-updater.XXXXXXXX)
cleanup() {
    python3 -B - "$fixture" <<'PY'
import os, shutil, sys
from pathlib import Path
p = Path(sys.argv[1])
assert p.parent == Path("/tmp") and p.name.startswith("veyl-durable-updater.")
for current, dirs, _ in os.walk(p, followlinks=False):
    for name in dirs:
        d = Path(current) / name
        if not d.is_symlink() and d.stat().st_uid == os.geteuid():
            d.chmod(0o700)
shutil.rmtree(p)
PY
}
trap cleanup EXIT
mkdir -m 700 "$fixture/home" "$fixture/run" "$fixture/units"
for unit in veyl-test basic sockets timers paths shutdown default; do
    printf '[Unit]\nDescription=Veyl durable updater fixture\nDefaultDependencies=no\n' > "$fixture/units/$unit.target"
done
job="veyl-durable-updater-${fixture##*.}"
if ! systemd-run --user --unit="$job" --collect --wait --pipe \
    --property=Delegate=yes --property=MemoryMax=1536M --property=TasksMax=96 \
    --property=RuntimeMaxSec=120s -- /usr/bin/bwrap --dev-bind / / --unshare-net \
    /usr/bin/env -i PATH=/usr/bin HOME="$fixture/home" XDG_CONFIG_HOME="$fixture/home/.config" XDG_RUNTIME_DIR="$fixture/run" \
    SYSTEMD_UNIT_PATH="$fixture/units:$fixture/home/.config/systemd/user" LANG=C.UTF-8 \
    /usr/bin/dbus-run-session -- /usr/bin/python3 -B "$repo/tests/$test_script" "$fixture" "$old" "$new"; then
    if [[ -f "$fixture/nested-manager.log" ]]; then tail -40 "$fixture/nested-manager.log"; fi
    exit 1
fi
