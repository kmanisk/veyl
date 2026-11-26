#!/data/data/com.termux/files/usr/bin/bash
# Native Termux preview only; never run as root. No package install or service.
set -eu
test "$(id -u)" -ge 10000 || { echo 'Run from ordinary Termux, not adb shell or root.' >&2; exit 2; }
cd "$(dirname "$0")/.."
case "$(rustc -vV | sed -n 's/^host: //p')" in
    *-linux-android) ;;
    *) echo 'Native Android/Bionic Rust toolchain required.' >&2; exit 2 ;;
esac
command -v python3 >/dev/null || { echo 'Python 3 required for the smoke suite.' >&2; exit 2; }
cargo build --locked --bin veyl --bin mcp-gateway
bin="${CARGO_TARGET_DIR:-target}/debug/mcp-gateway"
"$bin" platform
python3 -B tests/platform_probe.py "$bin" -v
sha256sum "$bin"
echo TERMUX_NATIVE_PLATFORM_PROBE_PASS
