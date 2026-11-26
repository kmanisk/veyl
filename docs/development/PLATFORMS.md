# Windows and Android platform foundation

## Android HTTP preview

Use the native5 debug binary in Termux. Create fresh private state with android-init veyl-android-preview, then android-add-client veyl-android-preview local platform_info,read_file,list_directory,file_info, and android-serve veyl-android-preview 7339. Keep the generated local bearer token private. Place test text files in ~/veyl-android-preview/workspaces/local. Server binds 127.0.0.1 only. Stop with Ctrl-C. No ChatGPT cloud connector or public route configured. For reproducible disposable acceptance run tests/android_http.py with the native gateway path. See STATUS.md for scope and limitations.


## Native Android result (2026-11-26 IST)

The historical openat2/ADB-blocked notes below have been superseded. Native Termux Rust/Cargo 1.96.0 builds both debug binaries under UID 10156 on Waydroid Android 13 x86_64. The old openat2-based experimental reader terminated with SIGSYS. The accepted test checkpoint uses bounded descriptor-relative openat traversal with O_NOFOLLOW, directory type and ownership checks, verified procfs mount IDs at each scoped component, and existing pinned regular-file reopen checks. This is not atomic openat2 containment; do not promise equivalent protection against concurrent outside same-UID relocation. All 3 native Rust workspace security cases and 2 native MCP smoke cases passed, with six expected dead-code warnings per binary. Linux HTTP and legacy entrypoints are compiled out on non-Linux. No remote MCP, mutations, jobs, dashboard, ARM64 acceptance, release build or publication yet. See latest STATUS.md for receipts; Windows paused.


Notion source: [Veyl — Future roadmap and design requirements](https://app.notion.com/p/4225c5fcdc5081ee8d01fe93e125a7f3?pvs=204), section "Future platform expansion — Windows and Android (Termux)". Live base: 0335e36f9bcce549dd8c09bc481f78468cb3f3cf, Linux release 0.4.0-beta. Operator requested both ports now; Nightshift is not included in this candidate. No version bump or production promotion.

## First checkpoint

Reuse the existing Rust MCP lifecycle and bounded newline transport. `veyl platform` reports compiled capabilities, not runtime security certification. `veyl platform-probe` is foreground stdio only; it provides platform_info with no file or command access. On Android an explicit `--root ABSOLUTE_PRIVATE_DIR` adds a bounded read_file tool, provided the app-private root passes the runtime descriptor checks. Native Windows file access, execution and credentials are not implemented. All non-Linux legacy root, HTTP, modes and administration commands fail closed at the CLI until their native adapters are accepted. Linux behavior stays unchanged.

Android-first refinement: ordinary com.termux app UID (not root or ADB shell), canonical private HOME, descriptor-relative opening of a strict private 0700 child (reject even in-HOME symlink aliases), openat2 NO_SYMLINKS/NO_MAGICLINKS/BENEATH/NO_XDEV, pinned regular inode reopened through verified procfs, singly linked owned files, bounded 64 KiB UTF-8, no special files or fallback to unconfined paths. Explicit --root adds read_file, list_directory and file_info. Listing is nonrecursive, scans at most 256 non-dot entries, omits hidden/unsafe/non-UTF8 entries, and reports scanned/omitted/truncated. Metadata includes type, size, mode and mtime, not a digest. The selected root inode remains pinned for the lifetime of the local probe; re-launch after changing a workspace. Android SELinux/kernel restrictions can reject openat2 or procfs and must fail closed. This is not an Android job sandbox; no shell/PTY, write, audit, upstream, dashboard or remote service is enabled.

Operator requested Android first; Windows work is paused. Waydroid app inventory confirms com.termux installed. ADB connection to the current Waydroid IP 192.168.240.112:5555 still fails authentication. Authorize the host key in Waydroid before further native device inspection; do not change Android authentication, request root, or select another attached device. The native toolchain and native Bionic/SELinux runtime remain unverified. See tests/platform_termux.sh for the native build and positive/negative smoke gates.

## Native builds (only after guest/toolchain access is established)

- Windows: native x86_64-pc-windows-msvc Rust, Windows SDK/C++ Build Tools, Git; PowerShell: `powershell -NoProfile -File tests/platform_windows.ps1` from the copied isolated source. Script builds CLI/gateway and runs native stdio smoke and authority-denial checks; no VM checkpoint or tool installation occurs in this script.
- Termux: supported Termux app, native Rust/Clang, Git, Python, and build dependencies. From the copied isolated source in app-private HOME: `bash tests/platform_termux.sh`. No root or shared-storage permission; do not run in the Android shell UID. No automatic package install. Script runs two black-box smoke cases including actual Android private reads and traversal denial. Test both Waydroid x86_64 and a real ARM64 Android device before claiming mobile support.

## Next gates

| Capability | Linux baseline | Windows | Android/Termux |
| --- | --- | --- | --- |
| Protocol + foreground stdio probe | New probe tested on Linux | Native build/smoke pending | Native build/smoke pending |
| Secure workspace reads | Existing Linux adapter | Handle-relative containment/ACL/reparse implementation pending | New private reader kernel tests on Linux; native SELinux/Bionic acceptance pending |
| Mutations and credential state | Existing | Pending | Pending |
| Jobs/shell/PTY | Existing | Job Objects + ConPTY + native isolation pending | Native child supervisor + PTY and command isolation pending |
| Authenticated loopback HTTP | Existing | Pending native credential containment | Pending native credential containment |
| Tailscale / remote MCP | Existing | Separate credential and route tests pending | Actual supported Android routing pending |
| Dashboard/TUI, services | Existing | Pending | Pending |

Do not equate Windows Job Objects with a sandbox or Android app sandbox with per-command isolation. No Linux Standard/YOLO/FULL guarantees on other targets until native negative controls pass. Windows VM preparation requires a consistent stopped checkpoint before installing toolchains. No host packages, root configuration, guest boot/restart or public route was changed by this candidate.

Initial environment observations: host Rust 1.100.0, Linux x86_64 std only, Android x86_64/aarch64 and Windows MSVC/GNU target libraries absent; no MinGW compiler. Waydroid was running; explicit ADB connection to its verified current IP failed authentication. ADB authorization is an operator gate, not a reason to bypass Android security using root. Windows native runner/toolchain not verified.
