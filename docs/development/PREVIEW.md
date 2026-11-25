# Development preview and local update pipeline

The production dashboard at http://127.0.0.1:7332/dashboard uses assets embedded in the installed Rust gateway. Source edits cannot alter that binary. Use the development preview before promotion.

## UI iteration (on demand)

From this checkout:

```sh
python3 -B tests/dashboard_preview.py
```

Open http://localhost:7333/dashboard. To preview a different candidate, pass
`--source /absolute/path/to/candidate`. The server listens only on IPv4
loopback, serves the exact candidate's dashboard HTML, CSS, JS and catalog,
and checks an asset content hash from the visible browser tab every 1.5 seconds.
Changed assets trigger reload without a Rust build or service restart. The banner
displays a short content revision so screenshots identify the preview.

All API data are synthetic fixtures, including all nine diagnostic sections.
No production API proxy, credentials, real tool execution, mutation or
configuration access is provided. No service or persistent watcher is installed.
Stop with Ctrl+C. The preview is not an independent backend acceptance test.

## TUI and other features

For TUI-only changes, build and run the candidate monitor directly against the
existing authenticated local admin listener, without replacing installed binaries:

```sh
cargo build --offline --locked --bin veyl-monitor
veyl dashboard pair | env VEYL_TUI_PREVIEW=1 ./target/debug/veyl-monitor --listen 127.0.0.1:7332
```

The header identifies the preview. It uses live data and the normal operator
permissions; do not exercise mutations against production for testing. For CLI,
MCP or backend changes, build the candidate binaries and start an isolated
instance with disposable roots, separate state and local ports (no Funnel or
production credentials). Provide a reproducible launch command and test cases.
The production service remains unchanged while the operator tests.

## Build storage and retention

Use external candidate worktrees instead of nesting them inside Cargo output:

```sh
export CARGO_TARGET_DIR="$HOME/Projects/veyl/target"
cargo build --offline --locked --bins -j 1
```

Serialize candidate builds sharing this cache. A shared-cache binary is not a
stable baseline merely because it exists: record its source commit and SHA-256
and recheck before deployment. Keep the accepted installed build and explicit
rollback bundle separate. Archive verification logs, hashes and source-only
snapshots under `~/.local/share/veyl-development/artifacts/<commit>/`, with
private permissions. After acceptance, check active processes and worktrees,
then prune only the inventoried redundant Cargo profiles. Never delete dirty
source, the external acceptance lab, or a rollback bundle as cache cleanup.
Historical paths under the old `target/` have been archived at
`~/.local/share/veyl-development/artifacts/2d1bd03/legacy-target/`.

## Promotion

1. Edit the isolated candidate, run focused tests, and provide the operator a runnable preview for personal acceptance before deploying.
2. Run `python3 -B tests/test_dashboard_preview.py -v`, JS syntax checks and
   the real browser acceptance tests; test the actual backend for non-UI changes.
3. Build the exact accepted candidate with `cargo build --offline --locked --release --bins -j 1`.
   Record the Git commit and binary checksums; keep the version unchanged unless
   the operator explicitly authorizes a bump.
4. With separate operator authorization, push the verified source and stage
   all three binaries; check every client's jobs are idle and retain rollback
   backups. Restart only Veyl. Confirm running executable identity, installed
   copies, unchanged policy, authenticated dashboard and remote tool discovery.
5. Report the deployed commit and status. If UI assets alone changed, the source
   preview still provides immediate feedback before this gate. Backend and TUI
   changes require separate candidate builds and actual integration tests.

The pending native updater is not part of this checkpoint. Do not bypass its
independent security-review gate or alter immutable public release assets.
