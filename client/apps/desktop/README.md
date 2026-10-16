# Desktop app (M4)

The Tauri v2 desktop client: tray icon, background sync, vault unlock, mount
control, and the Backups panel.

This directory is a placeholder and is **excluded from the Cargo workspace** — see
`client/Cargo.toml` — so `cargo check` works on a machine without the Tauri system
dependencies (webkit2gtk on Linux, the SDKs on macOS and Windows).

It joins the workspace in M4, when the UI is built on the crates that already exist:

| Crate | What the app uses it for |
| --- | --- |
| `syncbox-crypto` | unlock, re-encrypt, key handling |
| `syncbox-vault` | the on-disk vault and its layout |
| `syncbox-index` | local state, pending work |
| `syncbox-sync` | the sync loop and conflict naming |
| `syncbox-transport` | talking to the server |

Nothing in those five crates depends on Tauri, which is the point: the CLI in
`../cli` drives the same engine headlessly, and the mount layer in M5 will too.

## Shape (M4 in progress)

The window's behaviour lives in `../../crates/agent`, not in the Tauri shell, so it
is unit-tested headlessly (`cargo test -p syncbox-agent`) against the same in-process
fake server the sync engine uses. `apps/desktop` stays excluded from the Cargo
workspace, so `cargo check`/`test --workspace` never need the GUI libraries.

```
src-tauri/         Rust: tray, autostart, notifications; Tauri commands over the Agent
src/               static HTML/CSS/JS: status, activity, settings, backups
```

The frontend is plain HTML/CSS/JS for now (no Node in the build environment); a
Svelte or React frontend can drop in behind `frontendDist` in M6 when Node and
`tauri-cli` are available for bundling.

## Packaging (M6)

| Platform | Artefacts | Notes |
| --- | --- | --- |
| Linux | AppImage, `.deb` | AppImage is the primary artefact |
| macOS | universal `.dmg` | needs notarization; macFUSE is a system extension |
| Windows | `.msi`, NSIS `.exe` | WinFsp is an install-time dependency |
