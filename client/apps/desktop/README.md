# Desktop app (M4)

The Tauri v2 desktop client: tray icon, background sync, vault unlock, mount
control, and the Backups panel.

The app is **excluded from the client Cargo workspace** — see `client/Cargo.toml` —
so `cargo check`/`test --workspace` works on a machine without the Tauri system
dependencies (webkit2gtk on Linux, the SDKs on macOS and Windows).

It is built as its **own Cargo workspace** (still excluded from the client one), so
the GUI libraries are needed only to build the app itself — never for `cargo check`
or `cargo test --workspace`. It is built on the crates that already exist:

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
src-tauri/         Rust: Tauri window + commands over the Agent; icons; tauri.conf.json
src/               static HTML/CSS/JS frontend (embedded as `frontendDist`)
```

**Current state:** the shell compiles and links — a window with a `ping` IPC command,
serving `src/index.html`. The sync `Agent`/`SyncWorker`, tray, autostart, and panels
are the next steps. The **tray icon is left off the Linux build** here because it needs
`libappindicator`; `tauri` is pulled with `default-features = false, features = ["wry"]`
precisely so that missing lib (and the image decoders) are not required to compile.

## Building the app

```sh
cargo build --manifest-path client/apps/desktop/src-tauri/Cargo.toml
```

Needs webkit2gtk-4.1, gtk-3, libsoup-3.0, and javascriptcoregtk-4.1 on Linux, plus a
C compiler. It builds without `tauri-cli` (`tauri_build` in `build.rs` embeds the
frontend and generates the IPC glue). **It cannot be launched on a headless box** —
there is no display to open a window on — so on the dev machine this is a compile-and-
link check; run the binary on a desktop to see it. The frontend is plain
HTML/CSS/JS (no Node here); a Svelte/React frontend can drop in behind `frontendDist`
in M6 once Node and `tauri-cli` are available for bundling.

## Packaging (M6)

| Platform | Artefacts | Notes |
| --- | --- | --- |
| Linux | AppImage, `.deb` | AppImage is the primary artefact |
| macOS | universal `.dmg` | needs notarization; macFUSE is a system extension |
| Windows | `.msi`, NSIS `.exe` | WinFsp is an install-time dependency |
