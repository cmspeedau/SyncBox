# Desktop app (M4)

The Tauri v2 desktop client: background sync, vault unlock, sync status, and a
Backups panel (list snapshots, back up now).

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
| `syncbox-index` | local state (opened through the agent) |
| `syncbox-sync` | the sync engine and conflict naming |
| `syncbox-transport` | talking to the server (`UreqHttp`, the `ureq` feature) |
| `syncbox-agent` | the whole session: unlock, background loop, status, backups |

Nothing in those crates depends on Tauri, which is the point: the CLI in `../cli`
drives the same engine headlessly, the agent's states are unit-tested against the
in-process fake server, and the mount layer in M5 will too. This shell only maps the
agent across the IPC boundary (the DTOs in `src-tauri/src/dto.rs`).

## Shape

```
src-tauri/         Rust: Tauri window + commands over the Agent; icons; tauri.conf.json
  src/main.rs      window + command registration; the `today()` clock edge
  src/state.rs     shared state: the SyncWorker handle + re-auth client factory
  src/commands.rs  the #[tauri::command] surface (thin; blocking work off-thread)
  src/dto.rs       JSON shapes the webview sees, mapped from agent types (tested)
src/               static HTML/CSS/JS frontend (embedded as `frontendDist`)
```

The window's *behaviour* lives in `../../crates/agent`, not here, so it is
unit-tested headlessly (`cargo test -p syncbox-agent`) without a display. The shell's
own logic is the DTO mapping, which is pure and tested (`cargo test` in `src-tauri`).

### IPC commands

| Command | Does |
| --- | --- |
| `status` | current state (`locked`/`idle`/`syncing`/`error`), last sync, last pass |
| `activity` | recent sync outcomes, for the activity feed |
| `unlock` | unlock a vault and start the background loop (re-auths each pass) |
| `sync_now` | ask the loop for an immediate pass (non-blocking) |
| `lock` | stop the loop and drop the keys |
| `create_vault` | create a vault header, return its root id |
| `backups` | list the server's snapshots (`not_configured` is explained, not an error) |
| `back_up_now` | ask the server to snapshot now |

Unlock, create, and the two backups calls run on a blocking thread (Argon2id and the
network), so the webview never stalls; `status`/`activity`/`sync_now` just read the
shared snapshot the worker publishes.

## Current state (M4)

The shell is wired end to end: a window with the panels above, driving the
`Agent`/`SyncWorker` background loop, with the real `UreqHttp` client (shared with the
CLI via the transport `ureq` feature). `withGlobalTauri` is on so the static frontend
reaches the commands.

**Built and clippy-clean here, but not launched** — this is a headless box (no
display), so a window can't be opened on it; treat `cargo build` (links
webkit/gtk/soup) plus the agent + DTO tests as the verification, and run the binary on
a real desktop to see the UI.

**Shipped since M4:** autostart and single-instance (M6, below). **Still deferred:** the
**tray icon** — it needs `libappindicator`, which is absent here, so `tauri` is pulled
with `default-features = false, features = ["wry"]` precisely so the missing lib (and
image decoders) aren't required to compile; the window is the whole UI until a machine
carrying the lib builds the app. Mount control shipped with M5 (read-only + writable +
folderless sync); bundling shipped as M6's first step (see Packaging). A Node/Svelte
frontend behind `frontendDist` (instead of this static one) and code signing remain open.

## Building the app

```sh
cargo build --manifest-path client/apps/desktop/src-tauri/Cargo.toml
```

Needs webkit2gtk-4.1, gtk-3, libsoup-3.0, and javascriptcoregtk-4.1 on Linux, plus a
C compiler (rusqlite bundles SQLite). It builds without `tauri-cli` (`tauri_build` in
`build.rs` embeds the frontend and generates the IPC glue) — `tauri-cli` is needed for
bundling (`cargo-tauri build --bundles deb appimage`) and for `cargo-tauri icon`.
Its unit tests run with
`cargo test --manifest-path client/apps/desktop/src-tauri/Cargo.toml` (they need the
GUI libs to link but open no window).

## Packaging (M6)

**Linux — building and shipping from CI.** `tauri.conf.json` carries real bundle
metadata (publisher, license, category, descriptions) and `src-tauri/icons/` holds a
generated icon set (`cargo-tauri icon <1024px source>` regenerates every format).
`cargo-tauri build --bundles deb appimage` produces:

- `Syncbox_<ver>_amd64.deb` (~5 MB) — desktop entry, hicolor icons, and runtime
  dependencies derived from linkage (`libwebkit2gtk-4.1-0`, `libgtk-3-0`);
- `Syncbox_<ver>_amd64.AppImage` — self-contained; the static-pie AppImage runtime
  means no FUSE is needed even to *build* it.

The `Package (Linux desktop)` CI job rebuilds both on every PR (on the self-hosted
runner, which carries the webkit dev libraries and lets tauri do the deb via `ar`) and
uploads them as build artifacts. They are unsigned, like everything here — publishing
and signing stay deliberate acts, each to its own runner and identity.

| Platform | Artefacts | Status |
| --- | --- | --- |
| Linux | AppImage, `.deb` | built by CI, uploaded as artifacts |
| macOS | universal `.dmg` | deferred — needs a macOS runner + notarization identity |
| Windows | `.msi`, NSIS `.exe` | deferred — needs a Windows runner + signing identity |

**Autostart and single-instance shipped on top of the bundles:** a second launch just
focuses the running window (`tauri-plugin-single-instance`, registered first), and a
"Start at login" checkbox in the Vault card writes or removes the XDG autostart entry
(`tauri-plugin-autostart`, wrapped as the `get_autostart`/`set_autostart` commands and
round-trip-tested headlessly through tauri's mock runtime in a sandboxed `$HOME`).
The tray icon is what remains: `libappindicator` is absent on both the dev box and the
CI runner, so until one carries it `tauri` stays on
`default-features = false, features = ["wry"]` and the window is the whole UI.
