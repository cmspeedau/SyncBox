# Desktop app

The Tauri v2 desktop client: background sync, vault unlock, and the agent UI
built to `docs/reference-agent-ui.html` — a tinted status bar over a per-folder
sync list, a gear click menu, and a first-run card that connects to the server,
picks a space, and takes the folder the server derives.

The app is a **member of the client Cargo workspace** — see `client/Cargo.toml` —
so `cargo check`/`clippy`/`test --workspace` compile the shell and run its tests, and
CI's `Client (Rust)` job covers it. Building the workspace needs the Tauri system
libraries on the machine — webkit2gtk-4.1, gtk-3, libsoup-3.0, javascriptcoregtk-4.1
(the SDKs on macOS and Windows) — so CI pins that job to the one runner that has
them. It is built on the crates that already exist:

| Crate | What the app uses it for |
| --- | --- |
| `syncbox-crypto` | unlock, re-encrypt, key handling |
| `syncbox-vault` | the on-disk vault and its layout |
| `syncbox-index` | local state (opened through the agent, and read directly for the `usage` line) |
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
  src/state.rs     shared state: the SyncWorker handles + re-auth client factory
  src/commands.rs  the #[tauri::command] surface (thin; blocking work off-thread)
  src/dto.rs       JSON shapes the webview sees, mapped from agent types (tested)
  src/prefs.rs     the stored switches (prefs.json in the app config dir; tested)
src/               static HTML/CSS/JS frontend (embedded as `frontendDist`)
```

The window's *behaviour* lives in `../../crates/agent`, not here, so it is
unit-tested headlessly (`cargo test -p syncbox-agent`) without a display. The shell's
own logic is the DTO mapping, which is pure and tested (`cargo test` in `src-tauri`).

### IPC commands

| Command | Does |
| --- | --- |
| `status` | current state (`locked`/`idle`/`syncing`/`error`), whether the loops are paused, last sync, last pass |
| `activity` | recent sync outcomes, for the activity feed |
| `usage` | files and referenced bytes per synced folder (the row meta + usage line) |
| `unlock` | open a space — deriving keys for a vault, nothing for a sync space — and start one loop per folder |
| `sync_now` | ask the loops for an immediate pass (non-blocking; refused while paused) |
| `set_paused` | hold or release every loop's passes (the gear's Pause ⇄ Resume) |
| `lock` | stop the loops and drop the keys |
| `list_vaults` | the server's spaces for the picker: name, mode, derived folder, derived header dir |
| `create_vault` | create a vault header on this machine, return its root id (hidden tier) |
| `open_folder` | reveal a synced folder in the OS file manager (the row click) |
| `quit` | exit the process (the gear menu's Quit) |
| `get_prefs` / `set_prefs` | the stored switches (Show hidden features) |
| `get_autostart` / `set_autostart` | the start-at-login entry |

Unlock, create, and the network calls run on a blocking thread (Argon2id and
ureq), so the webview never stalls; `status`/`activity`/`usage`/`sync_now`/
`set_paused` only read or flip the shared snapshot the workers publish.

## Current state

The shell is wired end to end: the reference UI (M16), driving the
`Agent`/`SyncWorker` background loops, with the real `UreqHttp` client (shared
with the CLI via the transport `ureq` feature). `withGlobalTauri` is on so the
static frontend reaches the commands.

**Built and clippy-clean here, but not launched from CI** — the CI runner is
headless, so a window can't be opened there; `cargo build` (links
webkit/gtk/soup) plus the agent + DTO + prefs tests are the CI verification,
and `index.html` carries a browser preview (`?demo=setup|idle|sync|err|pause`,
`&hidden=1`, `&pick=1`, `&menu=1`): every invoke answers from fixtures outside Tauri, so
the window can be screenshotted and checked against the mock without the
shell. Inside Tauri the parameter is unreachable.

**M16 S1 specifics.** The main window is the reference's, with three honest
deviations: the row list shows the one space's folders (the client is
single-space today); the gear menu carries only what exists (Sync now, Pause
syncing, Lock vault, Quit — Settings… joins in S4); and a Recent activity
disclosure stands under the list until the settings window's Notifications
page inherits it. Unlock is now mode-aware — the same `open_folders` call the
CLI uses, so a sync space syncs in the clear from the picker with no vault
header. The space's local state dir is derived (`~/.syncbox/<id>`), so no
default screen asks for a path; the hidden tier can override it.

**M16 S2 specifics.** The pause is a worker-loop flag, not a `SyncState`:
`AgentStatus.paused` rides in the snapshot each loop publishes, so `status`
carries it while a paused idle folder still reports `idle` underneath — the
window draws the pause over the state word (an error still outranks it). One
`set_paused` flips every folder loop. A pause consumes nothing: a `sync_now`
that arrives while paused is refused at the command (the menu greys it out),
and a standing request runs the moment the loops resume, because resume marks
the loop dirty instead of waiting out the interval. A lock drops the loops, so
the state does not survive one — a fresh unlock starts running.

**Shipped since M4:** autostart and single-instance (M6, below), the operator
pointing at server-named vaults (M10), sync-space modes (M11), the reference
main window (M16 S1), and the pause (M16 S2). **Still deferred:** the separate Unlock and
Settings windows (M16 S3/S4 — today the main window hosts the unlock form
itself) and the **tray icon** — it needs
`libappindicator`, which is absent here, so `tauri` is pulled with
`default-features = false, features = ["wry"]` precisely so the missing lib
(and image decoders) aren't required to compile; the window is the whole UI
until a machine carrying the lib builds the app (S5). A Node/Svelte frontend
behind `frontendDist` (instead of this static one) and code signing remain
open.

## Building the app

The app is a **member** of the client workspace, so `cargo build`/`test --workspace`
from `client/` compiles it and runs its tests, and these build the binary and bundle
into `client/target/`. To build just this crate:

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
