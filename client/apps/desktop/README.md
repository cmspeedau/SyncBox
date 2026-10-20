# Desktop app

The Tauri v2 desktop client: background sync, vault unlock, and the agent UI
built to `docs/reference-agent-ui.html` — a tinted status bar over a per-folder
sync list, a gear click menu, and a first-run card that connects to the server,
picks a space, and takes the folder the server derives. Two more windows of
their own, per the references: the unlock window a vault password is typed in
(`docs/reference-agent-ui.md`) and the settings window (`docs/reference-agent-settings.md`).
And a tray icon for the hours no window is open (`docs/reference-agent-tray.md`).

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
src-tauri/         Rust: Tauri windows + commands over the Agent; icons; tauri.conf.json
  src/main.rs      window + command registration; the `today()` clock edge
  src/state.rs     shared state: the SyncWorker handles + re-auth client factory
  src/commands.rs  the #[tauri::command] surface (thin; blocking work off-thread)
  src/dto.rs       JSON shapes the webview sees, mapped from agent types (tested)
  src/prefs.rs     the stored switches (prefs.json in the app config dir; tested)
  src/tray.rs      the tray icon and its native menu; the state mirror and the
                   no-indicator fallback (the badge drawing is tested; the menu is not)
src/               static HTML/CSS/JS frontend (embedded as `frontendDist`)
  index.html       the main window
  unlock.html      the unlock window (its own top-level window; S3)
  settings.html    the settings window (rail + pages + footer switches; S4)
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
| `unlock` | open a space — deriving keys for a vault, nothing for a sync space — and start one loop per folder (the main window only calls this for a sync space; a vault goes through the unlock window) |
| `open_unlock_window` | hold the chosen session and open the unlock window on it (a vault only) |
| `unlock_pending` | unlock the held session with the password the unlock window collected, then close that window |
| `pending_unlock` | which space the open unlock window is for — name and mode, never a secret |
| `cancel_unlock` | drop the pending session and close the unlock window |
| `settings_info` | what this build is (version, platform, licence) and which space is running (name, server, mode, state folder) — no password in it |
| `open_settings_window` | open the settings window on the gear's *Settings…* (one window, reused) |
| `close_settings` | close it and hand focus back to the main window (its *Change…* rows run this after `lock`) |
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
and `index.html` carries a browser preview (`?demo=setup|step2|idle|sync|err|pause|pending`,
`&hidden=1`, `&pick=1`, `&menu=1`, `&pending=1`), as do `unlock.html` (`?demo=1`)
and `settings.html` (`?demo=1`, `&locked=1`): every invoke answers from fixtures
outside Tauri, so the windows
can be screenshotted and checked against the mock without the shell. Inside
Tauri the parameter is unreachable.

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

**M16 S3 specifics.** The two passwords are now two secrets asked for in two
places. The **server** password (the web login's, which buys the bearer token)
stays in the main window's card; the **vault** password — which derives the
keys — is typed only in `unlock.html`, its own top-level window with its own
webview. `open_unlock_window` holds the chosen session in `AppState::pending`
and opens the window; `unlock_pending` consumes it, unlocks, and closes the
window (a failed attempt puts the session back so the retry works); a failure
the human abandons is dropped by `cancel_unlock`, and a lock drops it too. The
window learns nothing but the space's name and mode (`pending_unlock`), so no
secret crosses the IPC boundary in that direction. While it stands, the main
window's card says it is waiting and offers *Cancel* — the fields keep their
values (the session was snapshotted) but stop being editable. A **sync space**
has no header to unlock and skips all of it: the card calls `unlock` directly
with an empty vault password. `create_vault` in the hidden tier has grown its
own vault-password field, since the card's other password field is no longer
the vault's.

**M16 S4 specifics.** The settings window (`settings.html`, 640 × 560, opened by
the gear's *Settings…*) is the reference's `today`-badged subset and nothing
more: the rail's space card and usage line, Sync Files (each synced folder with
`Open`, *Change…* which runs `lock` then closes this window so the main window's
card can pick again, and the pause as one switch), Account (server and space,
read-only, from `settings_info`), About (version, platform, licence, and the
space's state folder with `Open`), and the footer's two app-wide switches —
which is why the main window's temporary footer bar is gone; that window now
re-reads `get_prefs` on its poll and follows the switch instead of owning it. No
*Apply settings* button: everything shipped here writes as it is touched. The
`new`-badged controls are left out rather than drawn dead — no Notifications
page, choose-folders tree, pause durations, auto-lock timer, device id, server
version, logs or update check — and "Remove vault from this computer" waits for
session persistence, since a client that forgets the space on every launch has
nothing local to remove.

**M16 S5 specifics.** The tray (`src/tray.rs` — no HTML, it is a native menu) is
the reference's rows and nothing more: a disabled header spelling the state,
*Open Syncbox*, *Open sync folder* (the first chosen folder, through
`open_folder`, greyed while nothing is unlocked), *Lock vault* ⇄ *Unlock
vault…*, *Settings…* and *Quit*. Built once, then relabelled: a two-second watch
thread reads the same `current_status` the window polls and posts what it found
with `run_on_main_thread`, because menus belong to the event loop's thread — and
posts **only when the state moved**, since the appindicator backend writes the
tray image out as a fresh PNG for every `set_icon`. A
plain icon click raises the window; the menu is what a right-click brings up. The
glyph's corner badge is painted at runtime from the state (`badge`), the same
colours the status bar's dot uses. Whether a tray is even *attempted* is decided
by `indicator_library_present`: `tauri`'s `tray-icon` feature builds with no
system package at all (the backend `dlopen`s libayatana-appindicator, and
`libappindicator-sys` panics if neither soname opens), so the app asks the same
question first and falls back to windows-only with one line on stderr. While a
tray is up, closing the main window hides it and the loops keep syncing — *Quit*
is the only thing that ends the process; while none is, the close quits as it
always did.

**Shipped since M4:** autostart and single-instance (M6, below), the operator
pointing at server-named vaults (M10), sync-space modes (M11), the reference
main window (M16 S1), the pause (M16 S2), the separate unlock window
(M16 S3), the settings window (M16 S4), and the tray (M16 S5). **Still
deferred:** the drafted dark palette and the mock's per-vault locked rows (both
M16, above); **placeholder / on-demand files**, which want a hydrate path in the
folder loop and the platform's placeholder API (FileProvider, CFAPI) for a plain
folder — `syncbox mount` already serves files this way over FUSE; the **update
publish job** — `release.yml` now covers both halves (sign, cut a Release, write
`update.json`, and a flat apt repo when its key is set) but has not run: no minisign
keypair is stored, so no public key sits in the config; a Node/Svelte
frontend behind `frontendDist` (instead of this static one); and code signing.

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

## Running it

`client/target/debug/syncbox-desktop` runs against the desktop session it is started
from. Two things worth knowing from running it on the KDE/Wayland dev box:

* WebKitGTK aborts the process with `Error 71 (Protocol error) dispatching to Wayland
  display` while the webview is being created, unless the environment carries
  `WEBKIT_DISABLE_DMABUF_RENDERER=1`. That is a WebKitGTK/compositor pairing, not
  something the shell controls; the run that fails dies *after* the tray registered
  fine, so it is not the tray's doing.
* The tray appears only where `libayatana-appindicator3.so.1` is installed (on Arch:
  `libayatana-appindicator`). Whether it registered is checkable without looking at
  the panel:

  ```sh
  busctl --user call org.kde.StatusNotifierWatcher /StatusNotifierWatcher \
    org.freedesktop.DBus.Properties Get ss org.kde.StatusNotifierWatcher \
    RegisteredStatusNotifierItems
  ```

  A line ending `…/org/ayatana/NotificationItem/tray_icon_tray_app_main` is the
  agent's. The image the panel was given lands as a PNG under
  `/run/user/<uid>/tray-icon/`, which is the quickest way to see the badge as the
  tray actually has it.

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

And until that tag is cut, nothing updates a running install: the PR job uploads
artefacts and no manifest says which is newest. The publish half is
`.github/workflows/release.yml`: a `desktop-v*` tag (or a manual run against one)
builds with `createUpdaterArtifacts`, so tauri signs the AppImage and the `.deb` with a
`.sig` beside each, writes `update.json` with `syncbox-release manifest`, and attaches
bundles, signatures and manifest to a GitHub Release. When `APT_SIGNING_KEY` is set it
also writes a flat apt repository into that release — `Packages`, `Packages.gz`, a
signed `Release` (`Release.gpg` and `InRelease`) and the archive key — so an installed
`.deb` updates with the app closed:

```sources
Types: deb
URIs: https://github.com/cmspeedau/SyncBox/releases/latest/download
Suites: ./
Signed-By: /etc/apt/keyrings/syncbox-archive-keyring.asc
```

The repository is flat because a Release's assets cannot fake `dists/` and `pool/`:
`Filename:` names an asset in the same release, and the keyring is
`syncbox-archive-keyring.asc` from that URL. It has not run yet — no minisign keypair is
stored, so `plugins.updater.pubkey` is unwritten and no client checks; the workflow takes
the public key from a secret meanwhile, because the bundler refuses to sign without one.
To cut a release: generate the keypair once (`cargo tauri signer generate
-w ~/.tauri/syncbox.key`), store the private key, its password and the public key as the
three secrets named at the top of `release.yml` (plus the apt key and its passphrase if
you want the repository), bump the version in `tauri.conf.json`, and push the matching
`desktop-v<version>` tag. A client will read `releases/latest/download/update.json`; the
tag is the switch, and PRs never publish.
The client library is already there — `tauri-plugin-updater` covers `deb`, `rpm` and
AppImage on Linux, NSIS and MSI on Windows, and macOS `.app` replacement, and
`install()` knows how to apply each (`dpkg -i` with an escalation fallback, the `.app`
swapped in place when the old and new signatures match, the AppImage replacing itself)
— and because the manifest is keyed by target there is no per-format update script to
write. Those keys carry the architecture as well as the bundle: `linux-x86_64-deb`,
`linux-x86_64-appimage`, `darwin-x86_64-app` for this Intel mini, with a plain
`{os}-{arch}` key as the fallback.
There is no delta channel — the plugin downloads the signed bundle whole; `.zsync`
belongs to AppImageUpdate, which this is not. Each platform then takes its own road
through that manifest — AppImage is the shortest (no root, no identity); `linux-x86_64-deb`
rides `apt-daily` and `unattended-upgrades` through a signed repo (`dpkg-scanpackages` or
`reprepro` publishing `Packages.gz` and a signed `Release`, one `.sources` file and a key
for the user), with the plugin's in-app `dpkg -i` as the bootstrap for whoever has not
added it — and that index now ships in the same release when the apt key is set;
`darwin-x86_64-app` updates through the `.app.tar.gz` and needs a Developer ID and
notarisation first, since the updater will not install a signature mismatch and an
unsigned `.dmg` download is a Gatekeeper refusal anyway. Two keys sign two different
things: the apt key signs the repo's `Release`, the minisign key behind
`createUpdaterArtifacts` signs what the plugin checks. And a Release is where these bytes
belong regardless: the artefact pool refills after every PR and carries no retention rule.

| Platform | Artefacts | Status |
| --- | --- | --- |
| Linux | AppImage, `.deb` | built by CI, uploaded as artifacts |
| Any (updates) | signed `update.json` + bundles in a Release | `release.yml` added, not run — needs a minisign keypair, and the pubkey committed for clients |
| Linux (repo) | `Packages.gz` + signed `Release` | `release.yml` added, unrun — built when `APT_SIGNING_KEY` is set |
| macOS | universal `.dmg` | deferred — needs a macOS runner + notarization identity |
| macOS (updates) | `.app.tar.gz` + `.sig` (notarised `.dmg` for the download) | deferred — the updater refuses mismatched signatures, so no identity means no installable update |
| Windows | `.msi`, NSIS `.exe` | deferred — needs a Windows runner + signing identity |

**Autostart and single-instance shipped on top of the bundles:** a second launch just
focuses the running window (`tauri-plugin-single-instance`, registered first), and
the *Run at login* switch in the settings window's footer bar writes or removes the
XDG autostart entry (`tauri-plugin-autostart`, wrapped as the
`get_autostart`/`set_autostart` commands and
round-trip-tested headlessly through tauri's mock runtime in a sandboxed `$HOME`).
The tray ships with the bundle and cost the build nothing: the backend `dlopen`s
libayatana-appindicator at runtime, so CI compiles the tray on a runner that has no
such package. Auto-derivation cannot see a library the binary never links, so the
`.deb` names `libayatana-appindicator3-1` in `bundle.linux.deb.depends`; an AppImage
cannot carry it either, so there the tray appears only on a host that already has the
lib — which the app detects, and degrades from quietly.
