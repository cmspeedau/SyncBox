# Syncbox

A lightweight file sync server, with an encrypted vault as a choice.

A Linux desktop client (AppImage / .deb), a headless CLI, and a FUSE mount sync
to a single Go server — one binary, Docker deployment included. A space is
either a **sync** space, kept in the clear so the server can index and serve
it, or a **vault**, encrypted on the client before anything leaves the machine,
so the server stores opaque blobs and bookkeeping it can never read.

## How it works

```
Tauri v2 desktop client · CLI · FUSE mount   (Rust core; vaults client-side encrypted)
   crypto core  ·  sync engine  ·  vault/mount layer  ·  local chunk store
         |  HTTPS: REST + WebSocket  (vaults encrypted in flight)
         v
Go server (single binary; Dockerfile + compose provided)
   API  ·  metadata DB  ·  content-addressed chunk store  ·  rate limiter
         |
         v
   Docker volume / NAS   +   snapshot target (local dir or S3 object-lock)
```

For a vault the client does all encryption and the server never holds keys, real
filenames, or plaintext — which is what makes the vault hidden. A sync space
trades that away on purpose, for a server that can index, browse and share it.

Read [docs/format.md](docs/format.md) for the vault format,
[docs/protocol.md](docs/protocol.md) for the wire protocol, and
[docs/backup.md](docs/backup.md) for server-side snapshots.

## Repository layout

| Path | What lives there |
| --- | --- |
| `client/crates/crypto` | Argon2id KDF, AES-SIV filenames, AES-GCM chunks, key hierarchy |
| `client/crates/vault` | Cryptomator-style vault layout on disk |
| `client/crates/index` | Local index of files, chunks, and versions |
| `client/crates/sync` | Watcher, chunking, delta engine, conflict handling, GC |
| `client/crates/transport` | HTTP + WebSocket client for the server |
| `client/crates/mount` | FUSE filesystem over the vault, read-only or writable |
| `client/crates/agent` | The desktop app's sync controller, Tauri-free and testable |
| `client/apps/cli` | Headless `syncbox`: vault, sync, mount, gc, backup commands |
| `client/apps/desktop` | Tauri v2 desktop app (a workspace member; building it needs the Tauri system libraries) |
| `server` | Go server: API, metadata, chunk store, rate limiting, backup engine ([operator's manual](server/README.md)) |
| `deploy` | Dockerfile, docker-compose, Caddyfile |

## Prerequisites

- Rust (stable) and Go 1.24 or newer
- On Linux, `libfuse` headers to build the mount feature
- Docker and Docker Compose, optional, to run the server containerized

## Quick start

```sh
make help          # list developer tasks
make check         # format check, lint, and tests for both languages
make up            # start a server with docker compose
```

To run the server directly without Docker:

```sh
cd server && go run ./cmd/syncboxd serve
```

To sync a folder against it:

```sh
# A vault: everything is sealed on the client before it leaves the machine.
syncbox vault create ~/myvault
syncbox sync once --server http://127.0.0.1:8080 --vault-id <root-id> \
                  --vault ~/myvault --folder ~/Documents
syncbox mount ~/myvault /mnt/syncbox --writable

# A sync space: the server keeps the files in the clear so it can index and
# serve them. Register the space on the server first; the client needs only a
# folder to sync and a directory of its own for the local index.
syncbox sync once --server http://127.0.0.1:8080 --vault-name Files \
                  --vault ~/.local/state/syncbox/files --folder ~/Files
```

## Status

Milestones **M1–M8** are in place (packaging's macOS/Windows signing is
deferred with the runners and identities they need); **M10** through **M15** —
the operator console, the sync-space surfaces, first-run bring-up (seal and
rotate the server password), and settings driven from the console (a live
snapshot schedule, a read-only About panel), the console flagging a setting that
reverts on a restart, and uptime plus password age on that panel — are in as
well. **M16**, rebuilding the desktop agent UI on its references, has landed all
five slices. What's left of it — the drafted dark palette, the mock's per-vault
locked rows, **placeholder (on-demand) files**, and the **update publish job** that
would put a new build in front of a human — is set out under
[The M16 slices](#the-m16-slices).

The `crypto` crate implements the format in `docs/format.md` — content-defined
(FastCDC) chunking, content-derived chunk keys, and an authenticated per-file
manifest — with published vectors pinned by tests. The Go server runs on a
SQLite metadata store and a content-addressed chunk store, snapshots with GFS
retention, and rate-limits per IP. The `sync` engine pushes each changed file
uploading **only the chunks an edit did not touch**, reconciles both-sides edits
into conflicted copies so neither client loses work, and mirrors deletes as
tombstones; the durable `index` crate lets a restart resume without a rescan.

The desktop app (M4) is a thin Tauri shell over `crates/agent`, a Tauri-free
controller whose states are unit-tested against an in-process fake server. Its UI
(M16) is three windows and a tray, each built to its own reference in `docs/`: the
main window's status bar, per-folder rows and first-run card; a separate top-level
window for the vault password, which is the only place that secret is ever typed;
the settings window; and a tray icon whose native menu is the agent's presence
while no window is open — relabelled from the same status the window polls, with
the glyph's corner badge painted from it. One rule held across all five slices: a
control is drawn only when a command backs it, so the reference controls that have
no command yet are left out rather than drawn dead.
`syncbox mount` (M5) serves the vault as a FUSE filesystem — read-only by
default, and `--writable` seals writes into the vault so nothing on disk is
ever plaintext; with no folder, `sync once` runs folderless, relaying dirty
records straight out of the local chunk store. Packaging (M6) ships Linux
`.deb` + `.AppImage` from self-hosted CI; artifacts are deliberately unsigned,
and macOS/Windows builds are deferred with the runners and identities they
need. M7 hardening so far: client-side ciphertext GC whose liveness derives
from the index alone, a defined conflict policy (a local edit outranks a newer
revision or a tombstone), snapshot verification plus a live restore drill,
resumable transfers (chunks staged as they arrive; content-addressed dedup makes
pushes resume for free), the server's per-IP rate limiter, streaming at
both ends so a 4 GiB file costs a chunk-sized window of RAM, not 4 GiB, and an
automatic GC policy (`--gc 1d` on every sync pass — and a GC never runs in
front of a live mount). Backups now reach object storage: an `s3://` snapshot
target seals every object version under COMPLIANCE object lock, and the drill
watched the service itself refuse root's attempt to destroy a sealed version.
`SYNCBOX_BACKUP_POST` hands each sealed snapshot to restic, rsync, or borg as
a consumer; the drill carried a bundle through restic, lost the target
directory entirely, and came back byte-identical.

| Milestone | Scope | Done |
| --- | --- | --- |
| M0 | Scaffolding: workspaces, compose, CI | ✅ |
| M1 | Crypto crate + vault format + test vectors | ✅ |
| M2 | Server core + snapshot engine + Docker image | ✅ |
| M3 | Client core + CLI sync harness | ✅ |
| M4 | Tauri desktop app | ✅ |
| M5 | Mount: FUSE (macFUSE / WinFsp deferred) | ✅ |
| M6 | Packaging: Linux ✅; mac/win + signing deferred | 🟡 |
| M7 | Hardening: conflicts, GC + auto policy, verification, restore drills, resume, rate limits, streaming | ✅ |
| M8 | Backup targets: S3 object-lock + restic/rsync/borg consumer hook | ✅ |
| M10 | Operator console (one embedded page): vault registry, clients point at the server, snapshots page, commit enforcement, server-side vault location | ✅ |
| M11 | Space modes: a space is a sync space or a vault; the client syncs in the clear when the mode says so; browse/share/recycle-bin API; and the console browses, shares, and restores a sync space | ✅ |
| M12 | First-run bring-up: a fresh server with no password awaits one and seals it with Argon2id; the console sets it in place of a logged secret and can rotate it; env-provided passwords behave exactly as before | ✅ |
| M13 | Settings: the console sets the snapshot schedule live (`GET/PUT /admin/backups/config`; a restart falls back to `SYNCBOX_BACKUP_SCHEDULE`), reports backup freshness (newest snapshot's age and when the next one is due, via `next_due_unix`), and a read-only **About this server** panel (`GET /admin/about`) shows storage, data directory, backup target, share TTL and recycle retention | ✅ |
| M14 | Settings continuity: because the live schedule is not persisted, the console flags when it differs from the boot value — `GET /admin/backups/config` reports `boot_interval_seconds`/`boot_schedule` and a `drifted` flag, so an operator sees that a change made in the console reverts on restart — and the **About** panel reports the environment's security posture (session-token lifetime, rate limit, the unknown-vault commit gate) and how the sign-in password is managed (`password_source`: env vs stored, which decides whether the console can rotate it) | ✅ |
| M15 | Uptime visibility: the **About** panel reports when the process came up (`started_unix`) and how long it has run (`uptime_seconds`), so an operator can tell at a glance whether an unpersisted setting has already reverted on a restart; a stored password also reports its age (`password_changed_unix`, the credential file's mtime — the durable counterpart to `password_source`, omitted for an environment password) | ✅ |
| M16 | Agent UI rebuilt on the references, in five slices ([the details](#the-m16-slices) below) | 🟡 |

### The M16 slices

- **S1 — the main window** (`index.html`), built on the mock: a tinted status bar, a gear
  click menu carrying only what exists (Settings…, Sync now, Pause syncing, Lock vault,
  Quit), a first-run card that connects → picks a space from the server → takes the folder
  the server derives → unlocks, per-folder rows with state chips, and a usage line fed by
  the new `usage` IPC (`Index::files()`, `referenced_bytes()`). The desktop unlocks sync
  spaces too (`open_folders` by mode, so the default flow needs no vault header), derives
  each space's state dir (`~/.syncbox/<id>`), and carries a `?demo=…` browser preview for
  checking it against the mock.
- **S2 — the pause.** `set_paused` flips an `AgentStatus.paused` flag that every folder
  loop honours: no passes while held, and a resume runs the queued pass at once. Drawn as
  the amber dot and banner, with *Sync now* refused while paused.
- **S3 — the two passwords split.** The server password stays in the main window's card;
  the vault password is typed only in its own top-level window (`unlock.html`,
  `open_unlock_window` / `unlock_pending` / `pending_unlock` / `cancel_unlock`) with the
  main window waiting on it — and a sync space, having no header to unlock, skips it.
- **S4 — the settings window** (`settings.html`, 640×560) as the reference's
  `today`-badged subset: the rail's space card and usage line, Sync Files (each folder with
  `open_folder`, *Change…* which locks and re-runs first run, the pause as a switch),
  Account (server and space, read-only, from the new `settings_info`), About (version,
  platform, licence, state folder), and the footer's Run-at-login and Show-hidden switches
  — which is why the main window's temporary footer bar left.
- **S5 — the tray** (`src-tauri/src/tray.rs`, a native menu and no HTML): the reference's
  rows built once and relabelled from `current_status` on the window's own 2 s rhythm, the
  glyph's corner badge painted from the state, and closing the main window hiding it while
  a tray exists to raise it again. Where the desktop carries no indicator library it stays
  windows-only with no crash — the backend `dlopen`s libayatana-appindicator, so the build
  needs no package and CI is unaffected.
- **Left:**
  - the drafted **dark palette**, and the mock's per-vault **locked rows** — both wait on
    the client remembering a session between launches;
  - **placeholder / on-demand files** — what the OneDrive baseline calls *Files On Demand*:
    every file in the space shows in the folder and its bytes arrive when a file is opened,
    so a 200 GB space costs 200 GB of disk only if the human reads all of it. Half of it is
    already true — the index knows every file without holding its content, and
    `syncbox mount` (M5) serves exactly that over FUSE. Missing is a hydrate path in the
    folder loop (fetch one file's chunks when something opens it) and, for a plain folder
    rather than a mount, the platform's own placeholder API: FileProvider on macOS, CFAPI on
    Windows;
  - the **update publish job** — one CI job that takes the built deb, AppImage and dmg,
    signs them (`bundle.createUpdaterArtifacts` yields the `.sig`, and the `.zsync` metadata
    so an update pulls a diff rather than the whole bundle), cuts a GitHub Release so the
    bytes get an immutable URL, and writes `update.json` — which is the missing piece for
    every format, not one script per format. The client half is already shipped:
    `tauri-plugin-updater` handles `deb`, `rpm` and AppImage on Linux, NSIS and MSI on
    Windows, and replaces the `.app` on macOS, so a hand-written updater script would only
    reproduce the parts that are already finished — signature checks, privilege escalation,
    self-replacement, relaunch. Three roads, one manifest:
    - **AppImage** is the shortest road to a working update: no root, no identity, the
      bundle replaces itself;
    - **`.deb`** should be a signed apt repo — `dpkg-scanpackages` or `reprepro` publishing
      `Packages.gz` and a signed `Release`, one `.sources` file and a key for the user — so
      updates arrive through `apt-daily` and `unattended-upgrades`, the mechanism Debian
      users already trust and which works with the app closed. The plugin's in-app
      `dpkg -i` stays as the bootstrap for whoever has not added the repo;
    - **`.dmg`** waits on M6, not on code: an unsigned download is a Gatekeeper refusal and
      the updater refuses an update whose bundle signature differs from the running one, so
      a Developer ID has to exist before an update can be *installed*, not merely fetched.

    Two keys, two jobs, and they are not interchangeable: the apt key signs the repo's
    `Release`, the minisign key from `createUpdaterArtifacts` signs the manifest the plugin
    checks. Publishing to Releases is also where the artefacts *should* live — the artifact
    pool refills after every PR and carries no retention rule, and a Release is the same
    bytes with a URL and a lifetime.</newString>

## License

MIT — see [LICENSE](LICENSE). Everything in this repository is offered under
it, with no warranty of any kind.
