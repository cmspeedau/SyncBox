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
deferred with the runners and identities they need); **M10** through **M13** —
the operator console, the sync-space surfaces, first-run bring-up (seal and
rotate the server password), and settings driven from the console (a live
snapshot schedule, a read-only About panel) — are in as well.

The `crypto` crate implements the format in `docs/format.md` — content-defined
(FastCDC) chunking, content-derived chunk keys, and an authenticated per-file
manifest — with published vectors pinned by tests. The Go server runs on a
SQLite metadata store and a content-addressed chunk store, snapshots with GFS
retention, and rate-limits per IP. The `sync` engine pushes each changed file
uploading **only the chunks an edit did not touch**, reconciles both-sides edits
into conflicted copies so neither client loses work, and mirrors deletes as
tombstones; the durable `index` crate lets a restart resume without a rescan.

The desktop app (M4) is a thin Tauri shell over `crates/agent`, a Tauri-free
controller whose states are unit-tested against an in-process fake server.
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
| M16 | Agent UI to the reference (`docs/reference-agent-ui.html`): S1 rebuilds the desktop main window on the mock — tinted status bar, gear click menu (only what exists: Sync now, Lock, Quit), first-run card (connect → pick from server → the server-derived folder, read-only → unlock), per-folder rows with state chips, and a usage line fed by the new `usage` IPC (`Index::files()`, `referenced_bytes()`); the desktop unlocks sync spaces too (`open_folders` by mode, so the default flow needs no vault header), derives each space's state dir (`~/.syncbox/<id>`), adds `open_folder`/`quit` and a `prefs.json` hidden-tier switch, and carries a browser preview (`?demo=…`) for checking it against the mock; S2 adds the pause — `set_paused` flips an `AgentStatus.paused` flag every folder loop honors (no passes while held; resume runs the queued pass at once), drawn as the amber dot/banner and the gear's Pause ⇄ Resume, with Sync now refused while paused; pending: separate Unlock/Settings windows (S3/S4), tray (S5) | 🟡 |

## License

MIT — see [LICENSE](LICENSE). Everything in this repository is offered under
it, with no warranty of any kind.
