# Syncbox

A lightweight, zero-knowledge Dropbox alternative.

A Linux desktop client (AppImage / .deb), a headless CLI, and a FUSE mount sync
to a single Go server — one binary, Docker deployment included. Everything is
encrypted on the client before it leaves the machine, so the server stores
opaque blobs and bookkeeping it can never read.

## How it works

```
Tauri v2 desktop client · CLI · FUSE mount   (Rust core, zero-knowledge)
   crypto core  ·  sync engine  ·  vault/mount layer  ·  local chunk store
         |  HTTPS: REST + WebSocket  (client-side encrypted)
         v
Go server (single binary; Dockerfile + compose provided)
   API  ·  metadata DB  ·  content-addressed chunk store  ·  rate limiter
         |
         v
   Docker volume / NAS   +   snapshot target (local first, S3/restic later)
```

The client does all encryption. The server never holds keys, real filenames, or
plaintext — which is what makes the vault hidden.

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
| `client/apps/desktop` | Tauri v2 desktop app (its own workspace; built separately) |
| `server` | Go server: API, metadata, chunk store, rate limiting, backup engine |
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
syncbox vault create ~/myvault
syncbox sync once --server http://127.0.0.1:18510 --vault-id <root-id> \
                  --vault ~/myvault --folder ~/Documents
syncbox mount ~/myvault /mnt/syncbox --writable
```

## Status

Milestones **M1–M6** are in place; **M7** is one step from done.

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
pushes resume for free), the server's per-IP rate limiter, and streaming at
both ends so a 4 GiB file costs a chunk-sized window of RAM, not 4 GiB.

| Milestone | Scope | Done |
| --- | --- | --- |
| M0 | Scaffolding: workspaces, compose, CI | ✅ |
| M1 | Crypto crate + vault format + test vectors | ✅ |
| M2 | Server core + snapshot engine + Docker image | ✅ |
| M3 | Client core + CLI sync harness | ✅ |
| M4 | Tauri desktop app | ✅ |
| M5 | Mount: FUSE (macFUSE / WinFsp deferred) | ✅ |
| M6 | Packaging: Linux ✅; mac/win + signing deferred | 🟡 |
| M7 | Hardening: conflicts, GC, verification, restore drills, resume, rate limits, streaming | 🟡 |
| M8 | Alternate backup targets: S3 object-lock, restic |  |

M7's remaining step is the automatic GC policy: deciding *when* to collect
without a human invoking `syncbox gc`.

## License

No license has been chosen yet, so all rights are reserved by default. Pick one
before publishing anything.
