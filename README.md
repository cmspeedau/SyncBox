# Syncbox

A lightweight file sync server, with an encrypted vault as a choice.

A Linux desktop client (AppImage / .deb), a headless CLI, and a FUSE mount sync
to a single Go server — one binary, Docker deployment included. A space is
either a **sync** space, kept in the clear so the server can index and serve
it, or a **vault**, encrypted on the client before anything leaves the machine,
so the server stores opaque blobs and bookkeeping it can never read.

> **Canonical Roadmap:** For the complete engineering roadmap, architectural milestones (M0–M22), and ongoing work, see [ROADMAP.md](ROADMAP.md).

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

## Current Status

**Active Version:** `v0.4.x` / Desktop `desktop-v0.1.1`  
**Current Milestone Focus:** Completing **M16** (Desktop UI Overhaul & On-Demand Hydration) and preparing for **M17** (Real-Time Push Sync).

- **Core & Storage (M1–M8, M10–M15):** Complete. Implemented Argon2id/AES-SIV/FastCDC crypto, Go server daemon with SQLite metadata and content-addressed storage, S3 object-lock snapshots, admin console, dynamic schedule controls, configuration drift detection, and process uptime/credential age auditing.
- **Client & Mount (M3–M5, M7):** Complete. Rust CLI, FastCDC delta transfers, conflict resolution branches, staged resumable transfers, client-side GC, and Linux FUSE mount (`--writable` seals writes directly into the vault).
- **Desktop UI (M16):** Active. Shipped all 5 slices (main window, pause flow, dual password isolation modal, settings window, native system tray), remembered space registry, light/dark themes, and signed release updater with APT repo (`desktop-v0.1.1`).
- **Next Up:** On-demand placeholder files (M16 final slice), followed by Real-Time Push Sync (M17), Merkle Commits & OCC (M18), Batch Pipelines (M19), Zero-Knowledge Web Share Links (M20), Server-Side Garbage Collection (M21), and **Native Files On-Demand & Sparse Block Hydration (M22)** — the cross-platform Files On-Demand work that adds CFAPI on Windows, FileProvider on macOS, sparse-file + FUSE enhancements on Linux, and range-based block hydration for vaults and sync spaces alike.

See [ROADMAP.md](ROADMAP.md) for detailed descriptions, architecture diagrams, and the master milestone matrix.

## License

MIT — see [LICENSE](LICENSE). Everything in this repository is offered under
it, with no warranty of any kind.
