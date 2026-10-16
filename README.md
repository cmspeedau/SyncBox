# Syncbox

A lightweight, zero-knowledge Dropbox alternative.

Desktop clients for Linux (AppImage), macOS, and Windows sync to a single Go
server running in Docker. Everything is encrypted on the client before it
leaves the machine, so the server stores opaque blobs and bookkeeping it can
never read.

## How it works

```
Tauri v2 desktop client (Rust core + web UI)
  crypto core  ·  sync engine  ·  vault/mount layer
        |  HTTPS: REST + WebSocket  (client-side encrypted, zero-knowledge)
        v
Go server in Docker
  API  ·  metadata DB  ·  content-addressed chunk store
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
| `client/crates/sync` | Watcher, chunking, delta engine, conflict handling |
| `client/crates/transport` | HTTP + WebSocket client for the server |
| `client/apps/cli` | Headless sync client, used to drive end-to-end tests |
| `client/apps/desktop` | Tauri v2 desktop app (joins the workspace in M4) |
| `server` | Go server: API, metadata, chunk store, backup engine |
| `deploy` | Dockerfile, docker-compose, Caddyfile |

## Prerequisites

- Rust (stable) and Go 1.24 or newer
- Docker and Docker Compose, to run a server locally
- On Linux, `libfuse` headers to build the mount layer (M5)

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

## Status

Milestone **M1 — crypto & vault format**. `syncbox-crypto` implements Argon2id
key derivation, AES-SIV filenames, AES-GCM content chunks, and the HKDF key tree;
`syncbox-vault` creates and unlocks a vault on disk. The byte-level format is
specified with test vectors in [`docs/format.md`](docs/format.md), pinned by an
assertion in the crate. Per-file chunked read/write lands with M3's content-defined
chunker.

| Milestone | Scope | Status |
| --- | --- | --- |
| M0 | Scaffolding: workspaces, compose, CI | done |
| M1 | Crypto crate + vault format + test vectors | done |
| M2 | Server core + snapshot engine + Docker image | in review |
| M3 | Client core + CLI sync harness | next |
| M4 | Tauri desktop app | not started |
| M5 | Mount: FUSE / macFUSE / WinFsp | not started |
| M6 | Packaging: AppImage, .dmg, .msi, signing | not started |
| M7 | Hardening: conflicts, GC, verification, restore drills | not started |
| M8 | Alternate backup targets: S3 object-lock, restic | not started |

## License

No license has been chosen yet, so all rights are reserved by default. Pick one
before publishing anything.
