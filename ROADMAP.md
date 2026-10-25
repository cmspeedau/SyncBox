# Syncbox Engineering Roadmap

This document is the **canonical source of truth** for SyncBox development milestones, architecture, and engineering priorities.

SyncBox combines a single-binary Go server (`syncboxd`) with a Rust core engine (Tauri desktop app, CLI, FUSE mount). Storage spaces operate in two distinct modes:
- **Sync Space:** Cleartext on server for remote indexing, console browsing, and server-side operations.
- **Vault:** End-to-end encrypted (E2EE) on client devices; the server operates purely as an untrusted, content-addressed block & metadata store.

---

## Master Milestone Matrix

| Milestone | Scope | Target / Component | Status |
| :--- | :--- | :--- | :--- |
| **M0** | Scaffolding | Workspaces, Docker Compose, CI workflows | ✅ **Done** |
| **M1** | Crypto Core | Argon2id KDF, AES-SIV filenames, FastCDC + AES-GCM chunks, test vectors | ✅ **Done** |
| **M2** | Server Core | Go API, SQLite metadata DB, content-addressed store, snapshot engine | ✅ **Done** |
| **M3** | Client Core | Rust CLI sync harness (`syncbox sync once`) | ✅ **Done** |
| **M4** | Desktop Core | Tauri v2 shell + Tauri-free `agent` state machine | ✅ **Done** |
| **M5** | Virtual Mount | FUSE filesystem over vault (`syncbox mount`, ro/rw) | ✅ **Done** *(Linux)* |
| **M6** | Packaging | Linux `.deb` / `.AppImage` CI build + self-updater | 🟡 **Partial** *(macOS/Win deferred)* |
| **M7** | Resilience & Hardening | Conflict copies, resume staging, rate limits, client-side GC, streaming | ✅ **Done** |
| **M8** | Offsite Backup | S3 object-lock compliance + restic/rsync/borg hooks | ✅ **Done** |
| **M10** | Operator Console | Single-page console: vault registry, snapshots, commit gate | ✅ **Done** |
| **M11** | Dual Space Modes | Sync space (cleartext) vs Vault (E2EE); console file browser & recycle bin | ✅ **Done** |
| **M12** | First-Run Bring-Up | Sealed root password with Argon2id, console rotation, fallback env support | ✅ **Done** |
| **M13** | Server Settings | Live snapshot scheduling, backup freshness tracking, read-only About panel | ✅ **Done** |
| **M14** | Settings Continuity | Configuration drift alerts, posture reporting (session TTL, rate limits) | ✅ **Done** |
| **M15** | Uptime & Audit | Process uptime (`started_unix`), credential age tracking | ✅ **Done** |
| **M16** | Desktop UI Overhaul | Multi-window UI (main, unlock, settings, tray), dark theme, auto-updates | 🟡 **Active** *(Placeholders remaining)* |
| **M17** | Real-Time Push Sync | Authenticated SSE / WebSocket sync bus (sub-second multi-device latency) | 🔷 **Next Up** |
| **M18** | Merkle Commits & OCC | Append-only commit DAG, optimistic concurrency, time-travel history | 🔷 **Planned** |
| **M19** | Batch Block Pipeline | FastCDC delta pipeline, multi-chunk batching, convergent chunk hashing | 🔷 **Planned** |
| **M20** | Zero-Knowledge Sharing | URL `#fragment` keying, public share API, embedded WASM browser decryptor | 🔷 **Planned** |
| **M21** | Server-Side GC | `syncboxd gc`, Mark-and-Sweep chunk cleaner with 24h upload grace period | 🔷 **Planned** |
| **M22** | Native Files On-Demand | CFAPI (Windows), FileProvider (macOS), Linux sparse/FUSE, range-based block hydration | 🔷 **Planned** |

---

## Detailed Milestone Specifications

### Completed Foundation (M0 – M15)

- **M0 (Scaffolding):** Rust workspace, Go module, docker-compose setup, GitHub Actions CI.
- **M1 (Crypto Core):** Argon2id key derivation, AES-SIV deterministic filename obfuscation, FastCDC content-defined chunking, authenticated per-file manifests, test vector suites pinned in tests.
- **M2 (Server Core):** SQLite metadata DB, content-addressed disk store, snapshot engine with GFS retention rules.
- **M3 (Client Core):** Headless CLI `syncbox sync once`, local index with durable recovery after restarts.
- **M4 (Desktop Shell):** Tauri v2 agent decoupled into an in-process, Tauri-free state machine (`crates/agent`).
- **M5 (FUSE Mount):** Client-side userspace FUSE mount (`syncbox mount`), read-only or writable with live chunk encryption.
- **M6 (Packaging):** Linux `.deb` and `.AppImage` publishing. macOS and Windows binary signing deferred pending hardware runners and identities.
- **M7 (Hardening):** Both-sides conflict copies, tombstone delete propagation, staged chunk resumption, streaming windows (constant RAM usage on large transfers), per-IP rate limiter.
- **M8 (Backups):** S3 object-lock compliance mode and external consumer hooks (`SYNCBOX_BACKUP_POST` for restic, rsync, borg).
- **M10 (Operator Console):** Single-page embedded web dashboard: vault registry, client connection endpoints, snapshot management, commit gate.
- **M11 (Dual Modes):** Cleartext Sync spaces alongside E2EE Vaults; web console browsing, sharing, and recycle bin restoration for cleartext spaces.
- **M12 (Bootstrap):** Sealed root credentials via Argon2id, console credential rotation, environment variable backwards compatibility.
- **M13 (Settings API):** Live snapshot schedule modification, backup freshness probes (`next_due_unix`), read-only `/admin/about` system telemetry.
- **M14 (Drift Detection):** In-memory configuration drift tracking against boot flags, session timeout reporting, security posture visibility.
- **M15 (Audit & Uptime):** Daemon process uptime tracking (`started_unix`), credential age counters (`password_changed_unix`).

---

### Milestone 16: Desktop UI Modernization (In Progress)

Rebuilding the desktop agent UI around dedicated operational references:

- **S1 — Main Window:** Tinted status bar, gear menu, space picker, folder sync state chips, and usage telemetry (`Index::files()`, `referenced_bytes()`).
- **S2 — Pause Flow:** Agent-level synchronization suspension with amber status badge.
- **S3 — Dual Secret Boundary:** Server connection credentials stay in the main window; vault decryption passphrases are restricted exclusively to a dedicated top-level modal window (`unlock.html`).
- **S4 — Settings Panel:** Account statistics, active folder mappings, startup behavior, and local index inspection.
- **S5 — Tray Integration:** Desktop-native notification tray icon and menu via `libayatana-appindicator` with fallback resilience.
- **Remembered Spaces & Themes:** Multi-space persistent registry (`spaces.json`) and system/light/dark styling tokens (`theme.css`).
- **Auto-Updater:** GitHub Releases + signed APT repository integration with Minisign verification (`desktop-v0.1.1` shipped).
- **Remaining Slice (On-Demand Placeholders):**
  - Implement selective hydration via `Engine::hydrate` / `SyncWorker::hydrate`.
  - Sparse local file projection allowing browse-before-download without storing entire vault content locally (OneDrive Files On-Demand parity).

---

### Milestone 17: Real-Time Event Bus & Sub-Second Sync (Seafile / Dropbox Parity)
*Target: Eliminate CPU- and battery-draining HTTP polling intervals.*

- **Server Event Broker (`server/internal/api/events.go`):**
  - Authenticated Server-Sent Events (SSE) or WebSocket route:
    `GET /api/v1/spaces/:id/events`
  - Event channels:
    - `space.head_advanced`: Fired whenever a client pushes commits or modifies files.
    - `space.state_changed`: Lock/unlock and administrative events.
  - Resilience: 15-second heartbeat keep-alives and reconnection event buffer replaying.
- **Client Reactor (`client/crates/transport`, `client/crates/agent`):**
  - Replace the 30-second polling cadence with an active event listener.
  - Trigger immediate incremental sync upon receiving `space.head_advanced`, reducing cross-device sync latency to <200ms.
  - Fall back to exponential backoff polling if event stream disconnects.

---

### Milestone 18: Merkle Commits & Optimistic Concurrency (Git / Seafile Parity)
*Target: Atomic cross-device state management and point-in-time time travel.*

- **Server Commit Ledger (`server/internal/store/commits.go`):**
  ```sql
  CREATE TABLE space_commits (
      commit_id TEXT PRIMARY KEY,
      space_id TEXT NOT NULL,
      parent_id TEXT,
      root_manifest_hash TEXT NOT NULL,
      device_id TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      FOREIGN KEY(space_id) REFERENCES spaces(id) ON DELETE CASCADE
  );
  ```
- **Optimistic Concurrency Control (OCC):**
  - Push commit endpoint: `POST /api/v1/spaces/:id/commits`
  - Payload: `{ parent_commit: "c1", new_commit: "c2", root_manifest: "..." }`
  - If the space head has moved past `parent_commit`, reject with `HTTP 409 Conflict` and return the current server head.
  - The client pulls the missing commit delta, performs a 3-way manifest merge locally, and re-submits cleanly.
- **Version History & Rollbacks:**
  - Commit inspection endpoint: `GET /api/v1/spaces/:id/commits`.
  - Rollback endpoint: `POST /api/v1/spaces/:id/rollback`. Repoints space head to any prior commit instantaneously without moving chunk files.

---

### Milestone 19: Batch Pipeline & Convergent Chunking (Seafile-Grade Throughput)
*Target: High-speed ingestion and bandwidth optimization for large file hierarchies.*

- **Convergent Vault Deduplication:**
  - FastCDC chunk size boundaries tuned to dynamic 2 MiB – 4 MiB windows.
  - Deterministic sub-key derivation for vault blocks:
    $$\text{ChunkKey} = \text{HMAC-SHA256}(K_{vault}, \text{BLAKE3}(Plaintext))$$
    Enables identical plaintext blocks inside the vault to share chunk hashes without leaking keys across separate vaults.
- **Batch Transfer Protocol:**
  - `POST /api/v1/spaces/:id/chunks/query`: Client checks presence for a batch of chunk hashes; server returns missing subset.
  - `POST /api/v1/spaces/:id/chunks/batch`: Multipart chunk upload streaming multiple blocks in a single network roundtrip.

---

### Milestone 20: Zero-Knowledge Web Share Links (Proton Drive / MEGA Parity)
*Target: Frictionless public web sharing of vault files without sharing master vault keys.*

- **Ephemeral Share Keys:**
  - Client generates a random 256-bit AES-GCM share key ($K_s$).
  - Client seals the target file's manifest and chunk keys under $K_s$ and uploads the opaque blob:
    `POST /api/v1/shares` $\rightarrow$ returns public `share_token`.
  - Client presents URL with key in URI fragment:
    `https://syncbox.domain/s/<share_token>#<base64_K_s>`
- **Server Public Broker:**
  - Unauthenticated, rate-limited public routes:
    - `GET /s/:share_token`: Serves embedded web decryptor.
    - `GET /api/v1/public/shares/:share_token/manifest`: Delivers encrypted manifest.
    - `GET /api/v1/public/shares/:share_token/chunks/:chunk_id`: Streams individual encrypted chunks.
  - **Zero-Knowledge Guarantee:** The `#fragment` is never sent to the server in HTTP requests.
- **Embedded Browser WASM Decryptor:**
  - Static web UI embedded in `syncboxd` (`embed.FS`).
  - In-browser JavaScript/WASM extracts $K_s$ from `location.hash`, downloads chunks, decrypts via WebCrypto, and streams output directly to user storage via the browser File System Access API.

---

### Milestone 21: Server-Side Garbage Collection (Autonomous Maintenance)
*Target: Storage reclamation without human intervention or data race risks.*

- **Retention Policy Configuration (`syncboxd.yaml` / Admin Console):**
  ```yaml
  vault:
    retention:
      keep_commits_days: 30
      gc_interval: "24h"
      grace_period: "24h"
  ```
- **Mark-and-Sweep Engine (`server/internal/gc/`):**
  - **Phase 1 (Mark):** Scan all commits within the retention period + the current active head. Record active chunk hashes in an in-memory Roaring Bitmap.
  - **Phase 2 (Sweep):** Traverse physical chunk directories on disk. If a chunk file's creation timestamp is older than the 24-hour grace window and absent from the bitmap, delete it.
- **Tooling:**
  - CLI maintenance command: `syncboxd gc --dry-run` and `syncboxd gc --prune`.
  - Background cron runner with telemetry emitted to the Operator Console.

---

### Milestone 22: Native Files On-Demand & Sparse Block Hydration (OneDrive / iCloud Drive Parity)
*Target: Every file in a space is visible from a native file manager; bytes materialise only when something asks for them, so a 200 GB space stops costing 200 GB of disk by default.*

- **Goals:**
  - Eliminate the all-or-nothing hydrate-on-sync model by exposing the existing index (which already knows every file without its content) as the native OS browse experience.
  - Reuse the FUSE mount shipped in M5 as the Linux surface and add the OS-native equivalents on Windows and macOS.
  - Hydrate only the byte ranges a read actually requests; do not pull the whole chunk tree when one block is asked for.
  - Keep vault and sync-space behaviour identical — placeholders carry real metadata, encryption keys are pulled only at the moment of decrypt, and the server never learns which file was opened.

- **Cross-Cutting Plumbing (`client/crates/agent`, `client/crates/mount`, `client/crates/sync`, `client/crates/transport`):**
  - **Folder Policy:**
    - New `folder_policy` flag on the sync folder (`"materialised" | "on_demand"`, default `materialised`).
    - The agent runs an initial hydration pass for `on_demand` folders that writes placeholders for every file in the index and pulls chunks only on demand.
    - Existing folders flip policy on the next sync pass; a regression guard prevents accidental auto-hydration on policy change.
  - **Sparse Placeholder File Format:**
    - Each placeholder carries an extended attribute block: `{ space_id, file_id, size, chunk_count, chunk_manifest_hash, mode, mtime, content_hash }`.
    - For vaults, the placeholder xattr never stores a chunk key or plaintext metadata — only the content-addressed chunk IDs.
  - **Range-Based Block Hydration (`Engine::hydrate_range`, `SyncWorker::hydrate_range`):**
    - New server route: `GET /api/v1/spaces/:id/chunks/:chunk_id?range=<start>-<end>` returns a single chunk's byte window with `Accept-Ranges: bytes` and `Content-Range`.
    - The mount layer maps a read offset to the owning chunk and chunk-internal byte window before issuing the request, so a 4 KiB `read()` on a 4 GiB file costs one chunk query and one small response, not a whole-file pull.
    - The transport crate caches the just-fetched chunk window in a bounded LRU keyed on `(space_id, chunk_id, range)`; cache pressure evicts oldest ranges first.
  - **Placeholder State Machine:**
    - `Hollow` (only xattr present, zero-byte body) → `Hydrating` (chunk windows cached locally, body still sparse) → `Hydrated` (file body fully materialised, xattr retained so the next policy flip can re-sparse it without a re-scan) → `Evicted` (body truncated to zero after policy reversion or manual free).

- **Windows: Cloud Files API (CFAPI) Integration:**
  - New crate `client/crates/cfapi` wrapping the Win32 `Cfapi.h` ABI:
    - `CfRegisterSyncRoot` registers a sync root under `%USERPROFILE%\SyncBox\<space-id>` with the FILE_ATTRIBUTE_PINNED + FILE_ATTRIBUTE_UNPINNED placeholder flags.
    - `CfConnectSyncRoot` opens the placeholder root and the agent feeds it `CF_CALLBACK_TYPE_FETCH_PLACEHOLDER` / `FETCH_DATA` callbacks as the OS requests file or range data.
    - `CfUpdatePlaceholder` with `CF_SET_PIN_STATE.UNPINNED | REQUESTED` paints the placeholder icon overlay that File Explorer already knows how to render.
  - The placeholder directory uses NTFS sparse files so a hydrated chunk window can be written in place without re-allocating the whole file.
  - The CFAPI callbacks delegate straight to `Engine::hydrate_range`; no second transport path is introduced.
  - **Security:** Vault decryption happens in the same in-process path as the existing FUSE driver; chunk keys are pulled into process memory only for the duration of a single `FETCH_DATA` callback.

- **macOS: FileProvider Framework Integration:**
  - New crate `client/crates/file_provider` exposing an `NSFileProviderReplicatedExtension` Objective-C++ shim:
    - `item(for: identifier:)` returns the placeholder `NSFileProviderItem` (filename, size, capabilities, content type) sourced directly from the local index, so the Finder row exists before the bytes do.
    - `fetchContents(for: version: request: completionBlock:)` maps the requested `NSFileProviderRequest` byte range to a `Engine::hydrate_range` call and writes the bytes back into the NSFileProviderManager-managed URL.
  - `client/apps/desktop` (Tauri v2) installs and registers the FileProvider extension at first run; uninstall unregisters it cleanly so no orphan extension remains.
  - The tray (M16 S5) gains a *Free up space* menu item that walks the NSFileProviderManager item graph and evicts `Evictable` items back to `Hollow`.
  - **Parity with CFAPI:** The placeholder lifecycle, chunk-window caching and xattr-equivalent metadata block are identical so a later code review can compare both sides line-for-line.

- **Linux: Sparse Files + FUSE Enhancement:**
  - Extend `client/crates/mount` (the M5 driver) with:
    - `fallocate(FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE)` on hydrate so the placeholder becomes a true sparse file — the kernel reports the placeholder size without allocating blocks.
    - A `--on-demand` mount flag that flips the existing FUSE driver into `Hollow` default state, hydrating on `read()` and never on sync.
  - Existing `--writable` writes already go through chunk sealing; placeholders and materialised files share that write path unchanged.
  - New `syncboxctl placeholder set <path> --hollow` / `--hydrate` CLI subcommand for scripting without a desktop UI.

- **Operator Console Surface (`server/internal/api/`, embedded web UI):**
  - New endpoint `GET /api/v1/spaces/:id/placeholder_stats` returns `{ hollow_count, hydrating_count, hydrated_bytes, cached_range_count }` so an operator can see on-demand behaviour without a local agent.
  - The space detail card in the Operator Console surfaces the same numbers as a small chip next to the space name.

- **Testing & Test Vectors:**
  - Cross-platform contract test suite under `client/crates/mount/tests/placeholder_contract.rs`:
    - All three surfaces (CFAPI shim, FileProvider shim, FUSE driver) must pass identical fixture-driven assertions for: placeholder visibility before hydration, byte-exact round-trip after a range read, eviction restoring `Hollow` without deleting the xattr, and vault key confidentiality (chunk keys never appear in any cross-process IPC trace).
  - Range-hydration fuzz harness over the chunk manifest (sparse reads at chunk boundaries, mid-chunk offsets, multi-chunk spans, last-chunk short reads).
  - **Documentation:** `docs/on_demand.md` describes the placeholder lifecycle, the CFAPI/FileProvider/FUSE mapping table, and the operator-facing knobs.
