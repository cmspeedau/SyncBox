# The Syncbox sync protocol

Version 1, over HTTPS. This is the contract between `client/crates/transport` and
`server/internal/api`; both sides are written from this file.

Status: implemented on the server against the durable SQLite + filesystem store, and
on the Rust client (`client/crates/transport` over an `Http` seam, driven by
`client/crates/sync`). The two have been run against each other end to end: a folder
is pushed from one client and pulled, byte for byte, by a second, including edits,
deletions, and nested directories.

## What the server is

A store of opaque chunks and a ledger of revisions. It never holds a key and never
decrypts anything, so the useful mental model is "a content-addressed blob store with
a per-file version log bolted on".

| The server can see | The server cannot see |
| --- | --- |
| Chunk ids and sizes | Keys, and therefore any plaintext |
| Revision numbers and parentage | Real filenames or the folder tree |
| Plaintext file size and mtime | What a manifest says |
| When a vault was written to | Which vault belongs to whom |

## Authentication

Single-user for v1. One password buys a bearer token.

```
POST /api/v1/auth/token
     { "password": "..." }
 →   { "token": "<opaque>", "expires_unix": 1760000000 }
```

Send it back as `Authorization: Bearer <token>`. The token is a base64url claim set
with an HMAC-SHA256 over it, signed with `SYNCBOX_TOKEN_SECRET`; there is no session
table, so a restarted server keeps accepting tokens as long as that secret is stable.

`/healthz` is the only route that needs no token.

## Errors

Every non-2xx response has the same body:

```json
{ "code": "conflict", "reason": "vault x is at revision 4, client committed against 3" }
```

| Status | `code` | Client should |
| --- | --- | --- |
| 400 | `bad_request`, `bad_chunk_id` | Bug or bad input; do not retry |
| 401 | `unauthorized` | Re-authenticate, then retry once |
| 404 | `not_found`, `incomplete_snapshot` | Chunk collected, vault unknown, or a half-written snapshot |
| 409 | `conflict`, `restore_target_occupied` | Someone else committed. Re-fetch, keep both copies |
| 413 | `too_large` | Chunk exceeds the server's limit |
| 429 | `rate_limited` | Wait `Retry-After` seconds. Chunk transfers retry this themselves |
| 501 | `not_configured` | Feature off on this server (backups with no target) |
| 500 | `internal`, `corrupt_snapshot` | Back off and report |

Codes are the interface. Statuses are for humans reading a log.

## Chunks

Chunks are addressed by id, scoped to a vault. `PUT` is idempotent: the id is a
content address, so storing the same id twice is a no-op that reports zero new bytes.

```
POST /api/v1/vaults/{vaultID}/chunks/exists
     { "ids": ["ABCDEFGHIJKLMNOP", ...] }
 →   { "missing": ["ABCDEFGHIJKLMNOP", ...] }

HEAD /api/v1/vaults/{vaultID}/chunks/{chunkID}     → 200 + Content-Length, or 404
PUT  /api/v1/vaults/{vaultID}/chunks/{chunkID}     body: raw bytes → 201 { "stored": N }
GET  /api/v1/vaults/{vaultID}/chunks/{chunkID}     → raw bytes
```

Chunk ids are validated server-side as alphanumeric strings of 8–128 characters. The
server cannot check an id against a chunk's content — it has no key — but refusing
anything not shaped like a content address keeps path traversal and odd filenames out
of the blob store.

## Revisions

A revision is one committed state of one file. The client owns the plaintext path; the
server only ever sees `dir_id` and `cipher_name`, and only compares them for equality.

```
POST /api/v1/vaults/{vaultID}/revisions
     {
       "parent": 3,
       "revision": {
         "revision": 0,
         "parent": 3,
         "dir_id": "ABCDEFGHIJ",
         "cipher_name": "KLMNOPQRST",
         "manifest": "<base64 of the encrypted chunk list>",
         "size": 1048576,
         "modified_unix": 1760000000,
         "deleted": false
       }
     }
 →   201 { "revision": 4 }

GET  /api/v1/vaults/{vaultID}/revisions?since=4&limit=500
 →   { "revisions": [ ... ], "upto": 4 }
```

`revision.vault_id` is ignored: the URL path decides the vault, so a request cannot
write into someone else's history by naming it in the body. `revision.revision` is
assigned by the server and ignored on the way in.

`size` is plaintext on purpose. A client cannot allocate or show progress without it,
and this is one of the two leaks the design accepts — the other is `modified_unix`.

### Conflict rule

A commit names the revision it was derived from. If that is not the vault's current
head, the server answers `409 conflict` and changes nothing.

The client's response to a 409 is the important part: it re-fetches the head, keeps
the server's version, and writes its own next to it as

```
notes.txt  →  notes (conflicted copy 2026-10-16).txt
```

Both edits survive. There is no merge that is safe to perform silently on arbitrary
bytes, so Syncbox does not pretend otherwise.

### Tombstones

A deletion is not the absence of a revision; it is a revision with `"deleted": true`
committed against the current head. Because the log is ordered, the highest-numbered
revision for a `(dir_id, cipher_name)` is that file's current state, whether it is
content or a tombstone. A client applying the log therefore either writes the file
(content) or removes it (tombstone), and a file it has never seen can be skipped
rather than resurrected.

A tombstone carries no manifest. The client sends `""`, the Go server stores a nil
`[]byte`, and `encoding/json` writes a nil byte slice as `null` — so a tombstone comes
back over the wire as `"manifest": null`. Both sides treat `null`, `""`, and an absent
field as the same empty manifest; the Rust client pins this with a test so a future
Go or Rust change that makes them differ is caught.

## A full upload, in order

1. Read the vault's revision log and apply anything newer than the index reflects.
2. For each changed local file, split its content into chunks with FastCDC and seal
   each chunk under a content-derived key.
3. Ask `chunks/exists` for those ids, and `PUT` only the missing ones.
4. `POST` the revision with `parent` set to the vault's **current head** — the highest
   revision in the log, not the file's previous revision. The head advances on every
   commit by anyone, so a commit is always against the head the client last read.
5. On 409, the head moved under the client: keep its bytes as a conflicted copy and
   reconcile the canonical file on the next pass.

Steps 3 and 4 are why an edit to a large file costs the edit rather than the file:
content-defined chunking leaves every chunk after an insertion unchanged in both
content and id, so `chunks/exists` reports them present and only the touched bytes are
uploaded.

## A full download, in order

1. `GET .../revisions?since=0` and take the newest revision for each file key.
2. For a content revision newer than the local index, decrypt its manifest, `GET` its
   chunks, and reassemble — the same chunks the uploader sent, because keys are derived
   from content, not from which file referenced them. With a local store the client
   fetches *through* it: a chunk already stored is never re-downloaded, every chunk
   downloaded is staged the moment it arrives, and the manifest is cached only after
   the last chunk — so an interrupted file resumes where the drop happened instead
   of starting over.
3. For a tombstone, remove the file.

The client reads the log from `0` and reconciles it against a per-file revision number
it keeps in its own index, so it needs no sync cursor of its own and a crash mid-pass
costs a re-read, not a lost revision.

## Change notification

```
GET /api/v1/vaults/{vaultID}/events?since=4&wait=30s
 → 200 { "revisions": [ ... ], "upto": 7 }
```

A long poll, chosen over a WebSocket so the server needs no dependency and the
proxy story stays simple. The client passes the highest revision it already has as
`since`; the server holds the connection open until a commit advances the vault past
that point (returning the new revisions and the new head as `upto`), until `wait`
elapses (returning an empty `revisions` with the current `upto`), or until the client
disconnects. `wait` defaults to 30s and is clamped to 60s.

Crucially, the response is **the same revision page** `GET .../revisions` returns, so
the notification is a hint to read, not the change itself. A client that was offline
while commits landed loses nothing: it reconnects with its last-seen `since` and the
endpoint hands back the whole backlog. Catch-up and notification are the same path,
so a dropped or late signal can only cost one `wait` interval — never a missed
revision. `wait=0` turns the endpoint into a single-shot catch-up read that never
blocks.

## Backups

```
GET  /admin/backups     → [ { "ID": "...", "Manifest": { ... } } ]
POST /admin/backups     → 201 { "ID": "...", "Manifest": { ... } }

POST /admin/backups/{id}/verify  → 200 { "id", "chunks", "chunk_bytes", "metadata_sha256" }
POST /admin/backups/{id}/restore → { "dest_dir" }
                               → 200 { "id", "dest_dir", "chunks", "chunk_bytes" }
```

All four answer `501 not_configured` when no `SYNCBOX_BACKUP_TARGET` is set.
`verify` re-hashes every chunk and the metadata file against the manifest the snapshot
was sealed with, and answers `404 not_found` for a snapshot that never landed,
`404 incomplete_snapshot` for a half-written bundle, or `500 corrupt_snapshot` when a
stored object no longer matches its recorded hash. `restore` verifies before it copies
and refuses a destination that already holds a `metadata.json` with
`409 restore_target_occupied` — replacing live data is the one thing restore must not
do silently.

Refusals carry a stable `code` in the error body, and that code — not the HTTP status —
is what a client should branch on: `500 corrupt_snapshot` and a generic `500 internal`
are different problems an operator acts on differently. See
[backup.md](backup.md) for what a snapshot contains and how it is restored.

## Rate limits

By default the server answers every caller as fast as it can. A server on a home
connection — or any server that would rather stay responsive than maximally busy —
can opt into a per-address token bucket:

| Variable | Meaning |
| --- | --- |
| `SYNCBOX_RATE_LIMIT` | sustained requests per second per caller IP; unset means unlimited |
| `SYNCBOX_RATE_BURST` | how many requests a caller may spend at once before the sustained rate bites (default 100) |

A refusal is a `429` carrying the stable `rate_limited` code and a `Retry-After`
header in whole seconds. It guards every route, login included, and it refuses
*before* the request buys any auth or storage work — the point is to protect the
machine, not to meter honest use, which a full sync's burst will almost never
notice.

Chunk transfers retry a `rate_limited` themselves: the client waits a doubling
backoff (up to four retries), which converges on the granularity the server
advertised. Commit — the one call that is not idempotent — replays on a stricter
proof: only a `429` carrying this protocol's own `rate_limited` body, which only
the server's limiter writes and which it writes *before any handler runs*, so the
refused commit demonstrably never happened. A bare `429` from a proxy or any other
intermediary, which cannot say what happened downstream, surfaces unretried.

## Versioning the protocol

Every path carries `/api/v1`. A change that breaks an existing client is a new prefix,
not a modified v1, because clients in the wild are older than any server the user
upgrades.
