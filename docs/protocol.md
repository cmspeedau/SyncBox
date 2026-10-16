# The Syncbox sync protocol

Version 1, over HTTPS. This is the contract between `client/crates/transport` and
`server/internal/api`; both sides are written from this file.

Status: implemented on the server against the durable SQLite + filesystem store.
The Rust client has the same types and method signatures and returns `Unimplemented`
until M3 supplies the HTTP transport.

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
| 404 | `not_found` | Chunk collected or vault unknown |
| 409 | `conflict` | Someone else committed. Re-fetch, keep both copies |
| 413 | `too_large` | Chunk exceeds the server's limit |
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

## A full upload, in order

1. Watch the local tree; hash the changed file's content into chunks with FastCDC.
2. Ask `chunks/exists` for the ids it just derived.
3. `PUT` only the missing ones.
4. `POST` the revision with `parent` set to the last revision this client saw.
5. On 409, refetch and produce a conflicted copy.

Steps 2 and 3 are why an edit to a large file costs the edit rather than the file.

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
```

Both answer `501 not_configured` when no `SYNCBOX_BACKUP_TARGET` is set. See
[backup.md](backup.md) for what a snapshot contains and how it is restored.

## Versioning the protocol

Every path carries `/api/v1`. A change that breaks an existing client is a new prefix,
not a modified v1, because clients in the wild are older than any server the user
upgrades.
